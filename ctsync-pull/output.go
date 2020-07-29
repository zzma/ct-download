package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"github.com/lib/pq"
	log "github.com/sirupsen/logrus"
	"github.com/teamnsrg/zcrypto/ct"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

type csvFileWriter struct {
	csvWriter *csv.Writer
	osFile    *os.File
}

type certHashes struct {
	SHA256           string
	TBS_NO_CT_SHA256 string
}

func insertBuilder(values []*certHashes) string {
	var str strings.Builder
	str.WriteString("INSERT INTO downloaded_certs (sha256,tbs_no_ct_sha256) VALUES")

	for idx, hashes := range values {

		str.WriteString(" (decode('")
		str.WriteString(hashes.SHA256)
		str.WriteString("','hex'),decode('")
		str.WriteString(hashes.TBS_NO_CT_SHA256)
		if idx == len(values)-1 {
			str.WriteString("','hex'))")
		} else {
			str.WriteString("','hex')),")
		}
	}

	return str.String()
}

type logEntryWriter struct {
	ctRecords []*ct.LogEntry
	db        *sql.DB
	writers   map[string]*csvFileWriter
	outputDir string
}

const DB_INSERT_THRESHOLD = 100

func (c *logEntryWriter) Open() {
	c.ctRecords = make([]*ct.LogEntry, 0)

	cmdString := "user=ctdownloader dbname=ctdownload sslmode=disable"

	if runtime.GOOS == "linux" {
		cmdString = "user=ctdownloader dbname=ctdownload sslmode=disable host=/var/run/postgresql"
	}

	var err error
	c.db, err = sql.Open("postgres", cmdString)
	if err != nil {
		log.Fatal(err)
	}
	c.writers = make(map[string]*csvFileWriter)
}

func (c *logEntryWriter) Close() {
	for _, writer := range c.writers {
		writer.csvWriter.Flush()
		writer.osFile.Close()
	}
	c.db.Close()
}

func (c *logEntryWriter) insertRecords(startIdx, endIdx int) error {
	values := make([]*certHashes, endIdx-startIdx)
	for i := startIdx; i < endIdx; i++ {
		entry := c.ctRecords[i]
		var sha256, tbsNoCTSHA256 string
		if entry.Leaf.TimestampedEntry.EntryType == ct.X509LogEntryType {
			sha256 = entry.X509Cert.FingerprintSHA256.Hex()
			tbsNoCTSHA256 = entry.X509Cert.FingerprintNoCT.Hex()
		} else if entry.Leaf.TimestampedEntry.EntryType == ct.PrecertLogEntryType {
			sha256 = entry.Precert.TBSCertificate.FingerprintSHA256.Hex()
			tbsNoCTSHA256 = entry.Precert.TBSCertificate.FingerprintNoCT.Hex()
		}

		values[i-startIdx] = &certHashes{SHA256: sha256, TBS_NO_CT_SHA256: tbsNoCTSHA256}
	}

	_, e := c.db.Exec(insertBuilder(values))
	if err, hasErr := e.(*pq.Error); hasErr {
		return err
	}

	return nil
}

func (c *logEntryWriter) insertAndWriteRecords(startIdx, endIdx int) {
	if startIdx >= endIdx {
		return
	}

	if err := c.insertRecords(startIdx, endIdx); err != nil {
		if endIdx - startIdx == 1 {
			return
		}

		log.Info(err)
		log.Infof("DB error, splitting insert from %d to %d in half", startIdx, endIdx)
		//TODO: check specific unique idx violation error
		splitIdx := startIdx + ((endIdx - startIdx) / 2)
		c.insertAndWriteRecords(startIdx, splitIdx)
		c.insertAndWriteRecords(splitIdx, endIdx)
	} else {
		//Successfully inserted records, write to disk
		c.WriteRecords(startIdx, endIdx)
	}
}

func (c *logEntryWriter) WriteRecords(startIdx, endIdx int) {
	for _, entry := range c.ctRecords[startIdx:endIdx] {
		chainBytes := make([]byte, 0)
		chainB64 := make([]string, len(entry.Chain))
		for i, c := range entry.Chain {
			chainBytes = append(chainBytes, c...)
			chainB64[i] = base64.StdEncoding.EncodeToString(c)
		}

		chainHash := fmt.Sprintf("%x", sha256.Sum256(chainBytes))
		var leafB64, leafHash, leafTBSnoCTfingerprint string
		if entry.Leaf.TimestampedEntry.EntryType == ct.X509LogEntryType {
			leafB64 = base64.StdEncoding.EncodeToString(entry.X509Cert.Raw)
			leafHash = entry.X509Cert.FingerprintSHA256.Hex()
			leafTBSnoCTfingerprint = entry.X509Cert.FingerprintNoCT.Hex()
		} else if entry.Leaf.TimestampedEntry.EntryType == ct.PrecertLogEntryType {
			leafB64 = base64.StdEncoding.EncodeToString(entry.Precert.Raw)
			leafHash = entry.Precert.TBSCertificate.FingerprintSHA256.Hex()
			leafTBSnoCTfingerprint = entry.Precert.TBSCertificate.FingerprintNoCT.Hex()
		}

		row := []string{
			leafHash,
			leafTBSnoCTfingerprint,
			leafB64,
			//TODO: Add leaf's parent spki+subject fingerprint
			chainHash,
			strings.Join(chainB64, "|"),
		}

		hashPrefix := leafHash[0:3]
		_, ok := c.writers[hashPrefix]
		if !ok {
			filename := hashPrefix + ".csv"
			filepath := filepath.Join(c.outputDir, filename)
			outFile, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Errorf("unable to open file: %s", filepath)
				log.Fatal(err)
			}
			csvFW := csvFileWriter{csvWriter: csv.NewWriter(outFile), osFile: outFile}
			c.writers[hashPrefix] = &csvFW
		}

		c.writers[hashPrefix].csvWriter.Write(row)
	}
}

func (c *logEntryWriter) insertAndWriteAllRecords() {
	c.insertAndWriteRecords(0, len(c.ctRecords))
}

func (c *logEntryWriter) WriteEntry(entry *ct.LogEntry) {
	if c.db == nil {
		log.Fatal("Must open logEntryWriter (logEntryWriter.Open()) before adding records")
	}

	c.ctRecords = append(c.ctRecords, entry)
	if len(c.ctRecords) == DB_INSERT_THRESHOLD {
		// insert records
		c.insertAndWriteAllRecords()
		c.ctRecords = make([]*ct.LogEntry, 0)
	}
}

func pushToFile(incoming <-chan *ct.LogEntry, wg *sync.WaitGroup, outputDirectory string) {
	defer wg.Done()

	if _, err := ioutil.ReadDir(outputDirectory); err != nil {
		log.Fatal(err)
	}

	writer := &logEntryWriter{
		outputDir: outputDirectory,
	}
	writer.Open()
	defer writer.Close()

	for entry := range incoming {
		writer.WriteEntry(entry)
	}
}
