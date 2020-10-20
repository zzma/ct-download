package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
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
	"time"
)

type csvFileWriter struct {
	csvWriter *csv.Writer
	osFile    *os.File
}

type certHashes struct {
	SHA256           string
	TBS_NO_CT_SHA256 string
}

func selectBuilder(values []string) string {
	var str strings.Builder
	str.WriteString("SELECT sha256 FROM downloaded_certs WHERE sha256 IN (")

	for idx, sha256 := range values {
		str.WriteString("'\\x")
		str.WriteString(sha256)
		if idx == len(values)-1 {
			str.WriteString("')")
		} else {
			str.WriteString("',")
		}
	}

	return str.String()
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
	seenInBatch map[string]struct{}
	db        *sql.DB
	writers   map[string]*csvFileWriter
	outputDir string
	lastWriteTime time.Time
}

const DB_INSERT_THRESHOLD = 1000
const WRITER_TIMER_TIME = 10 * time.Second

func (c *logEntryWriter) Open() {
	c.ctRecords = make([]*ct.LogEntry, 0)
	c.seenInBatch = make(map[string]struct{})
	c.lastWriteTime = time.Now()

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
	c.insertAndWriteRecords()

	for _, writer := range c.writers {
		writer.csvWriter.Flush()
		writer.osFile.Close()
	}
	c.db.Close()
}

func (c *logEntryWriter) insertRecords(indexes []int) error {
	values := make([]*certHashes, len(indexes))

	for i, idx := range indexes {
		entry := c.ctRecords[idx]
		var sha256, tbsNoCTSHA256 string
		if entry.Leaf.TimestampedEntry.EntryType == ct.X509LogEntryType {
			sha256 = entry.X509Cert.FingerprintSHA256.Hex()
			tbsNoCTSHA256 = entry.X509Cert.FingerprintNoCT.Hex()
		} else if entry.Leaf.TimestampedEntry.EntryType == ct.PrecertLogEntryType {
			sha256 = entry.Precert.TBSCertificate.FingerprintSHA256.Hex()
			tbsNoCTSHA256 = entry.Precert.TBSCertificate.FingerprintNoCT.Hex()
		}

		values[i] = &certHashes{SHA256: sha256, TBS_NO_CT_SHA256: tbsNoCTSHA256}
	}

	_, e := c.db.Exec(insertBuilder(values))
	if err, hasErr := e.(*pq.Error); hasErr {
		return err
	}

	return nil
}

func (c *logEntryWriter) writeRecords(indexes []int) {
	for _, idx := range indexes {
		entry := c.ctRecords[idx]
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

func (c *logEntryWriter) insertAndWriteRecords() {
	if len(c.ctRecords) == 0 {
		return
	}
	// Check which records exist
	values := make([]string, len(c.ctRecords))
	for idx, ctRecord := range c.ctRecords {
		entry := ctRecord
		if entry.Leaf.TimestampedEntry.EntryType == ct.X509LogEntryType {
			values[idx] = entry.X509Cert.FingerprintSHA256.Hex()
		} else if entry.Leaf.TimestampedEntry.EntryType == ct.PrecertLogEntryType {
			values[idx] = entry.Precert.TBSCertificate.FingerprintSHA256.Hex()
		}
	}

	rows, e := c.db.Query(selectBuilder(values))
	defer rows.Close()
	if err, hasErr := e.(*pq.Error); hasErr {
		log.Error(err)
	}

	included := make(map[string]struct{})
	for rows.Next() {
		bytes := make([]byte, 32)
		err := rows.Scan(&bytes)
		if err != nil {
			log.Fatal(err)
		}
		sha256 := hex.EncodeToString(bytes)
		included[sha256] = struct{}{}
	}

	not_included := make([]int, 0)
	for idx, sha256 := range values {
		if _, ok := included[sha256]; !ok {
			not_included = append(not_included, idx)
		}
	}

	if len(not_included) == 0 {
		return
	}

	// Insert and write the ones that aren't
	if err := c.insertRecords(not_included); err != nil {
		log.Error(err)
		log.Info(not_included)
	}

	c.writeRecords(not_included)
}

func (c *logEntryWriter) WriteEntry(entry *ct.LogEntry) {
	if c.db == nil {
		log.Fatal("Must open logEntryWriter (logEntryWriter.Open()) before adding records")
	}

	var sha256Fingerprint string

	if entry.Leaf.TimestampedEntry.EntryType == ct.X509LogEntryType {
		sha256Fingerprint = entry.X509Cert.FingerprintSHA256.Hex()
	} else if entry.Leaf.TimestampedEntry.EntryType == ct.PrecertLogEntryType {
		hash := sha256.Sum256(entry.Precert.Raw)
		sha256Fingerprint = hex.EncodeToString(hash[:])
	}

	if _, seenAlready := c.seenInBatch[sha256Fingerprint]; seenAlready {
		return
	}

	c.seenInBatch[sha256Fingerprint] = struct{}{}
	c.ctRecords = append(c.ctRecords, entry)
	if len(c.ctRecords) == DB_INSERT_THRESHOLD || time.Now().After(c.lastWriteTime.Add(WRITER_TIMER_TIME)) {
		// insert records
		c.insertAndWriteRecords()
		c.ctRecords = make([]*ct.LogEntry, 0)
		c.lastWriteTime = time.Now()
		c.seenInBatch = make(map[string]struct{})
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
