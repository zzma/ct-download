package main

import (
	"database/sql"
	"encoding/csv"
	"flag"
	"fmt"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
	"runtime"
)

var log *zap.SugaredLogger

func initLogger() {
	atom := zap.NewAtomicLevelAt(zap.InfoLevel)
	logger := zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()),
		zapcore.Lock(os.Stdout),
		atom), zap.AddCaller(), zap.AddStacktrace(zap.ErrorLevel))
	defer logger.Sync()
	log = logger.Sugar()
}

type DownloadedCert struct {
	md5        uuid.UUID `gorm:"column:MD5;type:uuid;"`
	tbsnoctmd5 uuid.UUID `gorm:"column:TBS_NO_CT_MD5;type:uuid;"`
}

func main() {
	initLogger()

	const usage = `ct-download: retrieve all certificates from CT
usage: %s 
Options:
`
	var rows int
	flag.IntVar(&rows, "r", 1000, "number of rows to add")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, usage, os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	cmdString := "user=ctdownloader dbname=ctdownload sslmode=disable"

	if runtime.GOOS == "linux" {
		cmdString = "user=ctdownloader dbname=ctdownload sslmode=disable host=/var/run/postgresql"
	}

	db, err := sql.Open("postgres", cmdString)
	defer db.Close()
	if err != nil {
		log.Fatal(err)
	}

	// Looks like it would take about 27 days to manually upload 2B records
	// assuming no degradation in performance

	// TODO: try to do bulk upload without indexes using /data2/nsrg/ct/sha256_and_tbs_noct_fp.csv
	// This should provide 1B+ records

	file, err := os.Create("temp-copy.csv")
	if err != nil {
		log.Fatal(err)
	}

	writer := csv.NewWriter(file)
	writer.Write([]string{"md5", "tbs_no_ct_md5"})

	for i := 0; i < rows; i++ {
		if i%10000 == 0 {
			log.Infof("Writing %d rows to temp file...", i)
		}

		hexStr := fmt.Sprintf("%032x", i)
		writer.Write([]string{hexStr, hexStr})
	}

	writer.Flush()
	file.Close()

	_, err = db.Exec("COPY downloaded_certs FROM '/Users/zanema/src/golang/src/github.com/zzma/ct-download/temp.csv' CSV HEADER")
	if err, ok := err.(*pq.Error); ok {
		log.Error("pq error:", err)
	}

}
