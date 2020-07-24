package main

import (
	"database/sql"
	"flag"
	"fmt"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
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

	db, err := sql.Open("postgres", "user=ctdownloader dbname=ctdownload sslmode=disable")
	defer db.Close()
	if err != nil {
		log.Fatal(err)
	}


	for i := 0; i < rows; i++ {
		if i % 10000 == 0 {
			log.Infof("Inserted %d rows...", i)
		}
		md5, err := uuid.NewRandom()
		if err != nil {
			log.Fatal(err)
		}
		tbsnoctmd5, err := uuid.NewRandom()
		if err != nil {
			log.Fatal(err)
		}

		_, err = db.Exec("INSERT INTO downloaded_certs (MD5, TBS_NO_CT_MD5) VALUES ($1, $2)", md5, tbsnoctmd5)
		if err, ok := err.(*pq.Error); ok {
			log.Error("pq error:", err)
		}
	}
}
