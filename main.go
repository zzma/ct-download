package main

import (
	"database/sql"
	"flag"
	"fmt"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pkg/profile"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
	"runtime"
	"strings"
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
	sha256        uuid.UUID `gorm:"column:SHA256;type:uuid;"`
	tbsnoctsha256 uuid.UUID `gorm:"column:TBS_NO_CT_SHA256;type:uuid;"`
}

func insertBuilder(values [][]string) string {
	var str strings.Builder
	str.WriteString("INSERT INTO downloaded_certs (sha256,tbs_no_ct_sha256) VALUES")

	for idx, row := range values {
		if len(row) != 2 {
			log.Fatal("2 fields (sha256, tbs_no_ct_sha256) required")
		}
		str.WriteString(" (decode('")
		str.WriteString(row[0])
		str.WriteString("','hex'),decode('")
		str.WriteString(row[1])
		if idx == len(values)-1 {
			str.WriteString("','hex'))")
		} else {
			str.WriteString("','hex')),")
		}
	}

	return str.String()
}

func main() {
	initLogger()

	const usage = `ct-download: retrieve all certificates from CT
usage: %s 
Options:
`
	var rows int
	var memProfile, cpuProfile bool
	flag.IntVar(&rows, "r", 1000, "number of rows to add")
	flag.BoolVar(&memProfile, "mem-profile", false, "run memory profiling")
	flag.BoolVar(&cpuProfile, "cpu-profile", false, "run cpu profiling")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, usage, os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if cpuProfile {
		defer profile.Start(profile.CPUProfile, profile.ProfilePath(".")).Stop()
	}
	if memProfile {
		defer profile.Start(profile.MemProfile, profile.ProfilePath("."), profile.NoShutdownHook).Stop()
	}

	cmdString := "user=ctdownloader dbname=ctdownload sslmode=disable"

	if runtime.GOOS == "linux" {
		cmdString = "user=ctdownloader dbname=ctdownload sslmode=disable host=/var/run/postgresql"
	}

	db, err := sql.Open("postgres", cmdString)
	defer db.Close()
	if err != nil {
		log.Fatal(err)
	}

	values := make([][]string, 0)
	for i := 0; i < rows; i++ {
		if i%10000 == 0 {
			log.Infof("Writing %d rows...", i)
		}

		hexStr := fmt.Sprintf("%032x", i)
		row := []string{hexStr, hexStr}
		values = append(values, row)

		if i%100 == 0 {
			_, err = db.Exec(insertBuilder(values))
			if err, ok := err.(*pq.Error); ok {
				log.Error("pq error:", err)
			}
			values = make([][]string, 0)
		}

	}
}
