/*
 *  CTSync Pull Daemon Copyright 2017 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package main

import (
	"sync"
	"time"

	"github.com/teamnsrg/zcrypto/ct"
	"github.com/teamnsrg/zcrypto/ct/scanner"

	log "github.com/sirupsen/logrus"
)

const kMaxFailedScans = 10

func bindFoundBothCertToChannel(out chan *ct.LogEntry) func(*ct.LogEntry, string) {
	return func(entry *ct.LogEntry, server string) {
		out <- entry
	}
}

func pullFromCT(l CTLogInfo, externalCertificateOut chan *ct.LogEntry, updater chan int64, logInfoOut chan CTLogInfo, numMatch int, numFetch int, wg *sync.WaitGroup, running *runState) {
	defer wg.Done()
	failedScanCount := 0
	for {
		if !running.checkRunning() {
			log.Infof("%s: stopping", l.Name)
			break
		}
		if failedScanCount >= kMaxFailedScans {
			log.Errorf("%s: reached max failed scans (%d)", l.Name, failedScanCount)
			running.stopRunning()
			continue
		}
		log.Infof("%s: pulling from CT log", l.Name)
		logConnection := NewCTLogConnectionWithOffset(l.BaseURL, l.BatchSize, l.LastIndex)
		if logConnection == nil {
			log.Infof("%s: could not connect to log", l.Name)
			time.Sleep(time.Second * 60)
			continue
		}
		if l.LastIndex == logConnection.treeSize {
			log.Infof("%s: synchronized up to treeSize", l.Name)
			time.Sleep(time.Second * 60)
			continue
		}
		count := l.BatchSize * int64(numFetch)
		maxIndex := l.LastIndex + count
		if logConnection.treeSize < maxIndex {
			maxIndex = logConnection.treeSize
		}
		scanOpts := scanner.ScannerOptions{
			Matcher:       &scanner.MatchAll{},
			PrecertOnly:   false,
			BatchSize:     l.BatchSize,
			NumWorkers:    numMatch,
			ParallelFetch: numFetch,
			StartIndex:    l.LastIndex,
			Quiet:         true,
			Name:          l.Name,
			MaximumIndex:  maxIndex,
		}
		s := scanner.NewScanner(logConnection.logClient, scanOpts, logger)
		foundCert := bindFoundBothCertToChannel(externalCertificateOut)
		foundPrecert := bindFoundBothCertToChannel(externalCertificateOut)

		lastIndex, err := s.Scan(foundCert, foundPrecert, updater)
		if err != nil {
			log.Errorf("%s: scan failed: %s", l.Name, err)
			failedScanCount++
			time.Sleep(time.Second * 60)
			continue
		}
		failedScanCount = 0
		l.LastIndex = lastIndex //CT API doesn't use updater channel once scan is finished
		logInfoOut <- l
		log.Infof("%s: finished scan through %d", l.Name, maxIndex)
		time.Sleep(time.Second * 5)
	}
}
