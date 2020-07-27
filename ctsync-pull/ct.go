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
	"crypto/sha256"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/teamnsrg/zcrypto/ct"
	"github.com/teamnsrg/zcrypto/ct/scanner"

	log "github.com/sirupsen/logrus"

	zsearch "github.com/censys/censys-definitions/go/censys-definitions"
)

const kMaxFailedScans = 10

func extractMerkleTreeLeafFromLogEntry(entry *ct.LogEntry) (version string) {
	version = entry.Leaf.Version.String()
	return
}

func extractPrecertFromLogEntry(entry *ct.LogEntry) (raw []byte, chainWithoutLeaf [][]byte) {
	raw = entry.Precert.Raw
	if len(entry.Chain) > 0 {
		chainWithoutLeaf = convertASNCertToByteArray(entry.Chain[1:])
	}
	return
}

func extractCertificateFromLogEntry(entry *ct.LogEntry) (raw []byte, chainWithoutLeaf [][]byte) {
	raw = entry.X509Cert.Raw
	chainWithoutLeaf = convertASNCertToByteArray(entry.Chain)
	return
}

func buildExternalCertificatesFromBytes(raw []byte, chainWithoutLeaf [][]byte, entry *ct.LogEntry, server string) (out []*zsearch.ExternalCertificate) {
	serverNumber, ok := zsearch.CTServer_value[server]
	if !ok {
		log.Fatalf("unknown ct server name: %s", server)
	}
	serverValue := zsearch.CTServer(serverNumber)
	index := entry.Index
	timestamp := entry.Leaf.TimestampedEntry.Timestamp

	// Deal with the leaf (raw) first.
	var parentFingerprint []byte
	if len(chainWithoutLeaf) > 0 {
		sum := sha256.Sum256(chainWithoutLeaf[0])
		parentFingerprint = sum[:]
	}
	out = append(out, MakeExternalCertificateCT(raw, serverValue, index, timestamp, parentFingerprint, chainWithoutLeaf))

	// Also do every certificate in the chain
	for i, c := range chainWithoutLeaf {
		var parentFingerprint []byte
		chain := chainWithoutLeaf[i+1:]
		if len(chain) > 0 {
			sum := sha256.Sum256(chain[0])
			parentFingerprint = sum[:]
		}
		out = append(out, MakeExternalCertificateCTChain(c, serverValue, index, timestamp, parentFingerprint, chain))
	}
	return
}

func sendExternalCertificateThroughChannel(externalCertificate *zsearch.ExternalCertificate, out chan<- []byte) {
	if externalCertificate == nil {
		log.Fatal("received nil ExternalCertificate record")
	}
	externalCertificateBytes, err := proto.Marshal(externalCertificate)
	if err != nil {
		log.Fatalf("could not marshal ExternalCertificate protobuf: %s", err)
	}
	out <- externalCertificateBytes
}
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
