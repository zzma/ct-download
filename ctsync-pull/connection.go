/*
 *  CTSync Daemon Copyright 2017 Regents of the University of Michigan
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
	log "github.com/sirupsen/logrus"
	"github.com/teamnsrg/zcrypto/ct/client"
)

type LogServerConnection struct {
	logClient  *client.LogClient
	treeSize   int64
	bucketSize int64
	start      int64
	end        int64
}

func merkleTreeSize(logClient *client.LogClient) (uint64, error) {
	treeHead, err := logClient.GetSTH()
	if err != nil {
		return 0, err
	}
	return treeHead.TreeSize, nil
}

func NewCTLogConnection(uri string, bucketSize int64) *LogServerConnection {
	var c LogServerConnection

	c.logClient = client.New(uri)
	if c.logClient == nil {
		log.Warnf("could not create connection to %s", uri)
		return nil
	}
	treeSize, err := merkleTreeSize(c.logClient)
	if err != nil {
		log.Warnf("could not get tree size from %s STH: %v", uri, err)
		return nil
	}
	c.treeSize = int64(treeSize)
	if bucketSize >= c.treeSize {
		c.bucketSize = c.treeSize
	} else {
		c.bucketSize = bucketSize
	}
	c.start = 0
	c.end = c.bucketSize
	return &c
}

func NewCTLogConnectionWithOffset(uri string, bucketSize int64, start int64) *LogServerConnection {
	c := NewCTLogConnection(uri, bucketSize)
	if c == nil {
		return nil
	}
	c.start = start
	c.end = start + c.bucketSize
	return c
}
