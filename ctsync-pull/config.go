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
	"bufio"
	"encoding/json"
	"io"
	"log"
	"os"

	"github.com/jinzhu/gorm"
)

type CTLogInfo struct {
	gorm.Model
	Name      string `json:"name" gorm:"unique"`
	BaseURL   string `json:"url" gorm:"unique"`
	LastIndex int64  `json:"starting_index"`
	BatchSize int64  `sql:"-" json:"batch_size"`
}

type Configuration []CTLogInfo

func readAndLoadConfiguration(filepath string, db *gorm.DB) (Configuration, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	return loadConfiguration(file, db)
}

func loadConfiguration(configFile io.Reader, db *gorm.DB) (Configuration, error) {
	res := Configuration{}
	scanner := bufio.NewScanner(configFile)
	for scanner.Scan() {
		parsed := CTLogInfo{}
		err := json.Unmarshal([]byte(scanner.Text()), &parsed)
		if err != nil {
			return nil, err
		}
		var logConfigFromDB CTLogInfo
		if db.Where("name = ?", parsed.Name).First(&logConfigFromDB); db.Error != nil {
			log.Fatalf("error in querying database: %s", db.Error)
		}
		parsed.LastIndex = logConfigFromDB.LastIndex
		res = append(res, parsed)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return res, nil
}
