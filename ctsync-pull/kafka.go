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
	"fmt"
	"sync"
)

func pushToKafka(incoming <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	for message := range incoming {
		fmt.Println(string(message))

		//externalCertificate := zsearch.ExternalCertificate{}
		//err := proto.Unmarshal(message, &externalCertificate)
		//if err != nil {
		//	log.Fatal("could not unmarshal externalCertificate")
		//}
		//cert := externalCertificate.GetAnonymousRecord().GetCertificate()
		//x509cert,  _ := x509.ParseCertificate(cert.GetRaw())
		//jsonOut,  _ := json.Marshal(x509cert)
		//fmt.Println(string(jsonOut))
	}
	//log.Info("push to Kafka process ending")
}
