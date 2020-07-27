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
	"crypto/sha256"
	"time"

	"github.com/censys/censys-definitions/go/censys-definitions"
	"github.com/teamnsrg/zcrypto/ct"
	"github.com/teamnsrg/zcrypto/x509"
)

func convertASNCertToByteArray(chain []ct.ASN1Cert) (out [][]byte) {
	for _, val := range chain {
		out = append(out, val)
	}
	return out
}

func makeBaseAnonymousRecord(source censys_definitions.CertificateSource, chain [][]byte, parentSha256 []byte) *censys_definitions.AnonymousRecord {
	record := censys_definitions.AnonymousRecord{}
	record.Timestamp = time.Now().Unix()

	certificate := censys_definitions.Certificate{}
	certificate.Source = source
	certificate.PresentedChain = chain
	// Only add the parent hash if it is a hash, and not a null array
	if len(parentSha256) > 0 {
		certificate.Parents = append(certificate.Parents, parentSha256)
	}

	arCertificate := censys_definitions.AnonymousRecord_Certificate{}
	arCertificate.Certificate = &certificate
	record.OneofData = &arCertificate

	return &record
}

func makeUnparseableAnonymousRecord(raw []byte, source censys_definitions.CertificateSource, chain [][]byte, parentSha256 []byte, err error) *censys_definitions.AnonymousRecord {
	ar := makeBaseAnonymousRecord(source, chain, parentSha256)
	sha256Array := sha256.Sum256(raw)
	ar.Sha256Fp = sha256Array[:]

	certificate := ar.OneofData.(*censys_definitions.AnonymousRecord_Certificate).Certificate
	certificate.Raw = raw
	certificate.Sha256Fp = sha256Array[:]
	certificate.ParseStatus = censys_definitions.CertificateParseStatus_CERTIFICATE_PARSE_STATUS_FAIL
	certificate.ParseError = string(err.Error())

	return ar
}

func makeParsableAnonymousRecord(cert *x509.Certificate, source censys_definitions.CertificateSource, chain [][]byte, encoded_json_cert string, parentSha256 []byte) *censys_definitions.AnonymousRecord {
	ar := makeBaseAnonymousRecord(source, chain, parentSha256)
	ar.Sha256Fp = cert.FingerprintSHA256

	certificate := ar.OneofData.(*censys_definitions.AnonymousRecord_Certificate).Certificate
	certificate.Sha1Fp = cert.FingerprintSHA1
	certificate.Sha256Fp = cert.FingerprintSHA256
	certificate.IsPrecert = cert.IsPrecert
	certificate.Raw = cert.Raw
	certificate.ParseStatus = censys_definitions.CertificateParseStatus_CERTIFICATE_PARSE_STATUS_SUCCESS
	certificate.Parsed = encoded_json_cert

	return ar
}

func makeExternalCertificate(raw []byte, server censys_definitions.CTServer, index int64, timestamp uint64, parentSha256 []byte,
	chain [][]byte, source censys_definitions.CertificateSource) *censys_definitions.ExternalCertificate {

	externalCertificate := censys_definitions.ExternalCertificate{}
	parsed, err := x509.ParseCertificate(raw)
	if err != nil {
		externalCertificate.AnonymousRecord = makeUnparseableAnonymousRecord(raw, source, chain, parentSha256, err)
	} else {
		json_cert, err := parsed.MarshalJSON()
		if err != nil {
			externalCertificate.AnonymousRecord = makeUnparseableAnonymousRecord(raw, source, chain, parentSha256, err)
		}
		json_encoded := string(json_cert)
		externalCertificate.AnonymousRecord = makeParsableAnonymousRecord(parsed, source, chain, json_encoded, parentSha256)
	}
	externalCertificate.Source = source
	if source == censys_definitions.CertificateSource_CERTIFICATE_SOURCE_CT {
		externalCertificate.CtServer = server
		externalCertificate.CtStatus = new(censys_definitions.CTServerStatus)
		externalCertificate.CtStatus.Index = index
		externalCertificate.CtStatus.CtTimestamp = int64(timestamp) / 1000
		externalCertificate.CtStatus.PullTimestamp = time.Now().Unix()
	}
	return &externalCertificate
}

func MakeExternalCertificateCT(raw []byte, server censys_definitions.CTServer, index int64, timestamp uint64, parentSha256 []byte, chain [][]byte) *censys_definitions.ExternalCertificate {
	return makeExternalCertificate(raw, server, index, timestamp, parentSha256, chain, censys_definitions.CertificateSource_CERTIFICATE_SOURCE_CT)
}

func MakeExternalCertificateCTChain(raw []byte, server censys_definitions.CTServer, index int64, timestamp uint64, parentSha256 []byte, chain [][]byte) *censys_definitions.ExternalCertificate {
	return makeExternalCertificate(raw, server, index, timestamp, parentSha256, chain, censys_definitions.CertificateSource_CERTIFICATE_SOURCE_CT_CHAIN)
}
