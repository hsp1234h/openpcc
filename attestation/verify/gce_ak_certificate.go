// Copyright 2025 Nonvolatile Inc. d/b/a Confident Security

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package verify

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	ev "github.com/openpcc/openpcc/attestation/evidence"

	pb "github.com/google/go-tpm-tools/proto/attest"
)

// Source https://github.com/google/go-tpm-tools/blob/main/server/verify.go
var OidExtensionSubjectAltName = []int{2, 5, 29, 17}
var cloudComputeInstanceIdentifierOID asn1.ObjectIdentifier = []int{1, 3, 6, 1, 4, 1, 11129, 2, 1, 21}

type gceSecurityProperties struct {
	SecurityVersion int64 `asn1:"explicit,tag:0,optional"`
	IsProduction    bool  `asn1:"explicit,tag:1,optional"`
}

type gceInstanceInfo struct {
	Zone               string `asn1:"utf8"`
	ProjectNumber      int64
	ProjectID          string `asn1:"utf8"`
	InstanceID         int64
	InstanceName       string                `asn1:"utf8"`
	SecurityProperties gceSecurityProperties `asn1:"explicit,optional"`
}

func GetInstanceInfo(cert *x509.Certificate) (*pb.GCEInstanceInfo, error) {
	extensions := cert.Extensions
	var rawInfo []byte
	for _, ext := range extensions {
		if ext.Id.Equal(cloudComputeInstanceIdentifierOID) {
			rawInfo = ext.Value
			break
		}
	}

	// If GCE Instance Info extension is not found.
	if len(rawInfo) == 0 {
		return nil, errors.New("GCE Instance Information Extension not found")
	}

	info := gceInstanceInfo{}
	if _, err := asn1.Unmarshal(rawInfo, &info); err != nil {
		return nil, fmt.Errorf("failed to parse GCE Instance Information Extension: %w", err)
	}

	// TODO: Remove when fields are changed to uint64.
	if info.ProjectNumber < 0 || info.InstanceID < 0 || info.SecurityProperties.SecurityVersion < 0 {
		return nil, errors.New("negative integer fields found in GCE Instance Information Extension")
	}

	// Check production.
	if !info.SecurityProperties.IsProduction {
		return nil, errors.New("GCE Instance Information Extension is not production")
	}

	return &pb.GCEInstanceInfo{
		Zone:          info.Zone,
		ProjectId:     info.ProjectID,
		ProjectNumber: uint64(info.ProjectNumber),
		InstanceName:  info.InstanceName,
		InstanceId:    uint64(info.InstanceID),
	}, nil
}

func makePool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}

// VerifyAKCert checks a given Attestation Key certificate against the provided
// root and intermediate CAs.
// Source: https://github.com/google/go-tpm-tools/blob/main/server/verify.go
//
//revive:disable:exported
func VerifyAKCert(akCert *x509.Certificate, trustedRootCerts []*x509.Certificate, intermediateCerts []*x509.Certificate) error {
	if akCert == nil {
		return errors.New("failed to validate AK Cert: received nil cert")
	}
	if len(trustedRootCerts) == 0 {
		return errors.New("failed to validate AK Cert: received no trusted root certs")
	}

	// We manually handle the SAN extension because x509 marks it unhandled if
	// SAN does not parse any of DNSNames, EmailAddresses, IPAddresses, or URIs.
	// https://cs.opensource.google/go/go/+/master:src/crypto/x509/parser.go;l=668-678
	exts := make([]asn1.ObjectIdentifier, 0, len(akCert.UnhandledCriticalExtensions))
	for _, ext := range akCert.UnhandledCriticalExtensions {
		if ext.Equal(OidExtensionSubjectAltName) {
			continue
		}
		exts = append(exts, ext)
	}
	akCert.UnhandledCriticalExtensions = exts

	x509Opts := x509.VerifyOptions{
		Roots:         makePool(trustedRootCerts),
		Intermediates: makePool(intermediateCerts),
		// The default key usage (ExtKeyUsageServerAuth) is not appropriate for
		// an Attestation Key: ExtKeyUsage of
		// - https://oidref.com/2.23.133.8.1
		// - https://oidref.com/2.23.133.8.3
		// https://pkg.go.dev/crypto/x509#VerifyOptions
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := akCert.Verify(x509Opts); err != nil {
		return fmt.Errorf("certificate did not chain to a trusted root: %w", err)
	}

	return nil
}

//revive:enable:exported

func GceAkCertificate(
	intermediateCertificate x509.Certificate,
	signedEvidencePiece *ev.SignedEvidencePiece,
) (*x509.Certificate, *pb.GCEInstanceInfo, error) {
	akCert, err := x509.ParseCertificate(signedEvidencePiece.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse GCE AK Certificate: %w", err)
	}

	rootCert, err := GetGCEEKAKRootCert()

	if err != nil {
		return nil, nil, fmt.Errorf("failed to get GCE AK Root Certificate: %w", err)
	}

	intermediateCerts := []*x509.Certificate{&intermediateCertificate}

	rootCerts := []*x509.Certificate{rootCert}

	err = VerifyAKCert(
		akCert,
		rootCerts,
		intermediateCerts,
	)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify GCE AK Certificate: %w", err)
	}

	info, err := GetInstanceInfo(akCert)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to get GCE Instance Info: %w", err)
	}

	_, ok := akCert.PublicKey.(*rsa.PublicKey)

	if !ok {
		return nil, nil, errors.New("failed to get RSA Public Key from GCE AK Certificate")
	}

	return akCert, info, nil
}
