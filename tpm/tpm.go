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

package tpm

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/ccoveille/go-safecast"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

// See [ https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf ], section 6.12.
func GetTPMCapability(tpm transport.TPM, property tpm2.TPMPT) (*tpm2.TPMSTaggedProperty, error) {
	getCapabilitiesCommand := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(property),
		PropertyCount: 1,
	}
	getCapabilitiesResponse, err := getCapabilitiesCommand.Execute(tpm)
	if err != nil {
		return nil, err
	}

	tpmProperties, err := getCapabilitiesResponse.CapabilityData.Data.TPMProperties()
	if err != nil {
		return nil, err
	}

	var tpmsTaggedProperty *tpm2.TPMSTaggedProperty
	for _, p := range tpmProperties.TPMProperty {
		if p.Property == property {
			tpmsTaggedProperty = &p
			break
		}
	}

	if tpmsTaggedProperty == nil {
		return nil, fmt.Errorf("Property %x not found in capability data", property)
	}

	return tpmsTaggedProperty, nil
}

// GetHandles returns a list of handles of the specified type.
// See [ https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf ], section 7.
func GetHandles(tpm transport.TPM, handleType tpm2.TPMHT, nHandles uint32) ([]tpm2.TPMHandle, error) {
	getCapabilitiesCommand := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(handleType),
		PropertyCount: nHandles,
	}
	getCapabilitiesResponse, err := getCapabilitiesCommand.Execute(tpm)
	if err != nil {
		return nil, err
	}
	rawHandles, err := getCapabilitiesResponse.CapabilityData.Data.Handles()
	if err != nil {
		return nil, err
	}

	// This property, despite being singular, is indeed a list of handles indexes.
	return rawHandles.Handle, nil
}

// NVReadEXNoAuthorization reads the full (both public and private) contents of an NV index
// which has no authorization policy associated with it.
// NVRead commands are done in blocks of size TPMPTNVBufferMax.
// See similar method NVReadEx in tpm2/legacy library:
// https://github.com/google/go-tpm/blob/f37a5cab945313cd9e6276a7385145ebbaf5e2bd/legacy/tpm2/tpm2.go#L1429
func NVReadEXNoAuthorization(tpm transport.TPM, index tpmutil.Handle) ([]byte, error) {
	readPubRsp, err := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(index),
	}.Execute(tpm)

	if err != nil {
		return nil, err
	}

	nvPublicContents, err := readPubRsp.NVPublic.Contents()
	if err != nil {
		return nil, err
	}

	nvBufferMaxProperty, err := GetTPMCapability(tpm, tpm2.TPMPTNVBufferMax)
	if err != nil {
		return nil, err
	}

	blockSize := int(nvBufferMaxProperty.Value)

	outBuff := make([]byte, 0, int(nvPublicContents.DataSize))
	for len(outBuff) < int(nvPublicContents.DataSize) {
		readSize := blockSize
		if readSize > (int(nvPublicContents.DataSize) - len(outBuff)) {
			readSize = int(nvPublicContents.DataSize) - len(outBuff)
		}

		readRsp, err := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Name:   tpm2.HandleName(tpm2.TPMRHOwner),
				Auth:   NoAuth(),
			},
			NVIndex: tpm2.NamedHandle{
				Handle: tpm2.TPMHandle(index),
				Name:   readPubRsp.NVName,
			},
			Size:   uint16(readSize),     // #nosec
			Offset: uint16(len(outBuff)), // #nosec
		}.Execute(tpm)

		if err != nil {
			return nil, err
		}
		data := readRsp.Data.Buffer
		outBuff = append(outBuff, data...)
	}
	return outBuff, nil
}

func PersistObject(tpm transport.TPM, transientHandle tpmutil.Handle, targetHandle tpmutil.Handle) error {
	readRequest := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(transientHandle),
	}

	readResponse, err := readRequest.Execute(tpm)

	if err != nil {
		return err
	}

	evictControlCommand := tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: &tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(transientHandle),
			Name:   readResponse.Name,
		},
		PersistentHandle: tpm2.TPMHandle(targetHandle),
	}

	_, err = evictControlCommand.Execute(tpm)
	if err != nil {
		return err
	}

	return nil
}

func GetInUsePersistentHandles(tpm transport.TPM) ([]tpm2.TPMHandle, error) {
	getHandlesCommand := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(0x81000000),
		PropertyCount: 32,
	}

	getHandlesResponse, err := getHandlesCommand.Execute(tpm)
	if err != nil {
		return nil, err
	}

	rawHandles, err := getHandlesResponse.CapabilityData.Data.Handles()
	if err != nil {
		return nil, err
	}

	return rawHandles.Handle, nil
}

func GetInUseNVIndices(tpm transport.TPM) ([]tpm2.TPMHandle, error) {
	getHandlesCommand := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(0x01000000),
		PropertyCount: 32,
	}

	getHandlesResponse, err := getHandlesCommand.Execute(tpm)
	if err != nil {
		return nil, err
	}

	rawHandles, err := getHandlesResponse.CapabilityData.Data.Handles()
	if err != nil {
		return nil, err
	}

	return rawHandles.Handle, nil
}

func MaybeClearPersistentHandle(tpm transport.TPM, handle tpmutil.Handle) error {
	readCommand := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(handle),
	}
	_, err := readCommand.Execute(tpm)
	if err != nil {
		// Test error message
		if strings.Contains(err.Error(), "the handle is not correct for the use") {
			// Handle not found, nothing to do
			return nil
		}
		return fmt.Errorf("failed to read handle %x: %w", handle, err)
	}

	evictCommand := tpm2.EvictControl{
		Auth:             tpm2.TPMRHOwner,
		PersistentHandle: tpm2.TPMHandle(handle),
		ObjectHandle: &tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(handle),
			Name:   tpm2.HandleName(tpm2.TPMHandle(handle)),
		},
	}

	_, err = evictCommand.Execute(tpm)
	if err != nil {
		return fmt.Errorf("failed to evict handle %x: %w", handle, err)
	}

	return nil
}

func MaybeClearNVIndex(tpm transport.TPM, index tpmutil.Handle) error {
	readCommand := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(index),
	}
	_, err := readCommand.Execute(tpm)
	if err != nil {
		// Test error message
		if strings.Contains(err.Error(), "the handle is not correct for the use") {
			// Handle not found, nothing to do
			return nil
		}
		return fmt.Errorf("failed to read handle %x: %w", index, err)
	}

	evictCommand := tpm2.NVUndefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		NVIndex: tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(index),
			Name:   tpm2.HandleName(tpm2.TPMHandle(index)),
		},
	}

	_, err = evictCommand.Execute(tpm)
	if err != nil {
		return fmt.Errorf("failed to evict handle %x: %w", index, err)
	}

	return nil
}

// CreateECCPrimaryKey creates an ECC primary key and persists it in the TPM.
func CreateECCPrimaryKey(tpm transport.TPM) (*tpm2.CreatePrimaryResponse, error) {
	keyPublicInfo := tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			Restricted:          true,
			Decrypt:             true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP256,
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
			},
		),
	})

	pcrSelection := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{},
	}

	createPrimaryRequest := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      keyPublicInfo,
		CreationPCR:   pcrSelection,
	}

	createPrimaryResponse, err := createPrimaryRequest.Execute(tpm)

	if err != nil {
		return nil, err
	}

	return createPrimaryResponse, nil
}

func CreateECCEncryptionKey(
	tpm transport.TPM,
	primaryKeyHandle tpm2.TPMHandle,
	authPolicy []byte,
) (*tpm2.CreateResponse, *tpm2.LoadResponse, error) {
	keyPublicInfo := tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        false,
			Decrypt:             true,
			AdminWithPolicy:     true,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: authPolicy,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP256,
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgNull,
				},
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDH,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDH,
						&tpm2.TPMSKeySchemeECDH{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
			},
		),
	})

	readPrimaryPublicRequest := tpm2.ReadPublic{
		ObjectHandle: primaryKeyHandle,
	}

	readPrimaryPublicResponse, err := readPrimaryPublicRequest.Execute(tpm)
	if err != nil {
		return nil, nil, err
	}

	createRequest := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{
			Handle: primaryKeyHandle,
			Name:   readPrimaryPublicResponse.Name,
		},
		InPublic: keyPublicInfo,
	}

	createResponse, err := createRequest.Execute(tpm)
	if err != nil {
		return nil, nil, err
	}

	loadRequest := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: primaryKeyHandle,
			Name:   readPrimaryPublicResponse.Name,
		},
		InPrivate: createResponse.OutPrivate,
		InPublic:  createResponse.OutPublic,
	}

	loadResponse, err := loadRequest.Execute(tpm)
	if err != nil {
		return nil, nil, err
	}

	return createResponse, loadResponse, nil
}

func CertifyCreationKey(tpm transport.TPM,
	signingKeyHandle tpmutil.Handle,
	creationTicket tpm2.TPMTTKCreation,
	creationHash tpm2.TPM2BDigest,
	targetKeyHandle tpmutil.Handle,

) (*tpm2.CertifyCreationResponse, error) {
	inScheme := tpm2.TPMTSigScheme{
		Scheme: tpm2.TPMAlgRSASSA,
		Details: tpm2.NewTPMUSigScheme(
			tpm2.TPMAlgRSASSA,
			&tpm2.TPMSSchemeHash{
				HashAlg: tpm2.TPMAlgSHA256,
			},
		),
	}

	readAttestationKeyPublicRequest := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(signingKeyHandle),
	}

	readAttestationKeyPublicResponse, err := readAttestationKeyPublicRequest.Execute(tpm)

	if err != nil {
		return nil, fmt.Errorf("failed to read attestation key at handle (%x): %w", signingKeyHandle, err)
	}

	readTargetKeyPublicRequest := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(targetKeyHandle),
	}

	readTargetKeyPublicResponse, err := readTargetKeyPublicRequest.Execute(tpm)

	if err != nil {
		return nil, fmt.Errorf("failed to read target key: %w", err)
	}

	certifyCreationRequest := tpm2.CertifyCreation{
		SignHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(signingKeyHandle),
			Name:   readAttestationKeyPublicResponse.Name,
			// We assume there is no authorization policy on associated with the AK.
			Auth: NoAuth(),
		},
		ObjectHandle: tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(targetKeyHandle),
			Name:   readTargetKeyPublicResponse.Name,
		},
		InScheme:       inScheme,
		CreationTicket: creationTicket,
		CreationHash:   creationHash,
	}

	certifyCreationResponse, err := certifyCreationRequest.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to execute CertifyCreation command: %w", err)
	}

	return certifyCreationResponse, nil
}

func WriteToNVRamNoAuth(
	tpm transport.TPM,
	nvRAMIndex tpmutil.Handle,
	data []byte,
) error {
	lenU16, err := safecast.ToUint16(len(data))

	if err != nil {
		return fmt.Errorf("failed to cast length of data to uint16: %w", err)
	}

	slog.Info("Writing to NV", "len", lenU16, "index", nvRAMIndex)

	def := tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex: tpm2.TPMHandle(nvRAMIndex),
				NameAlg: tpm2.TPMAlgSHA256,
				Attributes: tpm2.TPMANV{
					OwnerWrite: true,
					OwnerRead:  true,
					AuthWrite:  true,
					AuthRead:   true,
					NT:         tpm2.TPMNTOrdinary,
					NoDA:       true,
				},
				DataSize: lenU16,
			}),
	}

	_, err = def.Execute(tpm)

	if (err != nil) && !strings.Contains(err.Error(), "TPM_RC_NV_DEFINED") {
		return err
	}

	pub, err := def.PublicInfo.Contents()
	if err != nil {
		return err
	}
	nvName, err := tpm2.NVName(pub)
	if err != nil {
		return err
	}

	prewrite := tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
			Auth:   NoAuth(),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
		},
		Data: tpm2.TPM2BMaxNVBuffer{
			Buffer: data,
		},
		Offset: 0,
	}

	_, err = prewrite.Execute(tpm)
	if err != nil {
		return err
	}

	return nil
}

// NoAuth returns an authorization session with no requirements.
// Most of the TPM2 commands require an authorization session
// so we need to provide one like this even if it seems not relevant.
func NoAuth() tpm2.Session {
	return tpm2.PasswordAuth(nil)
}

func pcrSelectionFromDesiredPcrValuesMap(
	pcrValues map[uint32][]byte,
) tpm2.TPMLPCRSelection {
	specifiedPcrs := make([]uint, 0, len(pcrValues))
	for k := range pcrValues {
		specifiedPcrs = append(specifiedPcrs, uint(k))
	}

	sort.Slice(specifiedPcrs, func(i, j int) bool {
		return specifiedPcrs[i] < specifiedPcrs[j]
	})

	return tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(specifiedPcrs...),
			},
		},
	}
}

// See https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-1-Version-184_pub.pdf 15.5
// The list of selectors is processed in order. The selected PCR are concatenated, with the lowest numbered PCR
// in the first selector being the first in the list and the highest numbered PCR in the last selector being the last ..
// TPM2_PolicyPCR() digest the concatenation of PCR
func pcrDigestFromDesiredPcrValuesMap(
	pcrValues map[uint32][]byte,
) [32]byte {
	// Concatenate the pcrValues by natural sorted ordering of the specifiedPcrs
	// Get all specifiedPcrs from the map
	specifiedPcrs := make([]uint32, 0, len(pcrValues))
	for k := range pcrValues {
		specifiedPcrs = append(specifiedPcrs, k)
	}

	// Sort the keys
	sort.Slice(specifiedPcrs, func(i, j int) bool {
		return specifiedPcrs[i] < specifiedPcrs[j]
	})

	// Calculate total length needed for the result
	totalLen := 0
	for _, k := range specifiedPcrs {
		totalLen += len(pcrValues[k])
	}

	// Allocate the result slice with the correct size
	concatenatedDesiredPcrValues := make([]byte, 0, totalLen)

	// Concatenate byte arrays in sorted order
	for _, k := range specifiedPcrs {
		concatenatedDesiredPcrValues = append(concatenatedDesiredPcrValues, pcrValues[k]...)
	}

	return sha256.Sum256(concatenatedDesiredPcrValues)
}

// This uses a trial policy session to get the policy digest for the given PCR selection.
// This function is using the real TPM to compute the policy digest, and so can be used to confirm
// that a software implementation of the policy digest is correct.
func GetTPMPCRPolicyDigest(
	tpm transport.TPM,
	pcrValues map[uint32][]byte,

) (*[]byte, error) {
	sess, cleanup, err := tpm2.PolicySession(tpm, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := cleanup(); err != nil {
			slog.Error("failed to cleanup tpm session", "err", err)
		}
	}()

	pcrSelection := pcrSelectionFromDesiredPcrValuesMap(pcrValues)
	pcrDigest := pcrDigestFromDesiredPcrValuesMap(pcrValues)

	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		PcrDigest:     tpm2.TPM2BDigest{Buffer: pcrDigest[:]},
		Pcrs:          pcrSelection,
	}.Execute(tpm)
	if err != nil {
		return nil, err
	}

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(tpm)
	if err != nil {
		return nil, err
	}
	_, err = tpm2.FlushContext{FlushHandle: sess.Handle()}.Execute(tpm)
	if err != nil {
		return nil, err
	}
	return &pgd.PolicyDigest.Buffer, nil
}

// This uses a software implementation of to get the policy digest for the given PCR selection.
// This is used on the client side to make the policy transparent to the relying party.
func GetSoftwarePCRPolicyDigest(
	pcrValues map[uint32][]byte,
) (*[]byte, error) {
	calculator, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return nil, err
	}
	pcrSelection := pcrSelectionFromDesiredPcrValuesMap(pcrValues)
	pcrHash := pcrDigestFromDesiredPcrValuesMap(pcrValues)

	policy := tpm2.PolicyPCR{
		PcrDigest: tpm2.TPM2BDigest{
			Buffer: pcrHash[:],
		},
		Pcrs: pcrSelection,
	}

	if err := policy.Update(calculator); err != nil {
		return nil, err
	}

	return &calculator.Hash().Digest, nil
}

func PCRPolicySession(
	tpm transport.TPM,
	desiredPcrValues map[uint32][]byte,
) (s tpm2.Session, sessionCleanup func() error, err error) {
	trialSession, closer, err := tpm2.PolicySession(tpm, tpm2.TPMAlgSHA256, 16)

	if err != nil {
		return nil, nil, err
	}

	pcrSelection := pcrSelectionFromDesiredPcrValuesMap(desiredPcrValues)
	pcrHash := pcrDigestFromDesiredPcrValuesMap(desiredPcrValues)

	_, err = tpm2.PolicyPCR{
		PolicySession: trialSession.Handle(),
		Pcrs:          pcrSelection,
		PcrDigest: tpm2.TPM2BDigest{
			Buffer: pcrHash[:],
		},
	}.Execute(tpm)

	if err != nil {
		return nil, nil, err
	}

	return trialSession, closer, nil
}

func getNonzeroBitIndices(data []byte) ([]uint, error) {
	var indices []uint

	for byteIndex, b := range data {
		for bitIndex := uint(0); bitIndex < 8; bitIndex++ {
			if b&(1<<bitIndex) != 0 {
				byteIndexUint, err := safecast.ToUint(byte(byteIndex))
				if err != nil {
					return nil, err
				}
				globalBitIndex := byteIndexUint*8 + bitIndex
				indices = append(indices, globalBitIndex)
			}
		}
	}

	return indices, nil
}

func PCRRead(tpm transport.TPM, pcrs []uint) (map[uint32][]byte, error) {
	pcrValues := make(map[uint32][]byte)
	// TPM2_PCRRead only allows us to read 8 PCRs at a time, so we need to chunk the input pcrs
	// in chunks of 8 or less
	for i := 0; i < len(pcrs); i += 8 {
		end := i + 8
		if end > len(pcrs) {
			end = len(pcrs)
		}
		pcrSelectionBytes := tpm2.PCClientCompatible.PCRs(pcrs[i:end]...)
		pcrSelection := tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					PCRSelect: pcrSelectionBytes,
					Hash:      tpm2.TPMAlgSHA256,
				},
			},
		}

		// Note: one invocation of PCRRead seems to only read 8 PCRs at a time
		// even if you pass a selection that indicates more than 8.
		// There wont be an error message though, it will just silently drop one of
		// the PCRs from the response.
		readRequest := tpm2.PCRRead{
			PCRSelectionIn: pcrSelection,
		}

		readResponse, err := readRequest.Execute(tpm)

		if err != nil {
			return nil, err
		}

		nonzeroBitIndices, err := getNonzeroBitIndices(pcrSelectionBytes)
		if err != nil {
			return nil, err
		}

		for idx, pcrIndex := range nonzeroBitIndices {
			pcrIndexSafe, err := safecast.ToUint32(pcrIndex)
			if err != nil {
				return nil, err
			}
			pcrValues[pcrIndexSafe] = readResponse.PCRValues.Digests[idx].Buffer
		}
	}

	return pcrValues, nil
}
