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
	"encoding/binary"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
const (
	tpmPtManufacturer = 0x00000100 + 5  // PT_FIXED + offset of 5
	tpmPtVendorString = 0x00000100 + 6  // PT_FIXED + offset of 6
	tpmPtFwVersion1   = 0x00000100 + 11 // PT_FIXED + offset of 11
)

type TCGVendorID uint32

var vendors = map[TCGVendorID]string{
	1095582720: "AMD",
	1096043852: "Atmel",
	1112687437: "Broadcom",
	1229081856: "IBM",
	1213220096: "HPE",
	1297303124: "Microsoft",
	1229346816: "Infineon",
	1229870147: "Intel",
	1279610368: "Lenovo",
	1314082080: "National Semiconductor",
	1314150912: "Nationz",
	1314145024: "Nuvoton Technology",
	1363365709: "Qualcomm",
	1397576515: "SMSC",
	1398033696: "ST Microelectronics",
	1397576526: "Samsung",
	1397641984: "Sinosun",
	1415073280: "Texas Instruments",
	1464156928: "Winbond",
	1380926275: "Fuzhou Rockchip",
	1196379975: "Google",
}

func (id TCGVendorID) String() string {
	return vendors[id]
}

type Properties struct {
	ActiveSessionsMax       uint32
	AuthSessionsActive      uint32
	AuthSessionsActiveAvail uint32
	AuthSessionsLoaded      uint32
	AuthSessionsLoadedAvail uint32
	Family                  string
	Fips1402                bool
	FwMajor                 int64
	FwMinor                 int64
	LoadedCurves            uint32
	LockoutCounter          uint32
	LockoutInterval         uint32
	LockoutRecovery         uint32
	Manufacturer            string
	Model                   string
	MaxAuthFail             uint32
	Memory                  uint32
	NVIndexesDefined        uint32
	NVIndexesMax            uint32
	NVWriteRecovery         uint32
	PersistentAvail         uint32
	PersistentLoaded        uint32
	PersistentMin           uint32
	Revision                string
	TransientAvail          uint32
	TransientMin            uint32
	VendorID                string
}

func IsFIPS140_2(tpm transport.TPM) (bool, error) {
	modesResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTModes),
		PropertyCount: 1,
	}.Execute(tpm)
	if err != nil {
		return false, err
	}
	modes, err := modesResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return false, err
	}
	return modes.TPMProperty[0].Value == 1, nil
}

func FixedProperties(tpm transport.TPM) (*Properties, error) {
	activeSessionsMax, err := activeSessionsMax(tpm)
	if err != nil {
		return nil, err
	}
	persistentLoaded, err := persistentLoaded(tpm)
	if err != nil {
		return nil, err
	}
	persistentAvail, err := persistentAvail(tpm)
	if err != nil {
		return nil, err
	}
	persistentMin, err := persistentMin(tpm)
	if err != nil {
		return nil, err
	}
	transientMin, err := transientMin(tpm)
	if err != nil {
		return nil, err
	}
	transientAvail, err := transientAvail(tpm)
	if err != nil {
		return nil, err
	}
	authSessionsLoaded, err := authSessionsLoaded(tpm)
	if err != nil {
		return nil, err
	}
	authSessionsLoadedAvail, err := authSessionsLoadedAvail(tpm)
	if err != nil {
		return nil, err
	}
	authSessionsActive, err := authSessionsActive(tpm)
	if err != nil {
		return nil, err
	}
	authSessionsActiveAvail, err := authSessionsActiveAvail(tpm)
	if err != nil {
		return nil, err
	}
	family, err := family(tpm)
	if err != nil {
		return nil, err
	}
	fips1402, err := IsFIPS140_2(tpm)
	if err != nil {
		return nil, err
	}
	fwMajor, fwMinor, err := firmware(tpm)
	if err != nil {
		return nil, err
	}
	lockoutCounter, err := lockoutCounter(tpm)
	if err != nil {
		return nil, err
	}
	manufacturer, err := manufacturer(tpm)
	if err != nil {
		return nil, err
	}
	maxAuthFail, err := maxAuthFail(tpm)
	if err != nil {
		return nil, err
	}
	model, err := model(tpm)
	if err != nil {
		return nil, err
	}
	nvIndexesDefined, err := nvIndexesDefined(tpm)
	if err != nil {
		return nil, err
	}
	nvWriteRecovery, err := nvWriteRecovery(tpm)
	if err != nil {
		return nil, err
	}
	nvIndexesMax, err := nvIndexesMax(tpm)
	if err != nil {
		return nil, err
	}
	memory, err := memory(tpm)
	if err != nil {
		return nil, err
	}
	revision, err := revision(tpm)
	if err != nil {
		return nil, err
	}
	vendorID, err := vendorID(tpm)
	if err != nil {
		return nil, err
	}
	return &Properties{
		ActiveSessionsMax:       activeSessionsMax,
		AuthSessionsActive:      authSessionsActive,
		AuthSessionsActiveAvail: authSessionsActiveAvail,
		AuthSessionsLoaded:      authSessionsLoaded,
		AuthSessionsLoadedAvail: authSessionsLoadedAvail,
		Family:                  family,
		Fips1402:                fips1402,
		FwMajor:                 fwMajor,
		FwMinor:                 fwMinor,
		LockoutCounter:          lockoutCounter,
		Manufacturer:            manufacturer,
		MaxAuthFail:             maxAuthFail,
		Memory:                  memory,
		Model:                   model,
		NVIndexesDefined:        nvIndexesDefined,
		NVIndexesMax:            nvIndexesMax,
		NVWriteRecovery:         nvWriteRecovery,
		PersistentAvail:         persistentAvail,
		PersistentLoaded:        persistentLoaded,
		PersistentMin:           persistentMin,
		TransientAvail:          transientAvail,
		TransientMin:            transientMin,
		Revision:                revision,
		VendorID:                vendorID,
	}, nil
}

func memory(thetpm transport.TPM) (uint32, error) {
	memoryResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTMemory),
		PropertyCount: 1,
	}.Execute(thetpm)
	if err != nil {
		return 0, err
	}
	memory, err := memoryResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return memory.TPMProperty[0].Value, nil
}

func persistentLoaded(thetpm transport.TPM) (uint32, error) {
	persistentLoadedResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRPersistent),
		PropertyCount: 1,
	}.Execute(thetpm)
	if err != nil {
		return 0, err
	}
	persistentLoaded, err := persistentLoadedResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return persistentLoaded.TPMProperty[0].Value, nil
}

func persistentAvail(thetpm transport.TPM) (uint32, error) {
	persistentAvailResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRPersistentAvail),
		PropertyCount: 1,
	}.Execute(thetpm)
	if err != nil {
		return 0, err
	}
	persistentAvail, err := persistentAvailResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return persistentAvail.TPMProperty[0].Value, nil
}

func persistentMin(thetpm transport.TPM) (uint32, error) {
	persistentMinResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRPersistentMin),
		PropertyCount: 1,
	}.Execute(thetpm)
	if err != nil {
		return 0, err
	}
	persistentMin, err := persistentMinResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return persistentMin.TPMProperty[0].Value, nil
}

func transientMin(thetpm transport.TPM) (uint32, error) {
	transientLoadedResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRTransientMin),
		PropertyCount: 1,
	}.Execute(thetpm)
	if err != nil {
		return 0, err
	}
	transientLoaded, err := transientLoadedResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return transientLoaded.TPMProperty[0].Value, nil
}

func transientAvail(thetpm transport.TPM) (uint32, error) {
	transientAvailResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRTransientAvail),
		PropertyCount: 1,
	}.Execute(thetpm)
	if err != nil {
		return 0, err
	}
	transientAvail, err := transientAvailResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return transientAvail.TPMProperty[0].Value, nil
}

func activeSessionsMax(thetpm transport.TPM) (uint32, error) {
	activeSessionsMaxResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTActiveSessionsMax),
		PropertyCount: 1,
	}.Execute(thetpm)
	if err != nil {
		return 0, err
	}
	activeSessionsMax, err := activeSessionsMaxResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return activeSessionsMax.TPMProperty[0].Value, nil
}

func authSessionsActive(thetpm transport.TPM) (uint32, error) {
	authSessionsActiveResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRActive),
		PropertyCount: 1,
	}.Execute(thetpm)
	if err != nil {
		return 0, err
	}
	authSessionsActive, err := authSessionsActiveResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return authSessionsActive.TPMProperty[0].Value, nil
}

func authSessionsActiveAvail(thetpm transport.TPM) (uint32, error) {
	authSessionsActiveAvailResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRActiveAvail),
		PropertyCount: 1,
	}.Execute(thetpm)
	if err != nil {
		return 0, err
	}
	authSessionsActiveAvail, err := authSessionsActiveAvailResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return authSessionsActiveAvail.TPMProperty[0].Value, nil
}

func authSessionsLoaded(thetpm transport.TPM) (uint32, error) {
	authSessionsLoadedResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRLoaded),
		PropertyCount: 1,
	}.Execute(thetpm)
	if err != nil {
		return 0, err
	}
	authSessionsLoaded, err := authSessionsLoadedResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return authSessionsLoaded.TPMProperty[0].Value, nil
}

func authSessionsLoadedAvail(thetpm transport.TPM) (uint32, error) {
	authSessionsLoadedAvailResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRLoadedAvail),
		PropertyCount: 1,
	}.Execute(thetpm)
	if err != nil {
		return 0, err
	}
	authSessionsAvail, err := authSessionsLoadedAvailResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return authSessionsAvail.TPMProperty[0].Value, nil
}

func family(thetpm transport.TPM) (string, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTFamilyIndicator),
		PropertyCount: 1,
	}.Execute(thetpm)
	if err != nil {
		return "", err
	}
	family, err := response.CapabilityData.Data.TPMProperties()
	if err != nil {
		return "", err
	}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, family.TPMProperty[0].Value)
	return string(buf), nil
}

func firmware(thetpm transport.TPM) (int64, int64, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      tpmPtFwVersion1,
		PropertyCount: 1,
	}.Execute(thetpm)
	if err != nil {
		return 0, 0, err
	}
	firmware, err := response.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, 0, err
	}
	fw := firmware.TPMProperty[0].Value
	var fwMajor = int64((fw & 0xffff0000) >> 16)
	var fwMinor = int64(fw & 0x0000ffff)
	return fwMajor, fwMinor, nil
}

func lockoutCounter(thetpm transport.TPM) (uint32, error) {
	lockoutCounterResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTLockoutCounter),
		PropertyCount: 1,
	}.Execute(thetpm)
	if err != nil {
		return 0, err
	}
	lockoutCounter, err := lockoutCounterResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return lockoutCounter.TPMProperty[0].Value, nil
}

func manufacturer(thetpm transport.TPM) (string, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      tpmPtManufacturer,
		PropertyCount: 1,
	}.Execute(thetpm)
	if err != nil {
		return "", nil
	}
	manufacturer, err := response.CapabilityData.Data.TPMProperties()
	if err != nil {
		return "", err
	}
	var vendor = TCGVendorID(manufacturer.TPMProperty[0].Value)
	return vendor.String(), nil
}

func model(thetpm transport.TPM) (string, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTVendorTPMType),
		PropertyCount: 1,
	}.Execute(thetpm)
	if err != nil {
		return "", nil
	}
	model, err := response.CapabilityData.Data.TPMProperties()
	if err != nil {
		return "", err
	}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, model.TPMProperty[0].Value)
	return string(buf), nil
}

func maxAuthFail(thetpm transport.TPM) (uint32, error) {
	maxAuthFailResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTMaxAuthFail),
		PropertyCount: 1,
	}.Execute(thetpm)
	if err != nil {
		return 0, err
	}
	maxAuthFail, err := maxAuthFailResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return maxAuthFail.TPMProperty[0].Value, nil
}

func nvIndexesDefined(thetpm transport.TPM) (uint32, error) {
	nvIndexResponse, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRNVIndex),
		PropertyCount: 1,
	}.Execute(thetpm)
	if err != nil {
		return 0, err
	}
	nvIndex, err := nvIndexResponse.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return nvIndex.TPMProperty[0].Value, nil
}

func nvIndexesMax(thetpm transport.TPM) (uint32, error) {
	nvIndexesMaxResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTNVIndexMax),
		PropertyCount: 1,
	}.Execute(thetpm)
	if err != nil {
		return 0, err
	}
	nvIndexesMax, err := nvIndexesMaxResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return nvIndexesMax.TPMProperty[0].Value, nil
}

func nvWriteRecovery(thetpm transport.TPM) (uint32, error) {
	nvWriteRecoveryResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTNVWriteRecovery),
		PropertyCount: 1,
	}.Execute(thetpm)
	if err != nil {
		return 0, err
	}
	nvWriteRecovery, err := nvWriteRecoveryResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return nvWriteRecovery.TPMProperty[0].Value, nil
}

func revision(thetpm transport.TPM) (string, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTRevision),
		PropertyCount: 1,
	}.Execute(thetpm)
	if err != nil {
		return "", err
	}
	revision, err := response.CapabilityData.Data.TPMProperties()
	if err != nil {
		return "", err
	}
	rev := fmt.Sprintf("%04d", revision.TPMProperty[0].Value)
	major := strings.TrimLeft(rev[:2], "0")
	minor := rev[2:]
	return fmt.Sprintf("%s.%s", major, minor), nil
}

func vendorID(thetpm transport.TPM) (string, error) {
	var vendorString string
	props := []tpm2.TPMPT{
		tpm2.TPMPTVendorString1,
		tpm2.TPMPTVendorString2,
		tpm2.TPMPTVendorString3,
		tpm2.TPMPTVendorString4}

	for _, prop := range props {
		vendorResp, err := tpm2.GetCapability{
			Capability:    tpm2.TPMCapTPMProperties,
			Property:      uint32(prop),
			PropertyCount: 1,
		}.Execute(thetpm)
		if err != nil {
			return "", err
		}
		vendorStr, err := vendorResp.CapabilityData.Data.TPMProperties()
		if err != nil {
			return "", err
		}
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, vendorStr.TPMProperty[0].Value)
		vendorString += string(buf)
	}
	return vendorString, nil
}

func LogTPMInfo(tpm transport.TPM) error {
	caps, err := FixedProperties(tpm)
	if err != nil {
		return err
	}

	nvHandles, err := GetInUseNVIndices(tpm)

	if err != nil {
		return err
	}

	// Convert to hex
	hexNvHandles := make([]string, len(nvHandles))
	for idx := range nvHandles {
		hexNvHandles[idx] = fmt.Sprintf("0x%x", nvHandles[idx])
	}

	persistentHandles, err := GetInUsePersistentHandles(tpm)

	if err != nil {
		return err
	}

	// Convert to hex
	hexPersistentHandles := make([]string, len(persistentHandles))
	for i := range persistentHandles {
		hexPersistentHandles[i] = fmt.Sprintf("0x%x", persistentHandles[i])
	}

	slog.Info("TPM Information",
		"Manufacturer", caps.Manufacturer,
		"VendorID", caps.VendorID,
		"Family", caps.Family,
		"Revision", caps.Revision,
		"Firmware", fmt.Sprintf("%d.%d", caps.FwMajor, caps.FwMinor),
		"Memory", caps.PersistentLoaded,
		"Model", caps.Model,
		"FIPS140-2", caps.Fips1402,
		"MaxAuthFail", caps.MaxAuthFail,
		"LoadedCurves", caps.LockoutCounter,
		"AuthSessionsActive", caps.AuthSessionsActive,
		"AuthSessionsActiveAvail", caps.AuthSessionsActiveAvail,
		"AuthSessionsLoaded", caps.AuthSessionsLoaded,
		"AuthSessionsLoadedAvail", caps.AuthSessionsLoadedAvail,
		"LockoutCounter", caps.LockoutCounter,
		"LockoutInterval", caps.LockoutInterval,
		"LockoutRecovery", caps.LockoutRecovery,
		"NVIndexesDefined", caps.NVIndexesDefined,
		"NVIndexesMax", caps.NVIndexesMax,
		"NVWriteRecovery", caps.NVIndexesMax,
		"PersistentLoaded", caps.PersistentLoaded,
		"PersistentAvail", caps.PersistentAvail,
		"TransientMin", caps.TransientMin,
		"TransientAvail", caps.TransientAvail,
		"InUsePersistentHandles", hexPersistentHandles,
		"InUseNVIndices", hexNvHandles,
	)

	return nil
}
