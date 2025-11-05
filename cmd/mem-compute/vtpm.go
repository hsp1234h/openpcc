package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/google/go-tpm/tpmutil"
	"github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/tpm"
)

func setupSimulatorAttestationKey(thetpm transport.TPMCloser, handle tpmutil.Handle) error {
	public := tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			Restricted:          true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
	})

	pcrSelection := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{},
	}

	createSigningCommand := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      public,
		CreationPCR:   pcrSelection,
	}
	createSigningResponse, err := createSigningCommand.Execute(thetpm)
	if err != nil {
		return fmt.Errorf("failed to ak key: %w", err)
	}

	flushContext := tpm2.FlushContext{FlushHandle: createSigningResponse.ObjectHandle}
	defer func() {
		if _, err := flushContext.Execute(thetpm); err != nil {
			slog.Error("Failed to flush context", "err", err)
		}
	}()

	err = tpm.MaybeClearPersistentHandle(thetpm, handle)
	if err != nil {
		return fmt.Errorf("failed to clear persistent handle: %w", err)
	}

	err = tpm.PersistObject(
		thetpm,
		tpmutil.Handle(createSigningResponse.ObjectHandle),
		handle)

	if err != nil {
		return fmt.Errorf("could not persist attestation key to %#x: %w", handle, err)
	}

	return nil
}

type TPMOperator struct {
	device                  *TPMInMemorySimulator
	primaryKeyHandle        tpmutil.Handle
	childKeyHandle          tpmutil.Handle
	rekCreationTicketHandle tpmutil.Handle
	rekCreationHashHandle   tpmutil.Handle
	attestationKeyHandle    tpmutil.Handle
}

func (t *TPMOperator) SetupAttestationKey() error {
	thetpm, err := t.device.OpenDevice()
	if err != nil {
		return fmt.Errorf("could not connect to TPM: %w", err)
	}

	// can only be used with fake attestation as this key won't trace back to a trusted party.
	err = setupSimulatorAttestationKey(thetpm, t.attestationKeyHandle)
	if err != nil {
		return fmt.Errorf("could not setup simulator AK for handle: %w", err)
	}

	return nil
}

// SetupEncryptionKeys creates a primary key and a child key in the TPM.
// This method returns the CreateResponse object, see Table 12.1.2 - Table 20 — TPM2_Create Response
// in the TPM 2.0 specification (https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-3-Commands.pdf).
// The create response object contains the TPMT_TK_CREATION structure, which is
// necessary for proving the provenance of this key.
// This structure cannot be retrieved after key creation and
// so must be returned from this method and persisted somewhere until CertifyCreation is called.
func (t *TPMOperator) SetupEncryptionKeys() error {
	thetpm, err := t.device.OpenDevice()

	if err != nil {
		return fmt.Errorf("could not connect to TPM: %w", err)
	}

	createPrimaryKeyResponse, err := tpm.CreateECCPrimaryKey(thetpm)

	if err != nil {
		return fmt.Errorf("could not create primary key: %w", err)
	}

	flushPrimaryContext := tpm2.FlushContext{FlushHandle: createPrimaryKeyResponse.ObjectHandle}

	defer func() {
		if _, err := flushPrimaryContext.Execute(thetpm); err != nil {
			slog.Error("Failed to flush context", "err", err)
		}
	}()

	err = tpm.MaybeClearPersistentHandle(thetpm, t.primaryKeyHandle)

	if err != nil {
		return fmt.Errorf("error clearing handle 0x%x: %w", t.primaryKeyHandle, err)
	}

	err = tpm.PersistObject(
		thetpm,
		tpmutil.Handle(createPrimaryKeyResponse.ObjectHandle),
		t.primaryKeyHandle)

	if err != nil {
		return fmt.Errorf("could not persist primary key to 0x%x: %w", t.primaryKeyHandle, err)
	}

	// The golden PCR values are going to be whatever the state of the machine is at this point
	goldenPcrValues, err := tpm.PCRRead(thetpm, evidence.AttestPCRSelection)

	if err != nil {
		return err
	}

	authorizationPolicyDigest, err := tpm.GetTPMPCRPolicyDigest(
		thetpm,
		goldenPcrValues,
	)

	if err != nil {
		return fmt.Errorf("could not get desired policy digest: %w", err)
	}

	creationResponse, loadResponse, err := tpm.CreateECCEncryptionKey(
		thetpm,
		createPrimaryKeyResponse.ObjectHandle,
		*authorizationPolicyDigest,
	)

	if err != nil {
		return fmt.Errorf("could not create primary key: %w", err)
	}

	flushChildContext := tpm2.FlushContext{FlushHandle: loadResponse.ObjectHandle}

	defer func() {
		if _, err := flushChildContext.Execute(thetpm); err != nil {
			slog.Error("Failed to flush context", "err", err)
		}
	}()

	err = tpm.MaybeClearPersistentHandle(thetpm, t.childKeyHandle)

	if err != nil {
		return fmt.Errorf("error clearing handle 0x%x: %w", t.childKeyHandle, err)
	}

	err = tpm.PersistObject(
		thetpm,
		tpmutil.Handle(loadResponse.ObjectHandle),
		t.childKeyHandle)

	if err != nil {
		return fmt.Errorf("could not persist child key to 0x%x: %w", t.childKeyHandle, err)
	}

	slog.Info("Child key handle:", "handle", fmt.Sprintf("0x%x", t.childKeyHandle))

	err = tpm.MaybeClearNVIndex(thetpm, t.rekCreationTicketHandle)
	if err != nil {
		return fmt.Errorf("error clearing nv index 0x%x: %w", t.rekCreationTicketHandle, err)
	}

	err = tpm.WriteToNVRamNoAuth(thetpm,
		t.rekCreationTicketHandle,
		tpm2.Marshal(creationResponse.CreationTicket))

	if err != nil {
		return fmt.Errorf("could not write creation ticket to NVRAM: %w", err)
	}

	err = tpm.MaybeClearNVIndex(thetpm, t.rekCreationHashHandle)
	if err != nil {
		return fmt.Errorf("error clearing nv index 0x%x: %w", t.rekCreationHashHandle, err)
	}

	err = tpm.WriteToNVRamNoAuth(thetpm,
		t.rekCreationHashHandle,
		tpm2.Marshal(creationResponse.CreationHash))

	if err != nil {
		return fmt.Errorf("could not write creation hash to NVRAM: %w", err)
	}

	return nil
}

func (t *TPMOperator) Close() error {
	if t.device != nil {
		return t.device.Close()
	}
	return nil
}

type TPMInMemorySimulator struct {
	tpmHandle *transport.TPMCloser
}

func NewTPMInMemorySimulator() *TPMInMemorySimulator {
	return &TPMInMemorySimulator{}
}

func setupTPM(ctx context.Context, tpmOperator *TPMOperator) error {

	err := tpmOperator.SetupAttestationKey()
	if err != nil {
		return fmt.Errorf("failed to setup attestation key on TPM: %w", err)
	}

	err = tpmOperator.SetupEncryptionKeys()
	if err != nil {
		return fmt.Errorf("failed to setup encryption keys on TPM: %w", err)
	}

	slog.InfoContext(ctx, "TPM encryption keys configured successfully")
	return nil
}

func (t *TPMInMemorySimulator) OpenDevice() (transport.TPMCloser, error) {
	if t.tpmHandle != nil {
		return *t.tpmHandle, nil
	}

	tpm, err := simulator.OpenSimulator()
	if err != nil {
		return nil, err
	}
	slog.Info("Using TPM simulator")

	t.tpmHandle = &tpm

	return tpm, nil
}

func (t *TPMInMemorySimulator) Close() error {
	if t.tpmHandle != nil {
		return (*t.tpmHandle).Close()
	}
	return nil
}

type TPMConfig struct {
	// PrimaryKeyHandle is the handle in the TPM for the primary key
	PrimaryKeyHandle uint32 `yaml:"primary_key_handle"`
	// ChildKeyHandle is the handle in the TPM for the child key
	ChildKeyHandle uint32 `yaml:"child_key_handle"`
	// REKCreationTicketHandle is the NV index where the
	// request encryption key creation ticket is saved.
	REKCreationTicketHandle uint32 `yaml:"rek_creation_ticket_handle"`
	// REKCreationHashHandle is the NV index where the
	// request encryption key creation has is saved.
	REKCreationHashHandle uint32 `yaml:"rek_creation_hash_handle"`
	// AttestationKeyHandle is the handle where the OEM attestation key
	// is persisted
	AttestationKeyHandle uint32 `yaml:"attestation_key_handle"`
	// SimulatorCmdAddress is the address to reach out to the simulator's command. Leave blank for default
	SimulatorCmdAddress string `yaml:"simulator_cmd_address"`
	// SimulatorPlatformAddress is the address to reach out to the simulator's command. Leave blank for default
	SimulatorPlatformAddress string `yaml:"simulator_platform_address"`
}

func collectFakeTPMEvidence() (evidence.SignedEvidenceList, error) {
	ctx := context.Background()

	tpmConfig := &TPMConfig{
		ChildKeyHandle:          0x81000000,
		PrimaryKeyHandle:        0x81010001,
		REKCreationTicketHandle: 0x01c0000A,
		REKCreationHashHandle:   0x01c0000B,
		AttestationKeyHandle:    0x81000003,
	}

	tpmOperator := &TPMOperator{
		childKeyHandle:          0x81000000,
		primaryKeyHandle:        0x81010001,
		rekCreationTicketHandle: 0x01c0000A,
		rekCreationHashHandle:   0x01c0000B,
		attestationKeyHandle:    0x81000003,
		device:                  NewTPMInMemorySimulator(),
	}

	err := setupTPM(ctx, tpmOperator)
	if err != nil {
		slog.Error("TPM setup failed", "error", err)
		return evidence.SignedEvidenceList{}, err
	}
	defer func() {
		err = errors.Join(err, tpmOperator.Close())
	}()

	slog.InfoContext(ctx, "Preparing attestation evidence")

	evidenceList, err := collectEvidence(tpmConfig, tpmOperator.device)
	if err != nil {
		slog.Error("failed to attest", "error", err)
		return evidence.SignedEvidenceList{}, err
	}

	fmt.Println("EVINDE", evidenceList)

	return evidenceList, nil
}
