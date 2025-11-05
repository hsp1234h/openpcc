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

package statements

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openpcc/openpcc/transparency"
)

const ImageManifestPredicateType = "https://confident.security/v2/image-manifest"

type TransparencyVerifier interface {
	VerifyStatementWithProcessor(b []byte, processor transparency.PredicateProcessor, identity transparency.IdentityPolicy) (*transparency.Statement, transparency.BundleMetadata, error)
}

func VerifyImageManifestBundle(b []byte, v TransparencyVerifier, idPolicy transparency.IdentityPolicy) (*transparency.Statement, transparency.BundleMetadata, error) {
	return v.VerifyStatementWithProcessor(b, func(s *transparency.Statement) ([]byte, error) {
		imageManifest, err := ToImageManifest(s)
		if err != nil {
			return nil, fmt.Errorf("failed to parse image manifest: %w", err)
		}
		if imageManifest.CustomData == nil {
			return nil, errors.New("no custom data in image manifest")
		}
		return []byte(imageManifest.ArtifactID), nil
	}, idPolicy)
}

func ToImageManifest(statement *transparency.Statement) (*ImageManifest, error) {
	err := statement.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid statement: %w", err)
	}

	if statement.PredicateType != ImageManifestPredicateType {
		return nil, fmt.Errorf("invalid predicate type. want %s, got %s", ImageManifestPredicateType, statement.PredicateType)
	}

	return parseImageManifestFromPredicate(statement.Predicate)
}

// PackerManifest contains *all* image build manifests (and additional details) outputted
// by a completed Packer build.
type PackerManifest struct {
	Builds      []ImageManifest `json:"builds"`
	LastRunUUID string          `json:"last_run_uuid"`
}

// ImageManifest represents a single image build outputted by Packer, including build-specific data.
type ImageManifest struct {
	Name          string           `json:"name"`
	BuilderType   string           `json:"builder_type"`
	BuildTime     int64            `json:"build_time"`
	Files         any              `json:"files"`
	ArtifactID    string           `json:"artifact_id"`
	PackerRunUUID string           `json:"packer_run_uuid"`
	CustomData    *BuildCustomData `json:"custom_data,omitempty"`
}

// BuildCustomData contains build-specific data, such as kernel command lines and GPT layout.
type BuildCustomData struct {
	BuildEnv       map[string]string `json:"build_env"`
	KernelCmdlines []KernelCmdline   `json:"kernel_cmdlines"`
	GPTLayout      string            `json:"gpt_layout"`
}

// KernelCmdline represents a single kernel command line.
type KernelCmdline struct {
	RO                           *string `json:"ro,omitempty"`
	Recovery                     *string `json:"recovery,omitempty"`
	NoModeSet                    *string `json:"nomodeset,omitempty"`
	DisUcodeLdr                  *string `json:"dis_ucode_ldr,omitempty"`
	RdDm                         string  `json:"rd.dm"`
	SystemdVerity                string  `json:"systemd.verity"`
	LSM                          string  `json:"lsm"`
	AppArmor                     string  `json:"apparmor"`
	SELinux                      string  `json:"selinux"`
	Root                         string  `json:"root"`
	ConfsecRoot                  string  `json:"confsec.root"`
	ConfsecEFI                   string  `json:"confsec.efi"`
	ConfsecCryptGit              string  `json:"confsec.crypt.git"`
	ConfsecCryptBuildID          string  `json:"confsec.crypt.build_id"`
	ConfsecCryptHardeningScope   string  `json:"confsec.crypt.hardening_scope"`
	ConfsecCryptDebugScope       string  `json:"confsec.crypt.debug_scope"`
	ConfsecCryptOptimizeDisk     string  `json:"confsec.crypt.optimize_disk"`
	ConfsecOpt                   string  `json:"confsec.opt"`
	ConfsecComputeGit            string  `json:"confsec.compute.git"`
	ConfsecComputeBuildID        string  `json:"confsec.compute.build_id"`
	ConfsecComputeHardeningScope string  `json:"confsec.compute.hardening_scope"`
	ConfsecComputeDebugScope     string  `json:"confsec.compute.debug_scope"`
	ConfsecComputeOptimizeDisk   string  `json:"confsec.compute.optimize_disk"`
	Console                      string  `json:"console,omitempty"`
}

func FromImageManifest(m *ImageManifest) (*transparency.Statement, error) {
	if m.CustomData == nil {
		return nil, errors.New("no custom data in image manifest")
	}

	subject := map[string][]byte{
		"image-manifest": []byte(m.ArtifactID),
	}

	msg, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal image manifest to json: %w", err)
	}

	predicate := map[string]any{
		"imageManifest": base64.StdEncoding.EncodeToString(msg),
	}

	return transparency.NewStatement(subject, ImageManifestPredicateType, predicate), nil
}

func parseImageManifestFromPredicate(predicate map[string]any) (*ImageManifest, error) {
	predicateVal, ok := predicate["imageManifest"]
	if !ok {
		return nil, errors.New("missing image manifest predicate entry")
	}

	imageManifestBase64, ok := predicateVal.(string)
	if !ok {
		return nil, fmt.Errorf("image manifest should be a string, is %#v", predicateVal)
	}

	jsonBytes, err := base64.StdEncoding.DecodeString(imageManifestBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode image manifest: %w", err)
	}

	var imageManifest ImageManifest
	err = json.Unmarshal(jsonBytes, &imageManifest)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal image manifest: %w", err)
	}

	return &imageManifest, nil
}
