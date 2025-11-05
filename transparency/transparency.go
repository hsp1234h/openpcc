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

package transparency

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/cenkalti/backoff/v5"
	trustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/util"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

func newTufClient(httpClient *http.Client, staging bool, localTrustedRootCachePath string, modRepositoryBaseURL func(string) string) (*tuf.Client, error) {
	f := fetcher.NewDefaultFetcher().NewFetcherWithHTTPClient(httpClient)
	f.SetHTTPUserAgent(util.ConstructUserAgent())
	// no retries as there is a bug in the fetcher where it keeps retrying on missing data.
	f.SetRetryOptions(backoff.WithMaxTries(1))

	opts := tuf.DefaultOptions()
	opts.Fetcher = f
	opts.CachePath = localTrustedRootCachePath
	opts.ForceCache = true

	if staging {
		opts.Root = tuf.StagingRoot()
		opts.RepositoryBaseURL = tuf.StagingMirror
	}

	// due to weird behavior of the tuf library, we should look to see if the root is cached and load it directly
	// or else an expired tuf.StagingRoot() prevents the library from working in an airgapped environment.
	if localTrustedRootCachePath != "" {
		sigStageCacheDir := "tuf-repo-cdn.sigstore.dev"
		if staging {
			sigStageCacheDir = "tuf-repo-cdn.sigstage.dev"
		}

		rootPath := path.Join(localTrustedRootCachePath, sigStageCacheDir, "root.json")

		rootb, err := os.ReadFile(rootPath)
		if err != nil {
			// If the cache root file doesn't exist, that's OK, set nothing.
			if !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
		} else {
			opts.Root = rootb
		}
	} else {
		opts.DisableLocalCache = true
	}

	if modRepositoryBaseURL != nil {
		opts.RepositoryBaseURL = modRepositoryBaseURL(opts.RepositoryBaseURL)
	}

	tufClient, err := tuf.New(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create tuf client: %w", err)
	}

	return tufClient, nil
}

func newStagingSigningConfig() (*root.SigningConfig, error) {
	fulcioCAs := []root.Service{
		{
			URL:                 "https://fulcio.sigstage.dev",
			MajorAPIVersion:     1,
			ValidityPeriodStart: time.Now().Add(-time.Hour),
			ValidityPeriodEnd:   time.Now().Add(time.Hour),
		},
	}
	oidcProviders := []root.Service{
		{
			URL:                 "https://oauth2.sigstage.dev/auth",
			MajorAPIVersion:     1,
			ValidityPeriodStart: time.Now().Add(-time.Hour),
			ValidityPeriodEnd:   time.Now().Add(time.Hour),
		},
	}
	rekorLogs := []root.Service{
		{
			URL:                 "https://rekor.sigstage.dev",
			MajorAPIVersion:     1,
			ValidityPeriodStart: time.Now().Add(-time.Hour),
			ValidityPeriodEnd:   time.Now().Add(time.Hour),
		},
	}
	rekorLogsCfg := root.ServiceConfiguration{
		Selector: trustroot.ServiceSelector_ANY,
	}
	tsas := []root.Service{
		{
			URL:                 "https://timestamp.sigstage.dev/api/v1/timestamp",
			MajorAPIVersion:     1,
			ValidityPeriodStart: time.Now().Add(-time.Hour),
			ValidityPeriodEnd:   time.Now().Add(time.Hour),
		},
	}
	tsasCfg := root.ServiceConfiguration{
		Selector: trustroot.ServiceSelector_ANY,
	}
	cfg, err := root.NewSigningConfig(
		root.SigningConfigMediaType02, fulcioCAs, oidcProviders, rekorLogs, rekorLogsCfg, tsas, tsasCfg,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create new staging signing config: %w", err)
	}

	return cfg, nil
}
