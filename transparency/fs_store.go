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
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/openpcc/openpcc/cserrors"
)

// FSStore is a store that stored sigstore bundles on the file system.
type FSStore struct {
	path string
}

func NewFSStore(path string) *FSStore {
	return &FSStore{
		path: path,
	}
}

func (s *FSStore) FindByKey(_ context.Context, key string) ([]byte, error) {
	fp := filepath.Join(s.path, key)
	file, err := os.Open(fp)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, cserrors.ErrNotFound
		}

		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	defer func() {
		closeErr := file.Close()
		if err != nil {
			err = closeErr
		}
	}()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read all data in the file: %w", err)
	}

	return data, nil
}

func (s *FSStore) Insert(_ context.Context, key string, bundle []byte) error {
	fp := filepath.Join(s.path, key)
	fDir := filepath.Dir(fp)
	err := os.MkdirAll(fDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	file, err := os.Create(fp)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}

	defer func() {
		closeErr := file.Close()
		if err != nil {
			err = closeErr
		}
	}()

	_, err = io.Copy(file, bytes.NewReader(bundle))
	if err != nil {
		return fmt.Errorf("failed to copy bundle to file: %w", err)
	}

	return nil
}

func (s *FSStore) FindByGlob(ctx context.Context, pattern string) ([][]byte, error) {
	var out [][]byte
	err := filepath.Walk(s.path, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// skip directories
		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(s.path, path)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %w", err)
		}

		matched, err := filepath.Match(pattern, relPath)
		if err != nil {
			return fmt.Errorf("failed to match path: %w", err)
		}

		if !matched {
			return nil
		}

		data, err := s.FindByKey(ctx, relPath)
		if err != nil {
			return fmt.Errorf("failed to get data for key %s: %w", relPath, err)
		}
		out = append(out, data)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return out, nil
}
