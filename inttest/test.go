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

package inttest

import (
	"crypto/rand"
	"io"
	"io/fs"
	"net"
	"strings"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/txtar"
	"google.golang.org/protobuf/proto"
)

// TextArchiveFS parses a txtar.Archive and returns a fs.FS of it or panics.
func TextArchiveFS(t *testing.T, filename string) fs.FS {
	t.Helper()

	a, err := txtar.ParseFile(filename)
	if err != nil {
		t.Fatalf("failed to parse txtar: %v", err)
	}

	fileSystem, err := txtar.FS(a)
	if err != nil {
		t.Fatalf("failed to get txtar archive as file system: %v", err)
	}

	return fileSystem
}

func ReadFile(t *testing.T, fsys fs.FS, name string) []byte {
	t.Helper()

	data, err := fs.ReadFile(fsys, name)
	require.NoError(t, err)

	return data
}

// DeriveP256PublicKeyFromSeed derives a public key from a seed.
func DeriveP256PublicKeyFromSeed(t *testing.T, seed []byte) []byte {
	t.Helper()

	scheme := hpke.KEM_P256_HKDF_SHA256.Scheme()

	// pad with zeroes if seed is too short
	if len(seed) < scheme.SeedSize() {
		diff := scheme.SeedSize() - len(seed)
		add := make([]byte, diff)
		seed = append(seed, add...)
	}

	if len(seed) > scheme.SeedSize() {
		t.Fatalf("seed too long, is %d, wants %d", len(seed), scheme.SeedSize())
	}

	pubKey, _ := scheme.DeriveKeyPair(seed)
	b, err := pubKey.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	return b
}

// Bytes loads data from the provided file or panics.
func Bytes(t *testing.T, fileSystem fs.FS, filename string) []byte {
	t.Helper()

	f, err := fileSystem.Open(filename)
	if err != nil {
		t.Fatalf("failed to open file: %v", err)
	}

	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("failed to read all data from file: %v", err)
	}

	return data
}

// String loads data from the provided file or panics.
func String(t *testing.T, fileSystem fs.FS, filename string) string {
	t.Helper()

	return string(Bytes(t, fileSystem, filename))
}

// BytesTrimSpace loads data from the provided file or panics. It also trims whitespace
// from the data before returning it. Can be useful when you have test data in a file
// that has spacing added by the user or their editor.
func BytesTrimSpace(t *testing.T, fileSystem fs.FS, filename string) []byte {
	t.Helper()

	data := Bytes(t, fileSystem, filename)
	return []byte(strings.TrimSpace(string(data)))
}

// RequireReadAll reads all data from the reader and verifies it matches want.
func RequireReadAll(t *testing.T, want []byte, r io.Reader) {
	t.Helper()

	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

// AssertReadAll reads all data from the reader and verifies it matches want.
func AssertReadAll(t *testing.T, want []byte, r io.Reader) {
	t.Helper()

	got, err := io.ReadAll(r)
	assert.NoError(t, err)
	assert.Equal(t, want, got)
}

// RequireJSONReadAll reads all data from the reader and verifies it matches want as JSON.
func RequireJSONReadAll(t *testing.T, want string, r io.Reader) {
	t.Helper()

	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.JSONEq(t, want, string(got))
}

// FreePort makes a best attempt to get a free port from the OS.
func FreePort(t *testing.T) int {
	t.Helper()

	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	addr, ok := lis.Addr().(*net.TCPAddr)
	require.True(t, ok)
	port := addr.Port

	err = lis.Close()
	require.NoError(t, err)

	return port
}

// RandomBytes returns n random bytes.
func RandomBytes(t *testing.T, n int) []byte {
	t.Helper()

	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)

	return b
}

func Must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func RequireProtoMarshal(t *testing.T, m proto.Message) []byte {
	t.Helper()

	data, err := proto.Marshal(m)
	require.NoError(t, err)
	return data
}

func RequireProtoUnmarshal(t *testing.T, b []byte, m proto.Message) {
	t.Helper()

	err := proto.Unmarshal(b, m)
	require.NoError(t, err)
}

func RequireProtoUnmarshalReader(t *testing.T, r io.Reader, m proto.Message) {
	t.Helper()

	data, err := io.ReadAll(r)
	require.NoError(t, err)
	RequireProtoUnmarshal(t, data, m)
}
