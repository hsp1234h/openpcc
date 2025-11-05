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

package transparency_test

import (
	"encoding/hex"
	"testing"
	"time"

	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/transparency"
	bundlepb "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

const (
	helloWorldHash   = `7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9`
	goodbyeWorldHash = `75f196b1bb0411d7687dc8ad215fcb6b702c8f960844aa64ce383e03ca038935`
)

func TestVerifier(t *testing.T) {
	hashBundleMeta := func() transparency.BundleMetadata {
		return transparency.BundleMetadata{
			Timestamp: time.Date(2025, time.May, 28, 13, 3, 59, 0, time.UTC),
		}
	}

	statementBundleMeta := func() transparency.BundleMetadata {
		return transparency.BundleMetadata{
			Timestamp: time.Date(2025, time.June, 23, 14, 25, 53, 0, time.UTC),
		}
	}

	multiStatementBundleMeta := func() transparency.BundleMetadata {
		return transparency.BundleMetadata{
			Timestamp: time.Date(2025, time.June, 23, 14, 25, 54, 0, time.UTC),
		}
	}

	t.Run("ok, verify on hash bundle", func(t *testing.T) {
		t.Parallel()

		wantMeta := hashBundleMeta()
		bundle := loadHashBundle(t, "bundle-hello-world-1.txt")
		identity := test.LocalDevIdentityPolicy()
		verifier, err := test.LocalDevVerifier()
		require.NoError(t, err)

		gotMeta, err := verifier.Verify([]byte("hello world!"), bundle, identity)
		require.NoError(t, err)
		require.Equal(t, wantMeta, gotMeta)

		// same as before, but verify with a hash not the original content.
		gotMeta, err = verifier.VerifyHash(mustHexDecode(helloWorldHash), bundle, identity)
		require.NoError(t, err)
		require.Equal(t, wantMeta, gotMeta)
	})

	t.Run("ok, verify on statement bundle", func(t *testing.T) {
		t.Parallel()

		wantMeta := statementBundleMeta()
		bundle := loadStatementBundle(t, "bundle-hello-world-1.txt")
		identity := test.LocalDevIdentityPolicy()
		verifier, err := test.LocalDevVerifier()
		require.NoError(t, err)

		gotMeta, err := verifier.Verify([]byte("hello world!"), bundle, identity)
		require.NoError(t, err)
		require.Equal(t, wantMeta, gotMeta)

		// same as before, but verify with a hash not the original content.
		gotMeta, err = verifier.VerifyHash(mustHexDecode(helloWorldHash), bundle, identity)
		require.NoError(t, err)
		require.Equal(t, wantMeta, gotMeta)
	})

	t.Run("ok, verify on statement bundle", func(t *testing.T) {
		t.Parallel()

		want := newGreetingStatement(t, "hello world!")
		wantMeta := statementBundleMeta()
		bundle := loadStatementBundle(t, "bundle-hello-world-1.txt")
		identity := test.LocalDevIdentityPolicy()
		verifier, err := test.LocalDevVerifier()
		require.NoError(t, err)

		got, gotMeta, err := verifier.VerifyStatement([]byte("hello world!"), bundle, identity)
		require.NoError(t, err)
		require.Equal(t, want, got)
		require.Equal(t, wantMeta, gotMeta)

		// same as before, but verify with a hash not the original content.
		got, gotMeta, err = verifier.VerifyStatementHash(mustHexDecode(helloWorldHash), bundle, identity)
		require.NoError(t, err)
		require.Equal(t, want, got)
		require.Equal(t, wantMeta, gotMeta)

		// verify the bundle integrity (does not verify it against any data)
		got, gotMeta, err = verifier.VerifyStatementIntegrity(bundle, identity)
		require.NoError(t, err)
		require.Equal(t, want, got)
		require.Equal(t, wantMeta, gotMeta)

		// this is a statement that contains it's own data, so we can verify it against
		got, gotMeta, err = verifier.VerifyStatementPredicate(bundle, "originalGreeting", identity)
		require.NoError(t, err)
		require.Equal(t, want, got)
		require.Equal(t, wantMeta, gotMeta)

		got, gotMeta, err = verifier.VerifyStatementWithProcessor(bundle, func(s *transparency.Statement) ([]byte, error) {
			return []byte("hello world!"), nil
		}, identity)
		require.NoError(t, err)
		requireEqualStatement(t, want, got)
		require.Equal(t, wantMeta, gotMeta)
	})

	t.Run("ok, verify on statement bundle with multiple subjects", func(t *testing.T) {
		t.Parallel()

		want := newConversationStatement(t, "hello world!", "goodbye world!")
		wantMeta := multiStatementBundleMeta()
		bundle := loadStatementBundle(t, "bundle-conversation-1.txt")
		identity := test.LocalDevIdentityPolicy()
		verifier, err := test.LocalDevVerifier()
		require.NoError(t, err)

		got, gotMeta, err := verifier.VerifyStatement([]byte("hello world!"), bundle, identity)
		require.NoError(t, err)
		requireEqualStatement(t, want, got)
		require.Equal(t, wantMeta, gotMeta)

		got, gotMeta, err = verifier.VerifyStatement([]byte("goodbye world!"), bundle, identity)
		require.NoError(t, err)
		requireEqualStatement(t, want, got)
		require.Equal(t, wantMeta, gotMeta)

		// same as before, but verify with a hash not the original content.
		got, gotMeta, err = verifier.VerifyStatementHash(mustHexDecode(helloWorldHash), bundle, identity)
		require.NoError(t, err)
		requireEqualStatement(t, want, got)
		require.Equal(t, wantMeta, gotMeta)

		// same as before, but verify with a hash not the original content.
		got, gotMeta, err = verifier.VerifyStatementHash(mustHexDecode(goodbyeWorldHash), bundle, identity)
		require.NoError(t, err)
		requireEqualStatement(t, want, got)
		require.Equal(t, wantMeta, gotMeta)

		// verify the bundle integrity (does not verify it against any data)
		got, gotMeta, err = verifier.VerifyStatementIntegrity(bundle, identity)
		require.NoError(t, err)
		requireEqualStatement(t, want, got)
		require.Equal(t, wantMeta, gotMeta)

		// this is a statement that contains it's own data, so we can verify it against
		got, gotMeta, err = verifier.VerifyStatementPredicate(bundle, "originalGreeting", identity)
		require.NoError(t, err)
		requireEqualStatement(t, want, got)
		require.Equal(t, wantMeta, gotMeta)

		// this is a statement that contains it's own data, so we can verify it against
		got, gotMeta, err = verifier.VerifyStatementPredicate(bundle, "originalGoodbye", identity)
		require.NoError(t, err)
		requireEqualStatement(t, want, got)
		require.Equal(t, wantMeta, gotMeta)
	})

	t.Run("fail, verify on hash bundle, signature tampered with", func(t *testing.T) {
		t.Parallel()

		bundle := loadHashBundle(t, "bundle-hello-world-1.txt")
		identity := test.LocalDevIdentityPolicy()
		verifier, err := test.LocalDevVerifier()
		require.NoError(t, err)

		bundle = modBundle(t, bundle, func(bpb *bundlepb.Bundle) {
			sig := bpb.GetMessageSignature()
			require.NotNil(t, sig)
			sig.Signature[0]++
		})

		_, err = verifier.Verify([]byte("hello world!"), bundle, identity)
		require.Error(t, err)

		_, err = verifier.VerifyHash([]byte(helloWorldHash), bundle, identity)
		require.Error(t, err)
	})

	t.Run("fail, verify on statement bundle, signature tampered with", func(t *testing.T) {
		t.Parallel()

		bundle := loadStatementBundle(t, "bundle-hello-world-1.txt")
		identity := test.LocalDevIdentityPolicy()
		verifier, err := test.LocalDevVerifier()
		require.NoError(t, err)

		bundle = modBundle(t, bundle, func(bpb *bundlepb.Bundle) {
			env := bpb.GetDsseEnvelope()
			require.NotNil(t, env)
			require.Len(t, env.Signatures, 1)
			env.Signatures[0].Sig[0]++
		})

		_, err = verifier.Verify([]byte("hello world!"), bundle, identity)
		require.Error(t, err)

		// same as before, but verify with a hash not the original content.
		_, err = verifier.VerifyHash([]byte(helloWorldHash), bundle, identity)
		require.Error(t, err)
	})

	t.Run("fail, verify on statement bundle, signature tampered with", func(t *testing.T) {
		t.Parallel()

		bundle := loadStatementBundle(t, "bundle-hello-world-1.txt")
		identity := test.LocalDevIdentityPolicy()
		verifier, err := test.LocalDevVerifier()
		require.NoError(t, err)
		bundle = modBundle(t, bundle, func(bpb *bundlepb.Bundle) {
			env := bpb.GetDsseEnvelope()
			require.NotNil(t, env)
			require.Len(t, env.Signatures, 1)
			env.Signatures[0].Sig[0]++
		})

		got, _, err := verifier.VerifyStatement([]byte("hello world!"), bundle, identity)
		require.Error(t, err)
		require.Nil(t, got)

		// same as before, but verify with a hash not the original content.
		got, _, err = verifier.VerifyStatementHash([]byte(helloWorldHash), bundle, identity)
		require.Error(t, err)
		require.Nil(t, got)

		// verify the bundle against itself.
		got, _, err = verifier.VerifyStatementIntegrity(bundle, identity)
		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("fail, verify statement on hash bundle", func(t *testing.T) {
		t.Parallel()

		bundle := loadHashBundle(t, "bundle-hello-world-1.txt")
		identity := test.LocalDevIdentityPolicy()
		verifier, err := test.LocalDevVerifier()
		require.NoError(t, err)

		got, _, err := verifier.VerifyStatement([]byte("hello world!"), bundle, identity)
		require.Error(t, err)
		require.ErrorIs(t, err, transparency.ErrNoStatement)
		require.Nil(t, got)

		// same as before, but verify with a hash not the original content.
		got, _, err = verifier.VerifyStatementHash(mustHexDecode(helloWorldHash), bundle, identity)
		require.Error(t, err)
		require.ErrorIs(t, err, transparency.ErrNoStatement)
		require.Nil(t, got)

		// verify the bundle against itself.
		got, _, err = verifier.VerifyStatementIntegrity(bundle, identity)
		require.Error(t, err)
		require.ErrorIs(t, err, transparency.ErrNoStatement)
		require.Nil(t, got)
	})
}

func requireEqualStatement(t *testing.T, want, got *transparency.Statement) {
	t.Helper()

	requireEqualCollections(t, want.Subject, got.Subject)
	require.Equal(t, want.PredicateType, got.PredicateType)
	require.Equal(t, want.Predicate, got.Predicate)
}

func modBundle(t *testing.T, b []byte, modFunc func(bpb *bundlepb.Bundle)) []byte {
	t.Helper()

	bpb := &bundlepb.Bundle{}
	err := proto.Unmarshal(b, bpb)
	require.NoError(t, err)

	modFunc(bpb)

	result, err := proto.Marshal(bpb)
	require.NoError(t, err)
	return result
}

func mustHexDecode(s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid hex encoded value: " + err.Error())
	}
	return data
}
