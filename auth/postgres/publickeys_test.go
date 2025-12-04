// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package postgres_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/absmach/supermq/auth"
	apostgres "github.com/absmach/supermq/auth/postgres"
	"github.com/absmach/supermq/internal/testsutil"
	"github.com/absmach/supermq/pkg/errors"
	repoerr "github.com/absmach/supermq/pkg/errors/repository"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSave(t *testing.T) {
	t.Cleanup(func() {
		_, err := db.Exec("DELETE FROM public_keys")
		require.Nil(t, err, fmt.Sprintf("clean public_keys failed with unexpected error: %s", err))
	})

	repo := apostgres.NewPublicKeyRepo(db)

	kid := testsutil.GenerateUUID(t)
	key, err := generateKey()
	require.Nil(t, err, fmt.Sprintf("generating jwk key failed with unexpected error: %s", err))
	createdAt := time.Now().UTC()

	cases := []struct {
		desc string
		key  auth.PublicKey
		err  error
	}{
		{
			desc: "save new public key",
			key: auth.PublicKey{
				Kid:       kid,
				JWKData:   key,
				Status:    auth.ActiveKeyStatus,
				CreatedAt: createdAt,
			},
			err: nil,
		},
		{
			desc: "save duplicate public key",
			key: auth.PublicKey{
				Kid:       kid,
				JWKData:   key,
				Status:    auth.ActiveKeyStatus,
				CreatedAt: createdAt,
			},
			err: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := repo.Save(context.Background(), tc.key)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		})
	}
}

func TestRetrieveAll(t *testing.T) {
	t.Cleanup(func() {
		_, err := db.Exec("DELETE FROM public_keys")
		require.Nil(t, err, fmt.Sprintf("clean public_keys failed with unexpected error: %s", err))
	})

	repo := apostgres.NewPublicKeyRepo(db)
	num := 5

	for range num {
		kid := testsutil.GenerateUUID(t)
		key, err := generateKey()
		require.Nil(t, err, fmt.Sprintf("generating jwk key failed with unexpected error: %s", err))
		createdAt := time.Now().UTC()

		publicKey := auth.PublicKey{
			Kid:       kid,
			JWKData:   key,
			Status:    auth.ActiveKeyStatus,
			CreatedAt: createdAt,
		}

		err = repo.Save(context.Background(), publicKey)
		require.Nil(t, err, fmt.Sprintf("saving public key failed with unexpected error: %s", err))
	}

	keys, err := repo.RetrieveAll(context.Background())
	require.Nil(t, err, fmt.Sprintf("retrieving all public keys failed with unexpected error: %s", err))
	assert.Equal(t, num, len(keys), fmt.Sprintf("expected to retrieve %d keys, got %d", 10, len(keys)))
}

func TestRetire(t *testing.T) {
	t.Cleanup(func() {
		_, err := db.Exec("DELETE FROM public_keys")
		require.Nil(t, err, fmt.Sprintf("clean public_keys failed with unexpected error: %s", err))
	})

	repo := apostgres.NewPublicKeyRepo(db)

	kid := testsutil.GenerateUUID(t)
	key, err := generateKey()
	require.Nil(t, err, fmt.Sprintf("generating jwk key failed with unexpected error: %s", err))
	createdAt := time.Now().UTC()

	publicKey := auth.PublicKey{
		Kid:       kid,
		JWKData:   key,
		Status:    auth.ActiveKeyStatus,
		CreatedAt: createdAt,
	}

	err = repo.Save(context.Background(), publicKey)
	require.Nil(t, err, fmt.Sprintf("saving public key failed with unexpected error: %s", err))

	cases := []struct {
		desc      string
		kid       string
		retiredAt time.Time
		err       error
	}{
		{
			desc:      "retire existing key",
			kid:       kid,
			retiredAt: time.Now().UTC(),
			err:       nil,
		},
		{
			desc:      "retire non-existent key",
			kid:       testsutil.GenerateUUID(t),
			retiredAt: time.Now().UTC(),
			err:       repoerr.ErrNotFound,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := repo.Retire(context.Background(), tc.kid, tc.retiredAt)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		})
	}
}

func TestPurgeExpired(t *testing.T) {
	t.Cleanup(func() {
		_, err := db.Exec("DELETE FROM public_keys")
		require.Nil(t, err, fmt.Sprintf("clean public_keys failed with unexpected error: %s", err))
	})

	repo := apostgres.NewPublicKeyRepo(db)

	activeKid := testsutil.GenerateUUID(t)
	activeKey, err := generateKey()
	require.Nil(t, err, fmt.Sprintf("generating jwk key failed with unexpected error: %s", err))

	activePublicKey := auth.PublicKey{
		Kid:       activeKid,
		JWKData:   activeKey,
		Status:    auth.ActiveKeyStatus,
		CreatedAt: time.Now().UTC(),
	}
	err = repo.Save(context.Background(), activePublicKey)
	require.Nil(t, err, fmt.Sprintf("saving active public key failed with unexpected error: %s", err))

	oldKid := testsutil.GenerateUUID(t)
	oldKey, err := generateKey()
	require.Nil(t, err, fmt.Sprintf("generating jwk key failed with unexpected error: %s", err))

	oldRetiredAt := time.Now().UTC().Add(-48 * time.Hour)
	oldPublicKey := auth.PublicKey{
		Kid:       oldKid,
		JWKData:   oldKey,
		Status:    auth.RetiredKeyStatus,
		CreatedAt: time.Now().UTC().Add(-72 * time.Hour),
		RetiredAt: &oldRetiredAt,
	}
	err = repo.Save(context.Background(), oldPublicKey)
	require.Nil(t, err, fmt.Sprintf("saving old retired public key failed with unexpected error: %s", err))

	recentKid := testsutil.GenerateUUID(t)
	recentKey, err := generateKey()
	require.Nil(t, err, fmt.Sprintf("generating jwk key failed with unexpected error: %s", err))

	recentRetiredAt := time.Now().UTC().Add(-1 * time.Hour)
	recentPublicKey := auth.PublicKey{
		Kid:       recentKid,
		JWKData:   recentKey,
		Status:    auth.RetiredKeyStatus,
		CreatedAt: time.Now().UTC().Add(-2 * time.Hour),
		RetiredAt: &recentRetiredAt,
	}
	err = repo.Save(context.Background(), recentPublicKey)
	require.Nil(t, err, fmt.Sprintf("saving recent retired public key failed with unexpected error: %s", err))

	cases := []struct {
		desc           string
		expiredBefore  time.Time
		expectedRemain int
		err            error
	}{
		{
			desc:           "purge keys expired before 24 hours ago",
			expiredBefore:  time.Now().UTC().Add(-24 * time.Hour),
			expectedRemain: 2,
			err:            nil,
		},
		{
			desc:           "purge with future date",
			expiredBefore:  time.Now().UTC().Add(24 * time.Hour),
			expectedRemain: 1,
			err:            nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := repo.PurgeExpired(context.Background(), tc.expiredBefore)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))

			if err == nil {
				keys, err := repo.RetrieveAll(context.Background())
				require.Nil(t, err, fmt.Sprintf("retrieving all public keys failed with unexpected error: %s", err))
				assert.Equal(t, tc.expectedRemain, len(keys), fmt.Sprintf("expected %d keys remaining, got %d", tc.expectedRemain, len(keys)))
			}
		})
	}
}

func generateKey() (jwk.Key, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	privateJwk, err := jwk.FromRaw(privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	return privateJwk, nil
}
