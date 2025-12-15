// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package asymmetric

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"sync"
	"time"

	"github.com/absmach/supermq"
	"github.com/absmach/supermq/auth"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var (
	cleanupInterval = 10 * time.Minute // How often to clean up expired keys
	skewDuration    = 15*time.Second + cleanupInterval
)

type manager struct {
	idProvider       supermq.IDProvider
	repo             auth.PublicKeyRepository
	gracePeriod      time.Duration
	rotationInterval time.Duration
	keySize          int
	activeKey        activeKey
}

type activeKey struct {
	mu         sync.RWMutex
	privateKey jwk.Key
	keyID      string
}

type keyPair struct {
	privateKey jwk.Key
	publicKey  jwk.Key
}

var _ auth.KeyManager = (*manager)(nil)

func NewKeyManager(ctx context.Context, cfg auth.KeyManagerConfig, idProvider supermq.IDProvider, repo auth.PublicKeyRepository) (auth.KeyManager, error) {
	km := &manager{
		idProvider:       idProvider,
		repo:             repo,
		gracePeriod:      cfg.AccessTokenDuration + skewDuration,
		keySize:          cfg.KeySize,
		rotationInterval: cfg.RotationInterval,
	}

	if err := km.initializeKeys(ctx); err != nil {
		return nil, err
	}

	if km.rotationInterval > 0 {
		go func() {
			if err := km.rotateHandler(ctx); err != nil {
				return
			}
		}()
	}

	go func() {
		if err := km.cleanupHandler(ctx); err != nil {
			return
		}
	}()

	return km, nil
}

func (km *manager) SignJWT(token jwt.Token) ([]byte, error) {
	km.activeKey.mu.RLock()
	privateKey := km.activeKey.privateKey
	km.activeKey.mu.RUnlock()

	return jwt.Sign(token, jwt.WithKey(jwa.RS256, privateKey))
}

func (km *manager) ParseJWT(ctx context.Context, token string) (jwt.Token, error) {
	keys := km.PublicJWKS(ctx)
	set := jwk.NewSet()
	for _, key := range keys {
		err := set.AddKey(key.Key())
		if err != nil {
			return nil, err
		}
	}
	tkn, err := jwt.Parse(
		[]byte(token),
		jwt.WithValidate(true),
		jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)),
	)
	if err != nil {
		return nil, err
	}
	return tkn, nil
}

func (km *manager) PublicJWKS(ctx context.Context) []auth.JWK {
	keys, err := km.repo.RetrieveAll(ctx)
	if err != nil {
		return nil
	}

	var jwkKeys []auth.JWK
	for _, key := range keys {
		jwkKeys = append(jwkKeys, key.JWKData)
	}

	return jwkKeys
}

func (km *manager) rotate(ctx context.Context) error {
	newID, err := km.idProvider.ID()
	if err != nil {
		return err
	}
	newPair, err := generateKeyPair(newID, km.keySize)
	if err != nil {
		return err
	}

	newPublicKey := auth.PublicKey{
		Kid:       newID,
		JWKData:   auth.NewJWK(newPair.publicKey),
		CreatedAt: time.Now().UTC(),
		Status:    auth.ActiveKeyStatus,
	}
	if err := km.repo.Save(ctx, newPublicKey); err != nil {
		return err
	}
	km.activeKey.mu.RLock()
	toRetire := km.activeKey.keyID
	km.activeKey.mu.RUnlock()

	err = km.repo.Retire(ctx, toRetire, time.Now().UTC())
	if err != nil {
		return err
	}
	km.setActiveKey(newID, newPair.privateKey)

	return nil
}

func (km *manager) rotateHandler(ctx context.Context) error {
	ticker := time.NewTicker(km.rotationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := km.rotate(ctx); err != nil {
				return err
			}
		}
	}
}

func (km *manager) cleanupHandler(ctx context.Context) error {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			expiredBefore := time.Now().UTC().Add(-km.gracePeriod)
			if err := km.repo.PurgeExpired(ctx, expiredBefore); err != nil {
				continue
			}
		}
	}
}

func (km *manager) initializeKeys(ctx context.Context) error {
	activeKid, err := km.idProvider.ID()
	if err != nil {
		return err
	}
	activePair, err := generateKeyPair(activeKid, km.keySize)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	activePublicKey := auth.PublicKey{
		Kid:       activeKid,
		JWKData:   auth.NewJWK(activePair.publicKey),
		CreatedAt: now,
		Status:    auth.ActiveKeyStatus,
	}
	if err := km.repo.Save(ctx, activePublicKey); err != nil {
		return err
	}
	km.setActiveKey(activeKid, activePair.privateKey)

	return nil
}

func (km *manager) setActiveKey(kid string, privateKey jwk.Key) {
	km.activeKey.mu.Lock()
	defer km.activeKey.mu.Unlock()

	km.activeKey.keyID = kid
	km.activeKey.privateKey = privateKey
}

func generateKeyPair(kid string, keySize int) (keyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return keyPair{}, err
	}
	publicKey := &privateKey.PublicKey

	privateJwk, err := jwk.FromRaw(privateKey)
	if err != nil {
		return keyPair{}, err
	}
	if err := privateJwk.Set(jwk.KeyIDKey, kid); err != nil {
		return keyPair{}, err
	}

	publicJwk, err := jwk.FromRaw(publicKey)
	if err != nil {
		return keyPair{}, err
	}
	if err := publicJwk.Set(jwk.KeyIDKey, kid); err != nil {
		return keyPair{}, err
	}
	if err := publicJwk.Set(jwk.KeyTypeKey, "RSA"); err != nil {
		return keyPair{}, err
	}

	return keyPair{
		privateKey: privateJwk,
		publicKey:  publicJwk,
	}, nil
}
