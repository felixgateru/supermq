// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var ErrUnsupportedKeyAlgorithm = errors.New("unsupported key algorithm")

// PublicKeyStatus represents the status of a public key.
type PublicKeyStatus int

const (
	// ActiveKeyStatus indicates the key is active and can be used for verification.
	ActiveKeyStatus PublicKeyStatus = iota
	// RetiredKeyStatus indicates the key is retired but still valid for verification during grace period.
	RetiredKeyStatus
)

type KeyManagerConfig struct {
	RotationInterval    time.Duration `env:"ROTATION_INTERVAL" envDefault:"24h"`
	AccessTokenDuration time.Duration `env:"ACCESS_TOKEN_DURATION" envDefault:"15m"`
	KeyAlgorithm        string        `env:"ALGORITHM" envDefault:"RS512"`
	KeySize             int           `env:"KEY_SIZE" envDefault:"4096"`
}

// JWK represents a JSON Web Key.
type JWK struct {
	key jwk.Key
}

// NewJWK creates a new JWK from a jwk.Key.
func NewJWK(key jwk.Key) JWK {
	return JWK{key: key}
}

// Key returns the underlying jwk.Key.
func (j JWK) Key() jwk.Key {
	return j.key
}

// PublicKey represents a public key stored in the database.
type PublicKey struct {
	Kid       string          `json:"kid" db:"kid"`
	JWKData   JWK             `json:"jwk_data" db:"jwk_data"`
	CreatedAt time.Time       `json:"created_at" db:"created_at"`
	RetiredAt *time.Time      `json:"retired_at,omitempty" db:"retired_at"`
	Status    PublicKeyStatus `json:"status" db:"status"`
}

// KeyManager represents a manager for JWT keys.
type KeyManager interface {
	SignJWT(token jwt.Token) ([]byte, error)

	ParseJWT(ctx context.Context, token string) (jwt.Token, error)

	PublicJWKS(ctx context.Context) []JWK
}

// PublicKeyRepository represents a repository for storing and retrieving public keys.
type PublicKeyRepository interface {
	// Save stores a public key in the database.
	Save(ctx context.Context, key PublicKey) error

	// RetrieveAll gets all active public keys.
	RetrieveAll(ctx context.Context) ([]PublicKey, error)

	// Retire marks a public key as retired.
	Retire(ctx context.Context, kid string, retiredAt time.Time) error

	// PurgeExpired removes all expired public keys from the database.
	PurgeExpired(ctx context.Context, expiredBefore time.Time) error
}

func IsSymmetricAlgorithm(alg string) (bool, error) {
	switch alg {
	case "HS256", "HS384", "HS512":
		return true, nil
	case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512":
		return false, nil
	default:
		return false, ErrUnsupportedKeyAlgorithm
	}
}
