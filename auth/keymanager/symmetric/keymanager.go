// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package symmetric

import (
	"context"

	"github.com/absmach/supermq/auth"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type manager struct {
	algorithm jwa.KeyAlgorithm
	secret    []byte
}

var _ auth.KeyManager = (*manager)(nil)

func NewKeyManager(cfg auth.KeyManagerConfig, secret []byte) (auth.KeyManager, error) {
	alg := jwa.KeyAlgorithmFrom(cfg.KeyAlgorithm)
	if _, ok := alg.(jwa.InvalidKeyAlgorithm); ok {
		return nil, auth.ErrUnsupportedKeyAlgorithm
	}
	return &manager{
		secret:    secret,
		algorithm: alg,
	}, nil
}

func (km *manager) SignJWT(token jwt.Token) ([]byte, error) {
	return jwt.Sign(token, jwt.WithKey(jwa.HS512, km.secret))
}

func (km *manager) ParseJWT(ctx context.Context, token string) (jwt.Token, error) {
	return jwt.Parse(
		[]byte(token),
		jwt.WithValidate(true),
		jwt.WithKey(jwa.HS512, km.secret),
	)
}

func (km *manager) PublicJWKS(ctx context.Context) []auth.JWK {
	return nil
}
