// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"

	"github.com/absmach/magistrala"
)

type Token struct {
	AccessToken  string // AccessToken contains the security credentials for a login session and identifies the client.
	RefreshToken string // RefreshToken is a credential artifact that OAuth can use to get a new access token without client interaction.
	AccessType   string // AccessType is the specific type of access token issued. It can be Bearer, Client or Basic.
}

type IdentityRes struct {
	ID       string
	UserID   string
	DomainID string
}

type AuthorizeRes struct {
	Authorized bool
	ID         string
}

// AuthWrapper specifies an API for interacting with authentication and authorization for magistrala services.
// Acts a wrapper for services that communicates with the magistrala auth service.
type AuthWrapper interface {
	// Issue issues a new Key, returning its token value alongside.
	Issue(ctx context.Context, req *magistrala.IssueReq) (Token, error)

	// Refresh iisues a refresh Key, returning its token value alongside.
	Refresh(ctx context.Context, req *magistrala.RefreshReq) (Token, error)

	// Identify validates token token. If token is valid, content
	// is returned. If token is invalid, or invocation failed for some
	// other reason, non-nil error value is returned in response.
	Identify(ctx context.Context, token *magistrala.IdentityReq) (IdentityRes, error)

	// Authorize checks if the `subject` is allowed to perform the `relation` on the `object`.
	// Returns a non-nil error if the `subject` is not authorized.
	Authorize(ctx context.Context, req *magistrala.AuthorizeReq) (AuthorizeRes, error)
}
