// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"

	"github.com/absmach/magistrala"
	"github.com/absmach/magistrala/pkg/clients"
	"google.golang.org/grpc"
)

type Token struct {
	AccessToken  string // AccessToken contains the security credentials for a login session and identifies the client.
	RefreshToken string // RefreshToken is a credential artifact that OAuth can use to get a new access token without client interaction.
	AccessType   string // AccessType is the specific type of access token issued. It can be Bearer, Client or Basic.
	UserID       string
	DomainID     string
	Name         string
	Role         clients.Role
}

type Session struct {
	UserID     string
	DomainID   string
	Token      string
	SuperAdmin bool
}

// AuthClient specifies a gRPC client for  authentication and authorization for magistrala services.
type AuthClient interface {
	// Issue issues a new Key, returning its token value alongside.
	Issue(ctx context.Context, in *magistrala.IssueReq, opts ...grpc.CallOption) (*magistrala.Token, error)

	// Refresh iisues a refresh Key, returning its token value alongside.
	Refresh(ctx context.Context, in *magistrala.RefreshReq, opts ...grpc.CallOption) (*magistrala.Token, error)

	// Identify validates token token. If token is valid, content
	// is returned. If token is invalid, or invocation failed for some
	// other reason, non-nil error value is returned in response.
	Identify(ctx context.Context, in *magistrala.IdentityReq, opts ...grpc.CallOption) (*magistrala.IdentityRes, error)

	// Authorize checks if the `subject` is allowed to perform the `relation` on the `object`.
	// Returns a non-nil error if the `subject` is not authorized.
	Authorize(ctx context.Context, in *magistrala.AuthorizeReq, opts ...grpc.CallOption) (*magistrala.AuthorizeRes, error)
}
