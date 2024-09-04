// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"

	"github.com/absmach/magistrala"
	grpcclient "github.com/absmach/magistrala/auth/api/grpc"
	"github.com/absmach/magistrala/pkg/auth"
)

type wrapper struct {
	auth grpcclient.AuthServiceClient
}

func NewAuthWrapper(authClient grpcclient.AuthServiceClient) auth.AuthWrapper {
	return &wrapper{
		auth: authClient,
	}
}

func (w wrapper) Issue(ctx context.Context, req *magistrala.IssueReq) (token auth.Token, err error) {
	resp, err := w.auth.Issue(ctx, req)
	if err != nil {
		return auth.Token{}, err
	}
	token = auth.Token{
		AccessToken:  resp.GetAccessToken(),
		RefreshToken: resp.GetRefreshToken(),
		AccessType:   resp.GetAccessType(),
	}
	return token, nil
}

func (w wrapper) Refresh(ctx context.Context, req *magistrala.RefreshReq) (token auth.Token, err error) {
	resp, err := w.auth.Refresh(ctx, req)
	if err != nil {
		return auth.Token{}, err
	}
	token = auth.Token{
		AccessToken:  resp.GetAccessToken(),
		RefreshToken: resp.GetRefreshToken(),
		AccessType:   resp.GetAccessType(),
	}
	return token, nil
}

func (w wrapper) Identify(ctx context.Context, token *magistrala.IdentityReq) (res auth.IdentifyRes, err error) {
	resp, err := w.auth.Identify(ctx, token)
	if err != nil {
		return auth.IdentifyRes{}, err
	}
	res = auth.IdentifyRes{
		ID:       resp.GetId(),
		UserID:   resp.GetUserId(),
		DomainID: resp.GetDomainId(),
	}
	return res, nil
}

func (w wrapper) Authorize(ctx context.Context, req *magistrala.AuthorizeReq) (res auth.AuthorizeRes, err error) {
	resp, err := w.auth.Authorize(ctx, req)
	if err != nil {
		return auth.AuthorizeRes{}, nil
	}
	res = auth.AuthorizeRes{
		Authorized: resp.GetAuthorized(),
		ID:         resp.GetId(),
	}
	return res, nil
}
