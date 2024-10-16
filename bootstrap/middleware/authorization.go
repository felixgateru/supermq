// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"

	"github.com/absmach/magistrala/bootstrap"
	mgauthn "github.com/absmach/magistrala/pkg/authn"
	"github.com/absmach/magistrala/pkg/authz"
	mgauthz "github.com/absmach/magistrala/pkg/authz"
	"github.com/absmach/magistrala/pkg/policies"
)

var _ bootstrap.Service = (*authorizationMiddleware)(nil)

type authorizationMiddleware struct {
	svc   bootstrap.Service
	authz mgauthz.Authorization
}

// AuthorizationMiddleware adds authorization to the clients service.
func AuthorizationMiddleware(svc bootstrap.Service, authz mgauthz.Authorization) bootstrap.Service {
	return &authorizationMiddleware{
		svc:   svc,
		authz: authz,
	}
}

func (am *authorizationMiddleware) Add(ctx context.Context, session mgauthn.Session, token string, cfg bootstrap.Config) (bootstrap.Config, error) {
	if err := am.authorize(ctx, "", policies.UserType, policies.UsersKind, session.DomainUserID, policies.MembershipPermission, policies.DomainType, session.DomainID); err != nil {
		return bootstrap.Config{}, err
	}

	return am.svc.Add(ctx, session, token, cfg)
}

func (am *authorizationMiddleware) View(ctx context.Context, session mgauthn.Session, id string) (bootstrap.Config, error) {
	if err := am.authorize(ctx, session.DomainID, policies.UserType, policies.UsersKind, session.DomainUserID, policies.ViewPermission, policies.DomainType, session.DomainID); err != nil {
		return bootstrap.Config{}, err
	}
	return am.svc.View(ctx, session, token, id)
}

func (am *authorizationMiddleware) checkSuperAdmin(ctx context.Context, adminID string) error {
	if err := am.authz.Authorize(ctx, authz.PolicyReq{
		SubjectType: policies.UserType,
		Subject:     adminID,
		Permission:  policies.AdminPermission,
		ObjectType:  policies.PlatformType,
		Object:      policies.MagistralaObject,
	}); err != nil {
		return err
	}
	return nil
}

func (am *authorizationMiddleware) authorize(ctx context.Context, domain, subjType, subjKind, subj, perm, objType, obj string) error {
	req := authz.PolicyReq{
		Domain:      domain,
		SubjectType: subjType,
		SubjectKind: subjKind,
		Subject:     subj,
		Permission:  perm,
		ObjectType:  objType,
		Object:      obj,
	}
	if err := am.authz.Authorize(ctx, req); err != nil {
		return err
	}
	return nil
}
