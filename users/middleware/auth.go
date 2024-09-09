// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"

	"github.com/absmach/magistrala"
	mgauth "github.com/absmach/magistrala/auth"
	"github.com/absmach/magistrala/pkg/auth"
	"github.com/absmach/magistrala/pkg/clients"
	"github.com/absmach/magistrala/pkg/errors"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	"github.com/absmach/magistrala/pkg/policy"
	"github.com/absmach/magistrala/users"
)

var _ users.Service = (*authMiddleware)(nil)

var errIssueToken = errors.New("failed to issue token")

type authMiddleware struct {
	auth auth.AuthClient
	svc  users.Service
}

// AuthMiddleware adds authorization and authentication facilities to the clients service.
func AuthMiddleware(svc users.Service, authClient auth.AuthClient) users.Service {
	return &authMiddleware{authClient, svc}
}

func (am authMiddleware) RegisterClient(ctx context.Context, session auth.Session, client clients.Client, selfRegister bool) (clients.Client, error) {
	if !selfRegister {
		resp, err := am.auth.Identify(ctx, &magistrala.IdentityReq{Token: session.Token})
		if err != nil {
			return clients.Client{}, errors.Wrap(svcerr.ErrAuthentication, err)
		}
		if err := am.checkSuperAdmin(ctx, resp.GetUserId()); err != nil {
			return clients.Client{}, err
		}
		session.UserID = resp.GetUserId()
	}
	session.Token = ""

	return am.svc.RegisterClient(ctx, session, client, selfRegister)
}

func (am authMiddleware) ViewClient(ctx context.Context, session auth.Session, id string) (clients.Client, error) {
	resp, err := am.auth.Identify(ctx, &magistrala.IdentityReq{Token: session.Token})
	if err != nil {
		return clients.Client{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	if err := am.checkSuperAdmin(ctx, resp.GetUserId()); err == nil {
		session.SuperAdmin = true
	}
	session.UserID = resp.GetUserId()
	session.Token = ""

	return am.svc.ViewClient(ctx, session, id)
}

func (am authMiddleware) ViewProfile(ctx context.Context, session auth.Session) (clients.Client, error) {
	resp, err := am.auth.Identify(ctx, &magistrala.IdentityReq{Token: session.Token})
	if err != nil {
		return clients.Client{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	session.UserID = resp.GetUserId()
	session.Token = ""

	return am.svc.ViewProfile(ctx, session)
}

func (am authMiddleware) ListClients(ctx context.Context, session auth.Session, pm clients.Page) (clients.ClientsPage, error) {
	resp, err := am.auth.Identify(ctx, &magistrala.IdentityReq{Token: session.Token})
	if err != nil {
		return clients.ClientsPage{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	if err := am.checkSuperAdmin(ctx, resp.GetUserId()); err == nil {
		session.SuperAdmin = true
	}
	session.UserID = resp.GetUserId()
	session.Token = ""

	return am.svc.ListClients(ctx, session, pm)
}

func (am authMiddleware) ListMembers(ctx context.Context, session auth.Session, objectKind, objectID string, pm clients.Page) (clients.MembersPage, error) {
	resp, err := am.auth.Identify(ctx, &magistrala.IdentityReq{Token: session.Token})
	if err != nil {
		return clients.MembersPage{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	session.DomainID = resp.GetDomainId()
	session.Token = ""

	var objectType string
	var authzPerm string
	switch objectKind {
	case policy.ThingsKind:
		objectType = policy.ThingType
		authzPerm = pm.Permission
	case policy.DomainsKind:
		objectType = policy.DomainType
		authzPerm = mgauth.SwitchToPermission(pm.Permission)
	case policy.GroupsKind:
		fallthrough
	default:
		objectType = policy.GroupType
		authzPerm = mgauth.SwitchToPermission(pm.Permission)
	}

	res, err := am.auth.Authorize(ctx, &magistrala.AuthorizeReq{
		SubjectType: policy.UserType,
		SubjectKind: policy.TokenKind,
		Subject:     session.Token,
		Permission:  authzPerm,
		ObjectType:  objectType,
		Object:      objectID,
	})
	if err != nil {
		return clients.MembersPage{}, errors.Wrap(svcerr.ErrAuthorization, err)
	}
	if !res.Authorized {
		return clients.MembersPage{}, svcerr.ErrAuthorization
	}

	return am.svc.ListMembers(ctx, session, objectKind, objectID, pm)
}

func (am authMiddleware) SearchUsers(ctx context.Context, session auth.Session, pm clients.Page) (clients.ClientsPage, error) {
	_, err := am.auth.Identify(ctx, &magistrala.IdentityReq{Token: session.Token})
	if err != nil {
		return clients.ClientsPage{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}

	return am.svc.SearchUsers(ctx, session, pm)
}

func (am authMiddleware) UpdateClient(ctx context.Context, session auth.Session, client clients.Client) (clients.Client, error) {
	resp, err := am.auth.Identify(ctx, &magistrala.IdentityReq{Token: session.Token})
	if err != nil {
		return clients.Client{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	if err := am.checkSuperAdmin(ctx, resp.GetUserId()); err == nil {
		session.SuperAdmin = true
	}
	session.UserID = resp.GetUserId()
	session.Token = ""

	return am.svc.UpdateClient(ctx, session, client)
}

func (am authMiddleware) UpdateClientTags(ctx context.Context, session auth.Session, client clients.Client) (clients.Client, error) {
	resp, err := am.auth.Identify(ctx, &magistrala.IdentityReq{Token: session.Token})
	if err != nil {
		return clients.Client{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	if err := am.checkSuperAdmin(ctx, resp.GetUserId()); err == nil {
		session.SuperAdmin = true
	}
	session.UserID = resp.GetUserId()
	session.Token = ""

	return am.svc.UpdateClientTags(ctx, session, client)
}

func (am authMiddleware) UpdateClientIdentity(ctx context.Context, session auth.Session, id, identity string) (clients.Client, error) {
	resp, err := am.auth.Identify(ctx, &magistrala.IdentityReq{Token: session.Token})
	if err != nil {
		return clients.Client{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	if err := am.checkSuperAdmin(ctx, resp.GetUserId()); err == nil {
		session.SuperAdmin = true
	}
	session.UserID = resp.GetUserId()
	session.Token = ""

	return am.svc.UpdateClientIdentity(ctx, session, id, identity)
}

func (am authMiddleware) GenerateResetToken(ctx context.Context, email, host string) (auth.Token, error) {
	svcResp, err := am.svc.GenerateResetToken(ctx, email, host)
	if err != nil {
		return auth.Token{}, errors.Wrap(errIssueToken, err)
	}
	token, err := am.auth.Issue(ctx, &magistrala.IssueReq{
		UserId: svcResp.UserID,
		Type:   uint32(mgauth.RecoveryKey),
	})
	if err != nil {
		return auth.Token{}, errors.Wrap(errIssueToken, err)
	}
	err = am.SendPasswordReset(ctx, host, email, svcResp.Name, token.AccessToken)
	if err != nil {
		return auth.Token{}, err
	}

	return auth.Token{}, nil
}

func (am authMiddleware) UpdateClientSecret(ctx context.Context, session auth.Session, oldSecret, newSecret string) (clients.Client, error) {
	resp, err := am.auth.Identify(ctx, &magistrala.IdentityReq{Token: session.Token})
	if err != nil {
		return clients.Client{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	session.UserID = resp.GetUserId()
	session.Token = ""

	return am.svc.UpdateClientSecret(ctx, session, oldSecret, newSecret)
}

func (am authMiddleware) ResetSecret(ctx context.Context, session auth.Session, secret string) error {
	resp, err := am.auth.Identify(ctx, &magistrala.IdentityReq{Token: session.Token})
	if err != nil {
		return errors.Wrap(svcerr.ErrAuthentication, err)
	}
	session.UserID = resp.GetUserId()
	session.Token = ""

	return am.svc.ResetSecret(ctx, session, secret)
}

func (am authMiddleware) SendPasswordReset(ctx context.Context, host, email, user, token string) error {
	return am.svc.SendPasswordReset(ctx, host, email, user, token)
}

func (am authMiddleware) UpdateClientRole(ctx context.Context, session auth.Session, client clients.Client) (clients.Client, error) {
	resp, err := am.auth.Identify(ctx, &magistrala.IdentityReq{Token: session.Token})
	if err != nil {
		return clients.Client{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	if err := am.checkSuperAdmin(ctx, resp.GetUserId()); err == nil {
		session.SuperAdmin = true
	}
	session.UserID = resp.GetUserId()
	session.Token = ""

	// check if client is a member of the platform
	res, err := am.auth.Authorize(ctx, &magistrala.AuthorizeReq{
		SubjectType: policy.UserType,
		SubjectKind: policy.UsersKind,
		Subject:     client.ID,
		Permission:  policy.MembershipPermission,
		ObjectType:  policy.PlatformType,
		Object:      policy.MagistralaObject,
	})
	if err != nil {
		return clients.Client{}, errors.Wrap(svcerr.ErrAuthorization, err)
	}
	if !res.Authorized {
		return clients.Client{}, svcerr.ErrAuthorization
	}

	return am.svc.UpdateClientRole(ctx, session, client)
}

func (am authMiddleware) EnableClient(ctx context.Context, session auth.Session, id string) (clients.Client, error) {
	resp, err := am.auth.Identify(ctx, &magistrala.IdentityReq{Token: session.Token})
	if err != nil {
		return clients.Client{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	if err := am.checkSuperAdmin(ctx, resp.GetUserId()); err == nil {
		session.SuperAdmin = true
	}
	session.UserID = resp.GetUserId()
	session.Token = ""

	return am.svc.EnableClient(ctx, session, id)
}

func (am authMiddleware) DisableClient(ctx context.Context, session auth.Session, id string) (clients.Client, error) {
	resp, err := am.auth.Identify(ctx, &magistrala.IdentityReq{Token: session.Token})
	if err != nil {
		return clients.Client{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	if err := am.checkSuperAdmin(ctx, resp.GetUserId()); err == nil {
		session.SuperAdmin = true
	}
	session.UserID = resp.GetUserId()
	session.Token = ""

	return am.svc.DisableClient(ctx, session, id)
}

func (am authMiddleware) DeleteClient(ctx context.Context, session auth.Session, id string) error {
	resp, err := am.auth.Identify(ctx, &magistrala.IdentityReq{Token: session.Token})
	if err != nil {
		return errors.Wrap(svcerr.ErrAuthentication, err)
	}
	if err := am.checkSuperAdmin(ctx, resp.GetUserId()); err == nil {
		session.SuperAdmin = true
	}
	session.UserID = resp.GetUserId()
	session.Token = ""

	return am.svc.DeleteClient(ctx, session, id)
}

func (am authMiddleware) Identify(ctx context.Context, session auth.Session) (string, error) {
	resp, err := am.auth.Identify(ctx, &magistrala.IdentityReq{Token: session.Token})
	if err != nil {
		return "", errors.Wrap(svcerr.ErrAuthentication, err)
	}
	session.UserID = resp.GetUserId()
	session.Token = ""

	return am.svc.Identify(ctx, session)
}

func (am authMiddleware) IssueToken(ctx context.Context, identity, secret, domainID string) (auth.Token, error) {
	resp, err := am.svc.IssueToken(ctx, identity, secret, domainID)
	if err != nil {
		return auth.Token{}, errors.Wrap(errIssueToken, err)
	}
	tkn, err := am.auth.Issue(ctx, &magistrala.IssueReq{
		UserId:   resp.UserID,
		DomainId: &resp.DomainID,
		Type:     uint32(mgauth.AccessKey),
	})
	if err != nil {
		return auth.Token{}, errors.Wrap(errIssueToken, err)
	}
	return auth.Token{
		AccessToken:  tkn.GetAccessToken(),
		RefreshToken: tkn.GetRefreshToken(),
		AccessType:   tkn.GetAccessType(),
	}, nil
}

func (am authMiddleware) RefreshToken(ctx context.Context, session auth.Session, domainID string) (auth.Token, error) {
	resp, err := am.auth.Identify(ctx, &magistrala.IdentityReq{Token: session.Token})
	if err != nil {
		return auth.Token{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	session.UserID = resp.GetUserId()
	svcResp, err := am.svc.RefreshToken(ctx, session, domainID)
	if err != nil {
		return auth.Token{}, err
	}

	tkn, err := am.auth.Refresh(ctx, &magistrala.RefreshReq{
		RefreshToken: session.Token,
		DomainId:     &svcResp.DomainID,
	})
	if err != nil {
		return auth.Token{}, errors.Wrap(errIssueToken, err)
	}
	return auth.Token{
		AccessToken:  tkn.GetAccessToken(),
		RefreshToken: tkn.GetRefreshToken(),
		AccessType:   tkn.GetAccessType(),
	}, nil
}

func (am authMiddleware) OAuthCallback(ctx context.Context, client clients.Client) (auth.Token, error) {
	svcResp, err := am.svc.OAuthCallback(ctx, client)
	if err != nil {
		return auth.Token{}, err
	}

	cli := clients.Client{
		ID:   svcResp.UserID,
		Role: svcResp.Role,
	}

	res, err := am.auth.Authorize(ctx, &magistrala.AuthorizeReq{
		SubjectType: policy.UserType,
		SubjectKind: policy.UsersKind,
		Subject:     client.ID,
		Permission:  policy.MembershipPermission,
		ObjectType:  policy.PlatformType,
		Object:      policy.MagistralaObject,
	})
	if err != nil {
		return auth.Token{}, errors.Wrap(svcerr.ErrAuthorization, err)
	}
	if !res.Authorized {
		return auth.Token{}, svcerr.ErrAuthorization
	}

	err = am.AddClientPolicy(ctx, cli)
	if err != nil {
		return auth.Token{}, err
	}

	tkn, err := am.auth.Issue(ctx, &magistrala.IssueReq{
		UserId: svcResp.UserID,
		Type:   uint32(mgauth.AccessKey),
	})
	if err != nil {
		return auth.Token{}, errors.Wrap(errIssueToken, err)
	}
	return auth.Token{
		AccessToken:  tkn.GetAccessToken(),
		RefreshToken: tkn.GetRefreshToken(),
		AccessType:   tkn.GetAccessType(),
	}, nil
}

func (am authMiddleware) AddClientPolicy(ctx context.Context, client clients.Client) error {
	return am.svc.AddClientPolicy(ctx, client)
}

func (am authMiddleware) checkSuperAdmin(ctx context.Context, adminID string) error {
	if _, err := am.auth.Authorize(ctx, &magistrala.AuthorizeReq{
		SubjectType: policy.UserType,
		SubjectKind: policy.UsersKind,
		Subject:     adminID,
		Permission:  policy.AdminPermission,
		ObjectType:  policy.PlatformType,
		Object:      policy.MagistralaObject,
	}); err != nil {
		return err
	}
	return nil
}
