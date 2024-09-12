// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/absmach/magistrala"
	mgauth "github.com/absmach/magistrala/auth"
	"github.com/absmach/magistrala/pkg/apiutil"
	"github.com/absmach/magistrala/pkg/auth"
	"github.com/absmach/magistrala/pkg/errors"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	"github.com/absmach/magistrala/pkg/policy"
	"github.com/go-kit/kit/endpoint"
)

var (
	listMembersByGroupAuthReq = policy.PolicyReq{
		SubjectType: policy.UserType,
		SubjectKind: policy.TokenKind,
		ObjectType:  policy.GroupType,
	}
	updateClientRoleAuthreq = policy.PolicyReq{
		SubjectType: policy.UserType,
		SubjectKind: policy.UsersKind,
		Permission:  policy.MembershipPermission,
		ObjectType:  policy.PlatformType,
		Object:      policy.MagistralaObject,
	}
)

func IdentifyMiddleware(authClient auth.AuthClient) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := apiutil.ExtractBearerToken(r)
			if token == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			resp, err := authClient.Identify(r.Context(), &magistrala.IdentityReq{Token: token})
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), "session", auth.Session{
				UserID:   resp.GetUserId(),
				DomainID: resp.GetDomainId(),
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func authorizeMiddleware(authClient auth.AuthClient, authReq policy.PolicyReq) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			req := request.(authorizeReq)
			if err := req.validate(); err != nil {
				return nil, errors.Wrap(apiutil.ErrValidation, err)
			}
			var subject string
			switch {
			case authReq.Subject != "":
				subject = authReq.Subject
			case authReq.SubjectKind == policy.TokenKind:
				subject = req.token
			case authReq.SubjectKind == policy.UsersKind:
				subject = req.id
			}

			permission := authReq.Permission
			if permission == "" {
				permission = mgauth.SwitchToPermission(req.Page.Permission)
			}
			object := authReq.Object
			if object == "" {
				object = req.objectID
			}

			res, err := authClient.Authorize(ctx, &magistrala.AuthorizeReq{
				SubjectType: authReq.SubjectType,
				SubjectKind: authReq.SubjectKind,
				Subject:     subject,
				Permission:  permission,
				ObjectType:  authReq.ObjectType,
				Object:      object,
			})
			if err != nil || !res.Authorized {
				return nil, errors.Wrap(svcerr.ErrAuthorization, err)
			}
			fmt.Println("This authorization was successful")
			return next(ctx, request)
		}
	}
}

func checkSuperAdminMiddleware(authClient auth.AuthClient) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			session, ok := ctx.Value("session").(auth.Session)
			if !ok {
				return nil, svcerr.ErrAuthorization
			}
			var superAdmin bool
			_, err := authClient.Authorize(ctx, &magistrala.AuthorizeReq{
				SubjectType: policy.UserType,
				SubjectKind: policy.UsersKind,
				Subject:     session.UserID,
				Permission:  policy.AdminPermission,
				ObjectType:  policy.PlatformType,
				Object:      policy.MagistralaObject,
			})
			if err == nil {
				superAdmin = true
			}

			ctx = context.WithValue(ctx, "session", auth.Session{
				UserID:     session.UserID,
				DomainID:   session.DomainID,
				SuperAdmin: superAdmin,
			})
			fmt.Println("This authorization was successful")
			return next(ctx, request)
		}
	}
}
