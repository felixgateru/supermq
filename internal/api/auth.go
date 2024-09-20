// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"

	"github.com/absmach/magistrala"
	"github.com/absmach/magistrala/pkg/apiutil"
	"github.com/absmach/magistrala/pkg/auth"
	"github.com/absmach/magistrala/pkg/errors"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	"github.com/absmach/magistrala/pkg/policies"
	"github.com/go-kit/kit/endpoint"
)

type sessionKeyType string

const SessionKey = sessionKeyType("session")

type authEndpointFunc func(context.Context, interface{}) ([]*magistrala.AuthorizeReq, error)

func IdentifyMiddleware(authClient auth.AuthClient) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := apiutil.ExtractBearerToken(r)
			if token == "" {
				EncodeError(r.Context(), apiutil.ErrBearerToken, w)
				return
			}

			resp, err := authClient.Identify(r.Context(), &magistrala.IdentityReq{Token: token})
			if err != nil {
				EncodeError(r.Context(), err, w)
				return
			}

			ctx := context.WithValue(r.Context(), SessionKey, auth.Session{
				DomainUserID: resp.GetId(),
				UserID:       resp.GetUserId(),
				DomainID:     resp.GetDomainId(),
			})

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func AuthorizeMiddleware(authClient auth.AuthClient, getAuthReq authEndpointFunc) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			prs, err := getAuthReq(ctx, request)
			if err != nil {
				return nil, errors.Wrap(apiutil.ErrValidation, err)
			}

			for _, pr := range prs {
				res, err := authClient.Authorize(ctx, pr)
				if err != nil || !res.Authorized {
					return nil, errors.Wrap(svcerr.ErrAuthorization, err)
				}
			}
			return next(ctx, request)
		}
	}
}

func CheckSuperAdminMiddleware(authClient auth.AuthClient) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			session, ok := ctx.Value(SessionKey).(auth.Session)
			if !ok {
				return nil, svcerr.ErrAuthorization
			}
			var superAdmin bool
			res, err := authClient.Authorize(ctx, &magistrala.AuthorizeReq{
				SubjectType: policies.UserType,
				SubjectKind: policies.UsersKind,
				Subject:     session.UserID,
				Permission:  policies.AdminPermission,
				ObjectType:  policies.PlatformType,
				Object:      policies.MagistralaObject,
			})
			if err == nil && res.Authorized {
				superAdmin = true
			}

			ctx = context.WithValue(ctx, SessionKey, auth.Session{
				DomainUserID: session.DomainUserID,
				UserID:       session.UserID,
				DomainID:     session.DomainID,
				SuperAdmin:   superAdmin,
			})

			return next(ctx, request)
		}
	}
}
