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
	"github.com/absmach/magistrala/pkg/policy"
	"github.com/go-kit/kit/endpoint"
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

func AuthorizeMiddleware(authClient auth.AuthClient, subjectKind, subject, permission, objectType, objectID string) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			req := request.(viewClientReq)
			if err := req.validate(); err != nil {
				return nil, errors.Wrap(apiutil.ErrValidation, err)
			}

			res, err := authClient.Authorize(ctx, &magistrala.AuthorizeReq{
				SubjectType: policy.UserType,
				SubjectKind: subjectKind,
				Subject:     subject,
				Permission:  permission,
				ObjectType:  objectType,
				Object:      objectID,
			})
			if err != nil || !res.Authorized {
				return nil, errors.Wrap(svcerr.ErrAuthorization, err)
			}

			return next(ctx, request)
		}
	}
}

func CheckSuperAdminMiddleware(authClient auth.AuthClient) endpoint.Middleware {
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

			return next(ctx, request)
		}
	}
}
