// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/absmach/magistrala"
	"github.com/absmach/magistrala/internal/api"
	gapi "github.com/absmach/magistrala/internal/groups/api"
	"github.com/absmach/magistrala/pkg/apiutil"
	"github.com/absmach/magistrala/pkg/auth"
	"github.com/absmach/magistrala/pkg/errors"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	"github.com/absmach/magistrala/pkg/groups"
	"github.com/absmach/magistrala/pkg/policies"
	"github.com/go-chi/chi/v5"
	"github.com/go-kit/kit/endpoint"
	kithttp "github.com/go-kit/kit/transport/http"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// MakeHandler returns a HTTP handler for Groups API endpoints.
func groupsHandler(svc groups.Service, authClient auth.AuthClient, r *chi.Mux, logger *slog.Logger) http.Handler {
	opts := []kithttp.ServerOption{
		kithttp.ServerErrorEncoder(apiutil.LoggingErrorEncoder(logger, api.EncodeError)),
	}

	checkSuperAdminMiddleware := api.CheckSuperAdminMiddleware(authClient)
	r.Group(func(r chi.Router) {
		r.Use(api.IdentifyMiddleware(authClient))

		r.Route("/groups", func(r chi.Router) {
			authzMiddleware := api.AuthorizeMiddleware(authClient, gapi.CreateGroupAuthReq)
			r.Post("/", otelhttp.NewHandler(kithttp.NewServer(
				authzMiddleware(gapi.CreateGroupEndpoint(svc, policies.NewGroupKind)),
				gapi.DecodeGroupCreate,
				api.EncodeResponse,
				opts...,
			), "create_group").ServeHTTP)

			authzMiddleware = api.AuthorizeMiddleware(authClient, gapi.ViewGroupAuthReq)
			r.Get("/{groupID}", otelhttp.NewHandler(kithttp.NewServer(
				authzMiddleware(gapi.ViewGroupEndpoint(svc)),
				gapi.DecodeGroupRequest,
				api.EncodeResponse,
				opts...,
			), "view_group").ServeHTTP)

			authzMiddleware = api.AuthorizeMiddleware(authClient, gapi.DeleteGroupAuthReq)
			r.Delete("/{groupID}", otelhttp.NewHandler(kithttp.NewServer(
				authzMiddleware(gapi.DeleteGroupEndpoint(svc)),
				gapi.DecodeGroupRequest,
				api.EncodeResponse,
				opts...,
			), "delete_group").ServeHTTP)

			r.Get("/{groupID}/permissions", otelhttp.NewHandler(kithttp.NewServer(
				gapi.ViewGroupPermsEndpoint(svc),
				gapi.DecodeGroupPermsRequest,
				api.EncodeResponse,
				opts...,
			), "view_group_permissions").ServeHTTP)

			authzMiddleware = api.AuthorizeMiddleware(authClient, gapi.UpdateGroupAuthReq)
			r.Put("/{groupID}", otelhttp.NewHandler(kithttp.NewServer(
				authzMiddleware(gapi.UpdateGroupEndpoint(svc)),
				gapi.DecodeGroupUpdate,
				api.EncodeResponse,
				opts...,
			), "update_group").ServeHTTP)

			authzMiddleware = api.AuthorizeMiddleware(authClient, gapi.ListGroupsByUserAuthReq)
			r.Get("/", otelhttp.NewHandler(kithttp.NewServer(
				checkSuperAdminMiddleware(authzMiddleware(gapi.ListGroupsEndpoint(svc, "groups", "users"))),
				gapi.DecodeListGroupsRequest,
				api.EncodeResponse,
				opts...,
			), "list_groups").ServeHTTP)

			r.Get("/{groupID}/children", otelhttp.NewHandler(kithttp.NewServer(
				checkSuperAdminMiddleware(authzMiddleware(gapi.ListGroupsEndpoint(svc, "groups", "users"))),
				gapi.DecodeListChildrenRequest,
				api.EncodeResponse,
				opts...,
			), "list_children").ServeHTTP)

			r.Get("/{groupID}/parents", otelhttp.NewHandler(kithttp.NewServer(
				checkSuperAdminMiddleware(authzMiddleware(gapi.ListGroupsEndpoint(svc, "groups", "users"))),
				gapi.DecodeListParentsRequest,
				api.EncodeResponse,
				opts...,
			), "list_parents").ServeHTTP)

			authzMiddleware = api.AuthorizeMiddleware(authClient, gapi.ChangeGroupStatusAuthReq)
			r.Post("/{groupID}/enable", otelhttp.NewHandler(kithttp.NewServer(
				authzMiddleware(gapi.EnableGroupEndpoint(svc)),
				gapi.DecodeChangeGroupStatus,
				api.EncodeResponse,
				opts...,
			), "enable_group").ServeHTTP)

			r.Post("/{groupID}/disable", otelhttp.NewHandler(kithttp.NewServer(
				authzMiddleware(gapi.DisableGroupEndpoint(svc)),
				gapi.DecodeChangeGroupStatus,
				api.EncodeResponse,
				opts...,
			), "disable_group").ServeHTTP)

			authzMiddleware = api.AuthorizeMiddleware(authClient, assignUsersAuthReq)
			r.Post("/{groupID}/users/assign", otelhttp.NewHandler(kithttp.NewServer(
				authzMiddleware(assignUsersEndpoint(svc)),
				decodeAssignUsersRequest,
				api.EncodeResponse,
				opts...,
			), "assign_users").ServeHTTP)

			r.Post("/{groupID}/users/unassign", otelhttp.NewHandler(kithttp.NewServer(
				authzMiddleware(unassignUsersEndpoint(svc)),
				decodeUnassignUsersRequest,
				api.EncodeResponse,
				opts...,
			), "unassign_users").ServeHTTP)

			authzMiddleware = api.AuthorizeMiddleware(authClient, assignGroupsAuthReq)
			r.Post("/{groupID}/groups/assign", otelhttp.NewHandler(kithttp.NewServer(
				authzMiddleware(assignGroupsEndpoint(svc)),
				decodeAssignGroupsRequest,
				api.EncodeResponse,
				opts...,
			), "assign_groups").ServeHTTP)

			r.Post("/{groupID}/groups/unassign", otelhttp.NewHandler(kithttp.NewServer(
				authzMiddleware(unassignGroupsEndpoint(svc)),
				decodeUnassignGroupsRequest,
				api.EncodeResponse,
				opts...,
			), "unassign_groups").ServeHTTP)
		})

		// The ideal placeholder name should be {channelID}, but gapi.DecodeListGroupsRequest uses {memberID} as a placeholder for the ID.
		// So here, we are using {memberID} as the placeholder.
		authzMiddleware := api.AuthorizeMiddleware(authClient, gapi.ListGroupsByChannelAuthReq)
		r.Get("/channels/{memberID}/groups", otelhttp.NewHandler(kithttp.NewServer(
			authzMiddleware(gapi.ListGroupsEndpoint(svc, "groups", "channels")),
			gapi.DecodeListGroupsRequest,
			api.EncodeResponse,
			opts...,
		), "list_groups_by_channel_id").ServeHTTP)

		authzMiddleware = api.AuthorizeMiddleware(authClient, gapi.ListGroupsByUserAuthReq)
		r.Get("/users/{memberID}/groups", otelhttp.NewHandler(kithttp.NewServer(
			checkSuperAdminMiddleware(authzMiddleware(gapi.ListGroupsEndpoint(svc, "groups", "users"))),
			gapi.DecodeListGroupsRequest,
			api.EncodeResponse,
			opts...,
		), "list_groups_by_user_id").ServeHTTP)
	})

	return r
}

func decodeAssignUsersRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := assignUsersReq{
		token:   apiutil.ExtractBearerToken(r),
		groupID: chi.URLParam(r, "groupID"),
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, errors.Wrap(err, errors.ErrMalformedEntity))
	}
	return req, nil
}

func decodeUnassignUsersRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := assignUsersReq{
		token:   apiutil.ExtractBearerToken(r),
		groupID: chi.URLParam(r, "groupID"),
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, errors.Wrap(err, errors.ErrMalformedEntity))
	}
	return req, nil
}

func assignUsersEndpoint(svc groups.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(assignUsersReq)

		session, ok := ctx.Value(api.SessionKey).(auth.Session)
		if !ok {
			return nil, svcerr.ErrAuthorization
		}
		if err := svc.Assign(ctx, session, req.groupID, req.Relation, "users", req.UserIDs...); err != nil {
			return nil, err
		}
		return assignUsersRes{}, nil
	}
}

func unassignUsersEndpoint(svc groups.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(assignUsersReq)

		session, ok := ctx.Value(api.SessionKey).(auth.Session)
		if !ok {
			return nil, svcerr.ErrAuthorization
		}

		if err := svc.Unassign(ctx, session, req.groupID, req.Relation, "users", req.UserIDs...); err != nil {
			return nil, err
		}
		return unassignUsersRes{}, nil
	}
}

func decodeAssignGroupsRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := assignGroupsReq{
		token:   apiutil.ExtractBearerToken(r),
		groupID: chi.URLParam(r, "groupID"),
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, errors.Wrap(err, errors.ErrMalformedEntity))
	}
	return req, nil
}

func decodeUnassignGroupsRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := assignGroupsReq{
		token:   apiutil.ExtractBearerToken(r),
		groupID: chi.URLParam(r, "groupID"),
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, errors.Wrap(err, errors.ErrMalformedEntity))
	}
	return req, nil
}

func assignGroupsEndpoint(svc groups.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(assignGroupsReq)

		session, ok := ctx.Value(api.SessionKey).(auth.Session)
		if !ok {
			return nil, svcerr.ErrAuthorization
		}
		if err := svc.Assign(ctx, session, req.groupID, policies.ParentGroupRelation, policies.GroupsKind, req.GroupIDs...); err != nil {
			return nil, err
		}
		return assignUsersRes{}, nil
	}
}

func unassignGroupsEndpoint(svc groups.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(assignGroupsReq)

		session, ok := ctx.Value(api.SessionKey).(auth.Session)
		if !ok {
			return nil, svcerr.ErrAuthorization
		}

		if err := svc.Unassign(ctx, session, req.groupID, policies.ParentGroupRelation, policies.GroupsKind, req.GroupIDs...); err != nil {
			return nil, err
		}
		return unassignUsersRes{}, nil
	}
}

func assignGroupsAuthReq(ctx context.Context, request interface{}) ([]*magistrala.AuthorizeReq, error) {
	req := request.(assignGroupsReq)
	if err := req.validate(); err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, err)
	}

	session, ok := ctx.Value(api.SessionKey).(auth.Session)
	if !ok {
		return nil, svcerr.ErrAuthorization
	}

	prs := []*magistrala.AuthorizeReq{
		{
			Domain:      session.DomainID,
			SubjectType: policies.UserType,
			SubjectKind: policies.UsersKind,
			Subject:     session.DomainUserID,
			Permission:  policies.EditPermission,
			ObjectType:  policies.GroupType,
			Object:      req.groupID,
		},
	}
	return prs, nil
}

func assignUsersAuthReq(ctx context.Context, request interface{}) ([]*magistrala.AuthorizeReq, error) {
	req := request.(assignUsersReq)
	if err := req.validate(); err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, err)
	}

	session, ok := ctx.Value(api.SessionKey).(auth.Session)
	if !ok {
		return nil, svcerr.ErrAuthorization
	}

	prs := []*magistrala.AuthorizeReq{
		{
			Domain:      session.DomainID,
			SubjectType: policies.UserType,
			SubjectKind: policies.UsersKind,
			Subject:     session.DomainUserID,
			Permission:  policies.EditPermission,
			ObjectType:  policies.GroupType,
			Object:      req.groupID,
		},
	}
	return prs, nil
}
