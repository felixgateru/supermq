// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	api "github.com/absmach/supermq/api/http"
	apiutil "github.com/absmach/supermq/api/http/util"
	"github.com/absmach/supermq/domains"
	"github.com/absmach/supermq/pkg/authn"
	"github.com/absmach/supermq/pkg/errors"
	"github.com/go-chi/chi/v5"
	kithttp "github.com/go-kit/kit/transport/http"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

const (
	userIDKey    = "user_id"
	domainIDKey  = "domain_id"
	invitedByKey = "invited_by"
	roleIDKey    = "role_id"
	roleNameKey  = "role_name"
	stateKey     = "state"
)

func invitationsHandler(svc domains.Service, authn authn.Authentication, mux *chi.Mux, logger *slog.Logger) *chi.Mux {
	opts := []kithttp.ServerOption{
		kithttp.ServerErrorEncoder(apiutil.LoggingErrorEncoder(logger, api.EncodeError)),
	}

	mux.Group(func(r chi.Router) {
		r.Use(api.AuthenticateMiddleware(authn, false))

		r.Route("/invitations", func(r chi.Router) {
			r.Post("/", otelhttp.NewHandler(kithttp.NewServer(
				sendInvitationEndpoint(svc),
				decodeSendInvitationReq,
				api.EncodeResponse,
				opts...,
			), "send_invitation").ServeHTTP)
			r.Get("/", otelhttp.NewHandler(kithttp.NewServer(
				listInvitationsEndpoint(svc),
				decodeListInvitationsReq,
				api.EncodeResponse,
				opts...,
			), "list_invitations").ServeHTTP)
			r.Route("/{user_id}/{domain_id}", func(r chi.Router) {
				r.Get("/", otelhttp.NewHandler(kithttp.NewServer(
					viewInvitationEndpoint(svc),
					decodeInvitationReq,
					api.EncodeResponse,
					opts...,
				), "view_invitations").ServeHTTP)
				r.Delete("/", otelhttp.NewHandler(kithttp.NewServer(
					deleteInvitationEndpoint(svc),
					decodeInvitationReq,
					api.EncodeResponse,
					opts...,
				), "delete_invitation").ServeHTTP)
			})
			r.Post("/accept", otelhttp.NewHandler(kithttp.NewServer(
				acceptInvitationEndpoint(svc),
				decodeAcceptInvitationReq,
				api.EncodeResponse,
				opts...,
			), "accept_invitation").ServeHTTP)
			r.Post("/reject", otelhttp.NewHandler(kithttp.NewServer(
				rejectInvitationEndpoint(svc),
				decodeAcceptInvitationReq,
				api.EncodeResponse,
				opts...,
			), "reject_invitation").ServeHTTP)
		})
	})

	return mux
}

func decodeSendInvitationReq(_ context.Context, r *http.Request) (interface{}, error) {
	if !strings.Contains(r.Header.Get("Content-Type"), api.ContentType) {
		return nil, errors.Wrap(apiutil.ErrValidation, apiutil.ErrUnsupportedContentType)
	}

	var req sendInvitationReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, errors.Wrap(err, errors.ErrMalformedEntity))
	}

	return req, nil
}

func decodeListInvitationsReq(_ context.Context, r *http.Request) (interface{}, error) {
	offset, err := apiutil.ReadNumQuery[uint64](r, api.OffsetKey, api.DefOffset)
	if err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, err)
	}
	limit, err := apiutil.ReadNumQuery[uint64](r, api.LimitKey, api.DefLimit)
	if err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, err)
	}
	userID, err := apiutil.ReadStringQuery(r, userIDKey, "")
	if err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, err)
	}
	invitedBy, err := apiutil.ReadStringQuery(r, invitedByKey, "")
	if err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, err)
	}
	roleID, err := apiutil.ReadStringQuery(r, roleIDKey, "")
	if err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, err)
	}
	roleName, err := apiutil.ReadStringQuery(r, roleNameKey, "")
	if err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, err)
	}
	domainID, err := apiutil.ReadStringQuery(r, domainIDKey, "")
	if err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, err)
	}
	st, err := apiutil.ReadStringQuery(r, stateKey, domains.AllState.String())
	if err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, err)
	}
	state, err := domains.ToState(st)
	if err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, err)
	}
	req := listInvitationsReq{
		InvitationPageMeta: domains.InvitationPageMeta{
			Offset:    offset,
			Limit:     limit,
			InvitedBy: invitedBy,
			UserID:    userID,
			RoleID:    roleID,
			RoleName:  roleName,
			DomainID:  domainID,
			State:     state,
		},
	}

	return req, nil
}

func decodeAcceptInvitationReq(_ context.Context, r *http.Request) (interface{}, error) {
	if !strings.Contains(r.Header.Get("Content-Type"), api.ContentType) {
		return nil, errors.Wrap(apiutil.ErrValidation, apiutil.ErrUnsupportedContentType)
	}

	var req acceptInvitationReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, errors.Wrap(err, errors.ErrMalformedEntity))
	}

	return req, nil
}

func decodeInvitationReq(_ context.Context, r *http.Request) (interface{}, error) {
	req := invitationReq{
		userID:   chi.URLParam(r, "user_id"),
		domainID: chi.URLParam(r, "domain_id"),
	}

	return req, nil
}
