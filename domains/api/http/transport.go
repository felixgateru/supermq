// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"log/slog"
	"net/http"

	"github.com/absmach/supermq"
	"github.com/absmach/supermq/domains"
	"github.com/absmach/supermq/pkg/authn"
	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MakeHandler returns a HTTP handler for Users and Groups API endpoints.
func MakeHandler(svc domains.Service, authn authn.Authentication, mux *chi.Mux, logger *slog.Logger, instanceID string) http.Handler {
	domainsHandler(svc, authn, mux, logger)
	invitationsHandler(svc, authn, mux, logger)

	mux.Get("/health", supermq.Health("domains", instanceID))
	mux.Handle("/metrics", promhttp.Handler())

	return mux
}
