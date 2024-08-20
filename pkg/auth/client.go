// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"

	"github.com/absmach/magistrala"
	authgrpc "github.com/absmach/magistrala/auth/api/grpc"
	"github.com/absmach/magistrala/pkg/errors"
	thingsauth "github.com/absmach/magistrala/things/api/grpc"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
)

var errSvcNotServing = errors.New("service is not serving")

// SetupAuthnz loads Authnz gRPC configuration and creates new Authnz gRPC client.
//
// For example:
//
//	authnzClient, authnzHandler, err := auth.SetupAuthnz(ctx, auth.Config{}).
func SetupAuthnz(ctx context.Context, cfg Config) (magistrala.AuthnzServiceClient, Handler, error) {
	client, err := newHandler(cfg)
	if err != nil {
		return nil, nil, err
	}

	health := grpchealth.NewHealthClient(client.Connection())
	resp, err := health.Check(ctx, &grpchealth.HealthCheckRequest{
		Service: "auth",
	})
	if err != nil || resp.GetStatus() != grpchealth.HealthCheckResponse_SERVING {
		return nil, nil, errSvcNotServing
	}

	return authgrpc.NewAuthnzClient(client.Connection(), cfg.Timeout), client, nil
}

// SetupPolicyClient loads Policy gRPC configuration and creates a new Policy gRPC client.
//
// For example:
//
// policyClient, policyHandler, err := auth.SetupPolicyClient(ctx, auth.Config{}).
func SetupPolicyClient(ctx context.Context, cfg Config) (magistrala.PolicyServiceClient, Handler, error) {
	client, err := newHandler(cfg)
	if err != nil {
		return nil, nil, err
	}

	health := grpchealth.NewHealthClient(client.Connection())
	resp, err := health.Check(ctx, &grpchealth.HealthCheckRequest{
		Service: "auth",
	})
	if err != nil || resp.GetStatus() != grpchealth.HealthCheckResponse_SERVING {
		return nil, nil, errSvcNotServing
	}

	return authgrpc.NewPolicyClient(client.Connection(), cfg.Timeout), client, nil
}

// SetupAuthz loads Authz gRPC configuration and creates new Authz gRPC client.
//
// For example:
//
//	authzClient, authzHandler, err := auth.Setup(ctx, auth.Config{}).
func SetupAuthz(ctx context.Context, cfg Config) (magistrala.AuthzServiceClient, Handler, error) {
	client, err := newHandler(cfg)
	if err != nil {
		return nil, nil, err
	}

	health := grpchealth.NewHealthClient(client.Connection())
	resp, err := health.Check(ctx, &grpchealth.HealthCheckRequest{
		Service: "things",
	})
	if err != nil || resp.GetStatus() != grpchealth.HealthCheckResponse_SERVING {
		return nil, nil, errSvcNotServing
	}

	return thingsauth.NewClient(client.Connection(), cfg.Timeout), client, nil
}
