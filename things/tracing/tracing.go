// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"

	"github.com/absmach/magistrala/pkg/authn"
	rmTrace "github.com/absmach/magistrala/pkg/roles/rolemanager/tracing"
	"github.com/absmach/magistrala/things"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var _ things.Service = (*tracingMiddleware)(nil)

type tracingMiddleware struct {
	tracer trace.Tracer
	svc    things.Service
	rmTrace.RoleManagerTracing
}

// New returns a new group service with tracing capabilities.
func New(svc things.Service, tracer trace.Tracer) things.Service {
	return &tracingMiddleware{
		tracer:             tracer,
		svc:                svc,
		RoleManagerTracing: rmTrace.NewRoleManagerTracing("group", svc, tracer),
	}
}

// CreateClients traces the "CreateClients" operation of the wrapped policies.Service.
func (tm *tracingMiddleware) CreateClients(ctx context.Context, session authn.Session, cli ...things.Client) ([]things.Client, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_create_client")
	defer span.End()

	return tm.svc.CreateClients(ctx, session, cli...)
}

// View traces the "View" operation of the wrapped policies.Service.
func (tm *tracingMiddleware) View(ctx context.Context, session authn.Session, id string) (things.Client, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_view_client", trace.WithAttributes(attribute.String("id", id)))
	defer span.End()
	return tm.svc.View(ctx, session, id)
}

// ListClients traces the "ListClients" operation of the wrapped policies.Service.
func (tm *tracingMiddleware) ListClients(ctx context.Context, session authn.Session, reqUserID string, pm things.Page) (things.ClientsPage, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_list_clients")
	defer span.End()
	return tm.svc.ListClients(ctx, session, reqUserID, pm)
}

// Update traces the "Update" operation of the wrapped policies.Service.
func (tm *tracingMiddleware) Update(ctx context.Context, session authn.Session, cli things.Client) (things.Client, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_update_client", trace.WithAttributes(attribute.String("id", cli.ID)))
	defer span.End()

	return tm.svc.Update(ctx, session, cli)
}

// UpdateTags traces the "UpdateTags" operation of the wrapped policies.Service.
func (tm *tracingMiddleware) UpdateTags(ctx context.Context, session authn.Session, cli things.Client) (things.Client, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_update_client_tags", trace.WithAttributes(
		attribute.String("id", cli.ID),
		attribute.StringSlice("tags", cli.Tags),
	))
	defer span.End()

	return tm.svc.UpdateTags(ctx, session, cli)
}

// UpdateSecret traces the "UpdateSecret" operation of the wrapped policies.Service.
func (tm *tracingMiddleware) UpdateSecret(ctx context.Context, session authn.Session, oldSecret, newSecret string) (things.Client, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_update_client_secret")
	defer span.End()

	return tm.svc.UpdateSecret(ctx, session, oldSecret, newSecret)
}

// Enable traces the "Enable" operation of the wrapped policies.Service.
func (tm *tracingMiddleware) Enable(ctx context.Context, session authn.Session, id string) (things.Client, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_enable_client", trace.WithAttributes(attribute.String("id", id)))
	defer span.End()

	return tm.svc.Enable(ctx, session, id)
}

// Disable traces the "Disable" operation of the wrapped policies.Service.
func (tm *tracingMiddleware) Disable(ctx context.Context, session authn.Session, id string) (things.Client, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_disable_client", trace.WithAttributes(attribute.String("id", id)))
	defer span.End()

	return tm.svc.Disable(ctx, session, id)
}

// Delete traces the "Delete" operation of the wrapped things.Service.
func (tm *tracingMiddleware) Delete(ctx context.Context, session authn.Session, id string) error {
	ctx, span := tm.tracer.Start(ctx, "delete_client", trace.WithAttributes(attribute.String("id", id)))
	defer span.End()
	return tm.svc.Delete(ctx, session, id)
}

func (tm *tracingMiddleware) SetParentGroup(ctx context.Context, session authn.Session, parentGroupID string, id string) error {
	ctx, span := tm.tracer.Start(ctx, "set_parent_group", trace.WithAttributes(
		attribute.String("id", id),
		attribute.String("parent_group_id", parentGroupID),
	))
	defer span.End()
	return tm.svc.SetParentGroup(ctx, session, parentGroupID, id)
}

func (tm *tracingMiddleware) RemoveParentGroup(ctx context.Context, session authn.Session, id string) error {
	ctx, span := tm.tracer.Start(ctx, "remove_parent_group", trace.WithAttributes(attribute.String("id", id)))
	defer span.End()
	return tm.svc.RemoveParentGroup(ctx, session, id)
}
