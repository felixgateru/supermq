// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"

	"github.com/absmach/supermq/channels"
	"github.com/absmach/supermq/pkg/authn"
	"github.com/absmach/supermq/pkg/connections"
	"github.com/absmach/supermq/pkg/roles"
	rmTrace "github.com/absmach/supermq/pkg/roles/rolemanager/tracing"
	"github.com/absmach/supermq/pkg/tracing"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var _ channels.Service = (*tracingMiddleware)(nil)

type tracingMiddleware struct {
	tracer trace.Tracer
	svc    channels.Service
	rmTrace.RoleManagerTracing
}

// New returns a new group service with tracing capabilities.
func New(svc channels.Service, tracer trace.Tracer) channels.Service {
	return &tracingMiddleware{tracer, svc, rmTrace.NewRoleManagerTracing("channels", svc, tracer)}
}

// CreateChannels traces the "CreateChannels" operation of the wrapped policies.Service.
func (tm *tracingMiddleware) CreateChannels(ctx context.Context, session authn.Session, chs ...channels.Channel) ([]channels.Channel, []roles.RoleProvision, error) {
	ctx, span := tracing.StartSpan(ctx, tm.tracer, "svc_create_channel")
	defer span.End()

	return tm.svc.CreateChannels(ctx, session, chs...)
}

// ViewChannel traces the "ViewChannel" operation of the wrapped policies.Service.
func (tm *tracingMiddleware) ViewChannel(ctx context.Context, session authn.Session, id string, withRoles bool) (channels.Channel, error) {
	ctx, span := tracing.StartSpan(ctx, tm.tracer, "svc_view_channel", trace.WithAttributes(attribute.String("id", id)))
	defer span.End()
	return tm.svc.ViewChannel(ctx, session, id, withRoles)
}

// ListChannels traces the "ListChannels" operation of the wrapped policies.Service.
func (tm *tracingMiddleware) ListChannels(ctx context.Context, session authn.Session, pm channels.Page) (channels.ChannelsPage, error) {
	ctx, span := tracing.StartSpan(ctx, tm.tracer, "svc_list_channels")
	defer span.End()
	return tm.svc.ListChannels(ctx, session, pm)
}

func (tm *tracingMiddleware) ListUserChannels(ctx context.Context, session authn.Session, userID string, pm channels.Page) (channels.ChannelsPage, error) {
	ctx, span := tracing.StartSpan(ctx, tm.tracer, "svc_list_user_channels")
	defer span.End()
	return tm.svc.ListUserChannels(ctx, session, userID, pm)
}

// UpdateChannel traces the "UpdateChannel" operation of the wrapped policies.Service.
func (tm *tracingMiddleware) UpdateChannel(ctx context.Context, session authn.Session, cli channels.Channel) (channels.Channel, error) {
	ctx, span := tracing.StartSpan(ctx, tm.tracer, "svc_update_channel", trace.WithAttributes(attribute.String("id", cli.ID)))
	defer span.End()

	return tm.svc.UpdateChannel(ctx, session, cli)
}

// UpdateChannelTags traces the "UpdateChannelTags" operation of the wrapped policies.Service.
func (tm *tracingMiddleware) UpdateChannelTags(ctx context.Context, session authn.Session, cli channels.Channel) (channels.Channel, error) {
	ctx, span := tracing.StartSpan(ctx, tm.tracer, "svc_update_channel_tags", trace.WithAttributes(
		attribute.String("id", cli.ID),
		attribute.StringSlice("tags", cli.Tags),
	))
	defer span.End()

	return tm.svc.UpdateChannelTags(ctx, session, cli)
}

// EnableChannel traces the "EnableChannel" operation of the wrapped policies.Service.
func (tm *tracingMiddleware) EnableChannel(ctx context.Context, session authn.Session, id string) (channels.Channel, error) {
	ctx, span := tracing.StartSpan(ctx, tm.tracer, "svc_enable_channel", trace.WithAttributes(attribute.String("id", id)))
	defer span.End()

	return tm.svc.EnableChannel(ctx, session, id)
}

// DisableChannel traces the "DisableChannel" operation of the wrapped policies.Service.
func (tm *tracingMiddleware) DisableChannel(ctx context.Context, session authn.Session, id string) (channels.Channel, error) {
	ctx, span := tracing.StartSpan(ctx, tm.tracer, "svc_disable_channel", trace.WithAttributes(attribute.String("id", id)))
	defer span.End()

	return tm.svc.DisableChannel(ctx, session, id)
}

// DeleteChannel traces the "DeleteChannel" operation of the wrapped channels.Service.
func (tm *tracingMiddleware) RemoveChannel(ctx context.Context, session authn.Session, id string) error {
	ctx, span := tracing.StartSpan(ctx, tm.tracer, "delete_channel", trace.WithAttributes(attribute.String("id", id)))
	defer span.End()
	return tm.svc.RemoveChannel(ctx, session, id)
}

func (tm *tracingMiddleware) Connect(ctx context.Context, session authn.Session, chIDs, thIDs []string, connTypes []connections.ConnType) error {
	ctx, span := tracing.StartSpan(ctx, tm.tracer, "connect", trace.WithAttributes(
		attribute.StringSlice("channel_ids", chIDs),
		attribute.StringSlice("client_ids", thIDs),
	))
	defer span.End()
	return tm.svc.Connect(ctx, session, chIDs, thIDs, connTypes)
}

func (tm *tracingMiddleware) Disconnect(ctx context.Context, session authn.Session, chIDs, thIDs []string, connTypes []connections.ConnType) error {
	ctx, span := tracing.StartSpan(ctx, tm.tracer, "disconnect", trace.WithAttributes(
		attribute.StringSlice("channel_ids", chIDs),
		attribute.StringSlice("client_ids", thIDs),
	))
	defer span.End()
	return tm.svc.Disconnect(ctx, session, chIDs, thIDs, connTypes)
}

func (tm *tracingMiddleware) SetParentGroup(ctx context.Context, session authn.Session, parentGroupID string, id string) error {
	ctx, span := tracing.StartSpan(ctx, tm.tracer, "set_parent_group", trace.WithAttributes(
		attribute.String("parent_group_id", parentGroupID),
		attribute.String("id", id),
	))
	defer span.End()
	return tm.svc.SetParentGroup(ctx, session, parentGroupID, id)
}

func (tm *tracingMiddleware) RemoveParentGroup(ctx context.Context, session authn.Session, id string) error {
	ctx, span := tracing.StartSpan(ctx, tm.tracer, "remove_parent_group", trace.WithAttributes(
		attribute.String("id", id),
	))
	defer span.End()
	return tm.svc.RemoveParentGroup(ctx, session, id)
}
