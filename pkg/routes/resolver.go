// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package routes

import (
	"context"

	grpcChannelsV1 "github.com/absmach/supermq/api/grpc/channels/v1"
	grpcCommonV1 "github.com/absmach/supermq/api/grpc/common/v1"
	grpcDomainsV1 "github.com/absmach/supermq/api/grpc/domains/v1"
	api "github.com/absmach/supermq/api/http"
	"github.com/absmach/supermq/pkg/errors"
)

var (
	ErrEmptyRoute           = errors.New("empty route")
	ErrFailedResolveDomain  = errors.New("failed to resolve domain route")
	ErrFailedResolveChannel = errors.New("failed to resolve channel route")
)

type Resolver interface {
	Resolve(ctx context.Context, domain, channel string) (domainID string, channelID string, err error)
}

type resolver struct {
	channels grpcChannelsV1.ChannelsServiceClient
	domains  grpcDomainsV1.DomainsServiceClient
}

func NewResolver(channelsClient grpcChannelsV1.ChannelsServiceClient, domainsClient grpcDomainsV1.DomainsServiceClient) Resolver {
	return &resolver{
		channels: channelsClient,
		domains:  domainsClient,
	}
}

func (r *resolver) Resolve(ctx context.Context, domain, channel string) (string, string, error) {
	if domain == "" || channel == "" {
		return "", "", ErrEmptyRoute
	}

	domainID, err := r.resolveDomain(ctx, domain)
	if err != nil {
		return "", "", errors.Wrap(ErrFailedResolveDomain, err)
	}
	channelID, err := r.resolveChannel(ctx, channel, domainID)
	if err != nil {
		return "", "", errors.Wrap(ErrFailedResolveChannel, err)
	}

	return domainID, channelID, nil
}

func (r *resolver) resolveDomain(ctx context.Context, domain string) (string, error) {
	if api.ValidateUUID(domain) == nil {
		return domain, nil
	}
	d, err := r.domains.RetrieveByRoute(ctx, &grpcCommonV1.RetrieveByRouteReq{
		Route: domain,
	})
	if err != nil {
		return "", err
	}

	return d.Entity.Id, nil
}

func (r *resolver) resolveChannel(ctx context.Context, channel, domainID string) (string, error) {
	if api.ValidateUUID(channel) == nil {
		return channel, nil
	}
	c, err := r.channels.RetrieveByRoute(ctx, &grpcCommonV1.RetrieveByRouteReq{
		Route:    channel,
		DomainId: domainID,
	})
	if err != nil {
		return "", err
	}

	return c.Entity.Id, nil
}
