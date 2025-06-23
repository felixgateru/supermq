// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package topics

import (
	"context"
	"fmt"

	grpcChannelsV1 "github.com/absmach/supermq/api/grpc/channels/v1"
	grpcCommonV1 "github.com/absmach/supermq/api/grpc/common/v1"
	grpcDomainsV1 "github.com/absmach/supermq/api/grpc/domains/v1"
	api "github.com/absmach/supermq/api/http"
	"github.com/absmach/supermq/pkg/errors"
	"github.com/absmach/supermq/pkg/messaging"
)

var (
	ErrInvalidTopicType     = errors.New("invalid topic type")
	ErrFailedResolveDomain  = errors.New("failed to resolve domain route")
	ErrFailedResolveChannel = errors.New("failed to resolve channel route")
)

type TopicType uint8

const (
	// PublishTopicType represents a topic used for publishing messages.
	PubTopicType TopicType = iota
	// SubscribeTopicType represents a topic used for subscribing to messages.
	SubTopicType
)

type Resolver interface {
	ResolveTopic(ctx context.Context, topicType TopicType, topic string) (domainID string, channelID string, subTopic string, err error)
	ResolveWSSubTopic(ctx context.Context, domain, channel, rsubTopic string) (domainID string, channelID string, subTopic string, err error)
	ResolveMQTTTopic(ctx context.Context, rtopic string) (topic string, err error)
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

func (r *resolver) ResolveTopic(ctx context.Context, topicType TopicType, topic string) (string, string, string, error) {
	var domain, channel, subTopic string
	var err error
	switch topicType {
	case PubTopicType:
		domain, channel, subTopic, err = messaging.ParsePublishTopic(topic)
	case SubTopicType:
		domain, channel, subTopic, err = messaging.ParseSubscribeTopic(topic)
	default:
		return "", "", "", ErrInvalidTopicType
	}
	if err != nil {
		return "", "", "", err
	}
	if domain == "" || channel == "" {
		return "", "", "", messaging.ErrMalformedTopic
	}

	domainID, err := r.resolveDomain(ctx, domain)
	if err != nil {
		return "", "", "", errors.Wrap(ErrFailedResolveDomain, err)
	}
	channelID, err := r.resolveChannel(ctx, channel, domainID)
	if err != nil {
		return "", "", "", errors.Wrap(ErrFailedResolveChannel, err)
	}

	return domainID, channelID, subTopic, nil
}

func (r *resolver) ResolveWSSubTopic(ctx context.Context, domain, channel, subTopic string) (string, string, string, error) {
	var st string
	domainID, err := r.resolveDomain(ctx, domain)
	if err != nil {
		return "", "", "", errors.Wrap(ErrFailedResolveDomain, err)
	}

	channelID, err := r.resolveChannel(ctx, channel, domainID)
	if err != nil {
		return "", "", "", errors.Wrap(ErrFailedResolveChannel, err)
	}

	if subTopic != "" {
		st, err = messaging.ParseSubscribeSubtopic(subTopic)
		if err != nil {
			return "", "", "", errors.Wrap(messaging.ErrMalformedSubtopic, err)
		}
	}

	return domainID, channelID, st, nil
}

func (r *resolver) ResolveMQTTTopic(ctx context.Context, topic string) (string, error) {
	matches := messaging.TopicRegExp.FindStringSubmatch(topic)
	if len(matches) < 4 {
		return "", messaging.ErrMalformedTopic
	}

	domainID, err := r.resolveDomain(ctx, matches[1])
	if err != nil {
		return "", errors.Wrap(ErrFailedResolveDomain, err)
	}
	channelID, err := r.resolveChannel(ctx, matches[2], domainID)
	if err != nil {
		return "", errors.Wrap(ErrFailedResolveChannel, err)
	}

	return fmt.Sprintf("m/%s/c/%s%s", domainID, channelID, matches[3]), nil
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
