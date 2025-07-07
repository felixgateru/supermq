// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package messaging

import (
	"context"

	grpcChannelsV1 "github.com/absmach/supermq/api/grpc/channels/v1"
	grpcDomainsV1 "github.com/absmach/supermq/api/grpc/domains/v1"
	"github.com/absmach/supermq/pkg/errors"
	"github.com/dgraph-io/ristretto/v2"
)

var (
	ErrCreateCache = errors.New("failed to create cache")

	DefaultCacheConfig = CacheConfig{
		NumCounters: 2e5,     // 200k
		MaxCost:     1 << 20, // 1MB
		BufferItems: 64,
	}
)

type CacheConfig struct {
	NumCounters int64 `env:"NUM_COUNTERS" envDefault:"200000"`  // number of keys to track frequency of.
	MaxCost     int64 `env:"MAX_COST"     envDefault:"1048576"` // maximum cost of cache.
	BufferItems int64 `env:"BUFFER_ITEMS" envDefault:"64"`      // number of keys per Get buffer.
}

type parsedTopic struct {
	domainID  string
	channelID string
	subtopic  string
	err       error
}

// TopicParser defines methods for parsing publish and subscribe topics.
// It uses a cache to store parsed topics for quick retrieval.
// It also resolves domain and channel IDs if requested.
type TopicParser interface {
	ParsePublishTopic(ctx context.Context, topic string, resolve bool) (domainID, channelID, subtopic string, err error)
	ParseSubscribeTopic(ctx context.Context, topic string, resolve bool) (domainID, channelID, subtopic string, err error)
}

type parser struct {
	resolver TopicResolver
	cache    *ristretto.Cache[string, *parsedTopic]
}

// NewTopicParser creates a new instance of TopicParser.
func NewTopicParser(cfg CacheConfig, channels grpcChannelsV1.ChannelsServiceClient, domains grpcDomainsV1.DomainsServiceClient) (TopicParser, error) {
	cache, err := ristretto.NewCache(&ristretto.Config[string, *parsedTopic]{
		NumCounters: cfg.NumCounters,
		MaxCost:     cfg.MaxCost,
		BufferItems: cfg.BufferItems,
		Cost:        costFunc,
	})
	if err != nil {
		return nil, errors.Wrap(ErrCreateCache, err)
	}
	return &parser{
		cache:    cache,
		resolver: NewTopicResolver(channels, domains),
	}, nil
}

func (p *parser) ParsePublishTopic(ctx context.Context, topic string, resolve bool) (string, string, string, error) {
	val, ok := p.cache.Get(topic)
	if ok {
		return val.domainID, val.channelID, val.subtopic, val.err
	}
	domainID, channelID, subtopic, err := ParsePublishTopic(topic)
	if err != nil {
		p.saveToCache(topic, "", "", "", err)
		return "", "", "", err
	}
	if resolve {
		domainID, channelID, err = p.resolver.Resolve(ctx, domainID, channelID)
		if err != nil {
			p.saveToCache(topic, "", "", "", err)
			return "", "", "", err
		}
	}
	p.saveToCache(topic, domainID, channelID, subtopic, nil)

	return domainID, channelID, subtopic, nil
}

func (p *parser) ParseSubscribeTopic(ctx context.Context, topic string, resolve bool) (string, string, string, error) {
	domainID, channelID, subtopic, err := ParseSubscribeTopic(topic)
	if err != nil {
		return "", "", "", err
	}
	if resolve {
		domainID, channelID, err = p.resolver.Resolve(ctx, domainID, channelID)
		if err != nil {
			p.saveToCache(topic, "", "", "", err)
			return "", "", "", err
		}
	}

	return domainID, channelID, subtopic, nil
}

func (p *parser) saveToCache(topic string, domainID, channelID, subtopic string, err error) {
	p.cache.Set(topic, &parsedTopic{
		domainID:  domainID,
		channelID: channelID,
		subtopic:  subtopic,
		err:       err,
	}, 0)
}

func costFunc(val *parsedTopic) int64 {
	errLen := 0
	if val.err != nil {
		errLen = len(val.err.Error())
	}
	cost := int64(len(val.domainID) + len(val.channelID) + len(val.subtopic) + errLen)

	return cost
}
