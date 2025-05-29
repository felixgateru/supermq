// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"context"
	"time"

	"github.com/absmach/supermq/pkg/errors"
	repoerr "github.com/absmach/supermq/pkg/errors/repository"
	"github.com/redis/go-redis/v9"
)

type channelsCache struct {
	client   *redis.Client
	duration time.Duration
}

func NewChannelsCache(client *redis.Client, duration time.Duration) *channelsCache {
	return &channelsCache{
		client:   client,
		duration: duration,
	}
}

func (cc *channelsCache) Save(ctx context.Context, domainID, channelID, channelRoute string) error {
	key := encodeKey(domainID, channelRoute)
	if err := cc.client.Set(ctx, key, channelID, cc.duration).Err(); err != nil {
		return errors.Wrap(repoerr.ErrCreateEntity, err)
	}

	return nil
}

func (cc *channelsCache) ChannelID(ctx context.Context, domainID, channelRoute string) (string, error) {
	key := encodeKey(domainID, channelRoute)
	channelID, err := cc.client.Get(ctx, key).Result()
	if err != nil {
		return "", errors.Wrap(repoerr.ErrNotFound, err)
	}

	return channelID, nil
}

func encodeKey(domainID, channelRoute string) string {
	return domainID + ":" + channelRoute
}
