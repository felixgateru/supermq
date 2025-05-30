// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package cache_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/absmach/supermq/channels"
	"github.com/absmach/supermq/channels/cache"
	"github.com/absmach/supermq/internal/testsutil"
	"github.com/absmach/supermq/pkg/errors"
	repoerr "github.com/absmach/supermq/pkg/errors/repository"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

func setupChannelsClient(t *testing.T) channels.Cache {
	opts, err := redis.ParseURL(redisURL)
	assert.Nil(t, err, fmt.Sprintf("got unexpected error on parsing redis URL: %s", err))
	redisClient := redis.NewClient(opts)

	return cache.NewChannelsCache(redisClient, 10*time.Minute)
}

func TestSaveID(t *testing.T) {
	cc := setupChannelsClient(t)

	route := "test-route"
	domainID := testsutil.GenerateUUID(t)

	cases := []struct {
		desc         string
		domainID     string
		channelID    string
		channelRoute string
		err          error
	}{
		{
			desc:         "Save successfully",
			domainID:     domainID,
			channelID:    testsutil.GenerateUUID(t),
			channelRoute: route,
			err:          nil,
		},
		{
			desc:         "Save with empty domain ID",
			domainID:     "",
			channelID:    testsutil.GenerateUUID(t),
			channelRoute: route,
			err:          cache.ErrEmptyDomainID,
		},
		{
			desc:         "Save with empty channel ID",
			domainID:     domainID,
			channelID:    "",
			channelRoute: route,
			err:          cache.ErrEmptyChannelID,
		},
		{
			desc:         "Save with empty channel route",
			domainID:     domainID,
			channelID:    testsutil.GenerateUUID(t),
			channelRoute: "",
			err:          cache.ErrEmptyChannelRoute,
		},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := cc.SaveID(context.Background(), tc.channelRoute, tc.domainID, tc.channelID)
			assert.True(t, errors.Contains(err, tc.err))
		})
	}
}

func TestSaveStatus(t *testing.T) {
	cc := setupChannelsClient(t)

	channelID := testsutil.GenerateUUID(t)

	cases := []struct {
		desc      string
		channelID string
		status    channels.Status
		err       error
	}{
		{
			desc:      "Save with enabled status",
			channelID: channelID,
			status:    channels.EnabledStatus,
			err:       nil,
		},
		{
			desc:      "Save with disabled status",
			channelID: testsutil.GenerateUUID(t),
			status:    channels.DisabledStatus,
			err:       nil,
		},
		{
			desc:      "Save with empty channel ID",
			channelID: "",
			status:    channels.EnabledStatus,
			err:       repoerr.ErrCreateEntity,
		},
		{
			desc:      "Save with all status",
			channelID: testsutil.GenerateUUID(t),
			status:    channels.AllStatus,
			err:       nil,
		},
		{
			desc:      "Save with invalid status",
			channelID: testsutil.GenerateUUID(t),
			status:    channels.Status(6),
			err:       repoerr.ErrCreateEntity,
		},
		{
			desc:      "Save the same record",
			channelID: channelID,
			status:    channels.EnabledStatus,
			err:       nil,
		},
		{
			desc:      "Save client with long id ",
			channelID: strings.Repeat("a", 513*1024*1024),
			status:    channels.EnabledStatus,
			err:       repoerr.ErrCreateEntity,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := cc.SaveStatus(context.Background(), tc.channelID, tc.status)
			assert.True(t, errors.Contains(err, tc.err))
		})
	}
}

func TestID(t *testing.T) {
	cc := setupChannelsClient(t)

	domainID := testsutil.GenerateUUID(t)
	route := "test-route"
	id := testsutil.GenerateUUID(t)

	err := cc.SaveID(context.Background(), route, domainID, id)
	assert.Nil(t, err, fmt.Sprintf("got unexpected error on saving channel ID: %s", err))

	cases := []struct {
		desc         string
		domainID     string
		channelRoute string
		channelID    string
		err          error
	}{
		{
			desc:         "Retrieve existing channel",
			domainID:     domainID,
			channelRoute: route,
			channelID:    id,
			err:          nil,
		},
		{
			desc:         "Retrieve non-existing channel",
			domainID:     domainID,
			channelRoute: "non-existing-route",
			channelID:    "",
			err:          repoerr.ErrNotFound,
		},
		{
			desc:         "Retrieve with empty domain ID",
			domainID:     "",
			channelRoute: route,
			channelID:    "",
			err:          cache.ErrEmptyDomainID,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			id, err := cc.ID(context.Background(), tc.channelRoute, tc.domainID)
			assert.Equal(t, tc.channelID, id, fmt.Sprintf("expected channel ID '%s' got '%s'", tc.channelID, id))
			assert.True(t, errors.Contains(err, tc.err))
		})
	}
}

func TestStatus(t *testing.T) {
	cc := setupChannelsClient(t)

	enabledChannelID := testsutil.GenerateUUID(t)
	err := cc.SaveStatus(context.Background(), enabledChannelID, channels.EnabledStatus)
	assert.Nil(t, err, fmt.Sprintf("Unexpected error while trying to save: %s", err))

	disabledChannelID := testsutil.GenerateUUID(t)
	err = cc.SaveStatus(context.Background(), disabledChannelID, channels.DisabledStatus)
	assert.Nil(t, err, fmt.Sprintf("Unexpected error while trying to save: %s", err))

	allChannelID := testsutil.GenerateUUID(t)
	err = cc.SaveStatus(context.Background(), allChannelID, channels.AllStatus)
	assert.Nil(t, err, fmt.Sprintf("Unexpected error while trying to save: %s", err))

	cases := []struct {
		desc      string
		channelID string
		status    channels.Status
		err       error
	}{
		{
			desc:      "Get channel status from cache for enabled channel",
			channelID: enabledChannelID,
			status:    channels.EnabledStatus,
			err:       nil,
		},
		{
			desc:      "Get channel status from cache for disabled channel",
			channelID: disabledChannelID,
			status:    channels.DisabledStatus,
			err:       nil,
		},
		{
			desc:      "Get channel status from cache for all channel",
			channelID: allChannelID,
			status:    channels.AllStatus,
			err:       nil,
		},
		{
			desc:      "Get channel status from cache for non existing channel",
			channelID: testsutil.GenerateUUID(t),
			status:    channels.AllStatus,
			err:       repoerr.ErrNotFound,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			status, err := cc.Status(context.Background(), tc.channelID)
			assert.True(t, errors.Contains(err, tc.err))
			assert.Equal(t, tc.status, status)
		})
	}
}

func TestRemoveID(t *testing.T) {
	cc := setupChannelsClient(t)

	domainID := testsutil.GenerateUUID(t)
	route := "test-route"
	id := testsutil.GenerateUUID(t)

	err := cc.SaveID(context.Background(), domainID, route, id)
	assert.Nil(t, err, fmt.Sprintf("got unexpected error on saving channel ID: %s", err))

	cases := []struct {
		desc         string
		domainID     string
		channelRoute string
		err          error
	}{
		{
			desc:         "Remove existing channel",
			domainID:     domainID,
			channelRoute: route,
			err:          nil,
		},
		{
			desc:         "Remove non-existing channel",
			domainID:     domainID,
			channelRoute: "non-existing-route",
			err:          nil,
		},
		{
			desc:         "Remove with empty domain ID",
			domainID:     "",
			channelRoute: route,
			err:          cache.ErrEmptyDomainID,
		},
		{
			desc:         "Remove with empty channel route",
			domainID:     domainID,
			channelRoute: "",
			err:          cache.ErrEmptyChannelRoute,
		},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := cc.RemoveID(context.Background(), tc.channelRoute, tc.domainID)
			assert.True(t, errors.Contains(err, tc.err))

			if tc.err == nil {
				id, err := cc.ID(context.Background(), tc.channelRoute, tc.domainID)
				assert.Equal(t, "", id, fmt.Sprintf("expected channel ID to be empty after removal, got '%s'", id))
				assert.True(t, errors.Contains(err, repoerr.ErrNotFound))
			}
		})
	}
}

func TestRemoveStatus(t *testing.T) {
	cc := setupChannelsClient(t)

	channelID := testsutil.GenerateUUID(t)

	err := cc.SaveStatus(context.Background(), channelID, channels.EnabledStatus)
	assert.Nil(t, err, fmt.Sprintf("got unexpected error on saving channel status: %s", err))

	cases := []struct {
		desc      string
		channelID string
		err       error
	}{
		{
			desc:      "Remove existing channel status",
			channelID: channelID,
			err:       nil,
		},
		{
			desc:      "Remove non-existing channel status",
			channelID: testsutil.GenerateUUID(t),
			err:       nil,
		},
		{
			desc:      "Remove with empty channel ID",
			channelID: "",
			err:       repoerr.ErrRemoveEntity,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := cc.RemoveStatus(context.Background(), tc.channelID)
			assert.True(t, errors.Contains(err, tc.err))
		})
	}
}
