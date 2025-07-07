// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package messaging_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	grpcCommonV1 "github.com/absmach/supermq/api/grpc/common/v1"
	chmocks "github.com/absmach/supermq/channels/mocks"
	dmocks "github.com/absmach/supermq/domains/mocks"
	"github.com/absmach/supermq/internal/testsutil"
	"github.com/absmach/supermq/pkg/errors"
	svcerr "github.com/absmach/supermq/pkg/errors/service"
	"github.com/absmach/supermq/pkg/messaging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var (
	subtopic         = "subtopic"
	topicSubtopicFmt = "m/%s/c/%s/%s"
	cachedTopic      = fmt.Sprintf(topicSubtopicFmt, domainID, channelID, subtopic)
)

func setupParser() (messaging.TopicParser, *dmocks.DomainsServiceClient, *chmocks.ChannelsServiceClient, error) {
	channels := new(chmocks.ChannelsServiceClient)
	domains := new(dmocks.DomainsServiceClient)
	parser, err := messaging.NewTopicParser(messaging.DefaultCacheConfig, channels, domains)
	if err != nil {
		return nil, nil, nil, err
	}

	return parser, domains, channels, nil
}

func TestParserPublishTopic(t *testing.T) {
	parser, domains, channels, err := setupParser()
	assert.Nil(t, err, fmt.Sprintf("unexpected error while setting up parser: %v", err))

	udomainID := testsutil.GenerateUUID(t)
	uchannelID := testsutil.GenerateUUID(t)

	cachedInvalidTopic := "m/invalid-domain/c"

	dom, ch, st, err := parser.ParsePublishTopic(context.Background(), cachedTopic, false)
	assert.Nil(t, err, fmt.Sprintf("unexpected error while publishing topic: %v", err))
	assert.Equal(t, domainID, dom, "expected domainID %s, got %s", domainID, dom)
	assert.Equal(t, channelID, ch, "expected channelID %s, got %s", channelID, ch)
	assert.Equal(t, subtopic, st, "expected subtopic %s, got %s", subtopic, st)

	dom, ch, st, err = parser.ParsePublishTopic(context.Background(), cachedInvalidTopic, false)
	assert.NotNil(t, err, "expected error for invalid cached topic")
	assert.Equal(t, "", dom, "expected empty domainID for invalid topic")
	assert.Equal(t, "", ch, "expected empty channelID for invalid topic")
	assert.Equal(t, "", st, "expected empty subtopic for invalid topic")
	time.Sleep(10 * time.Millisecond) // Ensure cache is populated

	cases := []struct {
		desc        string
		topic       string
		resolve     bool
		domain      string
		channel     string
		domainID    string
		channelID   string
		domainsErr  error
		channelsErr error
		err         error
	}{
		{
			desc:      "valid uncached topic with domainID and channelID",
			topic:     fmt.Sprintf(topicFmt, udomainID, uchannelID) + "/subtopic",
			resolve:   true,
			domain:    udomainID,
			channel:   uchannelID,
			domainID:  udomainID,
			channelID: uchannelID,
			err:       nil,
		},
		{
			desc:      "valid cached topic with domainID and channelID",
			topic:     cachedTopic,
			domain:    domainID,
			channel:   channelID,
			domainID:  domainID,
			channelID: channelID,
			err:       nil,
		},
		{
			desc:      "invalid uncached topic with invalid format",
			topic:     "invalid-topic",
			domain:    "",
			channel:   "",
			domainID:  "",
			channelID: "",
			err:       messaging.ErrMalformedTopic,
		},
		{
			desc:      "invalid cached topic with invalid format",
			topic:     cachedInvalidTopic,
			domain:    "",
			channel:   "",
			domainID:  "",
			channelID: "",
			err:       messaging.ErrMalformedTopic,
		},
		{
			desc:      "valid uncached topic with domain and channel routes",
			topic:     fmt.Sprintf(topicFmt, validRoute, validRoute) + "/subtopic",
			resolve:   true,
			domain:    validRoute,
			channel:   validRoute,
			domainID:  domainID,
			channelID: channelID,
			err:       nil,
		},
		{
			desc:       "valid uncached topic with failed domain resolution",
			topic:      fmt.Sprintf(topicFmt, invalidRoute, uchannelID) + "/subtopic",
			resolve:    true,
			domain:     invalidRoute,
			channel:    uchannelID,
			domainID:   "",
			channelID:  "",
			domainsErr: svcerr.ErrNotFound,
			err:        messaging.ErrFailedResolveDomain,
		},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			domainsCall := domains.On("RetrieveByRoute", mock.Anything, &grpcCommonV1.RetrieveByRouteReq{Route: tc.domain}).Return(&grpcCommonV1.RetrieveEntityRes{
				Entity: &grpcCommonV1.EntityBasic{
					Id: tc.domainID,
				},
			}, tc.domainsErr)
			channelsCall := channels.On("RetrieveByRoute", mock.Anything, &grpcCommonV1.RetrieveByRouteReq{Route: tc.channel, DomainId: tc.domainID}).Return(&grpcCommonV1.RetrieveEntityRes{
				Entity: &grpcCommonV1.EntityBasic{
					Id: tc.channelID,
				},
			}, tc.channelsErr)
			domainID, channelID, subtopic, err := parser.ParsePublishTopic(context.Background(), tc.topic, tc.resolve)
			assert.True(t, errors.Contains(err, tc.err), "expected error %v, got %v", tc.err, err)
			if err == nil {
				assert.Equal(t, tc.domainID, domainID, "expected domainID %s, got %s", tc.domainID, domainID)
				assert.Equal(t, tc.channelID, channelID, "expected channelID %s, got %s", tc.channelID, channelID)
				assert.Equal(t, subtopic, "subtopic", "expected subtopic %s, got %s", "subtopic", subtopic)
			}
			domainsCall.Unset()
			channelsCall.Unset()
		})
	}
}

func BenchmarkParserPublishTopic(b *testing.B) {
	parser, _, _, err := setupParser()
	if err != nil {
		b.Fatalf("unexpected error while setting up parser: %v", err)
	}

	for _, tc := range ParsePublisherTopicTestCases {
		b.Run(tc.desc, func(b *testing.B) {
			for b.Loop() {
				_, _, _, _ = parser.ParsePublishTopic(context.Background(), tc.topic, false)
			}
		})
	}
}

func TestParserSubscribeTopic(t *testing.T) {
	parser, domains, channels, err := setupParser()
	assert.Nil(t, err, fmt.Sprintf("unexpected error while setting up parser: %v", err))

	cases := []struct {
		desc        string
		topic       string
		resolve     bool
		domain      string
		channel     string
		domainID    string
		channelID   string
		subtopic    string
		domainsErr  error
		channelsErr error
		err         error
	}{
		{
			desc:      "valid topic with domainID and channelID",
			topic:     fmt.Sprintf(topicFmt, domainID, channelID),
			resolve:   true,
			domain:    domainID,
			channel:   channelID,
			domainID:  domainID,
			channelID: channelID,
			err:       nil,
		},
		{
			desc:      "valid topic with domainID and channelID and subtopic",
			topic:     fmt.Sprintf(topicSubtopicFmt, domainID, channelID, subtopic),
			resolve:   true,
			domain:    domainID,
			channel:   channelID,
			domainID:  domainID,
			channelID: channelID,
			subtopic:  subtopic,
			err:       nil,
		},
		{
			desc:      "valid topic with domain and channel routes",
			topic:     fmt.Sprintf(topicFmt, validRoute, validRoute),
			resolve:   true,
			domain:    validRoute,
			channel:   validRoute,
			domainID:  domainID,
			channelID: channelID,
			err:       nil,
		},
		{
			desc:      "invalid topic with invalid format",
			topic:     "invalid-topic",
			resolve:   false,
			domain:    "",
			channel:   "",
			domainID:  "",
			channelID: "",
			err:       messaging.ErrMalformedTopic,
		},
		{
			desc:       "valid topic with invalid domain route",
			topic:      fmt.Sprintf(topicFmt, invalidRoute, validRoute),
			resolve:    true,
			domain:     invalidRoute,
			channel:    validRoute,
			domainID:   "",
			channelID:  "",
			domainsErr: svcerr.ErrNotFound,
			err:        messaging.ErrFailedResolveDomain,
		},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			domainsCall := domains.On("RetrieveByRoute", mock.Anything, &grpcCommonV1.RetrieveByRouteReq{Route: tc.domain}).Return(&grpcCommonV1.RetrieveEntityRes{
				Entity: &grpcCommonV1.EntityBasic{
					Id: tc.domainID,
				},
			}, tc.domainsErr)
			channelsCall := channels.On("RetrieveByRoute", mock.Anything, &grpcCommonV1.RetrieveByRouteReq{Route: tc.channel, DomainId: tc.domainID}).Return(&grpcCommonV1.RetrieveEntityRes{
				Entity: &grpcCommonV1.EntityBasic{
					Id: tc.channelID,
				},
			}, tc.channelsErr)
			dom, ch, st, err := parser.ParseSubscribeTopic(context.Background(), tc.topic, tc.resolve)
			assert.True(t, errors.Contains(err, tc.err), "expected error %v, got %v", tc.err, err)
			if err == nil {
				assert.Equal(t, tc.domainID, dom, "expected domainID %s, got %s", tc.domainID, dom)
				assert.Equal(t, tc.channelID, ch, "expected channelID %s, got %s", tc.channelID, ch)
				assert.Equal(t, tc.subtopic, st, "expected  subtopic %s, got %s", tc.subtopic, st)
			}
			domainsCall.Unset()
			channelsCall.Unset()
		})
	}
}
