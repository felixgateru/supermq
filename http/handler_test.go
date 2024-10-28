// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package http_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/absmach/magistrala"
	mhttp "github.com/absmach/magistrala/http"
	mglog "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/apiutil"
	"github.com/absmach/magistrala/pkg/errors"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	"github.com/absmach/magistrala/pkg/messaging/mocks"
	thmocks "github.com/absmach/magistrala/things/mocks"
	mghttp "github.com/absmach/mgate/pkg/http"
	"github.com/absmach/mgate/pkg/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const (
	thingID               = "513d02d2-16c1-4f23-98be-9e12f8fee898"
	thingID1              = "513d02d2-16c1-4f23-98be-9e12f8fee899"
	password              = "password"
	password1             = "password1"
	chanID                = "123e4567-e89b-12d3-a456-000000000001"
	invalidID             = "invalidID"
	invalidValue          = "invalidValue"
	clientID              = "clientID"
	clientID1             = "clientID1"
	subtopic              = "testSubtopic"
	invalidChannelIDTopic = "channels/**/messages"
)

var (
	topicMsg      = "channels/%s/messages"
	topic         = fmt.Sprintf(topicMsg, chanID)
	invalidTopic  = invalidValue
	payload       = []byte("[{'n':'test-name', 'v': 1.2}]")
	sessionClient = session.Session{
		ID:       clientID,
		Username: thingID,
		Password: []byte(password),
	}
	invalidThingSessionClient = session.Session{
		ID:       clientID,
		Username: invalidID,
		Password: []byte(password),
	}
)

func newHandler() (session.Handler, *thmocks.ThingsServiceClient, *mocks.PubSub) {
	logger := mglog.NewMock()
	things := new(thmocks.ThingsServiceClient)
	publisher := new(mocks.PubSub)

	return mhttp.NewHandler(publisher, logger, things), things, publisher
}

func TestAuthConnect(t *testing.T) {
	handler, _, _ := newHandler()

	cases := []struct {
		desc    string
		session *session.Session
		status  int
		err     error
	}{
		{
			desc:    "connect with valid username and password",
			err:     nil,
			session: &sessionClient,
		},
		{
			desc:    "connect without active session",
			session: nil,
			status:  http.StatusUnauthorized,
			err:     mhttp.ErrClientNotInitialized,
		},
		{
			desc: "connect with invalid password",
			session: &session.Session{
				ID:       clientID,
				Username: thingID,
				Password: []byte(""),
			},
			status: http.StatusUnauthorized,
			err:    errors.Wrap(apiutil.ErrValidation, apiutil.ErrBearerKey),
		},
		{
			desc: "connect with thing key",
			session: &session.Session{
				ID:       clientID,
				Password: []byte("Thing " + thingID),
			},
			err: nil,
		},
		{
			desc:    "connect with valid password and invalid username",
			session: &invalidThingSessionClient,
			err:     nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			ctx := context.TODO()
			if tc.session != nil {
				ctx = session.NewContext(ctx, tc.session)
			}
			err := handler.AuthConnect(ctx)
			hpe, ok := err.(mghttp.HTTPProxyError)
			if ok {
				assert.Equal(t, tc.status, hpe.StatusCode())
			}
			assert.True(t, errors.Contains(err, tc.err))
		})
	}
}

func TestPublish(t *testing.T) {
	handler, things, publisher := newHandler()

	malformedSubtopics := topic + "/" + subtopic + "%"
	cases := []struct {
		desc       string
		topic      *string
		channelID  string
		payload    *[]byte
		session    *session.Session
		status     int
		authZRes   *magistrala.ThingsAuthzRes
		authZErr   error
		publishErr error
		err        error
	}{
		{
			desc:      "publish successfully",
			topic:     &topic,
			payload:   &payload,
			session:   &sessionClient,
			channelID: chanID,
			authZRes:  &magistrala.ThingsAuthzRes{Authorized: true, Id: thingID},
			authZErr:  nil,
			err:       nil,
		},
		{
			desc:      "publish with empty topic",
			topic:     nil,
			payload:   &payload,
			session:   &sessionClient,
			channelID: chanID,
			status:    http.StatusBadRequest,
			err:       mhttp.ErrMissingTopicPub,
		},
		{
			desc:      "publish with invalid session",
			topic:     &topic,
			payload:   &payload,
			session:   nil,
			channelID: chanID,
			status:    http.StatusUnauthorized,
			err:       errors.Wrap(mhttp.ErrFailedPublish, mhttp.ErrClientNotInitialized),
		},
		{
			desc:    "publish with invalid topic",
			topic:   &invalidTopic,
			status:  http.StatusBadRequest,
			session: &sessionClient,
			err:     errors.Wrap(mhttp.ErrFailedPublish, mhttp.ErrMalformedTopic),
		},
		{
			desc:    "publish with malformwd subtopic",
			topic:   &malformedSubtopics,
			status:  http.StatusBadRequest,
			session: &sessionClient,
			err:     errors.Wrap(mhttp.ErrFailedParseSubtopic, mhttp.ErrMalformedSubtopic),
		},
		{
			desc:    "publish with empty password",
			topic:   &topic,
			payload: &payload,
			session: &session.Session{
				ID:       clientID,
				Username: thingID,
				Password: []byte(""),
			},
			channelID: chanID,
			status:    http.StatusUnauthorized,
			err:       errors.Wrap(apiutil.ErrValidation, apiutil.ErrBearerKey),
		},
		{
			desc:    "publish with thing key",
			topic:   &topic,
			payload: &payload,
			session: &session.Session{
				ID:       clientID,
				Password: []byte("Thing " + thingID),
			},
			channelID: chanID,
			authZRes:  &magistrala.ThingsAuthzRes{Authorized: true, Id: thingID},
			authZErr:  nil,
			err:       nil,
		},
		{
			desc:      "publish with unauthorized thing",
			topic:     &topic,
			payload:   &payload,
			session:   &sessionClient,
			channelID: chanID,
			authZRes:  &magistrala.ThingsAuthzRes{Authorized: false},
			authZErr:  nil,
			status:    http.StatusForbidden,
			err:       svcerr.ErrAuthorization,
		},
		{
			desc:      "publish with authorization error",
			topic:     &topic,
			payload:   &payload,
			session:   &sessionClient,
			channelID: chanID,
			authZRes:  &magistrala.ThingsAuthzRes{Authorized: false},
			authZErr:  svcerr.ErrAuthorization,
			status:    http.StatusForbidden,
			err:       svcerr.ErrAuthorization,
		},
		{
			desc:       "publish with failed to publish",
			topic:      &topic,
			payload:    &payload,
			session:    &sessionClient,
			channelID:  chanID,
			authZRes:   &magistrala.ThingsAuthzRes{Authorized: true, Id: thingID},
			authZErr:   nil,
			publishErr: errors.New("failed to publish"),
			status:     http.StatusForbidden,
			err:        errors.Wrap(mhttp.ErrFailedPublishToMsgBroker, errors.New("failed to publish")),
		},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			ctx := context.TODO()
			if tc.session != nil {
				ctx = session.NewContext(ctx, tc.session)
			}
			authCall := things.On("Authorize", ctx, mock.Anything).Return(tc.authZRes, tc.authZErr)
			repoCall := publisher.On("Publish", ctx, tc.channelID, mock.Anything).Return(tc.publishErr)
			err := handler.Publish(ctx, tc.topic, tc.payload)
			hpe, ok := err.(mghttp.HTTPProxyError)
			if ok {
				assert.Equal(t, tc.status, hpe.StatusCode())
			}
			assert.True(t, errors.Contains(err, tc.err))
			authCall.Unset()
			repoCall.Unset()
		})
	}
}
