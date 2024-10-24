// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package http_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/absmach/magistrala/http"
	mglog "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/errors"
	"github.com/absmach/magistrala/pkg/messaging/mocks"
	thmocks "github.com/absmach/magistrala/things/mocks"
	"github.com/absmach/mgate/pkg/session"
	"github.com/stretchr/testify/assert"
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
	topicMsg            = "channels/%s/messages"
	topic               = fmt.Sprintf(topicMsg, chanID)
	invalidTopic        = invalidValue
	payload             = []byte("[{'n':'test-name', 'v': 1.2}]")
	topics              = []string{topic}
	invalidTopics       = []string{invalidValue}
	invalidChanIDTopics = []string{fmt.Sprintf(topicMsg, invalidValue)}
	logBuffer           = bytes.Buffer{}
	sessionClient       = session.Session{
		ID:       clientID,
		Username: thingID,
		Password: []byte(password),
	}
	sessionClientSub = session.Session{
		ID:       clientID1,
		Username: thingID1,
		Password: []byte(password1),
	}
	invalidThingSessionClient = session.Session{
		ID:       clientID,
		Username: invalidID,
		Password: []byte(password),
	}
)

func newHandler() (session.Handler, *thmocks.ThingsServiceClient) {
	logger := mglog.NewMock()
	things := new(thmocks.ThingsServiceClient)
	publisher := new(mocks.PubSub)

	return http.NewHandler(publisher, logger, things), things
}

func TestAuthConnect(t *testing.T) {
	handler, _ := newHandler()

	cases := []struct {
		desc    string
		session *session.Session
		err     error
	}{
		{
			desc:    "connect without active session",
			session: nil,
			err:     http.ErrClientNotInitialized,
		},
		// {
		// 	desc: "connect without clientID",
		// 	err:  mqtt.ErrMissingClientID,
		// 	session: &session.Session{
		// 		ID:       "",
		// 		Username: thingID,
		// 		Password: []byte(password),
		// 	},
		// },
		// {
		// 	desc: "connect with invalid password",
		// 	err:  nil,
		// 	session: &session.Session{
		// 		ID:       clientID,
		// 		Username: thingID,
		// 		Password: []byte(""),
		// 	},
		// },
		// {
		// 	desc:    "connect with valid password and invalid username",
		// 	err:     nil,
		// 	session: &invalidThingSessionClient,
		// },
		// {
		// 	desc:    "connect with valid username and password",
		// 	err:     nil,
		// 	session: &sessionClient,
		// },
	}
	for _, tc := range cases {
		ctx := context.TODO()
		if tc.session != nil {
			ctx = session.NewContext(ctx, tc.session)
		}
		err := handler.AuthConnect(ctx)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
	}
}
