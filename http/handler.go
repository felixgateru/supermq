// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/absmach/magistrala"
	"github.com/absmach/magistrala/pkg/apiutil"
	"github.com/absmach/magistrala/pkg/errors"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	"github.com/absmach/magistrala/pkg/messaging"
	"github.com/absmach/magistrala/pkg/policies"
	mhttp "github.com/absmach/mgate/pkg/http"
	"github.com/absmach/mgate/pkg/session"
)

var _ session.Handler = (*handler)(nil)

const protocol = "http"

// Log message formats.
const (
	logInfoConnected = "connected with thing_key %s"
	logInfoPublished = "published with client_id %s to the topic %s"
)

// Error wrappers for MQTT errors.
var (
	ErrMalformedSubtopic        = errors.New("malformed subtopic")
	ErrClientNotInitialized     = errors.New("client is not initialized")
	ErrMalformedTopic           = errors.New("malformed topic")
	ErrMissingTopicPub          = errors.New("failed to publish due to missing topic")
	ErrFailedPublish            = errors.New("failed to publish")
	ErrFailedParseSubtopic      = errors.New("failed to parse subtopic")
	ErrFailedPublishToMsgBroker = errors.New("failed to publish to magistrala message broker")
)

var channelRegExp = regexp.MustCompile(`^\/?channels\/([\w\-]+)\/messages(\/[^?]*)?(\?.*)?$`)

// Event implements events.Event interface.
type handler struct {
	publisher messaging.Publisher
	things    magistrala.ThingsServiceClient
	logger    *slog.Logger
}

// NewHandler creates new Handler entity.
func NewHandler(publisher messaging.Publisher, logger *slog.Logger, thingsClient magistrala.ThingsServiceClient) session.Handler {
	return &handler{
		logger:    logger,
		publisher: publisher,
		things:    thingsClient,
	}
}

// AuthConnect is called on device connection,
// prior forwarding to the HTTP server.
func (h *handler) AuthConnect(ctx context.Context) error {
	s, ok := session.FromContext(ctx)
	if !ok {
		return mhttp.NewHTTPProxyError(http.StatusUnauthorized, ErrClientNotInitialized)
	}

	var tok string
	switch {
	case string(s.Password) == "":
		return mhttp.NewHTTPProxyError(http.StatusUnauthorized, errors.Wrap(apiutil.ErrValidation, apiutil.ErrBearerKey))
	case strings.HasPrefix(string(s.Password), "Thing"):
		tok = extractThingKey(string(s.Password))
	default:
		tok = string(s.Password)
	}

	h.logger.Info(fmt.Sprintf(logInfoConnected, tok))
	return nil
}

// AuthPublish is not used in HTTP service.
func (h *handler) AuthPublish(ctx context.Context, topic *string, payload *[]byte) error {
	return nil
}

// AuthSubscribe is not used in HTTP service.
func (h *handler) AuthSubscribe(ctx context.Context, topics *[]string) error {
	return nil
}

// Connect - after client successfully connected.
func (h *handler) Connect(ctx context.Context) error {
	return nil
}

// Publish - after client successfully published.
func (h *handler) Publish(ctx context.Context, topic *string, payload *[]byte) error {
	if topic == nil {
		return mhttp.NewHTTPProxyError(http.StatusBadRequest, ErrMissingTopicPub)
	}
	topic = &strings.Split(*topic, "?")[0]
	s, ok := session.FromContext(ctx)
	if !ok {
		return mhttp.NewHTTPProxyError(http.StatusUnauthorized, errors.Wrap(ErrFailedPublish, ErrClientNotInitialized))
	}
	h.logger.Info(fmt.Sprintf(logInfoPublished, s.ID, *topic))
	// Topics are in the format:
	// channels/<channel_id>/messages/<subtopic>/.../ct/<content_type>

	channelParts := channelRegExp.FindStringSubmatch(*topic)
	if len(channelParts) < 2 {
		return mhttp.NewHTTPProxyError(http.StatusBadRequest, errors.Wrap(ErrFailedPublish, ErrMalformedTopic))
	}

	chanID := channelParts[1]
	subtopic := channelParts[2]

	subtopic, err := parseSubtopic(subtopic)
	if err != nil {
		return mhttp.NewHTTPProxyError(http.StatusBadRequest, errors.Wrap(ErrFailedParseSubtopic, err))
	}

	msg := messaging.Message{
		Protocol: protocol,
		Channel:  chanID,
		Subtopic: subtopic,
		Payload:  *payload,
		Created:  time.Now().UnixNano(),
	}
	var tok string
	switch {
	case string(s.Password) == "":
		return mhttp.NewHTTPProxyError(http.StatusUnauthorized, errors.Wrap(apiutil.ErrValidation, apiutil.ErrBearerKey))
	case strings.HasPrefix(string(s.Password), "Thing"):
		tok = extractThingKey(string(s.Password))
	default:
		tok = string(s.Password)
	}
	ar := &magistrala.ThingsAuthzReq{
		ThingKey:   tok,
		ChannelID:  msg.Channel,
		Permission: policies.PublishPermission,
	}
	res, err := h.things.Authorize(ctx, ar)
	if err != nil {
		return mhttp.NewHTTPProxyError(http.StatusForbidden, err)
	}
	if !res.GetAuthorized() {
		return mhttp.NewHTTPProxyError(http.StatusForbidden, svcerr.ErrAuthorization)
	}
	msg.Publisher = res.GetId()

	if err := h.publisher.Publish(ctx, msg.Channel, &msg); err != nil {
		return mhttp.NewHTTPProxyError(http.StatusForbidden, errors.Wrap(ErrFailedPublishToMsgBroker, err))
	}

	return nil
}

// Subscribe - not used for HTTP.
func (h *handler) Subscribe(ctx context.Context, topics *[]string) error {
	return nil
}

// Unsubscribe - not used for HTTP.
func (h *handler) Unsubscribe(ctx context.Context, topics *[]string) error {
	return nil
}

// Disconnect - not used for HTTP.
func (h *handler) Disconnect(ctx context.Context) error {
	return nil
}

func parseSubtopic(subtopic string) (string, error) {
	if subtopic == "" {
		return subtopic, nil
	}

	subtopic, err := url.QueryUnescape(subtopic)
	if err != nil {
		return "", ErrMalformedSubtopic
	}
	subtopic = strings.ReplaceAll(subtopic, "/", ".")

	elems := strings.Split(subtopic, ".")
	filteredElems := []string{}
	for _, elem := range elems {
		if elem == "" {
			continue
		}

		if len(elem) > 1 && (strings.Contains(elem, "*") || strings.Contains(elem, ">")) {
			return "", ErrMalformedSubtopic
		}

		filteredElems = append(filteredElems, elem)
	}

	subtopic = strings.Join(filteredElems, ".")
	return subtopic, nil
}

// extractThingKey returns value of the thing key. If there is no thing key - an empty value is returned.
func extractThingKey(topic string) string {
	if !strings.HasPrefix(topic, apiutil.ThingPrefix) {
		return ""
	}

	return strings.TrimPrefix(topic, apiutil.ThingPrefix)
}
