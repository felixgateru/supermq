// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"context"

	"github.com/absmach/magistrala/pkg/auth"
	mgclients "github.com/absmach/magistrala/pkg/clients"
	"github.com/absmach/magistrala/pkg/events"
	"github.com/absmach/magistrala/pkg/events/store"
	"github.com/absmach/magistrala/users"
)

const streamID = "magistrala.users"

var _ users.Service = (*eventStore)(nil)

type eventStore struct {
	events.Publisher
	svc users.Service
}

// NewEventStoreMiddleware returns wrapper around users service that sends
// events to event store.
func NewEventStoreMiddleware(ctx context.Context, svc users.Service, url string) (users.Service, error) {
	publisher, err := store.NewPublisher(ctx, url, streamID)
	if err != nil {
		return nil, err
	}

	return &eventStore{
		svc:       svc,
		Publisher: publisher,
	}, nil
}

func (es *eventStore) RegisterClient(ctx context.Context, authObject auth.AuthObject, user mgclients.Client, selfRegister bool) (mgclients.Client, error) {
	user, err := es.svc.RegisterClient(ctx, authObject, user, selfRegister)
	if err != nil {
		return user, err
	}

	event := createClientEvent{
		user,
	}

	if err := es.Publish(ctx, event); err != nil {
		return user, err
	}

	return user, nil
}

func (es *eventStore) UpdateClient(ctx context.Context, authObject auth.AuthObject, user mgclients.Client) (mgclients.Client, error) {
	user, err := es.svc.UpdateClient(ctx, authObject, user)
	if err != nil {
		return user, err
	}

	return es.update(ctx, "", user)
}

func (es *eventStore) UpdateClientRole(ctx context.Context, authObject auth.AuthObject, user mgclients.Client) (mgclients.Client, error) {
	user, err := es.svc.UpdateClientRole(ctx, authObject, user)
	if err != nil {
		return user, err
	}

	return es.update(ctx, "role", user)
}

func (es *eventStore) UpdateClientTags(ctx context.Context, authObject auth.AuthObject, user mgclients.Client) (mgclients.Client, error) {
	user, err := es.svc.UpdateClientTags(ctx, authObject, user)
	if err != nil {
		return user, err
	}

	return es.update(ctx, "tags", user)
}

func (es *eventStore) UpdateClientSecret(ctx context.Context, authObject auth.AuthObject, oldSecret, newSecret string) (mgclients.Client, error) {
	user, err := es.svc.UpdateClientSecret(ctx, authObject, oldSecret, newSecret)
	if err != nil {
		return user, err
	}

	return es.update(ctx, "secret", user)
}

func (es *eventStore) UpdateClientIdentity(ctx context.Context, authObject auth.AuthObject, id, identity string) (mgclients.Client, error) {
	user, err := es.svc.UpdateClientIdentity(ctx, authObject, id, identity)
	if err != nil {
		return user, err
	}

	return es.update(ctx, "identity", user)
}

func (es *eventStore) update(ctx context.Context, operation string, user mgclients.Client) (mgclients.Client, error) {
	event := updateClientEvent{
		user, operation,
	}

	if err := es.Publish(ctx, event); err != nil {
		return user, err
	}

	return user, nil
}

func (es *eventStore) ViewClient(ctx context.Context, authObject auth.AuthObject, id string) (mgclients.Client, error) {
	user, err := es.svc.ViewClient(ctx, authObject, id)
	if err != nil {
		return user, err
	}

	event := viewClientEvent{
		user,
	}

	if err := es.Publish(ctx, event); err != nil {
		return user, err
	}

	return user, nil
}

func (es *eventStore) ViewProfile(ctx context.Context, authObject auth.AuthObject) (mgclients.Client, error) {
	user, err := es.svc.ViewProfile(ctx, authObject)
	if err != nil {
		return user, err
	}

	event := viewProfileEvent{
		user,
	}

	if err := es.Publish(ctx, event); err != nil {
		return user, err
	}

	return user, nil
}

func (es *eventStore) ListClients(ctx context.Context, authObject auth.AuthObject, pm mgclients.Page) (mgclients.ClientsPage, error) {
	cp, err := es.svc.ListClients(ctx, authObject, pm)
	if err != nil {
		return cp, err
	}
	event := listClientEvent{
		pm,
	}

	if err := es.Publish(ctx, event); err != nil {
		return cp, err
	}

	return cp, nil
}

func (es *eventStore) SearchUsers(ctx context.Context, authObject auth.AuthObject, pm mgclients.Page) (mgclients.ClientsPage, error) {
	cp, err := es.svc.SearchUsers(ctx, authObject, pm)
	if err != nil {
		return cp, err
	}
	event := searchClientEvent{
		pm,
	}

	if err := es.Publish(ctx, event); err != nil {
		return cp, err
	}

	return cp, nil
}

func (es *eventStore) ListMembers(ctx context.Context, authObject auth.AuthObject, objectKind, objectID string, pm mgclients.Page) (mgclients.MembersPage, error) {
	mp, err := es.svc.ListMembers(ctx, authObject, objectKind, objectID, pm)
	if err != nil {
		return mp, err
	}
	event := listClientByGroupEvent{
		pm, objectKind, objectID,
	}

	if err := es.Publish(ctx, event); err != nil {
		return mp, err
	}

	return mp, nil
}

func (es *eventStore) EnableClient(ctx context.Context, authObject auth.AuthObject, id string) (mgclients.Client, error) {
	user, err := es.svc.EnableClient(ctx, authObject, id)
	if err != nil {
		return user, err
	}

	return es.delete(ctx, user)
}

func (es *eventStore) DisableClient(ctx context.Context, authObject auth.AuthObject, id string) (mgclients.Client, error) {
	user, err := es.svc.DisableClient(ctx, authObject, id)
	if err != nil {
		return user, err
	}

	return es.delete(ctx, user)
}

func (es *eventStore) delete(ctx context.Context, user mgclients.Client) (mgclients.Client, error) {
	event := removeClientEvent{
		id:        user.ID,
		updatedAt: user.UpdatedAt,
		updatedBy: user.UpdatedBy,
		status:    user.Status.String(),
	}

	if err := es.Publish(ctx, event); err != nil {
		return user, err
	}

	return user, nil
}

func (es *eventStore) Identify(ctx context.Context, authObject auth.AuthObject) (string, error) {
	userID, err := es.svc.Identify(ctx, authObject)
	if err != nil {
		return userID, err
	}

	event := identifyClientEvent{
		userID: userID,
	}

	if err := es.Publish(ctx, event); err != nil {
		return userID, err
	}

	return userID, nil
}

func (es *eventStore) GenerateResetToken(ctx context.Context, email, host string) (auth.Token, error) {
	token, err := es.svc.GenerateResetToken(ctx, email, host)
	if err != nil {
		return auth.Token{}, err
	}

	event := generateResetTokenEvent{
		email: email,
		host:  host,
	}

	return token, es.Publish(ctx, event)
}

func (es *eventStore) IssueToken(ctx context.Context, identity, secret, domainID string) (auth.Token, error) {
	token, err := es.svc.IssueToken(ctx, identity, secret, domainID)
	if err != nil {
		return token, err
	}

	event := issueTokenEvent{
		identity: identity,
		domainID: domainID,
	}

	if err := es.Publish(ctx, event); err != nil {
		return token, err
	}

	return token, nil
}

func (es *eventStore) RefreshToken(ctx context.Context, authObject auth.AuthObject, domainID string) (auth.Token, error) {
	token, err := es.svc.RefreshToken(ctx, authObject, domainID)
	if err != nil {
		return token, err
	}

	event := refreshTokenEvent{domainID: domainID}

	if err := es.Publish(ctx, event); err != nil {
		return token, err
	}

	return token, nil
}

func (es *eventStore) ResetSecret(ctx context.Context, authObject auth.AuthObject, secret string) error {
	if err := es.svc.ResetSecret(ctx, authObject, secret); err != nil {
		return err
	}

	event := resetSecretEvent{}

	return es.Publish(ctx, event)
}

func (es *eventStore) SendPasswordReset(ctx context.Context, host, email, user, token string) error {
	if err := es.svc.SendPasswordReset(ctx, host, email, user, token); err != nil {
		return err
	}

	event := sendPasswordResetEvent{
		host:  host,
		email: email,
		user:  user,
	}

	return es.Publish(ctx, event)
}

func (es *eventStore) OAuthCallback(ctx context.Context, client mgclients.Client) (auth.Token, error) {
	token, err := es.svc.OAuthCallback(ctx, client)
	if err != nil {
		return token, err
	}

	event := oauthCallbackEvent{
		clientID: client.ID,
	}

	if err := es.Publish(ctx, event); err != nil {
		return token, err
	}

	return token, nil
}

func (es *eventStore) DeleteClient(ctx context.Context, authObject auth.AuthObject, id string) error {
	if err := es.svc.DeleteClient(ctx, authObject, id); err != nil {
		return err
	}

	event := deleteClientEvent{
		id: id,
	}

	return es.Publish(ctx, event)
}

func (es *eventStore) AddClientPolicy(ctx context.Context, client mgclients.Client) error {
	if err := es.svc.AddClientPolicy(ctx, client); err != nil {
		return err
	}

	event := addClientPolicyEvent{
		id:   client.ID,
		role: client.Role.String(),
	}

	return es.Publish(ctx, event)
}
