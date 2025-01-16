// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package journal

import (
	"context"
	"fmt"

	"github.com/absmach/supermq"
	smqauthn "github.com/absmach/supermq/pkg/authn"
	"github.com/absmach/supermq/pkg/errors"
	svcerr "github.com/absmach/supermq/pkg/errors/service"
)

var (
	ErrMissingDomainID = errors.New("missing domain_id")
	ErrMissingClientID = errors.New("missing client_id")
)

type service struct {
	idProvider supermq.IDProvider
	repository Repository
}

func NewService(idp supermq.IDProvider, repository Repository) Service {
	return &service{
		idProvider: idp,
		repository: repository,
	}
}

func (svc *service) Save(ctx context.Context, journal Journal) error {
	id, err := svc.idProvider.ID()
	if err != nil {
		return err
	}
	journal.ID = id

	switch journal.Operation {
	case "client.create":
		if err := svc.saveClientTelemetry(ctx, journal); err != nil {
			return errors.Wrap(svcerr.ErrCreateEntity, err)
		}
	case "client.delete":
		if err := svc.deleteClientTelemetry(ctx, journal); err != nil {
			return errors.Wrap(svcerr.ErrCreateEntity, err)
		}
	case "channels.connect":
		if err := svc.addClientConnection(ctx, journal); err != nil {
			return errors.Wrap(svcerr.ErrCreateEntity, err)
		}
	case "channels.disconnect":
		if err := svc.removeClientConnection(ctx, journal); err != nil {
			return errors.Wrap(svcerr.ErrCreateEntity, err)
		}
	}

	return svc.repository.Save(ctx, journal)
}

func (svc *service) RetrieveAll(ctx context.Context, session smqauthn.Session, page Page) (JournalsPage, error) {
	journalPage, err := svc.repository.RetrieveAll(ctx, page)
	if err != nil {
		return JournalsPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}

	return journalPage, nil
}

func (svc *service) saveClientTelemetry(ctx context.Context, journal Journal) error {
	clientID, ok := journal.Attributes["id"].(string)
	if !ok {
		return errors.Wrap(svcerr.ErrCreateEntity, ErrMissingClientID)
	}
	domainID, ok := journal.Attributes["domain"].(string)
	if !ok {
		return errors.New("missing domain_id")
	}

	return svc.repository.SaveClientTelemetry(ctx, clientID, domainID)
}

func (svc *service) deleteClientTelemetry(ctx context.Context, journal Journal) error {
	clientID, ok := journal.Attributes["id"].(string)
	if !ok {
		return errors.Wrap(svcerr.ErrCreateEntity, ErrMissingClientID)
	}
	domainID, ok := journal.Attributes["domain"].(string)
	if !ok {
		return errors.New("missing domain_id")
	}

	return svc.repository.DeleteClientTelemetry(ctx, clientID, domainID)
}

func (svc *service) RetrieveClientTelemetry(ctx context.Context, clientID, domainID string) (ClientsTelemetry, error) {
	return svc.repository.RetrieveClientTelemetry(ctx, clientID, domainID)
}

func (svc *service) addClientConnection(ctx context.Context, journal Journal) error {
	domainID, ok := journal.Attributes["domain"].(string)
	if !ok {
		return errors.Wrap(svcerr.ErrCreateEntity, ErrMissingDomainID)
	}
	channelIDs, ok := journal.Attributes["channel_ids"].([]string)
	if !ok {
		return errors.New("missing channel_ids")
	}
	clientIDs, ok := journal.Attributes["client_ids"].([]string)
	if !ok {
		return errors.Wrap(svcerr.ErrCreateEntity, ErrMissingClientID)
	}

	for _, channelID := range channelIDs {
		for _, clientID := range clientIDs {
			connection := fmt.Sprintf("%s_%s", clientID, channelID)
			if err := svc.repository.AddClientConnection(ctx, clientID, domainID, connection); err != nil {
				return errors.Wrap(svcerr.ErrCreateEntity, err)
			}
		}
	}

	return nil
}

func (svc *service) removeClientConnection(ctx context.Context, journal Journal) error {
	domainID, ok := journal.Attributes["domain"].(string)
	if !ok {
		return errors.Wrap(svcerr.ErrCreateEntity, ErrMissingDomainID)
	}
	channelIDs, ok := journal.Attributes["channel_ids"].([]string)
	if !ok {
		return errors.New("missing channel_id")
	}
	clientIDs, ok := journal.Attributes["client_ids"].([]string)
	if !ok {
		return errors.Wrap(svcerr.ErrCreateEntity, ErrMissingClientID)
	}

	for _, channelID := range channelIDs {
		for _, clientID := range clientIDs {
			connection := fmt.Sprintf("%s_%s", clientID, channelID)
			if err := svc.repository.RemoveClientConnection(ctx, clientID, domainID, connection); err != nil {
				return errors.Wrap(svcerr.ErrCreateEntity, err)
			}
		}
	}

	return nil
}
