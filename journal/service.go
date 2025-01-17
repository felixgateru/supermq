// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package journal

import (
	"context"

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

	return svc.repository.Save(ctx, journal)
}

func (svc *service) RetrieveAll(ctx context.Context, session smqauthn.Session, page Page) (JournalsPage, error) {
	journalPage, err := svc.repository.RetrieveAll(ctx, page)
	if err != nil {
		return JournalsPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}

	return journalPage, nil
}

func (svc *service) RetrieveClientTelemetry(ctx context.Context, session smqauthn.Session, clientID string) (ClientsTelemetry, error) {
	ct, err := svc.repository.RetrieveClientTelemetry(ctx, clientID, session.DomainID)
	if err != nil {
		return ClientsTelemetry{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}

	return ct, nil
}
