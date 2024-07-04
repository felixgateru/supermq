// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package sdk_test

import (
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/absmach/magistrala/invitations"
	mgclients "github.com/absmach/magistrala/pkg/clients"
	mggroups "github.com/absmach/magistrala/pkg/groups"
	sdk "github.com/absmach/magistrala/pkg/sdk/go"
	"github.com/absmach/magistrala/pkg/uuid"
	"github.com/absmach/magistrala/users/hasher"
	"github.com/stretchr/testify/assert"
)

const (
	invalidIdentity = "invalididentity"
	Identity        = "identity"
	secret          = "strongsecret"
	token           = "token"
	invalidToken    = "invalid"
	contentType     = "application/senml+json"
)

var (
	idProvider    = uuid.New()
	phasher       = hasher.New()
	validMetadata = sdk.Metadata{"role": "client"}
	user          = generateTestUser(&testing.T{})
	thing         = sdk.Thing{
		Name:        "thingname",
		Tags:        []string{"tag1", "tag2"},
		Credentials: sdk.Credentials{Identity: "clientidentity", Secret: generateUUID(&testing.T{})},
		Metadata:    validMetadata,
		Status:      mgclients.EnabledStatus.String(),
	}
	description = "shortdescription"
	gName       = "groupname"

	limit  uint64 = 5
	offset uint64 = 0
	total  uint64 = 200

	subject   = generateUUID(&testing.T{})
	object    = generateUUID(&testing.T{})
	passRegex = regexp.MustCompile("^.{8,}$")
)

func generateUUID(t *testing.T) string {
	ulid, err := idProvider.ID()
	assert.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	return ulid
}

func convertThingsPage(cp sdk.ThingsPage) mgclients.ClientsPage {
	return mgclients.ClientsPage{
		Clients: convertThings(cp.Things...),
	}
}

func convertClients(cs []sdk.User) []mgclients.Client {
	ccs := []mgclients.Client{}

	for _, c := range cs {
		ccs = append(ccs, convertClient(c))
	}

	return ccs
}

func convertThings(cs ...sdk.Thing) []mgclients.Client {
	ccs := []mgclients.Client{}

	for _, c := range cs {
		ccs = append(ccs, convertThing(c))
	}

	return ccs
}

func convertGroups(cs []sdk.Group) []mggroups.Group {
	cgs := []mggroups.Group{}

	for _, c := range cs {
		cgs = append(cgs, convertGroup(c))
	}

	return cgs
}

func convertChannels(cs []sdk.Channel) []mggroups.Group {
	cgs := []mggroups.Group{}

	for _, c := range cs {
		cgs = append(cgs, convertChannel(c))
	}

	return cgs
}

func convertClientPage(p sdk.PageMetadata) mgclients.Page {
	if p.Status == "" {
		p.Status = mgclients.EnabledStatus.String()
	}
	status, err := mgclients.ToStatus(p.Status)
	if err != nil {
		return mgclients.Page{}
	}

	return mgclients.Page{
		Status:   status,
		Total:    p.Total,
		Offset:   p.Offset,
		Limit:    p.Limit,
		Name:     p.Name,
		Tag:      p.Tag,
		Metadata: mgclients.Metadata(p.Metadata),
	}
}

func convertGroup(g sdk.Group) mggroups.Group {
	if g.Status == "" {
		g.Status = mgclients.EnabledStatus.String()
	}
	status, err := mgclients.ToStatus(g.Status)
	if err != nil {
		return mggroups.Group{}
	}

	return mggroups.Group{
		ID:          g.ID,
		Domain:      g.DomainID,
		Parent:      g.ParentID,
		Name:        g.Name,
		Description: g.Description,
		Metadata:    mgclients.Metadata(g.Metadata),
		Level:       g.Level,
		Path:        g.Path,
		Children:    convertChildren(g.Children),
		CreatedAt:   g.CreatedAt,
		UpdatedAt:   g.UpdatedAt,
		Status:      status,
	}
}

func convertChildren(gs []*sdk.Group) []*mggroups.Group {
	cg := []*mggroups.Group{}

	if len(gs) == 0 {
		return cg
	}

	for _, g := range gs {
		insert := convertGroup(*g)
		cg = append(cg, &insert)
	}

	return cg
}

func convertClient(c sdk.User) mgclients.Client {
	if c.Status == "" {
		c.Status = mgclients.EnabledStatus.String()
	}
	status, err := mgclients.ToStatus(c.Status)
	if err != nil {
		return mgclients.Client{}
	}
	role, err := mgclients.ToRole(c.Role)
	if err != nil {
		return mgclients.Client{}
	}
	return mgclients.Client{
		ID:          c.ID,
		Name:        c.Name,
		Tags:        c.Tags,
		Domain:      c.Domain,
		Credentials: mgclients.Credentials(c.Credentials),
		Metadata:    mgclients.Metadata(c.Metadata),
		CreatedAt:   c.CreatedAt,
		UpdatedAt:   c.UpdatedAt,
		Status:      status,
		Role:        role,
	}
}

func convertThing(c sdk.Thing) mgclients.Client {
	if c.Status == "" {
		c.Status = mgclients.EnabledStatus.String()
	}
	status, err := mgclients.ToStatus(c.Status)
	if err != nil {
		return mgclients.Client{}
	}
	return mgclients.Client{
		ID:          c.ID,
		Name:        c.Name,
		Tags:        c.Tags,
		Domain:      c.DomainID,
		Credentials: mgclients.Credentials(c.Credentials),
		Metadata:    mgclients.Metadata(c.Metadata),
		CreatedAt:   c.CreatedAt,
		UpdatedAt:   c.UpdatedAt,
		Status:      status,
	}
}

func convertChannel(g sdk.Channel) mggroups.Group {
	if g.Status == "" {
		g.Status = mgclients.EnabledStatus.String()
	}
	status, err := mgclients.ToStatus(g.Status)
	if err != nil {
		return mggroups.Group{}
	}
	return mggroups.Group{
		ID:          g.ID,
		Domain:      g.DomainID,
		Parent:      g.ParentID,
		Name:        g.Name,
		Description: g.Description,
		Metadata:    mgclients.Metadata(g.Metadata),
		Level:       g.Level,
		Path:        g.Path,
		CreatedAt:   g.CreatedAt,
		UpdatedAt:   g.UpdatedAt,
		Status:      status,
	}
}

func convertInvitation(i sdk.Invitation) invitations.Invitation {
	return invitations.Invitation{
		InvitedBy:   i.InvitedBy,
		UserID:      i.UserID,
		DomainID:    i.DomainID,
		Token:       i.Token,
		Relation:    i.Relation,
		CreatedAt:   i.CreatedAt,
		UpdatedAt:   i.UpdatedAt,
		ConfirmedAt: i.ConfirmedAt,
		Resend:      i.Resend,
	}
}

func generateTestUser(t *testing.T) sdk.User {
	createdAt, err := time.Parse(time.RFC3339, "2024-01-01T00:00:00Z")
	assert.Nil(t, err, fmt.Sprintf("Unexpected error parsing time: %v", err))
	return sdk.User{
		ID:   generateUUID(t),
		Name: "clientname",
		Credentials: sdk.Credentials{
			Identity: "clientidentity@email.com",
			Secret:   secret,
		},
		Tags:      []string{"tag1", "tag2"},
		Metadata:  validMetadata,
		CreatedAt: createdAt,
		UpdatedAt: createdAt,
		Status:    mgclients.EnabledStatus.String(),
	}
}

func TestMain(m *testing.M) {
	exitCode := m.Run()
	os.Exit(exitCode)
}
