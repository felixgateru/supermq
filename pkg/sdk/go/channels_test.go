// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package sdk_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/absmach/magistrala"
	authmocks "github.com/absmach/magistrala/auth/mocks"
	"github.com/absmach/magistrala/internal/groups"
	"github.com/absmach/magistrala/internal/testsutil"
	mglog "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/apiutil"
	mgclients "github.com/absmach/magistrala/pkg/clients"
	"github.com/absmach/magistrala/pkg/errors"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	"github.com/absmach/magistrala/pkg/groups"
	gmocks "github.com/absmach/magistrala/pkg/groups/mocks"
	oauth2mocks "github.com/absmach/magistrala/pkg/oauth2/mocks"
	sdk "github.com/absmach/magistrala/pkg/sdk/go"
	thapi "github.com/absmach/magistrala/things/api/http"
	thmocks "github.com/absmach/magistrala/things/mocks"
	usapi "github.com/absmach/magistrala/users/api"
	usmocks "github.com/absmach/magistrala/users/mocks"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var (
	channelName    = "channelName"
	newName        = "newName"
	newDescription = "newDescription"
	channel        = generateTestChannel(&testing.T{})
	group          = convertChannel(channel)
)

func setupChannels() (*httptest.Server, *gmocks.Service) {
	tsvc := new(thmocks.Service)
	usvc := new(usmocks.Service)
	gsvc := new(gmocks.Service)
	logger := mglog.NewMock()
	provider := new(oauth2mocks.Provider)
	provider.On("Name").Return("test")

	mux := chi.NewRouter()

	thapi.MakeHandler(tsvc, gsvc, mux, logger, "")
	usapi.MakeHandler(usvc, gsvc, mux, logger, "", passRegex, provider)
	return httptest.NewServer(mux), gsvc
}

func TestCreateChannel(t *testing.T) {
	ts, gsvc := setupChannels()
	defer ts.Close()

	createGroupReq := groups.Group{
		Name:     channel.Name,
		Metadata: mgclients.Metadata{"role": "client"},
		Status:   mgclients.EnabledStatus,
	}

	channelReq := sdk.Channel{
		Name:     channel.Name,
		Metadata: validMetadata,
		Status:   mgclients.EnabledStatus.String(),
	}

	channelKind := "new_channel"
	parentID := testsutil.GenerateUUID(&testing.T{})
	pGroup := group
	pGroup.Parent = parentID
	pChannel := channel
	pChannel.ParentID = parentID

	iGroup := group
	iGroup.Metadata = mgclients.Metadata{
		"test": make(chan int),
	}

	conf := sdk.Config{
		ThingsURL: ts.URL,
	}
	mgsdk := sdk.NewSDK(conf)
	cases := []struct {
		desc           string
		channelReq     sdk.Channel
		token          string
		createGroupReq groups.Group
		svcRes         groups.Group
		svcErr         error
		response       sdk.Channel
		err            errors.SDKError
	}{
		{
			desc:           "create channel successfully",
			channelReq:     channelReq,
			token:          validToken,
			createGroupReq: createGroupReq,
			svcRes:         group,
			svcErr:         nil,
			response:       channel,
			err:            nil,
		},
		{
			desc:           "create channel with existing name",
			channelReq:     channelReq,
			token:          validToken,
			createGroupReq: createGroupReq,
			svcRes:         groups.Group{},
			svcErr:         svcerr.ErrCreateEntity,
			response:       sdk.Channel{},
			err:            errors.NewSDKErrorWithStatus(svcerr.ErrCreateEntity, http.StatusUnprocessableEntity),
		},
		{
			desc: "create channel that can't be marshalled",
			channelReq: sdk.Channel{
				Name: "test",
				Metadata: map[string]interface{}{
					"test": make(chan int),
				},
			},
			token:          validToken,
			createGroupReq: groups.Group{},
			svcRes:         groups.Group{},
			svcErr:         nil,
			response:       sdk.Channel{},
			err:            errors.NewSDKError(errors.New("json: unsupported type: chan int")),
		},
		{
			desc: "create channel with parent",
			channelReq: sdk.Channel{
				Name:     channel.Name,
				ParentID: parentID,
				Status:   mgclients.EnabledStatus.String(),
			},
			token: validToken,
			createGroupReq: groups.Group{
				Name:   channel.Name,
				Parent: parentID,
				Status: mgclients.EnabledStatus,
			},
			svcRes:   pGroup,
			svcErr:   nil,
			response: pChannel,
			err:      nil,
		},
		{
			desc: "create channel with invalid parent",
			channelReq: sdk.Channel{
				Name:     channel.Name,
				ParentID: wrongID,
				Status:   mgclients.EnabledStatus.String(),
			},
			token: validToken,
			createGroupReq: groups.Group{
				Name:   channel.Name,
				Parent: wrongID,
				Status: mgclients.EnabledStatus,
			},
			svcRes:   groups.Group{},
			svcErr:   svcerr.ErrCreateEntity,
			response: sdk.Channel{},
			err:      errors.NewSDKErrorWithStatus(svcerr.ErrCreateEntity, http.StatusUnprocessableEntity),
		},
		{
			desc: "create channel with missing name",
			channelReq: sdk.Channel{
				Status: mgclients.EnabledStatus.String(),
			},
			token:          validToken,
			createGroupReq: groups.Group{},
			svcRes:         groups.Group{},
			svcErr:         nil,
			response:       sdk.Channel{},
			err:            errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrNameSize), http.StatusBadRequest),
		},
		{
			desc: "create a channel with every field defined",
			channelReq: sdk.Channel{
				ID:          group.ID,
				ParentID:    parentID,
				Name:        channel.Name,
				Description: description,
				Metadata:    validMetadata,
				CreatedAt:   group.CreatedAt,
				UpdatedAt:   group.UpdatedAt,
				Status:      mgclients.EnabledStatus.String(),
			},
			token: validToken,
			createGroupReq: groups.Group{
				ID:          group.ID,
				Parent:      parentID,
				Name:        channel.Name,
				Description: description,
				Metadata:    mgclients.Metadata{"role": "client"},
				CreatedAt:   group.CreatedAt,
				UpdatedAt:   group.UpdatedAt,
				Status:      mgclients.EnabledStatus,
			},
			svcRes:   pGroup,
			svcErr:   nil,
			response: pChannel,
			err:      nil,
		},
		{
			desc:           "create channel with response that can't be unmarshalled",
			channelReq:     channelReq,
			token:          validToken,
			createGroupReq: createGroupReq,
			svcRes:         iGroup,
			svcErr:         nil,
			response:       sdk.Channel{},
			err:            errors.NewSDKError(errors.New("unexpected end of JSON input")),
		},
	}
	for _, tc := range cases {
		authCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: tc.token}).Return(&magistrala.IdentityRes{Id: validID, DomainId: testsutil.GenerateUUID(t)}, nil)
		authCall1 := auth.On("AddPolicies", mock.Anything, mock.Anything).Return(&magistrala.AddPoliciesRes{Added: true}, nil)
		authCall2 := auth.On("Authorize", mock.Anything, mock.Anything).Return(&magistrala.AuthorizeRes{Authorized: true}, nil)
		authCall3 := auth.On("DeletePolicies", mock.Anything, mock.Anything).Return(&magistrala.DeletePolicyRes{Deleted: false}, nil)
		repoCall := grepo.On("Save", mock.Anything, mock.Anything).Return(convertChannel(sdk.Channel{}), tc.err)
		rChannel, err := mgsdk.CreateChannel(tc.channel, validToken)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))
		if err == nil {
			assert.NotEmpty(t, rChannel, fmt.Sprintf("%s: expected not nil on client ID", tc.desc))
			ok := repoCall.Parent.AssertCalled(t, "Save", mock.Anything, mock.Anything)
			assert.True(t, ok, fmt.Sprintf("Save was not called on %s", tc.desc))
		}
		authCall.Unset()
		authCall1.Unset()
		authCall2.Unset()
		authCall3.Unset()
		repoCall.Unset()
	}
}

func TestListChannels(t *testing.T) {
	ts, gsvc := setupChannels()
	defer ts.Close()

	var chs []sdk.Channel
	conf := sdk.Config{
		ThingsURL: ts.URL,
	}
	mgsdk := sdk.NewSDK(conf)

	for i := 10; i < 100; i++ {
		gr := sdk.Channel{
			ID:       generateUUID(t),
			Name:     fmt.Sprintf("channel_%d", i),
			Metadata: sdk.Metadata{"name": fmt.Sprintf("thing_%d", i)},
			Status:   mgclients.EnabledStatus.String(),
		}
		chs = append(chs, gr)
	}

	cases := []struct {
		desc           string
		token          string
		status         mgclients.Status
		total          uint64
		offset         uint64
		limit          uint64
		level          int
		name           string
		metadata       sdk.Metadata
		groupsPageMeta groups.Page
		svcRes         groups.Page
		svcErr         error
		response       sdk.ChannelsPage
		err            errors.SDKError
	}{
		{
			desc:   "list channels successfully",
			token:  validToken,
			limit:  limit,
			offset: offset,
			total:  total,
			groupsPageMeta: groups.Page{
				PageMeta: groups.PageMeta{
					Offset: offset,
					Limit:  limit,
				},
				Permission: "view",
				Direction:  -1,
			},
			svcRes: groups.Page{
				PageMeta: groups.PageMeta{
					Total: uint64(len(chs[offset:limit])),
				},
				Groups: convertChannels(chs[offset:limit]),
			},
			response: sdk.ChannelsPage{
				PageRes: sdk.PageRes{
					Total: uint64(len(chs[offset:limit])),
				},
				Channels: chs[offset:limit],
			},
			err: nil,
		},
		{
			desc:   "list channels with invalid token",
			token:  invalidToken,
			offset: offset,
			limit:  limit,
			groupsPageMeta: groups.Page{
				PageMeta: groups.PageMeta{
					Offset: offset,
					Limit:  limit,
				},
				Permission: "view",
				Direction:  -1,
			},
			svcRes:   groups.Page{},
			svcErr:   svcerr.ErrAuthentication,
			response: sdk.ChannelsPage{},
			err:      errors.NewSDKErrorWithStatus(svcerr.ErrAuthentication, http.StatusUnauthorized),
		},
		{
			desc:           "list channels with empty token",
			token:          "",
			offset:         offset,
			limit:          limit,
			groupsPageMeta: groups.Page{},
			svcRes:         groups.Page{},
			svcErr:         nil,
			response:       sdk.ChannelsPage{},
			err:            errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrBearerToken), http.StatusUnauthorized),
		},
		{
			desc:   "list channels with zero limit",
			token:  token,
			offset: offset,
			limit:  0,
			groupsPageMeta: groups.Page{
				PageMeta: groups.PageMeta{
					Offset: offset,
					Limit:  10,
				},
				Permission: "view",
				Direction:  -1,
			},
			svcRes: groups.Page{
				PageMeta: groups.PageMeta{
					Total: uint64(len(chs[offset:])),
				},
				Groups: convertChannels(chs[offset:limit]),
			},
			svcErr: nil,
			response: sdk.ChannelsPage{
				PageRes: sdk.PageRes{
					Total: uint64(len(chs[offset:])),
				},
				Channels: chs[offset:limit],
			},
			err: nil,
		},
		{
			desc:           "list channels with limit greater than max",
			token:          token,
			offset:         offset,
			limit:          110,
			groupsPageMeta: groups.Page{},
			svcRes:         groups.Page{},
			svcErr:         nil,
			response:       sdk.ChannelsPage{},
			err:            errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrLimitSize), http.StatusBadRequest),
		},
		{
			desc:   "list channels with level",
			token:  token,
			offset: 0,
			limit:  1,
			level:  1,
			groupsPageMeta: groups.Page{
				PageMeta: groups.PageMeta{
					Offset: offset,
					Limit:  1,
				},
				Level:      1,
				Permission: "view",
				Direction:  -1,
			},
			svcRes: groups.Page{
				PageMeta: groups.PageMeta{
					Total: 1,
				},
				Groups: convertChannels(chs[0:1]),
			},
			svcErr: nil,
			response: sdk.ChannelsPage{
				PageRes: sdk.PageRes{
					Total: 1,
				},
				Channels: chs[0:1],
			},
			err: nil,
		},
		{
			desc:     "list channels with metadata",
			token:    token,
			offset:   0,
			limit:    10,
			metadata: sdk.Metadata{"name": "thing_89"},
			groupsPageMeta: groups.Page{
				PageMeta: groups.PageMeta{
					Offset:   offset,
					Limit:    10,
					Metadata: mgclients.Metadata{"name": "thing_89"},
				},
				Permission: "view",
				Direction:  -1,
			},
			svcRes: groups.Page{
				PageMeta: groups.PageMeta{
					Total: 1,
				},
				Groups: convertChannels([]sdk.Channel{chs[89]}),
			},
			svcErr: nil,
			response: sdk.ChannelsPage{
				PageRes: sdk.PageRes{
					Total: 1,
				},
				Channels: []sdk.Channel{chs[89]},
			},
			err: nil,
		},
		{
			desc:   "list channels with invalid metadata",
			token:  token,
			offset: 0,
			limit:  10,
			metadata: sdk.Metadata{
				"test": make(chan int),
			},
			groupsPageMeta: groups.Page{},
			svcRes:         groups.Page{},
			svcErr:         nil,
			response:       sdk.ChannelsPage{},
			err:            errors.NewSDKError(errors.New("json: unsupported type: chan int")),
		},
		{
			desc:   "list channels with service response that can't be unmarshalled",
			token:  token,
			offset: 0,
			limit:  10,
			groupsPageMeta: groups.Page{
				PageMeta: groups.PageMeta{
					Offset: 0,
					Limit:  10,
				},
				Permission: "view",
				Direction:  -1,
			},
			svcRes: groups.Page{
				PageMeta: groups.PageMeta{
					Total: 1,
				},
				Groups: []groups.Group{{
					ID: generateUUID(t),
					Metadata: mgclients.Metadata{
						"test": make(chan int),
					},
				}},
			},
			svcErr:   nil,
			response: sdk.ChannelsPage{},
			err:      errors.NewSDKError(errors.New("unexpected end of JSON input")),
		},
	}

	for _, tc := range cases {
		authCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: tc.token}).Return(&magistrala.IdentityRes{Id: validID, DomainId: testsutil.GenerateUUID(t)}, nil)
		authCall1 := auth.On("Authorize", mock.Anything, mock.Anything).Return(&magistrala.AuthorizeRes{Authorized: true}, nil)
		if tc.token == invalidToken {
			authCall = auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: invalidToken}).Return(&magistrala.IdentityRes{}, svcerr.ErrAuthentication)
			authCall1 = auth.On("Authorize", mock.Anything, mock.Anything).Return(&magistrala.AuthorizeRes{Authorized: false}, svcerr.ErrAuthorization)
		}
		authCall2 := auth.On("ListAllObjects", mock.Anything, mock.Anything).Return(&magistrala.ListObjectsRes{Policies: toIDs(tc.response)}, nil)
		repoCall := grepo.On("RetrieveByIDs", mock.Anything, mock.Anything, mock.Anything).Return(mggroups.Page{Groups: convertChannels(tc.response)}, tc.err)
		pm := sdk.PageMetadata{
			Offset: tc.offset,
			Limit:  tc.limit,
			Level:  uint64(tc.level),
		}
		svcCall := gsvc.On("ListGroups", mock.Anything, tc.token, memberKind, "", tc.groupsPageMeta).Return(tc.svcRes, tc.svcErr)
		page, err := mgsdk.Channels(pm, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %s, got %s", tc.desc, tc.err, err))
		assert.Equal(t, len(tc.response), len(page.Channels), fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, page))
		if tc.err == nil {
			ok := repoCall.Parent.AssertCalled(t, "RetrieveByIDs", mock.Anything, mock.Anything, mock.Anything)
			assert.True(t, ok, fmt.Sprintf("RetrieveByIDs was not called on %s", tc.desc))
		}
		authCall.Unset()
		authCall1.Unset()
		authCall2.Unset()
		repoCall.Unset()
	}
}

// func TestViewChannel(t *testing.T) {
// 	ts, grepo, auth := setupChannels()
// 	defer ts.Close()

// 	channel := sdk.Channel{
// 		Name:        "channelName",
// 		Description: description,
// 		Metadata:    validMetadata,
// 		Children:    []*sdk.Channel{},
// 		Status:      mgclients.EnabledStatus.String(),
// 	}

// 	conf := sdk.Config{
// 		ThingsURL: ts.URL,
// 	}
// 	mgsdk := sdk.NewSDK(conf)
// 	channel.ID = generateUUID(t)

// 	cases := []struct {
// 		desc      string
// 		token     string
// 		channelID string
// 		response  sdk.Channel
// 		err       errors.SDKError
// 	}{
// 		{
// 			desc:      "view channel",
// 			token:     validToken,
// 			channelID: channel.ID,
// 			response:  channel,
// 			err:       nil,
// 		},
// 		{
// 			desc:      "view channel with invalid token",
// 			token:     "wrongtoken",
// 			channelID: channel.ID,
// 			response:  sdk.Channel{Children: []*sdk.Channel{}},
// 			err:       errors.NewSDKErrorWithStatus(svcerr.ErrViewEntity, http.StatusBadRequest),
// 		},
// 		{
// 			desc:      "view channel for wrong id",
// 			token:     validToken,
// 			channelID: wrongID,
// 			response:  sdk.Channel{Children: []*sdk.Channel{}},
// 			err:       errors.NewSDKErrorWithStatus(svcerr.ErrViewEntity, http.StatusBadRequest),
// 		},
// 	}

	for _, tc := range cases {
		authCall := auth.On("Authorize", mock.Anything, mock.Anything).Return(&magistrala.AuthorizeRes{Authorized: true}, nil)
		repoCall := grepo.On("RetrieveByID", mock.Anything, tc.channelID).Return(convertChannel(tc.response), tc.err)
		grp, err := mgsdk.Channel(tc.channelID, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %s, got %s", tc.desc, tc.err, err))
		if len(tc.response.Children) == 0 {
			tc.response.Children = nil
		}
		if len(grp.Children) == 0 {
			grp.Children = nil
		}
		assert.Equal(t, tc.response, grp, fmt.Sprintf("%s: expected metadata %v got %v\n", tc.desc, tc.response, grp))
		if tc.err == nil {
			ok := repoCall.Parent.AssertCalled(t, "RetrieveByID", mock.Anything, tc.channelID)
			assert.True(t, ok, fmt.Sprintf("RetrieveByID was not called on %s", tc.desc))
		}
		authCall.Unset()
		repoCall.Unset()
	}
}

// func TestUpdateChannel(t *testing.T) {
// 	ts, grepo, auth := setupChannels()
// 	defer ts.Close()

// 	channel := sdk.Channel{
// 		ID:          generateUUID(t),
// 		Name:        "channelsName",
// 		Description: description,
// 		Metadata:    validMetadata,
// 	}

// 	conf := sdk.Config{
// 		ThingsURL: ts.URL,
// 	}
// 	mgsdk := sdk.NewSDK(conf)

// 	channel.ID = generateUUID(t)

// 	cases := []struct {
// 		desc     string
// 		token    string
// 		channel  sdk.Channel
// 		response sdk.Channel
// 		err      errors.SDKError
// 	}{
// 		{
// 			desc: "update channel name",
// 			channel: sdk.Channel{
// 				ID:   channel.ID,
// 				Name: "NewName",
// 			},
// 			response: sdk.Channel{
// 				ID:   channel.ID,
// 				Name: "NewName",
// 			},
// 			token: validToken,
// 			err:   nil,
// 		},
// 		{
// 			desc: "update channel description",
// 			channel: sdk.Channel{
// 				ID:          channel.ID,
// 				Description: "NewDescription",
// 			},
// 			response: sdk.Channel{
// 				ID:          channel.ID,
// 				Description: "NewDescription",
// 			},
// 			token: validToken,
// 			err:   nil,
// 		},
// 		{
// 			desc: "update channel metadata",
// 			channel: sdk.Channel{
// 				ID: channel.ID,
// 				Metadata: sdk.Metadata{
// 					"field": "value2",
// 				},
// 			},
// 			response: sdk.Channel{
// 				ID: channel.ID,
// 				Metadata: sdk.Metadata{
// 					"field": "value2",
// 				},
// 			},
// 			token: validToken,
// 			err:   nil,
// 		},
// 		{
// 			desc: "update channel name with invalid channel id",
// 			channel: sdk.Channel{
// 				ID:   wrongID,
// 				Name: "NewName",
// 			},
// 			response: sdk.Channel{},
// 			token:    validToken,
// 			err:      errors.NewSDKErrorWithStatus(svcerr.ErrNotFound, http.StatusNotFound),
// 		},
// 		{
// 			desc: "update channel description with invalid channel id",
// 			channel: sdk.Channel{
// 				ID:          wrongID,
// 				Description: "NewDescription",
// 			},
// 			response: sdk.Channel{},
// 			token:    validToken,
// 			err:      errors.NewSDKErrorWithStatus(svcerr.ErrNotFound, http.StatusNotFound),
// 		},
// 		{
// 			desc: "update channel metadata with invalid channel id",
// 			channel: sdk.Channel{
// 				ID: wrongID,
// 				Metadata: sdk.Metadata{
// 					"field": "value2",
// 				},
// 			},
// 			response: sdk.Channel{},
// 			token:    validToken,
// 			err:      errors.NewSDKErrorWithStatus(svcerr.ErrNotFound, http.StatusNotFound),
// 		},
// 		{
// 			desc: "update channel name with invalid token",
// 			channel: sdk.Channel{
// 				ID:   channel.ID,
// 				Name: "NewName",
// 			},
// 			response: sdk.Channel{},
// 			token:    invalidToken,
// 			err:      errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
// 		},
// 		{
// 			desc: "update channel description with invalid token",
// 			channel: sdk.Channel{
// 				ID:          channel.ID,
// 				Description: "NewDescription",
// 			},
// 			response: sdk.Channel{},
// 			token:    invalidToken,
// 			err:      errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
// 		},
// 		{
// 			desc: "update channel metadata with invalid token",
// 			channel: sdk.Channel{
// 				ID: channel.ID,
// 				Metadata: sdk.Metadata{
// 					"field": "value2",
// 				},
// 			},
// 			response: sdk.Channel{},
// 			token:    invalidToken,
// 			err:      errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
// 		},
// 		{
// 			desc: "update channel that can't be marshalled",
// 			channel: sdk.Channel{
// 				Name: "test",
// 				Metadata: map[string]interface{}{
// 					"test": make(chan int),
// 				},
// 			},
// 			response: sdk.Channel{},
// 			token:    token,
// 			err:      errors.NewSDKError(fmt.Errorf("json: unsupported type: chan int")),
// 		},
// 	}

	for _, tc := range cases {
		authCall := auth.On("Authorize", mock.Anything, mock.Anything).Return(&magistrala.AuthorizeRes{Authorized: true}, nil)
		repoCall := grepo.On("Update", mock.Anything, mock.Anything).Return(convertChannel(tc.response), tc.err)
		_, err := mgsdk.UpdateChannel(tc.channel, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %s, got %s", tc.desc, tc.err, err))
		if tc.err == nil {
			ok := repoCall.Parent.AssertCalled(t, "Update", mock.Anything, mock.Anything)
			assert.True(t, ok, fmt.Sprintf("Update was not called on %s", tc.desc))
		}
		authCall.Unset()
		repoCall.Unset()
	}
}

// func TestListChannelsByThing(t *testing.T) {
// 	ts, grepo, auth := setupChannels()
// 	auth.Test(t)
// 	defer ts.Close()

	conf := sdk.Config{
		ThingsURL: ts.URL,
	}
	mgsdk := sdk.NewSDK(conf)

	nChannels := uint64(10)
	aChannels := []sdk.Channel{}

// 	for i := uint64(1); i < nChannels; i++ {
// 		channel := sdk.Channel{
// 			ID:       generateUUID(t),
// 			Name:     fmt.Sprintf("membership_%d@example.com", i),
// 			Metadata: sdk.Metadata{"role": "channel"},
// 			Status:   mgclients.EnabledStatus.String(),
// 		}
// 		aChannels = append(aChannels, channel)
// 	}

// 	cases := []struct {
// 		desc     string
// 		token    string
// 		clientID string
// 		page     sdk.PageMetadata
// 		response []sdk.Channel
// 		err      errors.SDKError
// 	}{
// 		{
// 			desc:     "list channel with authorized token",
// 			token:    validToken,
// 			clientID: testsutil.GenerateUUID(t),
// 			page:     sdk.PageMetadata{},
// 			response: aChannels,
// 			err:      nil,
// 		},
// 		{
// 			desc:     "list channel with offset and limit",
// 			token:    validToken,
// 			clientID: testsutil.GenerateUUID(t),
// 			page: sdk.PageMetadata{
// 				Offset: 6,
// 				Total:  nChannels,
// 				Limit:  nChannels,
// 				Status: mgclients.AllStatus.String(),
// 			},
// 			response: aChannels[6 : nChannels-1],
// 			err:      nil,
// 		},
// 		{
// 			desc:     "list channel with given name",
// 			token:    validToken,
// 			clientID: testsutil.GenerateUUID(t),
// 			page: sdk.PageMetadata{
// 				Name:   gName,
// 				Offset: 6,
// 				Total:  nChannels,
// 				Limit:  nChannels,
// 				Status: mgclients.AllStatus.String(),
// 			},
// 			response: aChannels[6 : nChannels-1],
// 			err:      nil,
// 		},
// 		{
// 			desc:     "list channel with given level",
// 			token:    validToken,
// 			clientID: testsutil.GenerateUUID(t),
// 			page: sdk.PageMetadata{
// 				Level:  1,
// 				Offset: 6,
// 				Total:  nChannels,
// 				Limit:  nChannels,
// 				Status: mgclients.AllStatus.String(),
// 			},
// 			response: aChannels[6 : nChannels-1],
// 			err:      nil,
// 		},
// 		{
// 			desc:     "list channel with metadata",
// 			token:    validToken,
// 			clientID: testsutil.GenerateUUID(t),
// 			page: sdk.PageMetadata{
// 				Metadata: validMetadata,
// 				Offset:   6,
// 				Total:    nChannels,
// 				Limit:    nChannels,
// 				Status:   mgclients.AllStatus.String(),
// 			},
// 			response: aChannels[6 : nChannels-1],
// 			err:      nil,
// 		},
// 		{
// 			desc:     "list channel with an invalid token",
// 			token:    invalidToken,
// 			clientID: testsutil.GenerateUUID(t),
// 			page:     sdk.PageMetadata{},
// 			response: []sdk.Channel(nil),
// 			err:      errors.NewSDKErrorWithStatus(svcerr.ErrAuthentication, http.StatusUnauthorized),
// 		},
// 	}

	for _, tc := range cases {
		authCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: tc.token}).Return(&magistrala.IdentityRes{Id: validID, DomainId: testsutil.GenerateUUID(t)}, nil)
		authCall1 := auth.On("Authorize", mock.Anything, mock.Anything).Return(&magistrala.AuthorizeRes{Authorized: true}, nil)
		authCall2 := auth.On("ListAllSubjects", mock.Anything, mock.Anything).Return(&magistrala.ListSubjectsRes{Policies: toIDs(tc.response)}, nil)
		authCall3 := auth.On("ListAllObjects", mock.Anything, mock.Anything).Return(&magistrala.ListObjectsRes{Policies: toIDs(tc.response)}, nil)
		repoCall := grepo.On("RetrieveByIDs", mock.Anything, mock.Anything, mock.Anything).Return(mggroups.Page{Groups: convertChannels(tc.response)}, tc.err)
		page, err := mgsdk.ChannelsByThing(tc.clientID, tc.page, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %s, got %s", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, page.Channels, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, page.Channels))
		authCall.Unset()
		authCall1.Unset()
		authCall2.Unset()
		authCall3.Unset()
		repoCall.Unset()
	}
}

// func TestEnableChannel(t *testing.T) {
// 	ts, grepo, auth := setupChannels()
// 	defer ts.Close()

// 	conf := sdk.Config{
// 		ThingsURL: ts.URL,
// 	}
// 	mgsdk := sdk.NewSDK(conf)

// 	creationTime := time.Now().UTC()
// 	channel := sdk.Channel{
// 		ID:        generateUUID(t),
// 		Name:      gName,
// 		CreatedAt: creationTime,
// 		UpdatedAt: creationTime,
// 		Status:    mgclients.Disabled,
// 	}

	authCall := auth.On("Authorize", mock.Anything, mock.Anything).Return(&magistrala.AuthorizeRes{Authorized: true}, nil)
	repoCall := grepo.On("RetrieveByID", mock.Anything, mock.Anything).Return(mggroups.Group{}, repoerr.ErrNotFound)
	repoCall1 := grepo.On("ChangeStatus", mock.Anything, mock.Anything).Return(nil)
	_, err := mgsdk.EnableChannel("wrongID", validToken)
	assert.Equal(t, errors.NewSDKErrorWithStatus(svcerr.ErrViewEntity, http.StatusBadRequest), err, fmt.Sprintf("Enable channel with wrong id: expected %v got %v", svcerr.ErrViewEntity, err))
	ok := repoCall.Parent.AssertCalled(t, "RetrieveByID", mock.Anything, "wrongID")
	assert.True(t, ok, "RetrieveByID was not called on enabling channel")
	authCall.Unset()
	repoCall.Unset()
	repoCall1.Unset()

	ch := mggroups.Group{
		ID:        channel.ID,
		Name:      channel.Name,
		CreatedAt: creationTime,
		UpdatedAt: creationTime,
		Status:    mgclients.DisabledStatus,
	}
	authCall = auth.On("Authorize", mock.Anything, mock.Anything).Return(&magistrala.AuthorizeRes{Authorized: true}, nil)
	repoCall = grepo.On("RetrieveByID", mock.Anything, mock.Anything).Return(ch, nil)
	repoCall1 = grepo.On("ChangeStatus", mock.Anything, mock.Anything).Return(ch, nil)
	res, err := mgsdk.EnableChannel(channel.ID, validToken)
	assert.Nil(t, err, fmt.Sprintf("Enable channel with correct id: expected %v got %v", nil, err))
	assert.Equal(t, channel, res, fmt.Sprintf("Enable channel with correct id: expected %v got %v", channel, res))
	ok = repoCall.Parent.AssertCalled(t, "RetrieveByID", mock.Anything, channel.ID)
	assert.True(t, ok, "RetrieveByID was not called on enabling channel")
	ok = repoCall1.Parent.AssertCalled(t, "ChangeStatus", mock.Anything, mock.Anything)
	assert.True(t, ok, "ChangeStatus was not called on enabling channel")
	authCall.Unset()
	repoCall.Unset()
	repoCall1.Unset()
}

// func TestDisableChannel(t *testing.T) {
// 	ts, grepo, auth := setupChannels()
// 	defer ts.Close()

// 	conf := sdk.Config{
// 		ThingsURL: ts.URL,
// 	}
// 	mgsdk := sdk.NewSDK(conf)

// 	creationTime := time.Now().UTC()
// 	channel := sdk.Channel{
// 		ID:        generateUUID(t),
// 		Name:      gName,
// 		DomainID:  generateUUID(t),
// 		CreatedAt: creationTime,
// 		UpdatedAt: creationTime,
// 		Status:    mgclients.Enabled,
// 	}

	authCall := auth.On("Authorize", mock.Anything, mock.Anything).Return(&magistrala.AuthorizeRes{Authorized: true}, nil)
	repoCall := grepo.On("ChangeStatus", mock.Anything, mock.Anything).Return(nil)
	repoCall1 := grepo.On("RetrieveByID", mock.Anything, mock.Anything).Return(mggroups.Group{}, repoerr.ErrNotFound)
	_, err := mgsdk.DisableChannel("wrongID", validToken)
	assert.Equal(t, err, errors.NewSDKErrorWithStatus(svcerr.ErrViewEntity, http.StatusBadRequest), fmt.Sprintf("Disable channel with wrong id: expected %v got %v", svcerr.ErrNotFound, err))
	ok := repoCall.Parent.AssertCalled(t, "RetrieveByID", mock.Anything, "wrongID")
	assert.True(t, ok, "Memberships was not called on disabling channel with wrong id")
	authCall.Unset()
	repoCall.Unset()
	repoCall1.Unset()

// 	ch := mggroups.Group{
// 		ID:        channel.ID,
// 		Name:      channel.Name,
// 		Domain:    channel.DomainID,
// 		CreatedAt: creationTime,
// 		UpdatedAt: creationTime,
// 		Status:    mgclients.EnabledStatus,
// 	}

	authCall = auth.On("Authorize", mock.Anything, mock.Anything).Return(&magistrala.AuthorizeRes{Authorized: true}, nil)
	repoCall = grepo.On("ChangeStatus", mock.Anything, mock.Anything).Return(ch, nil)
	repoCall1 = grepo.On("RetrieveByID", mock.Anything, mock.Anything).Return(ch, nil)
	res, err := mgsdk.DisableChannel(channel.ID, validToken)
	assert.Nil(t, err, fmt.Sprintf("Disable channel with correct id: expected %v got %v", nil, err))
	assert.Equal(t, channel, res, fmt.Sprintf("Disable channel with correct id: expected %v got %v", channel, res))
	ok = repoCall.Parent.AssertCalled(t, "RetrieveByID", mock.Anything, channel.ID)
	assert.True(t, ok, "RetrieveByID was not called on disabling channel with correct id")
	ok = repoCall1.Parent.AssertCalled(t, "ChangeStatus", mock.Anything, mock.Anything)
	assert.True(t, ok, "ChangeStatus was not called on disabling channel with correct id")
	authCall.Unset()
	repoCall.Unset()
	repoCall1.Unset()
}

// func TestDeleteChannel(t *testing.T) {
// 	ts, grepo, auth := setupChannels()
// 	defer ts.Close()

// 	conf := sdk.Config{
// 		ThingsURL: ts.URL,
// 	}
// 	mgsdk := sdk.NewSDK(conf)

// 	creationTime := time.Now().UTC()
// 	channel := sdk.Channel{
// 		ID:        generateUUID(t),
// 		Name:      gName,
// 		CreatedAt: creationTime,
// 		UpdatedAt: creationTime,
// 		Status:    mgclients.Enabled,
// 	}

	authCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: validToken}).Return(&magistrala.IdentityRes{Id: validID, DomainId: testsutil.GenerateUUID(t)}, nil)
	authCall1 := auth.On("Authorize", mock.Anything, mock.Anything).Return(&magistrala.AuthorizeRes{Authorized: false}, nil)
	repoCall := grepo.On("Delete", mock.Anything, mock.Anything).Return(nil)
	err := mgsdk.DeleteChannel("wrongID", validToken)
	assert.Equal(t, err, errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden), fmt.Sprintf("Delete channel with wrong id: expected %v got %v", svcerr.ErrNotFound, err))
	authCall.Unset()
	authCall1.Unset()
	repoCall.Unset()

	authCall = auth.On("DeleteEntityPolicies", mock.Anything, mock.Anything, mock.Anything).Return(&magistrala.DeletePolicyRes{Deleted: true}, nil)
	authCall1 = auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: validToken}).Return(&magistrala.IdentityRes{Id: validID, DomainId: testsutil.GenerateUUID(t)}, nil)
	authCall2 := auth.On("Authorize", mock.Anything, mock.Anything).Return(&magistrala.AuthorizeRes{Authorized: true}, nil)
	repoCall = grepo.On("Delete", mock.Anything, mock.Anything).Return(nil)
	err = mgsdk.DeleteChannel(channel.ID, validToken)
	assert.Nil(t, err, fmt.Sprintf("Delete channel with correct id: expected %v got %v", nil, err))
	ok := repoCall.Parent.AssertCalled(t, "Delete", mock.Anything, channel.ID)
	assert.True(t, ok, "Delete was not called on deleting channel with correct id")
	authCall.Unset()
	authCall1.Unset()
	authCall2.Unset()
	repoCall.Unset()
}

func TestListGroupChannels(t *testing.T) {
	ts, gsvc := setupChannels()
	defer ts.Close()

	conf := sdk.Config{
		ThingsURL: ts.URL,
	}
	mgsdk := sdk.NewSDK(conf)

	groupChannel := sdk.Group{
		ID:       testsutil.GenerateUUID(t),
		Name:     "group_channel",
		Metadata: sdk.Metadata{"role": "group"},
		Status:   mgclients.EnabledStatus.String(),
	}

	cases := []struct {
		desc     string
		token    string
		groupID  string
		pageMeta sdk.PageMetadata
		svcReq   groups.Page
		svcRes   groups.Page
		svcErr   error
		response sdk.GroupsPage
		err      errors.SDKError
	}{
		{
			desc:    "list group channels successfully",
			token:   validToken,
			groupID: group.ID,
			pageMeta: sdk.PageMetadata{
				Offset: 0,
				Limit:  10,
			},
			svcReq: groups.Page{
				PageMeta: groups.PageMeta{
					Offset: 0,
					Limit:  10,
				},
				Permission: "view",
				Direction:  -1,
			},
			svcRes: groups.Page{
				PageMeta: groups.PageMeta{
					Total: 1,
				},
				Groups: []groups.Group{convertGroup(groupChannel)},
			},
			svcErr: nil,
			response: sdk.GroupsPage{
				PageRes: sdk.PageRes{
					Total: 1,
				},
				Groups: []sdk.Group{groupChannel},
			},
			err: nil,
		},
		{
			desc:    "list group channels with invalid token",
			token:   invalidToken,
			groupID: group.ID,
			pageMeta: sdk.PageMetadata{
				Offset: 0,
				Limit:  10,
			},
			svcReq: groups.Page{
				PageMeta: groups.PageMeta{
					Offset: 0,
					Limit:  10,
				},
				Permission: "view",
				Direction:  -1,
			},
			svcRes:   groups.Page{},
			svcErr:   svcerr.ErrAuthentication,
			response: sdk.GroupsPage{},
			err:      errors.NewSDKErrorWithStatus(svcerr.ErrAuthentication, http.StatusUnauthorized),
		},
		{
			desc:    "list group channels with empty token",
			token:   "",
			groupID: group.ID,
			pageMeta: sdk.PageMetadata{
				Offset: 0,
				Limit:  10,
			},
			svcReq:   groups.Page{},
			svcRes:   groups.Page{},
			svcErr:   nil,
			response: sdk.GroupsPage{},
			err:      errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrBearerToken), http.StatusUnauthorized),
		},
		{
			desc:    "list group channels with invalid group id",
			token:   validToken,
			groupID: wrongID,
			pageMeta: sdk.PageMetadata{
				Offset: 0,
				Limit:  10,
			},
			svcReq: groups.Page{
				PageMeta: groups.PageMeta{
					Offset: 0,
					Limit:  10,
				},
				Permission: "view",
				Direction:  -1,
			},
			svcRes:   groups.Page{},
			svcErr:   svcerr.ErrAuthorization,
			response: sdk.GroupsPage{},
			err:      errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
		},
		{
			desc:    "list group channels with invalid page metadata",
			token:   validToken,
			groupID: group.ID,
			pageMeta: sdk.PageMetadata{
				Offset: 0,
				Limit:  10,
				Metadata: sdk.Metadata{
					"test": make(chan int),
				},
			},
			svcReq:   groups.Page{},
			svcRes:   groups.Page{},
			svcErr:   nil,
			response: sdk.GroupsPage{},
			err:      errors.NewSDKError(errors.New("json: unsupported type: chan int")),
		},
		{
			desc:    "list group channels with service response that can't be unmarshalled",
			token:   validToken,
			groupID: group.ID,
			pageMeta: sdk.PageMetadata{
				Offset: 0,
				Limit:  10,
			},
			svcReq: groups.Page{
				PageMeta: groups.PageMeta{
					Offset: 0,
					Limit:  10,
				},
				Permission: "view",
				Direction:  -1,
			},
			svcRes: groups.Page{
				PageMeta: groups.PageMeta{
					Total: 1,
				},
				Groups: []groups.Group{
					{
						ID:       generateUUID(t),
						Metadata: mgclients.Metadata{"test": make(chan int)},
					},
				},
			},
			svcErr:   nil,
			response: sdk.GroupsPage{},
			err:      errors.NewSDKError(errors.New("unexpected end of JSON input")),
		},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svcCall := gsvc.On("ListGroups", mock.Anything, tc.token, auth.GroupsKind, tc.groupID, tc.svcReq).Return(tc.svcRes, tc.svcErr)
			resp, err := mgsdk.ListGroupChannels(tc.groupID, tc.pageMeta, tc.token)
			assert.Equal(t, tc.err, err)
			assert.Equal(t, tc.response, resp)
			if tc.err == nil {
				ok := svcCall.Parent.AssertCalled(t, "ListGroups", mock.Anything, tc.token, auth.GroupsKind, tc.groupID, tc.svcReq)
				assert.True(t, ok)
			}
			svcCall.Unset()
		})
	}
}

func toIDs(objects interface{}) []string {
	v := reflect.ValueOf(objects)
	if v.Kind() != reflect.Slice {
		panic("objects argument must be a slice")
	}
	ids := make([]string, v.Len())
	for i := 0; i < v.Len(); i++ {
		id := v.Index(i).FieldByName("ID").String()
		ids[i] = id
	}

	return ids
}

func generateTestChannel(t *testing.T) sdk.Channel {
	createdAt, err := time.Parse(time.RFC3339, "2023-03-03T00:00:00Z")
	assert.Nil(t, err, fmt.Sprintf("unexpected error %s", err))
	updatedAt := createdAt
	ch := sdk.Channel{
		ID:          testsutil.GenerateUUID(&testing.T{}),
		DomainID:    testsutil.GenerateUUID(&testing.T{}),
		Name:        channelName,
		Description: description,
		Metadata:    sdk.Metadata{"role": "client"},
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
		Status:      mgclients.EnabledStatus.String(),
	}
	return ch
}
