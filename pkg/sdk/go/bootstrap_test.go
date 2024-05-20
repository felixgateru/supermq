// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package sdk_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/absmach/magistrala/bootstrap"
	"github.com/absmach/magistrala/bootstrap/api"
	bmocks "github.com/absmach/magistrala/bootstrap/mocks"
	"github.com/absmach/magistrala/internal/apiutil"
	"github.com/absmach/magistrala/internal/testsutil"
	mglog "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/errors"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	sdk "github.com/absmach/magistrala/pkg/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var (
	externalId      = testsutil.GenerateUUID(&testing.T{})
	externalKey     = testsutil.GenerateUUID(&testing.T{})
	thingId         = testsutil.GenerateUUID(&testing.T{})
	thingKey        = testsutil.GenerateUUID(&testing.T{})
	channel1Id      = testsutil.GenerateUUID(&testing.T{})
	channel2Id      = testsutil.GenerateUUID(&testing.T{})
	clientCert      = "newcert"
	clientKey       = "newkey"
	caCert          = "newca"
	content         = "newcontent"
	state           = 1
	bsName          = "test"
	encKey          = []byte("1234567891011121")
	invalid         = "invalid"
	bootstrapConfig = bootstrap.Config{
		ThingID:    thingId,
		Name:       "test",
		ClientCert: clientCert,
		ClientKey:  clientKey,
		CACert:     caCert,
		Channels: []bootstrap.Channel{
			{
				ID: channel1Id,
			},
			{
				ID: channel2Id,
			},
		},
		ExternalID:  externalId,
		ExternalKey: externalKey,
		Content:     content,
		State:       bootstrap.Inactive,
	}
	sdkBootstrapConfig = sdk.BootstrapConfig{
		Channels:    []string{channel1Id, channel2Id},
		ExternalID:  externalId,
		ExternalKey: externalKey,
		ThingID:     thingId,
		ThingKey:    thingKey,
		Name:        bsName,
		ClientCert:  clientCert,
		ClientKey:   clientKey,
		CACert:      caCert,
		Content:     content,
		State:       state,
	}
	sdkBootsrapConfigRes = sdk.BootstrapConfig{
		ThingID:  thingId,
		ThingKey: thingKey,
		Channels: []sdk.Channel{
			{
				ID: channel1Id,
			},
			{
				ID: channel2Id,
			},
		},
		ClientCert: clientCert,
		ClientKey:  clientKey,
		CACert:     caCert,
	}
	readConfigResponse = struct {
		ThingID    string             `json:"thing_id"`
		ThingKey   string             `json:"thing_key"`
		Channels   []readerChannelRes `json:"channels"`
		Content    string             `json:"content,omitempty"`
		ClientCert string             `json:"client_cert,omitempty"`
		ClientKey  string             `json:"client_key,omitempty"`
		CACert     string             `json:"ca_cert,omitempty"`
	}{
		ThingID:  thingId,
		ThingKey: thingKey,
		Channels: []readerChannelRes{
			{
				ID: channel1Id,
			},
			{
				ID: channel2Id,
			},
		},
		ClientCert: clientCert,
		ClientKey:  clientKey,
		CACert:     caCert,
	}
)

var (
	errMarshalChan = errors.New("json: unsupported type: chan int")
	errJsonEOF     = errors.New("unexpected end of JSON input")
)

func setupBootstrap() (*httptest.Server, *bmocks.Service, *bmocks.ConfigReader) {
	bsvc := new(bmocks.Service)
	reader := new(bmocks.ConfigReader)
	logger := mglog.NewMock()

	mux := api.MakeHandler(bsvc, reader, logger, "")
	return httptest.NewServer(mux), bsvc, reader
}

func TestAddBootstrap(t *testing.T) {
	bs, bsvc, _ := setupBootstrap()
	defer bs.Close()

	conf := sdk.Config{
		BootstrapURL: bs.URL,
	}
	mgsdk := sdk.NewSDK(conf)

	neID := sdkBootstrapConfig
	neID.ThingID = "non-existent"

	neReqId := bootstrapConfig
	neReqId.ThingID = "non-existent"

	cases := []struct {
		desc   string
		token  string
		cfg    sdk.BootstrapConfig
		svcReq bootstrap.Config
		svcRes bootstrap.Config
		svcErr error
		err    errors.SDKError
	}{
		{
			desc:   "add successfully",
			token:  validToken,
			cfg:    sdkBootstrapConfig,
			svcReq: bootstrapConfig,
			svcRes: bootstrapConfig,
			svcErr: nil,
			err:    nil,
		},
		{
			desc:   "add with invalid token",
			token:  invalidToken,
			cfg:    sdkBootstrapConfig,
			svcReq: bootstrapConfig,
			svcRes: bootstrap.Config{},
			svcErr: svcerr.ErrAuthentication,
			err:    errors.NewSDKErrorWithStatus(svcerr.ErrAuthentication, http.StatusUnauthorized),
		},
		{
			desc:  "add with config that cannot be marshalled",
			token: validToken,
			cfg: sdk.BootstrapConfig{
				Channels: map[string]interface{}{
					"channel1": make(chan int),
				},
				ExternalID:  externalId,
				ExternalKey: externalKey,
				ThingID:     thingId,
				ThingKey:    thingKey,
				Name:        bsName,
				ClientCert:  clientCert,
				ClientKey:   clientKey,
				CACert:      caCert,
				Content:     content,
			},
			svcReq: bootstrap.Config{},
			svcRes: bootstrap.Config{},
			svcErr: nil,
			err:    errors.NewSDKError(errMarshalChan),
		},
		{
			desc:   "add an existing config",
			token:  validToken,
			cfg:    sdkBootstrapConfig,
			svcReq: bootstrapConfig,
			svcRes: bootstrap.Config{},
			svcErr: svcerr.ErrConflict,
			err:    errors.NewSDKErrorWithStatus(svcerr.ErrConflict, http.StatusConflict),
		},
		{
			desc:   "add empty config",
			token:  validToken,
			cfg:    sdk.BootstrapConfig{},
			svcReq: bootstrap.Config{},
			svcRes: bootstrap.Config{},
			svcErr: nil,
			err:    errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrMissingID), http.StatusBadRequest),
		},
		{
			desc:   "add with non-existent thing Id",
			token:  validToken,
			cfg:    neID,
			svcReq: neReqId,
			svcRes: bootstrap.Config{},
			svcErr: svcerr.ErrNotFound,
			err:    errors.NewSDKErrorWithStatus(svcerr.ErrNotFound, http.StatusNotFound),
		},
	}

	for _, tc := range cases {
		svcCall := bsvc.On("Add", mock.Anything, tc.token, tc.svcReq).Return(tc.svcRes, tc.svcErr)
		bsId, err := mgsdk.AddBootstrap(tc.cfg, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if err == nil {
			assert.Equal(t, bootstrapConfig.ThingID, bsId, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, bootstrapConfig.ThingID, bsId))
		}
		svcCall.Unset()
	}
}

func TestListBootstraps(t *testing.T) {
	bs, bsvc, _ := setupBootstrap()
	defer bs.Close()

	conf := sdk.Config{
		BootstrapURL: bs.URL,
	}
	mgsdk := sdk.NewSDK(conf)

	configRes := sdk.BootstrapConfig{
		Channels: []sdk.Channel{
			{
				ID: channel1Id,
			},
			{
				ID: channel2Id,
			},
		},
		ThingID:     thingId,
		Name:        bsName,
		ExternalID:  externalId,
		ExternalKey: externalKey,
		Content:     content,
	}
	unmarshalableConfig := bootstrapConfig
	unmarshalableConfig.Channels = []bootstrap.Channel{
		{
			ID: channel1Id,
			Metadata: map[string]interface{}{
				"test": make(chan int),
			},
		},
	}

	cases := []struct {
		desc        string
		token       string
		pageMeta    sdk.PageMetadata
		svcResponse bootstrap.ConfigsPage
		svcErr      error
		page        sdk.BootstrapPage
		err         errors.SDKError
	}{
		{
			desc:  "list successfully",
			token: validToken,
			pageMeta: sdk.PageMetadata{
				Offset: 0,
				Limit:  10,
			},
			svcResponse: bootstrap.ConfigsPage{
				Total:   1,
				Offset:  0,
				Configs: []bootstrap.Config{bootstrapConfig},
			},
			page: sdk.BootstrapPage{
				Configs: []sdk.BootstrapConfig{configRes},
			},
			err: nil,
		},
		{
			desc:  "list with invalid token",
			token: invalidToken,
			pageMeta: sdk.PageMetadata{
				Offset: 0,
				Limit:  10,
			},
			svcResponse: bootstrap.ConfigsPage{},
			page:        sdk.BootstrapPage{},
			svcErr:      svcerr.ErrAuthentication,
			err:         errors.NewSDKErrorWithStatus(svcerr.ErrAuthentication, http.StatusUnauthorized),
		},
		{
			desc:  "list with empty token",
			token: "",
			pageMeta: sdk.PageMetadata{
				Offset: 0,
				Limit:  10,
			},
			svcResponse: bootstrap.ConfigsPage{},
			page:        sdk.BootstrapPage{},
			svcErr:      nil,
			err:         errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrBearerToken), http.StatusUnauthorized),
		},
		{
			desc:  "list with invalid query params",
			token: validToken,
			pageMeta: sdk.PageMetadata{
				Offset: 1,
				Limit:  10,
				Metadata: map[string]interface{}{
					"test": make(chan int),
				},
			},
			svcResponse: bootstrap.ConfigsPage{},
			page:        sdk.BootstrapPage{},
			svcErr:      nil,
			err:         errors.NewSDKError(errMarshalChan),
		},
		{
			desc:  "list with response that cannot be unmarshalled",
			token: validToken,
			pageMeta: sdk.PageMetadata{
				Offset: 0,
				Limit:  10,
			},
			svcResponse: bootstrap.ConfigsPage{
				Total:   1,
				Offset:  0,
				Configs: []bootstrap.Config{unmarshalableConfig},
			},
			svcErr: nil,
			page:   sdk.BootstrapPage{},
			err:    errors.NewSDKError(errJsonEOF),
		},
	}
	for _, tc := range cases {
		svcCall := bsvc.On("List", mock.Anything, tc.token, mock.Anything, tc.pageMeta.Offset, tc.pageMeta.Limit).Return(tc.svcResponse, tc.svcErr)
		res, err := mgsdk.Bootstraps(tc.pageMeta, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if err == nil {
			assert.Equal(t, tc.page.Configs, res.Configs, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.page, res))
		}
		svcCall.Unset()
	}
}

func TestWhiteList(t *testing.T) {
	bs, bsvc, _ := setupBootstrap()
	defer bs.Close()

	conf := sdk.Config{
		BootstrapURL: bs.URL,
	}
	mgsdk := sdk.NewSDK(conf)

	cases := []struct {
		desc       string
		token      string
		cfg        sdk.BootstrapConfig
		svcRequest string
		svcErr     error
		err        errors.SDKError
	}{
		{
			desc:       "whitelist successfully",
			token:      validToken,
			cfg:        sdkBootstrapConfig,
			svcRequest: bootstrapConfig.ThingID,
			svcErr:     nil,
			err:        nil,
		},
		{
			desc:       "whitelist with invalid token",
			token:      invalidToken,
			cfg:        sdkBootstrapConfig,
			svcRequest: bootstrapConfig.ThingID,
			svcErr:     svcerr.ErrAuthentication,
			err:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthentication, http.StatusUnauthorized),
		},
		{
			desc:       "whitelist with empty token",
			token:      "",
			cfg:        sdkBootstrapConfig,
			svcRequest: bootstrapConfig.ThingID,
			svcErr:     nil,
			err:        errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrBearerToken), http.StatusUnauthorized),
		},
		{
			desc:  "whitelist with invalid state",
			token: validToken,
			cfg: sdk.BootstrapConfig{
				ThingID: thingId,
				State:   -1,
			},
			svcRequest: bootstrapConfig.ThingID,
			svcErr:     nil,
			err:        errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrBootstrapState), http.StatusBadRequest),
		},
		{
			desc:  "whitelist with empty thing Id",
			token: validToken,
			cfg: sdk.BootstrapConfig{
				ThingID: "",
				State:   0,
			},
			svcRequest: "",
			svcErr:     nil,
			err:        errors.NewSDKError(apiutil.ErrNotFoundParam),
		},
	}
	for _, tc := range cases {
		svcCall := bsvc.On("ChangeState", mock.Anything, tc.token, tc.svcRequest, bootstrap.Active).Return(tc.svcErr)
		err := mgsdk.Whitelist(tc.cfg, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		svcCall.Unset()
	}
}

func TestViewBootstrap(t *testing.T) {
	bs, bsvc, _ := setupBootstrap()
	defer bs.Close()

	conf := sdk.Config{
		BootstrapURL: bs.URL,
	}
	mgsdk := sdk.NewSDK(conf)

	viewBoostrapRes := sdk.BootstrapConfig{
		ThingID:     thingId,
		Channels:    sdkBootsrapConfigRes.Channels,
		ExternalID:  externalId,
		ExternalKey: externalKey,
		Name:        bsName,
		Content:     content,
		State:       0,
	}

	cases := []struct {
		desc        string
		token       string
		id          string
		svcResponse bootstrap.Config
		svcErr      error
		cfgResponse sdk.BootstrapConfig
		err         errors.SDKError
	}{
		{
			desc:        "view successfully",
			token:       validToken,
			id:          thingId,
			svcResponse: bootstrapConfig,
			svcErr:      nil,
			cfgResponse: viewBoostrapRes,
			err:         nil,
		},
		{
			desc:        "view with invalid token",
			token:       invalidToken,
			id:          thingId,
			svcResponse: bootstrap.Config{},
			svcErr:      svcerr.ErrAuthentication,
			err:         errors.NewSDKErrorWithStatus(svcerr.ErrAuthentication, http.StatusUnauthorized),
		},
		{
			desc:        "view with empty token",
			token:       "",
			id:          thingId,
			svcResponse: bootstrap.Config{},
			svcErr:      nil,
			err:         errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrBearerToken), http.StatusUnauthorized),
		},
		{
			desc:        "view with non-existent thing Id",
			token:       validToken,
			id:          invalid,
			svcResponse: bootstrap.Config{},
			svcErr:      svcerr.ErrNotFound,
			err:         errors.NewSDKErrorWithStatus(svcerr.ErrNotFound, http.StatusNotFound),
		},
		{
			desc:  "view with response that cannot be unmarshalled",
			token: validToken,
			id:    thingId,
			svcResponse: bootstrap.Config{
				ThingID: thingId,
				Channels: []bootstrap.Channel{
					{
						ID: channel1Id,
						Metadata: map[string]interface{}{
							"test": make(chan int),
						},
					},
				},
			},
			svcErr: nil,
			err:    errors.NewSDKError(errJsonEOF),
		},
	}
	for _, tc := range cases {
		svcCall := bsvc.On("View", mock.Anything, tc.token, tc.id).Return(tc.svcResponse, tc.svcErr)
		res, err := mgsdk.ViewBootstrap(tc.id, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if err == nil {
			assert.Equal(t, tc.cfgResponse, res, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.cfgResponse, res))
		}
		svcCall.Unset()
	}
}

func TestUpdateBootstrap(t *testing.T) {
	bs, bsvc, _ := setupBootstrap()
	defer bs.Close()

	conf := sdk.Config{
		BootstrapURL: bs.URL,
	}
	mgsdk := sdk.NewSDK(conf)

	cases := []struct {
		desc       string
		token      string
		cfg        sdk.BootstrapConfig
		svcRequest bootstrap.Config
		svcErr     error
		err        errors.SDKError
	}{
		{
			desc:  "update successfully",
			token: validToken,
			cfg:   sdkBootstrapConfig,
			svcRequest: bootstrap.Config{
				ThingID: thingId,
				Name:    bsName,
				Content: content,
			},
			svcErr: nil,
			err:    nil,
		},
		{
			desc:  "update with invalid token",
			token: invalidToken,
			cfg:   sdkBootstrapConfig,
			svcRequest: bootstrap.Config{
				ThingID: thingId,
				Name:    bsName,
				Content: content,
			},
			svcErr: svcerr.ErrAuthentication,
			err:    errors.NewSDKErrorWithStatus(svcerr.ErrAuthentication, http.StatusUnauthorized),
		},
		{
			desc:       "update with empty token",
			token:      "",
			cfg:        sdkBootstrapConfig,
			svcRequest: bootstrap.Config{},
			svcErr:     nil,
			err:        errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrBearerToken), http.StatusUnauthorized),
		},
		{
			desc:  "update with config that cannot be marshalled",
			token: validToken,
			cfg: sdk.BootstrapConfig{
				Channels: map[string]interface{}{
					"channel1": make(chan int),
				},
				ExternalID:  externalId,
				ExternalKey: externalKey,
				ThingID:     thingId,
				ThingKey:    thingKey,
				Name:        bsName,
				ClientCert:  clientCert,
				ClientKey:   clientKey,
				CACert:      caCert,
				Content:     content,
			},
			svcRequest: bootstrap.Config{
				ThingID: thingId,
				Name:    bsName,
				Content: content,
			},
			svcErr: nil,
			err:    errors.NewSDKError(errMarshalChan),
		},
		{
			desc:  "update with non-existent thing Id",
			token: validToken,
			cfg: sdk.BootstrapConfig{
				ThingID: invalid,
				Channels: []sdk.Channel{
					{
						ID: channel1Id,
					},
				},
				ExternalID:  externalId,
				ExternalKey: externalKey,
				Content:     content,
				Name:        bsName,
			},
			svcRequest: bootstrap.Config{
				ThingID: invalid,
				Name:    bsName,
				Content: content,
			},
			svcErr: svcerr.ErrNotFound,
			err:    errors.NewSDKErrorWithStatus(svcerr.ErrNotFound, http.StatusNotFound),
		},
		{
			desc:  "update with empty thing Id",
			token: validToken,
			cfg: sdk.BootstrapConfig{
				ThingID: "",
				Channels: []sdk.Channel{
					{
						ID: channel1Id,
					},
				},
				ExternalID:  externalId,
				ExternalKey: externalKey,
				Content:     content,
				Name:        bsName,
			},
			svcRequest: bootstrap.Config{
				ThingID: "",
				Name:    bsName,
				Content: content,
			},
			svcErr: nil,
			err:    errors.NewSDKErrorWithStatus(errors.New("unexpected end of JSON input"), http.StatusMethodNotAllowed),
		},
	}

	for _, tc := range cases {
		svcCall := bsvc.On("Update", mock.Anything, tc.token, tc.svcRequest).Return(tc.svcErr)
		err := mgsdk.UpdateBootstrap(tc.cfg, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		svcCall.Unset()
	}
}

func TestUpdateBootstrapCerts(t *testing.T) {
	bs, bsvc, _ := setupBootstrap()
	defer bs.Close()

	conf := sdk.Config{
		BootstrapURL: bs.URL,
	}
	mgsdk := sdk.NewSDK(conf)

	updateconfigRes := sdk.BootstrapConfig{
		ThingID:    thingId,
		ClientCert: clientCert,
		CACert:     caCert,
		ClientKey:  clientKey,
	}

	cases := []struct {
		desc        string
		token       string
		id          string
		clientCert  string
		clientKey   string
		caCert      string
		svcResponse bootstrap.Config
		svcErr      error
		response    sdk.BootstrapConfig
		err         errors.SDKError
	}{
		{
			desc:        "update certs successfully",
			token:       validToken,
			id:          thingId,
			clientCert:  clientCert,
			clientKey:   clientKey,
			caCert:      caCert,
			svcResponse: bootstrapConfig,
			svcErr:      nil,
			response:    updateconfigRes,
			err:         nil,
		},
		{
			desc:        "update certs with invalid token",
			token:       validToken,
			id:          thingId,
			clientCert:  clientCert,
			clientKey:   clientKey,
			caCert:      caCert,
			svcResponse: bootstrap.Config{},
			svcErr:      svcerr.ErrAuthentication,
			err:         errors.NewSDKErrorWithStatus(svcerr.ErrAuthentication, http.StatusUnauthorized),
		},
		{
			desc:        "update certs with empty token",
			token:       "",
			id:          thingId,
			clientCert:  clientCert,
			clientKey:   clientKey,
			caCert:      caCert,
			svcResponse: bootstrap.Config{},
			svcErr:      nil,
			err:         errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrBearerToken), http.StatusUnauthorized),
		},
		{
			desc:        "update certs with non-existent thing Id",
			token:       validToken,
			id:          invalid,
			clientCert:  clientCert,
			clientKey:   clientKey,
			caCert:      caCert,
			svcResponse: bootstrap.Config{},
			svcErr:      svcerr.ErrNotFound,
			err:         errors.NewSDKErrorWithStatus(svcerr.ErrNotFound, http.StatusNotFound),
		},
	}
	for _, tc := range cases {
		svcCall := bsvc.On("UpdateCert", mock.Anything, tc.token, tc.id, tc.clientCert, tc.clientKey, tc.caCert).Return(tc.svcResponse, tc.svcErr)
		res, err := mgsdk.UpdateBootstrapCerts(tc.id, tc.clientCert, tc.clientKey, tc.caCert, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if err == nil {
			assert.Equal(t, tc.response, res, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, res))
		}
		svcCall.Unset()
	}
}

func TestUpdateBootstrapConnection(t *testing.T) {
	bs, bsvc, _ := setupBootstrap()
	defer bs.Close()

	conf := sdk.Config{
		BootstrapURL: bs.URL,
	}
	mgsdk := sdk.NewSDK(conf)

	cases := []struct {
		desc     string
		token    string
		id       string
		channels []string
		svcRes   bootstrap.Config
		svcErr   error
		err      errors.SDKError
	}{
		{
			desc:     "update connection successfully",
			token:    validToken,
			id:       thingId,
			channels: []string{channel1Id, channel2Id},
			svcErr:   nil,
			err:      nil,
		},
		{
			desc:     "update connection with invalid token",
			token:    invalidToken,
			id:       thingId,
			channels: []string{channel1Id, channel2Id},
			svcErr:   svcerr.ErrAuthentication,
			err:      errors.NewSDKErrorWithStatus(svcerr.ErrAuthentication, http.StatusUnauthorized),
		},
		{
			desc:     "update connection with empty token",
			token:    "",
			id:       thingId,
			channels: []string{channel1Id, channel2Id},
			svcErr:   nil,
			err:      errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrBearerToken), http.StatusUnauthorized),
		},
		{
			desc:     "update connection with non-existent thing Id",
			token:    validToken,
			id:       invalid,
			channels: []string{channel1Id, channel2Id},
			svcErr:   svcerr.ErrNotFound,
			err:      errors.NewSDKErrorWithStatus(svcerr.ErrNotFound, http.StatusNotFound),
		},
		{
			desc:     "update connection with non-existent channel Id",
			token:    validToken,
			id:       thingId,
			channels: []string{invalid},
			svcErr:   svcerr.ErrNotFound,
			err:      errors.NewSDKErrorWithStatus(svcerr.ErrNotFound, http.StatusNotFound),
		},
	}
	for _, tc := range cases {
		svcCall := bsvc.On("UpdateConnections", mock.Anything, tc.token, tc.id, tc.channels).Return(tc.svcErr)
		err := mgsdk.UpdateBootstrapConnection(tc.id, tc.channels, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		svcCall.Unset()
	}
}

func TestRemoveBootstrap(t *testing.T) {
	bs, bsvc, _ := setupBootstrap()
	defer bs.Close()

	conf := sdk.Config{
		BootstrapURL: bs.URL,
	}
	mgsdk := sdk.NewSDK(conf)

	cases := []struct {
		desc   string
		token  string
		id     string
		svcErr error
		err    errors.SDKError
	}{
		{
			desc:   "remove successfully",
			token:  validToken,
			id:     thingId,
			svcErr: nil,
			err:    nil,
		},
		{
			desc:   "remove with invalid token",
			token:  invalidToken,
			id:     thingId,
			svcErr: svcerr.ErrAuthentication,
			err:    errors.NewSDKErrorWithStatus(svcerr.ErrAuthentication, http.StatusUnauthorized),
		},
		{
			desc:   "remove with non-existent thing Id",
			token:  validToken,
			id:     invalid,
			svcErr: svcerr.ErrNotFound,
			err:    errors.NewSDKErrorWithStatus(svcerr.ErrNotFound, http.StatusNotFound),
		},
		{
			desc:   "remove removed bootstrap",
			token:  validToken,
			id:     thingId,
			svcErr: svcerr.ErrNotFound,
			err:    errors.NewSDKErrorWithStatus(svcerr.ErrNotFound, http.StatusNotFound),
		},
		{
			desc:   "remove with empty token",
			token:  "",
			id:     thingId,
			svcErr: nil,
			err:    errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrBearerToken), http.StatusUnauthorized),
		},
	}
	for _, tc := range cases {
		svcCall := bsvc.On("Remove", mock.Anything, tc.token, tc.id).Return(tc.svcErr)
		err := mgsdk.RemoveBootstrap(tc.id, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		svcCall.Unset()
	}
}

func TestBoostrap(t *testing.T) {
	bs, bsvc, reader := setupBootstrap()
	defer bs.Close()

	conf := sdk.Config{
		BootstrapURL: bs.URL,
	}
	mgsdk := sdk.NewSDK(conf)

	cases := []struct {
		desc           string
		token          string
		externalID     string
		externalKey    string
		svcResponse    bootstrap.Config
		svcErr         error
		readerResponse interface{}
		readerErr      error
		response       sdk.BootstrapConfig
		err            errors.SDKError
	}{
		{
			desc:           "bootstrap successfully",
			token:          validToken,
			externalID:     externalId,
			externalKey:    externalKey,
			svcResponse:    bootstrapConfig,
			svcErr:         nil,
			readerResponse: readConfigResponse,
			readerErr:      nil,
			response:       sdkBootsrapConfigRes,
			err:            nil,
		},
		{
			desc:           "bootstrap with invalid token",
			token:          invalidToken,
			externalID:     externalId,
			externalKey:    externalKey,
			svcResponse:    bootstrap.Config{},
			svcErr:         svcerr.ErrAuthentication,
			readerResponse: bootstrap.Config{},
			readerErr:      nil,
			err:            errors.NewSDKErrorWithStatus(svcerr.ErrAuthentication, http.StatusUnauthorized),
		},
		{
			desc:           "bootstrap with error in reader",
			token:          validToken,
			externalID:     externalId,
			externalKey:    externalKey,
			svcResponse:    bootstrapConfig,
			svcErr:         nil,
			readerResponse: []byte{0},
			readerErr:      errJsonEOF,
			err:            errors.NewSDKErrorWithStatus(errJsonEOF, http.StatusInternalServerError),
		},
		{
			desc:           "boostrap with response that cannot be unmarshalled",
			token:          validToken,
			externalID:     externalId,
			externalKey:    externalKey,
			svcResponse:    bootstrapConfig,
			svcErr:         nil,
			readerResponse: []byte{0},
			readerErr:      nil,
			err:            errors.NewSDKError(errors.New("json: cannot unmarshal string into Go value of type map[string]json.RawMessage")),
		},
		{
			desc:           "bootstrap with empty id",
			token:          validToken,
			externalID:     "",
			externalKey:    externalKey,
			svcResponse:    bootstrap.Config{},
			svcErr:         nil,
			readerResponse: bootstrap.Config{},
			readerErr:      nil,
			err:            errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrMissingID), http.StatusBadRequest),
		},
		{
			desc:           "boostrap with empty key",
			token:          validToken,
			externalID:     externalId,
			externalKey:    "",
			svcResponse:    bootstrap.Config{},
			svcErr:         nil,
			readerResponse: bootstrap.Config{},
			readerErr:      nil,
			err:            errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrBearerKey), http.StatusBadRequest),
		},
	}
	for _, tc := range cases {
		svcCall := bsvc.On("Bootstrap", mock.Anything, tc.externalKey, tc.externalID, mock.Anything).Return(tc.svcResponse, tc.svcErr)
		readerCall := reader.On("ReadConfig", mock.Anything, mock.Anything).Return(tc.readerResponse, tc.readerErr)
		res, err := mgsdk.Bootstrap(tc.externalID, tc.externalKey)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if err == nil {
			assert.Equal(t, tc.response, res, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, res))
		}
		svcCall.Unset()
		readerCall.Unset()
	}
}

func TestBootstrapSecure(t *testing.T) {
	bs, bsvc, reader := setupBootstrap()
	defer bs.Close()

	conf := sdk.Config{
		BootstrapURL: bs.URL,
	}
	mgsdk := sdk.NewSDK(conf)

	b, err := json.Marshal(readConfigResponse)
	assert.Nil(t, err, fmt.Sprintf("Marshalling bootstrap response expected to succeed: %s.\n", err))
	encResponse, err := encrypt(b, encKey)
	assert.Nil(t, err, fmt.Sprintf("Encrypting bootstrap response expected to succeed: %s.\n", err))

	cases := []struct {
		desc           string
		token          string
		externalID     string
		externalKey    string
		cryptoKey      string
		svcResponse    bootstrap.Config
		svcErr         error
		readerResponse []byte
		readerErr      error
		response       sdk.BootstrapConfig
		err            errors.SDKError
	}{
		{
			desc:           "bootstrap successfully",
			token:          validToken,
			externalID:     externalId,
			externalKey:    externalKey,
			cryptoKey:      string(encKey),
			svcResponse:    bootstrapConfig,
			svcErr:         nil,
			readerResponse: encResponse,
			readerErr:      nil,
			response:       sdkBootsrapConfigRes,
			err:            nil,
		},
		{
			desc:           "bootstrap with invalid token",
			token:          invalidToken,
			externalID:     externalId,
			externalKey:    externalKey,
			cryptoKey:      string(encKey),
			svcResponse:    bootstrap.Config{},
			svcErr:         svcerr.ErrAuthentication,
			readerResponse: []byte{0},
			readerErr:      nil,
			err:            errors.NewSDKErrorWithStatus(svcerr.ErrAuthentication, http.StatusUnauthorized),
		},
		{
			desc:           "booostrap with invalid crypto key",
			token:          validToken,
			externalID:     externalId,
			externalKey:    externalKey,
			cryptoKey:      invalid,
			svcResponse:    bootstrap.Config{},
			svcErr:         nil,
			readerResponse: []byte{0},
			readerErr:      nil,
			err:            errors.NewSDKError(errors.New("crypto/aes: invalid key size 7")),
		},
		{
			desc:           "bootstrap with error in reader",
			token:          validToken,
			externalID:     externalId,
			externalKey:    externalKey,
			cryptoKey:      string(encKey),
			svcResponse:    bootstrapConfig,
			svcErr:         nil,
			readerResponse: []byte{0},
			readerErr:      errJsonEOF,
			err:            errors.NewSDKErrorWithStatus(errJsonEOF, http.StatusInternalServerError),
		},
		{
			desc:           "bootstrap with response that cannot be unmarshalled",
			token:          validToken,
			externalID:     externalId,
			externalKey:    externalKey,
			cryptoKey:      string(encKey),
			svcResponse:    bootstrapConfig,
			svcErr:         nil,
			readerResponse: []byte{0},
			readerErr:      nil,
			err:            errors.NewSDKError(errJsonEOF),
		},
	}
	for _, tc := range cases {
		svcCall := bsvc.On("Bootstrap", mock.Anything, mock.Anything, tc.externalID, mock.Anything).Return(tc.svcResponse, tc.svcErr)
		readerCall := reader.On("ReadConfig", mock.Anything, mock.Anything).Return(tc.readerResponse, tc.readerErr)
		res, err := mgsdk.BootstrapSecure(tc.externalID, tc.externalKey, tc.cryptoKey)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if err == nil {
			assert.Equal(t, sdkBootsrapConfigRes, res, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, sdkBootsrapConfigRes, res))
		}
		svcCall.Unset()
		readerCall.Unset()
	}
}

type readerChannelRes struct {
	ID       string      `json:"id"`
	Name     string      `json:"name,omitempty"`
	Metadata interface{} `json:"metadata,omitempty"`
}

func encrypt(in, encKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(in))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], in)
	return ciphertext, nil
}
