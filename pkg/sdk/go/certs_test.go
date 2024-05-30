// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package sdk_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authmocks "github.com/absmach/magistrala/auth/mocks"
	"github.com/absmach/magistrala/certs"
	httpapi "github.com/absmach/magistrala/certs/api"
	"github.com/absmach/magistrala/certs/mocks"
	"github.com/absmach/magistrala/internal/apiutil"
	"github.com/absmach/magistrala/internal/testsutil"
	mglog "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/errors"
	repoerr "github.com/absmach/magistrala/pkg/errors/repository"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	sdk "github.com/absmach/magistrala/pkg/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const instanceID = "5de9b29a-feb9-11ed-be56-0242ac120002"

var (
	valid   = "valid"
	invalid = "invalid"
	thingID = testsutil.GenerateUUID(&testing.T{})
	serial  = testsutil.GenerateUUID(&testing.T{})
	ttl     = "10h"
	cert    = certs.Cert{
		OwnerID:        testsutil.GenerateUUID(&testing.T{}),
		ThingID:        thingID,
		ClientCert:     valid,
		IssuingCA:      valid,
		CAChain:        []string{valid},
		ClientKey:      valid,
		PrivateKeyType: valid,
		Serial:         serial,
		Expire:         time.Now().Add(time.Hour),
	}
	defOffset uint64 = 0
	defLimit  uint64 = 10
)

func setupCerts() (*httptest.Server, *mocks.Service) {
	svc := new(mocks.Service)
	logger := mglog.NewMock()
	mux := httpapi.MakeHandler(svc, logger, instanceID)

	return httptest.NewServer(mux), svc
}

func TestIssueCert(t *testing.T) {
	ts, svc := setupCerts()
	defer ts.Close()

	sdkConf := sdk.Config{
		CertsURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	mgsdk := sdk.NewSDK(sdkConf)

	cases := []struct {
		desc     string
		thingID  string
		duration string
		token    string
		svcRes   certs.Cert
		svcErr   error
		err      errors.SDKError
	}{
		{
			desc:     "create new cert with thing id and duration",
			thingID:  thingID,
			duration: ttl,
			token:    validToken,
			svcRes:   cert,
			svcErr:   nil,
			err:      nil,
		},
		{
			desc:     "create new cert with empty thing id and duration",
			thingID:  "",
			duration: ttl,
			token:    validToken,
			svcRes:   certs.Cert{},
			svcErr:   errors.Wrap(certs.ErrFailedCertCreation, apiutil.ErrMissingID),
			err:      errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrMissingID), http.StatusBadRequest),
		},
		{
			desc:     "create new cert with invalid thing id and duration",
			thingID:  invalid,
			duration: ttl,
			token:    validToken,
			svcRes:   certs.Cert{},
			svcErr:   errors.Wrap(certs.ErrFailedCertCreation, apiutil.ErrValidation),
			err:      errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, certs.ErrFailedCertCreation), http.StatusBadRequest),
		},
		{
			desc:     "create new cert with thing id and empty duration",
			thingID:  thingID,
			duration: "",
			token:    validToken,
			svcRes:   certs.Cert{},
			svcErr:   errors.Wrap(certs.ErrFailedCertCreation, apiutil.ErrMissingCertData),
			err:      errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrMissingCertData), http.StatusBadRequest),
		},
		{
			desc:     "create new cert with thing id and malformed duration",
			thingID:  thingID,
			duration: invalid,
			token:    validToken,
			svcRes:   certs.Cert{},
			svcErr:   errors.Wrap(certs.ErrFailedCertCreation, apiutil.ErrInvalidCertData),
			err:      errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrInvalidCertData), http.StatusBadRequest),
		},
		{
			desc:     "create new cert with empty token",
			thingID:  thingID,
			duration: ttl,
			token:    "",
			svcRes:   certs.Cert{},
			svcErr:   errors.Wrap(certs.ErrFailedCertCreation, svcerr.ErrAuthentication),
			err:      errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrBearerToken), http.StatusUnauthorized),
		},
		{
			desc:     "create new cert with invalid token",
			thingID:  thingID,
			duration: ttl,
			token:    authmocks.InvalidValue,
			svcRes:   certs.Cert{},
			svcErr:   errors.Wrap(certs.ErrFailedCertCreation, svcerr.ErrAuthentication),
			err:      errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, certs.ErrFailedCertCreation), http.StatusUnauthorized),
		},
		{
			desc:     "create new empty cert",
			thingID:  "",
			duration: "",
			token:    validToken,
			svcRes:   certs.Cert{},
			svcErr:   errors.Wrap(certs.ErrFailedCertCreation, certs.ErrFailedCertCreation),
			err:      errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrMissingID), http.StatusBadRequest),
		},
	}

	for _, tc := range cases {
		svcCall := svc.On("IssueCert", mock.Anything, tc.token, tc.thingID, tc.duration).Return(tc.svcRes, tc.svcErr)
		_, err := mgsdk.IssueCert(tc.thingID, tc.duration, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %s, got %s", tc.desc, tc.err, err))
		svcCall.Unset()
	}
}

func TestViewCert(t *testing.T) {
	ts, svc := setupCerts()
	defer ts.Close()

	sdkConf := sdk.Config{
		CertsURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	mgsdk := sdk.NewSDK(sdkConf)

	cases := []struct {
		desc   string
		certID string
		token  string
		svcRes certs.Cert
		svcErr error
		err    errors.SDKError
	}{
		{
			desc:   "view existing cert",
			certID: validID,
			token:  token,
			svcRes: cert,
			svcErr: nil,
			err:    nil,
		},
		{
			desc:   "view non-existent cert",
			certID: invalid,
			token:  token,
			svcRes: certs.Cert{},
			svcErr: errors.Wrap(svcerr.ErrNotFound, repoerr.ErrNotFound),
			err:    errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, svcerr.ErrNotFound), http.StatusNotFound),
		},
		{
			desc:   "view cert with invalid token",
			certID: validID,
			token:  "",
			svcRes: certs.Cert{},
			svcErr: svcerr.ErrAuthentication,
			err:    errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrBearerToken), http.StatusUnauthorized),
		},
	}

	for _, tc := range cases {
		svcCall := svc.On("ViewCert", mock.Anything, tc.token, tc.certID).Return(tc.svcRes, tc.svcErr)
		cert, err := mgsdk.ViewCert(tc.certID, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %s, got %s", tc.desc, tc.err, err))
		if err == nil {
			assert.NotEmpty(t, cert, fmt.Sprintf("%s: got empty cert", tc.desc))
		}
		svcCall.Unset()
	}
}

func TestViewCertByThing(t *testing.T) {
	ts, svc := setupCerts()
	defer ts.Close()

	sdkConf := sdk.Config{
		CertsURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	mgsdk := sdk.NewSDK(sdkConf)

	cases := []struct {
		desc    string
		thingID string
		token   string
		svcRes  certs.Page
		svcErr  error
		err     errors.SDKError
	}{
		{
			desc:    "view existing cert",
			thingID: thingID,
			token:   validToken,
			svcRes:  certs.Page{Certs: []certs.Cert{cert}},
			svcErr:  nil,
			err:     nil,
		},
		{
			desc:    "get non-existent cert",
			thingID: invalid,
			token:   validToken,
			svcRes:  certs.Page{Certs: []certs.Cert{}},
			svcErr:  errors.Wrap(svcerr.ErrNotFound, repoerr.ErrNotFound),
			err:     errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, repoerr.ErrNotFound), http.StatusNotFound),
		},
		{
			desc:    "get cert with invalid token",
			thingID: thingID,
			token:   invalidToken,
			svcRes:  certs.Page{Certs: []certs.Cert{}},
			svcErr:  svcerr.ErrAuthentication,
			err:     errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, svcerr.ErrAuthentication), http.StatusUnauthorized),
		},
	}
	for _, tc := range cases {
		svcCall := svc.On("ListSerials", mock.Anything, tc.token, tc.thingID, defOffset, defLimit).Return(tc.svcRes, tc.svcErr)
		cert, err := mgsdk.ViewCertByThing(tc.thingID, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %s, got %s", tc.desc, tc.err, err))
		if err == nil {
			assert.NotEmpty(t, cert, fmt.Sprintf("%s: got empty cert", tc.desc))
		}
		svcCall.Unset()
	}
}

func TestRevokeCert(t *testing.T) {
	ts, svc := setupCerts()
	defer ts.Close()

	sdkConf := sdk.Config{
		CertsURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	mgsdk := sdk.NewSDK(sdkConf)

	cases := []struct {
		desc    string
		thingID string
		token   string
		svcResp certs.Revoke
		svcErr  error
		err     errors.SDKError
	}{
		{
			desc:    "revoke cert successfully",
			thingID: thingID,
			token:   validToken,
			svcResp: certs.Revoke{RevocationTime: time.Now()},
			svcErr:  nil,
			err:     nil,
		},
		{
			desc:    "revoke cert with invalid token",
			thingID: thingID,
			token:   invalidToken,
			svcResp: certs.Revoke{},
			svcErr:  errors.Wrap(svcerr.ErrAuthentication, svcerr.ErrAuthentication),
			err:     errors.NewSDKErrorWithStatus(svcerr.ErrAuthentication, http.StatusUnauthorized),
		},
		{
			desc:    "revoke non-existing cert",
			thingID: invalid,
			token:   token,
			svcResp: certs.Revoke{RevocationTime: time.Now()},
			svcErr:  errors.Wrap(certs.ErrFailedCertRevocation, svcerr.ErrNotFound),
			err:     errors.NewSDKErrorWithStatus(certs.ErrFailedCertRevocation, http.StatusNotFound),
		},
		{
			desc:    "revoke cert with empty token",
			thingID: thingID,
			token:   "",
			svcResp: certs.Revoke{RevocationTime: time.Now()},
			svcErr:  nil,
			err:     errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrBearerToken), http.StatusUnauthorized),
		},
		{
			desc:    "revoke deleted cert",
			thingID: thingID,
			token:   token,
			svcResp: certs.Revoke{},
			svcErr:  errors.Wrap(certs.ErrFailedToRemoveCertFromDB, svcerr.ErrNotFound),
			err:     errors.NewSDKErrorWithStatus(certs.ErrFailedToRemoveCertFromDB, http.StatusNotFound),
		},
	}
	for _, tc := range cases {
		svcCall := svc.On("RevokeCert", mock.Anything, tc.token, tc.thingID).Return(tc.svcResp, tc.svcErr)
		response, err := mgsdk.RevokeCert(tc.thingID, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %s, got %s", tc.desc, tc.err, err))
		if err == nil {
			assert.NotEmpty(t, response, fmt.Sprintf("%s: got empty revocation time", tc.desc))
		}
		svcCall.Unset()
	}
}
