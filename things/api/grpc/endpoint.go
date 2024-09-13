// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"

	"github.com/absmach/magistrala/things"
	"github.com/go-kit/kit/endpoint"
)

func authorizeEndpoint(svc things.Service, authClient auth.AuthClient) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(authorizeReq)

		thingID, err := svc.Authorize(ctx, things.AuthzReq{
			ChannelID:  req.ChannelID,
			ThingID:    req.ThingID,
			ThingKey:   req.ThingKey,
			Permission: req.Permission,
		})
		if err != nil {
			return authorizeRes{}, err
		}
		r := &magistrala.AuthorizeReq{
			SubjectType: policy.GroupType,
			Subject:     req.GetObject(),
			ObjectType:  policy.ThingType,
			Object:      thingID,
			Permission:  req.GetPermission(),
		}
		resp, err := authClient.Authorize(ctx, r)
		if err != nil {
			return authorizeRes{}, errors.Wrap(svcerr.ErrAuthorization, err)
		}
		if !resp.GetAuthorized() {
			return authorizeRes{}, svcerr.ErrAuthorization
		}

		return authorizeRes{
			authorized: true,
			id:         thingID,
		}, err
	}
}
