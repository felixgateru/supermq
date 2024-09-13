// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"

	"github.com/absmach/magistrala/internal/api"
	"github.com/absmach/magistrala/pkg/apiutil"
	"github.com/absmach/magistrala/pkg/authn"
	"github.com/absmach/magistrala/pkg/errors"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	"github.com/absmach/magistrala/pkg/groups"
	"github.com/absmach/magistrala/pkg/policies"
	"github.com/go-kit/kit/endpoint"
)

const groupTypeChannels = "channels"

func CreateGroupEndpoint(svc groups.Service, authClient auth.AuthClient, kind string) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(createGroupReq)
		if err := req.validate(); err != nil {
			return createGroupRes{created: false}, errors.Wrap(apiutil.ErrValidation, err)
		}

		session, ok := ctx.Value(api.SessionKey).(authn.Session)
		if !ok {
			return createGroupRes{created: false}, svcerr.ErrAuthorization
		}

		group, err := svc.CreateGroup(ctx, session, kind, req.Group)
		if err != nil {
			return createGroupRes{created: false}, err
		}

		return createGroupRes{created: true, Group: group}, nil
	}
}

func ViewGroupEndpoint(svc groups.Service, authClient auth.AuthClient) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(groupReq)
		if err := req.validate(); err != nil {
			return viewGroupRes{}, errors.Wrap(apiutil.ErrValidation, err)
		}
		if _, err := authorize(ctx, authClient, "", policies.UserType, policies.TokenKind, req.token, policies.ViewPermission, policies.GroupType, req.id); err != nil {
			return viewGroupRes{}, err
		}

		session, ok := ctx.Value(api.SessionKey).(authn.Session)
		if !ok {
			return viewGroupRes{}, svcerr.ErrAuthorization
		}
		group, err := svc.ViewGroup(ctx, session, req.id)
		if err != nil {
			return viewGroupRes{}, err
		}

		return viewGroupRes{Group: group}, nil
	}
}

func ViewGroupPermsEndpoint(svc groups.Service, authClient auth.AuthClient) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(groupPermsReq)
		if err := req.validate(); err != nil {
			return viewGroupPermsRes{}, errors.Wrap(apiutil.ErrValidation, err)
		}
		session, err := identify(ctx, authClient, req.token)
		if err != nil {
			return viewGroupPermsRes{}, err
		}

		session, ok := ctx.Value(api.SessionKey).(authn.Session)
		if !ok {
			return viewGroupPermsRes{}, svcerr.ErrAuthorization
		}

		p, err := svc.ViewGroupPerms(ctx, session, req.id)
		if err != nil {
			return viewGroupPermsRes{}, err
		}

		return viewGroupPermsRes{Permissions: p}, nil
	}
}

func UpdateGroupEndpoint(svc groups.Service, authClient auth.AuthClient) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateGroupReq)
		if err := req.validate(); err != nil {
			return updateGroupRes{}, errors.Wrap(apiutil.ErrValidation, err)
		}

		session, ok := ctx.Value(api.SessionKey).(authn.Session)
		if !ok {
			return updateGroupRes{}, svcerr.ErrAuthorization
		}

		group := groups.Group{
			ID:          req.id,
			Name:        req.Name,
			Description: req.Description,
			Metadata:    req.Metadata,
		}

		group, err := svc.UpdateGroup(ctx, session, group)
		if err != nil {
			return updateGroupRes{}, err
		}

		return updateGroupRes{Group: group}, nil
	}
}

func EnableGroupEndpoint(svc groups.Service, authClient auth.AuthClient) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(changeGroupStatusReq)
		if err := req.validate(); err != nil {
			return changeStatusRes{}, errors.Wrap(apiutil.ErrValidation, err)
		}

		session, ok := ctx.Value(api.SessionKey).(authn.Session)
		if !ok {
			return changeStatusRes{}, svcerr.ErrAuthorization
		}

		group, err := svc.EnableGroup(ctx, session, req.id)
		if err != nil {
			return changeStatusRes{}, err
		}
		return changeStatusRes{Group: group}, nil
	}
}

func DisableGroupEndpoint(svc groups.Service, authClient auth.AuthClient) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(changeGroupStatusReq)
		if err := req.validate(); err != nil {
			return changeStatusRes{}, errors.Wrap(apiutil.ErrValidation, err)
		}

		session, ok := ctx.Value(api.SessionKey).(authn.Session)
		if !ok {
			return changeStatusRes{}, svcerr.ErrAuthorization
		}

		group, err := svc.DisableGroup(ctx, session, req.id)
		if err != nil {
			return changeStatusRes{}, err
		}
		return changeStatusRes{Group: group}, nil
	}
}

func ListGroupsEndpoint(svc groups.Service, authClient auth.AuthClient, groupType, memberKind string) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listGroupsReq)
		if memberKind != "" {
			req.memberKind = memberKind
		}
		if err := req.validate(); err != nil {
			if groupType == groupTypeChannels {
				return channelPageRes{}, errors.Wrap(apiutil.ErrValidation, err)
			}
			return groupPageRes{}, errors.Wrap(apiutil.ErrValidation, err)
		}

		session, ok := ctx.Value(api.SessionKey).(authn.Session)
		if !ok {
			if groupType == groupTypeChannels {
				return channelPageRes{}, svcerr.ErrAuthorization
			}
			return groupPageRes{}, svcerr.ErrAuthorization
		}

		page, err := svc.ListGroups(ctx, session, req.memberKind, req.memberID, req.Page)
		if err != nil {
			if groupType == groupTypeChannels {
				return channelPageRes{}, err
			}
			return groupPageRes{}, err
		}

		if req.tree {
			return buildGroupsResponseTree(page), nil
		}
		filterByID := req.Page.ParentID != ""

		if groupType == groupTypeChannels {
			return buildChannelsResponse(page, filterByID), nil
		}
		return buildGroupsResponse(page, filterByID), nil
	}
}

func ListMembersEndpoint(svc groups.Service, authClient auth.AuthClient, memberKind string) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listMembersReq)
		if memberKind != "" {
			req.memberKind = memberKind
		}
		if err := req.validate(); err != nil {
			return listMembersRes{}, errors.Wrap(apiutil.ErrValidation, err)
		}

		session, ok := ctx.Value(api.SessionKey).(authn.Session)
		if !ok {
			return listMembersRes{}, svcerr.ErrAuthorization
		}

		page, err := svc.ListMembers(ctx, session, req.groupID, req.permission, req.memberKind)
		if err != nil {
			return listMembersRes{}, err
		}

		return listMembersRes{
			pageRes: pageRes{
				Limit:  page.Limit,
				Offset: page.Offset,
				Total:  page.Total,
			},
			Members: page.Members,
		}, nil
	}
}

func AssignMembersEndpoint(svc groups.Service, authClient auth.AuthClient, relation, memberKind string) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(assignReq)
		if relation != "" {
			req.Relation = relation
		}
		if memberKind != "" {
			req.MemberKind = memberKind
		}
		if err := req.validate(); err != nil {
			return assignRes{}, errors.Wrap(apiutil.ErrValidation, err)
		}
		session, ok := ctx.Value(api.SessionKey).(authn.Session)
		if !ok {
			return assignRes{}, svcerr.ErrAuthorization
		}

		if err := svc.Assign(ctx, session, req.groupID, req.Relation, req.MemberKind, req.Members...); err != nil {
			return assignRes{}, err
		}
		return assignRes{assigned: true}, nil
	}
}

func UnassignMembersEndpoint(svc groups.Service, authClient auth.AuthClient, relation, memberKind string) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(unassignReq)
		if relation != "" {
			req.Relation = relation
		}
		if memberKind != "" {
			req.MemberKind = memberKind
		}
		if err := req.validate(); err != nil {
			return unassignRes{}, errors.Wrap(apiutil.ErrValidation, err)
		}
		session, ok := ctx.Value(api.SessionKey).(authn.Session)
		if !ok {
			return unassignRes{}, svcerr.ErrAuthorization
		}

		if err := svc.Unassign(ctx, session, req.groupID, req.Relation, req.MemberKind, req.Members...); err != nil {
			return unassignRes{}, err
		}
		return unassignRes{unassigned: true}, nil
	}
}

func DeleteGroupEndpoint(svc groups.Service, authClient auth.AuthClient) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(groupReq)
		if err := req.validate(); err != nil {
			return deleteGroupRes{}, errors.Wrap(apiutil.ErrValidation, err)
		}

		session, ok := ctx.Value(api.SessionKey).(authn.Session)
		if !ok {
			return deleteGroupRes{}, svcerr.ErrAuthorization
		}
		if err := svc.DeleteGroup(ctx, session, req.id); err != nil {
			return deleteGroupRes{}, err
		}
		return deleteGroupRes{deleted: true}, nil
	}
}

func buildGroupsResponseTree(page groups.Page) groupPageRes {
	groupsMap := map[string]*groups.Group{}
	// Parents' map keeps its array of children.
	parentsMap := map[string][]*groups.Group{}
	for i := range page.Groups {
		if _, ok := groupsMap[page.Groups[i].ID]; !ok {
			groupsMap[page.Groups[i].ID] = &page.Groups[i]
			parentsMap[page.Groups[i].ID] = make([]*groups.Group, 0)
		}
	}

	for _, group := range groupsMap {
		if children, ok := parentsMap[group.Parent]; ok {
			children = append(children, group)
			parentsMap[group.Parent] = children
		}
	}

	res := groupPageRes{
		pageRes: pageRes{
			Limit:  page.Limit,
			Offset: page.Offset,
			Total:  page.Total,
			Level:  page.Level,
		},
		Groups: []viewGroupRes{},
	}

	for _, group := range groupsMap {
		if children, ok := parentsMap[group.ID]; ok {
			group.Children = children
		}
	}

	for _, group := range groupsMap {
		view := toViewGroupRes(*group)
		if children, ok := parentsMap[group.Parent]; len(children) == 0 || !ok {
			res.Groups = append(res.Groups, view)
		}
	}

	return res
}

func toViewGroupRes(group groups.Group) viewGroupRes {
	view := viewGroupRes{
		Group: group,
	}
	return view
}

func buildGroupsResponse(gp groups.Page, filterByID bool) groupPageRes {
	res := groupPageRes{
		pageRes: pageRes{
			Total: gp.Total,
			Level: gp.Level,
		},
		Groups: []viewGroupRes{},
	}

	for _, group := range gp.Groups {
		view := viewGroupRes{
			Group: group,
		}
		if filterByID && group.Level == 0 {
			continue
		}
		res.Groups = append(res.Groups, view)
	}

	return res
}

func buildChannelsResponse(cp groups.Page, filterByID bool) channelPageRes {
	res := channelPageRes{
		pageRes: pageRes{
			Total: cp.Total,
			Level: cp.Level,
		},
		Channels: []viewGroupRes{},
	}

	for _, channel := range cp.Groups {
		if filterByID && channel.Level == 0 {
			continue
		}
		view := viewGroupRes{
			Group: channel,
		}
		res.Channels = append(res.Channels, view)
	}

	return res
}

func identify(ctx context.Context, authClient auth.AuthClient, token string) (auth.Session, error) {
	resp, err := authClient.Identify(ctx, &magistrala.IdentityReq{Token: token})
	if err != nil {
		return auth.Session{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	if resp.GetId() == "" || resp.GetDomainId() == "" {
		return auth.Session{}, svcerr.ErrDomainAuthorization
	}
	return auth.Session{
		DomainUserID: resp.GetId(),
		UserID:       resp.GetUserId(),
		DomainID:     resp.GetDomainId(),
	}, nil
}

func checkSuperAdmin(ctx context.Context, authClient auth.AuthClient, adminID string) error {
	if _, err := authClient.Authorize(ctx, &magistrala.AuthorizeReq{
		SubjectType: policies.UserType,
		Subject:     adminID,
		Permission:  policies.AdminPermission,
		ObjectType:  policies.PlatformType,
		Object:      policies.MagistralaObject,
	}); err != nil {
		return err
	}
	return nil
}

func authorize(ctx context.Context, authClient auth.AuthClient, domainID, subjType, subjKind, subj, perm, objType, obj string) (auth.Session, error) {
	req := &magistrala.AuthorizeReq{
		Domain:      domainID,
		SubjectType: subjType,
		SubjectKind: subjKind,
		Subject:     subj,
		Permission:  perm,
		ObjectType:  objType,
		Object:      obj,
	}
	res, err := authClient.Authorize(ctx, req)
	if err != nil {
		return auth.Session{}, errors.Wrap(svcerr.ErrAuthorization, err)
	}
	if !res.GetAuthorized() {
		return auth.Session{}, errors.Wrap(svcerr.ErrAuthorization, err)
	}

	return auth.Session{
		UserID: res.GetId(),
	}, nil
}
