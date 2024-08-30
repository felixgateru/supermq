// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"

	"github.com/absmach/magistrala/pkg/errors"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	"github.com/absmach/magistrala/pkg/policy"
)

var errPlatform = errors.New("invalid platform id")

var (
	defThingsFilterPermissions = []string{
		policy.AdminPermission,
		policy.DeletePermission,
		policy.EditPermission,
		policy.ViewPermission,
		policy.SharePermission,
		policy.PublishPermission,
		policy.SubscribePermission,
	}

	defGroupsFilterPermissions = []string{
		policy.AdminPermission,
		policy.DeletePermission,
		policy.EditPermission,
		policy.ViewPermission,
		policy.MembershipPermission,
		policy.SharePermission,
	}

	defDomainsFilterPermissions = []string{
		policy.AdminPermission,
		policy.EditPermission,
		policy.ViewPermission,
		policy.MembershipPermission,
		policy.SharePermission,
	}

	defPlatformFilterPermissions = []string{
		policy.AdminPermission,
		policy.MembershipPermission,
	}
)

type service struct {
	agent policy.PolicyAgent
}

func NewPolicyService(policyAgent policy.PolicyAgent) policy.PolicyService {
	return &service{
		agent: policyAgent,
	}
}

func (svc service) AddPolicy(ctx context.Context, req *magistrala.AddPolicyReq) (bool, error) {
	res, err := svc.policy.AddPolicy(ctx, req)
	if err != nil {
		return false, err
	}
	return svc.agent.AddPolicy(ctx, pr)
}

func (svc service) AddPolicies(ctx context.Context, req *magistrala.AddPoliciesReq) (bool, error) {
	res, err := svc.policy.AddPolicies(ctx, req)
	if err != nil {
		return false, err
	}

	return res.GetAdded(), nil
}

func (svc service) DeletePolicyFilter(ctx context.Context, req *magistrala.DeletePolicyFilterReq) (bool, error) {
	res, err := svc.policy.DeletePolicyFilter(ctx, req)
	if err != nil {
		return false, err
	}
	return res.GetDeleted(), nil
}

func (svc service) DeletePolicies(ctx context.Context, req *magistrala.DeletePoliciesReq) (bool, error) {
	res, err := svc.policy.DeletePolicies(ctx, req)
	if err != nil {
		return false, err
	}
	return svc.agent.DeletePolicies(ctx, prs)
}

func (svc service) ListObjects(ctx context.Context, req *magistrala.ListObjectsReq) ([]string, error) {
	res, err := svc.policy.ListObjects(ctx, req)
	if err != nil {
		return policy.PolicyPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	var page policy.PolicyPage
	for _, tuple := range res {
		page.Policies = append(page.Policies, tuple.Object)
	}
	page.NextPageToken = npt
	return page, nil
}

func (svc service) ListAllObjects(ctx context.Context, req *magistrala.ListObjectsReq) ([]string, error) {
	res, err := svc.policy.ListAllObjects(ctx, req)
	if err != nil {
		return policy.PolicyPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	var page policy.PolicyPage
	for _, tuple := range res {
		page.Policies = append(page.Policies, tuple.Object)
	}
	return page, nil
}

func (svc service) CountObjects(ctx context.Context, req *magistrala.CountObjectsReq) (uint64, error) {
	res, err := svc.policy.CountObjects(ctx, req)
	if err != nil {
		return 0, err
	}

	return res.Count, nil
}

func (svc service) ListSubjects(ctx context.Context, req *magistrala.ListSubjectsReq) ([]string, error) {
	res, err := svc.policy.ListSubjects(ctx, req)
	if err != nil {
		return policy.PolicyPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	var page policy.PolicyPage
	for _, tuple := range res {
		page.Policies = append(page.Policies, tuple.Subject)
	}
	page.NextPageToken = npt
	return page, nil
}

func (svc service) ListAllSubjects(ctx context.Context, req *magistrala.ListSubjectsReq) ([]string, error) {
	res, err := svc.policy.ListAllSubjects(ctx, req)
	if err != nil {
		return policy.PolicyPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	var page policy.PolicyPage
	for _, tuple := range res {
		page.Policies = append(page.Policies, tuple.Subject)
	}
	return page, nil
}

func (svc service) CountSubjects(ctx context.Context, req *magistrala.CountSubjectsReq) (uint64, error) {
	res, err := svc.policy.CountSubjects(ctx, req)
	if err != nil {
		return 0, err
	}

	return res.Count, nil
}

func (svc service) ListPermissions(ctx context.Context, req *magistrala.ListPermissionsReq) ([]string, error) {
	res, err := svc.policy.ListPermissions(ctx, req)
	if err != nil {
		return []string{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}

	return pers, nil
}

func (svc service) DeleteEntityPolicies(ctx context.Context, req *magistrala.DeleteEntityPoliciesReq) (bool, error) {
	res, err := svc.policy.DeleteEntityPolicies(ctx, req)
	if err != nil {
		return false, err
	}
	return nil
}
