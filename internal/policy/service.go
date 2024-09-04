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

func (svc service) AddPolicy(ctx context.Context, pr policy.PolicyReq) error {
	if err := svc.policyValidation(pr); err != nil {
		return errors.Wrap(svcerr.ErrInvalidPolicy, err)
	}
	return svc.agent.AddPolicy(ctx, pr)
}

func (svc service) AddPolicies(ctx context.Context, prs []policy.PolicyReq) error {
	for _, pr := range prs {
		if err := svc.policyValidation(pr); err != nil {
			return errors.Wrap(svcerr.ErrInvalidPolicy, err)
		}
	}
	return svc.agent.AddPolicies(ctx, prs)
}

func (svc service) DeletePolicyFilter(ctx context.Context, pr policy.PolicyReq) error {
	return svc.agent.DeletePolicyFilter(ctx, pr)
}

func (svc service) DeletePolicies(ctx context.Context, prs []policy.PolicyReq) error {
	for _, pr := range prs {
		if err := svc.policyValidation(pr); err != nil {
			return errors.Wrap(svcerr.ErrInvalidPolicy, err)
		}
	}
	return svc.agent.DeletePolicies(ctx, prs)
}

func (svc service) ListObjects(ctx context.Context, pr policy.PolicyReq, nextPageToken string, limit uint64) (policy.PolicyPage, error) {
	if limit <= 0 {
		limit = 100
	}
	res, npt, err := svc.agent.RetrieveObjects(ctx, pr, nextPageToken, limit)
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

func (svc service) ListAllObjects(ctx context.Context, pr policy.PolicyReq) (policy.PolicyPage, error) {
	res, err := svc.agent.RetrieveAllObjects(ctx, pr)
	if err != nil {
		return policy.PolicyPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	var page policy.PolicyPage
	for _, tuple := range res {
		page.Policies = append(page.Policies, tuple.Object)
	}
	return page, nil
}

func (svc service) CountObjects(ctx context.Context, pr policy.PolicyReq) (uint64, error) {
	return svc.agent.RetrieveAllObjectsCount(ctx, pr)
}

func (svc service) ListSubjects(ctx context.Context, pr policy.PolicyReq, nextPageToken string, limit uint64) (policy.PolicyPage, error) {
	if limit <= 0 {
		limit = 100
	}
	res, npt, err := svc.agent.RetrieveSubjects(ctx, pr, nextPageToken, limit)
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

func (svc service) ListAllSubjects(ctx context.Context, pr policy.PolicyReq) (policy.PolicyPage, error) {
	res, err := svc.agent.RetrieveAllSubjects(ctx, pr)
	if err != nil {
		return policy.PolicyPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	var page policy.PolicyPage
	for _, tuple := range res {
		page.Policies = append(page.Policies, tuple.Subject)
	}
	return page, nil
}

func (svc service) CountSubjects(ctx context.Context, pr policy.PolicyReq) (uint64, error) {
	return svc.agent.RetrieveAllSubjectsCount(ctx, pr)
}

func (svc service) ListPermissions(ctx context.Context, pr policy.PolicyReq, permissionsFilter []string) (policy.Permissions, error) {
	if len(permissionsFilter) == 0 {
		switch pr.ObjectType {
		case policy.ThingType:
			permissionsFilter = defThingsFilterPermissions
		case policy.GroupType:
			permissionsFilter = defGroupsFilterPermissions
		case policy.PlatformType:
			permissionsFilter = defPlatformFilterPermissions
		case policy.DomainType:
			permissionsFilter = defDomainsFilterPermissions
		default:
			return nil, svcerr.ErrMalformedEntity
		}
	}
	pers, err := svc.agent.RetrievePermissions(ctx, pr, permissionsFilter)
	if err != nil {
		return []string{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}

	return pers, nil
}

func (svc *service) policyValidation(pr policy.PolicyReq) error {
	if pr.ObjectType == policy.PlatformType && pr.Object != policy.MagistralaObject {
		return errPlatform
	}
	return nil
}
