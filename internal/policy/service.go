// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"

	"github.com/absmach/magistrala"
	"github.com/absmach/magistrala/pkg/policy"
)

type service struct {
	policy magistrala.PolicyServiceClient
}

func NewService(policyClient magistrala.PolicyServiceClient) policy.PolicyService {
	return &service{
		policy: policyClient,
	}
}

func (s *service) AddPolicy(ctx context.Context, req *magistrala.AddPolicyReq) (bool, error) {
	res, err := s.policy.AddPolicy(ctx, req)
	if err != nil {
		return false, err
	}

	return res.GetAdded(), nil
}

func (svc *service) AddPolicies(ctx context.Context, req *magistrala.AddPoliciesReq) (bool, error) {
	res, err := svc.policy.AddPolicies(ctx, req)
	if err != nil {
		return false, err
	}

	return res.GetAdded(), nil
}

func (s *service) DeletePolicyFilter(ctx context.Context, req *magistrala.DeletePolicyFilterReq) (bool, error) {
	res, err := s.policy.DeletePolicyFilter(ctx, req)
	if err != nil {
		return false, err
	}
	return res.GetDeleted(), nil
}

func (s *service) DeletePolicies(ctx context.Context, req *magistrala.DeletePoliciesReq) (bool, error) {
	res, err := s.policy.DeletePolicies(ctx, req)
	if err != nil {
		return false, err
	}
	return res.GetDeleted(), nil
}

func (s *service) ListObjects(ctx context.Context, req *magistrala.ListObjectsReq) ([]string, error) {
	res, err := s.policy.ListObjects(ctx, req)
	if err != nil {
		return nil, err
	}

	return res.Policies, nil
}

func (s *service) ListAllObjects(ctx context.Context, req *magistrala.ListObjectsReq) ([]string, error) {
	res, err := s.policy.ListAllObjects(ctx, req)
	if err != nil {
		return nil, err
	}

	return res.Policies, nil
}

func (s *service) CountObjects(ctx context.Context, req *magistrala.CountObjectsReq) (uint64, error) {
	res, err := s.policy.CountObjects(ctx, req)
	if err != nil {
		return 0, err
	}

	return res.Count, nil
}

func (s *service) ListSubjects(ctx context.Context, req *magistrala.ListSubjectsReq) ([]string, error) {
	res, err := s.policy.ListSubjects(ctx, req)
	if err != nil {
		return nil, err
	}

	return res.Policies, nil
}

func (s *service) ListAllSubjects(ctx context.Context, req *magistrala.ListSubjectsReq) ([]string, error) {
	res, err := s.policy.ListAllSubjects(ctx, req)
	if err != nil {
		return nil, err
	}

	return res.Policies, nil
}

func (s *service) CountSubjects(ctx context.Context, req *magistrala.CountSubjectsReq) (uint64, error) {
	res, err := s.policy.CountSubjects(ctx, req)
	if err != nil {
		return 0, err
	}

	return res.Count, nil
}

func (s *service) ListPermissions(ctx context.Context, req *magistrala.ListPermissionsReq) ([]string, error) {
	res, err := s.policy.ListPermissions(ctx, req)
	if err != nil {
		return nil, err
	}

	return res.GetPermissions(), nil
}

func (s *service) DeleteEntityPolicies(ctx context.Context, req *magistrala.DeleteEntityPoliciesReq) (bool, error) {
	res, err := s.policy.DeleteEntityPolicies(ctx, req)
	if err != nil {
		return false, err
	}

	return res.GetDeleted(), nil
}
