// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"time"

	"github.com/absmach/magistrala/pkg/policy"
	"github.com/go-kit/kit/metrics"
)

var _ policy.PolicyService = (*metricsMiddleware)(nil)

type metricsMiddleware struct {
	counter metrics.Counter
	latency metrics.Histogram
	svc     policy.PolicyService
}

// MetricsMiddleware instruments core service by tracking request count and latency.
func MetricsMiddleware(svc policy.PolicyService, counter metrics.Counter, latency metrics.Histogram) policy.PolicyService {
	return &metricsMiddleware{
		counter: counter,
		latency: latency,
		svc:     svc,
	}
}

func (ms *metricsMiddleware) AddPolicy(ctx context.Context, pr policy.PolicyReq) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "add_policy").Add(1)
		ms.latency.With("method", "add_policy").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.AddPolicy(ctx, pr)
}

func (ms *metricsMiddleware) AddPolicies(ctx context.Context, prs []policy.PolicyReq) (err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "create_policy_bulk").Add(1)
		ms.latency.With("method", "create_policy_bulk").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.AddPolicies(ctx, prs)
}

func (ms *metricsMiddleware) DeletePolicyFilter(ctx context.Context, pr policy.PolicyReq) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "delete_policy_filter").Add(1)
		ms.latency.With("method", "delete_policy_filter").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.DeletePolicyFilter(ctx, pr)
}

func (ms *metricsMiddleware) DeletePolicies(ctx context.Context, prs []policy.PolicyReq) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "delete_policies").Add(1)
		ms.latency.With("method", "delete_policies").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.DeletePolicies(ctx, prs)
}

func (ms *metricsMiddleware) ListObjects(ctx context.Context, pr policy.PolicyReq, nextPageToken string, limit uint64) (p policy.PolicyPage, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "list_objects").Add(1)
		ms.latency.With("method", "list_objects").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.ListObjects(ctx, pr, nextPageToken, limit)
}

func (ms *metricsMiddleware) ListAllObjects(ctx context.Context, pr policy.PolicyReq) (p policy.PolicyPage, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "list_all_objects").Add(1)
		ms.latency.With("method", "list_all_objects").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.ListAllObjects(ctx, pr)
}

func (ms *metricsMiddleware) CountObjects(ctx context.Context, pr policy.PolicyReq) (count uint64, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "count_objects").Add(1)
		ms.latency.With("method", "count_objects").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.CountObjects(ctx, pr)
}

func (ms *metricsMiddleware) ListSubjects(ctx context.Context, pr policy.PolicyReq, nextPageToken string, limit uint64) (p policy.PolicyPage, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "list_subjects").Add(1)
		ms.latency.With("method", "list_subjects").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.ListSubjects(ctx, pr, nextPageToken, limit)
}

func (ms *metricsMiddleware) ListAllSubjects(ctx context.Context, pr policy.PolicyReq) (p policy.PolicyPage, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "list_all_subjects").Add(1)
		ms.latency.With("method", "list_all_subjects").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.ListAllSubjects(ctx, pr)
}

func (ms *metricsMiddleware) CountSubjects(ctx context.Context, pr policy.PolicyReq) (count uint64, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "count_subjects").Add(1)
		ms.latency.With("method", "count_subjects").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.CountSubjects(ctx, pr)
}

func (ms *metricsMiddleware) ListPermissions(ctx context.Context, pr policy.PolicyReq, filterPermissions []string) (p policy.Permissions, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "list_permissions").Add(1)
		ms.latency.With("method", "list_permissions").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.ListPermissions(ctx, pr, filterPermissions)
}
