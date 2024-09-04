// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/absmach/magistrala/pkg/policy"
)

var _ policy.PolicyService = (*loggingMiddleware)(nil)

type loggingMiddleware struct {
	logger *slog.Logger
	svc    policy.PolicyService
}

// LoggingMiddleware adds logging facilities to the core service.
func LoggingMiddleware(svc policy.PolicyService, logger *slog.Logger) policy.PolicyService {
	return &loggingMiddleware{logger, svc}
}

func (lm *loggingMiddleware) AddPolicy(ctx context.Context, pr policy.PolicyReq) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("policy_request",
				slog.String("object_id", pr.Object),
				slog.String("object_type", pr.ObjectType),
				slog.String("subject_id", pr.Subject),
				slog.String("subject_type", pr.SubjectType),
				slog.String("relation", pr.Relation),
			),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Add policy failed", args...)
			return
		}
		lm.logger.Info("Add policy completed successfully", args...)
	}(time.Now())
	return lm.svc.AddPolicy(ctx, pr)
}

func (lm *loggingMiddleware) AddPolicies(ctx context.Context, prs []policy.PolicyReq) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn(fmt.Sprintf("Add %d policies failed", len(prs)), args...)
			return
		}
		lm.logger.Info(fmt.Sprintf("Add %d policies completed successfully", len(prs)), args...)
	}(time.Now())

	return lm.svc.AddPolicies(ctx, prs)
}

func (lm *loggingMiddleware) DeletePolicyFilter(ctx context.Context, pr policy.PolicyReq) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("policy_request",
				slog.String("object_id", pr.Object),
				slog.String("object_type", pr.ObjectType),
				slog.String("subject_id", pr.Subject),
				slog.String("subject_type", pr.SubjectType),
				slog.String("relation", pr.Relation),
			),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Delete policy filter failed", args...)
			return
		}
		lm.logger.Info("Delete policy filter completed successfully", args...)
	}(time.Now())
	return lm.svc.DeletePolicyFilter(ctx, pr)
}

func (lm *loggingMiddleware) DeletePolicies(ctx context.Context, prs []policy.PolicyReq) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn(fmt.Sprintf("Delete %d policies failed", len(prs)), args...)
			return
		}
		lm.logger.Info(fmt.Sprintf("Delete %d policies completed successfully", len(prs)), args...)
	}(time.Now())
	return lm.svc.DeletePolicies(ctx, prs)
}

func (lm *loggingMiddleware) ListObjects(ctx context.Context, pr policy.PolicyReq, nextPageToken string, limit uint64) (p policy.PolicyPage, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Int64("limit", int64(limit)),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("List objects failed", args...)
			return
		}
		lm.logger.Info("List objects completed successfully", args...)
	}(time.Now())

	return lm.svc.ListObjects(ctx, pr, nextPageToken, limit)
}

func (lm *loggingMiddleware) ListAllObjects(ctx context.Context, pr policy.PolicyReq) (p policy.PolicyPage, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("policy_request",
				slog.String("object_type", pr.ObjectType),
				slog.String("subject_id", pr.Subject),
				slog.String("subject_type", pr.SubjectType),
				slog.String("permission", pr.Permission),
			),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("List all objects failed", args...)
			return
		}
		lm.logger.Info("List all objects completed successfully", args...)
	}(time.Now())

	return lm.svc.ListAllObjects(ctx, pr)
}

func (lm *loggingMiddleware) CountObjects(ctx context.Context, pr policy.PolicyReq) (count uint64, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Count objects failed", args...)
			return
		}
		lm.logger.Info("Count objects completed successfully", args...)
	}(time.Now())
	return lm.svc.CountObjects(ctx, pr)
}

func (lm *loggingMiddleware) ListSubjects(ctx context.Context, pr policy.PolicyReq, nextPageToken string, limit uint64) (p policy.PolicyPage, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("List subjects failed", args...)
			return
		}
		lm.logger.Info("List subjects completed successfully", args...)
	}(time.Now())

	return lm.svc.ListSubjects(ctx, pr, nextPageToken, limit)
}

func (lm *loggingMiddleware) ListAllSubjects(ctx context.Context, pr policy.PolicyReq) (p policy.PolicyPage, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("policy_request",
				slog.String("sybject_type", pr.SubjectType),
				slog.String("object_id", pr.Object),
				slog.String("object_type", pr.ObjectType),
				slog.String("permission", pr.Permission),
			),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("List all subjects failed", args...)
			return
		}
		lm.logger.Info("List all subjects completed successfully", args...)
	}(time.Now())

	return lm.svc.ListAllSubjects(ctx, pr)
}

func (lm *loggingMiddleware) CountSubjects(ctx context.Context, pr policy.PolicyReq) (count uint64, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Count subjects failed", args...)
			return
		}
		lm.logger.Info("Count subjects completed successfully", args...)
	}(time.Now())
	return lm.svc.CountSubjects(ctx, pr)
}

func (lm *loggingMiddleware) ListPermissions(ctx context.Context, pr policy.PolicyReq, filterPermissions []string) (p policy.Permissions, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Any("filter_permissions", filterPermissions),
			slog.Group("policy_request",
				slog.String("object_id", pr.Object),
				slog.String("object_type", pr.ObjectType),
				slog.String("subject_id", pr.Subject),
				slog.String("subject_type", pr.SubjectType),
			),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("List permissions failed", args...)
			return
		}
		lm.logger.Info("List permissions completed successfully", args...)
	}(time.Now())

	return lm.svc.ListPermissions(ctx, pr, filterPermissions)
}
