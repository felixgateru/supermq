// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"log/slog"
	"time"

	"github.com/absmach/magistrala/pkg/auth"
	mgclients "github.com/absmach/magistrala/pkg/clients"
	"github.com/absmach/magistrala/users"
)

var _ users.Service = (*loggingMiddleware)(nil)

type loggingMiddleware struct {
	logger *slog.Logger
	svc    users.Service
}

// LoggingMiddleware adds logging facilities to the clients service.
func LoggingMiddleware(svc users.Service, logger *slog.Logger) users.Service {
	return &loggingMiddleware{logger, svc}
}

// RegisterClient logs the register_client request. It logs the client id and the time it took to complete the request.
// If the request fails, it logs the error.
func (lm *loggingMiddleware) RegisterClient(ctx context.Context, authObject auth.AuthObject, client mgclients.Client, selfRegister bool) (c mgclients.Client, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("user",
				slog.String("id", c.ID),
				slog.String("name", c.Name),
			),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Register user failed", args...)
			return
		}
		lm.logger.Info("Register user completed successfully", args...)
	}(time.Now())
	return lm.svc.RegisterClient(ctx, authObject, client, selfRegister)
}

// IssueToken logs the issue_token request. It logs the client identity type and the time it took to complete the request.
// If the request fails, it logs the error.
func (lm *loggingMiddleware) IssueToken(ctx context.Context, identity, secret, domainID string) (t auth.Token, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("domain_id", domainID),
		}
		if t.AccessType != "" {
			args = append(args, slog.String("access_type", t.AccessType))
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Issue token failed", args...)
			return
		}
		lm.logger.Info("Issue token completed successfully", args...)
	}(time.Now())
	return lm.svc.IssueToken(ctx, identity, secret, domainID)
}

// RefreshToken logs the refresh_token request. It logs the refreshtoken, token type and the time it took to complete the request.
// If the request fails, it logs the error.
func (lm *loggingMiddleware) RefreshToken(ctx context.Context, authObject auth.AuthObject, domainID string) (t auth.Token, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("domain_id", domainID),
		}
		if t.AccessType != "" {
			args = append(args, slog.String("access_type", t.AccessType))
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Refresh token failed", args...)
			return
		}
		lm.logger.Info("Refresh token completed successfully", args...)
	}(time.Now())
	return lm.svc.RefreshToken(ctx, authObject, domainID)
}

// ViewClient logs the view_client request. It logs the client id and the time it took to complete the request.
// If the request fails, it logs the error.
func (lm *loggingMiddleware) ViewClient(ctx context.Context, authObject auth.AuthObject, id string) (c mgclients.Client, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("user",
				slog.String("id", id),
				slog.String("name", c.Name),
			),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("View user failed", args...)
			return
		}
		lm.logger.Info("View user completed successfully", args...)
	}(time.Now())
	return lm.svc.ViewClient(ctx, authObject, id)
}

// ViewProfile logs the view_profile request. It logs the client id and the time it took to complete the request.
// If the request fails, it logs the error.
func (lm *loggingMiddleware) ViewProfile(ctx context.Context, authObject auth.AuthObject) (c mgclients.Client, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("user",
				slog.String("id", c.ID),
				slog.String("name", c.Name),
			),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("View profile failed", args...)
			return
		}
		lm.logger.Info("View profile completed successfully", args...)
	}(time.Now())
	return lm.svc.ViewProfile(ctx, authObject)
}

// ListClients logs the list_clients request. It logs the page metadata and the time it took to complete the request.
// If the request fails, it logs the error.
func (lm *loggingMiddleware) ListClients(ctx context.Context, authObject auth.AuthObject, pm mgclients.Page) (cp mgclients.ClientsPage, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("page",
				slog.Uint64("limit", pm.Limit),
				slog.Uint64("offset", pm.Offset),
				slog.Uint64("total", cp.Total),
			),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("List users failed", args...)
			return
		}
		lm.logger.Info("List users completed successfully", args...)
	}(time.Now())
	return lm.svc.ListClients(ctx, authObject, pm)
}

// SearchUsers logs the search_users request. It logs the page metadata and the time it took to complete the request.
func (lm *loggingMiddleware) SearchUsers(ctx context.Context, authObject auth.AuthObject, cp mgclients.Page) (mp mgclients.ClientsPage, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("page",
				slog.Uint64("limit", cp.Limit),
				slog.Uint64("offset", cp.Offset),
				slog.Uint64("total", mp.Total),
			),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Search clients failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Search clients completed successfully", args...)
	}(time.Now())
	return lm.svc.SearchUsers(ctx, authObject, cp)
}

// UpdateClient logs the update_client request. It logs the client id and the time it took to complete the request.
// If the request fails, it logs the error.
func (lm *loggingMiddleware) UpdateClient(ctx context.Context, authObject auth.AuthObject, client mgclients.Client) (c mgclients.Client, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("user",
				slog.String("id", c.ID),
				slog.String("name", c.Name),
				slog.Any("metadata", c.Metadata),
			),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Update user failed", args...)
			return
		}
		lm.logger.Info("Update user completed successfully", args...)
	}(time.Now())
	return lm.svc.UpdateClient(ctx, authObject, client)
}

// UpdateClientTags logs the update_client_tags request. It logs the client id and the time it took to complete the request.
// If the request fails, it logs the error.
func (lm *loggingMiddleware) UpdateClientTags(ctx context.Context, authObject auth.AuthObject, client mgclients.Client) (c mgclients.Client, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("user",
				slog.String("id", c.ID),
				slog.String("name", c.Name),
				slog.Any("tags", c.Tags),
			),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Update user tags failed", args...)
			return
		}
		lm.logger.Info("Update user tags completed successfully", args...)
	}(time.Now())
	return lm.svc.UpdateClientTags(ctx, authObject, client)
}

// UpdateClientIdentity logs the update_identity request. It logs the client id and the time it took to complete the request.
// If the request fails, it logs the error.
func (lm *loggingMiddleware) UpdateClientIdentity(ctx context.Context, authObject auth.AuthObject, id, identity string) (c mgclients.Client, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("user",
				slog.String("id", c.ID),
				slog.String("name", c.Name),
			),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Update client identity failed", args...)
			return
		}
		lm.logger.Info("Update client identity completed successfully", args...)
	}(time.Now())
	return lm.svc.UpdateClientIdentity(ctx, authObject, id, identity)
}

// UpdateClientSecret logs the update_client_secret request. It logs the client id and the time it took to complete the request.
// If the request fails, it logs the error.
func (lm *loggingMiddleware) UpdateClientSecret(ctx context.Context, authObject auth.AuthObject, oldSecret, newSecret string) (c mgclients.Client, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("user",
				slog.String("id", c.ID),
				slog.String("name", c.Name),
			),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Update user secret failed", args...)
			return
		}
		lm.logger.Info("Update user secret completed successfully", args...)
	}(time.Now())
	return lm.svc.UpdateClientSecret(ctx, authObject, oldSecret, newSecret)
}

// GenerateResetToken logs the generate_reset_token request. It logs the time it took to complete the request.
// If the request fails, it logs the error.
func (lm *loggingMiddleware) GenerateResetToken(ctx context.Context, email, host string) (t auth.Token, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("host", host),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Generate reset token failed", args...)
			return
		}
		lm.logger.Info("Generate reset token completed successfully", args...)
	}(time.Now())
	return lm.svc.GenerateResetToken(ctx, email, host)
}

// ResetSecret logs the reset_secret request. It logs the time it took to complete the request.
// If the request fails, it logs the error.
func (lm *loggingMiddleware) ResetSecret(ctx context.Context, authObject auth.AuthObject, secret string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Reset secret failed", args...)
			return
		}
		lm.logger.Info("Reset secret completed successfully", args...)
	}(time.Now())
	return lm.svc.ResetSecret(ctx, authObject, secret)
}

// SendPasswordReset logs the send_password_reset request. It logs the time it took to complete the request.
// If the request fails, it logs the error.
func (lm *loggingMiddleware) SendPasswordReset(ctx context.Context, host, email, user, token string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("host", host),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Send password reset failed", args...)
			return
		}
		lm.logger.Info("Send password reset completed successfully", args...)
	}(time.Now())
	return lm.svc.SendPasswordReset(ctx, host, email, user, token)
}

// UpdateClientRole logs the update_client_role request. It logs the client id and the time it took to complete the request.
// If the request fails, it logs the error.
func (lm *loggingMiddleware) UpdateClientRole(ctx context.Context, authObject auth.AuthObject, client mgclients.Client) (c mgclients.Client, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("user",
				slog.String("id", c.ID),
				slog.String("name", c.Name),
				slog.String("role", client.Role.String()),
			),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Update user role failed", args...)
			return
		}
		lm.logger.Info("Update user role completed successfully", args...)
	}(time.Now())
	return lm.svc.UpdateClientRole(ctx, authObject, client)
}

// EnableClient logs the enable_client request. It logs the client id and the time it took to complete the request.
// If the request fails, it logs the error.
func (lm *loggingMiddleware) EnableClient(ctx context.Context, authObject auth.AuthObject, id string) (c mgclients.Client, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("user",
				slog.String("id", id),
				slog.String("name", c.Name),
			),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Enable user failed", args...)
			return
		}
		lm.logger.Info("Enable user completed successfully", args...)
	}(time.Now())
	return lm.svc.EnableClient(ctx, authObject, id)
}

// DisableClient logs the disable_client request. It logs the client id and the time it took to complete the request.
// If the request fails, it logs the error.
func (lm *loggingMiddleware) DisableClient(ctx context.Context, authObject auth.AuthObject, id string) (c mgclients.Client, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("user",
				slog.String("id", id),
				slog.String("name", c.Name),
			),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Disable user failed", args...)
			return
		}
		lm.logger.Info("Disable user completed successfully", args...)
	}(time.Now())
	return lm.svc.DisableClient(ctx, authObject, id)
}

// ListMembers logs the list_members request. It logs the group id, and the time it took to complete the request.
// If the request fails, it logs the error.
func (lm *loggingMiddleware) ListMembers(ctx context.Context, authObject auth.AuthObject, objectKind, objectID string, cp mgclients.Page) (mp mgclients.MembersPage, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("object",
				slog.String("kind", objectKind),
				slog.String("id", objectID),
			),
			slog.Group("page",
				slog.Uint64("limit", cp.Limit),
				slog.Uint64("offset", cp.Offset),
				slog.Uint64("total", mp.Total),
			),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("List members failed", args...)
			return
		}
		lm.logger.Info("List members completed successfully", args...)
	}(time.Now())
	return lm.svc.ListMembers(ctx, authObject, objectKind, objectID, cp)
}

// Identify logs the identify request. It logs the time it took to complete the request.
func (lm *loggingMiddleware) Identify(ctx context.Context, authObject auth.AuthObject) (id string, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("user_id", id),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Identify user failed", args...)
			return
		}
		lm.logger.Info("Identify user completed successfully", args...)
	}(time.Now())
	return lm.svc.Identify(ctx, authObject)
}

func (lm *loggingMiddleware) OAuthCallback(ctx context.Context, client mgclients.Client) (token auth.Token, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("user_id", client.ID),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("OAuth callback failed", args...)
			return
		}
		lm.logger.Info("OAuth callback completed successfully", args...)
	}(time.Now())
	return lm.svc.OAuthCallback(ctx, client)
}

// DeleteClient logs the delete_client request. It logs the client id and token and the time it took to complete the request.
func (lm *loggingMiddleware) DeleteClient(ctx context.Context, authObject auth.AuthObject, id string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("user_id", id),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Delete user failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Delete user completed successfully", args...)
	}(time.Now())
	return lm.svc.DeleteClient(ctx, authObject, id)
}

func (lm *loggingMiddleware) AddClientPolicy(ctx context.Context, client mgclients.Client) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("user_id", client.ID),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Add client policy failed", args...)
			return
		}
		lm.logger.Info("Add client policy completed successfully", args...)
	}(time.Now())
	return lm.svc.AddClientPolicy(ctx, client)
}
