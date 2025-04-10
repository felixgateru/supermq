// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
)

type TokenType uint32

const (
	// AccessToken represents token generated by user.
	AccessToken TokenType = iota
	// PersonalAccessToken represents token generated by user for automation.
	PersonalAccessToken
)

func (t TokenType) String() string {
	switch t {
	case AccessToken:
		return "access token"
	case PersonalAccessToken:
		return "pat"
	default:
		return "unknown"
	}
}

type Role uint32

const (
	UserRole Role = iota + 1
	AdminRole
)

type Session struct {
	Type         TokenType
	PatID        string
	UserID       string
	DomainID     string
	DomainUserID string
	SuperAdmin   bool
	Role         Role
}

// Authn is supermq authentication library.
type Authentication interface {
	Authenticate(ctx context.Context, token string) (Session, error)
}
