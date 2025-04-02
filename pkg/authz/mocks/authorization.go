// Code generated by mockery; DO NOT EDIT.
// github.com/vektra/mockery
// template: testify
// Copyright (c) Abstract Machines

// SPDX-License-Identifier: Apache-2.0

package mocks

import (
	"context"

	"github.com/absmach/supermq/pkg/authz"
	mock "github.com/stretchr/testify/mock"
)

// NewAuthorization creates a new instance of Authorization. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAuthorization(t interface {
	mock.TestingT
	Cleanup(func())
}) *Authorization {
	mock := &Authorization{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

// Authorization is an autogenerated mock type for the Authorization type
type Authorization struct {
	mock.Mock
}

type Authorization_Expecter struct {
	mock *mock.Mock
}

func (_m *Authorization) EXPECT() *Authorization_Expecter {
	return &Authorization_Expecter{mock: &_m.Mock}
}

// Authorize provides a mock function for the type Authorization
func (_mock *Authorization) Authorize(ctx context.Context, pr authz.PolicyReq) error {
	ret := _mock.Called(ctx, pr)

	if len(ret) == 0 {
		panic("no return value specified for Authorize")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, authz.PolicyReq) error); ok {
		r0 = returnFunc(ctx, pr)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// Authorization_Authorize_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Authorize'
type Authorization_Authorize_Call struct {
	*mock.Call
}

// Authorize is a helper method to define mock.On call
//   - ctx
//   - pr
func (_e *Authorization_Expecter) Authorize(ctx interface{}, pr interface{}) *Authorization_Authorize_Call {
	return &Authorization_Authorize_Call{Call: _e.mock.On("Authorize", ctx, pr)}
}

func (_c *Authorization_Authorize_Call) Run(run func(ctx context.Context, pr authz.PolicyReq)) *Authorization_Authorize_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(authz.PolicyReq))
	})
	return _c
}

func (_c *Authorization_Authorize_Call) Return(err error) *Authorization_Authorize_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *Authorization_Authorize_Call) RunAndReturn(run func(ctx context.Context, pr authz.PolicyReq) error) *Authorization_Authorize_Call {
	_c.Call.Return(run)
	return _c
}

// AuthorizePAT provides a mock function for the type Authorization
func (_mock *Authorization) AuthorizePAT(ctx context.Context, pr authz.PatReq) error {
	ret := _mock.Called(ctx, pr)

	if len(ret) == 0 {
		panic("no return value specified for AuthorizePAT")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, authz.PatReq) error); ok {
		r0 = returnFunc(ctx, pr)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// Authorization_AuthorizePAT_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AuthorizePAT'
type Authorization_AuthorizePAT_Call struct {
	*mock.Call
}

// AuthorizePAT is a helper method to define mock.On call
//   - ctx
//   - pr
func (_e *Authorization_Expecter) AuthorizePAT(ctx interface{}, pr interface{}) *Authorization_AuthorizePAT_Call {
	return &Authorization_AuthorizePAT_Call{Call: _e.mock.On("AuthorizePAT", ctx, pr)}
}

func (_c *Authorization_AuthorizePAT_Call) Run(run func(ctx context.Context, pr authz.PatReq)) *Authorization_AuthorizePAT_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(authz.PatReq))
	})
	return _c
}

func (_c *Authorization_AuthorizePAT_Call) Return(err error) *Authorization_AuthorizePAT_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *Authorization_AuthorizePAT_Call) RunAndReturn(run func(ctx context.Context, pr authz.PatReq) error) *Authorization_AuthorizePAT_Call {
	_c.Call.Return(run)
	return _c
}
