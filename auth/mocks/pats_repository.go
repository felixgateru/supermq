// Code generated by mockery; DO NOT EDIT.
// github.com/vektra/mockery
// template: testify
// Copyright (c) Abstract Machines

// SPDX-License-Identifier: Apache-2.0

package mocks

import (
	"context"
	"time"

	"github.com/absmach/supermq/auth"
	mock "github.com/stretchr/testify/mock"
)

// NewPATSRepository creates a new instance of PATSRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewPATSRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *PATSRepository {
	mock := &PATSRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

// PATSRepository is an autogenerated mock type for the PATSRepository type
type PATSRepository struct {
	mock.Mock
}

type PATSRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *PATSRepository) EXPECT() *PATSRepository_Expecter {
	return &PATSRepository_Expecter{mock: &_m.Mock}
}

// AddScope provides a mock function for the type PATSRepository
func (_mock *PATSRepository) AddScope(ctx context.Context, userID string, scopes []auth.Scope) error {
	ret := _mock.Called(ctx, userID, scopes)

	if len(ret) == 0 {
		panic("no return value specified for AddScope")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, []auth.Scope) error); ok {
		r0 = returnFunc(ctx, userID, scopes)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// PATSRepository_AddScope_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AddScope'
type PATSRepository_AddScope_Call struct {
	*mock.Call
}

// AddScope is a helper method to define mock.On call
//   - ctx
//   - userID
//   - scopes
func (_e *PATSRepository_Expecter) AddScope(ctx interface{}, userID interface{}, scopes interface{}) *PATSRepository_AddScope_Call {
	return &PATSRepository_AddScope_Call{Call: _e.mock.On("AddScope", ctx, userID, scopes)}
}

func (_c *PATSRepository_AddScope_Call) Run(run func(ctx context.Context, userID string, scopes []auth.Scope)) *PATSRepository_AddScope_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].([]auth.Scope))
	})
	return _c
}

func (_c *PATSRepository_AddScope_Call) Return(err error) *PATSRepository_AddScope_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *PATSRepository_AddScope_Call) RunAndReturn(run func(ctx context.Context, userID string, scopes []auth.Scope) error) *PATSRepository_AddScope_Call {
	_c.Call.Return(run)
	return _c
}

// CheckScope provides a mock function for the type PATSRepository
func (_mock *PATSRepository) CheckScope(ctx context.Context, userID string, patID string, entityType auth.EntityType, optionalDomainID string, operation auth.Operation, entityID string) error {
	ret := _mock.Called(ctx, userID, patID, entityType, optionalDomainID, operation, entityID)

	if len(ret) == 0 {
		panic("no return value specified for CheckScope")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, string, auth.EntityType, string, auth.Operation, string) error); ok {
		r0 = returnFunc(ctx, userID, patID, entityType, optionalDomainID, operation, entityID)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// PATSRepository_CheckScope_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CheckScope'
type PATSRepository_CheckScope_Call struct {
	*mock.Call
}

// CheckScope is a helper method to define mock.On call
//   - ctx
//   - userID
//   - patID
//   - entityType
//   - optionalDomainID
//   - operation
//   - entityID
func (_e *PATSRepository_Expecter) CheckScope(ctx interface{}, userID interface{}, patID interface{}, entityType interface{}, optionalDomainID interface{}, operation interface{}, entityID interface{}) *PATSRepository_CheckScope_Call {
	return &PATSRepository_CheckScope_Call{Call: _e.mock.On("CheckScope", ctx, userID, patID, entityType, optionalDomainID, operation, entityID)}
}

func (_c *PATSRepository_CheckScope_Call) Run(run func(ctx context.Context, userID string, patID string, entityType auth.EntityType, optionalDomainID string, operation auth.Operation, entityID string)) *PATSRepository_CheckScope_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].(auth.EntityType), args[4].(string), args[5].(auth.Operation), args[6].(string))
	})
	return _c
}

func (_c *PATSRepository_CheckScope_Call) Return(err error) *PATSRepository_CheckScope_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *PATSRepository_CheckScope_Call) RunAndReturn(run func(ctx context.Context, userID string, patID string, entityType auth.EntityType, optionalDomainID string, operation auth.Operation, entityID string) error) *PATSRepository_CheckScope_Call {
	_c.Call.Return(run)
	return _c
}

// Reactivate provides a mock function for the type PATSRepository
func (_mock *PATSRepository) Reactivate(ctx context.Context, userID string, patID string) error {
	ret := _mock.Called(ctx, userID, patID)

	if len(ret) == 0 {
		panic("no return value specified for Reactivate")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = returnFunc(ctx, userID, patID)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// PATSRepository_Reactivate_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Reactivate'
type PATSRepository_Reactivate_Call struct {
	*mock.Call
}

// Reactivate is a helper method to define mock.On call
//   - ctx
//   - userID
//   - patID
func (_e *PATSRepository_Expecter) Reactivate(ctx interface{}, userID interface{}, patID interface{}) *PATSRepository_Reactivate_Call {
	return &PATSRepository_Reactivate_Call{Call: _e.mock.On("Reactivate", ctx, userID, patID)}
}

func (_c *PATSRepository_Reactivate_Call) Run(run func(ctx context.Context, userID string, patID string)) *PATSRepository_Reactivate_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *PATSRepository_Reactivate_Call) Return(err error) *PATSRepository_Reactivate_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *PATSRepository_Reactivate_Call) RunAndReturn(run func(ctx context.Context, userID string, patID string) error) *PATSRepository_Reactivate_Call {
	_c.Call.Return(run)
	return _c
}

// Remove provides a mock function for the type PATSRepository
func (_mock *PATSRepository) Remove(ctx context.Context, userID string, patID string) error {
	ret := _mock.Called(ctx, userID, patID)

	if len(ret) == 0 {
		panic("no return value specified for Remove")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = returnFunc(ctx, userID, patID)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// PATSRepository_Remove_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Remove'
type PATSRepository_Remove_Call struct {
	*mock.Call
}

// Remove is a helper method to define mock.On call
//   - ctx
//   - userID
//   - patID
func (_e *PATSRepository_Expecter) Remove(ctx interface{}, userID interface{}, patID interface{}) *PATSRepository_Remove_Call {
	return &PATSRepository_Remove_Call{Call: _e.mock.On("Remove", ctx, userID, patID)}
}

func (_c *PATSRepository_Remove_Call) Run(run func(ctx context.Context, userID string, patID string)) *PATSRepository_Remove_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *PATSRepository_Remove_Call) Return(err error) *PATSRepository_Remove_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *PATSRepository_Remove_Call) RunAndReturn(run func(ctx context.Context, userID string, patID string) error) *PATSRepository_Remove_Call {
	_c.Call.Return(run)
	return _c
}

// RemoveAllPAT provides a mock function for the type PATSRepository
func (_mock *PATSRepository) RemoveAllPAT(ctx context.Context, userID string) error {
	ret := _mock.Called(ctx, userID)

	if len(ret) == 0 {
		panic("no return value specified for RemoveAllPAT")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = returnFunc(ctx, userID)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// PATSRepository_RemoveAllPAT_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RemoveAllPAT'
type PATSRepository_RemoveAllPAT_Call struct {
	*mock.Call
}

// RemoveAllPAT is a helper method to define mock.On call
//   - ctx
//   - userID
func (_e *PATSRepository_Expecter) RemoveAllPAT(ctx interface{}, userID interface{}) *PATSRepository_RemoveAllPAT_Call {
	return &PATSRepository_RemoveAllPAT_Call{Call: _e.mock.On("RemoveAllPAT", ctx, userID)}
}

func (_c *PATSRepository_RemoveAllPAT_Call) Run(run func(ctx context.Context, userID string)) *PATSRepository_RemoveAllPAT_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *PATSRepository_RemoveAllPAT_Call) Return(err error) *PATSRepository_RemoveAllPAT_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *PATSRepository_RemoveAllPAT_Call) RunAndReturn(run func(ctx context.Context, userID string) error) *PATSRepository_RemoveAllPAT_Call {
	_c.Call.Return(run)
	return _c
}

// RemoveAllScope provides a mock function for the type PATSRepository
func (_mock *PATSRepository) RemoveAllScope(ctx context.Context, patID string) error {
	ret := _mock.Called(ctx, patID)

	if len(ret) == 0 {
		panic("no return value specified for RemoveAllScope")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = returnFunc(ctx, patID)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// PATSRepository_RemoveAllScope_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RemoveAllScope'
type PATSRepository_RemoveAllScope_Call struct {
	*mock.Call
}

// RemoveAllScope is a helper method to define mock.On call
//   - ctx
//   - patID
func (_e *PATSRepository_Expecter) RemoveAllScope(ctx interface{}, patID interface{}) *PATSRepository_RemoveAllScope_Call {
	return &PATSRepository_RemoveAllScope_Call{Call: _e.mock.On("RemoveAllScope", ctx, patID)}
}

func (_c *PATSRepository_RemoveAllScope_Call) Run(run func(ctx context.Context, patID string)) *PATSRepository_RemoveAllScope_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *PATSRepository_RemoveAllScope_Call) Return(err error) *PATSRepository_RemoveAllScope_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *PATSRepository_RemoveAllScope_Call) RunAndReturn(run func(ctx context.Context, patID string) error) *PATSRepository_RemoveAllScope_Call {
	_c.Call.Return(run)
	return _c
}

// RemoveScope provides a mock function for the type PATSRepository
func (_mock *PATSRepository) RemoveScope(ctx context.Context, userID string, scopesIDs ...string) error {
	var tmpRet mock.Arguments
	if len(scopesIDs) > 0 {
		tmpRet = _mock.Called(ctx, userID, scopesIDs)
	} else {
		tmpRet = _mock.Called(ctx, userID)
	}
	ret := tmpRet

	if len(ret) == 0 {
		panic("no return value specified for RemoveScope")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, ...string) error); ok {
		r0 = returnFunc(ctx, userID, scopesIDs...)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// PATSRepository_RemoveScope_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RemoveScope'
type PATSRepository_RemoveScope_Call struct {
	*mock.Call
}

// RemoveScope is a helper method to define mock.On call
//   - ctx
//   - userID
//   - scopesIDs
func (_e *PATSRepository_Expecter) RemoveScope(ctx interface{}, userID interface{}, scopesIDs ...interface{}) *PATSRepository_RemoveScope_Call {
	return &PATSRepository_RemoveScope_Call{Call: _e.mock.On("RemoveScope",
		append([]interface{}{ctx, userID}, scopesIDs...)...)}
}

func (_c *PATSRepository_RemoveScope_Call) Run(run func(ctx context.Context, userID string, scopesIDs ...string)) *PATSRepository_RemoveScope_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]string, len(args)-2)
		for i, a := range args[2:] {
			if a != nil {
				variadicArgs[i] = a.(string)
			}
		}
		run(args[0].(context.Context), args[1].(string), variadicArgs...)
	})
	return _c
}

func (_c *PATSRepository_RemoveScope_Call) Return(err error) *PATSRepository_RemoveScope_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *PATSRepository_RemoveScope_Call) RunAndReturn(run func(ctx context.Context, userID string, scopesIDs ...string) error) *PATSRepository_RemoveScope_Call {
	_c.Call.Return(run)
	return _c
}

// Retrieve provides a mock function for the type PATSRepository
func (_mock *PATSRepository) Retrieve(ctx context.Context, userID string, patID string) (auth.PAT, error) {
	ret := _mock.Called(ctx, userID, patID)

	if len(ret) == 0 {
		panic("no return value specified for Retrieve")
	}

	var r0 auth.PAT
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, string) (auth.PAT, error)); ok {
		return returnFunc(ctx, userID, patID)
	}
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, string) auth.PAT); ok {
		r0 = returnFunc(ctx, userID, patID)
	} else {
		r0 = ret.Get(0).(auth.PAT)
	}
	if returnFunc, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = returnFunc(ctx, userID, patID)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// PATSRepository_Retrieve_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Retrieve'
type PATSRepository_Retrieve_Call struct {
	*mock.Call
}

// Retrieve is a helper method to define mock.On call
//   - ctx
//   - userID
//   - patID
func (_e *PATSRepository_Expecter) Retrieve(ctx interface{}, userID interface{}, patID interface{}) *PATSRepository_Retrieve_Call {
	return &PATSRepository_Retrieve_Call{Call: _e.mock.On("Retrieve", ctx, userID, patID)}
}

func (_c *PATSRepository_Retrieve_Call) Run(run func(ctx context.Context, userID string, patID string)) *PATSRepository_Retrieve_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *PATSRepository_Retrieve_Call) Return(pat auth.PAT, err error) *PATSRepository_Retrieve_Call {
	_c.Call.Return(pat, err)
	return _c
}

func (_c *PATSRepository_Retrieve_Call) RunAndReturn(run func(ctx context.Context, userID string, patID string) (auth.PAT, error)) *PATSRepository_Retrieve_Call {
	_c.Call.Return(run)
	return _c
}

// RetrieveAll provides a mock function for the type PATSRepository
func (_mock *PATSRepository) RetrieveAll(ctx context.Context, userID string, pm auth.PATSPageMeta) (auth.PATSPage, error) {
	ret := _mock.Called(ctx, userID, pm)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveAll")
	}

	var r0 auth.PATSPage
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, auth.PATSPageMeta) (auth.PATSPage, error)); ok {
		return returnFunc(ctx, userID, pm)
	}
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, auth.PATSPageMeta) auth.PATSPage); ok {
		r0 = returnFunc(ctx, userID, pm)
	} else {
		r0 = ret.Get(0).(auth.PATSPage)
	}
	if returnFunc, ok := ret.Get(1).(func(context.Context, string, auth.PATSPageMeta) error); ok {
		r1 = returnFunc(ctx, userID, pm)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// PATSRepository_RetrieveAll_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RetrieveAll'
type PATSRepository_RetrieveAll_Call struct {
	*mock.Call
}

// RetrieveAll is a helper method to define mock.On call
//   - ctx
//   - userID
//   - pm
func (_e *PATSRepository_Expecter) RetrieveAll(ctx interface{}, userID interface{}, pm interface{}) *PATSRepository_RetrieveAll_Call {
	return &PATSRepository_RetrieveAll_Call{Call: _e.mock.On("RetrieveAll", ctx, userID, pm)}
}

func (_c *PATSRepository_RetrieveAll_Call) Run(run func(ctx context.Context, userID string, pm auth.PATSPageMeta)) *PATSRepository_RetrieveAll_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(auth.PATSPageMeta))
	})
	return _c
}

func (_c *PATSRepository_RetrieveAll_Call) Return(pats auth.PATSPage, err error) *PATSRepository_RetrieveAll_Call {
	_c.Call.Return(pats, err)
	return _c
}

func (_c *PATSRepository_RetrieveAll_Call) RunAndReturn(run func(ctx context.Context, userID string, pm auth.PATSPageMeta) (auth.PATSPage, error)) *PATSRepository_RetrieveAll_Call {
	_c.Call.Return(run)
	return _c
}

// RetrieveScope provides a mock function for the type PATSRepository
func (_mock *PATSRepository) RetrieveScope(ctx context.Context, pm auth.ScopesPageMeta) (auth.ScopesPage, error) {
	ret := _mock.Called(ctx, pm)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveScope")
	}

	var r0 auth.ScopesPage
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, auth.ScopesPageMeta) (auth.ScopesPage, error)); ok {
		return returnFunc(ctx, pm)
	}
	if returnFunc, ok := ret.Get(0).(func(context.Context, auth.ScopesPageMeta) auth.ScopesPage); ok {
		r0 = returnFunc(ctx, pm)
	} else {
		r0 = ret.Get(0).(auth.ScopesPage)
	}
	if returnFunc, ok := ret.Get(1).(func(context.Context, auth.ScopesPageMeta) error); ok {
		r1 = returnFunc(ctx, pm)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// PATSRepository_RetrieveScope_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RetrieveScope'
type PATSRepository_RetrieveScope_Call struct {
	*mock.Call
}

// RetrieveScope is a helper method to define mock.On call
//   - ctx
//   - pm
func (_e *PATSRepository_Expecter) RetrieveScope(ctx interface{}, pm interface{}) *PATSRepository_RetrieveScope_Call {
	return &PATSRepository_RetrieveScope_Call{Call: _e.mock.On("RetrieveScope", ctx, pm)}
}

func (_c *PATSRepository_RetrieveScope_Call) Run(run func(ctx context.Context, pm auth.ScopesPageMeta)) *PATSRepository_RetrieveScope_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(auth.ScopesPageMeta))
	})
	return _c
}

func (_c *PATSRepository_RetrieveScope_Call) Return(scopes auth.ScopesPage, err error) *PATSRepository_RetrieveScope_Call {
	_c.Call.Return(scopes, err)
	return _c
}

func (_c *PATSRepository_RetrieveScope_Call) RunAndReturn(run func(ctx context.Context, pm auth.ScopesPageMeta) (auth.ScopesPage, error)) *PATSRepository_RetrieveScope_Call {
	_c.Call.Return(run)
	return _c
}

// RetrieveSecretAndRevokeStatus provides a mock function for the type PATSRepository
func (_mock *PATSRepository) RetrieveSecretAndRevokeStatus(ctx context.Context, userID string, patID string) (string, bool, bool, error) {
	ret := _mock.Called(ctx, userID, patID)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveSecretAndRevokeStatus")
	}

	var r0 string
	var r1 bool
	var r2 bool
	var r3 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, string) (string, bool, bool, error)); ok {
		return returnFunc(ctx, userID, patID)
	}
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, string) string); ok {
		r0 = returnFunc(ctx, userID, patID)
	} else {
		r0 = ret.Get(0).(string)
	}
	if returnFunc, ok := ret.Get(1).(func(context.Context, string, string) bool); ok {
		r1 = returnFunc(ctx, userID, patID)
	} else {
		r1 = ret.Get(1).(bool)
	}
	if returnFunc, ok := ret.Get(2).(func(context.Context, string, string) bool); ok {
		r2 = returnFunc(ctx, userID, patID)
	} else {
		r2 = ret.Get(2).(bool)
	}
	if returnFunc, ok := ret.Get(3).(func(context.Context, string, string) error); ok {
		r3 = returnFunc(ctx, userID, patID)
	} else {
		r3 = ret.Error(3)
	}
	return r0, r1, r2, r3
}

// PATSRepository_RetrieveSecretAndRevokeStatus_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RetrieveSecretAndRevokeStatus'
type PATSRepository_RetrieveSecretAndRevokeStatus_Call struct {
	*mock.Call
}

// RetrieveSecretAndRevokeStatus is a helper method to define mock.On call
//   - ctx
//   - userID
//   - patID
func (_e *PATSRepository_Expecter) RetrieveSecretAndRevokeStatus(ctx interface{}, userID interface{}, patID interface{}) *PATSRepository_RetrieveSecretAndRevokeStatus_Call {
	return &PATSRepository_RetrieveSecretAndRevokeStatus_Call{Call: _e.mock.On("RetrieveSecretAndRevokeStatus", ctx, userID, patID)}
}

func (_c *PATSRepository_RetrieveSecretAndRevokeStatus_Call) Run(run func(ctx context.Context, userID string, patID string)) *PATSRepository_RetrieveSecretAndRevokeStatus_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *PATSRepository_RetrieveSecretAndRevokeStatus_Call) Return(s string, b bool, b1 bool, err error) *PATSRepository_RetrieveSecretAndRevokeStatus_Call {
	_c.Call.Return(s, b, b1, err)
	return _c
}

func (_c *PATSRepository_RetrieveSecretAndRevokeStatus_Call) RunAndReturn(run func(ctx context.Context, userID string, patID string) (string, bool, bool, error)) *PATSRepository_RetrieveSecretAndRevokeStatus_Call {
	_c.Call.Return(run)
	return _c
}

// Revoke provides a mock function for the type PATSRepository
func (_mock *PATSRepository) Revoke(ctx context.Context, userID string, patID string) error {
	ret := _mock.Called(ctx, userID, patID)

	if len(ret) == 0 {
		panic("no return value specified for Revoke")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = returnFunc(ctx, userID, patID)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// PATSRepository_Revoke_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Revoke'
type PATSRepository_Revoke_Call struct {
	*mock.Call
}

// Revoke is a helper method to define mock.On call
//   - ctx
//   - userID
//   - patID
func (_e *PATSRepository_Expecter) Revoke(ctx interface{}, userID interface{}, patID interface{}) *PATSRepository_Revoke_Call {
	return &PATSRepository_Revoke_Call{Call: _e.mock.On("Revoke", ctx, userID, patID)}
}

func (_c *PATSRepository_Revoke_Call) Run(run func(ctx context.Context, userID string, patID string)) *PATSRepository_Revoke_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *PATSRepository_Revoke_Call) Return(err error) *PATSRepository_Revoke_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *PATSRepository_Revoke_Call) RunAndReturn(run func(ctx context.Context, userID string, patID string) error) *PATSRepository_Revoke_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function for the type PATSRepository
func (_mock *PATSRepository) Save(ctx context.Context, pat auth.PAT) error {
	ret := _mock.Called(ctx, pat)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, auth.PAT) error); ok {
		r0 = returnFunc(ctx, pat)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// PATSRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type PATSRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - ctx
//   - pat
func (_e *PATSRepository_Expecter) Save(ctx interface{}, pat interface{}) *PATSRepository_Save_Call {
	return &PATSRepository_Save_Call{Call: _e.mock.On("Save", ctx, pat)}
}

func (_c *PATSRepository_Save_Call) Run(run func(ctx context.Context, pat auth.PAT)) *PATSRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(auth.PAT))
	})
	return _c
}

func (_c *PATSRepository_Save_Call) Return(err error) *PATSRepository_Save_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *PATSRepository_Save_Call) RunAndReturn(run func(ctx context.Context, pat auth.PAT) error) *PATSRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateDescription provides a mock function for the type PATSRepository
func (_mock *PATSRepository) UpdateDescription(ctx context.Context, userID string, patID string, description string) (auth.PAT, error) {
	ret := _mock.Called(ctx, userID, patID, description)

	if len(ret) == 0 {
		panic("no return value specified for UpdateDescription")
	}

	var r0 auth.PAT
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, string, string) (auth.PAT, error)); ok {
		return returnFunc(ctx, userID, patID, description)
	}
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, string, string) auth.PAT); ok {
		r0 = returnFunc(ctx, userID, patID, description)
	} else {
		r0 = ret.Get(0).(auth.PAT)
	}
	if returnFunc, ok := ret.Get(1).(func(context.Context, string, string, string) error); ok {
		r1 = returnFunc(ctx, userID, patID, description)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// PATSRepository_UpdateDescription_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateDescription'
type PATSRepository_UpdateDescription_Call struct {
	*mock.Call
}

// UpdateDescription is a helper method to define mock.On call
//   - ctx
//   - userID
//   - patID
//   - description
func (_e *PATSRepository_Expecter) UpdateDescription(ctx interface{}, userID interface{}, patID interface{}, description interface{}) *PATSRepository_UpdateDescription_Call {
	return &PATSRepository_UpdateDescription_Call{Call: _e.mock.On("UpdateDescription", ctx, userID, patID, description)}
}

func (_c *PATSRepository_UpdateDescription_Call) Run(run func(ctx context.Context, userID string, patID string, description string)) *PATSRepository_UpdateDescription_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].(string))
	})
	return _c
}

func (_c *PATSRepository_UpdateDescription_Call) Return(pAT auth.PAT, err error) *PATSRepository_UpdateDescription_Call {
	_c.Call.Return(pAT, err)
	return _c
}

func (_c *PATSRepository_UpdateDescription_Call) RunAndReturn(run func(ctx context.Context, userID string, patID string, description string) (auth.PAT, error)) *PATSRepository_UpdateDescription_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateName provides a mock function for the type PATSRepository
func (_mock *PATSRepository) UpdateName(ctx context.Context, userID string, patID string, name string) (auth.PAT, error) {
	ret := _mock.Called(ctx, userID, patID, name)

	if len(ret) == 0 {
		panic("no return value specified for UpdateName")
	}

	var r0 auth.PAT
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, string, string) (auth.PAT, error)); ok {
		return returnFunc(ctx, userID, patID, name)
	}
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, string, string) auth.PAT); ok {
		r0 = returnFunc(ctx, userID, patID, name)
	} else {
		r0 = ret.Get(0).(auth.PAT)
	}
	if returnFunc, ok := ret.Get(1).(func(context.Context, string, string, string) error); ok {
		r1 = returnFunc(ctx, userID, patID, name)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// PATSRepository_UpdateName_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateName'
type PATSRepository_UpdateName_Call struct {
	*mock.Call
}

// UpdateName is a helper method to define mock.On call
//   - ctx
//   - userID
//   - patID
//   - name
func (_e *PATSRepository_Expecter) UpdateName(ctx interface{}, userID interface{}, patID interface{}, name interface{}) *PATSRepository_UpdateName_Call {
	return &PATSRepository_UpdateName_Call{Call: _e.mock.On("UpdateName", ctx, userID, patID, name)}
}

func (_c *PATSRepository_UpdateName_Call) Run(run func(ctx context.Context, userID string, patID string, name string)) *PATSRepository_UpdateName_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].(string))
	})
	return _c
}

func (_c *PATSRepository_UpdateName_Call) Return(pAT auth.PAT, err error) *PATSRepository_UpdateName_Call {
	_c.Call.Return(pAT, err)
	return _c
}

func (_c *PATSRepository_UpdateName_Call) RunAndReturn(run func(ctx context.Context, userID string, patID string, name string) (auth.PAT, error)) *PATSRepository_UpdateName_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateTokenHash provides a mock function for the type PATSRepository
func (_mock *PATSRepository) UpdateTokenHash(ctx context.Context, userID string, patID string, tokenHash string, expiryAt time.Time) (auth.PAT, error) {
	ret := _mock.Called(ctx, userID, patID, tokenHash, expiryAt)

	if len(ret) == 0 {
		panic("no return value specified for UpdateTokenHash")
	}

	var r0 auth.PAT
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, string, string, time.Time) (auth.PAT, error)); ok {
		return returnFunc(ctx, userID, patID, tokenHash, expiryAt)
	}
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, string, string, time.Time) auth.PAT); ok {
		r0 = returnFunc(ctx, userID, patID, tokenHash, expiryAt)
	} else {
		r0 = ret.Get(0).(auth.PAT)
	}
	if returnFunc, ok := ret.Get(1).(func(context.Context, string, string, string, time.Time) error); ok {
		r1 = returnFunc(ctx, userID, patID, tokenHash, expiryAt)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// PATSRepository_UpdateTokenHash_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateTokenHash'
type PATSRepository_UpdateTokenHash_Call struct {
	*mock.Call
}

// UpdateTokenHash is a helper method to define mock.On call
//   - ctx
//   - userID
//   - patID
//   - tokenHash
//   - expiryAt
func (_e *PATSRepository_Expecter) UpdateTokenHash(ctx interface{}, userID interface{}, patID interface{}, tokenHash interface{}, expiryAt interface{}) *PATSRepository_UpdateTokenHash_Call {
	return &PATSRepository_UpdateTokenHash_Call{Call: _e.mock.On("UpdateTokenHash", ctx, userID, patID, tokenHash, expiryAt)}
}

func (_c *PATSRepository_UpdateTokenHash_Call) Run(run func(ctx context.Context, userID string, patID string, tokenHash string, expiryAt time.Time)) *PATSRepository_UpdateTokenHash_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].(string), args[4].(time.Time))
	})
	return _c
}

func (_c *PATSRepository_UpdateTokenHash_Call) Return(pAT auth.PAT, err error) *PATSRepository_UpdateTokenHash_Call {
	_c.Call.Return(pAT, err)
	return _c
}

func (_c *PATSRepository_UpdateTokenHash_Call) RunAndReturn(run func(ctx context.Context, userID string, patID string, tokenHash string, expiryAt time.Time) (auth.PAT, error)) *PATSRepository_UpdateTokenHash_Call {
	_c.Call.Return(run)
	return _c
}
