// Code generated by mockery v2.38.0. DO NOT EDIT.

// Copyright (c) Abstract Machines

package mocks

import (
	context "context"

	auth "github.com/absmach/magistrala/auth"

	mock "github.com/stretchr/testify/mock"
)

// DomainsRepository is an autogenerated mock type for the DomainsRepository type
type DomainsRepository struct {
	mock.Mock
}

// Delete provides a mock function with given fields: ctx, id
func (_m *DomainsRepository) Delete(ctx context.Context, id string) error {
	ret := _m.Called(ctx, id)

	if len(ret) == 0 {
		panic("no return value specified for Delete")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeletePolicies provides a mock function with given fields: ctx, pcs
func (_m *DomainsRepository) DeletePolicies(ctx context.Context, pcs ...auth.Policy) error {
	_va := make([]interface{}, len(pcs))
	for _i := range pcs {
		_va[_i] = pcs[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for DeletePolicies")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, ...auth.Policy) error); ok {
		r0 = rf(ctx, pcs...)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ListDomains provides a mock function with given fields: ctx, pm
func (_m *DomainsRepository) ListDomains(ctx context.Context, pm auth.Page) (auth.DomainsPage, error) {
	ret := _m.Called(ctx, pm)

	if len(ret) == 0 {
		panic("no return value specified for ListDomains")
	}

	var r0 auth.DomainsPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, auth.Page) (auth.DomainsPage, error)); ok {
		return rf(ctx, pm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, auth.Page) auth.DomainsPage); ok {
		r0 = rf(ctx, pm)
	} else {
		r0 = ret.Get(0).(auth.DomainsPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, auth.Page) error); ok {
		r1 = rf(ctx, pm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveAllByIDs provides a mock function with given fields: ctx, pm
func (_m *DomainsRepository) RetrieveAllByIDs(ctx context.Context, pm auth.Page) (auth.DomainsPage, error) {
	ret := _m.Called(ctx, pm)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveAllByIDs")
	}

	var r0 auth.DomainsPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, auth.Page) (auth.DomainsPage, error)); ok {
		return rf(ctx, pm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, auth.Page) auth.DomainsPage); ok {
		r0 = rf(ctx, pm)
	} else {
		r0 = ret.Get(0).(auth.DomainsPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, auth.Page) error); ok {
		r1 = rf(ctx, pm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveByID provides a mock function with given fields: ctx, id
func (_m *DomainsRepository) RetrieveByID(ctx context.Context, id string) (auth.Domain, error) {
	ret := _m.Called(ctx, id)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveByID")
	}

	var r0 auth.Domain
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (auth.Domain, error)); ok {
		return rf(ctx, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) auth.Domain); ok {
		r0 = rf(ctx, id)
	} else {
		r0 = ret.Get(0).(auth.Domain)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrievePermissions provides a mock function with given fields: ctx, subject, id
func (_m *DomainsRepository) RetrievePermissions(ctx context.Context, subject string, id string) ([]string, error) {
	ret := _m.Called(ctx, subject, id)

	if len(ret) == 0 {
		panic("no return value specified for RetrievePermissions")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) ([]string, error)); ok {
		return rf(ctx, subject, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) []string); ok {
		r0 = rf(ctx, subject, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, subject, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Save provides a mock function with given fields: ctx, d
func (_m *DomainsRepository) Save(ctx context.Context, d auth.Domain) (auth.Domain, error) {
	ret := _m.Called(ctx, d)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 auth.Domain
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, auth.Domain) (auth.Domain, error)); ok {
		return rf(ctx, d)
	}
	if rf, ok := ret.Get(0).(func(context.Context, auth.Domain) auth.Domain); ok {
		r0 = rf(ctx, d)
	} else {
		r0 = ret.Get(0).(auth.Domain)
	}

	if rf, ok := ret.Get(1).(func(context.Context, auth.Domain) error); ok {
		r1 = rf(ctx, d)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SavePolicies provides a mock function with given fields: ctx, pcs
func (_m *DomainsRepository) SavePolicies(ctx context.Context, pcs ...auth.Policy) error {
	_va := make([]interface{}, len(pcs))
	for _i := range pcs {
		_va[_i] = pcs[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for SavePolicies")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, ...auth.Policy) error); ok {
		r0 = rf(ctx, pcs...)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Update provides a mock function with given fields: ctx, id, userID, d
func (_m *DomainsRepository) Update(ctx context.Context, id string, userID string, d auth.DomainReq) (auth.Domain, error) {
	ret := _m.Called(ctx, id, userID, d)

	if len(ret) == 0 {
		panic("no return value specified for Update")
	}

	var r0 auth.Domain
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, auth.DomainReq) (auth.Domain, error)); ok {
		return rf(ctx, id, userID, d)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, auth.DomainReq) auth.Domain); ok {
		r0 = rf(ctx, id, userID, d)
	} else {
		r0 = ret.Get(0).(auth.Domain)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, auth.DomainReq) error); ok {
		r1 = rf(ctx, id, userID, d)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewDomainsRepository creates a new instance of DomainsRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewDomainsRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *DomainsRepository {
	mock := &DomainsRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
