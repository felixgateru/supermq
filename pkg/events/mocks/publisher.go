// Code generated by mockery; DO NOT EDIT.
// github.com/vektra/mockery
// template: testify
// Copyright (c) Abstract Machines

// SPDX-License-Identifier: Apache-2.0

package mocks

import (
	"context"

	"github.com/absmach/supermq/pkg/events"
	mock "github.com/stretchr/testify/mock"
)

// NewPublisher creates a new instance of Publisher. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewPublisher(t interface {
	mock.TestingT
	Cleanup(func())
}) *Publisher {
	mock := &Publisher{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

// Publisher is an autogenerated mock type for the Publisher type
type Publisher struct {
	mock.Mock
}

type Publisher_Expecter struct {
	mock *mock.Mock
}

func (_m *Publisher) EXPECT() *Publisher_Expecter {
	return &Publisher_Expecter{mock: &_m.Mock}
}

// Close provides a mock function for the type Publisher
func (_mock *Publisher) Close() error {
	ret := _mock.Called()

	if len(ret) == 0 {
		panic("no return value specified for Close")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func() error); ok {
		r0 = returnFunc()
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// Publisher_Close_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Close'
type Publisher_Close_Call struct {
	*mock.Call
}

// Close is a helper method to define mock.On call
func (_e *Publisher_Expecter) Close() *Publisher_Close_Call {
	return &Publisher_Close_Call{Call: _e.mock.On("Close")}
}

func (_c *Publisher_Close_Call) Run(run func()) *Publisher_Close_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Publisher_Close_Call) Return(err error) *Publisher_Close_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *Publisher_Close_Call) RunAndReturn(run func() error) *Publisher_Close_Call {
	_c.Call.Return(run)
	return _c
}

// Publish provides a mock function for the type Publisher
func (_mock *Publisher) Publish(ctx context.Context, stream string, event events.Event) error {
	ret := _mock.Called(ctx, stream, event)

	if len(ret) == 0 {
		panic("no return value specified for Publish")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, events.Event) error); ok {
		r0 = returnFunc(ctx, stream, event)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// Publisher_Publish_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Publish'
type Publisher_Publish_Call struct {
	*mock.Call
}

// Publish is a helper method to define mock.On call
//   - ctx
//   - stream
//   - event
func (_e *Publisher_Expecter) Publish(ctx interface{}, stream interface{}, event interface{}) *Publisher_Publish_Call {
	return &Publisher_Publish_Call{Call: _e.mock.On("Publish", ctx, stream, event)}
}

func (_c *Publisher_Publish_Call) Run(run func(ctx context.Context, stream string, event events.Event)) *Publisher_Publish_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(events.Event))
	})
	return _c
}

func (_c *Publisher_Publish_Call) Return(err error) *Publisher_Publish_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *Publisher_Publish_Call) RunAndReturn(run func(ctx context.Context, stream string, event events.Event) error) *Publisher_Publish_Call {
	_c.Call.Return(run)
	return _c
}
