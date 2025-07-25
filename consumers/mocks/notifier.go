// Code generated by mockery; DO NOT EDIT.
// github.com/vektra/mockery
// template: testify
// Copyright (c) Abstract Machines

// SPDX-License-Identifier: Apache-2.0

package mocks

import (
	"github.com/absmach/supermq/pkg/messaging"
	mock "github.com/stretchr/testify/mock"
)

// NewNotifier creates a new instance of Notifier. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewNotifier(t interface {
	mock.TestingT
	Cleanup(func())
}) *Notifier {
	mock := &Notifier{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

// Notifier is an autogenerated mock type for the Notifier type
type Notifier struct {
	mock.Mock
}

type Notifier_Expecter struct {
	mock *mock.Mock
}

func (_m *Notifier) EXPECT() *Notifier_Expecter {
	return &Notifier_Expecter{mock: &_m.Mock}
}

// Notify provides a mock function for the type Notifier
func (_mock *Notifier) Notify(from string, to []string, msg *messaging.Message) error {
	ret := _mock.Called(from, to, msg)

	if len(ret) == 0 {
		panic("no return value specified for Notify")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(string, []string, *messaging.Message) error); ok {
		r0 = returnFunc(from, to, msg)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// Notifier_Notify_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Notify'
type Notifier_Notify_Call struct {
	*mock.Call
}

// Notify is a helper method to define mock.On call
//   - from string
//   - to []string
//   - msg *messaging.Message
func (_e *Notifier_Expecter) Notify(from interface{}, to interface{}, msg interface{}) *Notifier_Notify_Call {
	return &Notifier_Notify_Call{Call: _e.mock.On("Notify", from, to, msg)}
}

func (_c *Notifier_Notify_Call) Run(run func(from string, to []string, msg *messaging.Message)) *Notifier_Notify_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 string
		if args[0] != nil {
			arg0 = args[0].(string)
		}
		var arg1 []string
		if args[1] != nil {
			arg1 = args[1].([]string)
		}
		var arg2 *messaging.Message
		if args[2] != nil {
			arg2 = args[2].(*messaging.Message)
		}
		run(
			arg0,
			arg1,
			arg2,
		)
	})
	return _c
}

func (_c *Notifier_Notify_Call) Return(err error) *Notifier_Notify_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *Notifier_Notify_Call) RunAndReturn(run func(from string, to []string, msg *messaging.Message) error) *Notifier_Notify_Call {
	_c.Call.Return(run)
	return _c
}
