// Code generated by mockery v2.43.2. DO NOT EDIT.

// Copyright (c) Abstract Machines

package mocks

import (
	context "context"

	clients "github.com/absmach/supermq/clients"

	mock "github.com/stretchr/testify/mock"

	roles "github.com/absmach/supermq/pkg/roles"
)

// Repository is an autogenerated mock type for the Repository type
type Repository struct {
	mock.Mock
}

// AddConnections provides a mock function with given fields: ctx, conns
func (_m *Repository) AddConnections(ctx context.Context, conns []clients.Connection) error {
	ret := _m.Called(ctx, conns)

	if len(ret) == 0 {
		panic("no return value specified for AddConnections")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, []clients.Connection) error); ok {
		r0 = rf(ctx, conns)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AddRoles provides a mock function with given fields: ctx, rps
func (_m *Repository) AddRoles(ctx context.Context, rps []roles.RoleProvision) ([]roles.RoleProvision, error) {
	ret := _m.Called(ctx, rps)

	if len(ret) == 0 {
		panic("no return value specified for AddRoles")
	}

	var r0 []roles.RoleProvision
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, []roles.RoleProvision) ([]roles.RoleProvision, error)); ok {
		return rf(ctx, rps)
	}
	if rf, ok := ret.Get(0).(func(context.Context, []roles.RoleProvision) []roles.RoleProvision); ok {
		r0 = rf(ctx, rps)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]roles.RoleProvision)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, []roles.RoleProvision) error); ok {
		r1 = rf(ctx, rps)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ChangeStatus provides a mock function with given fields: ctx, client
func (_m *Repository) ChangeStatus(ctx context.Context, client clients.Client) (clients.Client, error) {
	ret := _m.Called(ctx, client)

	if len(ret) == 0 {
		panic("no return value specified for ChangeStatus")
	}

	var r0 clients.Client
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, clients.Client) (clients.Client, error)); ok {
		return rf(ctx, client)
	}
	if rf, ok := ret.Get(0).(func(context.Context, clients.Client) clients.Client); ok {
		r0 = rf(ctx, client)
	} else {
		r0 = ret.Get(0).(clients.Client)
	}

	if rf, ok := ret.Get(1).(func(context.Context, clients.Client) error); ok {
		r1 = rf(ctx, client)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ClientConnectionsCount provides a mock function with given fields: ctx, id
func (_m *Repository) ClientConnectionsCount(ctx context.Context, id string) (uint64, error) {
	ret := _m.Called(ctx, id)

	if len(ret) == 0 {
		panic("no return value specified for ClientConnectionsCount")
	}

	var r0 uint64
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (uint64, error)); ok {
		return rf(ctx, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) uint64); ok {
		r0 = rf(ctx, id)
	} else {
		r0 = ret.Get(0).(uint64)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Delete provides a mock function with given fields: ctx, clientIDs
func (_m *Repository) Delete(ctx context.Context, clientIDs ...string) error {
	_va := make([]interface{}, len(clientIDs))
	for _i := range clientIDs {
		_va[_i] = clientIDs[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for Delete")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, ...string) error); ok {
		r0 = rf(ctx, clientIDs...)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DoesClientHaveConnections provides a mock function with given fields: ctx, id
func (_m *Repository) DoesClientHaveConnections(ctx context.Context, id string) (bool, error) {
	ret := _m.Called(ctx, id)

	if len(ret) == 0 {
		panic("no return value specified for DoesClientHaveConnections")
	}

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (bool, error)); ok {
		return rf(ctx, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) bool); ok {
		r0 = rf(ctx, id)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListEntityMembers provides a mock function with given fields: ctx, entityID, pageQuery
func (_m *Repository) ListEntityMembers(ctx context.Context, entityID string, pageQuery roles.MembersRolePageQuery) (roles.MembersRolePage, error) {
	ret := _m.Called(ctx, entityID, pageQuery)

	if len(ret) == 0 {
		panic("no return value specified for ListEntityMembers")
	}

	var r0 roles.MembersRolePage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, roles.MembersRolePageQuery) (roles.MembersRolePage, error)); ok {
		return rf(ctx, entityID, pageQuery)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, roles.MembersRolePageQuery) roles.MembersRolePage); ok {
		r0 = rf(ctx, entityID, pageQuery)
	} else {
		r0 = ret.Get(0).(roles.MembersRolePage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, roles.MembersRolePageQuery) error); ok {
		r1 = rf(ctx, entityID, pageQuery)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RemoveChannelConnections provides a mock function with given fields: ctx, channelID
func (_m *Repository) RemoveChannelConnections(ctx context.Context, channelID string) error {
	ret := _m.Called(ctx, channelID)

	if len(ret) == 0 {
		panic("no return value specified for RemoveChannelConnections")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, channelID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveClientConnections provides a mock function with given fields: ctx, clientID
func (_m *Repository) RemoveClientConnections(ctx context.Context, clientID string) error {
	ret := _m.Called(ctx, clientID)

	if len(ret) == 0 {
		panic("no return value specified for RemoveClientConnections")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, clientID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveConnections provides a mock function with given fields: ctx, conns
func (_m *Repository) RemoveConnections(ctx context.Context, conns []clients.Connection) error {
	ret := _m.Called(ctx, conns)

	if len(ret) == 0 {
		panic("no return value specified for RemoveConnections")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, []clients.Connection) error); ok {
		r0 = rf(ctx, conns)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveEntityMembers provides a mock function with given fields: ctx, entityID, members
func (_m *Repository) RemoveEntityMembers(ctx context.Context, entityID string, members []string) error {
	ret := _m.Called(ctx, entityID, members)

	if len(ret) == 0 {
		panic("no return value specified for RemoveEntityMembers")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, []string) error); ok {
		r0 = rf(ctx, entityID, members)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveMemberFromAllRoles provides a mock function with given fields: ctx, memberID
func (_m *Repository) RemoveMemberFromAllRoles(ctx context.Context, memberID string) error {
	ret := _m.Called(ctx, memberID)

	if len(ret) == 0 {
		panic("no return value specified for RemoveMemberFromAllRoles")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, memberID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveParentGroup provides a mock function with given fields: ctx, cli
func (_m *Repository) RemoveParentGroup(ctx context.Context, cli clients.Client) error {
	ret := _m.Called(ctx, cli)

	if len(ret) == 0 {
		panic("no return value specified for RemoveParentGroup")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, clients.Client) error); ok {
		r0 = rf(ctx, cli)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveRoles provides a mock function with given fields: ctx, roleIDs
func (_m *Repository) RemoveRoles(ctx context.Context, roleIDs []string) error {
	ret := _m.Called(ctx, roleIDs)

	if len(ret) == 0 {
		panic("no return value specified for RemoveRoles")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, []string) error); ok {
		r0 = rf(ctx, roleIDs)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RetrieveAll provides a mock function with given fields: ctx, pm
func (_m *Repository) RetrieveAll(ctx context.Context, pm clients.Page) (clients.ClientsPage, error) {
	ret := _m.Called(ctx, pm)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveAll")
	}

	var r0 clients.ClientsPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, clients.Page) (clients.ClientsPage, error)); ok {
		return rf(ctx, pm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, clients.Page) clients.ClientsPage); ok {
		r0 = rf(ctx, pm)
	} else {
		r0 = ret.Get(0).(clients.ClientsPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, clients.Page) error); ok {
		r1 = rf(ctx, pm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveAllRoles provides a mock function with given fields: ctx, entityID, limit, offset
func (_m *Repository) RetrieveAllRoles(ctx context.Context, entityID string, limit uint64, offset uint64) (roles.RolePage, error) {
	ret := _m.Called(ctx, entityID, limit, offset)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveAllRoles")
	}

	var r0 roles.RolePage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, uint64, uint64) (roles.RolePage, error)); ok {
		return rf(ctx, entityID, limit, offset)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, uint64, uint64) roles.RolePage); ok {
		r0 = rf(ctx, entityID, limit, offset)
	} else {
		r0 = ret.Get(0).(roles.RolePage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, uint64, uint64) error); ok {
		r1 = rf(ctx, entityID, limit, offset)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveByID provides a mock function with given fields: ctx, id
func (_m *Repository) RetrieveByID(ctx context.Context, id string) (clients.Client, error) {
	ret := _m.Called(ctx, id)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveByID")
	}

	var r0 clients.Client
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (clients.Client, error)); ok {
		return rf(ctx, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) clients.Client); ok {
		r0 = rf(ctx, id)
	} else {
		r0 = ret.Get(0).(clients.Client)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveByIDWithRoles provides a mock function with given fields: ctx, id, memberID
func (_m *Repository) RetrieveByIDWithRoles(ctx context.Context, id string, memberID string) (clients.Client, error) {
	ret := _m.Called(ctx, id, memberID)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveByIDWithRoles")
	}

	var r0 clients.Client
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (clients.Client, error)); ok {
		return rf(ctx, id, memberID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) clients.Client); ok {
		r0 = rf(ctx, id, memberID)
	} else {
		r0 = ret.Get(0).(clients.Client)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, id, memberID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveByIds provides a mock function with given fields: ctx, ids
func (_m *Repository) RetrieveByIds(ctx context.Context, ids []string) (clients.ClientsPage, error) {
	ret := _m.Called(ctx, ids)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveByIds")
	}

	var r0 clients.ClientsPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, []string) (clients.ClientsPage, error)); ok {
		return rf(ctx, ids)
	}
	if rf, ok := ret.Get(0).(func(context.Context, []string) clients.ClientsPage); ok {
		r0 = rf(ctx, ids)
	} else {
		r0 = ret.Get(0).(clients.ClientsPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, []string) error); ok {
		r1 = rf(ctx, ids)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveBySecret provides a mock function with given fields: ctx, key
func (_m *Repository) RetrieveBySecret(ctx context.Context, key string) (clients.Client, error) {
	ret := _m.Called(ctx, key)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveBySecret")
	}

	var r0 clients.Client
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (clients.Client, error)); ok {
		return rf(ctx, key)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) clients.Client); ok {
		r0 = rf(ctx, key)
	} else {
		r0 = ret.Get(0).(clients.Client)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, key)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveEntitiesRolesActionsMembers provides a mock function with given fields: ctx, entityIDs
func (_m *Repository) RetrieveEntitiesRolesActionsMembers(ctx context.Context, entityIDs []string) ([]roles.EntityActionRole, []roles.EntityMemberRole, error) {
	ret := _m.Called(ctx, entityIDs)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveEntitiesRolesActionsMembers")
	}

	var r0 []roles.EntityActionRole
	var r1 []roles.EntityMemberRole
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, []string) ([]roles.EntityActionRole, []roles.EntityMemberRole, error)); ok {
		return rf(ctx, entityIDs)
	}
	if rf, ok := ret.Get(0).(func(context.Context, []string) []roles.EntityActionRole); ok {
		r0 = rf(ctx, entityIDs)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]roles.EntityActionRole)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, []string) []roles.EntityMemberRole); ok {
		r1 = rf(ctx, entityIDs)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).([]roles.EntityMemberRole)
		}
	}

	if rf, ok := ret.Get(2).(func(context.Context, []string) error); ok {
		r2 = rf(ctx, entityIDs)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// RetrieveEntityRole provides a mock function with given fields: ctx, entityID, roleID
func (_m *Repository) RetrieveEntityRole(ctx context.Context, entityID string, roleID string) (roles.Role, error) {
	ret := _m.Called(ctx, entityID, roleID)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveEntityRole")
	}

	var r0 roles.Role
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (roles.Role, error)); ok {
		return rf(ctx, entityID, roleID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) roles.Role); ok {
		r0 = rf(ctx, entityID, roleID)
	} else {
		r0 = ret.Get(0).(roles.Role)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, entityID, roleID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveParentGroupClients provides a mock function with given fields: ctx, parentGroupID
func (_m *Repository) RetrieveParentGroupClients(ctx context.Context, parentGroupID string) ([]clients.Client, error) {
	ret := _m.Called(ctx, parentGroupID)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveParentGroupClients")
	}

	var r0 []clients.Client
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) ([]clients.Client, error)); ok {
		return rf(ctx, parentGroupID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) []clients.Client); ok {
		r0 = rf(ctx, parentGroupID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]clients.Client)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, parentGroupID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveRole provides a mock function with given fields: ctx, roleID
func (_m *Repository) RetrieveRole(ctx context.Context, roleID string) (roles.Role, error) {
	ret := _m.Called(ctx, roleID)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveRole")
	}

	var r0 roles.Role
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (roles.Role, error)); ok {
		return rf(ctx, roleID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) roles.Role); ok {
		r0 = rf(ctx, roleID)
	} else {
		r0 = ret.Get(0).(roles.Role)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, roleID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveUserClients provides a mock function with given fields: ctx, domainID, userID, pm
func (_m *Repository) RetrieveUserClients(ctx context.Context, domainID string, userID string, pm clients.Page) (clients.ClientsPage, error) {
	ret := _m.Called(ctx, domainID, userID, pm)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveUserClients")
	}

	var r0 clients.ClientsPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, clients.Page) (clients.ClientsPage, error)); ok {
		return rf(ctx, domainID, userID, pm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, clients.Page) clients.ClientsPage); ok {
		r0 = rf(ctx, domainID, userID, pm)
	} else {
		r0 = ret.Get(0).(clients.ClientsPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, clients.Page) error); ok {
		r1 = rf(ctx, domainID, userID, pm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleAddActions provides a mock function with given fields: ctx, role, actions
func (_m *Repository) RoleAddActions(ctx context.Context, role roles.Role, actions []string) ([]string, error) {
	ret := _m.Called(ctx, role, actions)

	if len(ret) == 0 {
		panic("no return value specified for RoleAddActions")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, roles.Role, []string) ([]string, error)); ok {
		return rf(ctx, role, actions)
	}
	if rf, ok := ret.Get(0).(func(context.Context, roles.Role, []string) []string); ok {
		r0 = rf(ctx, role, actions)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, roles.Role, []string) error); ok {
		r1 = rf(ctx, role, actions)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleAddMembers provides a mock function with given fields: ctx, role, members
func (_m *Repository) RoleAddMembers(ctx context.Context, role roles.Role, members []string) ([]string, error) {
	ret := _m.Called(ctx, role, members)

	if len(ret) == 0 {
		panic("no return value specified for RoleAddMembers")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, roles.Role, []string) ([]string, error)); ok {
		return rf(ctx, role, members)
	}
	if rf, ok := ret.Get(0).(func(context.Context, roles.Role, []string) []string); ok {
		r0 = rf(ctx, role, members)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, roles.Role, []string) error); ok {
		r1 = rf(ctx, role, members)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleCheckActionsExists provides a mock function with given fields: ctx, roleID, actions
func (_m *Repository) RoleCheckActionsExists(ctx context.Context, roleID string, actions []string) (bool, error) {
	ret := _m.Called(ctx, roleID, actions)

	if len(ret) == 0 {
		panic("no return value specified for RoleCheckActionsExists")
	}

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, []string) (bool, error)); ok {
		return rf(ctx, roleID, actions)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, []string) bool); ok {
		r0 = rf(ctx, roleID, actions)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, []string) error); ok {
		r1 = rf(ctx, roleID, actions)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleCheckMembersExists provides a mock function with given fields: ctx, roleID, members
func (_m *Repository) RoleCheckMembersExists(ctx context.Context, roleID string, members []string) (bool, error) {
	ret := _m.Called(ctx, roleID, members)

	if len(ret) == 0 {
		panic("no return value specified for RoleCheckMembersExists")
	}

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, []string) (bool, error)); ok {
		return rf(ctx, roleID, members)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, []string) bool); ok {
		r0 = rf(ctx, roleID, members)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, []string) error); ok {
		r1 = rf(ctx, roleID, members)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleListActions provides a mock function with given fields: ctx, roleID
func (_m *Repository) RoleListActions(ctx context.Context, roleID string) ([]string, error) {
	ret := _m.Called(ctx, roleID)

	if len(ret) == 0 {
		panic("no return value specified for RoleListActions")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) ([]string, error)); ok {
		return rf(ctx, roleID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) []string); ok {
		r0 = rf(ctx, roleID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, roleID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleListMembers provides a mock function with given fields: ctx, roleID, limit, offset
func (_m *Repository) RoleListMembers(ctx context.Context, roleID string, limit uint64, offset uint64) (roles.MembersPage, error) {
	ret := _m.Called(ctx, roleID, limit, offset)

	if len(ret) == 0 {
		panic("no return value specified for RoleListMembers")
	}

	var r0 roles.MembersPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, uint64, uint64) (roles.MembersPage, error)); ok {
		return rf(ctx, roleID, limit, offset)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, uint64, uint64) roles.MembersPage); ok {
		r0 = rf(ctx, roleID, limit, offset)
	} else {
		r0 = ret.Get(0).(roles.MembersPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, uint64, uint64) error); ok {
		r1 = rf(ctx, roleID, limit, offset)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleRemoveActions provides a mock function with given fields: ctx, role, actions
func (_m *Repository) RoleRemoveActions(ctx context.Context, role roles.Role, actions []string) error {
	ret := _m.Called(ctx, role, actions)

	if len(ret) == 0 {
		panic("no return value specified for RoleRemoveActions")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, roles.Role, []string) error); ok {
		r0 = rf(ctx, role, actions)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RoleRemoveAllActions provides a mock function with given fields: ctx, role
func (_m *Repository) RoleRemoveAllActions(ctx context.Context, role roles.Role) error {
	ret := _m.Called(ctx, role)

	if len(ret) == 0 {
		panic("no return value specified for RoleRemoveAllActions")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, roles.Role) error); ok {
		r0 = rf(ctx, role)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RoleRemoveAllMembers provides a mock function with given fields: ctx, role
func (_m *Repository) RoleRemoveAllMembers(ctx context.Context, role roles.Role) error {
	ret := _m.Called(ctx, role)

	if len(ret) == 0 {
		panic("no return value specified for RoleRemoveAllMembers")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, roles.Role) error); ok {
		r0 = rf(ctx, role)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RoleRemoveMembers provides a mock function with given fields: ctx, role, members
func (_m *Repository) RoleRemoveMembers(ctx context.Context, role roles.Role, members []string) error {
	ret := _m.Called(ctx, role, members)

	if len(ret) == 0 {
		panic("no return value specified for RoleRemoveMembers")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, roles.Role, []string) error); ok {
		r0 = rf(ctx, role, members)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Save provides a mock function with given fields: ctx, client
func (_m *Repository) Save(ctx context.Context, client ...clients.Client) ([]clients.Client, error) {
	_va := make([]interface{}, len(client))
	for _i := range client {
		_va[_i] = client[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 []clients.Client
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, ...clients.Client) ([]clients.Client, error)); ok {
		return rf(ctx, client...)
	}
	if rf, ok := ret.Get(0).(func(context.Context, ...clients.Client) []clients.Client); ok {
		r0 = rf(ctx, client...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]clients.Client)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, ...clients.Client) error); ok {
		r1 = rf(ctx, client...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SearchClients provides a mock function with given fields: ctx, pm
func (_m *Repository) SearchClients(ctx context.Context, pm clients.Page) (clients.ClientsPage, error) {
	ret := _m.Called(ctx, pm)

	if len(ret) == 0 {
		panic("no return value specified for SearchClients")
	}

	var r0 clients.ClientsPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, clients.Page) (clients.ClientsPage, error)); ok {
		return rf(ctx, pm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, clients.Page) clients.ClientsPage); ok {
		r0 = rf(ctx, pm)
	} else {
		r0 = ret.Get(0).(clients.ClientsPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, clients.Page) error); ok {
		r1 = rf(ctx, pm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SetParentGroup provides a mock function with given fields: ctx, cli
func (_m *Repository) SetParentGroup(ctx context.Context, cli clients.Client) error {
	ret := _m.Called(ctx, cli)

	if len(ret) == 0 {
		panic("no return value specified for SetParentGroup")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, clients.Client) error); ok {
		r0 = rf(ctx, cli)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UnsetParentGroupFromClient provides a mock function with given fields: ctx, parentGroupID
func (_m *Repository) UnsetParentGroupFromClient(ctx context.Context, parentGroupID string) error {
	ret := _m.Called(ctx, parentGroupID)

	if len(ret) == 0 {
		panic("no return value specified for UnsetParentGroupFromClient")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, parentGroupID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Update provides a mock function with given fields: ctx, client
func (_m *Repository) Update(ctx context.Context, client clients.Client) (clients.Client, error) {
	ret := _m.Called(ctx, client)

	if len(ret) == 0 {
		panic("no return value specified for Update")
	}

	var r0 clients.Client
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, clients.Client) (clients.Client, error)); ok {
		return rf(ctx, client)
	}
	if rf, ok := ret.Get(0).(func(context.Context, clients.Client) clients.Client); ok {
		r0 = rf(ctx, client)
	} else {
		r0 = ret.Get(0).(clients.Client)
	}

	if rf, ok := ret.Get(1).(func(context.Context, clients.Client) error); ok {
		r1 = rf(ctx, client)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdateIdentity provides a mock function with given fields: ctx, client
func (_m *Repository) UpdateIdentity(ctx context.Context, client clients.Client) (clients.Client, error) {
	ret := _m.Called(ctx, client)

	if len(ret) == 0 {
		panic("no return value specified for UpdateIdentity")
	}

	var r0 clients.Client
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, clients.Client) (clients.Client, error)); ok {
		return rf(ctx, client)
	}
	if rf, ok := ret.Get(0).(func(context.Context, clients.Client) clients.Client); ok {
		r0 = rf(ctx, client)
	} else {
		r0 = ret.Get(0).(clients.Client)
	}

	if rf, ok := ret.Get(1).(func(context.Context, clients.Client) error); ok {
		r1 = rf(ctx, client)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdateRole provides a mock function with given fields: ctx, ro
func (_m *Repository) UpdateRole(ctx context.Context, ro roles.Role) (roles.Role, error) {
	ret := _m.Called(ctx, ro)

	if len(ret) == 0 {
		panic("no return value specified for UpdateRole")
	}

	var r0 roles.Role
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, roles.Role) (roles.Role, error)); ok {
		return rf(ctx, ro)
	}
	if rf, ok := ret.Get(0).(func(context.Context, roles.Role) roles.Role); ok {
		r0 = rf(ctx, ro)
	} else {
		r0 = ret.Get(0).(roles.Role)
	}

	if rf, ok := ret.Get(1).(func(context.Context, roles.Role) error); ok {
		r1 = rf(ctx, ro)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdateSecret provides a mock function with given fields: ctx, client
func (_m *Repository) UpdateSecret(ctx context.Context, client clients.Client) (clients.Client, error) {
	ret := _m.Called(ctx, client)

	if len(ret) == 0 {
		panic("no return value specified for UpdateSecret")
	}

	var r0 clients.Client
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, clients.Client) (clients.Client, error)); ok {
		return rf(ctx, client)
	}
	if rf, ok := ret.Get(0).(func(context.Context, clients.Client) clients.Client); ok {
		r0 = rf(ctx, client)
	} else {
		r0 = ret.Get(0).(clients.Client)
	}

	if rf, ok := ret.Get(1).(func(context.Context, clients.Client) error); ok {
		r1 = rf(ctx, client)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdateTags provides a mock function with given fields: ctx, client
func (_m *Repository) UpdateTags(ctx context.Context, client clients.Client) (clients.Client, error) {
	ret := _m.Called(ctx, client)

	if len(ret) == 0 {
		panic("no return value specified for UpdateTags")
	}

	var r0 clients.Client
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, clients.Client) (clients.Client, error)); ok {
		return rf(ctx, client)
	}
	if rf, ok := ret.Get(0).(func(context.Context, clients.Client) clients.Client); ok {
		r0 = rf(ctx, client)
	} else {
		r0 = ret.Get(0).(clients.Client)
	}

	if rf, ok := ret.Get(1).(func(context.Context, clients.Client) error); ok {
		r1 = rf(ctx, client)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewRepository creates a new instance of Repository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *Repository {
	mock := &Repository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
