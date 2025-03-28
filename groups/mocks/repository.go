// Code generated by mockery v2.43.2. DO NOT EDIT.

// Copyright (c) Abstract Machines

package mocks

import (
	context "context"

	groups "github.com/absmach/supermq/groups"
	mock "github.com/stretchr/testify/mock"

	roles "github.com/absmach/supermq/pkg/roles"
)

// Repository is an autogenerated mock type for the Repository type
type Repository struct {
	mock.Mock
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

// AssignParentGroup provides a mock function with given fields: ctx, parentGroupID, groupIDs
func (_m *Repository) AssignParentGroup(ctx context.Context, parentGroupID string, groupIDs ...string) error {
	ret := _m.Called(ctx, parentGroupID, groupIDs)

	if len(ret) == 0 {
		panic("no return value specified for AssignParentGroup")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, ...string) error); ok {
		r0 = rf(ctx, parentGroupID, groupIDs...)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ChangeStatus provides a mock function with given fields: ctx, group
func (_m *Repository) ChangeStatus(ctx context.Context, group groups.Group) (groups.Group, error) {
	ret := _m.Called(ctx, group)

	if len(ret) == 0 {
		panic("no return value specified for ChangeStatus")
	}

	var r0 groups.Group
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, groups.Group) (groups.Group, error)); ok {
		return rf(ctx, group)
	}
	if rf, ok := ret.Get(0).(func(context.Context, groups.Group) groups.Group); ok {
		r0 = rf(ctx, group)
	} else {
		r0 = ret.Get(0).(groups.Group)
	}

	if rf, ok := ret.Get(1).(func(context.Context, groups.Group) error); ok {
		r1 = rf(ctx, group)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Delete provides a mock function with given fields: ctx, groupID
func (_m *Repository) Delete(ctx context.Context, groupID string) error {
	ret := _m.Called(ctx, groupID)

	if len(ret) == 0 {
		panic("no return value specified for Delete")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, groupID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
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
func (_m *Repository) RetrieveAll(ctx context.Context, pm groups.PageMeta) (groups.Page, error) {
	ret := _m.Called(ctx, pm)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveAll")
	}

	var r0 groups.Page
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, groups.PageMeta) (groups.Page, error)); ok {
		return rf(ctx, pm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, groups.PageMeta) groups.Page); ok {
		r0 = rf(ctx, pm)
	} else {
		r0 = ret.Get(0).(groups.Page)
	}

	if rf, ok := ret.Get(1).(func(context.Context, groups.PageMeta) error); ok {
		r1 = rf(ctx, pm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveAllParentGroups provides a mock function with given fields: ctx, domainID, userID, groupID, pm
func (_m *Repository) RetrieveAllParentGroups(ctx context.Context, domainID string, userID string, groupID string, pm groups.PageMeta) (groups.Page, error) {
	ret := _m.Called(ctx, domainID, userID, groupID, pm)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveAllParentGroups")
	}

	var r0 groups.Page
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, groups.PageMeta) (groups.Page, error)); ok {
		return rf(ctx, domainID, userID, groupID, pm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, groups.PageMeta) groups.Page); ok {
		r0 = rf(ctx, domainID, userID, groupID, pm)
	} else {
		r0 = ret.Get(0).(groups.Page)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string, groups.PageMeta) error); ok {
		r1 = rf(ctx, domainID, userID, groupID, pm)
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
func (_m *Repository) RetrieveByID(ctx context.Context, id string) (groups.Group, error) {
	ret := _m.Called(ctx, id)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveByID")
	}

	var r0 groups.Group
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (groups.Group, error)); ok {
		return rf(ctx, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) groups.Group); ok {
		r0 = rf(ctx, id)
	} else {
		r0 = ret.Get(0).(groups.Group)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveByIDAndUser provides a mock function with given fields: ctx, domainID, userID, groupID
func (_m *Repository) RetrieveByIDAndUser(ctx context.Context, domainID string, userID string, groupID string) (groups.Group, error) {
	ret := _m.Called(ctx, domainID, userID, groupID)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveByIDAndUser")
	}

	var r0 groups.Group
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) (groups.Group, error)); ok {
		return rf(ctx, domainID, userID, groupID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) groups.Group); ok {
		r0 = rf(ctx, domainID, userID, groupID)
	} else {
		r0 = ret.Get(0).(groups.Group)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string) error); ok {
		r1 = rf(ctx, domainID, userID, groupID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveByIDWithRoles provides a mock function with given fields: ctx, groupID, memberID
func (_m *Repository) RetrieveByIDWithRoles(ctx context.Context, groupID string, memberID string) (groups.Group, error) {
	ret := _m.Called(ctx, groupID, memberID)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveByIDWithRoles")
	}

	var r0 groups.Group
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (groups.Group, error)); ok {
		return rf(ctx, groupID, memberID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) groups.Group); ok {
		r0 = rf(ctx, groupID, memberID)
	} else {
		r0 = ret.Get(0).(groups.Group)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, groupID, memberID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveByIDs provides a mock function with given fields: ctx, pm, ids
func (_m *Repository) RetrieveByIDs(ctx context.Context, pm groups.PageMeta, ids ...string) (groups.Page, error) {
	ret := _m.Called(ctx, pm, ids)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveByIDs")
	}

	var r0 groups.Page
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, groups.PageMeta, ...string) (groups.Page, error)); ok {
		return rf(ctx, pm, ids...)
	}
	if rf, ok := ret.Get(0).(func(context.Context, groups.PageMeta, ...string) groups.Page); ok {
		r0 = rf(ctx, pm, ids...)
	} else {
		r0 = ret.Get(0).(groups.Page)
	}

	if rf, ok := ret.Get(1).(func(context.Context, groups.PageMeta, ...string) error); ok {
		r1 = rf(ctx, pm, ids...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveChildrenGroups provides a mock function with given fields: ctx, domainID, userID, groupID, startLevel, endLevel, pm
func (_m *Repository) RetrieveChildrenGroups(ctx context.Context, domainID string, userID string, groupID string, startLevel int64, endLevel int64, pm groups.PageMeta) (groups.Page, error) {
	ret := _m.Called(ctx, domainID, userID, groupID, startLevel, endLevel, pm)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveChildrenGroups")
	}

	var r0 groups.Page
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, int64, int64, groups.PageMeta) (groups.Page, error)); ok {
		return rf(ctx, domainID, userID, groupID, startLevel, endLevel, pm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, int64, int64, groups.PageMeta) groups.Page); ok {
		r0 = rf(ctx, domainID, userID, groupID, startLevel, endLevel, pm)
	} else {
		r0 = ret.Get(0).(groups.Page)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string, int64, int64, groups.PageMeta) error); ok {
		r1 = rf(ctx, domainID, userID, groupID, startLevel, endLevel, pm)
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

// RetrieveHierarchy provides a mock function with given fields: ctx, id, hm
func (_m *Repository) RetrieveHierarchy(ctx context.Context, id string, hm groups.HierarchyPageMeta) (groups.HierarchyPage, error) {
	ret := _m.Called(ctx, id, hm)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveHierarchy")
	}

	var r0 groups.HierarchyPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, groups.HierarchyPageMeta) (groups.HierarchyPage, error)); ok {
		return rf(ctx, id, hm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, groups.HierarchyPageMeta) groups.HierarchyPage); ok {
		r0 = rf(ctx, id, hm)
	} else {
		r0 = ret.Get(0).(groups.HierarchyPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, groups.HierarchyPageMeta) error); ok {
		r1 = rf(ctx, id, hm)
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

// RetrieveUserGroups provides a mock function with given fields: ctx, domainID, userID, pm
func (_m *Repository) RetrieveUserGroups(ctx context.Context, domainID string, userID string, pm groups.PageMeta) (groups.Page, error) {
	ret := _m.Called(ctx, domainID, userID, pm)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveUserGroups")
	}

	var r0 groups.Page
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, groups.PageMeta) (groups.Page, error)); ok {
		return rf(ctx, domainID, userID, pm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, groups.PageMeta) groups.Page); ok {
		r0 = rf(ctx, domainID, userID, pm)
	} else {
		r0 = ret.Get(0).(groups.Page)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, groups.PageMeta) error); ok {
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

// Save provides a mock function with given fields: ctx, g
func (_m *Repository) Save(ctx context.Context, g groups.Group) (groups.Group, error) {
	ret := _m.Called(ctx, g)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 groups.Group
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, groups.Group) (groups.Group, error)); ok {
		return rf(ctx, g)
	}
	if rf, ok := ret.Get(0).(func(context.Context, groups.Group) groups.Group); ok {
		r0 = rf(ctx, g)
	} else {
		r0 = ret.Get(0).(groups.Group)
	}

	if rf, ok := ret.Get(1).(func(context.Context, groups.Group) error); ok {
		r1 = rf(ctx, g)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UnassignAllChildrenGroups provides a mock function with given fields: ctx, id
func (_m *Repository) UnassignAllChildrenGroups(ctx context.Context, id string) error {
	ret := _m.Called(ctx, id)

	if len(ret) == 0 {
		panic("no return value specified for UnassignAllChildrenGroups")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UnassignParentGroup provides a mock function with given fields: ctx, parentGroupID, groupIDs
func (_m *Repository) UnassignParentGroup(ctx context.Context, parentGroupID string, groupIDs ...string) error {
	ret := _m.Called(ctx, parentGroupID, groupIDs)

	if len(ret) == 0 {
		panic("no return value specified for UnassignParentGroup")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, ...string) error); ok {
		r0 = rf(ctx, parentGroupID, groupIDs...)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Update provides a mock function with given fields: ctx, g
func (_m *Repository) Update(ctx context.Context, g groups.Group) (groups.Group, error) {
	ret := _m.Called(ctx, g)

	if len(ret) == 0 {
		panic("no return value specified for Update")
	}

	var r0 groups.Group
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, groups.Group) (groups.Group, error)); ok {
		return rf(ctx, g)
	}
	if rf, ok := ret.Get(0).(func(context.Context, groups.Group) groups.Group); ok {
		r0 = rf(ctx, g)
	} else {
		r0 = ret.Get(0).(groups.Group)
	}

	if rf, ok := ret.Get(1).(func(context.Context, groups.Group) error); ok {
		r1 = rf(ctx, g)
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
