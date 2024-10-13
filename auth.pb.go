// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        v5.27.1
// source: auth.proto

package magistrala

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// If a token is not carrying any information itself, the type
// field can be used to determine how to validate the token.
// Also, different tokens can be encoded in different ways.
type Token struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AccessToken  string  `protobuf:"bytes,1,opt,name=accessToken,proto3" json:"accessToken,omitempty"`
	RefreshToken *string `protobuf:"bytes,2,opt,name=refreshToken,proto3,oneof" json:"refreshToken,omitempty"`
	AccessType   string  `protobuf:"bytes,3,opt,name=accessType,proto3" json:"accessType,omitempty"`
}

func (x *Token) Reset() {
	*x = Token{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Token) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Token) ProtoMessage() {}

func (x *Token) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Token.ProtoReflect.Descriptor instead.
func (*Token) Descriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{0}
}

func (x *Token) GetAccessToken() string {
	if x != nil {
		return x.AccessToken
	}
	return ""
}

func (x *Token) GetRefreshToken() string {
	if x != nil && x.RefreshToken != nil {
		return *x.RefreshToken
	}
	return ""
}

func (x *Token) GetAccessType() string {
	if x != nil {
		return x.AccessType
	}
	return ""
}

type AuthenticateReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Token string `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
}

func (x *AuthenticateReq) Reset() {
	*x = AuthenticateReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthenticateReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthenticateReq) ProtoMessage() {}

func (x *AuthenticateReq) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthenticateReq.ProtoReflect.Descriptor instead.
func (*AuthenticateReq) Descriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{1}
}

func (x *AuthenticateReq) GetToken() string {
	if x != nil {
		return x.Token
	}
	return ""
}

type AuthenticateRes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id       string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`                             // IMPROVEMENT NOTE: change name from "id" to "subject" , sub in jwt = user id  + domain id //
	UserId   string `protobuf:"bytes,2,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`       // user id
	DomainId string `protobuf:"bytes,3,opt,name=domain_id,json=domainId,proto3" json:"domain_id,omitempty"` // domain id
}

func (x *AuthenticateRes) Reset() {
	*x = AuthenticateRes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthenticateRes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthenticateRes) ProtoMessage() {}

func (x *AuthenticateRes) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthenticateRes.ProtoReflect.Descriptor instead.
func (*AuthenticateRes) Descriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{2}
}

func (x *AuthenticateRes) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *AuthenticateRes) GetUserId() string {
	if x != nil {
		return x.UserId
	}
	return ""
}

func (x *AuthenticateRes) GetDomainId() string {
	if x != nil {
		return x.DomainId
	}
	return ""
}

type IssueReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	UserId   string  `protobuf:"bytes,1,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	DomainId *string `protobuf:"bytes,2,opt,name=domain_id,json=domainId,proto3,oneof" json:"domain_id,omitempty"`
	Type     uint32  `protobuf:"varint,3,opt,name=type,proto3" json:"type,omitempty"`
}

func (x *IssueReq) Reset() {
	*x = IssueReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IssueReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IssueReq) ProtoMessage() {}

func (x *IssueReq) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IssueReq.ProtoReflect.Descriptor instead.
func (*IssueReq) Descriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{3}
}

func (x *IssueReq) GetUserId() string {
	if x != nil {
		return x.UserId
	}
	return ""
}

func (x *IssueReq) GetDomainId() string {
	if x != nil && x.DomainId != nil {
		return *x.DomainId
	}
	return ""
}

func (x *IssueReq) GetType() uint32 {
	if x != nil {
		return x.Type
	}
	return 0
}

type RefreshReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RefreshToken string  `protobuf:"bytes,1,opt,name=refresh_token,json=refreshToken,proto3" json:"refresh_token,omitempty"`
	DomainId     *string `protobuf:"bytes,2,opt,name=domain_id,json=domainId,proto3,oneof" json:"domain_id,omitempty"`
}

func (x *RefreshReq) Reset() {
	*x = RefreshReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RefreshReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RefreshReq) ProtoMessage() {}

func (x *RefreshReq) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RefreshReq.ProtoReflect.Descriptor instead.
func (*RefreshReq) Descriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{4}
}

func (x *RefreshReq) GetRefreshToken() string {
	if x != nil {
		return x.RefreshToken
	}
	return ""
}

func (x *RefreshReq) GetDomainId() string {
	if x != nil && x.DomainId != nil {
		return *x.DomainId
	}
	return ""
}

type AuthorizeReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Domain          string `protobuf:"bytes,1,opt,name=domain,proto3" json:"domain,omitempty"`                                          // Domain
	SubjectType     string `protobuf:"bytes,2,opt,name=subject_type,json=subjectType,proto3" json:"subject_type,omitempty"`             // Thing or User
	SubjectKind     string `protobuf:"bytes,3,opt,name=subject_kind,json=subjectKind,proto3" json:"subject_kind,omitempty"`             // ID or Token
	SubjectRelation string `protobuf:"bytes,4,opt,name=subject_relation,json=subjectRelation,proto3" json:"subject_relation,omitempty"` // Subject relation
	Subject         string `protobuf:"bytes,5,opt,name=subject,proto3" json:"subject,omitempty"`                                        // Subject value (id or token, depending on kind)
	Relation        string `protobuf:"bytes,6,opt,name=relation,proto3" json:"relation,omitempty"`                                      // Relation to filter
	Permission      string `protobuf:"bytes,7,opt,name=permission,proto3" json:"permission,omitempty"`                                  // Action
	Object          string `protobuf:"bytes,8,opt,name=object,proto3" json:"object,omitempty"`                                          // Object ID
	ObjectType      string `protobuf:"bytes,9,opt,name=object_type,json=objectType,proto3" json:"object_type,omitempty"`                // Thing, User, Group
}

func (x *AuthorizeReq) Reset() {
	*x = AuthorizeReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthorizeReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthorizeReq) ProtoMessage() {}

func (x *AuthorizeReq) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthorizeReq.ProtoReflect.Descriptor instead.
func (*AuthorizeReq) Descriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{5}
}

func (x *AuthorizeReq) GetDomain() string {
	if x != nil {
		return x.Domain
	}
	return ""
}

func (x *AuthorizeReq) GetSubjectType() string {
	if x != nil {
		return x.SubjectType
	}
	return ""
}

func (x *AuthorizeReq) GetSubjectKind() string {
	if x != nil {
		return x.SubjectKind
	}
	return ""
}

func (x *AuthorizeReq) GetSubjectRelation() string {
	if x != nil {
		return x.SubjectRelation
	}
	return ""
}

func (x *AuthorizeReq) GetSubject() string {
	if x != nil {
		return x.Subject
	}
	return ""
}

func (x *AuthorizeReq) GetRelation() string {
	if x != nil {
		return x.Relation
	}
	return ""
}

func (x *AuthorizeReq) GetPermission() string {
	if x != nil {
		return x.Permission
	}
	return ""
}

func (x *AuthorizeReq) GetObject() string {
	if x != nil {
		return x.Object
	}
	return ""
}

func (x *AuthorizeReq) GetObjectType() string {
	if x != nil {
		return x.ObjectType
	}
	return ""
}

type AuthorizeRes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Authorized bool   `protobuf:"varint,1,opt,name=authorized,proto3" json:"authorized,omitempty"`
	Id         string `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *AuthorizeRes) Reset() {
	*x = AuthorizeRes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthorizeRes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthorizeRes) ProtoMessage() {}

func (x *AuthorizeRes) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthorizeRes.ProtoReflect.Descriptor instead.
func (*AuthorizeRes) Descriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{6}
}

func (x *AuthorizeRes) GetAuthorized() bool {
	if x != nil {
		return x.Authorized
	}
	return false
}

func (x *AuthorizeRes) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

type DeleteUserRes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Deleted bool `protobuf:"varint,1,opt,name=deleted,proto3" json:"deleted,omitempty"`
}

func (x *DeleteUserRes) Reset() {
	*x = DeleteUserRes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteUserRes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteUserRes) ProtoMessage() {}

func (x *DeleteUserRes) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteUserRes.ProtoReflect.Descriptor instead.
func (*DeleteUserRes) Descriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{7}
}

func (x *DeleteUserRes) GetDeleted() bool {
	if x != nil {
		return x.Deleted
	}
	return false
}

type DeleteUserReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *DeleteUserReq) Reset() {
	*x = DeleteUserReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteUserReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteUserReq) ProtoMessage() {}

func (x *DeleteUserReq) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteUserReq.ProtoReflect.Descriptor instead.
func (*DeleteUserReq) Descriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{8}
}

func (x *DeleteUserReq) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

type ThingsAuthzReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ChannelID  string `protobuf:"bytes,1,opt,name=channelID,proto3" json:"channelID,omitempty"`
	ThingID    string `protobuf:"bytes,2,opt,name=thingID,proto3" json:"thingID,omitempty"`
	ThingKey   string `protobuf:"bytes,3,opt,name=thingKey,proto3" json:"thingKey,omitempty"`
	Permission string `protobuf:"bytes,4,opt,name=permission,proto3" json:"permission,omitempty"`
}

func (x *ThingsAuthzReq) Reset() {
	*x = ThingsAuthzReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ThingsAuthzReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ThingsAuthzReq) ProtoMessage() {}

func (x *ThingsAuthzReq) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ThingsAuthzReq.ProtoReflect.Descriptor instead.
func (*ThingsAuthzReq) Descriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{9}
}

func (x *ThingsAuthzReq) GetChannelID() string {
	if x != nil {
		return x.ChannelID
	}
	return ""
}

func (x *ThingsAuthzReq) GetThingID() string {
	if x != nil {
		return x.ThingID
	}
	return ""
}

func (x *ThingsAuthzReq) GetThingKey() string {
	if x != nil {
		return x.ThingKey
	}
	return ""
}

func (x *ThingsAuthzReq) GetPermission() string {
	if x != nil {
		return x.Permission
	}
	return ""
}

type ThingsAuthzRes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Authorized bool   `protobuf:"varint,1,opt,name=authorized,proto3" json:"authorized,omitempty"`
	Id         string `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *ThingsAuthzRes) Reset() {
	*x = ThingsAuthzRes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ThingsAuthzRes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ThingsAuthzRes) ProtoMessage() {}

func (x *ThingsAuthzRes) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ThingsAuthzRes.ProtoReflect.Descriptor instead.
func (*ThingsAuthzRes) Descriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{10}
}

func (x *ThingsAuthzRes) GetAuthorized() bool {
	if x != nil {
		return x.Authorized
	}
	return false
}

func (x *ThingsAuthzRes) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

var File_auth_proto protoreflect.FileDescriptor

var file_auth_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0a, 0x6d, 0x61,
	0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x6c, 0x61, 0x22, 0x83, 0x01, 0x0a, 0x05, 0x54, 0x6f, 0x6b,
	0x65, 0x6e, 0x12, 0x20, 0x0a, 0x0b, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x54, 0x6f, 0x6b, 0x65,
	0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x54,
	0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x27, 0x0a, 0x0c, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x54,
	0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x0c, 0x72, 0x65,
	0x66, 0x72, 0x65, 0x73, 0x68, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x88, 0x01, 0x01, 0x12, 0x1e, 0x0a,
	0x0a, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x54, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0a, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x54, 0x79, 0x70, 0x65, 0x42, 0x0f, 0x0a,
	0x0d, 0x5f, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x27,
	0x0a, 0x0f, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65,
	0x71, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x57, 0x0a, 0x0f, 0x41, 0x75, 0x74, 0x68, 0x65,
	0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x17, 0x0a, 0x07, 0x75, 0x73,
	0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x75, 0x73, 0x65,
	0x72, 0x49, 0x64, 0x12, 0x1b, 0x0a, 0x09, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x5f, 0x69, 0x64,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x49, 0x64,
	0x22, 0x67, 0x0a, 0x08, 0x49, 0x73, 0x73, 0x75, 0x65, 0x52, 0x65, 0x71, 0x12, 0x17, 0x0a, 0x07,
	0x75, 0x73, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x75,
	0x73, 0x65, 0x72, 0x49, 0x64, 0x12, 0x20, 0x0a, 0x09, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x5f,
	0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x08, 0x64, 0x6f, 0x6d, 0x61,
	0x69, 0x6e, 0x49, 0x64, 0x88, 0x01, 0x01, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x42, 0x0c, 0x0a, 0x0a, 0x5f,
	0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x5f, 0x69, 0x64, 0x22, 0x61, 0x0a, 0x0a, 0x52, 0x65, 0x66,
	0x72, 0x65, 0x73, 0x68, 0x52, 0x65, 0x71, 0x12, 0x23, 0x0a, 0x0d, 0x72, 0x65, 0x66, 0x72, 0x65,
	0x73, 0x68, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c,
	0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x20, 0x0a, 0x09,
	0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x48,
	0x00, 0x52, 0x08, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x49, 0x64, 0x88, 0x01, 0x01, 0x42, 0x0c,
	0x0a, 0x0a, 0x5f, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x5f, 0x69, 0x64, 0x22, 0xa6, 0x02, 0x0a,
	0x0c, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x52, 0x65, 0x71, 0x12, 0x16, 0x0a,
	0x06, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x64,
	0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x12, 0x21, 0x0a, 0x0c, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74,
	0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x73, 0x75, 0x62,
	0x6a, 0x65, 0x63, 0x74, 0x54, 0x79, 0x70, 0x65, 0x12, 0x21, 0x0a, 0x0c, 0x73, 0x75, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x5f, 0x6b, 0x69, 0x6e, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b,
	0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4b, 0x69, 0x6e, 0x64, 0x12, 0x29, 0x0a, 0x10, 0x73,
	0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x72, 0x65, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0f, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x52, 0x65,
	0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x18, 0x0a, 0x07, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63,
	0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74,
	0x12, 0x1a, 0x0a, 0x08, 0x72, 0x65, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x06, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x08, 0x72, 0x65, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1e, 0x0a, 0x0a,
	0x70, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0a, 0x70, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x16, 0x0a, 0x06,
	0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x6f, 0x62,
	0x6a, 0x65, 0x63, 0x74, 0x12, 0x1f, 0x0a, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x74,
	0x79, 0x70, 0x65, 0x18, 0x09, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x6f, 0x62, 0x6a, 0x65, 0x63,
	0x74, 0x54, 0x79, 0x70, 0x65, 0x22, 0x3e, 0x0a, 0x0c, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69,
	0x7a, 0x65, 0x52, 0x65, 0x73, 0x12, 0x1e, 0x0a, 0x0a, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69,
	0x7a, 0x65, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0a, 0x61, 0x75, 0x74, 0x68, 0x6f,
	0x72, 0x69, 0x7a, 0x65, 0x64, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x02, 0x69, 0x64, 0x22, 0x29, 0x0a, 0x0d, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x55,
	0x73, 0x65, 0x72, 0x52, 0x65, 0x73, 0x12, 0x18, 0x0a, 0x07, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x64,
	0x22, 0x1f, 0x0a, 0x0d, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x55, 0x73, 0x65, 0x72, 0x52, 0x65,
	0x71, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69,
	0x64, 0x22, 0x84, 0x01, 0x0a, 0x0e, 0x54, 0x68, 0x69, 0x6e, 0x67, 0x73, 0x41, 0x75, 0x74, 0x68,
	0x7a, 0x52, 0x65, 0x71, 0x12, 0x1c, 0x0a, 0x09, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x49,
	0x44, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c,
	0x49, 0x44, 0x12, 0x18, 0x0a, 0x07, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x49, 0x44, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x07, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x49, 0x44, 0x12, 0x1a, 0x0a, 0x08,
	0x74, 0x68, 0x69, 0x6e, 0x67, 0x4b, 0x65, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08,
	0x74, 0x68, 0x69, 0x6e, 0x67, 0x4b, 0x65, 0x79, 0x12, 0x1e, 0x0a, 0x0a, 0x70, 0x65, 0x72, 0x6d,
	0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x70, 0x65,
	0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x40, 0x0a, 0x0e, 0x54, 0x68, 0x69, 0x6e,
	0x67, 0x73, 0x41, 0x75, 0x74, 0x68, 0x7a, 0x52, 0x65, 0x73, 0x12, 0x1e, 0x0a, 0x0a, 0x61, 0x75,
	0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0a,
	0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x32, 0x56, 0x0a, 0x0d, 0x54, 0x68,
	0x69, 0x6e, 0x67, 0x73, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x45, 0x0a, 0x09, 0x41,
	0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x12, 0x1a, 0x2e, 0x6d, 0x61, 0x67, 0x69, 0x73,
	0x74, 0x72, 0x61, 0x6c, 0x61, 0x2e, 0x54, 0x68, 0x69, 0x6e, 0x67, 0x73, 0x41, 0x75, 0x74, 0x68,
	0x7a, 0x52, 0x65, 0x71, 0x1a, 0x1a, 0x2e, 0x6d, 0x61, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x6c,
	0x61, 0x2e, 0x54, 0x68, 0x69, 0x6e, 0x67, 0x73, 0x41, 0x75, 0x74, 0x68, 0x7a, 0x52, 0x65, 0x73,
	0x22, 0x00, 0x32, 0x7a, 0x0a, 0x0c, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x53, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x12, 0x32, 0x0a, 0x05, 0x49, 0x73, 0x73, 0x75, 0x65, 0x12, 0x14, 0x2e, 0x6d, 0x61,
	0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x6c, 0x61, 0x2e, 0x49, 0x73, 0x73, 0x75, 0x65, 0x52, 0x65,
	0x71, 0x1a, 0x11, 0x2e, 0x6d, 0x61, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x6c, 0x61, 0x2e, 0x54,
	0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x00, 0x12, 0x36, 0x0a, 0x07, 0x52, 0x65, 0x66, 0x72, 0x65, 0x73,
	0x68, 0x12, 0x16, 0x2e, 0x6d, 0x61, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x6c, 0x61, 0x2e, 0x52,
	0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x52, 0x65, 0x71, 0x1a, 0x11, 0x2e, 0x6d, 0x61, 0x67, 0x69,
	0x73, 0x74, 0x72, 0x61, 0x6c, 0x61, 0x2e, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x00, 0x32, 0x9c,
	0x01, 0x0a, 0x0b, 0x41, 0x75, 0x74, 0x68, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x41,
	0x0a, 0x09, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x12, 0x18, 0x2e, 0x6d, 0x61,
	0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x6c, 0x61, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69,
	0x7a, 0x65, 0x52, 0x65, 0x71, 0x1a, 0x18, 0x2e, 0x6d, 0x61, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61,
	0x6c, 0x61, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x52, 0x65, 0x73, 0x22,
	0x00, 0x12, 0x4a, 0x0a, 0x0c, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74,
	0x65, 0x12, 0x1b, 0x2e, 0x6d, 0x61, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x6c, 0x61, 0x2e, 0x41,
	0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x1a, 0x1b,
	0x2e, 0x6d, 0x61, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x6c, 0x61, 0x2e, 0x41, 0x75, 0x74, 0x68,
	0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x22, 0x00, 0x32, 0x61, 0x0a,
	0x0e, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x73, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12,
	0x4f, 0x0a, 0x15, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x55, 0x73, 0x65, 0x72, 0x46, 0x72, 0x6f,
	0x6d, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x73, 0x12, 0x19, 0x2e, 0x6d, 0x61, 0x67, 0x69, 0x73,
	0x74, 0x72, 0x61, 0x6c, 0x61, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x55, 0x73, 0x65, 0x72,
	0x52, 0x65, 0x71, 0x1a, 0x19, 0x2e, 0x6d, 0x61, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x6c, 0x61,
	0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x55, 0x73, 0x65, 0x72, 0x52, 0x65, 0x73, 0x22, 0x00,
	0x42, 0x0e, 0x5a, 0x0c, 0x2e, 0x2f, 0x6d, 0x61, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x6c, 0x61,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_auth_proto_rawDescOnce sync.Once
	file_auth_proto_rawDescData = file_auth_proto_rawDesc
)

func file_auth_proto_rawDescGZIP() []byte {
	file_auth_proto_rawDescOnce.Do(func() {
		file_auth_proto_rawDescData = protoimpl.X.CompressGZIP(file_auth_proto_rawDescData)
	})
	return file_auth_proto_rawDescData
}

var file_auth_proto_msgTypes = make([]protoimpl.MessageInfo, 11)
var file_auth_proto_goTypes = []any{
	(*Token)(nil),           // 0: magistrala.Token
	(*AuthenticateReq)(nil), // 1: magistrala.AuthenticateReq
	(*AuthenticateRes)(nil), // 2: magistrala.AuthenticateRes
	(*IssueReq)(nil),        // 3: magistrala.IssueReq
	(*RefreshReq)(nil),      // 4: magistrala.RefreshReq
	(*AuthorizeReq)(nil),    // 5: magistrala.AuthorizeReq
	(*AuthorizeRes)(nil),    // 6: magistrala.AuthorizeRes
	(*DeleteUserRes)(nil),   // 7: magistrala.DeleteUserRes
	(*DeleteUserReq)(nil),   // 8: magistrala.DeleteUserReq
	(*ThingsAuthzReq)(nil),  // 9: magistrala.ThingsAuthzReq
	(*ThingsAuthzRes)(nil),  // 10: magistrala.ThingsAuthzRes
}
var file_auth_proto_depIdxs = []int32{
	9,  // 0: magistrala.ThingsService.Authorize:input_type -> magistrala.ThingsAuthzReq
	3,  // 1: magistrala.TokenService.Issue:input_type -> magistrala.IssueReq
	4,  // 2: magistrala.TokenService.Refresh:input_type -> magistrala.RefreshReq
	5,  // 3: magistrala.AuthService.Authorize:input_type -> magistrala.AuthorizeReq
	1,  // 4: magistrala.AuthService.Authenticate:input_type -> magistrala.AuthenticateReq
	8,  // 5: magistrala.DomainsService.DeleteUserFromDomains:input_type -> magistrala.DeleteUserReq
	10, // 6: magistrala.ThingsService.Authorize:output_type -> magistrala.ThingsAuthzRes
	0,  // 7: magistrala.TokenService.Issue:output_type -> magistrala.Token
	0,  // 8: magistrala.TokenService.Refresh:output_type -> magistrala.Token
	6,  // 9: magistrala.AuthService.Authorize:output_type -> magistrala.AuthorizeRes
	2,  // 10: magistrala.AuthService.Authenticate:output_type -> magistrala.AuthenticateRes
	7,  // 11: magistrala.DomainsService.DeleteUserFromDomains:output_type -> magistrala.DeleteUserRes
	6,  // [6:12] is the sub-list for method output_type
	0,  // [0:6] is the sub-list for method input_type
	0,  // [0:0] is the sub-list for extension type_name
	0,  // [0:0] is the sub-list for extension extendee
	0,  // [0:0] is the sub-list for field type_name
}

func init() { file_auth_proto_init() }
func file_auth_proto_init() {
	if File_auth_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_auth_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*Token); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_auth_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*AuthenticateReq); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_auth_proto_msgTypes[2].Exporter = func(v any, i int) any {
			switch v := v.(*AuthenticateRes); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_auth_proto_msgTypes[3].Exporter = func(v any, i int) any {
			switch v := v.(*IssueReq); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_auth_proto_msgTypes[4].Exporter = func(v any, i int) any {
			switch v := v.(*RefreshReq); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_auth_proto_msgTypes[5].Exporter = func(v any, i int) any {
			switch v := v.(*AuthorizeReq); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_auth_proto_msgTypes[6].Exporter = func(v any, i int) any {
			switch v := v.(*AuthorizeRes); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_auth_proto_msgTypes[7].Exporter = func(v any, i int) any {
			switch v := v.(*DeleteUserRes); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_auth_proto_msgTypes[8].Exporter = func(v any, i int) any {
			switch v := v.(*DeleteUserReq); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_auth_proto_msgTypes[9].Exporter = func(v any, i int) any {
			switch v := v.(*ThingsAuthzReq); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_auth_proto_msgTypes[10].Exporter = func(v any, i int) any {
			switch v := v.(*ThingsAuthzRes); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_auth_proto_msgTypes[0].OneofWrappers = []any{}
	file_auth_proto_msgTypes[3].OneofWrappers = []any{}
	file_auth_proto_msgTypes[4].OneofWrappers = []any{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_auth_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   11,
			NumExtensions: 0,
			NumServices:   4,
		},
		GoTypes:           file_auth_proto_goTypes,
		DependencyIndexes: file_auth_proto_depIdxs,
		MessageInfos:      file_auth_proto_msgTypes,
	}.Build()
	File_auth_proto = out.File
	file_auth_proto_rawDesc = nil
	file_auth_proto_goTypes = nil
	file_auth_proto_depIdxs = nil
}
