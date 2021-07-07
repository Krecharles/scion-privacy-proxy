// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.15.3
// source: proto/control_plane/v1/cppki.proto

package control_plane

import (
	context "context"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type ChainsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IsdAs        uint64                 `protobuf:"varint,1,opt,name=isd_as,json=isdAs,proto3" json:"isd_as,omitempty"`
	SubjectKeyId []byte                 `protobuf:"bytes,2,opt,name=subject_key_id,json=subjectKeyId,proto3" json:"subject_key_id,omitempty"`
	Date         *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=date,proto3" json:"date,omitempty"`
}

func (x *ChainsRequest) Reset() {
	*x = ChainsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_control_plane_v1_cppki_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ChainsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ChainsRequest) ProtoMessage() {}

func (x *ChainsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_control_plane_v1_cppki_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ChainsRequest.ProtoReflect.Descriptor instead.
func (*ChainsRequest) Descriptor() ([]byte, []int) {
	return file_proto_control_plane_v1_cppki_proto_rawDescGZIP(), []int{0}
}

func (x *ChainsRequest) GetIsdAs() uint64 {
	if x != nil {
		return x.IsdAs
	}
	return 0
}

func (x *ChainsRequest) GetSubjectKeyId() []byte {
	if x != nil {
		return x.SubjectKeyId
	}
	return nil
}

func (x *ChainsRequest) GetDate() *timestamppb.Timestamp {
	if x != nil {
		return x.Date
	}
	return nil
}

type ChainsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Chains []*Chain `protobuf:"bytes,1,rep,name=chains,proto3" json:"chains,omitempty"`
}

func (x *ChainsResponse) Reset() {
	*x = ChainsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_control_plane_v1_cppki_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ChainsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ChainsResponse) ProtoMessage() {}

func (x *ChainsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_control_plane_v1_cppki_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ChainsResponse.ProtoReflect.Descriptor instead.
func (*ChainsResponse) Descriptor() ([]byte, []int) {
	return file_proto_control_plane_v1_cppki_proto_rawDescGZIP(), []int{1}
}

func (x *ChainsResponse) GetChains() []*Chain {
	if x != nil {
		return x.Chains
	}
	return nil
}

type Chain struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AsCert []byte `protobuf:"bytes,1,opt,name=as_cert,json=asCert,proto3" json:"as_cert,omitempty"`
	CaCert []byte `protobuf:"bytes,2,opt,name=ca_cert,json=caCert,proto3" json:"ca_cert,omitempty"`
}

func (x *Chain) Reset() {
	*x = Chain{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_control_plane_v1_cppki_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Chain) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Chain) ProtoMessage() {}

func (x *Chain) ProtoReflect() protoreflect.Message {
	mi := &file_proto_control_plane_v1_cppki_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Chain.ProtoReflect.Descriptor instead.
func (*Chain) Descriptor() ([]byte, []int) {
	return file_proto_control_plane_v1_cppki_proto_rawDescGZIP(), []int{2}
}

func (x *Chain) GetAsCert() []byte {
	if x != nil {
		return x.AsCert
	}
	return nil
}

func (x *Chain) GetCaCert() []byte {
	if x != nil {
		return x.CaCert
	}
	return nil
}

type TRCRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Isd    uint32 `protobuf:"varint,1,opt,name=isd,proto3" json:"isd,omitempty"`
	Base   uint64 `protobuf:"varint,2,opt,name=base,proto3" json:"base,omitempty"`
	Serial uint64 `protobuf:"varint,3,opt,name=serial,proto3" json:"serial,omitempty"`
}

func (x *TRCRequest) Reset() {
	*x = TRCRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_control_plane_v1_cppki_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TRCRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TRCRequest) ProtoMessage() {}

func (x *TRCRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_control_plane_v1_cppki_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TRCRequest.ProtoReflect.Descriptor instead.
func (*TRCRequest) Descriptor() ([]byte, []int) {
	return file_proto_control_plane_v1_cppki_proto_rawDescGZIP(), []int{3}
}

func (x *TRCRequest) GetIsd() uint32 {
	if x != nil {
		return x.Isd
	}
	return 0
}

func (x *TRCRequest) GetBase() uint64 {
	if x != nil {
		return x.Base
	}
	return 0
}

func (x *TRCRequest) GetSerial() uint64 {
	if x != nil {
		return x.Serial
	}
	return 0
}

type TRCResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Trc []byte `protobuf:"bytes,1,opt,name=trc,proto3" json:"trc,omitempty"`
}

func (x *TRCResponse) Reset() {
	*x = TRCResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_control_plane_v1_cppki_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TRCResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TRCResponse) ProtoMessage() {}

func (x *TRCResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_control_plane_v1_cppki_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TRCResponse.ProtoReflect.Descriptor instead.
func (*TRCResponse) Descriptor() ([]byte, []int) {
	return file_proto_control_plane_v1_cppki_proto_rawDescGZIP(), []int{4}
}

func (x *TRCResponse) GetTrc() []byte {
	if x != nil {
		return x.Trc
	}
	return nil
}

type VerificationKeyID struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IsdAs        uint64 `protobuf:"varint,1,opt,name=isd_as,json=isdAs,proto3" json:"isd_as,omitempty"`
	SubjectKeyId []byte `protobuf:"bytes,2,opt,name=subject_key_id,json=subjectKeyId,proto3" json:"subject_key_id,omitempty"`
	TrcBase      uint64 `protobuf:"varint,3,opt,name=trc_base,json=trcBase,proto3" json:"trc_base,omitempty"`
	TrcSerial    uint64 `protobuf:"varint,4,opt,name=trc_serial,json=trcSerial,proto3" json:"trc_serial,omitempty"`
}

func (x *VerificationKeyID) Reset() {
	*x = VerificationKeyID{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_control_plane_v1_cppki_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VerificationKeyID) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VerificationKeyID) ProtoMessage() {}

func (x *VerificationKeyID) ProtoReflect() protoreflect.Message {
	mi := &file_proto_control_plane_v1_cppki_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VerificationKeyID.ProtoReflect.Descriptor instead.
func (*VerificationKeyID) Descriptor() ([]byte, []int) {
	return file_proto_control_plane_v1_cppki_proto_rawDescGZIP(), []int{5}
}

func (x *VerificationKeyID) GetIsdAs() uint64 {
	if x != nil {
		return x.IsdAs
	}
	return 0
}

func (x *VerificationKeyID) GetSubjectKeyId() []byte {
	if x != nil {
		return x.SubjectKeyId
	}
	return nil
}

func (x *VerificationKeyID) GetTrcBase() uint64 {
	if x != nil {
		return x.TrcBase
	}
	return 0
}

func (x *VerificationKeyID) GetTrcSerial() uint64 {
	if x != nil {
		return x.TrcSerial
	}
	return 0
}

var File_proto_control_plane_v1_cppki_proto protoreflect.FileDescriptor

var file_proto_control_plane_v1_cppki_proto_rawDesc = []byte{
	0x0a, 0x22, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x5f,
	0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x63, 0x70, 0x70, 0x6b, 0x69, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x16, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x5f, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x76, 0x31, 0x1a, 0x1f, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x7c, 0x0a,
	0x0d, 0x43, 0x68, 0x61, 0x69, 0x6e, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x15,
	0x0a, 0x06, 0x69, 0x73, 0x64, 0x5f, 0x61, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x05,
	0x69, 0x73, 0x64, 0x41, 0x73, 0x12, 0x24, 0x0a, 0x0e, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74,
	0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0c, 0x73,
	0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4b, 0x65, 0x79, 0x49, 0x64, 0x12, 0x2e, 0x0a, 0x04, 0x64,
	0x61, 0x74, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x04, 0x64, 0x61, 0x74, 0x65, 0x22, 0x47, 0x0a, 0x0e, 0x43,
	0x68, 0x61, 0x69, 0x6e, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x35, 0x0a,
	0x06, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1d, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x5f, 0x70, 0x6c,
	0x61, 0x6e, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x68, 0x61, 0x69, 0x6e, 0x52, 0x06, 0x63, 0x68,
	0x61, 0x69, 0x6e, 0x73, 0x22, 0x39, 0x0a, 0x05, 0x43, 0x68, 0x61, 0x69, 0x6e, 0x12, 0x17, 0x0a,
	0x07, 0x61, 0x73, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06,
	0x61, 0x73, 0x43, 0x65, 0x72, 0x74, 0x12, 0x17, 0x0a, 0x07, 0x63, 0x61, 0x5f, 0x63, 0x65, 0x72,
	0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x63, 0x61, 0x43, 0x65, 0x72, 0x74, 0x22,
	0x4a, 0x0a, 0x0a, 0x54, 0x52, 0x43, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x10, 0x0a,
	0x03, 0x69, 0x73, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x69, 0x73, 0x64, 0x12,
	0x12, 0x0a, 0x04, 0x62, 0x61, 0x73, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x04, 0x62,
	0x61, 0x73, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x04, 0x52, 0x06, 0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x22, 0x1f, 0x0a, 0x0b, 0x54,
	0x52, 0x43, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x74, 0x72,
	0x63, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x74, 0x72, 0x63, 0x22, 0x8a, 0x01, 0x0a,
	0x11, 0x56, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4b, 0x65, 0x79,
	0x49, 0x44, 0x12, 0x15, 0x0a, 0x06, 0x69, 0x73, 0x64, 0x5f, 0x61, 0x73, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x04, 0x52, 0x05, 0x69, 0x73, 0x64, 0x41, 0x73, 0x12, 0x24, 0x0a, 0x0e, 0x73, 0x75, 0x62,
	0x6a, 0x65, 0x63, 0x74, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x0c, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4b, 0x65, 0x79, 0x49, 0x64, 0x12,
	0x19, 0x0a, 0x08, 0x74, 0x72, 0x63, 0x5f, 0x62, 0x61, 0x73, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x04, 0x52, 0x07, 0x74, 0x72, 0x63, 0x42, 0x61, 0x73, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x74, 0x72,
	0x63, 0x5f, 0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x18, 0x04, 0x20, 0x01, 0x28, 0x04, 0x52, 0x09,
	0x74, 0x72, 0x63, 0x53, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x32, 0xc3, 0x01, 0x0a, 0x14, 0x54, 0x72,
	0x75, 0x73, 0x74, 0x4d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x53, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x12, 0x59, 0x0a, 0x06, 0x43, 0x68, 0x61, 0x69, 0x6e, 0x73, 0x12, 0x25, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x5f, 0x70, 0x6c, 0x61,
	0x6e, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x68, 0x61, 0x69, 0x6e, 0x73, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x26, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x5f, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x68, 0x61,
	0x69, 0x6e, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x50, 0x0a,
	0x03, 0x54, 0x52, 0x43, 0x12, 0x22, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x5f, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x52,
	0x43, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x23, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x5f, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x76,
	0x31, 0x2e, 0x54, 0x52, 0x43, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42,
	0x38, 0x5a, 0x36, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x63,
	0x69, 0x6f, 0x6e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x63, 0x69, 0x6f, 0x6e, 0x2f, 0x67,
	0x6f, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x5f, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_proto_control_plane_v1_cppki_proto_rawDescOnce sync.Once
	file_proto_control_plane_v1_cppki_proto_rawDescData = file_proto_control_plane_v1_cppki_proto_rawDesc
)

func file_proto_control_plane_v1_cppki_proto_rawDescGZIP() []byte {
	file_proto_control_plane_v1_cppki_proto_rawDescOnce.Do(func() {
		file_proto_control_plane_v1_cppki_proto_rawDescData = protoimpl.X.CompressGZIP(file_proto_control_plane_v1_cppki_proto_rawDescData)
	})
	return file_proto_control_plane_v1_cppki_proto_rawDescData
}

var file_proto_control_plane_v1_cppki_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_proto_control_plane_v1_cppki_proto_goTypes = []interface{}{
	(*ChainsRequest)(nil),         // 0: proto.control_plane.v1.ChainsRequest
	(*ChainsResponse)(nil),        // 1: proto.control_plane.v1.ChainsResponse
	(*Chain)(nil),                 // 2: proto.control_plane.v1.Chain
	(*TRCRequest)(nil),            // 3: proto.control_plane.v1.TRCRequest
	(*TRCResponse)(nil),           // 4: proto.control_plane.v1.TRCResponse
	(*VerificationKeyID)(nil),     // 5: proto.control_plane.v1.VerificationKeyID
	(*timestamppb.Timestamp)(nil), // 6: google.protobuf.Timestamp
}
var file_proto_control_plane_v1_cppki_proto_depIdxs = []int32{
	6, // 0: proto.control_plane.v1.ChainsRequest.date:type_name -> google.protobuf.Timestamp
	2, // 1: proto.control_plane.v1.ChainsResponse.chains:type_name -> proto.control_plane.v1.Chain
	0, // 2: proto.control_plane.v1.TrustMaterialService.Chains:input_type -> proto.control_plane.v1.ChainsRequest
	3, // 3: proto.control_plane.v1.TrustMaterialService.TRC:input_type -> proto.control_plane.v1.TRCRequest
	1, // 4: proto.control_plane.v1.TrustMaterialService.Chains:output_type -> proto.control_plane.v1.ChainsResponse
	4, // 5: proto.control_plane.v1.TrustMaterialService.TRC:output_type -> proto.control_plane.v1.TRCResponse
	4, // [4:6] is the sub-list for method output_type
	2, // [2:4] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_proto_control_plane_v1_cppki_proto_init() }
func file_proto_control_plane_v1_cppki_proto_init() {
	if File_proto_control_plane_v1_cppki_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proto_control_plane_v1_cppki_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ChainsRequest); i {
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
		file_proto_control_plane_v1_cppki_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ChainsResponse); i {
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
		file_proto_control_plane_v1_cppki_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Chain); i {
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
		file_proto_control_plane_v1_cppki_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TRCRequest); i {
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
		file_proto_control_plane_v1_cppki_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TRCResponse); i {
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
		file_proto_control_plane_v1_cppki_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*VerificationKeyID); i {
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
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_proto_control_plane_v1_cppki_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_proto_control_plane_v1_cppki_proto_goTypes,
		DependencyIndexes: file_proto_control_plane_v1_cppki_proto_depIdxs,
		MessageInfos:      file_proto_control_plane_v1_cppki_proto_msgTypes,
	}.Build()
	File_proto_control_plane_v1_cppki_proto = out.File
	file_proto_control_plane_v1_cppki_proto_rawDesc = nil
	file_proto_control_plane_v1_cppki_proto_goTypes = nil
	file_proto_control_plane_v1_cppki_proto_depIdxs = nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// TrustMaterialServiceClient is the client API for TrustMaterialService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type TrustMaterialServiceClient interface {
	Chains(ctx context.Context, in *ChainsRequest, opts ...grpc.CallOption) (*ChainsResponse, error)
	TRC(ctx context.Context, in *TRCRequest, opts ...grpc.CallOption) (*TRCResponse, error)
}

type trustMaterialServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewTrustMaterialServiceClient(cc grpc.ClientConnInterface) TrustMaterialServiceClient {
	return &trustMaterialServiceClient{cc}
}

func (c *trustMaterialServiceClient) Chains(ctx context.Context, in *ChainsRequest, opts ...grpc.CallOption) (*ChainsResponse, error) {
	out := new(ChainsResponse)
	err := c.cc.Invoke(ctx, "/proto.control_plane.v1.TrustMaterialService/Chains", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *trustMaterialServiceClient) TRC(ctx context.Context, in *TRCRequest, opts ...grpc.CallOption) (*TRCResponse, error) {
	out := new(TRCResponse)
	err := c.cc.Invoke(ctx, "/proto.control_plane.v1.TrustMaterialService/TRC", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TrustMaterialServiceServer is the server API for TrustMaterialService service.
type TrustMaterialServiceServer interface {
	Chains(context.Context, *ChainsRequest) (*ChainsResponse, error)
	TRC(context.Context, *TRCRequest) (*TRCResponse, error)
}

// UnimplementedTrustMaterialServiceServer can be embedded to have forward compatible implementations.
type UnimplementedTrustMaterialServiceServer struct {
}

func (*UnimplementedTrustMaterialServiceServer) Chains(context.Context, *ChainsRequest) (*ChainsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Chains not implemented")
}
func (*UnimplementedTrustMaterialServiceServer) TRC(context.Context, *TRCRequest) (*TRCResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method TRC not implemented")
}

func RegisterTrustMaterialServiceServer(s *grpc.Server, srv TrustMaterialServiceServer) {
	s.RegisterService(&_TrustMaterialService_serviceDesc, srv)
}

func _TrustMaterialService_Chains_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ChainsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TrustMaterialServiceServer).Chains(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.control_plane.v1.TrustMaterialService/Chains",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TrustMaterialServiceServer).Chains(ctx, req.(*ChainsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TrustMaterialService_TRC_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TRCRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TrustMaterialServiceServer).TRC(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.control_plane.v1.TrustMaterialService/TRC",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TrustMaterialServiceServer).TRC(ctx, req.(*TRCRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _TrustMaterialService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "proto.control_plane.v1.TrustMaterialService",
	HandlerType: (*TrustMaterialServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Chains",
			Handler:    _TrustMaterialService_Chains_Handler,
		},
		{
			MethodName: "TRC",
			Handler:    _TrustMaterialService_TRC_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/control_plane/v1/cppki.proto",
}
