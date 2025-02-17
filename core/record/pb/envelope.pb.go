// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v3.21.12
// source: pb/envelope.proto

package pb

import (
	pb "github.com/seqsy/go-libp2p/core/crypto/pb"
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

// Envelope encloses a signed payload produced by a peer, along with the public
// key of the keypair it was signed with so that it can be statelessly validated
// by the receiver.
//
// The payload is prefixed with a byte string that determines the type, so it
// can be deserialized deterministically. Often, this byte string is a
// multicodec.
type Envelope struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// public_key is the public key of the keypair the enclosed payload was
	// signed with.
	PublicKey *pb.PublicKey `protobuf:"bytes,1,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	// payload_type encodes the type of payload, so that it can be deserialized
	// deterministically.
	PayloadType []byte `protobuf:"bytes,2,opt,name=payload_type,json=payloadType,proto3" json:"payload_type,omitempty"`
	// payload is the actual payload carried inside this envelope.
	Payload []byte `protobuf:"bytes,3,opt,name=payload,proto3" json:"payload,omitempty"`
	// signature is the signature produced by the private key corresponding to
	// the enclosed public key, over the payload, prefixing a domain string for
	// additional security.
	Signature []byte `protobuf:"bytes,5,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *Envelope) Reset() {
	*x = Envelope{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pb_envelope_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Envelope) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Envelope) ProtoMessage() {}

func (x *Envelope) ProtoReflect() protoreflect.Message {
	mi := &file_pb_envelope_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Envelope.ProtoReflect.Descriptor instead.
func (*Envelope) Descriptor() ([]byte, []int) {
	return file_pb_envelope_proto_rawDescGZIP(), []int{0}
}

func (x *Envelope) GetPublicKey() *pb.PublicKey {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

func (x *Envelope) GetPayloadType() []byte {
	if x != nil {
		return x.PayloadType
	}
	return nil
}

func (x *Envelope) GetPayload() []byte {
	if x != nil {
		return x.Payload
	}
	return nil
}

func (x *Envelope) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

var File_pb_envelope_proto protoreflect.FileDescriptor

var file_pb_envelope_proto_rawDesc = []byte{
	0x0a, 0x11, 0x70, 0x62, 0x2f, 0x65, 0x6e, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x09, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x2e, 0x70, 0x62, 0x1a, 0x1b,
	0x63, 0x6f, 0x72, 0x65, 0x2f, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2f, 0x70, 0x62, 0x2f, 0x63,
	0x72, 0x79, 0x70, 0x74, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x9a, 0x01, 0x0a, 0x08,
	0x45, 0x6e, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x12, 0x33, 0x0a, 0x0a, 0x70, 0x75, 0x62, 0x6c,
	0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x63,
	0x72, 0x79, 0x70, 0x74, 0x6f, 0x2e, 0x70, 0x62, 0x2e, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b,
	0x65, 0x79, 0x52, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x21, 0x0a,
	0x0c, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x0b, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x54, 0x79, 0x70, 0x65,
	0x12, 0x18, 0x0a, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69,
	0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73,
	0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_pb_envelope_proto_rawDescOnce sync.Once
	file_pb_envelope_proto_rawDescData = file_pb_envelope_proto_rawDesc
)

func file_pb_envelope_proto_rawDescGZIP() []byte {
	file_pb_envelope_proto_rawDescOnce.Do(func() {
		file_pb_envelope_proto_rawDescData = protoimpl.X.CompressGZIP(file_pb_envelope_proto_rawDescData)
	})
	return file_pb_envelope_proto_rawDescData
}

var file_pb_envelope_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_pb_envelope_proto_goTypes = []interface{}{
	(*Envelope)(nil),     // 0: record.pb.Envelope
	(*pb.PublicKey)(nil), // 1: crypto.pb.PublicKey
}
var file_pb_envelope_proto_depIdxs = []int32{
	1, // 0: record.pb.Envelope.public_key:type_name -> crypto.pb.PublicKey
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_pb_envelope_proto_init() }
func file_pb_envelope_proto_init() {
	if File_pb_envelope_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pb_envelope_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Envelope); i {
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
			RawDescriptor: file_pb_envelope_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_pb_envelope_proto_goTypes,
		DependencyIndexes: file_pb_envelope_proto_depIdxs,
		MessageInfos:      file_pb_envelope_proto_msgTypes,
	}.Build()
	File_pb_envelope_proto = out.File
	file_pb_envelope_proto_rawDesc = nil
	file_pb_envelope_proto_goTypes = nil
	file_pb_envelope_proto_depIdxs = nil
}
