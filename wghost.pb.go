// Code generated by protoc-gen-go. DO NOT EDIT.
// source: wghost.proto

package wghost

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	timestamp "github.com/golang/protobuf/ptypes/timestamp"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type PeerConfig struct {
	// PublicKey is the public key of a peer, computed from its private key.
	PublicKey string `protobuf:"bytes,1,opt,name=PublicKey,proto3" json:"PublicKey,omitempty"`
	// PresharedKey is an optional preshared key which may be used as an
	// additional layer of security for peer communications.
	PresharedKey string `protobuf:"bytes,2,opt,name=PresharedKey,proto3" json:"PresharedKey,omitempty"`
	// AllowedIPs specifies which IPv4 and IPv6 addresses this peer is allowed
	// to communicate on.
	//
	// 0.0.0.0/0 indicates that all IPv4 addresses are allowed, and ::/0
	// indicates that all IPv6 addresses are allowed.
	AllowedIPs           []string `protobuf:"bytes,3,rep,name=AllowedIPs,proto3" json:"AllowedIPs,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PeerConfig) Reset()         { *m = PeerConfig{} }
func (m *PeerConfig) String() string { return proto.CompactTextString(m) }
func (*PeerConfig) ProtoMessage()    {}
func (*PeerConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_af5326e8f7a8c8f0, []int{0}
}

func (m *PeerConfig) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PeerConfig.Unmarshal(m, b)
}
func (m *PeerConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PeerConfig.Marshal(b, m, deterministic)
}
func (m *PeerConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PeerConfig.Merge(m, src)
}
func (m *PeerConfig) XXX_Size() int {
	return xxx_messageInfo_PeerConfig.Size(m)
}
func (m *PeerConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_PeerConfig.DiscardUnknown(m)
}

var xxx_messageInfo_PeerConfig proto.InternalMessageInfo

func (m *PeerConfig) GetPublicKey() string {
	if m != nil {
		return m.PublicKey
	}
	return ""
}

func (m *PeerConfig) GetPresharedKey() string {
	if m != nil {
		return m.PresharedKey
	}
	return ""
}

func (m *PeerConfig) GetAllowedIPs() []string {
	if m != nil {
		return m.AllowedIPs
	}
	return nil
}

type PeerConfigList struct {
	// ReplacePeers specifies if the Peers in this configuration should replace
	// the existing peer list, instead of appending them to the existing list.
	ReplacePeers bool `protobuf:"varint,1,opt,name=ReplacePeers,proto3" json:"ReplacePeers,omitempty"`
	// Peers specifies a list of peer configurations to apply to a device.
	Peers                []*PeerConfig `protobuf:"bytes,2,rep,name=Peers,proto3" json:"Peers,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *PeerConfigList) Reset()         { *m = PeerConfigList{} }
func (m *PeerConfigList) String() string { return proto.CompactTextString(m) }
func (*PeerConfigList) ProtoMessage()    {}
func (*PeerConfigList) Descriptor() ([]byte, []int) {
	return fileDescriptor_af5326e8f7a8c8f0, []int{1}
}

func (m *PeerConfigList) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PeerConfigList.Unmarshal(m, b)
}
func (m *PeerConfigList) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PeerConfigList.Marshal(b, m, deterministic)
}
func (m *PeerConfigList) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PeerConfigList.Merge(m, src)
}
func (m *PeerConfigList) XXX_Size() int {
	return xxx_messageInfo_PeerConfigList.Size(m)
}
func (m *PeerConfigList) XXX_DiscardUnknown() {
	xxx_messageInfo_PeerConfigList.DiscardUnknown(m)
}

var xxx_messageInfo_PeerConfigList proto.InternalMessageInfo

func (m *PeerConfigList) GetReplacePeers() bool {
	if m != nil {
		return m.ReplacePeers
	}
	return false
}

func (m *PeerConfigList) GetPeers() []*PeerConfig {
	if m != nil {
		return m.Peers
	}
	return nil
}

type PeerQuery struct {
	// PublicKey is the public key of a peer, computed from its private key.
	PublicKey            string   `protobuf:"bytes,1,opt,name=PublicKey,proto3" json:"PublicKey,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PeerQuery) Reset()         { *m = PeerQuery{} }
func (m *PeerQuery) String() string { return proto.CompactTextString(m) }
func (*PeerQuery) ProtoMessage()    {}
func (*PeerQuery) Descriptor() ([]byte, []int) {
	return fileDescriptor_af5326e8f7a8c8f0, []int{2}
}

func (m *PeerQuery) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PeerQuery.Unmarshal(m, b)
}
func (m *PeerQuery) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PeerQuery.Marshal(b, m, deterministic)
}
func (m *PeerQuery) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PeerQuery.Merge(m, src)
}
func (m *PeerQuery) XXX_Size() int {
	return xxx_messageInfo_PeerQuery.Size(m)
}
func (m *PeerQuery) XXX_DiscardUnknown() {
	xxx_messageInfo_PeerQuery.DiscardUnknown(m)
}

var xxx_messageInfo_PeerQuery proto.InternalMessageInfo

func (m *PeerQuery) GetPublicKey() string {
	if m != nil {
		return m.PublicKey
	}
	return ""
}

type Endpoint struct {
	IP                   string   `protobuf:"bytes,1,opt,name=IP,proto3" json:"IP,omitempty"`
	Port                 int32    `protobuf:"varint,2,opt,name=Port,proto3" json:"Port,omitempty"`
	Zone                 string   `protobuf:"bytes,3,opt,name=Zone,proto3" json:"Zone,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Endpoint) Reset()         { *m = Endpoint{} }
func (m *Endpoint) String() string { return proto.CompactTextString(m) }
func (*Endpoint) ProtoMessage()    {}
func (*Endpoint) Descriptor() ([]byte, []int) {
	return fileDescriptor_af5326e8f7a8c8f0, []int{3}
}

func (m *Endpoint) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Endpoint.Unmarshal(m, b)
}
func (m *Endpoint) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Endpoint.Marshal(b, m, deterministic)
}
func (m *Endpoint) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Endpoint.Merge(m, src)
}
func (m *Endpoint) XXX_Size() int {
	return xxx_messageInfo_Endpoint.Size(m)
}
func (m *Endpoint) XXX_DiscardUnknown() {
	xxx_messageInfo_Endpoint.DiscardUnknown(m)
}

var xxx_messageInfo_Endpoint proto.InternalMessageInfo

func (m *Endpoint) GetIP() string {
	if m != nil {
		return m.IP
	}
	return ""
}

func (m *Endpoint) GetPort() int32 {
	if m != nil {
		return m.Port
	}
	return 0
}

func (m *Endpoint) GetZone() string {
	if m != nil {
		return m.Zone
	}
	return ""
}

type Peer struct {
	// PublicKey is the public key of a peer, computed from its private key.
	PublicKey string `protobuf:"bytes,1,opt,name=PublicKey,proto3" json:"PublicKey,omitempty"`
	// PresharedKey is an optional preshared key which may be used as an
	// additional layer of security for peer communications.
	PresharedKey string `protobuf:"bytes,2,opt,name=PresharedKey,proto3" json:"PresharedKey,omitempty"`
	// Endpoint is the most recent source address used for communication by
	// this Peer.
	Endpoint *Endpoint `protobuf:"bytes,3,opt,name=Endpoint,proto3" json:"Endpoint,omitempty"`
	// LastHandshakeTime indicates the most recent time a handshake was performed
	// with this peer.
	//
	// A zero-value time.Time indicates that no handshake has taken place with
	// this peer.
	LastHandshakeTime *timestamp.Timestamp `protobuf:"bytes,4,opt,name=LastHandshakeTime,proto3" json:"LastHandshakeTime,omitempty"`
	// ReceiveBytes indicates the number of bytes received from this peer.
	ReceiveBytes int64 `protobuf:"varint,5,opt,name=ReceiveBytes,proto3" json:"ReceiveBytes,omitempty"`
	// TransmitBytes indicates the number of bytes transmitted to this peer.
	TransmitBytes int64 `protobuf:"varint,6,opt,name=TransmitBytes,proto3" json:"TransmitBytes,omitempty"`
	// AllowedIPs specifies which IPv4 and IPv6 addresses this peer is allowed
	// to communicate on.
	//
	// 0.0.0.0/0 indicates that all IPv4 addresses are allowed, and ::/0
	// indicates that all IPv6 addresses are allowed.
	AllowedIPs []string `protobuf:"bytes,7,rep,name=AllowedIPs,proto3" json:"AllowedIPs,omitempty"`
	// ProtocolVersion specifies which version of the WireGuard protocol is used
	// for this Peer.
	//
	// A value of 0 indicates that the most recent protocol version will be used.
	ProtocolVersion      int32    `protobuf:"varint,8,opt,name=ProtocolVersion,proto3" json:"ProtocolVersion,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Peer) Reset()         { *m = Peer{} }
func (m *Peer) String() string { return proto.CompactTextString(m) }
func (*Peer) ProtoMessage()    {}
func (*Peer) Descriptor() ([]byte, []int) {
	return fileDescriptor_af5326e8f7a8c8f0, []int{4}
}

func (m *Peer) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Peer.Unmarshal(m, b)
}
func (m *Peer) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Peer.Marshal(b, m, deterministic)
}
func (m *Peer) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Peer.Merge(m, src)
}
func (m *Peer) XXX_Size() int {
	return xxx_messageInfo_Peer.Size(m)
}
func (m *Peer) XXX_DiscardUnknown() {
	xxx_messageInfo_Peer.DiscardUnknown(m)
}

var xxx_messageInfo_Peer proto.InternalMessageInfo

func (m *Peer) GetPublicKey() string {
	if m != nil {
		return m.PublicKey
	}
	return ""
}

func (m *Peer) GetPresharedKey() string {
	if m != nil {
		return m.PresharedKey
	}
	return ""
}

func (m *Peer) GetEndpoint() *Endpoint {
	if m != nil {
		return m.Endpoint
	}
	return nil
}

func (m *Peer) GetLastHandshakeTime() *timestamp.Timestamp {
	if m != nil {
		return m.LastHandshakeTime
	}
	return nil
}

func (m *Peer) GetReceiveBytes() int64 {
	if m != nil {
		return m.ReceiveBytes
	}
	return 0
}

func (m *Peer) GetTransmitBytes() int64 {
	if m != nil {
		return m.TransmitBytes
	}
	return 0
}

func (m *Peer) GetAllowedIPs() []string {
	if m != nil {
		return m.AllowedIPs
	}
	return nil
}

func (m *Peer) GetProtocolVersion() int32 {
	if m != nil {
		return m.ProtocolVersion
	}
	return 0
}

type ConfigSuccess struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ConfigSuccess) Reset()         { *m = ConfigSuccess{} }
func (m *ConfigSuccess) String() string { return proto.CompactTextString(m) }
func (*ConfigSuccess) ProtoMessage()    {}
func (*ConfigSuccess) Descriptor() ([]byte, []int) {
	return fileDescriptor_af5326e8f7a8c8f0, []int{5}
}

func (m *ConfigSuccess) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ConfigSuccess.Unmarshal(m, b)
}
func (m *ConfigSuccess) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ConfigSuccess.Marshal(b, m, deterministic)
}
func (m *ConfigSuccess) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ConfigSuccess.Merge(m, src)
}
func (m *ConfigSuccess) XXX_Size() int {
	return xxx_messageInfo_ConfigSuccess.Size(m)
}
func (m *ConfigSuccess) XXX_DiscardUnknown() {
	xxx_messageInfo_ConfigSuccess.DiscardUnknown(m)
}

var xxx_messageInfo_ConfigSuccess proto.InternalMessageInfo

type PeerListQuery struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PeerListQuery) Reset()         { *m = PeerListQuery{} }
func (m *PeerListQuery) String() string { return proto.CompactTextString(m) }
func (*PeerListQuery) ProtoMessage()    {}
func (*PeerListQuery) Descriptor() ([]byte, []int) {
	return fileDescriptor_af5326e8f7a8c8f0, []int{6}
}

func (m *PeerListQuery) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PeerListQuery.Unmarshal(m, b)
}
func (m *PeerListQuery) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PeerListQuery.Marshal(b, m, deterministic)
}
func (m *PeerListQuery) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PeerListQuery.Merge(m, src)
}
func (m *PeerListQuery) XXX_Size() int {
	return xxx_messageInfo_PeerListQuery.Size(m)
}
func (m *PeerListQuery) XXX_DiscardUnknown() {
	xxx_messageInfo_PeerListQuery.DiscardUnknown(m)
}

var xxx_messageInfo_PeerListQuery proto.InternalMessageInfo

type PeerList struct {
	Peers                []*Peer  `protobuf:"bytes,1,rep,name=Peers,proto3" json:"Peers,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PeerList) Reset()         { *m = PeerList{} }
func (m *PeerList) String() string { return proto.CompactTextString(m) }
func (*PeerList) ProtoMessage()    {}
func (*PeerList) Descriptor() ([]byte, []int) {
	return fileDescriptor_af5326e8f7a8c8f0, []int{7}
}

func (m *PeerList) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PeerList.Unmarshal(m, b)
}
func (m *PeerList) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PeerList.Marshal(b, m, deterministic)
}
func (m *PeerList) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PeerList.Merge(m, src)
}
func (m *PeerList) XXX_Size() int {
	return xxx_messageInfo_PeerList.Size(m)
}
func (m *PeerList) XXX_DiscardUnknown() {
	xxx_messageInfo_PeerList.DiscardUnknown(m)
}

var xxx_messageInfo_PeerList proto.InternalMessageInfo

func (m *PeerList) GetPeers() []*Peer {
	if m != nil {
		return m.Peers
	}
	return nil
}

func init() {
	proto.RegisterType((*PeerConfig)(nil), "wghost.PeerConfig")
	proto.RegisterType((*PeerConfigList)(nil), "wghost.PeerConfigList")
	proto.RegisterType((*PeerQuery)(nil), "wghost.PeerQuery")
	proto.RegisterType((*Endpoint)(nil), "wghost.Endpoint")
	proto.RegisterType((*Peer)(nil), "wghost.Peer")
	proto.RegisterType((*ConfigSuccess)(nil), "wghost.ConfigSuccess")
	proto.RegisterType((*PeerListQuery)(nil), "wghost.PeerListQuery")
	proto.RegisterType((*PeerList)(nil), "wghost.PeerList")
}

func init() { proto.RegisterFile("wghost.proto", fileDescriptor_af5326e8f7a8c8f0) }

var fileDescriptor_af5326e8f7a8c8f0 = []byte{
	// 485 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x92, 0xcf, 0x6b, 0xdb, 0x30,
	0x14, 0xc7, 0x13, 0x3b, 0x3f, 0xec, 0xd7, 0xf4, 0x97, 0xa0, 0xc3, 0x98, 0xb1, 0x05, 0xb1, 0x83,
	0x07, 0xc5, 0x85, 0x0c, 0x7a, 0xd9, 0xa9, 0x1d, 0x63, 0x0d, 0xeb, 0xc1, 0x73, 0xc3, 0x06, 0x3b,
	0x0c, 0x1c, 0xfb, 0xd5, 0x11, 0x73, 0xac, 0x60, 0x29, 0x2b, 0xf9, 0x3f, 0x77, 0xdf, 0xbf, 0x32,
	0x24, 0xc5, 0x73, 0x9c, 0x6e, 0x3b, 0xf5, 0x26, 0x7d, 0xf4, 0x7d, 0x7a, 0x3f, 0xbe, 0x0f, 0x46,
	0x0f, 0xf9, 0x82, 0x0b, 0x19, 0xae, 0x2a, 0x2e, 0x39, 0x19, 0x98, 0x9b, 0xff, 0x32, 0xe7, 0x3c,
	0x2f, 0xf0, 0x42, 0xd3, 0xf9, 0xfa, 0xfe, 0x42, 0xb2, 0x25, 0x0a, 0x99, 0x2c, 0x57, 0x46, 0x48,
	0x4b, 0x80, 0x08, 0xb1, 0x7a, 0xc7, 0xcb, 0x7b, 0x96, 0x93, 0xe7, 0xe0, 0x46, 0xeb, 0x79, 0xc1,
	0xd2, 0x8f, 0xb8, 0xf1, 0xba, 0xe3, 0x6e, 0xe0, 0xc6, 0x0d, 0x20, 0x14, 0x46, 0x51, 0x85, 0x62,
	0x91, 0x54, 0x98, 0x29, 0x81, 0xa5, 0x05, 0x2d, 0x46, 0x5e, 0x00, 0x5c, 0x15, 0x05, 0x7f, 0xc0,
	0x6c, 0x1a, 0x09, 0xcf, 0x1e, 0xdb, 0x81, 0x1b, 0xef, 0x10, 0xfa, 0x0d, 0x8e, 0x9a, 0x7c, 0xb7,
	0x4c, 0x48, 0xf5, 0x6b, 0x8c, 0xab, 0x22, 0x49, 0x51, 0x3d, 0x08, 0x9d, 0xd6, 0x89, 0x5b, 0x8c,
	0x04, 0xd0, 0x37, 0x8f, 0xd6, 0xd8, 0x0e, 0x0e, 0x26, 0x24, 0xdc, 0x36, 0xdb, 0x7c, 0x15, 0x1b,
	0x01, 0x7d, 0x0d, 0xae, 0x3a, 0x7c, 0x5a, 0x63, 0xb5, 0xf9, 0x7f, 0x3b, 0xf4, 0x1a, 0x9c, 0xf7,
	0x65, 0xb6, 0xe2, 0xac, 0x94, 0xe4, 0x08, 0xac, 0x69, 0xb4, 0x95, 0x58, 0xd3, 0x88, 0x10, 0xe8,
	0x45, 0xbc, 0x92, 0xba, 0xc5, 0x7e, 0xac, 0xcf, 0x8a, 0x7d, 0xe5, 0x25, 0x7a, 0xb6, 0x56, 0xe9,
	0x33, 0xfd, 0x69, 0x41, 0x4f, 0xe5, 0x7b, 0x82, 0xc9, 0x9d, 0x37, 0xe5, 0xe8, 0x14, 0x07, 0x93,
	0x93, 0xba, 0xcd, 0x9a, 0xc7, 0x4d, 0xc1, 0x37, 0x70, 0x7a, 0x9b, 0x08, 0x79, 0x93, 0x94, 0x99,
	0x58, 0x24, 0xdf, 0x71, 0xc6, 0x96, 0xe8, 0xf5, 0x74, 0x98, 0x1f, 0x1a, 0xd3, 0xc3, 0xda, 0xf4,
	0x70, 0x56, 0x9b, 0x1e, 0x3f, 0x0e, 0x32, 0xf3, 0x4f, 0x91, 0xfd, 0xc0, 0xeb, 0x8d, 0x44, 0xe1,
	0xf5, 0xc7, 0xdd, 0xc0, 0x8e, 0x5b, 0x8c, 0xbc, 0x82, 0xc3, 0x59, 0x95, 0x94, 0x62, 0xc9, 0xa4,
	0x11, 0x0d, 0xb4, 0xa8, 0x0d, 0xf7, 0xbc, 0x1f, 0xee, 0x7b, 0x4f, 0x02, 0x38, 0x8e, 0x54, 0x49,
	0x29, 0x2f, 0x3e, 0x63, 0x25, 0x18, 0x2f, 0x3d, 0x47, 0xcf, 0x77, 0x1f, 0xd3, 0x63, 0x38, 0x34,
	0xb6, 0xde, 0xad, 0xd3, 0x14, 0x85, 0x50, 0x40, 0x8d, 0x59, 0x2d, 0x8c, 0xb6, 0x96, 0x86, 0xe0,
	0xd4, 0x80, 0xd0, 0x7a, 0x3b, 0xba, 0x7a, 0x3b, 0x46, 0xbb, 0xdb, 0xb1, 0xdd, 0x8b, 0xc9, 0xaf,
	0x2e, 0x58, 0x5f, 0x72, 0x72, 0x09, 0xc3, 0xab, 0x2c, 0xd3, 0x8e, 0xfd, 0x65, 0x89, 0xfc, 0xb3,
	0x9a, 0xb5, 0xb3, 0x77, 0xc8, 0x5b, 0x70, 0xee, 0x50, 0x9a, 0x65, 0x7c, 0xf6, 0x38, 0x50, 0x95,
	0xf1, 0xef, 0xe0, 0x73, 0x18, 0x7e, 0x30, 0xc1, 0xe4, 0x74, 0x37, 0x56, 0x77, 0xe2, 0xb7, 0xca,
	0xa5, 0x1d, 0x72, 0x09, 0xae, 0xfa, 0xce, 0xe4, 0x3a, 0xdb, 0x7d, 0xfc, 0xd3, 0xbd, 0x7f, 0xb2,
	0x8f, 0x69, 0x67, 0x3e, 0xd0, 0x76, 0xbf, 0xf9, 0x1d, 0x00, 0x00, 0xff, 0xff, 0x33, 0xed, 0xa3,
	0x28, 0x09, 0x04, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// WgClient is the client API for Wg service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type WgClient interface {
	AddPeer(ctx context.Context, in *PeerConfig, opts ...grpc.CallOption) (*ConfigSuccess, error)
	SetPeers(ctx context.Context, in *PeerConfigList, opts ...grpc.CallOption) (*ConfigSuccess, error)
	GetPeer(ctx context.Context, in *PeerQuery, opts ...grpc.CallOption) (*Peer, error)
	ListPeers(ctx context.Context, in *PeerListQuery, opts ...grpc.CallOption) (*PeerList, error)
}

type wgClient struct {
	cc *grpc.ClientConn
}

func NewWgClient(cc *grpc.ClientConn) WgClient {
	return &wgClient{cc}
}

func (c *wgClient) AddPeer(ctx context.Context, in *PeerConfig, opts ...grpc.CallOption) (*ConfigSuccess, error) {
	out := new(ConfigSuccess)
	err := c.cc.Invoke(ctx, "/wghost.Wg/AddPeer", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *wgClient) SetPeers(ctx context.Context, in *PeerConfigList, opts ...grpc.CallOption) (*ConfigSuccess, error) {
	out := new(ConfigSuccess)
	err := c.cc.Invoke(ctx, "/wghost.Wg/SetPeers", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *wgClient) GetPeer(ctx context.Context, in *PeerQuery, opts ...grpc.CallOption) (*Peer, error) {
	out := new(Peer)
	err := c.cc.Invoke(ctx, "/wghost.Wg/GetPeer", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *wgClient) ListPeers(ctx context.Context, in *PeerListQuery, opts ...grpc.CallOption) (*PeerList, error) {
	out := new(PeerList)
	err := c.cc.Invoke(ctx, "/wghost.Wg/ListPeers", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// WgServer is the server API for Wg service.
type WgServer interface {
	AddPeer(context.Context, *PeerConfig) (*ConfigSuccess, error)
	SetPeers(context.Context, *PeerConfigList) (*ConfigSuccess, error)
	GetPeer(context.Context, *PeerQuery) (*Peer, error)
	ListPeers(context.Context, *PeerListQuery) (*PeerList, error)
}

// UnimplementedWgServer can be embedded to have forward compatible implementations.
type UnimplementedWgServer struct {
}

func (*UnimplementedWgServer) AddPeer(ctx context.Context, req *PeerConfig) (*ConfigSuccess, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AddPeer not implemented")
}
func (*UnimplementedWgServer) SetPeers(ctx context.Context, req *PeerConfigList) (*ConfigSuccess, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetPeers not implemented")
}
func (*UnimplementedWgServer) GetPeer(ctx context.Context, req *PeerQuery) (*Peer, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPeer not implemented")
}
func (*UnimplementedWgServer) ListPeers(ctx context.Context, req *PeerListQuery) (*PeerList, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListPeers not implemented")
}

func RegisterWgServer(s *grpc.Server, srv WgServer) {
	s.RegisterService(&_Wg_serviceDesc, srv)
}

func _Wg_AddPeer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PeerConfig)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WgServer).AddPeer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/wghost.Wg/AddPeer",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WgServer).AddPeer(ctx, req.(*PeerConfig))
	}
	return interceptor(ctx, in, info, handler)
}

func _Wg_SetPeers_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PeerConfigList)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WgServer).SetPeers(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/wghost.Wg/SetPeers",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WgServer).SetPeers(ctx, req.(*PeerConfigList))
	}
	return interceptor(ctx, in, info, handler)
}

func _Wg_GetPeer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PeerQuery)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WgServer).GetPeer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/wghost.Wg/GetPeer",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WgServer).GetPeer(ctx, req.(*PeerQuery))
	}
	return interceptor(ctx, in, info, handler)
}

func _Wg_ListPeers_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PeerListQuery)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WgServer).ListPeers(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/wghost.Wg/ListPeers",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WgServer).ListPeers(ctx, req.(*PeerListQuery))
	}
	return interceptor(ctx, in, info, handler)
}

var _Wg_serviceDesc = grpc.ServiceDesc{
	ServiceName: "wghost.Wg",
	HandlerType: (*WgServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "AddPeer",
			Handler:    _Wg_AddPeer_Handler,
		},
		{
			MethodName: "SetPeers",
			Handler:    _Wg_SetPeers_Handler,
		},
		{
			MethodName: "GetPeer",
			Handler:    _Wg_GetPeer_Handler,
		},
		{
			MethodName: "ListPeers",
			Handler:    _Wg_ListPeers_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "wghost.proto",
}
