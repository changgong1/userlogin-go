// Code generated by protoc-gen-go. DO NOT EDIT.
// source: login_guide/login_guide.proto

package userlogin

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
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

type LoginStreamRequest struct {
	Type                 string        `protobuf:"bytes,1,opt,name=type,proto3" json:"type,omitempty"`
	Param                *LoginRequest `protobuf:"bytes,2,opt,name=param,proto3" json:"param,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *LoginStreamRequest) Reset()         { *m = LoginStreamRequest{} }
func (m *LoginStreamRequest) String() string { return proto.CompactTextString(m) }
func (*LoginStreamRequest) ProtoMessage()    {}
func (*LoginStreamRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_297f1529e65767ff, []int{0}
}

func (m *LoginStreamRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LoginStreamRequest.Unmarshal(m, b)
}
func (m *LoginStreamRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LoginStreamRequest.Marshal(b, m, deterministic)
}
func (m *LoginStreamRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LoginStreamRequest.Merge(m, src)
}
func (m *LoginStreamRequest) XXX_Size() int {
	return xxx_messageInfo_LoginStreamRequest.Size(m)
}
func (m *LoginStreamRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_LoginStreamRequest.DiscardUnknown(m)
}

var xxx_messageInfo_LoginStreamRequest proto.InternalMessageInfo

func (m *LoginStreamRequest) GetType() string {
	if m != nil {
		return m.Type
	}
	return ""
}

func (m *LoginStreamRequest) GetParam() *LoginRequest {
	if m != nil {
		return m.Param
	}
	return nil
}

// The request message containing the user's name.
type LoginRequest struct {
	UserId               string   `protobuf:"bytes,1,opt,name=userId,proto3" json:"userId,omitempty"`
	Password             string   `protobuf:"bytes,2,opt,name=password,proto3" json:"password,omitempty"`
	DeviceId             string   `protobuf:"bytes,3,opt,name=deviceId,proto3" json:"deviceId,omitempty"`
	Onece                string   `protobuf:"bytes,4,opt,name=onece,proto3" json:"onece,omitempty"`
	Signature            string   `protobuf:"bytes,5,opt,name=signature,proto3" json:"signature,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LoginRequest) Reset()         { *m = LoginRequest{} }
func (m *LoginRequest) String() string { return proto.CompactTextString(m) }
func (*LoginRequest) ProtoMessage()    {}
func (*LoginRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_297f1529e65767ff, []int{1}
}

func (m *LoginRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LoginRequest.Unmarshal(m, b)
}
func (m *LoginRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LoginRequest.Marshal(b, m, deterministic)
}
func (m *LoginRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LoginRequest.Merge(m, src)
}
func (m *LoginRequest) XXX_Size() int {
	return xxx_messageInfo_LoginRequest.Size(m)
}
func (m *LoginRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_LoginRequest.DiscardUnknown(m)
}

var xxx_messageInfo_LoginRequest proto.InternalMessageInfo

func (m *LoginRequest) GetUserId() string {
	if m != nil {
		return m.UserId
	}
	return ""
}

func (m *LoginRequest) GetPassword() string {
	if m != nil {
		return m.Password
	}
	return ""
}

func (m *LoginRequest) GetDeviceId() string {
	if m != nil {
		return m.DeviceId
	}
	return ""
}

func (m *LoginRequest) GetOnece() string {
	if m != nil {
		return m.Onece
	}
	return ""
}

func (m *LoginRequest) GetSignature() string {
	if m != nil {
		return m.Signature
	}
	return ""
}

type TokenReply struct {
	Token                string   `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *TokenReply) Reset()         { *m = TokenReply{} }
func (m *TokenReply) String() string { return proto.CompactTextString(m) }
func (*TokenReply) ProtoMessage()    {}
func (*TokenReply) Descriptor() ([]byte, []int) {
	return fileDescriptor_297f1529e65767ff, []int{2}
}

func (m *TokenReply) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TokenReply.Unmarshal(m, b)
}
func (m *TokenReply) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TokenReply.Marshal(b, m, deterministic)
}
func (m *TokenReply) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TokenReply.Merge(m, src)
}
func (m *TokenReply) XXX_Size() int {
	return xxx_messageInfo_TokenReply.Size(m)
}
func (m *TokenReply) XXX_DiscardUnknown() {
	xxx_messageInfo_TokenReply.DiscardUnknown(m)
}

var xxx_messageInfo_TokenReply proto.InternalMessageInfo

func (m *TokenReply) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

type TokenCheckRequest struct {
	Token                string   `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *TokenCheckRequest) Reset()         { *m = TokenCheckRequest{} }
func (m *TokenCheckRequest) String() string { return proto.CompactTextString(m) }
func (*TokenCheckRequest) ProtoMessage()    {}
func (*TokenCheckRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_297f1529e65767ff, []int{3}
}

func (m *TokenCheckRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TokenCheckRequest.Unmarshal(m, b)
}
func (m *TokenCheckRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TokenCheckRequest.Marshal(b, m, deterministic)
}
func (m *TokenCheckRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TokenCheckRequest.Merge(m, src)
}
func (m *TokenCheckRequest) XXX_Size() int {
	return xxx_messageInfo_TokenCheckRequest.Size(m)
}
func (m *TokenCheckRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_TokenCheckRequest.DiscardUnknown(m)
}

var xxx_messageInfo_TokenCheckRequest proto.InternalMessageInfo

func (m *TokenCheckRequest) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

type TokenCheckReply struct {
	Flag                 int32    `protobuf:"varint,1,opt,name=flag,proto3" json:"flag,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *TokenCheckReply) Reset()         { *m = TokenCheckReply{} }
func (m *TokenCheckReply) String() string { return proto.CompactTextString(m) }
func (*TokenCheckReply) ProtoMessage()    {}
func (*TokenCheckReply) Descriptor() ([]byte, []int) {
	return fileDescriptor_297f1529e65767ff, []int{4}
}

func (m *TokenCheckReply) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TokenCheckReply.Unmarshal(m, b)
}
func (m *TokenCheckReply) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TokenCheckReply.Marshal(b, m, deterministic)
}
func (m *TokenCheckReply) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TokenCheckReply.Merge(m, src)
}
func (m *TokenCheckReply) XXX_Size() int {
	return xxx_messageInfo_TokenCheckReply.Size(m)
}
func (m *TokenCheckReply) XXX_DiscardUnknown() {
	xxx_messageInfo_TokenCheckReply.DiscardUnknown(m)
}

var xxx_messageInfo_TokenCheckReply proto.InternalMessageInfo

func (m *TokenCheckReply) GetFlag() int32 {
	if m != nil {
		return m.Flag
	}
	return 0
}

func init() {
	proto.RegisterType((*LoginStreamRequest)(nil), "userlogin.LoginStreamRequest")
	proto.RegisterType((*LoginRequest)(nil), "userlogin.LoginRequest")
	proto.RegisterType((*TokenReply)(nil), "userlogin.TokenReply")
	proto.RegisterType((*TokenCheckRequest)(nil), "userlogin.TokenCheckRequest")
	proto.RegisterType((*TokenCheckReply)(nil), "userlogin.TokenCheckReply")
}

func init() {
	proto.RegisterFile("login_guide/login_guide.proto", fileDescriptor_297f1529e65767ff)
}

var fileDescriptor_297f1529e65767ff = []byte{
	// 346 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x52, 0x4d, 0x4b, 0xf3, 0x40,
	0x10, 0x7e, 0xf3, 0xda, 0x54, 0x33, 0x56, 0x8a, 0x83, 0x1f, 0x21, 0xb4, 0x50, 0x02, 0x42, 0x3d,
	0x58, 0xa5, 0x9e, 0x05, 0xc1, 0x83, 0x16, 0xf4, 0xb2, 0x2a, 0xde, 0x94, 0xd8, 0x8c, 0x31, 0xb4,
	0x4d, 0xe2, 0xee, 0x46, 0xe9, 0xdf, 0xf0, 0xb7, 0xf9, 0x83, 0x64, 0x27, 0x69, 0x1b, 0x8b, 0xbd,
	0x78, 0x9b, 0xe7, 0x63, 0x1e, 0x9e, 0x5d, 0x06, 0xda, 0xe3, 0x34, 0x8a, 0x93, 0xa7, 0x28, 0x8f,
	0x43, 0x3a, 0xae, 0xcc, 0xbd, 0x4c, 0xa6, 0x3a, 0x45, 0x27, 0x57, 0x24, 0x99, 0xf6, 0x1f, 0x00,
	0xaf, 0xcd, 0x70, 0xab, 0x25, 0x05, 0x13, 0x41, 0x6f, 0x39, 0x29, 0x8d, 0x08, 0x35, 0x3d, 0xcd,
	0xc8, 0xb5, 0x3a, 0x56, 0xd7, 0x11, 0x3c, 0xe3, 0x11, 0xd8, 0x59, 0x20, 0x83, 0x89, 0xfb, 0xbf,
	0x63, 0x75, 0x37, 0xfb, 0xfb, 0xbd, 0x79, 0x48, 0x8f, 0x13, 0xca, 0x5d, 0x51, 0xb8, 0xfc, 0x4f,
	0x0b, 0x1a, 0x55, 0x1e, 0xf7, 0xa0, 0x6e, 0x36, 0x06, 0x61, 0x99, 0x5a, 0x22, 0xf4, 0x60, 0x23,
	0x0b, 0x94, 0xfa, 0x48, 0x65, 0xc8, 0xd1, 0x8e, 0x98, 0x63, 0xa3, 0x85, 0xf4, 0x1e, 0x0f, 0x69,
	0x10, 0xba, 0x6b, 0x85, 0x36, 0xc3, 0xb8, 0x03, 0x76, 0x9a, 0xd0, 0x90, 0xdc, 0x1a, 0x0b, 0x05,
	0xc0, 0x16, 0x38, 0x2a, 0x8e, 0x92, 0x40, 0xe7, 0x92, 0x5c, 0x9b, 0x95, 0x05, 0xe1, 0xfb, 0x00,
	0x77, 0xe9, 0x88, 0x12, 0x41, 0xd9, 0x78, 0x6a, 0x12, 0xb4, 0x41, 0x65, 0xa1, 0x02, 0xf8, 0x87,
	0xb0, 0xcd, 0x9e, 0x8b, 0x57, 0x1a, 0x8e, 0x66, 0xe5, 0x7f, 0xb7, 0x1e, 0x40, 0xb3, 0x6a, 0x35,
	0x99, 0x08, 0xb5, 0x97, 0x71, 0x10, 0xb1, 0xcf, 0x16, 0x3c, 0xf7, 0xbf, 0x2c, 0x58, 0xbf, 0x94,
	0x44, 0x9a, 0x24, 0x9e, 0x43, 0xe3, 0x5e, 0x91, 0x14, 0x14, 0xc5, 0xca, 0xe0, 0x55, 0xdf, 0xe8,
	0xed, 0x56, 0x84, 0x45, 0x67, 0xff, 0x1f, 0x9e, 0x81, 0x63, 0x12, 0xd8, 0xfc, 0x87, 0xf5, 0xab,
	0xf2, 0x0b, 0xb8, 0x33, 0xb6, 0x96, 0x6d, 0xd5, 0x57, 0x7b, 0xde, 0x0a, 0x95, 0x93, 0xfa, 0x8f,
	0xb0, 0x55, 0x5c, 0xcd, 0xec, 0x6d, 0x37, 0xd0, 0x2c, 0x88, 0x45, 0xbf, 0xf6, 0x72, 0xbf, 0x1f,
	0x77, 0xb6, 0xb2, 0x65, 0xd7, 0x3a, 0xb1, 0x9e, 0xeb, 0x7c, 0xac, 0xa7, 0xdf, 0x01, 0x00, 0x00,
	0xff, 0xff, 0x1e, 0xd0, 0x9c, 0x8c, 0xcd, 0x02, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// GreeterClient is the client API for Greeter service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type GreeterClient interface {
	// Sends a greeting
	UserRegister(ctx context.Context, in *LoginRequest, opts ...grpc.CallOption) (*TokenReply, error)
	UserLogin(ctx context.Context, in *LoginRequest, opts ...grpc.CallOption) (*TokenReply, error)
	TokenCheck(ctx context.Context, in *TokenCheckRequest, opts ...grpc.CallOption) (*TokenCheckReply, error)
}

type greeterClient struct {
	cc grpc.ClientConnInterface
}

func NewGreeterClient(cc grpc.ClientConnInterface) GreeterClient {
	return &greeterClient{cc}
}

func (c *greeterClient) UserRegister(ctx context.Context, in *LoginRequest, opts ...grpc.CallOption) (*TokenReply, error) {
	out := new(TokenReply)
	err := c.cc.Invoke(ctx, "/userlogin.Greeter/UserRegister", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *greeterClient) UserLogin(ctx context.Context, in *LoginRequest, opts ...grpc.CallOption) (*TokenReply, error) {
	out := new(TokenReply)
	err := c.cc.Invoke(ctx, "/userlogin.Greeter/UserLogin", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *greeterClient) TokenCheck(ctx context.Context, in *TokenCheckRequest, opts ...grpc.CallOption) (*TokenCheckReply, error) {
	out := new(TokenCheckReply)
	err := c.cc.Invoke(ctx, "/userlogin.Greeter/TokenCheck", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GreeterServer is the server API for Greeter service.
type GreeterServer interface {
	// Sends a greeting
	UserRegister(context.Context, *LoginRequest) (*TokenReply, error)
	UserLogin(context.Context, *LoginRequest) (*TokenReply, error)
	TokenCheck(context.Context, *TokenCheckRequest) (*TokenCheckReply, error)
}

// UnimplementedGreeterServer can be embedded to have forward compatible implementations.
type UnimplementedGreeterServer struct {
}

func (*UnimplementedGreeterServer) UserRegister(ctx context.Context, req *LoginRequest) (*TokenReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UserRegister not implemented")
}
func (*UnimplementedGreeterServer) UserLogin(ctx context.Context, req *LoginRequest) (*TokenReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UserLogin not implemented")
}
func (*UnimplementedGreeterServer) TokenCheck(ctx context.Context, req *TokenCheckRequest) (*TokenCheckReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method TokenCheck not implemented")
}

func RegisterGreeterServer(s *grpc.Server, srv GreeterServer) {
	s.RegisterService(&_Greeter_serviceDesc, srv)
}

func _Greeter_UserRegister_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LoginRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GreeterServer).UserRegister(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/userlogin.Greeter/UserRegister",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GreeterServer).UserRegister(ctx, req.(*LoginRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Greeter_UserLogin_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LoginRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GreeterServer).UserLogin(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/userlogin.Greeter/UserLogin",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GreeterServer).UserLogin(ctx, req.(*LoginRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Greeter_TokenCheck_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TokenCheckRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GreeterServer).TokenCheck(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/userlogin.Greeter/TokenCheck",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GreeterServer).TokenCheck(ctx, req.(*TokenCheckRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Greeter_serviceDesc = grpc.ServiceDesc{
	ServiceName: "userlogin.Greeter",
	HandlerType: (*GreeterServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "UserRegister",
			Handler:    _Greeter_UserRegister_Handler,
		},
		{
			MethodName: "UserLogin",
			Handler:    _Greeter_UserLogin_Handler,
		},
		{
			MethodName: "TokenCheck",
			Handler:    _Greeter_TokenCheck_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "login_guide/login_guide.proto",
}

// StreamGreeterClient is the client API for StreamGreeter service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type StreamGreeterClient interface {
	StreamUserLogin(ctx context.Context, opts ...grpc.CallOption) (StreamGreeter_StreamUserLoginClient, error)
}

type streamGreeterClient struct {
	cc grpc.ClientConnInterface
}

func NewStreamGreeterClient(cc grpc.ClientConnInterface) StreamGreeterClient {
	return &streamGreeterClient{cc}
}

func (c *streamGreeterClient) StreamUserLogin(ctx context.Context, opts ...grpc.CallOption) (StreamGreeter_StreamUserLoginClient, error) {
	stream, err := c.cc.NewStream(ctx, &_StreamGreeter_serviceDesc.Streams[0], "/userlogin.StreamGreeter/StreamUserLogin", opts...)
	if err != nil {
		return nil, err
	}
	x := &streamGreeterStreamUserLoginClient{stream}
	return x, nil
}

type StreamGreeter_StreamUserLoginClient interface {
	Send(*LoginStreamRequest) error
	Recv() (*TokenReply, error)
	grpc.ClientStream
}

type streamGreeterStreamUserLoginClient struct {
	grpc.ClientStream
}

func (x *streamGreeterStreamUserLoginClient) Send(m *LoginStreamRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *streamGreeterStreamUserLoginClient) Recv() (*TokenReply, error) {
	m := new(TokenReply)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// StreamGreeterServer is the server API for StreamGreeter service.
type StreamGreeterServer interface {
	StreamUserLogin(StreamGreeter_StreamUserLoginServer) error
}

// UnimplementedStreamGreeterServer can be embedded to have forward compatible implementations.
type UnimplementedStreamGreeterServer struct {
}

func (*UnimplementedStreamGreeterServer) StreamUserLogin(srv StreamGreeter_StreamUserLoginServer) error {
	return status.Errorf(codes.Unimplemented, "method StreamUserLogin not implemented")
}

func RegisterStreamGreeterServer(s *grpc.Server, srv StreamGreeterServer) {
	s.RegisterService(&_StreamGreeter_serviceDesc, srv)
}

func _StreamGreeter_StreamUserLogin_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(StreamGreeterServer).StreamUserLogin(&streamGreeterStreamUserLoginServer{stream})
}

type StreamGreeter_StreamUserLoginServer interface {
	Send(*TokenReply) error
	Recv() (*LoginStreamRequest, error)
	grpc.ServerStream
}

type streamGreeterStreamUserLoginServer struct {
	grpc.ServerStream
}

func (x *streamGreeterStreamUserLoginServer) Send(m *TokenReply) error {
	return x.ServerStream.SendMsg(m)
}

func (x *streamGreeterStreamUserLoginServer) Recv() (*LoginStreamRequest, error) {
	m := new(LoginStreamRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

var _StreamGreeter_serviceDesc = grpc.ServiceDesc{
	ServiceName: "userlogin.StreamGreeter",
	HandlerType: (*StreamGreeterServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "StreamUserLogin",
			Handler:       _StreamGreeter_StreamUserLogin_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "login_guide/login_guide.proto",
}
