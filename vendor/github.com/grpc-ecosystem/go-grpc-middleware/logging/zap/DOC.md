# grpc_zap
`import "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"`

* [Overview](#pkg-overview)
* [Imported Packages](#pkg-imports)
* [Index](#pkg-index)

## <a name="pkg-overview">Overview</a>
`grpc_zap` is a gRPC logging middleware backed by ZAP loggers

It accepts a user-configured `zap.Logger` that will be used for logging completed gRPC calls. The same `zap.Logger` will
be used for logging completed gRPC calls, and be populated into the `context.Context` passed into gRPC handler code.

On calling `StreamServerInterceptor` or `UnaryServerInterceptor` this logging middleware will add gRPC call information
to the ctx so that it will be present on subsequent use of the `ctx_zap` logger.

This package also implements request and response *payload* logging, both for server-side and client-side. These will be
logged as structured `jsonbp` fields for every message received/sent (both unary and streaming). For that please use
`Payload*Interceptor` functions for that. Please note that the user-provided function that determines whetether to log
the full request/response payload needs to be written with care, this can significantly slow down gRPC.

ZAP can also be made as a backend for gRPC library internals. For that use `ReplaceGrpcLogger`.

Please see examples and tests for examples of use.

## <a name="pkg-imports">Imported Packages</a>

- [github.com/golang/protobuf/jsonpb](https://godoc.org/github.com/golang/protobuf/jsonpb)
- [github.com/golang/protobuf/proto](https://godoc.org/github.com/golang/protobuf/proto)
- [github.com/grpc-ecosystem/go-grpc-middleware](./../..)
- [github.com/grpc-ecosystem/go-grpc-middleware/logging](./..)
- [github.com/grpc-ecosystem/go-grpc-middleware/tags/zap](./../../tags/zap)
- [go.uber.org/zap](https://godoc.org/go.uber.org/zap)
- [go.uber.org/zap/zapcore](https://godoc.org/go.uber.org/zap/zapcore)
- [golang.org/x/net/context](https://godoc.org/golang.org/x/net/context)
- [google.golang.org/grpc](https://godoc.org/google.golang.org/grpc)
- [google.golang.org/grpc/codes](https://godoc.org/google.golang.org/grpc/codes)
- [google.golang.org/grpc/grpclog](https://godoc.org/google.golang.org/grpc/grpclog)

## <a name="pkg-index">Index</a>
* [Variables](#pkg-variables)
* [func AddFields(ctx context.Context, fields ...zapcore.Field)](#AddFields)
* [func DefaultClientCodeToLevel(code codes.Code) zapcore.Level](#DefaultClientCodeToLevel)
* [func DefaultCodeToLevel(code codes.Code) zapcore.Level](#DefaultCodeToLevel)
* [func DurationToDurationField(duration time.Duration) zapcore.Field](#DurationToDurationField)
* [func DurationToTimeMillisField(duration time.Duration) zapcore.Field](#DurationToTimeMillisField)
* [func Extract(ctx context.Context) \*zap.Logger](#Extract)
* [func PayloadStreamClientInterceptor(logger \*zap.Logger, decider grpc\_logging.ClientPayloadLoggingDecider) grpc.StreamClientInterceptor](#PayloadStreamClientInterceptor)
* [func PayloadStreamServerInterceptor(logger \*zap.Logger, decider grpc\_logging.ServerPayloadLoggingDecider) grpc.StreamServerInterceptor](#PayloadStreamServerInterceptor)
* [func PayloadUnaryClientInterceptor(logger \*zap.Logger, decider grpc\_logging.ClientPayloadLoggingDecider) grpc.UnaryClientInterceptor](#PayloadUnaryClientInterceptor)
* [func PayloadUnaryServerInterceptor(logger \*zap.Logger, decider grpc\_logging.ServerPayloadLoggingDecider) grpc.UnaryServerInterceptor](#PayloadUnaryServerInterceptor)
* [func ReplaceGrpcLogger(logger \*zap.Logger)](#ReplaceGrpcLogger)
* [func StreamClientInterceptor(logger \*zap.Logger, opts ...Option) grpc.StreamClientInterceptor](#StreamClientInterceptor)
* [func StreamServerInterceptor(logger \*zap.Logger, opts ...Option) grpc.StreamServerInterceptor](#StreamServerInterceptor)
* [func UnaryClientInterceptor(logger \*zap.Logger, opts ...Option) grpc.UnaryClientInterceptor](#UnaryClientInterceptor)
* [func UnaryServerInterceptor(logger \*zap.Logger, opts ...Option) grpc.UnaryServerInterceptor](#UnaryServerInterceptor)
* [type CodeToLevel](#CodeToLevel)
* [type DurationToField](#DurationToField)
* [type Option](#Option)
  * [func WithCodes(f grpc\_logging.ErrorToCode) Option](#WithCodes)
  * [func WithDurationField(f DurationToField) Option](#WithDurationField)
  * [func WithLevels(f CodeToLevel) Option](#WithLevels)

#### <a name="pkg-files">Package files</a>
[client_interceptors.go](./client_interceptors.go) [context.go](./context.go) [doc.go](./doc.go) [grpclogger.go](./grpclogger.go) [options.go](./options.go) [payload_interceptors.go](./payload_interceptors.go) [server_interceptors.go](./server_interceptors.go) 

## <a name="pkg-variables">Variables</a>
``` go
var (
    // SystemField is used in every log statement made through grpc_zap. Can be overwritten before any initialization code.
    SystemField = zap.String("system", "grpc")

    // ServerField is used in every server-side log statment made through grpc_zap.Can be overwritten before initialization.
    ServerField = zap.String("span.kind", "server")
)
```
``` go
var (
    // ClientField is used in every client-side log statement made through grpc_zap. Can be overwritten before initialization.
    ClientField = zap.String("span.kind", "client")
)
```
``` go
var DefaultDurationToField = DurationToTimeMillisField
```
DefaultDurationToField is the default implementation of converting request duration to a Zap field.

``` go
var (
    // JsonPBMarshaller is the marshaller used for serializing protobuf messages.
    JsonPbMarshaller = &jsonpb.Marshaler{}
)
```

## <a name="AddFields">func</a> [AddFields](./context.go#L12)
``` go
func AddFields(ctx context.Context, fields ...zapcore.Field)
```
AddFields adds zap fields to the logger.
Deprecated: should use the ctx_zap.AddFields instead

## <a name="DefaultClientCodeToLevel">func</a> [DefaultClientCodeToLevel](./options.go#L121)
``` go
func DefaultClientCodeToLevel(code codes.Code) zapcore.Level
```
DefaultClientCodeToLevel is the default implementation of gRPC return codes to log levels for client side.

## <a name="DefaultCodeToLevel">func</a> [DefaultCodeToLevel](./options.go#L79)
``` go
func DefaultCodeToLevel(code codes.Code) zapcore.Level
```
DefaultCodeToLevel is the default implementation of gRPC return codes and interceptor log level for server side.

## <a name="DurationToDurationField">func</a> [DurationToDurationField](./options.go#L172)
``` go
func DurationToDurationField(duration time.Duration) zapcore.Field
```
DurationToDurationField uses a Duration field to log the request duration
and leaves it up to Zap's encoder settings to determine how that is output.

## <a name="DurationToTimeMillisField">func</a> [DurationToTimeMillisField](./options.go#L166)
``` go
func DurationToTimeMillisField(duration time.Duration) zapcore.Field
```
DurationToTimeMillisField converts the duration to milliseconds and uses the key `grpc.time_ms`.

## <a name="Extract">func</a> [Extract](./context.go#L18)
``` go
func Extract(ctx context.Context) *zap.Logger
```
Extract takes the call-scoped Logger from grpc_zap middleware.
Deprecated: should use the ctx_zap.Extract instead

## <a name="PayloadStreamClientInterceptor">func</a> [PayloadStreamClientInterceptor](./payload_interceptors.go#L74)
``` go
func PayloadStreamClientInterceptor(logger *zap.Logger, decider grpc_logging.ClientPayloadLoggingDecider) grpc.StreamClientInterceptor
```
PayloadStreamServerInterceptor returns a new streaming client interceptor that logs the paylods of requests and responses.

## <a name="PayloadStreamServerInterceptor">func</a> [PayloadStreamServerInterceptor](./payload_interceptors.go#L46)
``` go
func PayloadStreamServerInterceptor(logger *zap.Logger, decider grpc_logging.ServerPayloadLoggingDecider) grpc.StreamServerInterceptor
```
PayloadUnaryServerInterceptor returns a new server server interceptors that logs the payloads of requests.

This *only* works when placed *after* the `grpc_zap.StreamServerInterceptor`. However, the logging can be done to a
separate instance of the logger.

## <a name="PayloadUnaryClientInterceptor">func</a> [PayloadUnaryClientInterceptor](./payload_interceptors.go#L58)
``` go
func PayloadUnaryClientInterceptor(logger *zap.Logger, decider grpc_logging.ClientPayloadLoggingDecider) grpc.UnaryClientInterceptor
```
PayloadUnaryClientInterceptor returns a new unary client interceptor that logs the paylods of requests and responses.

## <a name="PayloadUnaryServerInterceptor">func</a> [PayloadUnaryServerInterceptor](./payload_interceptors.go#L26)
``` go
func PayloadUnaryServerInterceptor(logger *zap.Logger, decider grpc_logging.ServerPayloadLoggingDecider) grpc.UnaryServerInterceptor
```
PayloadUnaryServerInterceptor returns a new unary server interceptors that logs the payloads of requests.

This *only* works when placed *after* the `grpc_zap.UnaryServerInterceptor`. However, the logging can be done to a
separate instance of the logger.

## <a name="ReplaceGrpcLogger">func</a> [ReplaceGrpcLogger](./grpclogger.go#L15)
``` go
func ReplaceGrpcLogger(logger *zap.Logger)
```
ReplaceGrpcLogger sets the given zap.Logger as a gRPC-level logger.
This should be called *before* any other initialization, preferably from init() functions.

## <a name="StreamClientInterceptor">func</a> [StreamClientInterceptor](./client_interceptors.go#L34)
``` go
func StreamClientInterceptor(logger *zap.Logger, opts ...Option) grpc.StreamClientInterceptor
```
StreamServerInterceptor returns a new streaming client interceptor that optionally logs the execution of external gRPC calls.

## <a name="StreamServerInterceptor">func</a> [StreamServerInterceptor](./server_interceptors.go#L44)
``` go
func StreamServerInterceptor(logger *zap.Logger, opts ...Option) grpc.StreamServerInterceptor
```
StreamServerInterceptor returns a new streaming server interceptor that adds zap.Logger to the context.

## <a name="UnaryClientInterceptor">func</a> [UnaryClientInterceptor](./client_interceptors.go#L22)
``` go
func UnaryClientInterceptor(logger *zap.Logger, opts ...Option) grpc.UnaryClientInterceptor
```
UnaryClientInterceptor returns a new unary client interceptor that optionally logs the execution of external gRPC calls.

## <a name="UnaryServerInterceptor">func</a> [UnaryServerInterceptor](./server_interceptors.go#L24)
``` go
func UnaryServerInterceptor(logger *zap.Logger, opts ...Option) grpc.UnaryServerInterceptor
```
UnaryServerInterceptor returns a new unary server interceptors that adds zap.Logger to the context.

## <a name="CodeToLevel">type</a> [CodeToLevel](./options.go#L52)
``` go
type CodeToLevel func(code codes.Code) zapcore.Level
```
CodeToLevel function defines the mapping between gRPC return codes and interceptor log level.

## <a name="DurationToField">type</a> [DurationToField](./options.go#L55)
``` go
type DurationToField func(duration time.Duration) zapcore.Field
```
DurationToField function defines how to produce duration fields for logging

## <a name="Option">type</a> [Option](./options.go#L49)
``` go
type Option func(*options)
```

### <a name="WithCodes">func</a> [WithCodes](./options.go#L65)
``` go
func WithCodes(f grpc_logging.ErrorToCode) Option
```
WithCodes customizes the function for mapping errors to error codes.

### <a name="WithDurationField">func</a> [WithDurationField](./options.go#L72)
``` go
func WithDurationField(f DurationToField) Option
```
WithDurationField customizes the function for mapping request durations to Zap fields.

### <a name="WithLevels">func</a> [WithLevels](./options.go#L58)
``` go
func WithLevels(f CodeToLevel) Option
```
WithLevels customizes the function for mapping gRPC return codes and interceptor log level statements.

- - -
Generated by [godoc2ghmd](https://github.com/GandalfUK/godoc2ghmd)