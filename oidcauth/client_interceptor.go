package oidcauth

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// UnaryHeaderInterceptor adds key value pairs as headers
func UnaryHeaderInterceptor(headers map[string]string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		grpc.SetHeader(ctx, metadata.New(headers))
		return nil
	}

}

// StreamHeaderInterceptor adds key value pairs as headers
func StreamHeaderInterceptor(headers map[string]string) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		grpc.SetHeader(ctx, metadata.New(headers))
		return streamer(ctx, desc, cc, method, opts...)
	}
}
