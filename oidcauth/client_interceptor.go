package oidcauth

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func UnaryHeaderInterceptor(header, value string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		grpc.SetHeader(ctx, metadata.New(map[string]string{header: value}))
		return nil
	}

}

/*
func StreamHeaderInterceptor(header, value string) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		grpc.SetHeader(ctx, metadata.New(map[string]string{header: value}))
		return nil
	}
}
*/
