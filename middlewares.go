package main

import (
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	"github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/skuid/keyman/oidcauth"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
)

func NewServer(clientID string, opts ...grpc.ServerOption) *grpc.Server {
	grpc_zap.ReplaceGrpcLogger(zap.L())
	zopts := []grpc_zap.Option{
		grpc_zap.WithDurationField(func(duration time.Duration) zapcore.Field {
			return zap.Int64("grpc.time_ns", duration.Nanoseconds())
		}),
	}
	// Make sure that log statements internal to gRPC library are logged using the zapLogger as well.
	grpc_zap.ReplaceGrpcLogger(zap.L())
	// Create a server, make sure we put the grpc_ctxtags context before everything else.
	server_opts := []grpc.ServerOption{
		grpc_middleware.WithUnaryServerChain(
			grpc_ctxtags.UnaryServerInterceptor(grpc_ctxtags.WithFieldExtractor(grpc_ctxtags.CodeGenRequestFieldExtractor)),
			grpc_recovery.UnaryServerInterceptor(),
			grpc_prometheus.UnaryServerInterceptor,
			grpc_zap.UnaryServerInterceptor(zap.L(), zopts...),
			grpc_auth.UnaryServerInterceptor(oidcauth.ValidateIdToken(clientID, "email", "https://accounts.google.com")),
		),
		grpc_middleware.WithStreamServerChain(
			grpc_ctxtags.StreamServerInterceptor(grpc_ctxtags.WithFieldExtractor(grpc_ctxtags.CodeGenRequestFieldExtractor)),
			grpc_prometheus.StreamServerInterceptor,
			grpc_zap.StreamServerInterceptor(zap.L(), zopts...),
			grpc_recovery.StreamServerInterceptor(),
			//grpc_auth.StreamServerInterceptor(oidcauth.ValidateIdToken(clientID, "email", "https://accounts.google.com")),
		),
	}
	server_opts = append(server_opts, opts...)
	server := grpc.NewServer(server_opts...)
	return server
}
