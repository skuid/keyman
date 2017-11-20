package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/skuid/keyman/oidcauth"
	"github.com/skuid/keyman/server"
	pb "github.com/skuid/keyman/shapes"
	"github.com/skuid/keyman/sign"
	"github.com/skuid/spec"
	"github.com/skuid/spec/lifecycle"
	_ "github.com/skuid/spec/metrics"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	// flags
	level := spec.LevelPflagPCommandLine("level", "l", zapcore.InfoLevel, "Log level")
	flag.StringP("key", "k", "./ca", "The CA private key to load")
	flag.IntP("port", "p", 3000, "The port to listen on")
	flag.Int("metrics-port", 3001, "The metrics port to listen on")
	flag.String("cert_file", "./server.pem", "The TLS cert file")
	flag.String("key_file", "./server.key", "The TLS key file")
	flag.Duration("validity", time.Duration(8)*time.Hour, "The amount of time certs are signed for")
	flag.String("ca-name", "ca", "The CA name")
	flag.Bool("tls", true, "Use TLS")
	flag.String("client-id", "", "The ClientID for the OIDC application")

	flag.Parse()

	// Logging
	l, err := spec.NewStandardLevelLogger(*level)
	if err != nil {
		zap.L().Fatal("Error initializing logger", zap.Error(err))
	}
	zap.ReplaceGlobals(l)

	// Viper binds
	viper.BindPFlags(flag.CommandLine)
	viper.SetEnvPrefix("keyman")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	ca, err := sign.ReadPrivKey(viper.GetString("key"))
	if err != nil {
		zap.L().Fatal("Error reading key", zap.Error(err))
	}

	caServer := &server.Server{
		CA:             ca,
		CaComment:      viper.GetString("ca-name"),
		Duration:       viper.GetDuration("validity"),
		IdentityHeader: oidcauth.Identity,
	}

	hostPort := fmt.Sprintf(":%d", viper.GetInt("port"))
	zap.L().Info("Server is starting", zap.String("listen", hostPort))
	lis, err := net.Listen("tcp", hostPort)
	if err != nil {
		zap.L().Fatal("Failed to listen", zap.Error(err))
	}

	var opts []grpc.ServerOption
	if viper.GetBool("tls") {
		creds, err := credentials.NewServerTLSFromFile(viper.GetString("cert_file"), viper.GetString("key_file"))
		if err != nil {
			zap.L().Fatal("Failed generate credentials", zap.Error(err))
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)}
	}
	//grpcServer := grpc.NewServer(opts...)
	grpcServer := NewServer(viper.GetString("client_id"), opts...)

	pb.RegisterSignerServer(grpcServer, caServer)

	go func() {
		internalMux := http.NewServeMux()
		internalMux.Handle("/metrics", promhttp.Handler())
		internalMux.HandleFunc("/live", lifecycle.LivenessHandler)
		internalMux.HandleFunc("/ready", lifecycle.ReadinessHandler)
		metricsHostPort := fmt.Sprintf(":%d", viper.GetInt("metrics-port"))

		zap.L().Info("Metrics server is starting", zap.String("listen", metricsHostPort))
		httpServer := &http.Server{Addr: metricsHostPort, Handler: internalMux}
		lifecycle.ShutdownOnTerm(httpServer)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			zap.L().Fatal("Error listening", zap.Error(err))
		}
		zap.L().Info("Metrics server gracefully stopped")
	}()

	if err := grpcServer.Serve(lis); err != grpc.ErrServerStopped {
		zap.L().Fatal("Error stopping server", zap.Error(err))
	}
	zap.L().Info("Server gracefully stopped")
}
