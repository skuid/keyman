package cmd

import (
	"flag"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/skuid/keyman/oidcauth"
	"github.com/skuid/keyman/server"
	"github.com/skuid/keyman/sign"
	"github.com/skuid/spec"
	"github.com/skuid/spec/lifecycle"
	_ "github.com/skuid/spec/metrics" // import spec metrics
	"github.com/skuid/spec/middlewares"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var level = zapcore.InfoLevel

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run a SSH key signing server",
	// Set up logging
	PreRunE: func(cmd *cobra.Command, args []string) error {
		l, err := spec.NewStandardLevelLogger(level)
		if err != nil {
			return fmt.Errorf("Error initializing logger: %q", err)
		}
		zap.ReplaceGlobals(l)
		return nil
	},
	Run: serverFunc,
}

func serverFunc(cmd *cobra.Command, args []string) {

	ca, err := sign.ReadPrivKey(viper.GetString("key"))
	if err != nil {
		zap.L().Fatal("Error reading key", zap.Error(err))
	}

	authority := &server.Authority{
		CA:             ca,
		CaComment:      viper.GetString("ca-name"),
		Duration:       viper.GetDuration("validity"),
		IdentityHeader: oidcauth.Identity,
	}
	hostPort := fmt.Sprintf(":%d", viper.GetInt("port"))

	// Metrics and lifecycle server
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

	authMux := http.NewServeMux()
	authMux.HandleFunc("/api/v1/sign", authority.SignHTTP)
	handler := middlewares.Apply(
		authMux,
		oidcauth.OidcUserContext(
			"https://accounts.google.com",
			viper.GetString("client_id"),
		),
	)

	mux := http.NewServeMux()
	mux.Handle("/", handler)
	mux.HandleFunc("/api/v1/key", authority.PublicKeyHTTP)
	handler = middlewares.Apply(
		mux,
		middlewares.InstrumentRoute(),
		middlewares.Logging(oidcauth.UserLoggingClosure),
	)

	httpServer := &http.Server{Addr: hostPort, Handler: handler}
	lifecycle.ShutdownOnTerm(httpServer)

	if err := httpServer.ListenAndServeTLS(viper.GetString("cert_file"), viper.GetString("key_file")); err != http.ErrServerClosed {
		zap.L().Fatal("Error listening", zap.Error(err))
	}
	zap.L().Info("Server gracefully stopped")

}

func init() {
	RootCmd.AddCommand(serverCmd)

	// Hack to make level work
	set := flag.NewFlagSet("temp", flag.ExitOnError)
	set.Var(&level, "level", "Log level")
	levelPFlag := pflag.PFlagFromGoFlag(set.Lookup("level"))
	levelPFlag.Shorthand = "l"

	localFlagSet := serverCmd.Flags()
	localFlagSet.AddFlag(levelPFlag)
	localFlagSet.StringP("key", "k", "./ca", "The CA private key to load")
	localFlagSet.IntP("port", "p", 3000, "The port to listen on")
	localFlagSet.Int("metrics-port", 3001, "The metrics port to listen on")
	localFlagSet.String("cert_file", "./server.pem", "The TLS cert file")
	localFlagSet.String("key_file", "./server.key", "The TLS key file")
	localFlagSet.Duration("validity", time.Duration(8)*time.Hour, "The amount of time certs are signed for")
	localFlagSet.String("ca-name", "ca", "The CA name")
	localFlagSet.Bool("tls", true, "Use TLS")

	viper.BindPFlags(localFlagSet)
}
