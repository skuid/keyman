package cmd

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/skuid/keyman/groupauth"
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

	// Certificate Authority initialization
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

	// Group authorization initialization
	saData, err := ioutil.ReadFile(viper.GetString("service-account"))
	if err != nil {
		zap.L().Fatal("Error reading group credential file", zap.Error(err))
	}
	ud, err := groupauth.NewUserDirectory(
		saData,
		viper.GetString("admin-username"),
		viper.GetString("domain"),
		viper.GetStringSlice("groups"),
		viper.GetString("redis-host"),
		viper.GetDuration("validity"),
	)
	if err != nil {
		zap.L().Fatal("Error creating directory", zap.Error(err))
	}

	authMux := http.NewServeMux()
	authMux.HandleFunc("/api/v1/sign", authority.SignHTTP)
	handler := middlewares.Apply(
		authMux,
		ud.Authorize(oidcauth.FromContext),
		oidcauth.OidcEmailContext(
			"https://accounts.google.com",
			viper.GetString("client-id"),
		),
	)

	mux := http.NewServeMux()
	mux.Handle("/", handler)
	mux.HandleFunc("/api/v1/key", authority.PublicKeyHTTP)
	handler = middlewares.Apply(
		mux,
		middlewares.InstrumentRoute(),
		middlewares.Logging(oidcauth.EmailLoggingClosure),
	)

	httpServer := &http.Server{Addr: hostPort, Handler: handler}
	lifecycle.ShutdownOnTerm(httpServer)

	zap.L().Info("Keyman server is starting", zap.String("listen", hostPort))
	if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
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
	localFlagSet.Duration("validity", time.Duration(8)*time.Hour, "The amount of time certs are signed for")
	localFlagSet.String("ca-name", "ca", "The CA name")

	localFlagSet.String("service-account", "", "The Google service account file")
	localFlagSet.String("admin-username", "", "The Google admin username")
	localFlagSet.String("domain", "", "The Google domain")
	localFlagSet.StringSlice("groups", []string{}, "The Google groups to authorize")
	localFlagSet.String("redis-host", "", "The redis hostname to connect to")

	viper.BindPFlags(localFlagSet)
}
