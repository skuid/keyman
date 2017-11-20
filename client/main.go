package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"

	"github.com/mitchellh/go-homedir"
	"github.com/skuid/keyman/oidcauth"
	pb "github.com/skuid/keyman/shapes"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

func requestCert(client pb.SignerClient, content []byte, principals []string) ([]byte, error) {
	request := &pb.SignRequest{
		Key:        content,
		Principals: principals,
	}
	value := fmt.Sprintf("bearer %s", viper.GetString("id_token"))
	md := metadata.New(map[string]string{"authorization": value})
	ctx := metadata.NewOutgoingContext(context.Background(), md)
	resp, err := client.Sign(ctx, request)

	if err != nil {
		return nil, err
	}
	return resp.Certificate, nil
}

func main() {
	flag.Bool("open-browser", true, "Open the oauth approval URL in the browser")
	flag.String("client-id", "", "The ClientID for the application")
	flag.String("client-secret", "", "The ClientSecret for the application")

	flag.String("server", "localhost:3000", "The server to connect to")
	flag.StringSlice("principals", []string{"core", "openvpnas"}, "The identities to request")
	flag.String("pubkey", "", "The key to get signed")
	flag.String("cert_file", "./server.pem", "The TLS cert file")
	flag.Bool("tls", true, "Use TLS")
	flag.Parse()

	// Viper binds
	viper.BindPFlags(flag.CommandLine)
	viper.SetEnvPrefix("keyman")
	viper.AutomaticEnv()
	viper.SetConfigName(".keyman")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("$HOME")
	viper.AddConfigPath(".")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	// ignore error, file might not exist
	viper.MergeInConfig()

	err := oidcauth.Setup()
	if err != nil {
		log.Fatalf("Error setting up oidc: %q", err)
	}

	opts := []grpc.DialOption{
	/*
		grpc.WithUnaryInterceptor(
			oidcauth.UnaryHeaderInterceptor(
				"authorization",
				fmt.Sprintf("bearer %s", viper.GetString("id_token")),
			),
		),
	*/
	}
	//opts = append(opts, grpc.WithInsecure())
	creds, err := credentials.NewClientTLSFromFile(viper.GetString("cert_file"), "localhost")
	if err != nil {
		log.Fatalf("fail to open cert file: %v", err)
	}
	opts = append(opts, grpc.WithTransportCredentials(creds))
	conn, err := grpc.Dial(viper.GetString("server"), opts...)
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()
	client := pb.NewSignerClient(conn)

	keyPath := viper.GetString("pubkey")
	if keyPath == "" {
		home, err := homedir.Dir()
		if err != nil {
			log.Fatalf("Error getting home: %q", err)
		}
		keyPath = filepath.Join(home, ".ssh/id_rsa.pub")
	}

	keyContent, err := ioutil.ReadFile(keyPath)
	if err != nil {
		log.Fatalf("Error reading pubkey %s: %q", viper.GetString("pubkey"), err)
	}
	resp, err := requestCert(client, keyContent, viper.GetStringSlice("principals"))
	if err != nil {
		log.Fatalf("Error geting key signed: %q", err)
	}
	fmt.Println(string(resp))
}
