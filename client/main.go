package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"

	"github.com/mitchellh/go-homedir"
	pb "github.com/skuid/keyman/shapes"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func requestCert(client pb.SignerClient, content []byte, principals []string) ([]byte, error) {
	request := &pb.SignRequest{
		Key:        content,
		Principals: principals,
	}
	resp, err := client.Sign(context.Background(), request)
	if err != nil {
		return nil, err
	}
	return resp.Certificate, nil
}

func main() {
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
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	var opts []grpc.DialOption
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
