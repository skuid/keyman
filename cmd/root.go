package cmd

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/mitchellh/go-homedir"
	"github.com/skuid/keyman/oidcauth"
	pb "github.com/skuid/keyman/shapes"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

var RootCmd = &cobra.Command{
	Use:   "keyman",
	Short: "keyman is a cli for requesting server-signed SSH certs",
	Run:   clientRequest,
}

func clientRequest(cmd *cobra.Command, args []string) {

	// Setup the OIDC configuration
	err := oidcauth.Setup()
	if err != nil {
		fmt.Printf("Error setting up OIDC: %q\n", err)
		os.Exit(1)
	}

	// Get the user's ssh key
	keyPath := viper.GetString("pubkey")
	if keyPath == "" {
		home, err := homedir.Dir()
		if err != nil {
			fmt.Printf("Error getting home: %q\n", err)
			os.Exit(1)
		}
		keyPath = filepath.Join(home, ".ssh/id_rsa.pub")
	}

	keyContent, err := ioutil.ReadFile(keyPath)
	if err != nil {
		fmt.Printf("Error reading in key file: %q\n", err)
		os.Exit(1)
	}

	// Create the request
	request := &pb.SignRequest{
		Key:        keyContent,
		Principals: viper.GetStringSlice("principals"),
	}
	buf := &bytes.Buffer{}
	err = json.NewEncoder(buf).Encode(request)
	if err != nil {
		fmt.Printf("Error encoding request: %q\n", err)
		os.Exit(1)
	}
	url := fmt.Sprintf("%s/api/v1/sign", viper.GetString("server"))
	req, err := http.NewRequest(http.MethodPost, url, buf)
	if err != nil {
		fmt.Printf("Error preparing request: %s\n", err)
		os.Exit(1)
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("bearer %s", viper.GetString("id-token")))
	req.Header.Set("user-agent", "keyman-cli")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: viper.GetBool("skip-verify")},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error requesting cert: %s\n", err)
		os.Exit(1)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		buf := &bytes.Buffer{}
		buf.ReadFrom(resp.Body)
		fmt.Printf("Error: %s - %s\n", resp.Status, string(buf.Bytes()))
		os.Exit(1)
	}

	response := &pb.KeyResponse{}
	err = json.NewDecoder(resp.Body).Decode(response)
	if err != nil {
		fmt.Printf("Error decoding response: %s\n", err)
		os.Exit(1)
	}

	if viper.GetBool("write") {
		outfile := filepath.Join(
			filepath.Dir(keyPath),
			certFileName(keyPath),
		)
		err = ioutil.WriteFile(outfile, response.Certificate, 0644)
		if err != nil {
			fmt.Printf("Error writing ssh cert: %s\n", err)
			os.Exit(1)
		}
		fmt.Printf("Wrote SSH Cert to %s\n", outfile)
		return
	}
	fmt.Println(string(response.Certificate))
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	localFlagSet := RootCmd.Flags()
	localFlagSet.Bool("skip-verify", false, "Skip server TLS verification")
	localFlagSet.Bool("open-browser", true, "Open the oauth approval URL in the browser")
	localFlagSet.String("client-secret", "", "The client secret for the application")
	localFlagSet.String("server", "https://localhost:3000", "The server to connect to")
	localFlagSet.StringSlice("principals", []string{"core", "openvpnas"}, "The identities to request")
	localFlagSet.String("pubkey", "", "The key to sign. Defaults to ~/.ssh/id_rsa.pub")
	localFlagSet.Bool("write", true, "Write the issued SSH cert to the ~/.ssh directory")

	// Here you will define your flags and configuration settings.
	// Cobra supports Persistent Flags, which, if defined here,
	// will be global for your application.

	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.keyman.yaml)")
	RootCmd.PersistentFlags().String("client-id", "", "The client ID for the application")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	}

	viper.SetConfigName(".keyman")
	viper.AddConfigPath("$HOME")
	viper.AddConfigPath(".")

	viper.BindPFlags(RootCmd.Flags())

	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.SetEnvPrefix("keyman")
	viper.AutomaticEnv()

	viper.ReadInConfig()
}
