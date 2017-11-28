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
	RunE:  clientRequest,
}

func clientRequest(cmd *cobra.Command, args []string) error {

	// Setup the OIDC configuration
	err := oidcauth.Setup()
	if err != nil {
		return err
	}

	// Get the user's ssh key
	keyPath := viper.GetString("pubkey")
	if keyPath == "" {
		home, err := homedir.Dir()
		if err != nil {
			return fmt.Errorf("Error getting home: %q", err)
		}
		keyPath = filepath.Join(home, ".ssh/id_rsa.pub")
	}
	keyContent, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("Error reading in key file: %q", err)
	}

	// Create the request
	request := &pb.SignRequest{
		Key:        keyContent,
		Principals: viper.GetStringSlice("principals"),
	}
	buf := &bytes.Buffer{}
	err = json.NewEncoder(buf).Encode(request)
	if err != nil {
		return fmt.Errorf("Error encoding request: %q", err)
	}
	url := fmt.Sprintf("%s/api/v1/sign", viper.GetString("server"))
	req, err := http.NewRequest(http.MethodPost, url, buf)
	if err != nil {
		return fmt.Errorf("Error preparing request: %s", err)
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("bearer %s", viper.GetString("id_token")))
	req.Header.Set("user-agent", "keyman-cli")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: viper.GetBool("skip-verify")},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Error requesting cert: %s", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		buf := &bytes.Buffer{}
		buf.ReadFrom(resp.Body)
		fmt.Printf("Error: %s - %s\n", resp.Status, string(buf.Bytes()))
		return fmt.Errorf("Error: %q", resp.Status)
	}

	response := &pb.KeyResponse{}
	err = json.NewDecoder(resp.Body).Decode(response)
	if err != nil {
		return fmt.Errorf("Error decoding response: %s", err)
	}

	fmt.Println(string(response.Certificate))
	return nil
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
	localFlagSet.String("pubkey", "", "The key to sign")

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
