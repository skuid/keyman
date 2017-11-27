package oidcauth

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// AuthManager is a convienence struct for caching an oidc Provider and
// IDTokenVerifier
type AuthManager struct {
	Config   *oauth2.Config
	Provider *oidc.Provider
	Verifier *oidc.IDTokenVerifier
}

// NewManager returns a new AuthManager for the given client id/secret
func NewManager(ctx context.Context, clientID, clientSecret string) (*AuthManager, error) {
	manager := &AuthManager{}

	manager.Config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/auth",
			TokenURL: "https://www.googleapis.com/oauth2/v3/token",
		},
		RedirectURL: "urn:ietf:wg:oauth:2.0:oob",
		Scopes:      []string{"openid", "email", "profile"},
	}

	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		return nil, fmt.Errorf("Error creating provider: %q", err)
	}
	manager.Provider = provider
	manager.Verifier = provider.Verifier(&oidc.Config{ClientID: clientID})
	return manager, nil
}

func openURI(openBrowser bool, url string) {
	openInstructions := fmt.Sprintf("Open this url in your browser: %s\n", url)

	if !openBrowser {
		fmt.Print(openInstructions)
		return
	}

	var cmd *exec.Cmd
	switch os := runtime.GOOS; os {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	}

	if err := cmd.Start(); err != nil {
		fmt.Print(openInstructions)
	}
}

// EnsureValidTokens ensures a given id, access, and refresh token are valid
// and refreshed
func EnsureValidTokens(manager *AuthManager, idToken, accessToken, refreshToken string) (string, string, string, error) {
	ctx := context.Background()
	var token *oauth2.Token

	if idToken == "" {
		// Get a token from Google
		url := manager.Config.AuthCodeURL("state", oauth2.AccessTypeOffline)
		openURI(true, url)
		fmt.Print("Enter the code Google gave you: \n")
		reader := bufio.NewReader(os.Stdin)
		code, err := reader.ReadString('\n')
		if err != nil {
			return "", "", "", fmt.Errorf("Error readin input: %q", err)
		}
		code = strings.TrimSpace(code)

		// Exchange the code for a token
		token, err = manager.Config.Exchange(ctx, code)
		if err != nil {
			return "", "", "", fmt.Errorf("Error getting token: %q", err)
		}
		var ok bool
		idToken, ok = token.Extra("id_token").(string)
		if !ok {
			return "", "", "", fmt.Errorf("Error getting id_token off of token")
		}

		accessToken = token.AccessToken
		refreshToken = token.RefreshToken
	} else {
		token = &oauth2.Token{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			TokenType:    "Bearer",
			// set Expiry to non-zero, so we get a refresh
			Expiry: time.Now().Add(time.Duration(-5) * time.Minute),
		}
	}

	// Token needs refresh
	if jwtIsExpired(idToken) {
		ts := manager.Config.TokenSource(ctx, token)

		// perform refresh
		var err error
		token, err = ts.Token()
		if err != nil {
			return "", "", "", fmt.Errorf("Error refreshing token: %q", err)
		}
		var ok bool
		idToken, ok = token.Extra("id_token").(string)
		if !ok {
			return "", "", "", fmt.Errorf("Error getting id_token off of token")
		}

		// update the access & refresh token
		accessToken = token.AccessToken
		refreshToken = token.RefreshToken
	}

	// Verify the token
	_, err := manager.Verifier.Verify(ctx, idToken)
	if err != nil {
		return "", "", "", fmt.Errorf("Error verifying id token: %q", err)
	}

	return idToken, accessToken, refreshToken, nil
}
