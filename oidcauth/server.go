package oidcauth

import (
	"context"

	"github.com/coreos/go-oidc"
	"github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

// Identity is a constant for grpc metadata
const Identity = "identity"

// ValidateIDToken returns a grpc_auth.AuthFunc for verifying OIDC requests
func ValidateIDToken(clientID, issuerURL string) grpc_auth.AuthFunc {
	return func(ctx context.Context) (context.Context, error) {
		provider, err := oidc.NewProvider(ctx, issuerURL)
		if err != nil {
			return nil, grpc.Errorf(codes.Unauthenticated, "Error creating provider: %v", err)
		}
		verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

		token, err := grpc_auth.AuthFromMD(ctx, "bearer")
		if err != nil {
			return nil, grpc.Errorf(codes.Unauthenticated, "could not comsume bearer token: %v", err)
		}

		idToken, err := verifier.Verify(ctx, token)
		if err != nil {
			return nil, grpc.Errorf(codes.Unauthenticated, "invalid auth token: %v", err)
		}
		var claims struct {
			Email string `json:"email"`
		}
		if err := idToken.Claims(&claims); err != nil {
			return nil, grpc.Errorf(codes.Unauthenticated, "Could not get claim off of token: %v", err)
		}

		md := metadata.New(map[string]string{Identity: claims.Email})
		return metadata.NewIncomingContext(ctx, md), nil
	}
}
