package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/skuid/keyman/shapes"
	"github.com/skuid/keyman/sign"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
)

// Authority is an SSH CA signing server
type Authority struct {
	// The Signer that signs requests
	CA sign.Signer
	// The CA comment to emit on the PublicKey
	CaComment string

	// The duration to sign keys for
	Duration time.Duration

	IdentityHeader string
}

// Sign handler for incoming certificate requests
func (s *Authority) Sign(ctx context.Context, r *shapes.SignRequest) (*shapes.KeyResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)

	if !ok {
		return nil, fmt.Errorf("Could not get metadata from incoming request")
	}
	identity, ok := md[s.IdentityHeader]
	if !ok {
		return nil, fmt.Errorf("Could not get identity from incoming request")
	}
	if len(identity) != 1 {
		return nil, fmt.Errorf("Got more or less than one identity from incoming request")
	}

	signedCert, err := s.CA.Sign(
		r.Key,
		identity[0],
		r.Principals,
		s.Duration,
	)
	if err != nil {
		zap.L().Error("Error signing request", zap.Error(err))
		return nil, fmt.Errorf("Error signing Request: %q", err)
	}
	return &shapes.KeyResponse{Certificate: signedCert}, nil
}

// PublicKey returns the server's public key
func (s *Authority) PublicKey(ctx context.Context, r *shapes.KeyRequest) (*shapes.KeyResponse, error) {
	data := base64.StdEncoding.EncodeToString(s.CA.Cert().Marshal())
	content := []byte(fmt.Sprintf("%s %s %s", s.CA.Cert().Type(), data, s.CaComment))
	return &shapes.KeyResponse{Certificate: content}, nil
}
