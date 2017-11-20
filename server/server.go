package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/skuid/keyman/shapes"
	"github.com/skuid/keyman/sign"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/metadata"
)

type Server struct {
	// The Signer that signs requests
	CA sign.Signer
	// The CA comment to emit on the PublicKey
	CaComment string

	// The duration to sign keys for
	Duration time.Duration

	IdentityHeader string
}

// Sign handler for incoming certificate requests
func (s *Server) Sign(ctx context.Context, r *shapes.SignRequest) (*shapes.KeyResponse, error) {
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
func (s *Server) PublicKey(ctx context.Context, r *shapes.KeyRequest) (*shapes.KeyResponse, error) {
	pubKey, err := ssh.NewPublicKey(s.CA.Cert())
	if err != nil {
		zap.L().Error("Error converting CA pubkey", zap.Error(err))
		return nil, fmt.Errorf("Error converting CA pubkey")
	}

	data := base64.StdEncoding.EncodeToString(pubKey.Marshal())
	content := []byte(fmt.Sprintf("%s %s %s", pubKey.Type(), data, s.CaComment))
	return &shapes.KeyResponse{Certificate: content}, nil
}
