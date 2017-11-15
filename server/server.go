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
)

type KeyRequest struct {
	Key        string   `json:"key"`
	Principals []string `json:"principals"`
}

type KeyResponse struct {
	Certificate string `json:"certificate"`
}

type Server struct {
	CA        sign.Signer
	CaComment string

	Duration time.Duration

	// TODO change to per-request identity
	Identity string
}

func (s *Server) Sign(ctx context.Context, r *shapes.SignRequest) (*shapes.KeyResponse, error) {
	signedCert, err := s.CA.Sign(
		r.Key,
		s.Identity,
		r.Principals,
		s.Duration,
	)
	if err != nil {
		zap.L().Error("Error signing request", zap.Error(err))
		return nil, fmt.Errorf("Error signing Request: %q", err)
	}
	return &shapes.KeyResponse{Certificate: signedCert}, nil
}

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
