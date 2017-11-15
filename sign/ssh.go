package sign

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"golang.org/x/crypto/ssh"
)

// Signer is an interface for signing SSH keys
type Signer interface {
	Sign(userKey []byte, identity string, principals []string, validity time.Duration) ([]byte, error)
	Cert() ssh.PublicKey
}

// NewCaServer returns a server that can be used for signing keys.
// It is initialized with a new 4096 bit key
func NewCaServer() (*CaServer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("Error generating key: %q", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, fmt.Errorf("Error creating signer: %q", err)
	}
	server := &CaServer{
		Starter: time.Now,
		Random:  rand.Reader,
		cert:    signer.PublicKey(),
		key:     signer,
	}
	return server, nil
}

// CaServer stores a SSH Certificate Authority keypair for signing SSH keys
type CaServer struct {
	// Starter is a function to invoke for the beginning time of certificate
	// validity
	Starter func() time.Time
	// Random is an io.Reader used for signing ssh certificates
	Random io.Reader

	// Cert contains the Public key information of the Certificate Authority
	cert ssh.PublicKey
	key  ssh.Signer
}

func (c *CaServer) Cert() ssh.PublicKey {
	return c.cert
}

// Read in an RSA private key and return a new *CaServer
func ReadPrivKey(filename string) (*CaServer, error) {
	certData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("Error reading key file: %q", err)
	}

	signer, err := ssh.ParsePrivateKey(certData)
	if err != nil {
		return nil, fmt.Errorf("Error parsing key data: %q", err)
	}
	server := &CaServer{
		Starter: time.Now,
		Random:  rand.Reader,
		cert:    signer.PublicKey(),
		key:     signer,
	}
	return server, nil
}

// Sign signs a given SSH public key and returns the signed certificate
func (c *CaServer) Sign(userKey []byte, identity string, principals []string, validity time.Duration) ([]byte, error) {
	key, comment, _, _, err := ssh.ParseAuthorizedKey(userKey)
	if err != nil {
		return nil, fmt.Errorf("Error parsing user cert: %q", err)
	}

	begin := c.Starter()
	expires := begin.Add(validity)

	cert := &ssh.Certificate{
		Key:             key,
		Serial:          uint64(begin.UnixNano()),
		CertType:        ssh.UserCert,
		KeyId:           identity,
		ValidPrincipals: principals,
		ValidAfter:      uint64(begin.Unix()),
		ValidBefore:     uint64(expires.Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		},
	}

	err = cert.SignCert(c.Random, c.key)
	if err != nil {
		return nil, fmt.Errorf("Error signing cert: %q", err)
	}

	return []byte(fmt.Sprintf(
		"%s %s %s",
		cert.Type(),
		base64.StdEncoding.EncodeToString(cert.Marshal()),
		comment,
	)), nil
}
