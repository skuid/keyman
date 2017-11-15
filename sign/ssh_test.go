package sign

import (
	"crypto/rsa"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Thanks Mitchell - https://youtu.be/8hQG7QlcLBk?t=12m18s
var update = flag.Bool("update", false, "Update golden files")

func newTestCaServer(seed int64, starter time.Time) (*CaServer, error) {
	random := rand.New(rand.NewSource(seed))
	key, err := rsa.GenerateKey(random, 4096)
	if err != nil {
		return nil, fmt.Errorf("Error generating key: %q", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, fmt.Errorf("Error creating signer: %q", err)
	}
	server := &CaServer{
		Starter: func() time.Time { return starter },
		Random:  random,
		cert:    signer.PublicKey(),
		key:     signer,
	}
	return server, nil
}

func generateRSAKey(seed int64, comment string) ([]byte, error) {
	random := rand.New(rand.NewSource(seed))
	key, err := rsa.GenerateKey(random, 4096)
	if err != nil {
		return nil, fmt.Errorf("Error generating key: %q", err)
	}

	pubkey, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		return nil, fmt.Errorf("Error converting rsa pubkey: %q", err)
	}

	data := base64.StdEncoding.EncodeToString(pubkey.Marshal())
	return []byte(fmt.Sprintf("%s %s %s", pubkey.Type(), data, comment)), nil
}

func TestSign(t *testing.T) {
	begin, err := time.Parse("2006-01-02T15:04:05", "2017-11-13T13:55:00")
	if err != nil {
		t.Fatalf("Error parsing beginning time: %q", err)
	}

	server, err := newTestCaServer(100, begin)
	if err != nil {
		t.Fatalf("Error creating test server: %q", err)
	}

	keyMaterial, err := generateRSAKey(200, "core@localhost")
	if err != nil {
		t.Fatalf("Error creating client key: %q", err)
	}

	cases := []struct {
		name       string
		validAfter time.Time
		validity   time.Duration
		username   string
		principals []string
		goldenName string
	}{
		{
			"Test one hour validity",
			begin,
			time.Duration(1) * time.Hour,
			"micahhausler",
			[]string{"root"},
			"one-hour",
		},
		{
			"Test one day validity",
			begin,
			time.Duration(24) * time.Hour,
			"lskywalker",
			[]string{"jedi", "hermits"},
			"one-day",
		},
		{
			"Test no principals",
			begin,
			time.Duration(24) * time.Hour,
			"trump",
			[]string{},
			"no-principals",
		},
	}

	for _, c := range cases {
		got, err := server.Sign(keyMaterial, c.username, c.principals, c.validity)
		if err != nil {
			t.Errorf("Error signing pubkey: %q", err)
			continue
		}

		golden := filepath.Join("test-fixtures", c.goldenName+".golden")
		if *update {
			err = ioutil.WriteFile(golden, got, 0644)
			if err != nil {
				t.Errorf("Error updating golden file %s: %q", golden, err)
				continue
			}
		}

		want, err := ioutil.ReadFile(golden)
		if err != nil {
			t.Errorf("Error reading golden file %s: %q", golden, err)
			continue
		}
		if string(got) != string(want) {
			t.Errorf("Cert not expected! \nGot:\n\t%s\nExpected:\n\t%s\n", string(got), string(want))
		}

		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(got))
		if err != nil {
			t.Errorf("Error parsing authorized key: %q", err)
			continue
		}
		cert := pk.(*ssh.Certificate)
		if cert.KeyId != c.username {
			t.Errorf("Certificate username not expected! Got: %s, Expected: %s", cert.KeyId, c.username)
		}
	}
}
