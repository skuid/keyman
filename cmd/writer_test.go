package cmd

import (
	"testing"
)

func TestCertFileName(t *testing.T) {
	cases := []struct {
		Filename string
		Want     string
	}{
		{
			"~/.ssh/id_rsa.pub",
			"id_rsa-cert.pub",
		},
		{
			"/Users/you/.ssh/id_rsa.pub",
			"id_rsa-cert.pub",
		},
		{
			"./id_rsa.pub",
			"id_rsa-cert.pub",
		},
		{
			"id_ecdsa.pub",
			"id_ecdsa-cert.pub",
		},
	}

	for _, c := range cases {
		got := certFileName(c.Filename)
		if c.Want != got {
			t.Errorf("Expected %s, got %s", c.Want, got)
		}
	}

}
