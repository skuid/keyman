[![Build Status](https://travis-ci.org/skuid/keyman.svg?branch=master)](https://travis-ci.org/skuid/keyman)
[![https://img.shields.io/badge/godoc-reference-5272B4.svg?style=flat-square](https://img.shields.io/badge/godoc-reference-5272B4.svg?style=flat-square)](http://godoc.org/github.com/skuid/keyman/)
[![Docker Repository on Quay](https://quay.io/repository/skuid/keyman/status "Docker Repository on Quay")](https://quay.io/repository/skuid/keyman)

# keyman

An SSH key CA Server

[![keyman](/keyman.jpg)]()

# Usage

```
keyman is a cli for requesting server-signed SSH certs

Usage:
  keyman [flags]
  keyman [command]

Available Commands:
  help        Help about any command
  server      Run a SSH key signing server

Flags:
      --client-id string         The client ID for the application
      --client-secret string     The client secret for the application
      --config string            config file (default is $HOME/.keyman.yaml)
  -h, --help                     help for keyman
      --open-browser             Open the oauth approval URL in the browser (default true)
      --principals stringSlice   The identities to request (default [core,openvpnas])
      --pubkey string            The key to sign
      --server string            The server to connect to (default "localhost:3000")
      --skip-verify              Skip server TLS verification

Use "keyman [command] --help" for more information about a command.
```

# Demo

Create a ClientID/Client Secret in Google, and set the environment variables
`KEYMAN_CLIENT_ID` and `KEYMAN_CLIENT_SECRET`.

```bash
# Create a server key pair
cd demo
openssl req -x509 -nodes -newkey rsa:4096 -keyout server.key -out server.pem -subj "/C=US/ST=Tennessee/L=Chattanooga/O=Skuid/OU=/CN=localhost"
cd -

# Start the server and an SSH server
echo "      KEYMAN_CLIENT_ID: \"${KEYMAN_CLIENT_ID}\"" >> docker-compose.yaml
docker-compose up -d

# Get your pubkey signed by the server
go build
MY_PUBKEY=$(ls ~/.ssh/id_rsa.pub)
./keyman --pubkey $MY_PUBKEY > ~/.ssh/id_rsa-cert.pub
ssh-keygen -Lf ~/.ssh/id_rsa-cert.pub
ssh -p 2222 core@localhost

# When inside the container
cat /var/log/sshd.log
```

# Production Setup

You'll need an SSH keypair that will function as your Certificate Authority.
Create it and keep the private key secret.

```bash
# Create an SSH Certificate Authority
ssh-keygen -C CA -f ca

keyman -k ./ca
```

# Reading

- [Facebook Blog post](https://code.facebook.com/posts/365787980419535/scalable-and-secure-access-with-ssh/)

# TODO

- AuthN/AuthZ
- Key Revocation

# License

MIT. See [LICENSE](/LICENSE)
