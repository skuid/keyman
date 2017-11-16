[![Build Status](https://travis-ci.org/skuid/keyman.svg?branch=master)](https://travis-ci.org/skuid/keyman)
[![https://img.shields.io/badge/godoc-reference-5272B4.svg?style=flat-square](https://img.shields.io/badge/godoc-reference-5272B4.svg?style=flat-square)](http://godoc.org/github.com/skuid/keyman/)

# keyman

An SSH key CA Server

# Usage

```
Usage of ./keyman:
      --cert_file string   The TLS cert file (default "./server.pem")
  -k, --key string         The CA private key to load (default "./ca")
      --key_file string    The TLS key file (default "./server.key")
  -l, --level Level        Log level (default info)
      --metrics-port int   The metrics port to listen on (default 3001)
  -p, --port int           The port to listen on (default 3000)
      --tls                Use TLS (default true)
```

# Demo

```bash
# Create a server key pair
cd demo
openssl req -x509 -nodes -newkey rsa:4096 -keyout server.key -out server.pem -subj "/C=US/ST=Tennessee/L=Chattanooga/O=Skuid/OU=/CN=localhost"
cd -

# Start the server and an SSH server
docker-compose up -d

# Get your pubkey signed by the server
go build -o keyman-cli ./client/
MY_PUBKEY=$(ls ~/.ssh/id_rsa.pub)
./keyman-cli --cert_file ./demo/server.pem --pubkey $MY_PUBKEY > ~/.ssh/id_rsa-cert.pub
ssh-keygen -Lf ~/.ssh/id_rsa-cert.pub
ssh -p 2222 core@localhost

# When inside the container
cat /var/log/ssh.log
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
