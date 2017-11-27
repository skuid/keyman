package oidcauth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

func getCert(kid string) (string, error) {
	resp, err := http.Get("https://www.googleapis.com/oauth2/v1/certs")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var data map[string]string
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return "", fmt.Errorf("error decoding body: %q", err)
	}

	key, ok := data[kid]
	if !ok {
		return "", fmt.Errorf("Could not find key with kid %s", kid)
	}
	return key, nil
}

func keyFunc(tok *jwt.Token) (interface{}, error) {
	kid, ok := tok.Header["kid"]
	if !ok {
		return nil, fmt.Errorf("Key 'kid' not found in header")
	}
	keyID := kid.(string)
	key, err := getCert(keyID)
	if err != nil {
		return nil, err
	}
	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("Error parsing RSA key: %q", err)
	}

	return verifyKey, nil
}

func jwtIsExpired(idToken string) bool {
	_, err := jwt.Parse(idToken, keyFunc)
	if err != nil {
		return true
	}
	return false
}
