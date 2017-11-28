package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/skuid/keyman/oidcauth"
	"github.com/skuid/keyman/shapes"
	"go.uber.org/zap"
)

// SignHTTP is a handler for incoming certificate requests. Requests must contain
// an context that has an oidcauth email in the context
func (a *Authority) SignHTTP(w http.ResponseWriter, r *http.Request) {
	var (
		input    = &shapes.SignRequest{}
		response = &shapes.KeyResponse{}
	)

	email, ok := oidcauth.FromContext(r.Context())
	if !ok {
		zap.L().Error("Couldn't get email from context: please wrap with oidcauth.OidcEmailContext()")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	err := json.NewDecoder(r.Body).Decode(input)
	if err != nil {
		http.Error(w, "Error decoding input", http.StatusBadRequest)
		return
	}

	signedCert, err := a.CA.Sign(
		input.Key,
		email,
		input.Principals,
		a.Duration,
	)
	if err != nil {
		zap.L().Error("Error signing request", zap.Error(err))
		http.Error(w, "Error signing request", http.StatusInternalServerError)
		return
	}

	response.Certificate = signedCert
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		zap.L().Error("Error encoding response", zap.Error(err))
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
		return
	}
}

// PublicKeyHTTP is an endpoint for exporting the SSH public key of the CA server
func (a *Authority) PublicKeyHTTP(w http.ResponseWriter, r *http.Request) {
	data := base64.StdEncoding.EncodeToString(a.CA.Cert().Marshal())
	content := []byte(fmt.Sprintf("%s %s %s", a.CA.Cert().Type(), data, a.CaComment))
	if _, err := w.Write(content); err != nil {
		zap.L().Error("Error writing response", zap.Error(err))
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
}
