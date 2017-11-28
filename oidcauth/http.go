package oidcauth

import (
	"context"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/skuid/spec/middlewares"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type user struct {
	Email string `json:"email"`
}

// key is an unexported type for keys defined in this package.
// This prevents collisions with keys defined in other packages.
type key int

// emailKey is the key for an email in Contexts. It is
// unexported; clients use oidcauth.NewContext and oidcauth.FromContext
// instead of using this key directly.
var emailKey key

// NewContext returns a new Context that carries value email.
func NewContext(ctx context.Context, email string) context.Context {
	return context.WithValue(ctx, emailKey, email)
}

// FromContext returns the Email value stored in ctx, if any.
func FromContext(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(emailKey).(string)
	return email, ok
}

// EmailLoggingClosure adds a "user" field for an authorized user
func EmailLoggingClosure(r *http.Request) []zapcore.Field {
	email, ok := FromContext(r.Context())
	if !ok {
		return []zapcore.Field{}
	}
	return []zapcore.Field{zap.String("user", email)}
}

// OidcEmailContext is a middlware for embedding a Email in the request's context
func OidcEmailContext(issuerURL, clientID string) middlewares.Middleware {
	provider, err := oidc.NewProvider(context.Background(), issuerURL)
	if err != nil {
		zap.L().Error("Error creating provider", zap.Error(err))
		// painc?
		return func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			})
		}
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// get the 'Authorization: Bearer xxx' token
			val := r.Header.Get("Authorization")
			if val == "" {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			splits := strings.SplitN(val, " ", 2)
			if len(splits) < 2 {
				http.Error(w, "Bad authorization string", http.StatusUnauthorized)
				return
			}
			if strings.ToLower(splits[0]) != strings.ToLower("bearer") {
				http.Error(w, "Request unauthorization with bearer", http.StatusUnauthorized)
				return
			}
			token := splits[1]

			// Verify the token
			idToken, err := verifier.Verify(r.Context(), token)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			u := &user{}
			if err := idToken.Claims(&u); err != nil {
				zap.L().Error("Couldn't get claim off of token", zap.Error(err))
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			*r = *r.WithContext(NewContext(r.Context(), u.Email))
			h.ServeHTTP(w, r)
		})
	}
}
