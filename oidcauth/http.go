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

// User is an OIDC authenticated user
type User struct {
	Email string `json:"email"`
}

// key is an unexported type for keys defined in this package.
// This prevents collisions with keys defined in other packages.
type key int

// userKey is the key for user.User values in Contexts. It is
// unexported; clients use user.NewContext and user.FromContext
// instead of using this key directly.
var userKey key

// NewContext returns a new Context that carries value u.
func NewContext(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, userKey, u)
}

// FromContext returns the User value stored in ctx, if any.
func FromContext(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(userKey).(*User)
	return u, ok
}

// UserLoggingClosure adds a "user" field for an authorized user
func UserLoggingClosure(r *http.Request) []zapcore.Field {
	user, ok := FromContext(r.Context())
	if !ok {
		return []zapcore.Field{}
	}
	return []zapcore.Field{zap.String("user", user.Email)}
}

// OidcUserContext is a middlware for embedding a User in the request's context
func OidcUserContext(issuerURL, clientID string) middlewares.Middleware {
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
			user := &User{}
			if err := idToken.Claims(&user); err != nil {
				zap.L().Error("Couldn't get claim off of token", zap.Error(err))
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			*r = *r.WithContext(NewContext(r.Context(), user))
			h.ServeHTTP(w, r)
		})
	}
}
