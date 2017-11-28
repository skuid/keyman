package groupauth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-redis/redis"
	"github.com/skuid/spec/middlewares"
	"go.uber.org/zap"
	"golang.org/x/oauth2/google"
	directory "google.golang.org/api/admin/directory/v1"
)

// UserDirectory is for authorizing users against Google's Gsuite
type UserDirectory struct {
	directoryService *directory.Service
	redisClient      *redis.Client
	cacheTTL         time.Duration
	domain           string
	authorizedGroups []string
}

// NewUserDirectory returns a user directory
func NewUserDirectory(authJSON []byte, adminUsername, domain string, authorizedGroups []string, redisHost string, duration time.Duration) (*UserDirectory, error) {
	conf, err := google.JWTConfigFromJSON(authJSON, directory.AdminDirectoryGroupReadonlyScope)
	if err != nil {
		return nil, fmt.Errorf("Error loading json credential: %q", err)
	}
	conf.Subject = adminUsername

	api, err := directory.New(conf.Client(context.Background()))
	if err != nil {
		return nil, fmt.Errorf("Error creating new Google API client: %q", err)
	}

	return &UserDirectory{
		directoryService: api,
		redisClient: redis.NewClient(&redis.Options{
			Addr: fmt.Sprintf("%s:6379", redisHost),
			DB:   0,
		}),
		cacheTTL:         duration,
		domain:           domain,
		authorizedGroups: authorizedGroups,
	}, nil
}

// Authorize is a middleware for authenticating handlers. It accepts a func that
// takes a context and provides a username
func (d *UserDirectory) Authorize(userFunc func(context.Context) (string, bool)) middlewares.Middleware {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := userFunc(r.Context())
			if !ok {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			ok, err := d.AuthorizeUser(user)
			if err != nil {
				zap.L().Error("Error authorizing user", zap.Error(err))
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if !ok {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			h.ServeHTTP(w, r)
		})
	}
}

// AuthorizeUser checks the authorization for a given user
func (d *UserDirectory) AuthorizeUser(user string) (bool, error) {
	_, err := d.redisClient.Get(user).Int64()
	if err == nil {
		return true, nil
	}

	groups, err := d.directoryService.Groups.List().Domain(d.domain).UserKey(user).Do()
	if err != nil {
		return false, fmt.Errorf("Error getting user groups: %q", err)
	}
	userGroups := []string{}
	for _, group := range groups.Groups {
		userGroups = append(userGroups, group.Email)
	}

	authorized := false
	for _, authGroup := range d.authorizedGroups {
		for _, groupName := range userGroups {
			if authGroup == groupName {
				authorized = true
				break
			}
		}
		if authorized {
			break
		}
	}

	if authorized {
		if err := d.redisClient.Set(user, 1, d.cacheTTL).Err(); err != nil {
			zap.L().Error("Error setting cache", zap.Error(err))
		}
	}
	return authorized, nil
}
