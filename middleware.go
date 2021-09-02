package oauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/render"
)

// BearerAuthentication middleware for go-chi
type BearerAuthentication struct {
	secretKey string
	provider  *TokenProvider
}

// NewBearerAuthentication create a BearerAuthentication middleware
func NewBearerAuthentication(secretKey string, formatter TokenSecureFormatter) *BearerAuthentication {
	ba := &BearerAuthentication{secretKey: secretKey}
	if formatter == nil {
		formatter = NewSHA256RC4TokenSecurityProvider([]byte(secretKey))
	}
	ba.provider = NewTokenProvider(formatter)
	return ba
}

// Authorize is the OAuth 2.0 middleware for go-chi resource server.
// Authorize creates a BearerAuthentication middleware and return the Authorize method.
func Authorize(secretKey string, formatter TokenSecureFormatter) func(next http.Handler) http.Handler {
	return NewBearerAuthentication(secretKey, formatter).Authorize
}

// Authorize verifies the bearer token authorizing or not the request.
// Token is retrieved from the Authorization HTTP header that respects the format
// Authorization: Bearer {access_token}
func (ba *BearerAuthentication) Authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		token, err := ba.checkAuthorizationHeader(auth)
		ctx := r.Context()
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			render.JSON(w, r, "Not authorized: "+err.Error())
			return
		} else {
			context.WithValue(ctx, "oauth.credential", token.Credential)
			context.WithValue(ctx, "oauth.claims", token.Claims)
			context.WithValue(ctx, "oauth.scope", token.Scope)
			context.WithValue(ctx, "oauth.tokentype", token.TokenType)
			context.WithValue(ctx, "oauth.accesstoken", auth[7:])
			next.ServeHTTP(w, r.WithContext(ctx))
		}
	})
}

// Check header and token.
func (ba *BearerAuthentication) checkAuthorizationHeader(auth string) (t *Token, err error) {
	if len(auth) < 7 {
		return nil, errors.New("Invalid bearer authorization header")
	}
	authType := strings.ToLower(auth[:6])
	if authType != "bearer" {
		return nil, errors.New("Invalid bearer authorization header")
	}
	token, err := ba.provider.DecryptToken(auth[7:])
	if err != nil {
		return nil, errors.New("Invalid token")
	}
	if time.Now().UTC().After(token.CreationDate.Add(token.ExpiresIn)) {
		return nil, errors.New("Token expired")
	}
	return token, nil
}
