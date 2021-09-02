package oauth

import (
	"net/http"
	"time"

	"github.com/go-chi/render"
	"github.com/gofrs/uuid"
)

type GrantType string

const (
	PasswordGrant          GrantType = "password"
	ClientCredentialsGrant GrantType = "client_credentials"
	AuthCodeGrant          GrantType = "authorization_code"
	RefreshTokenGrant      GrantType = "refresh_token"
)

// CredentialsVerifier defines the interface of the user and client credentials verifier.
type CredentialsVerifier interface {
	// Validate username and password returning an error if the user credentials are wrong
	ValidateUser(username, password, scope string, req *http.Request) error
	// Validate clientID and secret returning an error if the client credentials are wrong
	ValidateClient(clientID, clientSecret, scope string, req *http.Request) error
	// Provide additional claims to the token
	AddClaims(tokenType TokenType, credential, tokenID, scope string) (map[string]string, error)
	// Optionally store the tokenID generated for the user
	StoreTokenID(tokenType TokenType, credential, tokenID, refreshTokenID string) error
	// Provide additional information to the authorization server response
	AddProperties(tokenType TokenType, credential, tokenID, scope string) (map[string]string, error)
	// Optionally validate previously stored tokenID during refresh request
	ValidateTokenID(tokenType TokenType, credential, tokenID, refreshTokenID string) error
}

// AuthorizationCodeVerifier defines the interface of the Authorization Code verifier
type AuthorizationCodeVerifier interface {
	// ValidateCode checks the authorization code and returns the user credential
	ValidateCode(clientID, clientSecret, code, redirectURI string, req *http.Request) (string, error)
}

// OAuthBearerServer is the OAuth 2 Bearer Server implementation.
type OAuthBearerServer struct {
	secretKey string
	TokenTTL  time.Duration
	verifier  CredentialsVerifier
	provider  *TokenProvider
}

// NewOAuthBearerServer creates new OAuth 2 Bearer Server
func NewOAuthBearerServer(secretKey string,
	ttl time.Duration,
	verifier CredentialsVerifier,
	formatter TokenSecureFormatter) *OAuthBearerServer {
	if formatter == nil {
		formatter = NewSHA256RC4TokenSecurityProvider([]byte(secretKey))
	}
	obs := &OAuthBearerServer{
		secretKey: secretKey,
		TokenTTL:  ttl,
		verifier:  verifier,
		provider:  NewTokenProvider(formatter)}
	return obs
}

// UserCredentials manages password grant type requests
func (s *OAuthBearerServer) UserCredentials(w http.ResponseWriter, r *http.Request) {
	grantType := r.FormValue("grant_type")
	// grant_type password variables
	username := r.FormValue("username")
	password := r.FormValue("password")
	scope := r.FormValue("scope")
	if username == "" || password == "" {
		// get username and password from basic authorization header
		var err error
		username, password, err = GetBasicAuthentication(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			render.JSON(w, r, "Not authorized")
			return
		}
	}
	// grant_type refresh_token
	refreshToken := r.FormValue("refresh_token")
	code, resp := s.generateTokenResponse(GrantType(grantType), username, password, refreshToken, scope, "", "", r)
	w.WriteHeader(code)
	render.JSON(w, r, resp)
}

// ClientCredentials manages client credentials grant type requests
func (s *OAuthBearerServer) ClientCredentials(w http.ResponseWriter, r *http.Request) {
	grantType := r.FormValue("grant_type")
	// grant_type client_credentials variables
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	if clientID == "" || clientSecret == "" {
		// get clientID and secret from basic authorization header
		var err error
		clientID, clientSecret, err = GetBasicAuthentication(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			render.JSON(w, r, "Not authorized")
			return
		}
	}
	scope := r.FormValue("scope")
	refreshToken := r.FormValue("refresh_token")
	code, resp := s.generateTokenResponse(GrantType(grantType), clientID, clientSecret, refreshToken, scope, "", "", r)
	w.WriteHeader(code)
	render.JSON(w, r, resp)
}

// AuthorizationCode manages authorization code grant type requests for the phase two of the authorization process
func (s *OAuthBearerServer) AuthorizationCode(w http.ResponseWriter, r *http.Request) {
	grantType := r.FormValue("grant_type")
	// grant_type client_credentials variables
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret") // not mandatory
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri") // not mandatory
	scope := r.FormValue("scope")              // not mandatory
	if clientID == "" {
		// get clientID and secret from basic authorization header
		var err error
		clientID, clientSecret, err = GetBasicAuthentication(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			render.JSON(w, r, "Not authorized")
			return
		}
	}
	status, resp := s.generateTokenResponse(GrantType(grantType), clientID, clientSecret, "", scope, code, redirectURI, r)
	w.WriteHeader(status)
	render.JSON(w, r, resp)
}

// Generate token response
func (s *OAuthBearerServer) generateTokenResponse(grantType GrantType, credential, secret, refreshToken, scope, code, redirectURI string, req *http.Request) (int, interface{}) {
	var resp *TokenResponse
	switch grantType {
	case PasswordGrant:
		if err := s.verifier.ValidateUser(credential, secret, scope, req); err != nil {
			return http.StatusUnauthorized, "Not authorized"
		}

		token, refresh, err := s.generateTokens(UserToken, credential, scope)
		if err != nil {
			return http.StatusInternalServerError, "Token generation failed, check claims"
		}

		if err = s.verifier.StoreTokenID(token.TokenType, credential, token.ID, refresh.RefreshTokenID); err != nil {
			return http.StatusInternalServerError, "Storing Token ID failed"
		}

		if resp, err = s.cryptTokens(token, refresh); err != nil {
			return http.StatusInternalServerError, "Token generation failed, check security provider"
		}
	case ClientCredentialsGrant:
		if err := s.verifier.ValidateClient(credential, secret, scope, req); err != nil {
			return http.StatusUnauthorized, "Not authorized"
		}

		token, refresh, err := s.generateTokens(ClientToken, credential, scope)
		if err != nil {
			return http.StatusInternalServerError, "Token generation failed, check claims"
		}

		if err = s.verifier.StoreTokenID(token.TokenType, credential, token.ID, refresh.RefreshTokenID); err != nil {
			return http.StatusInternalServerError, "Storing Token ID failed"
		}

		if resp, err = s.cryptTokens(token, refresh); err != nil {
			return http.StatusInternalServerError, "Token generation failed, check security provider"
		}
	case AuthCodeGrant:
		codeVerifier, ok := s.verifier.(AuthorizationCodeVerifier)
		if !ok {
			return http.StatusUnauthorized, "Not authorized, grant type not supported"
		}

		user, err := codeVerifier.ValidateCode(credential, secret, code, redirectURI, req)
		if err != nil {
			return http.StatusUnauthorized, "Not authorized"
		}

		token, refresh, err := s.generateTokens(AuthToken, user, scope)
		if err != nil {
			return http.StatusInternalServerError, "Token generation failed, check claims"
		}

		err = s.verifier.StoreTokenID(token.TokenType, user, token.ID, refresh.RefreshTokenID)
		if err != nil {
			return http.StatusInternalServerError, "Storing Token ID failed"
		}

		if resp, err = s.cryptTokens(token, refresh); err != nil {
			return http.StatusInternalServerError, "Token generation failed, check security provider"
		}
	case RefreshTokenGrant:
		refresh, err := s.provider.DecryptRefreshTokens(refreshToken)
		if err != nil {
			return http.StatusUnauthorized, "Not authorized"
		}

		if err = s.verifier.ValidateTokenID(refresh.TokenType, refresh.Credential, refresh.TokenID, refresh.RefreshTokenID); err != nil {
			return http.StatusUnauthorized, "Not authorized invalid token"
		}

		token, refresh, err := s.generateTokens(refresh.TokenType, refresh.Credential, refresh.Scope)
		if err != nil {
			return http.StatusInternalServerError, "Token generation failed"
		}

		err = s.verifier.StoreTokenID(token.TokenType, refresh.Credential, token.ID, refresh.RefreshTokenID)
		if err != nil {
			return http.StatusInternalServerError, "Storing Token ID failed"
		}

		if resp, err = s.cryptTokens(token, refresh); err != nil {
			return http.StatusInternalServerError, "Token generation failed"
		}
	default:
		return http.StatusBadRequest, "Invalid grant_type"
	}

	return http.StatusOK, resp
}

func (s *OAuthBearerServer) generateTokens(tokenType TokenType, username, scope string) (token *Token, refresh *RefreshToken, err error) {
	token = &Token{Credential: username, ExpiresIn: s.TokenTTL, CreationDate: time.Now().UTC(), TokenType: tokenType, Scope: scope}
	// generate token ID
	token.ID = uuid.Must(uuid.NewV4()).String()
	if s.verifier != nil {
		claims, err := s.verifier.AddClaims(token.TokenType, username, token.ID, token.Scope)
		if err != nil {
			// claims error
			return nil, nil, err
		}
		token.Claims = claims
	}
	// create refresh token
	refresh = &RefreshToken{RefreshTokenID: uuid.Must(uuid.NewV4()).String(), TokenID: token.ID, CreationDate: time.Now().UTC(), Credential: username, TokenType: tokenType, Scope: scope}

	return token, refresh, nil
}

func (s *OAuthBearerServer) cryptTokens(token *Token, refresh *RefreshToken) (resp *TokenResponse, err error) {
	ctoken, err := s.provider.CryptToken(token)
	if err != nil {
		return nil, err
	}
	crefresh, err := s.provider.CryptRefreshToken(refresh)
	if err != nil {
		return nil, err
	}
	resp = &TokenResponse{Token: ctoken, RefreshToken: crefresh, TokenType: BearerToken, ExpiresIn: (int64)(s.TokenTTL / time.Second)}

	if s.verifier != nil {
		// add properties
		props, err := s.verifier.AddProperties(token.TokenType, token.Credential, token.ID, token.Scope)
		if err != nil {
			return nil, err
		}
		resp.Properties = props
	}
	return resp, nil
}
