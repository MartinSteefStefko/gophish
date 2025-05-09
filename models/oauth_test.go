package models

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"

	"golang.org/x/oauth2"
	"gopkg.in/check.v1"
)

type OAuth2Suite struct {
	ModelsSuite
	server *httptest.Server
}

var _ = check.Suite(&OAuth2Suite{})

func (s *OAuth2Suite) SetUpTest(c *check.C) {
	s.server = setupMockOAuth2Server()
	// Override the Microsoft Graph API endpoint for testing
	graphAPIEndpoint = s.server.URL
}

func (s *OAuth2Suite) TearDownTest(c *check.C) {
	s.server.Close()
	s.ModelsSuite.TearDownTest(c)
	// Reset the Microsoft Graph API endpoint
	graphAPIEndpoint = "https://graph.microsoft.com/v1.0"
}

func setupMockOAuth2Server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			// Mock token endpoint
			if r.Method != "POST" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			resp := struct {
				AccessToken  string `json:"access_token"`
				TokenType   string `json:"token_type"`
				ExpiresIn   int    `json:"expires_in"`
				RefreshToken string `json:"refresh_token"`
			}{
				AccessToken:  "test_access_token",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
				RefreshToken: "test_refresh_token",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		case "/me":
			// Mock Microsoft Graph API user endpoint
			auth := r.Header.Get("Authorization")
			if auth != "Bearer test_access_token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			resp := struct {
				ID                string `json:"id"`
				UserPrincipalName string `json:"userPrincipalName"`
				DisplayName       string `json:"displayName"`
			}{
				ID:                "test_user_id",
				UserPrincipalName: "test@example.com",
				DisplayName:       "Test User",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func (s *OAuth2Suite) TestOAuth2Config(c *check.C) {
	config := &OAuth2Config{
		UserId:      1,
		ClientID:     "test_client_id",
		ClientSecret: "test_client_secret",
		TenantID:    "test_tenant_id",
		RedirectURI: "http://localhost:3333/oauth2/callback",
		Enabled:     true,
		ModifiedDate: time.Now().UTC(),
	}
	err := db.Save(config).Error
	c.Assert(err, check.IsNil)

	result, err := GetOAuth2Config()
	c.Assert(err, check.IsNil)
	c.Assert(result.ClientID, check.Equals, config.ClientID)
	c.Assert(result.ClientSecret, check.Equals, config.ClientSecret)
	c.Assert(result.Scopes, check.DeepEquals, []string{"https://graph.microsoft.com/User.Read", "offline_access"})

	// Test not enabled case
	config.Enabled = false
	err = db.Save(config).Error
	c.Assert(err, check.IsNil)

	_, err = GetOAuth2Config()
	c.Assert(err, check.NotNil)
}

func (s *OAuth2Suite) TestOAuth2Token(c *check.C) {
	userId := int64(1)
	token := &oauth2.Token{
		AccessToken:  "test_access_token",
		TokenType:    "Bearer",
		RefreshToken: "test_refresh_token",
		Expiry:      time.Now().Add(time.Hour),
	}

	err := SaveOAuth2Token(userId, token)
	c.Assert(err, check.IsNil)

	savedToken, err := GetUserOAuth2Token(userId)
	c.Assert(err, check.IsNil)
	c.Assert(savedToken.AccessToken, check.Equals, token.AccessToken)
	c.Assert(savedToken.RefreshToken, check.Equals, token.RefreshToken)
	c.Assert(savedToken.TokenType, check.Equals, token.TokenType)

	// Test update
	token2 := &oauth2.Token{
		AccessToken:  "test_access_token_2",
		TokenType:    "Bearer",
		RefreshToken: "test_refresh_token_2",
		Expiry:      time.Now().Add(2 * time.Hour),
	}

	err = SaveOAuth2Token(userId, token2)
	c.Assert(err, check.IsNil)

	savedToken, err = GetUserOAuth2Token(userId)
	c.Assert(err, check.IsNil)
	c.Assert(savedToken.AccessToken, check.Equals, token2.AccessToken)
	c.Assert(savedToken.RefreshToken, check.Equals, token2.RefreshToken)
}

func (s *OAuth2Suite) TestUserProfile(c *check.C) {
	token := &OAuth2Token{
		AccessToken: "test_access_token",
		TokenType:  "Bearer",
		ExpiresAt:  time.Now().Add(time.Hour),
	}

	profile, err := GetUserProfile(token)
	c.Assert(err, check.IsNil)
	c.Assert(profile["userPrincipalName"], check.Equals, "test@example.com")
	c.Assert(profile["displayName"], check.Equals, "Test User")

	// Test invalid token
	token.AccessToken = "invalid_token"
	_, err = GetUserProfile(token)
	c.Assert(err, check.NotNil)
} 