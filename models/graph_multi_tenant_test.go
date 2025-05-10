package models

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

// mockEndpoint is used to override the default endpoint in tests
var mockEndpoint oauth2.Endpoint

// CustomTokenSource is a token source that automatically saves refreshed tokens
type CustomTokenSource struct {
	config    *oauth2.Config
	token     *oauth2.Token
	appRegID  uuid.UUID
	userID    int64
}

func (s *CustomTokenSource) Token() (*oauth2.Token, error) {
	if s.token.Valid() {
		return s.token, nil
	}

	// Get a new token using the refresh token
	token, err := s.config.TokenSource(context.Background(), s.token).Token()
	if err != nil {
		return nil, err
	}

	// Save the new token
	err = SaveOAuth2Token(context.Background(), s.appRegID, s.userID, token)
	if err != nil {
		return nil, err
	}

	s.token = token
	return token, nil
}

func setupMultiTenantTest(t *testing.T) (*Tenant, *ProviderTenant, *AppRegistration, func()) {
	cleanup := setupTest(t)

	// Create a tenant
	tenant := &Tenant{
		ID:   uuid.New(),
		Name: "Test Tenant",
	}
	err := tenant.Create()
	assert.NoError(t, err)

	// Create a provider tenant
	providerTenant := &ProviderTenant{
		ID:               uuid.New(),
		TenantID:         tenant.ID,
		ProviderType:     ProviderTypeAzure,
		ProviderTenantID: "test-tenant-id",
		DisplayName:      "Test Azure Tenant",
	}
	err = providerTenant.Create()
	assert.NoError(t, err)

	// Create an app registration
	clientSecret := "test-secret"
	appReg := &AppRegistration{
		ID:               uuid.New(),
		ProviderTenantID: providerTenant.ID,
		UseCase:          "email",
		ClientID:         "test-client-id",
		RedirectURI:      "http://localhost/callback",
	}
	appReg.SetScopes([]string{"https://graph.microsoft.com/Mail.Send"})

	// Encrypt and hash the client secret
	secretHash := HashSecret(clientSecret)
	secretEnc, err := Encrypt([]byte(clientSecret))
	assert.NoError(t, err)

	appReg.ClientSecretHash = secretHash
	appReg.ClientSecretEncrypted = secretEnc

	err = appReg.Create()
	assert.NoError(t, err)

	return tenant, providerTenant, appReg, cleanup
}

func setupMockMultiTenantGraphAPI() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Validate client credentials
		clientID := r.Form.Get("client_id")
		clientSecret := r.Form.Get("client_secret")
		if clientID != "test-client-id" || clientSecret != "test-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Handle refresh token request
		if r.Form.Get("grant_type") == "refresh_token" {
			refreshToken := r.Form.Get("refresh_token")
			if refreshToken != "test_refresh_token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			// Return new tokens
			resp := struct {
				AccessToken  string `json:"access_token"`
				TokenType   string `json:"token_type"`
				ExpiresIn   int    `json:"expires_in"`
				RefreshToken string `json:"refresh_token"`
			}{
				AccessToken:  "new_access_token",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
				RefreshToken: "new_refresh_token",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		// Handle initial token request
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
	}))
}

func TestMultiTenantGraphAPIIntegration(t *testing.T) {
	_, providerTenant, appReg, cleanup := setupMultiTenantTest(t)
	defer cleanup()

	mockServer := setupMockMultiTenantGraphAPI()
	defer mockServer.Close()

	// Set up mock endpoint
	mockEndpoint = oauth2.Endpoint{
		TokenURL: mockServer.URL,
	}

	// Override GetOAuth2Config for testing
	originalGetOAuth2Config := GetOAuth2Config
	GetOAuth2Config = func(appRegID uuid.UUID) (*oauth2.Config, error) {
		appReg, err := GetAppRegistration(appRegID)
		if err != nil {
			return nil, err
		}

		clientSecret, err := Decrypt(appReg.ClientSecretEncrypted)
		if err != nil {
			return nil, err
		}

		return &oauth2.Config{
			ClientID:     appReg.ClientID,
			ClientSecret: string(clientSecret),
			RedirectURL:  appReg.RedirectURI,
			Scopes:       appReg.GetScopes(),
			Endpoint:     mockEndpoint,
		}, nil
	}
	defer func() {
		GetOAuth2Config = originalGetOAuth2Config
	}()

	t.Run("Tenant_Specific_Token", func(t *testing.T) {
		// Get OAuth2 config for the app registration
		config, err := GetOAuth2Config(appReg.ID)
		assert.NoError(t, err)
		assert.NotNil(t, config)

		// Create a token
		token := &oauth2.Token{
			AccessToken:  "test_token_" + providerTenant.ProviderTenantID,
			TokenType:    "Bearer",
			RefreshToken: "test_refresh_token",
			Expiry:      time.Now().Add(-1 * time.Hour),
		}

		// Save token for user 1
		err = SaveOAuth2Token(context.Background(), appReg.ID, 1, token)
		assert.NoError(t, err)

		// Verify token is saved correctly
		retrieved, err := GetUserOAuth2Token(context.Background(), appReg.ID, 1)
		assert.NoError(t, err)
		assert.Equal(t, token.AccessToken, retrieved.AccessToken)
	})

	t.Run("Cross_Tenant_Access_Prevention", func(t *testing.T) {
		// Create another tenant
		otherTenant := &Tenant{
			ID:   uuid.New(),
			Name: "Other Tenant",
		}
		err := otherTenant.Create()
		assert.NoError(t, err)

		// Try to access first tenant's token with second tenant
		_, err = GetUserOAuth2Token(context.Background(), appReg.ID, 2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("Tenant_Token_Isolation", func(t *testing.T) {
		// Create tokens for two different users in the same tenant
		token1 := &oauth2.Token{
			AccessToken:  "test_token_user1",
			TokenType:    "Bearer",
			RefreshToken: "test_refresh_token_1",
			Expiry:      time.Now().Add(time.Hour),
		}

		token2 := &oauth2.Token{
			AccessToken:  "test_token_user2",
			TokenType:    "Bearer",
			RefreshToken: "test_refresh_token_2",
			Expiry:      time.Now().Add(time.Hour),
		}

		// Save tokens
		err := SaveOAuth2Token(context.Background(), appReg.ID, 1, token1)
		assert.NoError(t, err)

		err = SaveOAuth2Token(context.Background(), appReg.ID, 2, token2)
		assert.NoError(t, err)

		// Verify tokens are isolated
		retrieved1, err := GetUserOAuth2Token(context.Background(), appReg.ID, 1)
		assert.NoError(t, err)
		assert.Equal(t, token1.AccessToken, retrieved1.AccessToken)

		retrieved2, err := GetUserOAuth2Token(context.Background(), appReg.ID, 2)
		assert.NoError(t, err)
		assert.Equal(t, token2.AccessToken, retrieved2.AccessToken)
	})

	t.Run("Token_Refresh_Per_Tenant", func(t *testing.T) {
		// Create an expired token
		expiredToken := &oauth2.Token{
			AccessToken:  "expired_token",
			TokenType:    "Bearer",
			RefreshToken: "test_refresh_token",
			Expiry:      time.Now().Add(-1 * time.Hour),
		}

		// Save the expired token
		err := SaveOAuth2Token(context.Background(), appReg.ID, 1, expiredToken)
		assert.NoError(t, err)

		// Get the OAuth2 config
		config, err := GetOAuth2Config(appReg.ID)
		assert.NoError(t, err)

		// Create a custom token source
		tokenSource := &CustomTokenSource{
			config:    config,
			token:     expiredToken,
			appRegID:  appReg.ID,
			userID:    1,
		}

		// Get a new token
		newToken, err := tokenSource.Token()
		assert.NoError(t, err)
		assert.NotEqual(t, expiredToken.AccessToken, newToken.AccessToken)
		assert.Equal(t, "new_access_token", newToken.AccessToken)
		assert.Equal(t, "new_refresh_token", newToken.RefreshToken)
		assert.True(t, newToken.Expiry.After(time.Now()))

		// Verify the token was saved
		savedToken, err := GetUserOAuth2Token(context.Background(), appReg.ID, 1)
		assert.NoError(t, err)
		assert.Equal(t, newToken.AccessToken, savedToken.AccessToken)
		assert.Equal(t, newToken.RefreshToken, savedToken.RefreshToken)
	})
} 