package models

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func TestOAuth2(t *testing.T) {
	// Setup
	cleanup := SetupTest(t)
	defer cleanup()

	// Create test tenant
	tenant := &Tenant{
		ID:   uuid.New().String(),
		Name: "Test Tenant",
	}
	err := tenant.Create()
	assert.NoError(t, err)

	// Create test provider tenant
	providerTenant := &ProviderTenant{
		ID:               uuid.New().String(),
		TenantID:         tenant.ID,
		ProviderType:     ProviderTypeAzure,
		ProviderTenantID: "test-tenant-id",
		DisplayName:      "Test Provider",
	}
	err = providerTenant.Create()
	assert.NoError(t, err)

	// Create test app registration
	appReg := &AppRegistration{
		ID:               uuid.New().String(),
		ProviderTenantID: providerTenant.ID,
		ClientID:         "test-client-id",
		RedirectURI:      "http://localhost/callback",
	}
	appReg.SetScopes([]string{"https://graph.microsoft.com/Mail.Send"})

	clientSecret := "test-secret"
	secretHash := HashSecret(clientSecret)
	secretEnc, err := Encrypt([]byte(clientSecret))
	assert.NoError(t, err)

	appReg.ClientSecretHash = string(secretHash)
	appReg.ClientSecretEncrypted = string(secretEnc)

	err = appReg.Create()
	assert.NoError(t, err)

	// Create OAuth2 feature
	feature := &Feature{
		ID:               uuid.New().String(),
		AppRegistrationID: appReg.ID,
		FeatureType:      FeatureTypeOAuth2,
		Enabled:          true,
		Config: map[string]interface{}{
			"scopes": []string{"https://graph.microsoft.com/Mail.Send"},
		},
	}
	err = feature.Create()
	assert.NoError(t, err)

	t.Run("GetOAuth2Config", func(t *testing.T) {
		config, err := GetOAuth2Config(appReg.ID)
		assert.NoError(t, err)
		assert.Equal(t, appReg.ClientID, config.ClientID)
		assert.Equal(t, clientSecret, config.ClientSecret)
		assert.Equal(t, appReg.RedirectURI, config.RedirectURL)
		assert.Equal(t, appReg.GetScopes(), config.Scopes)
	})

	t.Run("SaveAndGetOAuth2Token", func(t *testing.T) {
		ctx := context.Background()
		userID := int64(1)

		// Create test token
		token := &oauth2.Token{
			AccessToken:  "test_access_token",
			TokenType:    "Bearer",
			RefreshToken: "test_refresh_token",
			Expiry:      time.Now().Add(time.Hour),
		}

		// Save token
		err := SaveOAuth2Token(ctx, appReg.ID, userID, token)
		assert.NoError(t, err)

		// Get token
		savedToken, err := GetUserOAuth2Token(ctx, appReg.ID, userID)
		assert.NoError(t, err)
		assert.Equal(t, token.AccessToken, savedToken.AccessToken)
		assert.Equal(t, token.TokenType, savedToken.TokenType)
		assert.Equal(t, token.RefreshToken, savedToken.RefreshToken)
		assert.WithinDuration(t, token.Expiry, savedToken.Expiry, time.Second)
	})

	// Clean up
	err = feature.Delete()
	assert.NoError(t, err)
	err = appReg.Delete()
	assert.NoError(t, err)
	err = providerTenant.Delete()
	assert.NoError(t, err)
	err = tenant.Delete()
	assert.NoError(t, err)
} 