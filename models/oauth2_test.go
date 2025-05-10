package models

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func TestOAuth2ConfigWithMultiTenant(t *testing.T) {
	// Setup
	cleanup := setupTest(t)
	defer cleanup()

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
		UseCase:          "test-use-case",
		ClientID:         "test-client-id",
		RedirectURI:      "http://localhost/callback",
	}
	appReg.SetScopes([]string{"test.scope"})

	// Encrypt and hash the client secret
	secretHash := HashSecret(clientSecret)
	secretEnc, err := Encrypt([]byte(clientSecret))
	assert.NoError(t, err)

	appReg.ClientSecretHash = secretHash
	appReg.ClientSecretEncrypted = secretEnc

	err = appReg.Create()
	assert.NoError(t, err)
	assert.NotNil(t, appReg)

	// Test cases
	tests := []struct {
		name    string
		appID   uuid.UUID
		wantErr bool
	}{
		{
			name:    "Valid app registration",
			appID:   appReg.ID,
			wantErr: false,
		},
		{
			name:    "Non-existent app registration",
			appID:   uuid.New(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := GetOAuth2Config(tt.appID)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, config)
			assert.Equal(t, "test-client-id", config.ClientID)
			assert.Equal(t, clientSecret, config.ClientSecret)
			assert.Equal(t, "http://localhost/callback", config.RedirectURL)
			assert.Contains(t, config.Scopes, "test.scope")
		})
	}
}

func TestOAuth2TokenManagement(t *testing.T) {
	// Setup
	cleanup := setupTest(t)
	defer cleanup()

	// Create test data
	tenant := &Tenant{
		ID:   uuid.New(),
		Name: "Test Tenant",
	}
	err := tenant.Create()
	assert.NoError(t, err)

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
		UseCase:          "test-use-case",
		ClientID:         "test-client-id",
		RedirectURI:      "http://localhost/callback",
	}
	appReg.SetScopes([]string{"test.scope"})

	// Encrypt and hash the client secret
	secretHash := HashSecret(clientSecret)
	secretEnc, err := Encrypt([]byte(clientSecret))
	assert.NoError(t, err)

	appReg.ClientSecretHash = secretHash
	appReg.ClientSecretEncrypted = secretEnc

	err = appReg.Create()
	assert.NoError(t, err)

	// Test token management
	ctx := context.Background()
	userID := int64(1)
	token := &oauth2.Token{
		AccessToken:  "test-access-token",
		TokenType:    "Bearer",
		RefreshToken: "test-refresh-token",
		Expiry:      time.Now().Add(time.Hour),
	}

	// Save token
	err = SaveOAuth2Token(ctx, appReg.ID, userID, token)
	assert.NoError(t, err)

	// Retrieve token
	retrieved, err := GetUserOAuth2Token(ctx, appReg.ID, userID)
	assert.NoError(t, err)
	assert.Equal(t, token.AccessToken, retrieved.AccessToken)
	assert.Equal(t, token.RefreshToken, retrieved.RefreshToken)
	assert.Equal(t, token.TokenType, retrieved.TokenType)
	assert.WithinDuration(t, token.Expiry, retrieved.Expiry, time.Second)

	// Test token update
	newToken := &oauth2.Token{
		AccessToken:  "new-access-token",
		TokenType:    "Bearer",
		RefreshToken: "new-refresh-token",
		Expiry:      time.Now().Add(2 * time.Hour),
	}
	err = SaveOAuth2Token(ctx, appReg.ID, userID, newToken)
	assert.NoError(t, err)

	// Verify update
	updated, err := GetUserOAuth2Token(ctx, appReg.ID, userID)
	assert.NoError(t, err)
	assert.Equal(t, newToken.AccessToken, updated.AccessToken)
	assert.Equal(t, newToken.RefreshToken, updated.RefreshToken)
} 