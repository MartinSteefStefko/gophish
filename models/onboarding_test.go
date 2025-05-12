package models

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestOnboarding(t *testing.T) {
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

	t.Run("CreateFeature", func(t *testing.T) {
		appReg := &AppRegistration{
			ID:               uuid.New().String(),
			ProviderTenantID: providerTenant.ID,
			ClientID:         "test-client-id",
			RedirectURI:      "http://localhost/callback",
		}
		appReg.SetScopes([]string{"https://graph.microsoft.com/Mail.Send"})

		clientSecret := "test-secret"
		secretEnc, err := Encrypt([]byte(clientSecret))
		assert.NoError(t, err)

		appReg.ClientSecretEncrypted = string(secretEnc)

		err = appReg.Create()
		assert.NoError(t, err)

		feature := &Feature{
			ID:                uuid.New().String(),
			AppRegistrationID: appReg.ID,
			FeatureType:       FeatureTypeOAuth2,
			Enabled:          true,
			Config: map[string]interface{}{
				"scopes": []string{"https://graph.microsoft.com/Mail.Send"},
			},
		}

		err = feature.Create()
		assert.NoError(t, err)

		// Verify feature was created
		found, err := GetFeature(feature.ID)
		assert.NoError(t, err)
		assert.Equal(t, feature.ID, found.ID)
		assert.Equal(t, feature.AppRegistrationID, found.AppRegistrationID)
		assert.Equal(t, feature.FeatureType, found.FeatureType)
		assert.Equal(t, feature.Enabled, found.Enabled)

		// Clean up
		err = feature.Delete()
		assert.NoError(t, err)
		err = appReg.Delete()
		assert.NoError(t, err)
	})

	// Test provider tenant creation
	t.Run("CreateProviderTenant", func(t *testing.T) {
		ctx := context.Background()
		providerType := ProviderTypeAzure
		providerTenantID := "new-tenant-id"
		displayName := "New Test Provider"
		region := "us-east-1"

		provider, err := CreateProviderTenant(ctx, tenant.ID, providerType, providerTenantID, displayName, region)
		assert.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, tenant.ID, provider.TenantID)
		assert.Equal(t, providerType, provider.ProviderType)
		assert.Equal(t, providerTenantID, provider.ProviderTenantID)
		assert.Equal(t, displayName, provider.DisplayName)
		assert.Equal(t, region, provider.Region)

		// Clean up
		err = provider.Delete()
		assert.NoError(t, err)
	})

	// Clean up
	err = providerTenant.Delete()
	assert.NoError(t, err)
	err = tenant.Delete()
	assert.NoError(t, err)
} 