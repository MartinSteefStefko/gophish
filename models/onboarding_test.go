package models

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestOnboarding(t *testing.T) {
	// Setup
	cleanup := setupTest(t)
	defer cleanup()

	t.Run("BasicOAuth2Onboarding", func(t *testing.T) {
		// Test basic OAuth2 onboarding flow
		tenant := &Tenant{
			ID:   uuid.New(),
			Name: "Test OAuth2 Tenant",
		}
		err := tenant.Create()
		assert.NoError(t, err)

		// Test provider tenant creation
		providerTenant := &ProviderTenant{
			ID:               uuid.New(),
			TenantID:         tenant.ID,
			ProviderType:     ProviderTypeAzure,
			ProviderTenantID: "test-azure-tenant",
			DisplayName:      "Test Azure Provider",
		}
		err = providerTenant.Create()
		assert.NoError(t, err)

		// Test app registration creation with OAuth2
		clientID := "test-client-" + uuid.New().String()
		clientSecret := "test-secret-" + uuid.New().String()
		redirectURI := "http://localhost:3333/oauth2/callback"
		scopes := []string{"https://graph.microsoft.com/Mail.Send"}

		appReg, err := CreateAppRegistration(context.Background(), providerTenant.ID, "oauth2", clientID, clientSecret, redirectURI, scopes)
		assert.NoError(t, err)
		assert.NotNil(t, appReg)

		// Verify OAuth2 configuration
		config, err := GetOAuth2Config(appReg.ID)
		assert.NoError(t, err)
		assert.Equal(t, clientID, config.ClientID)
		assert.Equal(t, redirectURI, config.RedirectURL)
		assert.Equal(t, scopes, config.Scopes)

		// Clean up
		err = appReg.Delete()
		assert.NoError(t, err)
	})

	t.Run("MultiTenantOnboarding", func(t *testing.T) {
		// Create multiple tenants with different configurations
		tenants := make([]*Tenant, 3)
		for i := 0; i < 3; i++ {
			tenant := &Tenant{
				ID:   uuid.New(),
				Name: "Multi Tenant " + uuid.New().String(),
			}
			err := tenant.Create()
			assert.NoError(t, err)
			tenants[i] = tenant

			// Create provider tenant for each tenant
			providerTenant := &ProviderTenant{
				ID:               uuid.New(),
				TenantID:         tenant.ID,
				ProviderType:     ProviderTypeAzure,
				ProviderTenantID: "azure-tenant-" + uuid.New().String(),
				DisplayName:      "Azure Provider " + tenant.Name,
			}
			err = providerTenant.Create()
			assert.NoError(t, err)

			// Create multiple app registrations per tenant
			useCases := []string{"email", "dmarc", "phishing"}
			for _, useCase := range useCases {
				clientID := "client-" + uuid.New().String()
				clientSecret := "secret-" + uuid.New().String()
				redirectURI := "http://localhost:3333/" + useCase + "/callback"
				scopes := []string{"https://graph.microsoft.com/" + useCase}

				appReg, err := CreateAppRegistration(context.Background(), providerTenant.ID, useCase, clientID, clientSecret, redirectURI, scopes)
				assert.NoError(t, err)
				assert.NotNil(t, appReg)

				// Verify isolation
				found, err := GetAppRegistration(appReg.ID)
				assert.NoError(t, err)
				assert.Equal(t, providerTenant.ID, found.ProviderTenantID)
				assert.Equal(t, useCase, found.UseCase)

				// Clean up
				err = appReg.Delete()
				assert.NoError(t, err)
			}
		}
	})

	t.Run("ProviderRegistration", func(t *testing.T) {
		tenant := &Tenant{
			ID:   uuid.New(),
			Name: "Provider Test Tenant",
		}
		err := tenant.Create()
		assert.NoError(t, err)

		// Test Azure provider registration
		azureProvider := &ProviderTenant{
			ID:               uuid.New(),
			TenantID:         tenant.ID,
			ProviderType:     ProviderTypeAzure,
			ProviderTenantID: "azure-" + uuid.New().String(),
			DisplayName:      "Azure Provider",
			Region:           "us-east-1",
		}
		err = azureProvider.Create()
		assert.NoError(t, err)

		// Test app registration with region
		clientID := "client-" + uuid.New().String()
		clientSecret := "secret-" + uuid.New().String()
		redirectURI := "http://localhost:3333/callback"
		scopes := []string{"https://graph.microsoft.com/Mail.Send"}

		appReg, err := CreateAppRegistration(context.Background(), azureProvider.ID, "email", clientID, clientSecret, redirectURI, scopes)
		assert.NoError(t, err)
		assert.NotNil(t, appReg)

		// Verify provider-specific configuration
		found, err := GetAppRegistration(appReg.ID)
		assert.NoError(t, err)
		assert.Equal(t, azureProvider.ID, found.ProviderTenantID)

		// Test provider features
		feature := &Feature{
			ID:               uuid.New(),
			AppRegistrationID: appReg.ID,
			FeatureType:      FeatureTypeOAuth2,
			Enabled:          true,
			Config: map[string]interface{}{
				"provider": "azure",
				"region":   azureProvider.Region,
			},
		}
		err = feature.Create()
		assert.NoError(t, err)

		// Clean up
		err = feature.Delete()
		assert.NoError(t, err)
		err = appReg.Delete()
		assert.NoError(t, err)
	})
} 