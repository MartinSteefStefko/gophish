package models

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAppRegistration(t *testing.T) {
	// Setup
	cleanup := setupTest(t)
	defer cleanup()

	// Create test tenant
	tenant := &Tenant{
		ID:   uuid.New(),
		Name: "Test Tenant",
	}
	err := tenant.Create()
	assert.NoError(t, err)

	// Create test provider tenant
	providerTenant := &ProviderTenant{
		ID:               uuid.New(),
		TenantID:         tenant.ID,
		ProviderType:     ProviderTypeAzure,
		ProviderTenantID: "test-tenant-id",
		DisplayName:      "Test Provider",
	}
	err = providerTenant.Create()
	assert.NoError(t, err)

	t.Run("CreateAppRegistration", func(t *testing.T) {
		appReg := &AppRegistration{
			ID:               uuid.New(),
			ProviderTenantID: providerTenant.ID,
			UseCase:          "email",
			ClientID:         fmt.Sprintf("test-client-id-%s", uuid.New().String()),
			RedirectURI:      "http://localhost/callback",
		}
		appReg.SetScopes([]string{"https://graph.microsoft.com/Mail.Send"})

		// Test client secret handling
		clientSecret := "test-secret"
		secretHash := HashSecret(clientSecret)
		secretEnc, err := Encrypt([]byte(clientSecret))
		assert.NoError(t, err)

		appReg.ClientSecretHash = secretHash
		appReg.ClientSecretEncrypted = secretEnc

		err = appReg.Create()
		assert.NoError(t, err)
		assert.NotEmpty(t, appReg.CreatedAt)
		assert.NotEmpty(t, appReg.UpdatedAt)

		// Verify app registration was created
		found, err := GetAppRegistration(appReg.ID)
		assert.NoError(t, err)
		assert.Equal(t, appReg.ID, found.ID)
		assert.Equal(t, appReg.ProviderTenantID, found.ProviderTenantID)
		assert.Equal(t, appReg.UseCase, found.UseCase)
		assert.Equal(t, appReg.ClientID, found.ClientID)
		assert.Equal(t, appReg.GetScopes(), found.GetScopes())

		// Verify client secret handling
		decrypted, err := Decrypt(found.ClientSecretEncrypted)
		assert.NoError(t, err)
		assert.Equal(t, clientSecret, string(decrypted))

		// Clean up
		err = appReg.Delete()
		assert.NoError(t, err)
	})

	t.Run("UpdateAppRegistration", func(t *testing.T) {
		appReg := &AppRegistration{
			ID:               uuid.New(),
			ProviderTenantID: providerTenant.ID,
			UseCase:          "email",
			ClientID:         fmt.Sprintf("test-client-id-%s", uuid.New().String()),
			RedirectURI:      "http://localhost/callback",
		}
		appReg.SetScopes([]string{"https://graph.microsoft.com/Mail.Send"})

		clientSecret := "test-secret"
		secretHash := HashSecret(clientSecret)
		secretEnc, err := Encrypt([]byte(clientSecret))
		assert.NoError(t, err)

		appReg.ClientSecretHash = secretHash
		appReg.ClientSecretEncrypted = secretEnc

		err = appReg.Create()
		assert.NoError(t, err)

		// Update scopes
		newScopes := []string{
			"https://graph.microsoft.com/Mail.Send",
			"https://graph.microsoft.com/Mail.Read",
		}
		appReg.SetScopes(newScopes)

		// Update client secret
		newSecret := "new-secret"
		newSecretHash := HashSecret(newSecret)
		newSecretEnc, err := Encrypt([]byte(newSecret))
		assert.NoError(t, err)

		appReg.ClientSecretHash = newSecretHash
		appReg.ClientSecretEncrypted = newSecretEnc

		err = appReg.Update()
		assert.NoError(t, err)

		// Verify updates
		found, err := GetAppRegistration(appReg.ID)
		assert.NoError(t, err)
		assert.Equal(t, newScopes, found.GetScopes())

		decrypted, err := Decrypt(found.ClientSecretEncrypted)
		assert.NoError(t, err)
		assert.Equal(t, newSecret, string(decrypted))

		// Clean up
		err = appReg.Delete()
		assert.NoError(t, err)
	})

	t.Run("DeleteAppRegistration", func(t *testing.T) {
		appReg := &AppRegistration{
			ID:               uuid.New(),
			ProviderTenantID: providerTenant.ID,
			UseCase:          "email",
			ClientID:         fmt.Sprintf("test-client-id-%s", uuid.New().String()),
			RedirectURI:      "http://localhost/callback",
		}
		err := appReg.Create()
		assert.NoError(t, err)

		// Delete app registration
		err = appReg.Delete()
		assert.NoError(t, err)

		// Verify deletion
		_, err = GetAppRegistration(appReg.ID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "app registration not found")

		// Try to delete again
		err = appReg.Delete()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "app registration not found")
	})

	t.Run("CrossTenantIsolation", func(t *testing.T) {
		// Clean up any existing app registrations
		err := db.Exec("DELETE FROM app_registrations").Error
		assert.NoError(t, err)

		// Create another tenant and provider tenant
		otherTenant := &Tenant{
			ID:   uuid.New(),
			Name: "Other Tenant",
		}
		err = otherTenant.Create()
		assert.NoError(t, err)

		otherProviderTenant := &ProviderTenant{
			ID:               uuid.New(),
			TenantID:         otherTenant.ID,
			ProviderType:     ProviderTypeAzure,
			ProviderTenantID: "other-tenant-id",
			DisplayName:      "Other Provider",
		}
		err = otherProviderTenant.Create()
		assert.NoError(t, err)

		// Create app registrations for both provider tenants
		appReg1 := &AppRegistration{
			ID:               uuid.New(),
			ProviderTenantID: providerTenant.ID,
			UseCase:          "email",
			ClientID:         fmt.Sprintf("client-id-%s", uuid.New().String()),
			RedirectURI:      "http://localhost/callback1",
		}
		err = appReg1.Create()
		assert.NoError(t, err)

		appReg2 := &AppRegistration{
			ID:               uuid.New(),
			ProviderTenantID: otherProviderTenant.ID,
			UseCase:          "email",
			ClientID:         fmt.Sprintf("client-id-%s", uuid.New().String()),
			RedirectURI:      "http://localhost/callback2",
		}
		err = appReg2.Create()
		assert.NoError(t, err)

		// Verify app registrations are isolated
		appRegs1, err := GetAppRegistrationsByProviderTenant(providerTenant.ID)
		assert.NoError(t, err)
		assert.Len(t, appRegs1, 1)
		assert.Equal(t, appReg1.ID, appRegs1[0].ID)

		appRegs2, err := GetAppRegistrationsByProviderTenant(otherProviderTenant.ID)
		assert.NoError(t, err)
		assert.Len(t, appRegs2, 1)
		assert.Equal(t, appReg2.ID, appRegs2[0].ID)

		// Clean up
		err = appReg1.Delete()
		assert.NoError(t, err)
		err = appReg2.Delete()
		assert.NoError(t, err)
	})

	t.Run("OAuth2Config", func(t *testing.T) {
		appReg := &AppRegistration{
			ID:               uuid.New(),
			ProviderTenantID: providerTenant.ID,
			UseCase:          "email",
			ClientID:         fmt.Sprintf("test-client-id-%s", uuid.New().String()),
			RedirectURI:      "http://localhost/callback",
		}
		appReg.SetScopes([]string{"https://graph.microsoft.com/Mail.Send"})

		clientSecret := "test-secret"
		secretHash := HashSecret(clientSecret)
		secretEnc, err := Encrypt([]byte(clientSecret))
		assert.NoError(t, err)

		appReg.ClientSecretHash = secretHash
		appReg.ClientSecretEncrypted = secretEnc

		err = appReg.Create()
		assert.NoError(t, err)

		// Get OAuth2 config
		config, err := GetOAuth2Config(appReg.ID)
		assert.NoError(t, err)
		assert.Equal(t, appReg.ClientID, config.ClientID)
		assert.Equal(t, clientSecret, config.ClientSecret)
		assert.Equal(t, appReg.RedirectURI, config.RedirectURL)
		assert.Equal(t, appReg.GetScopes(), config.Scopes)
		assert.NotEmpty(t, config.Endpoint)

		// Clean up
		err = appReg.Delete()
		assert.NoError(t, err)
	})

	t.Run("ValidationTests", func(t *testing.T) {
		// Test empty client ID
		appReg := &AppRegistration{
			ID:               uuid.New(),
			ProviderTenantID: providerTenant.ID,
			UseCase:          "email",
			ClientID:         "", // Empty client ID
			RedirectURI:      "http://localhost/callback",
		}
		err := appReg.Create()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "client ID cannot be empty")

		// Test invalid redirect URI
		appReg = &AppRegistration{
			ID:               uuid.New(),
			ProviderTenantID: providerTenant.ID,
			UseCase:          "email",
			ClientID:         "test-client-id",
			RedirectURI:      "invalid-uri", // Invalid URI
		}
		err = appReg.Create()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid redirect URI")

		// Test duplicate client ID
		appReg1 := &AppRegistration{
			ID:               uuid.New(),
			ProviderTenantID: providerTenant.ID,
			UseCase:          "email",
			ClientID:         "duplicate-id",
			RedirectURI:      "http://localhost/callback1",
		}
		err = appReg1.Create()
		assert.NoError(t, err)

		appReg2 := &AppRegistration{
			ID:               uuid.New(),
			ProviderTenantID: providerTenant.ID,
			UseCase:          "email",
			ClientID:         "duplicate-id", // Same client ID
			RedirectURI:      "http://localhost/callback2",
		}
		err = appReg2.Create()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "client ID already exists")

		// Clean up
		err = appReg1.Delete()
		assert.NoError(t, err)
	})

	t.Run("ErrorHandling", func(t *testing.T) {
		// Test GetAppRegistration with non-existent ID
		nonExistentID := uuid.New()
		_, err := GetAppRegistration(nonExistentID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "app registration not found")

		// Test GetAppRegistrationsByProviderTenant with non-existent provider tenant ID
		nonExistentProviderID := uuid.New()
		appRegs, err := GetAppRegistrationsByProviderTenant(nonExistentProviderID)
		assert.NoError(t, err)
		assert.Empty(t, appRegs)

		// Test decryption failure
		appReg := &AppRegistration{
			ID:               uuid.New(),
			ProviderTenantID: providerTenant.ID,
			UseCase:          "email",
			ClientID:         "test-client-id",
			RedirectURI:      "http://localhost/callback",
			ClientSecretEncrypted: []byte("invalid-encrypted-data"),
		}
		err = appReg.Create()
		assert.NoError(t, err)

		_, err = GetOAuth2Config(appReg.ID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt client secret")

		// Clean up
		err = appReg.Delete()
		assert.NoError(t, err)
	})

	t.Run("UseCaseTests", func(t *testing.T) {
		// Test different use cases
		useCases := []string{"email", "dmarc", "phishing", "reporting"}
		for _, useCase := range useCases {
			appReg := &AppRegistration{
				ID:               uuid.New(),
				ProviderTenantID: providerTenant.ID,
				UseCase:          useCase,
				ClientID:         "test-client-id-" + useCase,
				RedirectURI:      "http://localhost/callback/" + useCase,
			}
			err := appReg.Create()
			assert.NoError(t, err)
			assert.Equal(t, useCase, appReg.UseCase)

			// Clean up
			err = appReg.Delete()
			assert.NoError(t, err)
		}

		// Test region-specific configuration
		regions := []string{"us-east-1", "eu-west-1", "ap-southeast-1"}
		for _, region := range regions {
			appReg := &AppRegistration{
				ID:               uuid.New(),
				ProviderTenantID: providerTenant.ID,
				UseCase:          "email",
				ClientID:         "test-client-id-" + region,
				RedirectURI:      "http://localhost/callback",
				Region:          region,
			}
			err := appReg.Create()
			assert.NoError(t, err)
			assert.Equal(t, region, appReg.Region)

			// Clean up
			err = appReg.Delete()
			assert.NoError(t, err)
		}
	})
} 