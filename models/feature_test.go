package models

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestFeatureManagement(t *testing.T) {
	// Setup
	cleanup := SetupTest(t)
	defer cleanup()

	// Create test tenant and provider tenant
	tenant := &Tenant{
		ID:   uuid.New().String(),
		Name: "Test Tenant",
	}
	err := tenant.Create()
	assert.NoError(t, err)

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
	secretEnc, err := Encrypt([]byte(clientSecret))
	assert.NoError(t, err)

	appReg.ClientSecretEncrypted = string(secretEnc)

	err = appReg.Create()
	assert.NoError(t, err)

	// Clean up any existing features
	err = db.Exec("DELETE FROM features").Error
	assert.NoError(t, err)

	t.Run("EnableFeature", func(t *testing.T) {
		feature := &Feature{
			ID:                uuid.New().String(),
			AppRegistrationID: appReg.ID,
			FeatureType:       FeatureTypeOAuth2,
			Enabled:          true,
			Config: map[string]interface{}{
				"scopes": []string{"https://graph.microsoft.com/Mail.Send"},
			},
		}
		err := feature.Create()
		assert.NoError(t, err)
		assert.NotEmpty(t, feature.CreatedAt)

		// Verify feature was created
		found, err := GetFeature(feature.ID)
		assert.NoError(t, err)
		assert.Equal(t, feature.ID, found.ID)
		assert.Equal(t, feature.FeatureType, found.FeatureType)
		assert.True(t, found.Enabled)

		// Clean up
		err = feature.Delete()
		assert.NoError(t, err)
	})

	t.Run("DisableFeature", func(t *testing.T) {
		feature := &Feature{
			ID:                uuid.New().String(),
			AppRegistrationID: appReg.ID,
			FeatureType:       FeatureTypeEmail,
			Enabled:          true,
		}
		err := feature.Create()
		assert.NoError(t, err)

		// Disable feature
		feature.Enabled = false
		err = feature.Update()
		assert.NoError(t, err)

		// Verify feature was disabled
		found, err := GetFeature(feature.ID)
		assert.NoError(t, err)
		assert.False(t, found.Enabled)

		// Clean up
		err = feature.Delete()
		assert.NoError(t, err)
	})

	t.Run("UpdateFeatureConfig", func(t *testing.T) {
		feature := &Feature{
			ID:                uuid.New().String(),
			AppRegistrationID: appReg.ID,
			FeatureType:       FeatureTypeOAuth2,
			Enabled:          true,
			Config: map[string]interface{}{
				"scopes": []string{"https://graph.microsoft.com/Mail.Send"},
			},
		}
		err := feature.Create()
		assert.NoError(t, err)

		// Update config
		feature.Config["scopes"] = []string{
			"https://graph.microsoft.com/Mail.Send",
			"https://graph.microsoft.com/Mail.Read",
		}
		err = feature.Update()
		assert.NoError(t, err)

		// Verify config was updated
		found, err := GetFeature(feature.ID)
		assert.NoError(t, err)
		assert.Equal(t, feature.Config, found.Config)

		// Clean up
		err = feature.Delete()
		assert.NoError(t, err)
	})

	t.Run("CrossTenantFeatureIsolation", func(t *testing.T) {
		// Clean up any existing features
		err = db.Exec("DELETE FROM features").Error
		assert.NoError(t, err)

		// Create another tenant and app registration
		otherTenant := &Tenant{
			ID:   uuid.New().String(),
			Name: "Other Tenant",
		}
		err := otherTenant.Create()
		assert.NoError(t, err)

		otherProviderTenant := &ProviderTenant{
			ID:               uuid.New().String(),
			TenantID:         otherTenant.ID,
			ProviderType:     ProviderTypeAzure,
			ProviderTenantID: "other-tenant-id",
			DisplayName:      "Other Provider",
		}
		err = otherProviderTenant.Create()
		assert.NoError(t, err)

		otherAppReg := &AppRegistration{
			ID:               uuid.New().String(),
			ProviderTenantID: otherProviderTenant.ID,
			ClientID:         "other-client-id",
			RedirectURI:      "http://localhost/callback",
		}
		err = otherAppReg.Create()
		assert.NoError(t, err)

		// Create features for both app registrations
		feature1 := &Feature{
			ID:                uuid.New().String(),
			AppRegistrationID: appReg.ID,
			FeatureType:       FeatureTypeOAuth2,
			Enabled:          true,
		}
		err = feature1.Create()
		assert.NoError(t, err)

		feature2 := &Feature{
			ID:                uuid.New().String(),
			AppRegistrationID: otherAppReg.ID,
			FeatureType:       FeatureTypeOAuth2,
			Enabled:          true,
		}
		err = feature2.Create()
		assert.NoError(t, err)

		// Verify features are isolated
		features1, err := GetFeaturesByAppRegistration(appReg.ID)
		assert.NoError(t, err)
		assert.Len(t, features1, 1)
		assert.Equal(t, feature1.ID, features1[0].ID)

		features2, err := GetFeaturesByAppRegistration(otherAppReg.ID)
		assert.NoError(t, err)
		assert.Len(t, features2, 1)
		assert.Equal(t, feature2.ID, features2[0].ID)

		// Clean up
		err = feature1.Delete()
		assert.NoError(t, err)
		err = feature2.Delete()
		assert.NoError(t, err)
	})

	t.Run("InvalidFeatureType", func(t *testing.T) {
		feature := &Feature{
			ID:                uuid.New().String(),
			AppRegistrationID: appReg.ID,
			FeatureType:       "invalid",
			Enabled:          true,
		}
		err := feature.Create()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid feature type")
	})

	t.Run("DeleteFeature", func(t *testing.T) {
		feature := &Feature{
			ID:                uuid.New().String(),
			AppRegistrationID: appReg.ID,
			FeatureType:       FeatureTypeOAuth2,
			Enabled:          true,
		}
		err := feature.Create()
		assert.NoError(t, err)

		// Delete feature
		err = feature.Delete()
		assert.NoError(t, err)

		// Verify feature was deleted
		_, err = GetFeature(feature.ID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "feature not found")
	})
}

func TestFeature(t *testing.T) {
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
	secretEnc, err := Encrypt([]byte(clientSecret))
	assert.NoError(t, err)

	appReg.ClientSecretEncrypted = string(secretEnc)

	err = appReg.Create()
	assert.NoError(t, err)

	t.Run("CreateFeature", func(t *testing.T) {
		feature := &Feature{
			ID:                uuid.New().String(),
			AppRegistrationID: appReg.ID,
			FeatureType:       FeatureTypeOAuth2,
			Enabled:          true,
			Config: map[string]interface{}{
				"scopes": []string{"https://graph.microsoft.com/Mail.Send"},
			},
		}

		err := feature.Create()
		assert.NoError(t, err)
		assert.NotEmpty(t, feature.CreatedAt)
		assert.NotEmpty(t, feature.UpdatedAt)

		// Verify feature was created
		var found Feature
		err = db.First(&found, "id = ?", feature.ID).Error
		assert.NoError(t, err)
		assert.Equal(t, feature.ID, found.ID)
		assert.Equal(t, feature.AppRegistrationID, found.AppRegistrationID)
		assert.Equal(t, feature.FeatureType, found.FeatureType)
		assert.Equal(t, feature.Enabled, found.Enabled)

		// Clean up
		err = db.Delete(&feature).Error
		assert.NoError(t, err)
	})

	t.Run("UpdateFeature", func(t *testing.T) {
		feature := &Feature{
			ID:                uuid.New().String(),
			AppRegistrationID: appReg.ID,
			FeatureType:       FeatureTypeOAuth2,
			Enabled:          true,
			Config: map[string]interface{}{
				"scopes": []string{"https://graph.microsoft.com/Mail.Send"},
			},
		}

		err := feature.Create()
		assert.NoError(t, err)

		// Update feature
		feature.Enabled = false
		feature.Config["scopes"] = []string{
			"https://graph.microsoft.com/Mail.Send",
			"https://graph.microsoft.com/Mail.Read",
		}

		err = feature.Update()
		assert.NoError(t, err)

		// Verify updates
		var found Feature
		err = db.First(&found, "id = ?", feature.ID).Error
		assert.NoError(t, err)
		assert.Equal(t, feature.Enabled, found.Enabled)
		assert.Equal(t, feature.Config, found.Config)

		// Clean up
		err = db.Delete(&feature).Error
		assert.NoError(t, err)
	})

	t.Run("DeleteFeature", func(t *testing.T) {
		feature := &Feature{
			ID:                uuid.New().String(),
			AppRegistrationID: appReg.ID,
			FeatureType:       FeatureTypeOAuth2,
			Enabled:          true,
			Config: map[string]interface{}{
				"scopes": []string{"https://graph.microsoft.com/Mail.Send"},
			},
		}

		err := feature.Create()
		assert.NoError(t, err)

		// Delete feature
		err = feature.Delete()
		assert.NoError(t, err)

		// Verify feature was deleted
		_, err = GetFeature(feature.ID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "feature not found")
	})

	// Clean up app registration
	err = appReg.Delete()
	assert.NoError(t, err)
} 