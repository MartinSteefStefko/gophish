package models

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestFeatureManagement(t *testing.T) {
	// Setup
	cleanup := setupTest(t)
	defer cleanup()

	// Create test tenant and provider tenant
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
		DisplayName:      "Test Provider",
	}
	err = providerTenant.Create()
	assert.NoError(t, err)

	// Create test app registration
	appReg := &AppRegistration{
		ID:               uuid.New(),
		ProviderTenantID: providerTenant.ID,
		UseCase:          "email",
		ClientID:         "test-client-id",
		RedirectURI:      "http://localhost/callback",
	}
	err = appReg.Create()
	assert.NoError(t, err)

	// Clean up any existing features
	err = db.Exec("DELETE FROM features").Error
	assert.NoError(t, err)

	t.Run("EnableFeature", func(t *testing.T) {
		feature := &Feature{
			ID:               uuid.New(),
			AppRegistrationID: appReg.ID,
			FeatureType:      FeatureTypeOAuth2,
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
			ID:               uuid.New(),
			AppRegistrationID: appReg.ID,
			FeatureType:      FeatureTypeEmail,
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
			ID:               uuid.New(),
			AppRegistrationID: appReg.ID,
			FeatureType:      FeatureTypeOAuth2,
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
			ID:   uuid.New(),
			Name: "Other Tenant",
		}
		err := otherTenant.Create()
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

		otherAppReg := &AppRegistration{
			ID:               uuid.New(),
			ProviderTenantID: otherProviderTenant.ID,
			UseCase:          "email",
			ClientID:         "other-client-id",
			RedirectURI:      "http://localhost/callback",
		}
		err = otherAppReg.Create()
		assert.NoError(t, err)

		// Create features for both app registrations
		feature1 := &Feature{
			ID:               uuid.New(),
			AppRegistrationID: appReg.ID,
			FeatureType:      FeatureTypeOAuth2,
			Enabled:          true,
		}
		err = feature1.Create()
		assert.NoError(t, err)

		feature2 := &Feature{
			ID:               uuid.New(),
			AppRegistrationID: otherAppReg.ID,
			FeatureType:      FeatureTypeOAuth2,
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
			ID:               uuid.New(),
			AppRegistrationID: appReg.ID,
			FeatureType:      "invalid",
			Enabled:          true,
		}
		err := feature.Create()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid feature type")
	})

	t.Run("DeleteFeature", func(t *testing.T) {
		feature := &Feature{
			ID:               uuid.New(),
			AppRegistrationID: appReg.ID,
			FeatureType:      FeatureTypeOAuth2,
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