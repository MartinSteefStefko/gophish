package main

import (
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gophish/gophish/config"
	"github.com/gophish/gophish/models"
	"github.com/stretchr/testify/assert"
)

func TestCompleteSetupFlowWithCLIFlags(t *testing.T) {
	// Setup temporary test directory
	tmpDir, err := os.MkdirTemp("", "gophish-test-*")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Test complete setup flow with CLI flags
	t.Run("CompleteSetupWithFlags", func(t *testing.T) {
		// 1. Initialize database with CLI flags
		conf := &config.Config{
			DBName: "sqlite3",
			DBPath: tmpDir + "/test.db",
		}
		err := models.Setup(conf)
		assert.NoError(t, err)

		// 2. Initialize encryption
		err = models.InitializeEncryption()
		assert.NoError(t, err)

		// 3. Create tenant
		tenant := &models.Tenant{
			ID:   uuid.New().String(),
			Name: "Integration Test Tenant",
		}
		err = tenant.Create()
		assert.NoError(t, err)

		// 4. Create provider tenant
		providerTenant := &models.ProviderTenant{
			ID:               uuid.New().String(),
			TenantID:         tenant.ID,
			ProviderType:     models.ProviderTypeAzure,
			ProviderTenantID: "test-tenant-id",
			DisplayName:      "Test Provider",
			Region:           "us-east-1",
			CreatedAt:        time.Now().UTC(),
		}
		err = providerTenant.Create()
		assert.NoError(t, err)

		// 5. Create app registration
		appReg := &models.AppRegistration{
			ID:               uuid.New().String(),
			ProviderTenantID: providerTenant.ID,
			ClientID:         "test-client-id",
			RedirectURI:      "http://localhost/callback",
			CreatedAt:        time.Now().UTC(),
			UpdatedAt:        time.Now().UTC(),
		}
		appReg.SetScopes([]string{"https://graph.microsoft.com/Mail.Send"})

		clientSecret := "test-secret"
		secretEnc, err := models.Encrypt([]byte(clientSecret))
		assert.NoError(t, err)

		appReg.ClientSecretEncrypted = string(secretEnc)

		err = appReg.Create()
		assert.NoError(t, err)

		// 6. Create OAuth2 feature
		feature := &models.Feature{
			ID:                uuid.New().String(),
			AppRegistrationID: appReg.ID,
			FeatureType:       models.FeatureTypeOAuth2,
			Enabled:          true,
			Config: map[string]interface{}{
				"scopes": []string{"https://graph.microsoft.com/Mail.Send"},
			},
		}
		err = feature.Create()
		assert.NoError(t, err)

		// 7. Verify complete setup
		// Check tenant
		foundTenant, err := models.GetTenant(tenant.ID)
		assert.NoError(t, err)
		assert.Equal(t, tenant.Name, foundTenant.Name)

		// Check provider tenant
		foundProvider, err := models.GetProviderTenant(providerTenant.ID)
		assert.NoError(t, err)
		assert.Equal(t, providerTenant.ProviderType, foundProvider.ProviderType)
		assert.Equal(t, providerTenant.ProviderTenantID, foundProvider.ProviderTenantID)

		// Check app registration
		foundApp, err := models.GetAppRegistration(appReg.ID)
		assert.NoError(t, err)
		assert.Equal(t, appReg.ClientID, foundApp.ClientID)
		assert.Equal(t, appReg.RedirectURI, foundApp.RedirectURI)

		// Check feature
		foundFeature, err := models.GetFeature(feature.ID)
		assert.NoError(t, err)
		assert.Equal(t, feature.FeatureType, foundFeature.FeatureType)
		assert.Equal(t, feature.Enabled, foundFeature.Enabled)

		// Verify encryption still works
		decryptedSecret, err := models.Decrypt([]byte(foundApp.ClientSecretEncrypted))
		assert.NoError(t, err)
		assert.Equal(t, clientSecret, string(decryptedSecret))
	})
}

func TestCompleteSetupFlowWithEnvVars(t *testing.T) {
	// Setup temporary test directory
	tmpDir, err := os.MkdirTemp("", "gophish-test-*")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Test complete setup flow with environment variables
	t.Run("CompleteSetupWithEnvVars", func(t *testing.T) {
		// Set environment variables
		os.Setenv("GOPHISH_DB_NAME", "sqlite3")
		os.Setenv("GOPHISH_DB_PATH", tmpDir+"/test.db")
		os.Setenv("MASTER_ENCRYPTION_KEY", "KAl7yFk8/DUwX/+Z1QkWvjoBxI2gFvg5wESelHC+dEE=")
		defer func() {
			os.Unsetenv("GOPHISH_DB_NAME")
			os.Unsetenv("GOPHISH_DB_PATH")
			os.Unsetenv("MASTER_ENCRYPTION_KEY")
		}()

		// 1. Initialize database
		conf := &config.Config{}
		err := models.Setup(conf)
		assert.NoError(t, err)

		// 2. Initialize encryption
		err = models.InitializeEncryption()
		assert.NoError(t, err)

		// 3. Create tenant
		tenant := &models.Tenant{
			ID:   uuid.New().String(),
			Name: "Integration Test Tenant",
		}
		err = tenant.Create()
		assert.NoError(t, err)

		// 4. Create provider tenant
		providerTenant := &models.ProviderTenant{
			ID:               uuid.New().String(),
			TenantID:         tenant.ID,
			ProviderType:     models.ProviderTypeAzure,
			ProviderTenantID: "test-tenant-id",
			DisplayName:      "Test Provider",
			Region:           "us-east-1",
			CreatedAt:        time.Now().UTC(),
		}
		err = providerTenant.Create()
		assert.NoError(t, err)

		// 5. Create app registration
		appReg := &models.AppRegistration{
			ID:               uuid.New().String(),
			ProviderTenantID: providerTenant.ID,
			ClientID:         "test-client-id",
			RedirectURI:      "http://localhost/callback",
			CreatedAt:        time.Now().UTC(),
			UpdatedAt:        time.Now().UTC(),
		}
		appReg.SetScopes([]string{"https://graph.microsoft.com/Mail.Send"})

		clientSecret := "test-secret"
		secretEnc, err := models.Encrypt([]byte(clientSecret))
		assert.NoError(t, err)

		appReg.ClientSecretEncrypted = string(secretEnc)

		err = appReg.Create()
		assert.NoError(t, err)

		// 6. Create OAuth2 feature
		feature := &models.Feature{
			ID:                uuid.New().String(),
			AppRegistrationID: appReg.ID,
			FeatureType:       models.FeatureTypeOAuth2,
			Enabled:          true,
			Config: map[string]interface{}{
				"scopes": []string{"https://graph.microsoft.com/Mail.Send"},
			},
		}
		err = feature.Create()
		assert.NoError(t, err)

		// 7. Verify complete setup
		// Check tenant
		foundTenant, err := models.GetTenant(tenant.ID)
		assert.NoError(t, err)
		assert.Equal(t, tenant.Name, foundTenant.Name)

		// Check provider tenant
		foundProvider, err := models.GetProviderTenant(providerTenant.ID)
		assert.NoError(t, err)
		assert.Equal(t, providerTenant.ProviderType, foundProvider.ProviderType)
		assert.Equal(t, providerTenant.ProviderTenantID, foundProvider.ProviderTenantID)

		// Check app registration
		foundApp, err := models.GetAppRegistration(appReg.ID)
		assert.NoError(t, err)
		assert.Equal(t, appReg.ClientID, foundApp.ClientID)
		assert.Equal(t, appReg.RedirectURI, foundApp.RedirectURI)

		// Check feature
		foundFeature, err := models.GetFeature(feature.ID)
		assert.NoError(t, err)
		assert.Equal(t, feature.FeatureType, foundFeature.FeatureType)
		assert.Equal(t, feature.Enabled, foundFeature.Enabled)

		// Verify encryption still works
		decryptedSecret, err := models.Decrypt([]byte(foundApp.ClientSecretEncrypted))
		assert.NoError(t, err)
		assert.Equal(t, clientSecret, string(decryptedSecret))
	})
}

func TestMixedSetupFlow(t *testing.T) {
	// Setup temporary test directory
	tmpDir, err := os.MkdirTemp("", "gophish-test-*")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Test setup with mixed configuration (some flags, some env vars)
	t.Run("MixedSetup", func(t *testing.T) {
		// Set some settings via environment variables
		os.Setenv("GOPHISH_DB_NAME", "sqlite3")
		os.Setenv("MASTER_ENCRYPTION_KEY", "KAl7yFk8/DUwX/+Z1QkWvjoBxI2gFvg5wESelHC+dEE=")
		defer func() {
			os.Unsetenv("GOPHISH_DB_NAME")
			os.Unsetenv("MASTER_ENCRYPTION_KEY")
		}()

		// Set some settings via config
		conf := &config.Config{
			DBPath: tmpDir + "/test.db",
		}

		// Initialize and verify setup works with mixed configuration
		err := models.Setup(conf)
		assert.NoError(t, err)

		err = models.InitializeEncryption()
		assert.NoError(t, err)

		// Create a test tenant to verify database is working
		tenant := &models.Tenant{
			ID:   uuid.New().String(),
			Name: "Test Tenant",
		}
		err = tenant.Create()
		assert.NoError(t, err)

		// Verify encryption works
		testData := []byte("test data")
		encrypted, err := models.Encrypt(testData)
		assert.NoError(t, err)

		decrypted, err := models.Decrypt(encrypted)
		assert.NoError(t, err)
		assert.Equal(t, testData, decrypted)
	})
}

func TestErrorCases(t *testing.T) {
	t.Run("InvalidDatabasePath", func(t *testing.T) {
		conf := &config.Config{
			DBName: "sqlite3",
			DBPath: "/nonexistent/path/db.sqlite",
		}
		err := models.Setup(conf)
		assert.Error(t, err)
	})

	t.Run("InvalidEncryptionKey", func(t *testing.T) {
		os.Setenv("MASTER_ENCRYPTION_KEY", "invalid-key")
		defer os.Unsetenv("MASTER_ENCRYPTION_KEY")

		err := models.InitializeEncryption()
		assert.Error(t, err)
	})

	t.Run("MissingRequiredFields", func(t *testing.T) {
		// Initialize database first
		tmpDir, err := os.MkdirTemp("", "gophish-test-*")
		assert.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		conf := &config.Config{
			DBName: "sqlite3",
			DBPath: tmpDir + "/test.db",
		}
		err = models.Setup(conf)
		assert.NoError(t, err)

		tenant := &models.Tenant{
			ID: uuid.New().String(),
			// Missing Name field
		}
		err = tenant.Create()
		assert.Error(t, err)
	})

	t.Run("DuplicateRecords", func(t *testing.T) {
		// Initialize database first
		tmpDir, err := os.MkdirTemp("", "gophish-test-*")
		assert.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		conf := &config.Config{
			DBName: "sqlite3",
			DBPath: tmpDir + "/test.db",
		}
		err = models.Setup(conf)
		assert.NoError(t, err)

		// Try to create duplicate tenant
		tenant := &models.Tenant{
			ID:   uuid.New().String(),
			Name: "Test Tenant",
		}
		err = tenant.Create()
		assert.NoError(t, err)

		// Try to create tenant with same ID
		duplicateTenant := &models.Tenant{
			ID:   tenant.ID,
			Name: "Another Tenant",
		}
		err = duplicateTenant.Create()
		assert.Error(t, err)
	})
} 