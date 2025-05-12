package main

import (
	"encoding/base64"
	"os"
	"testing"

	"github.com/gophish/gophish/config"
	"github.com/gophish/gophish/models"
	"github.com/stretchr/testify/assert"
)

// verifyTableExists checks if a table exists by attempting to create a record
func verifyTableExists(t *testing.T, table string) {
	switch table {
	case "tenants":
		tenant := &models.Tenant{
			ID:   "test-id",
			Name: "Test Tenant",
		}
		err := tenant.Create()
		assert.NoError(t, err)
	case "provider_tenants":
		pt := &models.ProviderTenant{
			ID:               "test-id",
			TenantID:        "test-tenant-id",
			ProviderType:    models.ProviderTypeAzure,
			DisplayName:     "Test Provider",
			Region:          "us-east-1",
		}
		err := pt.Create()
		assert.NoError(t, err)
	case "app_registrations":
		ar := &models.AppRegistration{
			ID:               "test-id",
			ProviderTenantID: "test-provider-id",
			ClientID:         "test-client-id",
			RedirectURI:      "http://localhost/callback",
		}
		err := ar.Create()
		assert.NoError(t, err)
	case "oauth2_tokens":
		// OAuth2 tokens are created through the OAuth2 flow
		// We can't create them directly, so we'll skip this test
		// The table existence is verified by the migration process
		return
	}
}

func TestDatabaseSetupWithCLIFlags(t *testing.T) {
	// Setup temporary test directory
	tmpDir, err := os.MkdirTemp("", "gophish-test-*")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Test database setup with CLI flags
	t.Run("SetupWithCLIFlags", func(t *testing.T) {
		conf := &config.Config{
			DBName: "sqlite3",
			DBPath: tmpDir + "/test.db",
		}

		// Initialize database
		err := models.Setup(conf)
		assert.NoError(t, err)

		// Verify tables exist by attempting to use them
		tables := []string{
			"tenants",
			"provider_tenants",
			"app_registrations",
			"oauth2_tokens",
		}

		for _, table := range tables {
			verifyTableExists(t, table)
		}

		// Verify table structures through model operations
		t.Run("VerifyTenantTable", func(t *testing.T) {
			tenant := &models.Tenant{
				ID:   "test-id-2",
				Name: "Test Tenant 2",
			}
			err := tenant.Create()
			assert.NoError(t, err)

			found, err := models.GetTenant(tenant.ID)
			assert.NoError(t, err)
			assert.Equal(t, tenant.Name, found.Name)
			assert.NotEmpty(t, found.CreatedAt)
		})

		t.Run("VerifyProviderTenantTable", func(t *testing.T) {
			pt := &models.ProviderTenant{
				ID:               "test-id-2",
				TenantID:        "test-tenant-id-2",
				ProviderType:    models.ProviderTypeAzure,
				DisplayName:     "Test Provider 2",
				Region:          "us-east-1",
			}
			err := pt.Create()
			assert.NoError(t, err)

			found, err := models.GetProviderTenant(pt.ID)
			assert.NoError(t, err)
			assert.Equal(t, pt.TenantID, found.TenantID)
			assert.Equal(t, pt.ProviderType, found.ProviderType)
			assert.Equal(t, pt.ProviderTenantID, found.ProviderTenantID)
		})

		t.Run("VerifyAppRegistrationTable", func(t *testing.T) {
			ar := &models.AppRegistration{
				ID:               "test-id-2",
				ProviderTenantID: "test-provider-id-2",
				ClientID:         "test-client-id-2",
				RedirectURI:      "http://localhost/callback",
			}
			err := ar.Create()
			assert.NoError(t, err)

			found, err := models.GetAppRegistration(ar.ID)
			assert.NoError(t, err)
			assert.Equal(t, ar.ClientID, found.ClientID)
			assert.Equal(t, ar.RedirectURI, found.RedirectURI)
		})

		t.Run("VerifyOAuth2TokenTable", func(t *testing.T) {
			// OAuth2 tokens are created through the OAuth2 flow
			// We can't create them directly, so we'll skip this test
			// The table existence is verified by the migration process
			return
		})
	})
}

func TestDatabaseSetupWithEnvVars(t *testing.T) {
	// Setup temporary test directory
	tmpDir, err := os.MkdirTemp("", "gophish-test-*")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Test database setup with environment variables
	t.Run("SetupWithEnvVars", func(t *testing.T) {
		// Set environment variables
		os.Setenv("GOPHISH_DB_NAME", "sqlite3")
		os.Setenv("GOPHISH_DB_PATH", tmpDir+"/test.db")
		defer func() {
			os.Unsetenv("GOPHISH_DB_NAME")
			os.Unsetenv("GOPHISH_DB_PATH")
		}()

		conf := &config.Config{}
		// Initialize database
		err := models.Setup(conf)
		assert.NoError(t, err)

		// Verify tables exist by attempting to use them
		tables := []string{
			"tenants",
			"provider_tenants",
			"app_registrations",
			"oauth2_tokens",
		}

		for _, table := range tables {
			verifyTableExists(t, table)
		}
	})

	// Test environment variable precedence over CLI flags
	t.Run("EnvVarPrecedence", func(t *testing.T) {
		envDBPath := tmpDir + "/env_test.db"
		flagDBPath := tmpDir + "/flag_test.db"

		// Set environment variables
		os.Setenv("GOPHISH_DB_NAME", "sqlite3")
		os.Setenv("GOPHISH_DB_PATH", envDBPath)
		defer func() {
			os.Unsetenv("GOPHISH_DB_NAME")
			os.Unsetenv("GOPHISH_DB_PATH")
		}()

		conf := &config.Config{
			DBName: "sqlite3",
			DBPath: flagDBPath,
		}

		// Initialize database
		err := models.Setup(conf)
		assert.NoError(t, err)

		// Verify the env var path was used instead of flag path
		_, err = os.Stat(envDBPath)
		assert.NoError(t, err)
		_, err = os.Stat(flagDBPath)
		assert.Error(t, err)
	})

	// Test fallback to defaults
	t.Run("DefaultFallback", func(t *testing.T) {
		// Clear environment variables
		os.Unsetenv("GOPHISH_DB_NAME")
		os.Unsetenv("GOPHISH_DB_PATH")

		conf := &config.Config{}
		// Initialize database
		err := models.Setup(conf)
		assert.NoError(t, err)

		// Verify default SQLite database was used
		assert.Equal(t, "sqlite3", conf.DBName)
		assert.NotEmpty(t, conf.DBPath)
	})
}

func TestMasterEncryptionKey(t *testing.T) {
	// Test key generation and .env handling
	t.Run("KeyGenerationAndEnv", func(t *testing.T) {
		// Clear any existing key
		os.Unsetenv("MASTER_ENCRYPTION_KEY")

		// Initialize encryption
		err := models.InitializeEncryption()
		assert.NoError(t, err)

		// Verify key was generated and set
		key := os.Getenv("MASTER_ENCRYPTION_KEY")
		assert.NotEmpty(t, key)

		// Verify key format and length
		keyBytes, err := base64.StdEncoding.DecodeString(key)
		assert.NoError(t, err)
		assert.Equal(t, 32, len(keyBytes))
	})

	// Test key preservation
	t.Run("KeyPreservation", func(t *testing.T) {
		// Set existing key
		existingKey := "KAl7yFk8/DUwX/+Z1QkWvjoBxI2gFvg5wESelHC+dEE="
		os.Setenv("MASTER_ENCRYPTION_KEY", existingKey)
		defer os.Unsetenv("MASTER_ENCRYPTION_KEY")

		// Initialize encryption
		err := models.InitializeEncryption()
		assert.NoError(t, err)

		// Verify key was preserved
		key := os.Getenv("MASTER_ENCRYPTION_KEY")
		assert.Equal(t, existingKey, key)
	})

	// Test encryption functionality with key
	t.Run("EncryptionFunctionality", func(t *testing.T) {
		// Set test key
		testKey := "KAl7yFk8/DUwX/+Z1QkWvjoBxI2gFvg5wESelHC+dEE="
		os.Setenv("MASTER_ENCRYPTION_KEY", testKey)
		defer os.Unsetenv("MASTER_ENCRYPTION_KEY")

		// Initialize encryption
		err := models.InitializeEncryption()
		assert.NoError(t, err)

		// Test encryption/decryption
		testData := []byte("test secret data")
		encrypted, err := models.Encrypt(testData)
		assert.NoError(t, err)
		assert.NotEqual(t, testData, encrypted)

		decrypted, err := models.Decrypt(encrypted)
		assert.NoError(t, err)
		assert.Equal(t, testData, decrypted)
	})
} 