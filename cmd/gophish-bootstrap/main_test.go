package main

import (
	"context"
	"os"
	"testing"

	"github.com/gophish/gophish/models"
	"github.com/stretchr/testify/assert"
)

func TestBootstrapFlow(t *testing.T) {
	// Set up test environment
	os.Args = []string{
		"gophish-bootstrap",
		"--name", "Test Tenant",
		"--provider", "azure",
		"--provider-tenant-id", "test-tenant-id",
		"--region", "us-east-1",
		"--client-id", "test-client-id",
		"--client-secret", "test-client-secret",
		"--redirect-uri", "https://test.com/oauth2/callback",
		"--use-case", "oauth2",
	}

	// Create a test context
	ctx := context.Background()

	// Run the bootstrap process
	tenant, err := models.CreateTenant(ctx, "Test Tenant")
	assert.NoError(t, err)
	assert.NotNil(t, tenant)
	assert.Equal(t, "Test Tenant", tenant.DisplayName)

	// Create provider tenant
	provTenant, err := models.CreateProviderTenant(ctx, tenant.ID, "azure", "test-tenant-id", "Test Tenant", "us-east-1")
	assert.NoError(t, err)
	assert.NotNil(t, provTenant)
	assert.Equal(t, "azure", provTenant.ProviderType)
	assert.Equal(t, "test-tenant-id", provTenant.ProviderTenantID)

	// Create app registration
	scopes := []string{
		"https://graph.microsoft.com/.default",
		"offline_access",
	}
	appReg, err := models.CreateAppRegistration(ctx, provTenant.ID, "oauth2", "test-client-id", "test-client-secret", "https://test.com/oauth2/callback", scopes)
	assert.NoError(t, err)
	assert.NotNil(t, appReg)
	assert.Equal(t, "oauth2", appReg.UseCase)
	assert.Equal(t, "test-client-id", appReg.ClientID)

	// Enable feature
	config := map[string]interface{}{
		"enabled": true,
	}
	err = models.EnableFeature(ctx, appReg.ID, "oauth2", config)
	assert.NoError(t, err)

	// Verify feature is enabled
	var feature models.Feature
	err = models.db.Where("app_registration_id = ? AND feature_type = ?", appReg.ID, "oauth2").First(&feature).Error
	assert.NoError(t, err)
	assert.True(t, feature.Enabled)
}

func TestBootstrapEmailFlow(t *testing.T) {
	// Set up test environment for email use case
	os.Args = []string{
		"gophish-bootstrap",
		"--name", "Test Email Tenant",
		"--provider", "azure",
		"--provider-tenant-id", "test-email-tenant-id",
		"--region", "us-east-1",
		"--client-id", "test-email-client-id",
		"--client-secret", "test-email-client-secret",
		"--redirect-uri", "https://test.com/oauth2/callback",
		"--use-case", "email",
	}

	// Create a test context
	ctx := context.Background()

	// Run the bootstrap process for email
	tenant, err := models.CreateTenant(ctx, "Test Email Tenant")
	assert.NoError(t, err)
	assert.NotNil(t, tenant)

	// Create provider tenant
	provTenant, err := models.CreateProviderTenant(ctx, tenant.ID, "azure", "test-email-tenant-id", "Test Email Tenant", "us-east-1")
	assert.NoError(t, err)
	assert.NotNil(t, provTenant)

	// Create app registration with email scopes
	scopes := []string{
		"https://graph.microsoft.com/.default",
		"offline_access",
		"https://outlook.office.com/SMTP.Send",
	}
	appReg, err := models.CreateAppRegistration(ctx, provTenant.ID, "email", "test-email-client-id", "test-email-client-secret", "https://test.com/oauth2/callback", scopes)
	assert.NoError(t, err)
	assert.NotNil(t, appReg)
	assert.Equal(t, "email", appReg.UseCase)

	// Enable email feature
	config := map[string]interface{}{
		"enabled": true,
		"smtp": map[string]interface{}{
			"host": "smtp.office365.com",
			"port": 587,
		},
	}
	err = models.EnableFeature(ctx, appReg.ID, "email", config)
	assert.NoError(t, err)

	// Verify feature is enabled with correct config
	var feature models.Feature
	err = models.db.Where("app_registration_id = ? AND feature_type = ?", appReg.ID, "email").First(&feature).Error
	assert.NoError(t, err)
	assert.True(t, feature.Enabled)
	assert.Contains(t, feature.Config, "smtp")
} 