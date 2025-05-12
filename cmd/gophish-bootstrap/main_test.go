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
		"--feature", "oauth2",
	}

	// Create a test context
	ctx := context.Background()

	// Run the bootstrap process
	tenant, err := models.CreateTenant(ctx, "Test Tenant")
	assert.NoError(t, err)
	assert.NotNil(t, tenant)
	assert.Equal(t, "Test Tenant", tenant.Name)

	// Create provider tenant
	provTenant, err := models.CreateProviderTenant(ctx, tenant.ID, models.ProviderType("azure"), "test-tenant-id", "Test Tenant", "us-east-1")
	assert.NoError(t, err)
	assert.NotNil(t, provTenant)
	assert.Equal(t, "azure", string(provTenant.ProviderType))
	assert.Equal(t, "test-tenant-id", provTenant.ProviderTenantID)

	// Create app registration
	scopes := []string{
		"https://graph.microsoft.com/.default",
		"offline_access",
	}
	appReg, err := models.CreateAppRegistration(ctx, provTenant.ID, "test-client-id", "test-client-secret", "https://test.com/oauth2/callback", scopes)
	assert.NoError(t, err)
	assert.NotNil(t, appReg)
	assert.Equal(t, "test-client-id", appReg.ClientID)

	// Enable feature
	config := map[string]interface{}{
		"enabled": true,
	}
	err = models.EnableFeature(ctx, appReg.ID, models.FeatureType("oauth2"), config)
	assert.NoError(t, err)

	// Verify feature is enabled
	features, err := models.GetFeaturesByAppRegistration(appReg.ID)
	assert.NoError(t, err)
	assert.Len(t, features, 1)
	assert.Equal(t, "oauth2", string(features[0].FeatureType))
	assert.True(t, features[0].Enabled)
}

func TestBootstrapPhishingFlow(t *testing.T) {
	// Set up test environment for phishing feature
	os.Args = []string{
		"gophish-bootstrap",
		"--name", "Test Phishing Tenant",
		"--provider", "azure",
		"--provider-tenant-id", "test-phishing-tenant-id",
		"--region", "us-east-1",
		"--client-id", "test-phishing-client-id",
		"--client-secret", "test-phishing-client-secret",
		"--redirect-uri", "https://test.com/oauth2/callback",
		"--feature", "phishing",
	}

	// Create a test context
	ctx := context.Background()

	// Run the bootstrap process for phishing
	tenant, err := models.CreateTenant(ctx, "Test Phishing Tenant")
	assert.NoError(t, err)
	assert.NotNil(t, tenant)

	// Create provider tenant
	provTenant, err := models.CreateProviderTenant(ctx, tenant.ID, models.ProviderType("azure"), "test-phishing-tenant-id", "Test Phishing Tenant", "us-east-1")
	assert.NoError(t, err)
	assert.NotNil(t, provTenant)

	// Create app registration with phishing scopes
	scopes := []string{
		"https://graph.microsoft.com/.default",
		"offline_access",
		"https://graph.microsoft.com/Mail.Send",
	}
	appReg, err := models.CreateAppRegistration(ctx, provTenant.ID, "test-phishing-client-id", "test-phishing-client-secret", "https://test.com/oauth2/callback", scopes)
	assert.NoError(t, err)
	assert.NotNil(t, appReg)

	// Enable phishing feature
	config := map[string]interface{}{
		"enabled": true,
		"smtp": map[string]interface{}{
			"host": "smtp.office365.com",
			"port": 587,
		},
	}
	err = models.EnableFeature(ctx, appReg.ID, models.FeatureType("phishing"), config)
	assert.NoError(t, err)

	// Verify feature is enabled with correct config
	features, err := models.GetFeaturesByAppRegistration(appReg.ID)
	assert.NoError(t, err)
	assert.Len(t, features, 1)
	assert.Equal(t, "phishing", string(features[0].FeatureType))
	assert.True(t, features[0].Enabled)
	assert.Contains(t, features[0].Config, "smtp")
} 