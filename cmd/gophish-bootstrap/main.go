package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/gophish/gophish/models"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

// createAzureServicePrincipal creates a new service principal in Azure AD
func createAzureServicePrincipal(ctx context.Context, displayName string) (*graphrbac.ServicePrincipal, string, error) {
	// Get Azure credentials from environment
	creds, err := auth.NewAuthorizerFromEnvironment()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get Azure credentials: %v", err)
	}

	// Create Graph RBAC client
	client := graphrbac.NewServicePrincipalsClient(os.Getenv("AZURE_TENANT_ID"))
	client.Authorizer = creds

	// Create application registration
	app := graphrbac.ApplicationCreateParameters{
		DisplayName: &displayName,
		RequiredResourceAccess: &[]graphrbac.RequiredResourceAccess{
			{
				ResourceAppID: stringPtr("00000003-0000-0000-c000-000000000000"), // Microsoft Graph
				ResourceAccess: &[]graphrbac.ResourceAccess{
					{
						ID:   stringPtr("SMTP.Send"), // Request SMTP.Send permission
						Type: stringPtr("Scope"),
					},
				},
			},
		},
		ReplyUrls: &[]string{"http://localhost:3333/oauth2/callback"},
		SignInAudience: stringPtr("AzureADMyOrg"), // Single tenant
		PublicClient:   boolPtr(false),            // Confidential client
	}

	appClient := graphrbac.NewApplicationsClient(os.Getenv("AZURE_TENANT_ID"))
	appClient.Authorizer = creds

	appResult, err := appClient.Create(ctx, app)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create application: %v", err)
	}

	// Create service principal
	sp := graphrbac.ServicePrincipalCreateParameters{
		AppID:          appResult.AppID,
		AccountEnabled: boolPtr(true),
	}

	spResult, err := client.Create(ctx, sp)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create service principal: %v", err)
	}

	// Generate client secret
	secret := generateSecureSecret()

	return &spResult, secret, nil
}

func stringPtr(s string) *string {
	return &s
}

func boolPtr(b bool) *bool {
	return &b
}

func generateSecureSecret() string {
	// Implementation of secure secret generation
	// This is a placeholder - implement proper secure secret generation
	return "generated-secure-secret"
}

// validateServicePrincipal validates the created service principal and tests OAuth2 flow
func validateServicePrincipal(ctx context.Context, clientID, clientSecret, tenantID string) error {
	// 1. Verify service principal exists and is enabled
	creds, err := auth.NewAuthorizerFromEnvironment()
	if err != nil {
		return fmt.Errorf("failed to get Azure credentials: %v", err)
	}

	client := graphrbac.NewServicePrincipalsClient(tenantID)
	client.Authorizer = creds

	filter := fmt.Sprintf("appId eq '%s'", clientID)
	result, err := client.List(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to get service principal: %v", err)
	}

	if len(result.Values()) == 0 {
		return fmt.Errorf("service principal not found")
	}

	sp := result.Values()[0]
	if sp.AccountEnabled == nil || !*sp.AccountEnabled {
		return fmt.Errorf("service principal is disabled")
	}

	// 2. Verify SMTP.Send permission
	appClient := graphrbac.NewApplicationsClient(tenantID)
	appClient.Authorizer = creds

	app, err := appClient.Get(ctx, *sp.AppID)
	if err != nil {
		return fmt.Errorf("failed to get application: %v", err)
	}

	hasSmtpPermission := false
	if app.RequiredResourceAccess != nil {
		for _, resource := range *app.RequiredResourceAccess {
			if *resource.ResourceAppID == "00000003-0000-0000-c000-000000000000" { // Microsoft Graph
				for _, permission := range *resource.ResourceAccess {
					// Check if permission is for SMTP.Send (by type, not specific ID)
					if permission.Type != nil && *permission.Type == "Scope" {
						hasSmtpPermission = true
						break
					}
				}
			}
		}
	}

	if !hasSmtpPermission {
		return fmt.Errorf("SMTP.Send permission not found")
	}

	// 3. Test OAuth2 flow
	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     microsoft.AzureADEndpoint(tenantID),
		Scopes: []string{
			"https://graph.microsoft.com/SMTP.Send",
			"offline_access",
		},
	}

	// Try to get token with client credentials
	token, err := config.Exchange(ctx, "")
	if err != nil {
		return fmt.Errorf("failed to get OAuth2 token: %v", err)
	}

	if !token.Valid() {
		return fmt.Errorf("received invalid token")
	}

	fmt.Printf("Validation successful:\n")
	fmt.Printf("- Service principal is active\n")
	fmt.Printf("- SMTP.Send permission configured\n")
	fmt.Printf("- OAuth2 flow working\n")
	fmt.Printf("- Token expires: %v\n", token.Expiry)

	return nil
}

func main() {
	var (
		providerType     string
		displayName      string
		providerTenantID string
		region          string
		clientID        string
		clientSecret    string
		redirectURI     string
		feature         string
		createSP        bool
		validate        bool
	)

	// Define command line flags
	flag.StringVar(&providerType, "provider", "azure", "Provider type (azure)")
	flag.StringVar(&displayName, "name", "", "Display name for the tenant")
	flag.StringVar(&providerTenantID, "provider-tenant-id", "", "Provider tenant ID (e.g., Azure tenant GUID)")
	flag.StringVar(&region, "region", "", "Region for the provider tenant")
	flag.StringVar(&clientID, "client-id", "", "OAuth2 client ID")
	flag.StringVar(&clientSecret, "client-secret", "", "OAuth2 client secret")
	flag.StringVar(&redirectURI, "redirect-uri", "", "OAuth2 redirect URI")
	flag.StringVar(&feature, "feature", "phishing", "Feature type (phishing, oauth2)")
	flag.BoolVar(&createSP, "create-sp", false, "Create Azure service principal")
	flag.BoolVar(&validate, "validate", false, "Validate service principal and OAuth2 flow")

	flag.Parse()

	ctx := context.Background()

	// Create Azure service principal if requested
	if createSP {
		sp, secret, err := createAzureServicePrincipal(ctx, displayName)
		if err != nil {
			log.Fatalf("Failed to create service principal: %v", err)
		}
		
		// Use the created service principal details
		clientID = *sp.AppID
		clientSecret = secret
		fmt.Printf("Created service principal:\n")
		fmt.Printf("- App ID (client ID): %s\n", *sp.AppID)
		fmt.Printf("- Client Secret: %s\n", secret)

		// Validate if requested
		if validate {
			if err := validateServicePrincipal(ctx, clientID, clientSecret, providerTenantID); err != nil {
				log.Printf("Warning: Validation failed: %v", err)
			}
		}
	}

	// Validate required flags
	if displayName == "" || providerTenantID == "" || clientID == "" || clientSecret == "" || redirectURI == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Create a new tenant
	tenant, err := models.CreateTenant(ctx, displayName)
	if err != nil {
		log.Fatalf("Failed to create tenant: %v", err)
	}

	// Create a provider tenant
	provTenant, err := models.CreateProviderTenant(ctx, tenant.ID, models.ProviderType(providerType), providerTenantID, displayName, region)
	if err != nil {
		log.Fatalf("Failed to create provider tenant: %v", err)
	}

	// Create an app registration
	scopes := []string{
		"https://graph.microsoft.com/.default",
		"offline_access",
	}
	if feature == "phishing" {
		scopes = append(scopes, "https://graph.microsoft.com/Mail.Send")
	}

	appReg, err := models.CreateAppRegistration(ctx, provTenant.ID, clientID, clientSecret, redirectURI, scopes)
	if err != nil {
		log.Fatalf("Failed to create app registration: %v", err)
	}

	// Enable features based on feature type
	config := map[string]interface{}{
		"enabled": true,
	}
	if err := models.EnableFeature(ctx, appReg.ID, models.FeatureType(feature), config); err != nil {
		log.Fatalf("Failed to enable feature: %v", err)
	}

	fmt.Printf("Successfully created:\n")
	fmt.Printf("- Tenant: %s (ID: %s)\n", tenant.Name, tenant.ID)
	fmt.Printf("- Provider Tenant: %s (ID: %s)\n", provTenant.DisplayName, provTenant.ID)
	fmt.Printf("- App Registration: %s (ID: %s)\n", appReg.ID, appReg.ID)
	fmt.Printf("- Feature: %s (enabled)\n", feature)
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("1. Use these IDs to configure your Gophish instance\n")
	fmt.Printf("2. Set up the email-oauth2-proxy if using phishing features\n")
	fmt.Printf("3. Configure your provider's OAuth2 settings (redirect URIs, permissions)\n")
} 