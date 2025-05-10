package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/gophish/gophish/models"
)

func main() {
	var (
		providerType     string
		displayName      string
		providerTenantID string
		region          string
		clientID        string
		clientSecret    string
		redirectURI     string
		useCase         string
	)

	// Define command line flags
	flag.StringVar(&providerType, "provider", "azure", "Provider type (azure)")
	flag.StringVar(&displayName, "name", "", "Display name for the tenant")
	flag.StringVar(&providerTenantID, "provider-tenant-id", "", "Provider tenant ID (e.g., Azure tenant GUID)")
	flag.StringVar(&region, "region", "", "Region for the provider tenant")
	flag.StringVar(&clientID, "client-id", "", "OAuth2 client ID")
	flag.StringVar(&clientSecret, "client-secret", "", "OAuth2 client secret")
	flag.StringVar(&redirectURI, "redirect-uri", "", "OAuth2 redirect URI")
	flag.StringVar(&useCase, "use-case", "oauth2", "Use case (oauth2, email)")

	flag.Parse()

	// Validate required flags
	if displayName == "" || providerTenantID == "" || clientID == "" || clientSecret == "" || redirectURI == "" {
		flag.Usage()
		os.Exit(1)
	}

	ctx := context.Background()

	// Create a new tenant
	tenant, err := models.CreateTenant(ctx, displayName)
	if err != nil {
		log.Fatalf("Failed to create tenant: %v", err)
	}

	// Create a provider tenant
	provTenant, err := models.CreateProviderTenant(ctx, tenant.ID, providerType, providerTenantID, displayName, region)
	if err != nil {
		log.Fatalf("Failed to create provider tenant: %v", err)
	}

	// Create an app registration
	scopes := []string{
		"https://graph.microsoft.com/.default",
		"offline_access",
	}
	if useCase == "email" {
		scopes = append(scopes, "https://outlook.office.com/SMTP.Send")
	}

	appReg, err := models.CreateAppRegistration(ctx, provTenant.ID, useCase, clientID, clientSecret, redirectURI, scopes)
	if err != nil {
		log.Fatalf("Failed to create app registration: %v", err)
	}

	// Enable features based on use case
	config := map[string]interface{}{
		"enabled": true,
	}
	if err := models.EnableFeature(ctx, appReg.ID, useCase, config); err != nil {
		log.Fatalf("Failed to enable feature: %v", err)
	}

	fmt.Printf("Successfully created:\n")
	fmt.Printf("- Tenant: %s (ID: %s)\n", tenant.DisplayName, tenant.ID)
	fmt.Printf("- Provider Tenant: %s (ID: %s)\n", provTenant.DisplayName, provTenant.ID)
	fmt.Printf("- App Registration: %s (ID: %s)\n", appReg.UseCase, appReg.ID)
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("1. Use these IDs to configure your Gophish instance\n")
	fmt.Printf("2. Set up the email-oauth2-proxy if using email features\n")
	fmt.Printf("3. Configure your provider's OAuth2 settings (redirect URIs, permissions)\n")
} 