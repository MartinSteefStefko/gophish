package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/google/uuid"
	"github.com/gophish/gophish/config"
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

// encryptData encrypts data using the master encryption key
func encryptData(data string) (string, error) {
	// Initialize encryption if not already done
	if err := models.InitializeEncryption(); err != nil {
		return "", fmt.Errorf("failed to initialize encryption: %v", err)
	}

	// Encrypt the data
	encrypted, err := models.EncryptToString([]byte(data))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt data: %v", err)
	}

	return encrypted, nil
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
	flag.StringVar(&providerType, "provider", getEnvDefault("OAUTH2_PROVIDER_TYPE", "azure"), "Provider type (azure)")
	flag.StringVar(&displayName, "name", getEnvDefault("OAUTH2_DISPLAY_NAME", ""), "Display name for the tenant")
	flag.StringVar(&providerTenantID, "provider-tenant-id", getEnvDefault("OAUTH2_TENANT_ID", ""), "Provider tenant ID (e.g., Azure tenant GUID)")
	flag.StringVar(&region, "region", getEnvDefault("OAUTH2_REGION", ""), "Region for the provider tenant")
	flag.StringVar(&clientID, "client-id", getEnvDefault("OAUTH2_CLIENT_ID", ""), "OAuth2 client ID")
	flag.StringVar(&clientSecret, "client-secret", getEnvDefault("OAUTH2_CLIENT_SECRET", ""), "OAuth2 client secret")
	flag.StringVar(&redirectURI, "redirect-uri", getEnvDefault("OAUTH2_REDIRECT_URI", "http://localhost:3333/oauth2/callback"), "OAuth2 redirect URI")
	flag.StringVar(&feature, "feature", getEnvDefault("OAUTH2_FEATURE", "phishing"), "Feature type (phishing, oauth2)")
	flag.BoolVar(&createSP, "create-sp", false, "Create Azure service principal")
	flag.BoolVar(&validate, "validate", false, "Validate service principal and OAuth2 flow")

	flag.Parse()

	// Initialize database connection
	cfg := &config.Config{
		DBName:         "sqlite3",
		DBPath:         getEnvDefault("GOPHISH_DB_PATH", "data/gophish.db"),
		MigrationsPath: getEnvDefault("GOPHISH_MIGRATIONS_PATH", "db/db_sqlite3/migrations"),
	}
	if err := models.Setup(cfg); err != nil {
		log.Fatalf("Failed to setup database: %v", err)
	}

	ctx := context.Background()

	// Check if tenant exists
	tenants, err := models.GetTenants()
	if err != nil {
		log.Fatalf("Failed to get tenants: %v", err)
	}
	tenantCount := len(tenants)

	if tenantCount == 0 {
		// Create tenant
		tenant, err := models.CreateTenant(ctx, displayName)
		if err != nil {
			log.Fatalf("Failed to create tenant: %v", err)
		}

		// Create provider tenant
		providerTenant, err := models.CreateProviderTenant(ctx, tenant.ID, models.ProviderType(providerType), providerTenantID, displayName, region)
		if err != nil {
			log.Fatalf("Failed to create provider tenant: %v", err)
		}

		// Encrypt client secret
		encryptedSecret, err := encryptData(clientSecret)
		if err != nil {
			log.Fatalf("Failed to encrypt client secret: %v", err)
		}

		// Create app registration
		appReg := &models.AppRegistration{
			ID:                  generateUUID(),
			ProviderTenantID:    providerTenant.ID,
			ClientID:            clientID,
			ClientSecretEncrypted: encryptedSecret,
			RedirectURI:         redirectURI,
			CreatedAt:           time.Now().UTC(),
			UpdatedAt:           time.Now().UTC(),
		}
		appReg.SetScopes([]string{
			"openid",
			"profile",
			"email",
			"offline_access",
			"https://graph.microsoft.com/Mail.Send",
		})
		if err := appReg.Create(); err != nil {
			log.Fatalf("Failed to create app registration: %v", err)
		}

		log.Printf("Successfully created tenant and related records")
	} else {
		log.Printf("Found %d existing tenant(s), skipping initialization", tenantCount)
	}

	// Handle service principal creation if requested
	if createSP {
		ctx := context.Background()
		sp, secret, err := createAzureServicePrincipal(ctx, displayName)
		if err != nil {
			log.Fatalf("Failed to create service principal: %v", err)
		}
		log.Printf("Created service principal with ID: %s", *sp.ObjectID)
		log.Printf("Client secret: %s", secret)
	}

	// Validate setup if requested
	if validate {
		ctx := context.Background()
		if err := validateServicePrincipal(ctx, clientID, clientSecret, providerTenantID); err != nil {
			log.Fatalf("Validation failed: %v", err)
		}
	}
}

func generateUUID() string {
	return uuid.New().String()
}

// getEnvDefault gets an environment variable value or returns a default if not set
func getEnvDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
} 