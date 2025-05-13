package models

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

// GetOAuth2Config returns the OAuth2 configuration for a specific app registration
var GetOAuth2Config = func(appRegID string) (*oauth2.Config, error) {
	// If no app registration ID is provided, get the default one
	if appRegID == "" {
		defaultAppReg, err := GetDefaultAppRegistration()
		if err != nil {
			return nil, fmt.Errorf("failed to get default app registration: %v", err)
		}
		appRegID = defaultAppReg.ID
	}

	appReg, err := GetAppRegistration(appRegID)
	if err != nil {
		return nil, fmt.Errorf("app registration not found: %v", err)
	}

	// Get provider tenant info
	providerTenant, err := GetProviderTenant(appReg.ProviderTenantID)
	if err != nil {
		return nil, fmt.Errorf("provider tenant not found: %v", err)
	}

	var endpoint oauth2.Endpoint
	switch providerTenant.ProviderType {
	case ProviderTypeAzure:
		endpoint = microsoft.AzureADEndpoint(providerTenant.ProviderTenantID)
	// Add other providers here as needed
	default:
		return nil, fmt.Errorf("unsupported provider type: %s", providerTenant.ProviderType)
	}

	// TEMPORARY: Skip decryption and use client secret directly
	clientSecret := appReg.ClientSecretEncrypted

	return &oauth2.Config{
		ClientID:     appReg.ClientID,
		ClientSecret: clientSecret,
		RedirectURL:  appReg.RedirectURI,
		Scopes:       appReg.GetScopes(),
		Endpoint:     endpoint,
	}, nil
}

// SaveOAuth2Token saves an OAuth2 token for a user
func SaveOAuth2Token(ctx context.Context, appRegID string, userID int64, token *oauth2.Token) error {
	// Check if the app registration exists
	appReg, err := GetAppRegistration(appRegID)
	if err != nil {
		return fmt.Errorf("failed to get app registration: %v", err)
	}

	// TEMPORARY: Skip encryption and store token directly
	tokenBytes, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %v", err)
	}

	// Save the token
	oauthToken := &OAuthToken{
		ID:               uuid.New().String(),
		AppRegistrationID: appReg.ID,
		UserID:           userID,
		AccessToken:      tokenBytes,
		TokenType:        token.TokenType,
		ExpiresAt:        token.Expiry,
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}

	if token.RefreshToken != "" {
		oauthToken.RefreshToken = []byte(token.RefreshToken)
	}

	if err := db.Create(oauthToken).Error; err != nil {
		return fmt.Errorf("failed to save token: %v", err)
	}

	return nil
}

// GetUserOAuth2Token retrieves the OAuth2 token for a user and app registration
func GetUserOAuth2Token(ctx context.Context, appRegID string, userID int64) (*oauth2.Token, error) {
	token, err := GetOAuthTokenByUserAndApp(userID, appRegID)
	if err != nil {
		return nil, fmt.Errorf("failed to get OAuth token: %v", err)
	}

	// TEMPORARY: Skip decryption and use tokens directly
	var storedToken oauth2.Token
	if err := json.Unmarshal(token.AccessToken, &storedToken); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %v", err)
	}

	storedToken.RefreshToken = string(token.RefreshToken)
	return &storedToken, nil
}

// CreateProviderTenant creates a new provider tenant
func CreateProviderTenant(ctx context.Context, tenantID string, providerType ProviderType, providerTenantID, displayName, region string) (*ProviderTenant, error) {
	provTenant := &ProviderTenant{
		ID:               uuid.New().String(),
		TenantID:         tenantID,
		ProviderType:     providerType,
		ProviderTenantID: providerTenantID,
		DisplayName:      displayName,
		Region:           region,
		CreatedAt:        time.Now().UTC(),
	}

	if err := db.Create(provTenant).Error; err != nil {
		return nil, fmt.Errorf("failed to create provider tenant: %v", err)
	}

	return provTenant, nil
}

// CreateTenant creates a new tenant
func CreateTenant(ctx context.Context, name string) (*Tenant, error) {
	tenant := &Tenant{
		ID:        uuid.New().String(),
		Name:      name,
		CreatedAt: time.Now().UTC(),
	}

	if err := db.Create(tenant).Error; err != nil {
		return nil, fmt.Errorf("failed to create tenant: %v", err)
	}

	return tenant, nil
}