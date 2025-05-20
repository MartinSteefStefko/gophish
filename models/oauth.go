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

// SaveOAuth2Token saves or updates an OAuth2 token for a user
func SaveOAuth2Token(ctx context.Context, appRegID string, userID int64, token *oauth2.Token) error {
	// Check if the app registration exists
	appReg, err := GetAppRegistration(appRegID)
	if err != nil {
		return fmt.Errorf("failed to get app registration: %v", err)
	}

	// TEMPORARY: Skip encryption and store token directly
	accessTokenBytes, err := json.Marshal(token.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to marshal access token: %v", err)
	}

	refreshTokenBytes, err := json.Marshal(token.RefreshToken)
	if err != nil {
		return fmt.Errorf("failed to marshal refresh token: %v", err)
	}

	// Try to get existing token first
	existingToken, err := GetOAuthTokenByUserAndProviderTenant(userID, appReg.ProviderTenantID)
	if err == nil {
		// Token exists, update it
		existingToken.AccessTokenEncrypted = string(accessTokenBytes)
		existingToken.RefreshTokenEncrypted = string(refreshTokenBytes)
		existingToken.ExpiresAt = token.Expiry
		return existingToken.Update()
	}

	// Token doesn't exist, create new one
	oauthToken := &OAuthToken{
		ID:                   uuid.New().String(),
		ProviderTenantID:    appReg.ProviderTenantID,
		UserID:              userID,
		ProviderType:        "azure",
		AccessTokenEncrypted: string(accessTokenBytes),
		RefreshTokenEncrypted: string(refreshTokenBytes),
		ExpiresAt:           token.Expiry,
		CreatedAt:           time.Now().UTC(),
	}

	if err := db.Create(oauthToken).Error; err != nil {
		return fmt.Errorf("failed to save token: %v", err)
	}

	return nil
}

// GetUserOAuth2Token retrieves the OAuth2 token for a user and app registration
func GetUserOAuth2Token(ctx context.Context, appRegID string, userID int64) (*oauth2.Token, error) {
	// Get the app registration to find its provider tenant
	appReg, err := GetAppRegistration(appRegID)
	if err != nil {
		return nil, fmt.Errorf("failed to get app registration: %v", err)
	}

	// Get the token using provider tenant ID
	token, err := GetOAuthTokenByUserAndProviderTenant(userID, appReg.ProviderTenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get OAuth token: %v", err)
	}

	// TEMPORARY: Skip decryption and use token directly
	var accessToken string
	if err := json.Unmarshal([]byte(token.AccessTokenEncrypted), &accessToken); err != nil {
		return nil, fmt.Errorf("failed to unmarshal access token: %v", err)
	}

	var refreshToken string
	if err := json.Unmarshal([]byte(token.RefreshTokenEncrypted), &refreshToken); err != nil {
		return nil, fmt.Errorf("failed to unmarshal refresh token: %v", err)
	}

	return &oauth2.Token{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		Expiry:      token.ExpiresAt,
	}, nil
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

// GetAndRefreshTokenIfNeeded gets a token for a user and refreshes it if needed
func GetAndRefreshTokenIfNeeded(ctx context.Context, userID int64) (*oauth2.Token, error) {
	// Get the default app registration
	defaultAppReg, err := GetDefaultAppRegistration()
	if err != nil {
		return nil, fmt.Errorf("failed to get default app registration: %v", err)
	}

	// Get the token
	token, err := GetUserOAuth2Token(ctx, defaultAppReg.ID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %v", err)
	}

	// Check if token needs refresh
	if token.Expiry.Before(time.Now()) {
		// Get OAuth2 config
		config, err := GetOAuth2Config(defaultAppReg.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get OAuth2 config: %v", err)
		}

		// Use the refresh token to get a new access token
		tokenSource := config.TokenSource(ctx, token)
		newToken, err := tokenSource.Token()
		if err != nil {
			return nil, fmt.Errorf("failed to refresh token: %v", err)
		}

		// Save the new token
		err = SaveOAuth2Token(ctx, defaultAppReg.ID, userID, newToken)
		if err != nil {
			return nil, fmt.Errorf("failed to save refreshed token: %v", err)
		}

		return newToken, nil
	}

	return token, nil
}

// SaveOAuthTokenDirect saves an OAuth token directly without requiring app registration
func SaveOAuthTokenDirect(token *OAuthToken) error {
	if err := token.Validate(); err != nil {
		return fmt.Errorf("invalid token: %v", err)
	}
	return db.Create(token).Error
}