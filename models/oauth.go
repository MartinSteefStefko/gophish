package models

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

// GetAppRegistration retrieves an app registration by ID
func GetAppRegistration(id uuid.UUID) (*AppRegistration, error) {
	var appReg AppRegistration
	if err := db.First(&appReg, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("app registration not found: %v", err)
	}
	return &appReg, nil
}

// GetOAuth2Config returns the OAuth2 configuration for a specific app registration
var GetOAuth2Config = func(appRegID uuid.UUID) (*oauth2.Config, error) {
	var appReg AppRegistration
	if err := db.First(&appReg, "id = ?", appRegID).Error; err != nil {
		return nil, fmt.Errorf("app registration not found: %v", err)
	}

	// Decrypt client secret
	clientSecret, err := Decrypt(appReg.ClientSecretEncrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt client secret: %v", err)
	}

	// Get provider tenant info
	var providerTenant ProviderTenant
	if err := db.First(&providerTenant, "id = ?", appReg.ProviderTenantID).Error; err != nil {
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

	return &oauth2.Config{
		ClientID:     appReg.ClientID,
		ClientSecret: string(clientSecret),
		RedirectURL:  appReg.RedirectURI,
		Scopes:       appReg.GetScopes(),
		Endpoint:     endpoint,
	}, nil
}

// OAuth2Token represents the OAuth2 token in the database
type OAuth2Token struct {
	Id            int64     `json:"id" gorm:"column:id; primary_key:yes"`
	UserId        int64     `json:"-" gorm:"column:user_id"`
	AccessToken   string    `json:"access_token"`
	RefreshToken  string    `json:"refresh_token"`
	TokenType     string    `json:"token_type"`
	ExpiresAt     time.Time `json:"expires_at"`
	ModifiedDate  time.Time `json:"modified_date"`
}

// TableName specifies the database table name for OAuth2Token
func (t OAuth2Token) TableName() string {
	return "oauth2_tokens"
}

// SaveOAuth2Token saves or updates the OAuth2 token for a user and app registration
func SaveOAuth2Token(ctx context.Context, appRegID uuid.UUID, userID int64, token *oauth2.Token) error {
	// Encrypt tokens
	accessTokenEnc, err := Encrypt([]byte(token.AccessToken))
	if err != nil {
		return fmt.Errorf("failed to encrypt access token: %v", err)
	}

	var refreshTokenEnc []byte
	if token.RefreshToken != "" {
		refreshTokenEnc, err = Encrypt([]byte(token.RefreshToken))
		if err != nil {
			return fmt.Errorf("failed to encrypt refresh token: %v", err)
		}
	}

	oauthToken := &OAuthToken{
		AppRegistrationID: appRegID,
		UserID:           userID,
		AccessToken:      accessTokenEnc,
		RefreshToken:     refreshTokenEnc,
		TokenType:        token.TokenType,
		ExpiresAt:        token.Expiry,
		UpdatedAt:        time.Now().UTC(),
	}

	// Check if token exists
	var existing OAuthToken
	if err := db.Where("app_registration_id = ? AND user_id = ?", appRegID, userID).First(&existing).Error; err == nil {
		oauthToken.ID = existing.ID
		oauthToken.CreatedAt = existing.CreatedAt
	} else {
		oauthToken.ID = uuid.New()
		oauthToken.CreatedAt = time.Now().UTC()
	}

	return db.Save(oauthToken).Error
}

// GetUserOAuth2Token retrieves the OAuth2 token for a user and app registration
func GetUserOAuth2Token(ctx context.Context, appRegID uuid.UUID, userID int64) (*oauth2.Token, error) {
	var token OAuthToken
	if err := db.Where("app_registration_id = ? AND user_id = ?", appRegID, userID).First(&token).Error; err != nil {
		return nil, err
	}

	// Decrypt tokens
	accessToken, err := Decrypt(token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt access token: %v", err)
	}

	var refreshToken []byte
	if len(token.RefreshToken) > 0 {
		refreshToken, err = Decrypt(token.RefreshToken)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt refresh token: %v", err)
		}
	}

	return &oauth2.Token{
		AccessToken:  string(accessToken),
		RefreshToken: string(refreshToken),
		TokenType:    token.TokenType,
		Expiry:      token.ExpiresAt,
	}, nil
}

// CreateAppRegistration creates a new app registration with encrypted client secret
func CreateAppRegistration(ctx context.Context, providerTenantID uuid.UUID, useCase, clientID, clientSecret, redirectURI string, scopes []string) (*AppRegistration, error) {
	// Hash the client secret for verification
	secretHash := HashSecret(clientSecret)

	// Encrypt the client secret for use
	secretEnc, err := Encrypt([]byte(clientSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt client secret: %v", err)
	}

	appReg := &AppRegistration{
		ID:                 uuid.New(),
		ProviderTenantID:   providerTenantID,
		UseCase:            useCase,
		ClientID:           clientID,
		ClientSecretHash:   secretHash,
		ClientSecretEncrypted: secretEnc,
		RedirectURI:        redirectURI,
		CreatedAt:          time.Now().UTC(),
		UpdatedAt:          time.Now().UTC(),
	}
	appReg.SetScopes(scopes)

	if err := db.Create(appReg).Error; err != nil {
		return nil, fmt.Errorf("failed to create app registration: %v", err)
	}

	return appReg, nil
}

// CreateProviderTenant creates a new provider tenant
func CreateProviderTenant(ctx context.Context, tenantID uuid.UUID, providerType ProviderType, providerTenantID, displayName, region string) (*ProviderTenant, error) {
	provTenant := &ProviderTenant{
		ID:               uuid.New(),
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
		ID:        uuid.New(),
		Name:      name,
		CreatedAt: time.Now().UTC(),
	}

	if err := db.Create(tenant).Error; err != nil {
		return nil, fmt.Errorf("failed to create tenant: %v", err)
	}

	return tenant, nil
}

// EnableFeature enables a feature for an app registration
func EnableFeature(ctx context.Context, appRegID uuid.UUID, featureType FeatureType, config map[string]interface{}) error {
	feature := &Feature{
		ID:               uuid.New(),
		AppRegistrationID: appRegID,
		FeatureType:      featureType,
		Enabled:          true,
		Config:           config,
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}

	return db.Create(feature).Error
} 