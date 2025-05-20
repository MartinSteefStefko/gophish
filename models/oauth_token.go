package models

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// OAuthToken represents an OAuth token for a specific provider tenant
type OAuthToken struct {
	ID                    string    `gorm:"type:text;primary_key"`
	UserID               int64     `gorm:"index:idx_user_provider,unique:user_provider"` // Unique constraint with provider_tenant_id
	ProviderTenantID     string    `gorm:"type:text;index:idx_user_provider,unique:user_provider"` // Unique constraint with user_id
	ProviderType         string    `gorm:"type:text"`
	AccessTokenEncrypted string    `gorm:"type:text"`
	RefreshTokenEncrypted string   `gorm:"type:text"`
	ExpiresAt            time.Time `gorm:"type:timestamp"`
	CreatedAt            time.Time `gorm:"type:timestamp;default:CURRENT_TIMESTAMP"`
}

// TableName specifies the table name for the OAuthToken model
func (OAuthToken) TableName() string {
	return "oauth_tokens"
}

// BeforeCreate will set a UUID rather than numeric ID.
func (t *OAuthToken) BeforeCreate() error {
	if t.ID == "" {
		t.ID = uuid.New().String()
	}
	return nil
}

// Validate checks if the OAuth token has valid data
func (t *OAuthToken) Validate() error {
	if t.ID == "" {
		return errors.New("token ID cannot be empty")
	}
	if t.ProviderTenantID == "" {
		return errors.New("provider tenant ID cannot be empty")
	}
	if t.UserID == 0 {
		return errors.New("user ID cannot be empty")
	}
	if len(t.AccessTokenEncrypted) == 0 {
		return errors.New("token cannot be empty")
	}
	return nil
}

// Create inserts a new OAuth token into the database
func (t *OAuthToken) Create() error {
	if err := t.Validate(); err != nil {
		return err
	}
	if t.ID == "" {
		t.ID = uuid.New().String()
	}
	t.CreatedAt = time.Now().UTC()
	return db.Create(t).Error
}

// Update updates an existing OAuth token in the database
func (t *OAuthToken) Update() error {
	if err := t.Validate(); err != nil {
		return fmt.Errorf("invalid token: %v", err)
	}
	return db.Model(&OAuthToken{}).Where("id = ?", t.ID).Updates(map[string]interface{}{
		"access_token_encrypted": t.AccessTokenEncrypted,
		"refresh_token_encrypted": t.RefreshTokenEncrypted,
		"expires_at": t.ExpiresAt,
	}).Error
}

// Delete removes an OAuth token from the database
func (t *OAuthToken) Delete() error {
	// Check if the record exists first
	var count int64
	if err := db.Model(&OAuthToken{}).Where("id = ?", t.ID).Count(&count).Error; err != nil {
		return fmt.Errorf("OAuth token not found: %v", err)
	}
	if count == 0 {
		return fmt.Errorf("OAuth token not found: record does not exist")
	}

	err := db.Delete(t).Error
	if err != nil {
		return fmt.Errorf("failed to delete OAuth token: %v", err)
	}
	return nil
}

// GetOAuthToken retrieves an OAuth token by ID
func GetOAuthToken(id string) (*OAuthToken, error) {
	if id == "" {
		return nil, errors.New("invalid OAuth token ID")
	}
	
	token := &OAuthToken{}
	err := db.Where("id = ?", id).First(token).Error
	if err != nil {
		return nil, fmt.Errorf("OAuth token not found: %v", err)
	}
	return token, nil
}

// GetOAuthTokensByProviderTenant retrieves all OAuth tokens for a given provider tenant
func GetOAuthTokensByProviderTenant(providerTenantID string) ([]*OAuthToken, error) {
	if providerTenantID == "" {
		return nil, errors.New("invalid provider tenant ID")
	}
	
	var tokens []*OAuthToken
	err := db.Where("provider_tenant_id = ?", providerTenantID).Find(&tokens).Error
	if err != nil {
		return nil, err
	}
	return tokens, nil
}

// GetOAuthTokenByUserAndProviderTenant retrieves an OAuth token for a specific user and provider tenant
func GetOAuthTokenByUserAndProviderTenant(userID int64, providerTenantID string) (*OAuthToken, error) {
	if userID == 0 {
		return nil, errors.New("invalid user ID")
	}
	if providerTenantID == "" {
		return nil, errors.New("invalid provider tenant ID")
	}
	
	token := &OAuthToken{}
	err := db.Where("user_id = ? AND provider_tenant_id = ?", userID, providerTenantID).First(token).Error
	if err != nil {
		return nil, fmt.Errorf("OAuth token not found: %v", err)
	}
	return token, nil
}