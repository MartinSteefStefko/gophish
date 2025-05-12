package models

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// OAuthToken represents an OAuth token for a specific app registration
type OAuthToken struct {
	ID               string    `gorm:"type:text;primary_key"`
	AppRegistrationID string    `gorm:"type:text;index"`
	UserID           int64     `gorm:"index"` // Reference to Gophish user
	AccessToken      []byte    `gorm:"type:bytea"` // Encrypted
	RefreshToken     []byte    `gorm:"type:bytea"` // Encrypted
	TokenType        string    `gorm:"type:text"`
	ExpiresAt        time.Time `gorm:"type:timestamp"`
	CreatedAt        time.Time `gorm:"type:timestamp"`
	UpdatedAt        time.Time `gorm:"type:timestamp"`
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
	if t.AppRegistrationID == "" {
		return errors.New("app registration ID cannot be empty")
	}
	if t.UserID == 0 {
		return errors.New("user ID cannot be empty")
	}
	if len(t.AccessToken) == 0 {
		return errors.New("access token cannot be empty")
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
	t.UpdatedAt = time.Now().UTC()
	return db.Create(t).Error
}

// Update modifies an existing OAuth token in the database
func (t *OAuthToken) Update() error {
	if err := t.Validate(); err != nil {
		return err
	}
	t.UpdatedAt = time.Now().UTC()
	return db.Save(t).Error
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

// GetOAuthTokensByAppRegistration retrieves all OAuth tokens for a given app registration
func GetOAuthTokensByAppRegistration(appRegID string) ([]*OAuthToken, error) {
	if appRegID == "" {
		return nil, errors.New("invalid app registration ID")
	}
	
	var tokens []*OAuthToken
	err := db.Where("app_registration_id = ?", appRegID).Find(&tokens).Error
	if err != nil {
		return nil, err
	}
	return tokens, nil
}

// GetOAuthTokenByUserAndApp retrieves an OAuth token for a specific user and app registration
func GetOAuthTokenByUserAndApp(userID int64, appRegID string) (*OAuthToken, error) {
	if userID == 0 {
		return nil, errors.New("invalid user ID")
	}
	if appRegID == "" {
		return nil, errors.New("invalid app registration ID")
	}
	
	token := &OAuthToken{}
	err := db.Where("user_id = ? AND app_registration_id = ?", userID, appRegID).First(token).Error
	if err != nil {
		return nil, fmt.Errorf("OAuth token not found: %v", err)
	}
	return token, nil
}