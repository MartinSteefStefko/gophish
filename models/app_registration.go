package models

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// AppRegistration represents an application registration in a provider
type AppRegistration struct {
	ID                  string    `gorm:"type:text;primary_key"`
	ProviderTenantID    string    `gorm:"type:text;index"`
	ClientID            string    `gorm:"type:text"`
	ClientSecretEncrypted string  `gorm:"type:text"`
	RedirectURI         string    `gorm:"type:text"`
	ScopesStr           string    `gorm:"column:scopes;type:text"`
	Region              string    `gorm:"type:text"`
	ExternalID          string    `gorm:"type:text"`
	CreatedAt           time.Time `gorm:"type:timestamp"`
	UpdatedAt           time.Time `gorm:"type:timestamp"`
}

// BeforeCreate will set a UUID rather than numeric ID.
func (ar *AppRegistration) BeforeCreate() error {
	if ar.ID == "" {
		ar.ID = uuid.New().String()
	}
	return nil
}

// GetScopes returns the scopes as a slice
func (ar *AppRegistration) GetScopes() []string {
	if ar.ScopesStr == "" {
		return []string{}
	}
	return strings.Split(ar.ScopesStr, ",")
}

// SetScopes sets the scopes from a slice
func (ar *AppRegistration) SetScopes(scopes []string) {
	ar.ScopesStr = strings.Join(scopes, ",")
}

// Validate checks if the app registration has valid data
func (ar *AppRegistration) Validate() error {
	if ar.ID == "" {
		return errors.New("app registration ID cannot be empty")
	}
	if ar.ProviderTenantID == "" {
		return errors.New("provider tenant ID cannot be empty")
	}
	if ar.ClientID == "" {
		return errors.New("client ID cannot be empty")
	}
	if ar.RedirectURI == "" {
		return errors.New("redirect URI cannot be empty")
	}
	if !isValidRedirectURI(ar.RedirectURI) {
		return errors.New("invalid redirect URI")
	}
	return nil
}

// Create inserts a new app registration into the database
func (ar *AppRegistration) Create() error {
	if err := ar.Validate(); err != nil {
		return err
	}

	// Check for duplicate client ID
	var count int64
	if err := db.Model(&AppRegistration{}).Where("client_id = ? AND provider_tenant_id = ?", ar.ClientID, ar.ProviderTenantID).Count(&count).Error; err != nil {
		return fmt.Errorf("failed to check for duplicate client ID: %v", err)
	}
	if count > 0 {
		return errors.New("client ID already exists")
	}

	if ar.ID == "" {
		ar.ID = uuid.New().String()
	}
	ar.CreatedAt = time.Now().UTC()
	ar.UpdatedAt = time.Now().UTC()
	return db.Create(ar).Error
}

// Update modifies an existing app registration in the database
func (ar *AppRegistration) Update() error {
	if ar.ID == "" {
		return errors.New("app registration ID cannot be empty")
	}
	ar.UpdatedAt = time.Now().UTC()
	return db.Save(ar).Error
}

// Delete removes an app registration from the database
func (ar *AppRegistration) Delete() error {
	// Check if the record exists first
	var count int64
	if err := db.Model(&AppRegistration{}).Where("id = ?", ar.ID).Count(&count).Error; err != nil {
		return fmt.Errorf("app registration not found: %v", err)
	}
	if count == 0 {
		return fmt.Errorf("app registration not found: record does not exist")
	}

	err := db.Delete(ar).Error
	if err != nil {
		return fmt.Errorf("failed to delete app registration: %v", err)
	}
	return nil
}

// GetAppRegistration retrieves an app registration by ID
func GetAppRegistration(id string) (*AppRegistration, error) {
	if id == "" {
		return nil, errors.New("invalid app registration ID")
	}
	
	appReg := &AppRegistration{}
	err := db.Where("id = ?", id).First(appReg).Error
	if err != nil {
		return nil, fmt.Errorf("app registration not found: %v", err)
	}
	return appReg, nil
}

// GetAppRegistrationsByProviderTenant retrieves all app registrations for a given provider tenant
func GetAppRegistrationsByProviderTenant(providerTenantID string) ([]*AppRegistration, error) {
	if providerTenantID == "" {
		return nil, errors.New("invalid provider tenant ID")
	}
	
	var appRegs []*AppRegistration
	err := db.Where("provider_tenant_id = ?", providerTenantID).Find(&appRegs).Error
	if err != nil {
		return nil, err
	}

	// Clean up any deleted app registrations
	var activeAppRegs []*AppRegistration
	for _, ar := range appRegs {
		if !ar.CreatedAt.IsZero() {
			activeAppRegs = append(activeAppRegs, ar)
		}
	}
	return activeAppRegs, nil
}

// isValidRedirectURI checks if the redirect URI is valid
func isValidRedirectURI(uri string) bool {
	// Basic validation: must start with http:// or https://
	return strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://")
}

// GetDefaultAppRegistration returns the first available app registration
func GetDefaultAppRegistration() (*AppRegistration, error) {
	var appReg AppRegistration
	err := db.First(&appReg).Error
	if err != nil {
		return nil, fmt.Errorf("no app registrations found: %v", err)
	}
	return &appReg, nil
}

// CreateAppRegistration creates a new app registration with the given parameters
func CreateAppRegistration(ctx context.Context, providerTenantID, clientID, clientSecret, redirectURI string, scopes []string) (*AppRegistration, error) {
	// Create a new app registration
	appReg := &AppRegistration{
		ID:               uuid.New().String(),
		ProviderTenantID: providerTenantID,
		ClientID:         clientID,
		RedirectURI:      redirectURI,
	}
	appReg.SetScopes(scopes)

	// Hash and encrypt the client secret
	secretEnc, err := Encrypt([]byte(clientSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt client secret: %v", err)
	}

	appReg.ClientSecretEncrypted = string(secretEnc)

	// Create the app registration
	if err := appReg.Create(); err != nil {
		return nil, fmt.Errorf("failed to create app registration: %v", err)
	}

	return appReg, nil
}

// GetAppRegistrations returns all app registrations
func GetAppRegistrations() ([]*AppRegistration, error) {
	var appRegs []*AppRegistration
	err := db.Find(&appRegs).Error
	if err != nil {
		return nil, fmt.Errorf("failed to get app registrations: %v", err)
	}

	// Clean up any deleted app registrations
	var activeAppRegs []*AppRegistration
	for _, ar := range appRegs {
		if !ar.CreatedAt.IsZero() {
			activeAppRegs = append(activeAppRegs, ar)
		}
	}
	return activeAppRegs, nil
} 