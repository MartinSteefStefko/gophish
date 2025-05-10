package models

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Tenant represents a top-level organization in the multi-tenant model
type Tenant struct {
    ID        uuid.UUID `json:"id" gorm:"type:uuid;primary_key"`
    Name      string    `json:"name"`
    CreatedAt time.Time `json:"created_at"`
}

// Validate checks if the tenant has valid data
func (t *Tenant) Validate() error {
    if t.Name == "" {
        return errors.New("tenant name cannot be empty")
    }
    if t.ID == uuid.Nil {
        return errors.New("tenant ID cannot be empty")
    }
    return nil
}

// Create inserts a new tenant into the database
func (t *Tenant) Create() error {
    if err := t.Validate(); err != nil {
        return err
    }
    if t.ID == uuid.Nil {
        t.ID = uuid.New()
    }
    t.CreatedAt = time.Now().UTC()
    return db.Create(t).Error
}

// Update modifies an existing tenant in the database
func (t *Tenant) Update() error {
    if err := t.Validate(); err != nil {
        return err
    }
    return db.Save(t).Error
}

// Delete removes a tenant from the database
func (t *Tenant) Delete() error {
    // Check if the record exists first
    var count int64
    if err := db.Model(&Tenant{}).Where("id = ?", t.ID).Count(&count).Error; err != nil {
        return fmt.Errorf("tenant not found: %v", err)
    }
    if count == 0 {
        return fmt.Errorf("tenant not found: record does not exist")
    }

    err := db.Delete(t).Error
    if err != nil {
        return fmt.Errorf("tenant not found: %v", err)
    }
    return nil
}

// GetTenant retrieves a tenant by ID
func GetTenant(id uuid.UUID) (*Tenant, error) {
    if id == uuid.Nil {
        return nil, errors.New("invalid tenant ID")
    }
    
    tenant := &Tenant{}
    err := db.Where("id = ?", id).First(tenant).Error
    if err != nil {
        return nil, fmt.Errorf("tenant not found: %v", err)
    }
    return tenant, nil
}

// GetTenants retrieves all tenants
func GetTenants() ([]*Tenant, error) {
    var tenants []*Tenant
    err := db.Find(&tenants).Error
    return tenants, err
}

// AppRegistration represents an application registration in a provider
type AppRegistration struct {
    ID                 uuid.UUID `gorm:"type:uuid;primary_key"`
    ProviderTenantID   uuid.UUID `gorm:"type:uuid;index"`
    UseCase            string    // 'oauth2', 'email', etc.
    ClientID           string
    ClientSecretHash   []byte    // Hashed for verification
    ClientSecretEncrypted []byte // Encrypted for use
    RedirectURI        string
    ScopesStr          string    `gorm:"column:scopes"` // Stored as comma-separated string
    Region             string    // Region for region-specific configurations
    CreatedAt          time.Time
    UpdatedAt          time.Time
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

// OAuthToken represents an OAuth token for a specific app registration
type OAuthToken struct {
    ID               uuid.UUID `gorm:"type:uuid;primary_key"`
    AppRegistrationID uuid.UUID `gorm:"type:uuid;index"`
    UserID           int64     `gorm:"index"` // Reference to Gophish user
    AccessToken      []byte    // Encrypted
    RefreshToken     []byte    // Encrypted
    TokenType        string
    ExpiresAt        time.Time
    CreatedAt        time.Time
    UpdatedAt        time.Time
}

// BeforeCreate will set a UUID rather than numeric ID.
func (t *Tenant) BeforeCreate() error {
    if t.ID == uuid.Nil {
        t.ID = uuid.New()
    }
    return nil
}

func (ar *AppRegistration) BeforeCreate() error {
    if ar.ID == uuid.Nil {
        ar.ID = uuid.New()
    }
    return nil
}

func (t *OAuthToken) BeforeCreate() error {
    if t.ID == uuid.Nil {
        t.ID = uuid.New()
    }
    return nil
}

// Validate checks if the app registration has valid data
func (ar *AppRegistration) Validate() error {
    if ar.ID == uuid.Nil {
        return errors.New("app registration ID cannot be empty")
    }
    if ar.ProviderTenantID == uuid.Nil {
        return errors.New("provider tenant ID cannot be empty")
    }
    if ar.UseCase == "" {
        return errors.New("use case cannot be empty")
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
    if ar.Region != "" && !isValidRegion(ar.Region) {
        return errors.New("invalid region")
    }
    return nil
}

// isValidRedirectURI checks if the redirect URI is valid
func isValidRedirectURI(uri string) bool {
    // Basic validation: must start with http:// or https://
    return strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://")
}

// isValidRegion checks if the region is valid
func isValidRegion(region string) bool {
    validRegions := map[string]bool{
        "us-east-1": true,
        "us-west-1": true,
        "eu-west-1": true,
        "eu-central-1": true,
        "ap-southeast-1": true,
        "ap-northeast-1": true,
    }
    return validRegions[region]
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

    if ar.ID == uuid.Nil {
        ar.ID = uuid.New()
    }
    ar.CreatedAt = time.Now().UTC()
    ar.UpdatedAt = time.Now().UTC()
    return db.Create(ar).Error
}

// Update modifies an existing app registration in the database
func (ar *AppRegistration) Update() error {
    if ar.ID == uuid.Nil {
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

// GetAppRegistrationsByProviderTenant retrieves all app registrations for a given provider tenant
func GetAppRegistrationsByProviderTenant(providerTenantID uuid.UUID) ([]*AppRegistration, error) {
    if providerTenantID == uuid.Nil {
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