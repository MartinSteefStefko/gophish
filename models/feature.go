package models

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// FeatureType represents the type of feature
type FeatureType string

const (
	FeatureTypeOAuth2    FeatureType = "oauth2"
	FeatureTypePhishing  FeatureType = "phishing"
	FeatureTypeEmail     FeatureType = "email"
	FeatureTypeDMARC     FeatureType = "dmarc"
	FeatureTypeReporting FeatureType = "reporting"
)

// IsValid checks if the feature type is valid
func (ft FeatureType) IsValid() bool {
	switch ft {
	case FeatureTypeOAuth2, FeatureTypePhishing, FeatureTypeEmail, FeatureTypeDMARC, FeatureTypeReporting:
		return true
	}
	return false
}

// Feature represents a feature enabled for an app registration
type Feature struct {
	ID               uuid.UUID                 `gorm:"type:uuid;primary_key"`
	AppRegistrationID uuid.UUID                 `gorm:"type:uuid;index"`
	FeatureType      FeatureType              `gorm:"type:string"`
	Enabled          bool                     `gorm:"default:true"`
	ConfigJSON       []byte                   `gorm:"column:config;type:jsonb"`
	Config           map[string]interface{}   `gorm:"-"`
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// BeforeSave converts Config to JSON before saving
func (f *Feature) BeforeSave() error {
	if f.Config != nil {
		configJSON, err := json.Marshal(f.Config)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %v", err)
		}
		f.ConfigJSON = configJSON
	}
	return nil
}

// AfterFind converts JSON back to Config after loading
func (f *Feature) AfterFind() error {
	if len(f.ConfigJSON) > 0 {
		var rawConfig map[string]interface{}
		if err := json.Unmarshal(f.ConfigJSON, &rawConfig); err != nil {
			return err
		}
		
		// Convert interface slices back to string slices where needed
		for k, v := range rawConfig {
			if interfaceSlice, ok := v.([]interface{}); ok {
				stringSlice := make([]string, len(interfaceSlice))
				for i, item := range interfaceSlice {
					if str, ok := item.(string); ok {
						stringSlice[i] = str
					}
				}
				rawConfig[k] = stringSlice
			}
		}
		f.Config = rawConfig
	}
	return nil
}

// Validate checks if the feature has valid data
func (f *Feature) Validate() error {
	if f.ID == uuid.Nil {
		return fmt.Errorf("feature ID cannot be empty")
	}
	if f.AppRegistrationID == uuid.Nil {
		return fmt.Errorf("app registration ID cannot be empty")
	}
	if !f.FeatureType.IsValid() {
		return fmt.Errorf("invalid feature type: %s", f.FeatureType)
	}
	return nil
}

// BeforeCreate will set a UUID rather than numeric ID
func (f *Feature) BeforeCreate() error {
	if f.ID == uuid.Nil {
		f.ID = uuid.New()
	}
	return nil
}

// Create inserts a new feature into the database
func (f *Feature) Create() error {
	if err := f.Validate(); err != nil {
		return err
	}
	f.CreatedAt = time.Now().UTC()
	f.UpdatedAt = time.Now().UTC()
	return db.Create(f).Error
}

// Update modifies an existing feature in the database
func (f *Feature) Update() error {
	if err := f.Validate(); err != nil {
		return err
	}
	f.UpdatedAt = time.Now().UTC()
	return db.Save(f).Error
}

// Delete removes a feature from the database
func (f *Feature) Delete() error {
	// Check if the record exists first
	var count int64
	if err := db.Model(&Feature{}).Where("id = ?", f.ID).Count(&count).Error; err != nil {
		return fmt.Errorf("feature not found: %v", err)
	}
	if count == 0 {
		return fmt.Errorf("feature not found: record does not exist")
	}

	err := db.Delete(f).Error
	if err != nil {
		return fmt.Errorf("failed to delete feature: %v", err)
	}
	return nil
}

// GetFeature retrieves a feature by ID
func GetFeature(id uuid.UUID) (*Feature, error) {
	if id == uuid.Nil {
		return nil, errors.New("invalid feature ID")
	}
	
	feature := &Feature{}
	err := db.Where("id = ?", id).First(feature).Error
	if err != nil {
		return nil, fmt.Errorf("feature not found: %v", err)
	}
	return feature, nil
}

// GetFeaturesByAppRegistration retrieves all features for a given app registration
func GetFeaturesByAppRegistration(appRegID uuid.UUID) ([]*Feature, error) {
	if appRegID == uuid.Nil {
		return nil, errors.New("invalid app registration ID")
	}
	
	var features []*Feature
	err := db.Where("app_registration_id = ?", appRegID).Find(&features).Error
	if err != nil {
		return nil, err
	}

	// Clean up any deleted features
	var activeFeatures []*Feature
	for _, f := range features {
		if !f.CreatedAt.IsZero() {
			activeFeatures = append(activeFeatures, f)
		}
	}
	return activeFeatures, nil
} 