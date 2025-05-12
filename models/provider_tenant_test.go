package models

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestProviderTenant(t *testing.T) {
	// Setup
	cleanup := SetupTest(t)
	defer cleanup()

	// Create test tenant
	tenant := &Tenant{
		ID:   uuid.New().String(),
		Name: "Test Tenant",
	}
	err := tenant.Create()
	assert.NoError(t, err)

	t.Run("CreateProviderTenant", func(t *testing.T) {
		providerTenant := &ProviderTenant{
			ID:               uuid.New().String(),
			TenantID:         tenant.ID,
			ProviderType:     ProviderTypeAzure,
			ProviderTenantID: "test-tenant-id",
			DisplayName:      "Test Provider",
		}
		err := providerTenant.Create()
		assert.NoError(t, err)

		// Verify provider tenant was created
		found, err := GetProviderTenant(providerTenant.ID)
		assert.NoError(t, err)
		assert.Equal(t, providerTenant.ID, found.ID)
		assert.Equal(t, providerTenant.TenantID, found.TenantID)
		assert.Equal(t, providerTenant.ProviderType, found.ProviderType)
		assert.Equal(t, providerTenant.ProviderTenantID, found.ProviderTenantID)
		assert.Equal(t, providerTenant.DisplayName, found.DisplayName)

		// Clean up
		err = providerTenant.Delete()
		assert.NoError(t, err)
	})

	t.Run("UpdateProviderTenant", func(t *testing.T) {
		providerTenant := &ProviderTenant{
			ID:               uuid.New().String(),
			TenantID:         tenant.ID,
			ProviderType:     ProviderTypeAzure,
			ProviderTenantID: "test-tenant-id",
			DisplayName:      "Test Provider",
		}
		err := providerTenant.Create()
		assert.NoError(t, err)

		// Update provider tenant
		providerTenant.DisplayName = "Updated Provider"
		err = providerTenant.Update()
		assert.NoError(t, err)

		// Verify update
		found, err := GetProviderTenant(providerTenant.ID)
		assert.NoError(t, err)
		assert.Equal(t, "Updated Provider", found.DisplayName)

		// Clean up
		err = providerTenant.Delete()
		assert.NoError(t, err)
	})

	t.Run("DeleteProviderTenant", func(t *testing.T) {
		providerTenant := &ProviderTenant{
			ID:               uuid.New().String(),
			TenantID:         tenant.ID,
			ProviderType:     ProviderTypeAzure,
			ProviderTenantID: "test-tenant-id",
			DisplayName:      "Test Provider",
		}
		err := providerTenant.Create()
		assert.NoError(t, err)

		// Delete provider tenant
		err = providerTenant.Delete()
		assert.NoError(t, err)

		// Verify deletion
		_, err = GetProviderTenant(providerTenant.ID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "provider tenant not found")
	})

	t.Run("GetProviderTenantsByTenant", func(t *testing.T) {
		// Create multiple provider tenants
		pt1 := &ProviderTenant{
			ID:               uuid.New().String(),
			TenantID:         tenant.ID,
			ProviderType:     ProviderTypeAzure,
			ProviderTenantID: "test-tenant-id-1",
			DisplayName:      "Test Provider 1",
		}
		err := pt1.Create()
		assert.NoError(t, err)

		pt2 := &ProviderTenant{
			ID:               uuid.New().String(),
			TenantID:         tenant.ID,
			ProviderType:     ProviderTypeAzure,
			ProviderTenantID: "test-tenant-id-2",
			DisplayName:      "Test Provider 2",
		}
		err = pt2.Create()
		assert.NoError(t, err)

		// Get provider tenants by tenant
		providerTenants, err := GetProviderTenantsByTenant(tenant.ID)
		assert.NoError(t, err)
		assert.Len(t, providerTenants, 2)

		// Clean up
		err = pt1.Delete()
		assert.NoError(t, err)
		err = pt2.Delete()
		assert.NoError(t, err)
	})

	t.Run("InvalidProviderType", func(t *testing.T) {
		providerTenant := &ProviderTenant{
			ID:               uuid.New().String(),
			TenantID:         tenant.ID,
			ProviderType:     "invalid",
			ProviderTenantID: "test-tenant-id",
			DisplayName:      "Test Provider",
		}
		err := providerTenant.Create()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid provider type")
	})
}

func TestCreateProviderTenant(t *testing.T) {
	// Setup
	cleanup := SetupTest(t)
	defer cleanup()

	// Create a parent tenant first
	tenant := &Tenant{
		ID:   uuid.New().String(),
		Name: "Test Parent Tenant",
	}
	err := tenant.Create()
	assert.NoError(t, err)

	// Test cases
	tests := []struct {
		name            string
		providerTenant  *ProviderTenant
		wantErr         bool
		errContains     string
	}{
		{
			name: "Valid Azure provider tenant",
			providerTenant: &ProviderTenant{
				ID:              uuid.New().String(),
				TenantID:        tenant.ID,
				ProviderType:    ProviderTypeAzure,
				ProviderTenantID: "12345678-1234-1234-1234-123456789012",
				DisplayName:     "Test Azure Tenant",
				Region:         "us-east-1",
			},
			wantErr: false,
		},
		{
			name: "Valid AWS provider tenant",
			providerTenant: &ProviderTenant{
				ID:              uuid.New().String(),
				TenantID:        tenant.ID,
				ProviderType:    ProviderTypeAWS,
				ProviderTenantID: "123456789012",
				DisplayName:     "Test AWS Account",
				Region:         "us-east-1",
			},
			wantErr: false,
		},
		{
			name: "Missing tenant ID",
			providerTenant: &ProviderTenant{
				ID:              uuid.New().String(),
				ProviderType:    ProviderTypeAzure,
				ProviderTenantID: "12345678-1234-1234-1234-123456789012",
			},
			wantErr:     true,
			errContains: "tenant ID cannot be empty",
		},
		{
			name: "Invalid provider type",
			providerTenant: &ProviderTenant{
				ID:              uuid.New().String(),
				TenantID:        tenant.ID,
				ProviderType:    "invalid",
				ProviderTenantID: "12345678-1234-1234-1234-123456789012",
			},
			wantErr:     true,
			errContains: "invalid provider type",
		},
		{
			name: "Missing provider tenant ID",
			providerTenant: &ProviderTenant{
				ID:           uuid.New().String(),
				TenantID:     tenant.ID,
				ProviderType: ProviderTypeAzure,
			},
			wantErr:     true,
			errContains: "provider tenant ID cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.providerTenant.Create()

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotEmpty(t, tt.providerTenant.CreatedAt)

			// Verify provider tenant was created
			found, err := GetProviderTenant(tt.providerTenant.ID)
			assert.NoError(t, err)
			assert.Equal(t, tt.providerTenant.ID, found.ID)
			assert.Equal(t, tt.providerTenant.TenantID, found.TenantID)
			assert.Equal(t, tt.providerTenant.ProviderType, found.ProviderType)
			assert.Equal(t, tt.providerTenant.ProviderTenantID, found.ProviderTenantID)
		})
	}
}

func TestGetProviderTenant(t *testing.T) {
	// Setup
	cleanup := SetupTest(t)
	defer cleanup()

	// Create a parent tenant
	tenant := &Tenant{
		ID:   uuid.New().String(),
		Name: "Test Parent Tenant",
	}
	err := tenant.Create()
	assert.NoError(t, err)

	// Create a test provider tenant
	providerTenant := &ProviderTenant{
		ID:              uuid.New().String(),
		TenantID:        tenant.ID,
		ProviderType:    ProviderTypeAzure,
		ProviderTenantID: "12345678-1234-1234-1234-123456789012",
		DisplayName:     "Test Azure Tenant",
	}
	err = providerTenant.Create()
	assert.NoError(t, err)

	// Test cases
	tests := []struct {
		name        string
		id          string
		wantErr     bool
		errContains string
	}{
		{
			name:    "Existing provider tenant",
			id:      providerTenant.ID,
			wantErr: false,
		},
		{
			name:        "Non-existent provider tenant",
			id:          uuid.New().String(),
			wantErr:     true,
			errContains: "provider tenant not found",
		},
		{
			name:        "Invalid UUID",
			id:          "",
			wantErr:     true,
			errContains: "invalid provider tenant ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, err := GetProviderTenant(tt.id)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, providerTenant.ID, found.ID)
			assert.Equal(t, providerTenant.TenantID, found.TenantID)
			assert.Equal(t, providerTenant.ProviderType, found.ProviderType)
			assert.Equal(t, providerTenant.ProviderTenantID, found.ProviderTenantID)
		})
	}
}

func TestListProviderTenants(t *testing.T) {
	// Setup
	cleanup := SetupTest(t)
	defer cleanup()

	// Create a parent tenant
	tenant := &Tenant{
		ID:   uuid.New().String(),
		Name: "Test Parent Tenant",
	}
	err := tenant.Create()
	assert.NoError(t, err)

	// Create test provider tenants
	providerTenants := []*ProviderTenant{
		{
			ID:              uuid.New().String(),
			TenantID:        tenant.ID,
			ProviderType:    ProviderTypeAzure,
			ProviderTenantID: "12345678-1234-1234-1234-123456789012",
			DisplayName:     "Azure Tenant 1",
		},
		{
			ID:              uuid.New().String(),
			TenantID:        tenant.ID,
			ProviderType:    ProviderTypeAWS,
			ProviderTenantID: "123456789012",
			DisplayName:     "AWS Account 1",
		},
	}

	for _, pt := range providerTenants {
		err := pt.Create()
		assert.NoError(t, err)
	}

	// Test listing all provider tenants
	found, err := GetProviderTenants()
	assert.NoError(t, err)
	assert.Len(t, found, len(providerTenants))

	// Test listing by tenant ID
	foundByTenant, err := GetProviderTenantsByTenant(tenant.ID)
	assert.NoError(t, err)
	assert.Len(t, foundByTenant, len(providerTenants))

	// Test listing by provider type
	foundByType, err := GetProviderTenantsByType(ProviderTypeAzure)
	assert.NoError(t, err)
	assert.Len(t, foundByType, 1)
}

func TestUpdateProviderTenant(t *testing.T) {
	// Setup
	cleanup := SetupTest(t)
	defer cleanup()

	// Create a parent tenant
	tenant := &Tenant{
		ID:   uuid.New().String(),
		Name: "Test Parent Tenant",
	}
	err := tenant.Create()
	assert.NoError(t, err)

	// Create a test provider tenant
	providerTenant := &ProviderTenant{
		ID:              uuid.New().String(),
		TenantID:        tenant.ID,
		ProviderType:    ProviderTypeAzure,
		ProviderTenantID: "12345678-1234-1234-1234-123456789012",
		DisplayName:     "Original Name",
	}
	err = providerTenant.Create()
	assert.NoError(t, err)

	// Test cases
	tests := []struct {
		name        string
		updates     map[string]interface{}
		wantErr     bool
		errContains string
	}{
		{
			name: "Update display name",
			updates: map[string]interface{}{
				"DisplayName": "Updated Name",
			},
			wantErr: false,
		},
		{
			name: "Update region",
			updates: map[string]interface{}{
				"Region": "us-west-2",
			},
			wantErr: false,
		},
		{
			name: "Invalid provider type",
			updates: map[string]interface{}{
				"ProviderType": "invalid",
			},
			wantErr:     true,
			errContains: "invalid provider type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Apply updates
			for key, value := range tt.updates {
				switch key {
				case "DisplayName":
					providerTenant.DisplayName = value.(string)
				case "Region":
					providerTenant.Region = value.(string)
				case "ProviderType":
					providerTenant.ProviderType = ProviderType(value.(string))
				}
			}

			err := providerTenant.Update()

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)

			// Verify updates
			found, err := GetProviderTenant(providerTenant.ID)
			assert.NoError(t, err)
			for key, value := range tt.updates {
				switch key {
				case "DisplayName":
					assert.Equal(t, value.(string), found.DisplayName)
				case "Region":
					assert.Equal(t, value.(string), found.Region)
				case "ProviderType":
					assert.Equal(t, ProviderType(value.(string)), found.ProviderType)
				}
			}
		})
	}
}

func TestDeleteProviderTenant(t *testing.T) {
	// Setup
	cleanup := SetupTest(t)
	defer cleanup()

	// Create a parent tenant
	tenant := &Tenant{
		ID:   uuid.New().String(),
		Name: "Test Parent Tenant",
	}
	err := tenant.Create()
	assert.NoError(t, err)

	// Create a test provider tenant
	providerTenant := &ProviderTenant{
		ID:              uuid.New().String(),
		TenantID:        tenant.ID,
		ProviderType:    ProviderTypeAzure,
		ProviderTenantID: "12345678-1234-1234-1234-123456789012",
		DisplayName:     "Test Azure Tenant",
	}
	err = providerTenant.Create()
	assert.NoError(t, err)

	// Delete the provider tenant
	err = providerTenant.Delete()
	assert.NoError(t, err)

	// Try to get the deleted provider tenant
	_, err = GetProviderTenant(providerTenant.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "provider tenant not found")

	// Try to delete again
	err = providerTenant.Delete()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "provider tenant not found")
} 