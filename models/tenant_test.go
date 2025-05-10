package models

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestCreateTenant(t *testing.T) {
	// Setup
	cleanupTenant := setupTest(t)
	defer cleanupTenant()

	// Test cases
	tests := []struct {
		name        string
		tenantName  string
		wantErr     bool
		errContains string
	}{
		{
			name:       "Valid tenant",
			tenantName: "Test Tenant",
			wantErr:    false,
		},
		{
			name:        "Empty tenant name",
			tenantName:  "",
			wantErr:     true,
			errContains: "tenant name cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenant := &Tenant{
				ID:   uuid.New(),
				Name: tt.tenantName,
			}

			err := tenant.Create()

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotEmpty(t, tenant.ID)
			assert.NotEmpty(t, tenant.CreatedAt)

			// Verify tenant was created
			found, err := GetTenant(tenant.ID)
			assert.NoError(t, err)
			assert.Equal(t, tenant.ID, found.ID)
			assert.Equal(t, tenant.Name, found.Name)
		})
	}
}

func TestGetTenant(t *testing.T) {
	// Setup
	cleanupTenant := setupTest(t)
	defer cleanupTenant()

	// Create a test tenant
	tenant := &Tenant{
		ID:   uuid.New(),
		Name: "Test Tenant",
	}
	err := tenant.Create()
	assert.NoError(t, err)

	// Test cases
	tests := []struct {
		name        string
		tenantID    uuid.UUID
		wantErr     bool
		errContains string
	}{
		{
			name:     "Existing tenant",
			tenantID: tenant.ID,
			wantErr:  false,
		},
		{
			name:        "Non-existent tenant",
			tenantID:    uuid.New(),
			wantErr:     true,
			errContains: "tenant not found",
		},
		{
			name:        "Invalid UUID",
			tenantID:    uuid.Nil,
			wantErr:     true,
			errContains: "invalid tenant ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, err := GetTenant(tt.tenantID)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tenant.ID, found.ID)
			assert.Equal(t, tenant.Name, found.Name)
		})
	}
}

func TestListTenants(t *testing.T) {
	// Setup
	cleanupTenant := setupTest(t)
	defer cleanupTenant()

	// Create test tenants
	tenants := []*Tenant{
		{ID: uuid.New(), Name: "Tenant 1"},
		{ID: uuid.New(), Name: "Tenant 2"},
		{ID: uuid.New(), Name: "Tenant 3"},
	}

	for _, tenant := range tenants {
		err := tenant.Create()
		assert.NoError(t, err)
	}

	// Test listing
	found, err := GetTenants()
	assert.NoError(t, err)
	assert.Len(t, found, len(tenants))

	// Verify all tenants are present
	tenantMap := make(map[uuid.UUID]bool)
	for _, tenant := range tenants {
		tenantMap[tenant.ID] = true
	}

	for _, tenant := range found {
		assert.True(t, tenantMap[tenant.ID])
	}
}

func TestUpdateTenant(t *testing.T) {
	// Setup
	cleanupTenant := setupTest(t)
	defer cleanupTenant()

	// Create a test tenant
	tenant := &Tenant{
		ID:   uuid.New(),
		Name: "Original Name",
	}
	err := tenant.Create()
	assert.NoError(t, err)

	// Test cases
	tests := []struct {
		name        string
		newName     string
		wantErr     bool
		errContains string
	}{
		{
			name:    "Valid update",
			newName: "Updated Name",
			wantErr: false,
		},
		{
			name:        "Empty name",
			newName:     "",
			wantErr:     true,
			errContains: "tenant name cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenant.Name = tt.newName
			err := tenant.Update()

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)

			// Verify update
			found, err := GetTenant(tenant.ID)
			assert.NoError(t, err)
			assert.Equal(t, tt.newName, found.Name)
		})
	}
}

func TestDeleteTenant(t *testing.T) {
	// Setup
	cleanupTenant := setupTest(t)
	defer cleanupTenant()

	// Create a test tenant
	tenant := &Tenant{
		ID:   uuid.New(),
		Name: "Test Tenant",
	}
	err := tenant.Create()
	assert.NoError(t, err)

	// Delete the tenant
	err = tenant.Delete()
	assert.NoError(t, err)

	// Try to get the deleted tenant
	_, err = GetTenant(tenant.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant not found")

	// Try to delete again
	err = tenant.Delete()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant not found")
} 