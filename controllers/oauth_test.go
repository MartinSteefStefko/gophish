package controllers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/gophish/gophish/models"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func setupOAuthTest(t *testing.T) (*httptest.Server, *mux.Router) {
	// Setup test environment
	cleanup := models.SetupTest(t)
	defer cleanup()

	// Create test tenant
	tenant := &models.Tenant{
		ID:   uuid.New(),
		Name: "Test Tenant",
	}
	err := tenant.Create()
	assert.NoError(t, err)

	// Create test provider tenant
	providerTenant := &models.ProviderTenant{
		ID:               uuid.New(),
		TenantID:         tenant.ID,
		ProviderType:     models.ProviderTypeAzure,
		ProviderTenantID: "test-tenant-id",
		DisplayName:      "Test Provider",
	}
	err = providerTenant.Create()
	assert.NoError(t, err)

	// Create test app registration
	appReg := &models.AppRegistration{
		ID:               uuid.New(),
		ProviderTenantID: providerTenant.ID,
		ClientID:         "test-client-id",
		RedirectURI:      "http://localhost/callback",
	}
	appReg.SetScopes([]string{"https://graph.microsoft.com/Mail.Send"})

	clientSecret := "test-secret"
	secretHash := models.HashSecret(clientSecret)
	secretEnc, err := models.Encrypt([]byte(clientSecret))
	assert.NoError(t, err)

	appReg.ClientSecretHash = secretHash
	appReg.ClientSecretEncrypted = secretEnc

	err = appReg.Create()
	assert.NoError(t, err)

	// Create test router
	router := mux.NewRouter()
	router.HandleFunc("/oauth2/login", OAuth2Login)
	router.HandleFunc("/oauth2/callback", OAuth2Callback)

	return httptest.NewServer(router), router
}

func TestOAuth2Login(t *testing.T) {
	server, _ := setupOAuthTest(t)
	defer server.Close()

	// Test OAuth2 login
	req := httptest.NewRequest("GET", "/oauth2/login", nil)
	w := httptest.NewRecorder()

	// Create test session
	session, err := models.Store.Get(req, "session")
	assert.NoError(t, err)

	// Set app registration ID in session
	session.Values["app_reg_id"] = uuid.New()
	err = session.Save(req, w)
	assert.NoError(t, err)

	// Call handler
	OAuth2Login(w, req)

	// Check response
	resp := w.Result()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestOAuth2Callback(t *testing.T) {
	server, _ := setupOAuthTest(t)
	defer server.Close()

	// Test OAuth2 callback
	req := httptest.NewRequest("GET", "/oauth2/callback", nil)
	w := httptest.NewRecorder()

	// Create test session
	session, err := models.Store.Get(req, "session")
	assert.NoError(t, err)

	// Set app registration ID in session
	session.Values["app_reg_id"] = uuid.New()
	err = session.Save(req, w)
	assert.NoError(t, err)

	// Call handler
	OAuth2Callback(w, req)

	// Check response
	resp := w.Result()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
} 