package controllers

import (
	"encoding/gob"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	ctx "github.com/gophish/gophish/context"
	"github.com/gophish/gophish/models"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func init() {
	// Register UUID type with gob for session storage
	gob.Register(uuid.UUID{})
}

func setupOAuthTest(t *testing.T) (*httptest.Server, *mux.Router, *models.AppRegistration, func()) {
	// Setup test environment
	cleanup := models.SetupTest(t)

	// Create test tenant
	tenant := &models.Tenant{
		ID:   uuid.New().String(),
		Name: "Test Tenant",
	}
	err := tenant.Create()
	assert.NoError(t, err)

	// Create test provider tenant
	providerTenant := &models.ProviderTenant{
		ID:               uuid.New().String(),
		TenantID:         tenant.ID,
		ProviderType:     models.ProviderTypeAzure,
		ProviderTenantID: "test-tenant-id",
		DisplayName:      "Test Provider",
		Region:           "us-east-1",
		CreatedAt:        time.Now().UTC(),
	}
	err = providerTenant.Create()
	assert.NoError(t, err)

	// Create test app registration
	appReg := &models.AppRegistration{
		ID:               uuid.New().String(),
		ProviderTenantID: providerTenant.ID,
		ClientID:         "test-client-id",
		RedirectURI:      "http://localhost/callback",
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}
	appReg.SetScopes([]string{"https://graph.microsoft.com/Mail.Send"})

	clientSecret := "test-secret"
	secretEnc, err := models.Encrypt([]byte(clientSecret))
	assert.NoError(t, err)

	appReg.ClientSecretEncrypted = string(secretEnc)

	err = appReg.Create()
	assert.NoError(t, err)

	// Create test router
	router := mux.NewRouter()
	router.HandleFunc("/oauth2/login", OAuth2Login)
	router.HandleFunc("/oauth2/callback", OAuth2Callback)

	server := httptest.NewServer(router)
	return server, router, appReg, func() {
		cleanup()
		server.Close()
	}
}

func TestOAuth2Login(t *testing.T) {
	_, _, appReg, cleanup := setupOAuthTest(t)
	defer cleanup()

	// Test OAuth2 login
	req := httptest.NewRequest("GET", "/oauth2/login", nil)
	w := httptest.NewRecorder()

	// Create test session
	session := sessions.NewSession(models.Store, "session")
	req = ctx.Set(req, "session", session)

	// Set app registration ID in session
	session.Values["app_reg_id"] = appReg.ID
	err := session.Save(req, w)
	assert.NoError(t, err)

	// Call handler
	OAuth2Login(w, req)

	// Check response
	resp := w.Result()
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
}

func TestOAuth2Callback(t *testing.T) {
	// Setup mock token endpoint
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Verify the token request
		if r.Form.Get("grant_type") != "authorization_code" ||
			r.Form.Get("code") != "test-code" ||
			r.Form.Get("client_id") != "test-client-id" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Return a mock token response
		resp := struct {
			AccessToken  string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int    `json:"expires_in"`
			RefreshToken string `json:"refresh_token"`
		}{
			AccessToken:  "test_access_token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "test_refresh_token",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer tokenServer.Close()

	// Override the GetOAuth2Config function for testing
	originalGetOAuth2Config := models.GetOAuth2Config
	models.GetOAuth2Config = func(appRegID string) (*oauth2.Config, error) {
		config, err := originalGetOAuth2Config(appRegID)
		if err != nil {
			return nil, err
		}
		config.Endpoint = oauth2.Endpoint{
			TokenURL: tokenServer.URL,
		}
		return config, nil
	}
	defer func() {
		models.GetOAuth2Config = originalGetOAuth2Config
	}()

	_, _, appReg, cleanup := setupOAuthTest(t)
	defer cleanup()

	// Test OAuth2 callback
	req := httptest.NewRequest("GET", "/oauth2/callback", nil)
	w := httptest.NewRecorder()

	// Create test session
	session := sessions.NewSession(models.Store, "session")
	req = ctx.Set(req, "session", session)

	// Set app registration ID and state in session
	state := uuid.New().String()
	session.Values["app_reg_id"] = appReg.ID
	session.Values["oauth2_state"] = state
	session.Values["next"] = "/dashboard"
	err := session.Save(req, w)
	assert.NoError(t, err)

	// Add state and code to request
	q := req.URL.Query()
	q.Set("state", state)
	q.Set("code", "test-code")
	req.URL.RawQuery = q.Encode()

	// Set user ID in context
	req = ctx.Set(req, "user_id", int64(1))

	// Call handler
	OAuth2Callback(w, req)

	// Check response
	resp := w.Result()
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	assert.Equal(t, "/dashboard", resp.Header.Get("Location"))

	// Verify token was saved
	token, err := models.GetUserOAuth2Token(req.Context(), appReg.ID, 1)
	assert.NoError(t, err)
	assert.Equal(t, "test_access_token", token.AccessToken)
	assert.Equal(t, "test_refresh_token", token.RefreshToken)
	assert.Equal(t, "Bearer", token.TokenType)
} 