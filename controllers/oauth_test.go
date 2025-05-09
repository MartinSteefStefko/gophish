package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"

	ctx "github.com/gophish/gophish/context"
	"github.com/gophish/gophish/models"
)

func setupOAuthTest(t *testing.T) (*httptest.Server, *AdminServer) {
	// Setup test database
	setupTest(t)

	// Create OAuth2 config
	config := &models.OAuth2Config{
		ClientID:     "test_client_id",
		ClientSecret: "test_client_secret",
		TenantID:    "test_tenant_id",
		RedirectURI: "http://localhost:3333/oauth2/callback",
		Enabled:     true,
		ModifiedDate: time.Now().UTC(),
	}
	err := models.db.Save(config).Error
	assert.NoError(t, err)

	// Setup mock OAuth2 server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			resp := &oauth2.Token{
				AccessToken:  "test_access_token",
				TokenType:    "Bearer",
				RefreshToken: "test_refresh_token",
				Expiry:      time.Now().Add(time.Hour),
			}
			json.NewEncoder(w).Encode(resp)
		case "/v1.0/me":
			resp := map[string]interface{}{
				"id":                "test_user_id",
				"userPrincipalName": "test@example.com",
				"displayName":       "Test User",
			}
			json.NewEncoder(w).Encode(resp)
		}
	}))

	// Create admin server
	as := &AdminServer{}
	return server, as
}

func TestOAuth2Login(t *testing.T) {
	server, as := setupOAuthTest(t)
	defer server.Close()

	router := mux.NewRouter()
	as.RegisterOAuth2Routes(router)

	t.Run("OAuth2Login_Success", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/oauth2/login", nil)
		w := httptest.NewRecorder()

		// Create session
		session := sessions.NewSession(Store, "gophish")
		ctx.Set(req, "session", session)

		as.OAuth2Login(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

		location, err := resp.Location()
		assert.NoError(t, err)
		assert.Contains(t, location.String(), "client_id=test_client_id")
		assert.Contains(t, location.String(), "response_type=code")

		// Verify state was saved in session
		state := session.Values["oauth2_state"]
		assert.NotNil(t, state)
	})
}

func TestOAuth2Callback(t *testing.T) {
	server, as := setupOAuthTest(t)
	defer server.Close()

	router := mux.NewRouter()
	as.RegisterOAuth2Routes(router)

	t.Run("OAuth2Callback_Success", func(t *testing.T) {
		// Create state and session
		state := "test_state"
		session := sessions.NewSession(Store, "gophish")
		session.Values["oauth2_state"] = state

		// Create request with state and code
		form := url.Values{}
		form.Add("state", state)
		form.Add("code", "test_code")
		req := httptest.NewRequest("GET", "/oauth2/callback?"+form.Encode(), nil)
		ctx.Set(req, "session", session)

		w := httptest.NewRecorder()
		as.OAuth2Callback(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

		// Verify user was created and token was saved
		user, err := models.GetUserByUsername("test@example.com")
		assert.NoError(t, err)

		token, err := models.GetUserOAuth2Token(user.Id)
		assert.NoError(t, err)
		assert.Equal(t, "test_access_token", token.AccessToken)
	})

	t.Run("OAuth2Callback_InvalidState", func(t *testing.T) {
		// Create session with different state
		session := sessions.NewSession(Store, "gophish")
		session.Values["oauth2_state"] = "different_state"

		// Create request with invalid state
		form := url.Values{}
		form.Add("state", "test_state")
		form.Add("code", "test_code")
		req := httptest.NewRequest("GET", "/oauth2/callback?"+form.Encode(), nil)
		ctx.Set(req, "session", session)

		w := httptest.NewRecorder()
		as.OAuth2Callback(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
		location, err := resp.Location()
		assert.NoError(t, err)
		assert.Equal(t, "/login", location.Path)
	})

	t.Run("OAuth2Callback_MissingCode", func(t *testing.T) {
		// Create session with state
		state := "test_state"
		session := sessions.NewSession(Store, "gophish")
		session.Values["oauth2_state"] = state

		// Create request with state but no code
		form := url.Values{}
		form.Add("state", state)
		req := httptest.NewRequest("GET", "/oauth2/callback?"+form.Encode(), nil)
		ctx.Set(req, "session", session)

		w := httptest.NewRecorder()
		as.OAuth2Callback(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
		location, err := resp.Location()
		assert.NoError(t, err)
		assert.Equal(t, "/login", location.Path)
	})
} 