package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/google/uuid"
	"github.com/gophish/gophish/auth"
	ctx "github.com/gophish/gophish/context"
	"github.com/gophish/gophish/middleware"
	"github.com/gophish/gophish/models"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

// OAuth2Login initiates the OAuth2 login flow
func OAuth2Login(w http.ResponseWriter, r *http.Request) {
	// Get the session
	session := ctx.Get(r, "session").(*sessions.Session)

	// If user is already logged in, redirect to home
	if u := ctx.Get(r, "user"); u != nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// Get OAuth2 config from environment variables
	tenantID := os.Getenv("OAUTH2_TENANT_ID")
	redirectURI := os.Getenv("OAUTH2_REDIRECT_URI")
	clientID := os.Getenv("OAUTH2_CLIENT_ID")
	clientSecret := os.Getenv("OAUTH2_CLIENT_SECRET")
	if tenantID == "" || redirectURI == "" || clientID == "" || clientSecret == "" {
		http.Error(w, "Missing OAuth2 configuration", http.StatusInternalServerError)
		return
	}

	// Create OAuth2 config with only basic scopes needed for authentication
	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     microsoft.AzureADEndpoint(tenantID),
		Scopes: []string{
			"openid",
			"profile",
			"email",
			"offline_access",
		},
	}

	// Generate a random state
	state := uuid.New().String()
	session.Values["oauth2_state"] = state
	session.Values["auth_method"] = "oauth2" // Mark this as an OAuth2 login
	if err := session.Save(r, w); err != nil {
		http.Error(w, fmt.Sprintf("Error saving session: %v", err), http.StatusInternalServerError)
		return
	}

	// Redirect to the provider's consent page
	url := config.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// OAuth2Callback handles the callback from the OAuth2 provider
func OAuth2Callback(w http.ResponseWriter, r *http.Request) {
	// Get the session
	session := ctx.Get(r, "session").(*sessions.Session)

	// Verify this is an OAuth2 login flow
	authMethod, ok := session.Values["auth_method"].(string)
	if !ok || authMethod != "oauth2" {
		http.Error(w, "Invalid authentication flow", http.StatusBadRequest)
		return
	}

	// Verify state
	state := r.URL.Query().Get("state")
	if state != session.Values["oauth2_state"] {
		http.Error(w, "Invalid OAuth2 state", http.StatusBadRequest)
		return
	}

	// Get OAuth2 config using environment variables
	tenantID := os.Getenv("OAUTH2_TENANT_ID")
	redirectURI := os.Getenv("OAUTH2_REDIRECT_URI")
	clientID := os.Getenv("OAUTH2_CLIENT_ID")
	clientSecret := os.Getenv("OAUTH2_CLIENT_SECRET")
	if tenantID == "" || redirectURI == "" || clientID == "" || clientSecret == "" {
		http.Error(w, "Missing OAuth2 configuration", http.StatusInternalServerError)
		return
	}

	// Create OAuth2 config with only basic scopes needed for authentication
	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     microsoft.AzureADEndpoint(tenantID),
		Scopes: []string{
			"openid",
			"profile",
			"email",
			"offline_access",
		},
	}

	// Exchange the code for a token
	code := r.URL.Query().Get("code")
	token, err := config.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error exchanging code for token: %v", err), http.StatusInternalServerError)
		return
	}

	// Get Microsoft Graph client
	client := oauth2.NewClient(context.Background(), config.TokenSource(context.Background(), token))
	graphClient := &http.Client{Transport: client.Transport}

	// Get user info from Microsoft Graph
	resp, err := graphClient.Get("https://graph.microsoft.com/v1.0/me")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error getting user info: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var userInfo struct {
		DisplayName string `json:"displayName"`
		Mail        string `json:"mail"`
		ID          string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		http.Error(w, fmt.Sprintf("Error decoding user info: %v", err), http.StatusInternalServerError)
		return
	}

	// Get the user role
	role, err := models.GetRoleBySlug(models.RoleUser)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error getting user role: %v", err), http.StatusInternalServerError)
		return
	}

	// Create or get existing user
	user := &models.User{
		Username:               userInfo.Mail, // Use email as username
		Role:                   role,
		RoleID:                role.ID,
		PasswordChangeRequired: false,
		ApiKey:                auth.GenerateSecureKey(auth.APIKeyLength),
	}

	// Try to get existing user first
	existingUser, err := models.GetUserByUsername(user.Username)
	if err == nil {
		// User exists, use existing user
		user = &existingUser
	} else {
		// Create new user
		err = models.PutUser(user)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error creating user: %v", err), http.StatusInternalServerError)
			return
		}
	}

	// Create or get existing tenant
	tenant := &models.Tenant{
		ID:   uuid.New().String(),
		Name: models.DefaultSystemTenantName,
	}

	// Try to get existing tenant first
	existingTenant, err := models.GetTenantByName(tenant.Name)
	if err == nil {
		// Tenant exists, use existing tenant
		tenant = &existingTenant
	} else {
		// Create new tenant
		err = tenant.Create()
		if err != nil {
			http.Error(w, fmt.Sprintf("Error creating tenant: %v", err), http.StatusInternalServerError)
			return
		}
	}

	// Update user with tenant ID
	user.TenantID = tenant.ID
	err = models.PutUser(user)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error updating user with tenant: %v", err), http.StatusInternalServerError)
		return
	}

	// Create provider tenant if it doesn't exist
	providerTenant := &models.ProviderTenant{
		ID:               uuid.New().String(),
		TenantID:         tenant.ID,
		ProviderType:     models.ProviderTypeAzure,
		ProviderTenantID: tenantID, // From environment variable
		DisplayName:      "",
	}

	// Try to get existing provider tenant first
	existingProviderTenant, err := models.GetProviderTenantByProviderTenantID(tenantID)
	if err == nil {
		// Provider tenant exists, use existing provider tenant
		providerTenant = &existingProviderTenant
	} else {
		// Create new provider tenant
		err = providerTenant.Create()
		if err != nil {
			http.Error(w, fmt.Sprintf("Error creating provider tenant: %v", err), http.StatusInternalServerError)
			return
		}
	}

	// Set up the user session
	session.Values["id"] = user.Id
	delete(session.Values, "oauth2_state")
	delete(session.Values, "auth_method")

	// Redirect to the next URL or home
	next := "/"
	if nextURL, ok := session.Values["next"]; ok && nextURL != nil {
		if nextStr, ok := nextURL.(string); ok && nextStr != "" {
			next = nextStr
		}
	}
	delete(session.Values, "next")
	if err := session.Save(r, w); err != nil {
		http.Error(w, fmt.Sprintf("Error saving session: %v", err), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, next, http.StatusTemporaryRedirect)
}

// RegisterOAuth2Routes registers the OAuth2 routes with the router
func (as *AdminServer) RegisterOAuth2Routes(router *mux.Router) {
	router.HandleFunc("/oauth2/login", middleware.Use(OAuth2Login, middleware.GetContext, as.limiter.Limit))
	router.HandleFunc("/oauth2/callback", middleware.Use(OAuth2Callback, middleware.GetContext, as.limiter.Limit))
} 