package controllers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	ctx "github.com/gophish/gophish/context"
	"github.com/gophish/gophish/middleware"
	"github.com/gophish/gophish/models"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

// OAuth2Login initiates the OAuth2 login flow
func OAuth2Login(w http.ResponseWriter, r *http.Request) {
	// Get the app registration ID from the session
	session := ctx.Get(r, "session").(*sessions.Session)
	appRegID, ok := session.Values["app_reg_id"].(uuid.UUID)
	if !ok {
		// Get the default app registration
		appRegs, err := models.GetAppRegistrations()
		if err != nil || len(appRegs) == 0 {
			http.Error(w, "No app registrations found", http.StatusInternalServerError)
			return
		}
		appRegID = appRegs[0].ID
		session.Values["app_reg_id"] = appRegID
		session.Save(r, w)
	}

	// Get the OAuth2 config
	config, err := models.GetOAuth2Config(appRegID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error getting OAuth2 config: %v", err), http.StatusInternalServerError)
		return
	}

	// Generate a random state
	state := uuid.New().String()
	session.Values["oauth2_state"] = state
	session.Save(r, w)

	// Redirect to the provider's consent page
	url := config.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// OAuth2Callback handles the callback from the OAuth2 provider
func OAuth2Callback(w http.ResponseWriter, r *http.Request) {
	// Get the session
	session := ctx.Get(r, "session").(*sessions.Session)

	// Verify state
	state := r.URL.Query().Get("state")
	if state != session.Values["oauth2_state"] {
		http.Error(w, "Invalid OAuth2 state", http.StatusBadRequest)
		return
	}

	// Get the app registration ID from the session
	appRegID, ok := session.Values["app_reg_id"].(uuid.UUID)
	if !ok {
		http.Error(w, "No app registration ID found in session", http.StatusBadRequest)
		return
	}

	// Get the OAuth2 config
	config, err := models.GetOAuth2Config(appRegID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error getting OAuth2 config: %v", err), http.StatusInternalServerError)
		return
	}

	// Exchange the code for a token
	code := r.URL.Query().Get("code")
	token, err := config.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error exchanging code for token: %v", err), http.StatusInternalServerError)
		return
	}

	// Save the token
	userID := ctx.Get(r, "user_id").(int64)
	err = models.SaveOAuth2Token(context.Background(), appRegID, userID, token)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error saving token: %v", err), http.StatusInternalServerError)
		return
	}

	// Clear the state from the session
	delete(session.Values, "oauth2_state")
	session.Save(r, w)

	// Redirect to the next URL or home
	next := session.Values["next"].(string)
	if next == "" {
		next = "/"
	}
		http.Redirect(w, r, next, http.StatusTemporaryRedirect)
}

// RegisterOAuth2Routes registers the OAuth2 routes with the router
func (as *AdminServer) RegisterOAuth2Routes(router *mux.Router) {
	router.HandleFunc("/oauth2/login", middleware.Use(OAuth2Login, as.limiter.Limit))
	router.HandleFunc("/oauth2/callback", middleware.Use(OAuth2Callback, as.limiter.Limit))
} 