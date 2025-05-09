package controllers

import (
	"encoding/json"
	"net/http"
	"time"

	ctx "github.com/gophish/gophish/context"
	"github.com/gophish/gophish/models"
	"github.com/gophish/gophish/logger"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

// OAuth2Login initiates the OAuth2 login flow
func (as *AdminServer) OAuth2Login(w http.ResponseWriter, r *http.Request) {
	session := ctx.Get(r, "session").(*sessions.Session)
	next := r.URL.Query().Get("next")
	if next != "" {
		session.Values["next"] = next
	}

	logger.Info("Getting OAuth2 config...")
	config, err := models.GetOAuth2Config()
	if err != nil {
		logger.Error("OAuth2 config error:", err)
		Flash(w, r, "danger", "OAuth2 configuration error")
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	// Generate random state
	state := models.GenerateRandomString(32)
	session.Values["oauth2_state"] = state
	err = session.Save(r, w)
	if err != nil {
		logger.Error("Failed to save session:", err)
		Flash(w, r, "danger", "Session error")
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	url := config.AuthCodeURL(state)
	logger.Info("Redirecting to OAuth2 URL:", url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// OAuth2Callback handles the OAuth2 callback from Microsoft
func (as *AdminServer) OAuth2Callback(w http.ResponseWriter, r *http.Request) {
	session := ctx.Get(r, "session").(*sessions.Session)
	state := session.Values["oauth2_state"]
	if state == nil || state.(string) != r.URL.Query().Get("state") {
		Flash(w, r, "danger", "Invalid OAuth state")
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		Flash(w, r, "danger", "Authorization code not received")
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	config, err := models.GetOAuth2Config()
	if err != nil {
		logger.Error(err)
		Flash(w, r, "danger", "OAuth2 configuration error")
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	token, err := config.Exchange(r.Context(), code)
	if err != nil {
		logger.Error(err)
		Flash(w, r, "danger", "Failed to exchange authorization code")
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	// Get user profile from Microsoft Graph API
	client := config.Client(r.Context(), token)
	resp, err := client.Get("https://graph.microsoft.com/v1.0/me")
	if err != nil {
		logger.Error(err)
		Flash(w, r, "danger", "Failed to get user profile")
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}
	defer resp.Body.Close()

	var profile map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		logger.Error(err)
		Flash(w, r, "danger", "Failed to parse user profile")
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	// Get or create user based on email
	email, ok := profile["userPrincipalName"].(string)
	if !ok {
		Flash(w, r, "danger", "Email not found in profile")
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	user, err := models.GetUserByUsername(email)
	if err != nil {
		// Create new user if not exists
		user = models.User{
			Username: email,
			Role:     models.Role{Slug: "user"},
		}
		err = models.PutUser(&user)
		if err != nil {
			logger.Error(err)
			Flash(w, r, "danger", "Failed to create user")
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			return
		}
	}

	// Save OAuth2 token
	err = models.SaveOAuth2Token(user.Id, token)
	if err != nil {
		logger.Error(err)
		Flash(w, r, "danger", "Failed to save OAuth token")
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	// Update last login
	user.LastLogin = time.Now().UTC()
	err = models.PutUser(&user)
	if err != nil {
		logger.Error(err)
	}

	// Set session
	session.Values["id"] = user.Id
	delete(session.Values, "oauth2_state")
	session.Save(r, w)

	// Redirect to next URL or dashboard
	next, ok := session.Values["next"].(string)
	if ok {
		delete(session.Values, "next")
		session.Save(r, w)
		http.Redirect(w, r, next, http.StatusTemporaryRedirect)
		return
	}

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

// RegisterOAuth2Routes registers the OAuth2 routes with the router
func (as *AdminServer) RegisterOAuth2Routes(router *mux.Router) {
	router.HandleFunc("/oauth2/login", as.OAuth2Login)
	router.HandleFunc("/oauth2/callback", as.OAuth2Callback)
} 