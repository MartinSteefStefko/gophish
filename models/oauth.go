package models

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

// For testing purposes
var graphAPIEndpoint = "https://graph.microsoft.com/v1.0"

// OAuth2Config represents the OAuth2 configuration for Microsoft authentication
type OAuth2Config struct {
	Id            int64     `json:"id" gorm:"column:id; primary_key:yes"`
	UserId        int64     `json:"-" gorm:"column:user_id"`
	ClientID      string    `json:"client_id"`
	ClientSecret  string    `json:"client_secret,omitempty"`
	TenantID      string    `json:"tenant_id"`
	RedirectURI   string    `json:"redirect_uri"`
	Scopes        []string  `json:"scopes" gorm:"-"`
	ModifiedDate  time.Time `json:"modified_date"`
	Enabled       bool      `json:"enabled"`
}

// OAuth2Token represents the OAuth2 token information
type OAuth2Token struct {
	Id            int64     `json:"id" gorm:"column:id; primary_key:yes"`
	UserId        int64     `json:"-" gorm:"column:user_id"`
	AccessToken   string    `json:"access_token"`
	RefreshToken  string    `json:"refresh_token"`
	TokenType     string    `json:"token_type"`
	ExpiresAt     time.Time `json:"expires_at"`
	ModifiedDate  time.Time `json:"modified_date"`
}

// TableName specifies the database table name for OAuth2Config
func (o OAuth2Config) TableName() string {
	return "oauth2_config"
}

// TableName specifies the database table name for OAuth2Token
func (t OAuth2Token) TableName() string {
	return "oauth2_tokens"
}

// GetOAuth2Config returns the OAuth2 configuration for Microsoft authentication
func GetOAuth2Config() (*oauth2.Config, error) {
	var config OAuth2Config
	err := db.Where("enabled = ?", true).First(&config).Error
	if err != nil {
		return nil, err
	}

	return &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURI,
		Scopes: []string{
			"https://graph.microsoft.com/User.Read",
			"offline_access",
		},
		Endpoint: microsoft.AzureADEndpoint(config.TenantID),
	}, nil
}

// GetUserOAuth2Token retrieves the OAuth2 token for a user
func GetUserOAuth2Token(userId int64) (*OAuth2Token, error) {
	var token OAuth2Token
	err := db.Where("user_id = ?", userId).First(&token).Error
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// SaveOAuth2Token saves or updates the OAuth2 token for a user
func SaveOAuth2Token(userId int64, token *oauth2.Token) error {
	oauthToken := &OAuth2Token{
		UserId:       userId,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		ExpiresAt:    token.Expiry,
		ModifiedDate: time.Now().UTC(),
	}

	// Check if token exists
	var existing OAuth2Token
	if err := db.Where("user_id = ?", userId).First(&existing).Error; err == nil {
		oauthToken.Id = existing.Id
	}

	return db.Save(oauthToken).Error
}

// GetUserProfile retrieves the Microsoft user profile using the OAuth2 token
func GetUserProfile(token *OAuth2Token) (map[string]interface{}, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/me", graphAPIEndpoint), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user profile: %s", resp.Status)
	}

	var profile map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, err
	}

	return profile, nil
} 