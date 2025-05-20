package models

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"sync"
	"time"

	log "github.com/gophish/gophish/logger"
	"github.com/gophish/gophish/mailer"
	"golang.org/x/oauth2"
)

// TokenCache holds the cached access token and its expiry
type TokenCache struct {
	AccessToken string
	ExpiresAt   time.Time
	mu          sync.RWMutex
}

var (
	// Global token cache map keyed by tenant ID
	tokenCaches = make(map[string]*TokenCache)
	// Mutex for the token cache map
	tokenCachesMu sync.RWMutex
	// Default token endpoint URL
	defaultTokenEndpoint = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
)

// GraphAPISender implements the mailer.Sender interface for Microsoft Graph API
type GraphAPISender struct {
	client         *http.Client
	tokenCache     *TokenCache
	graphBaseURL   string
	tokenEndpoint  string
	clientID       string
	clientSecret   string
	tenantID       string
	fromAddress    string
}

// GraphAPI contains the attributes needed to handle sending campaign emails via Microsoft Graph API
type GraphAPI struct {
	Id            int64     `json:"id" gorm:"column:id; primary_key:yes"`
	UserId        int64     `json:"-" gorm:"column:user_id"`
	Name          string    `json:"name"`
	FromAddress   string    `json:"from_address"`
	Headers       []Header  `json:"headers"`
	ModifiedDate  time.Time `json:"modified_date"`
	InterfaceType string    `json:"interface_type" gorm:"column:interface_type"`
	// Graph API credentials - populated from app_registration and provider_tenant
	ClientID      string    `json:"client_id,omitempty" gorm:"-"`
	ClientSecret  string    `json:"client_secret,omitempty" gorm:"-"`
	TenantID      string    `json:"tenant_id,omitempty" gorm:"-"`
}

// TableName specifies the database tablename for Gorm to use
func (g GraphAPI) TableName() string {
	return "sending_profiles"
}

// Validate ensures that Graph API configs are valid
func (g *GraphAPI) Validate() error {
	if g.FromAddress == "" {
		return ErrFromAddressNotSpecified
	}

	if g.ClientID == "" {
		return errors.New("client_id not specified")
	}

	if g.ClientSecret == "" {
		return errors.New("client_secret not specified")
	}

	if g.TenantID == "" {
		return errors.New("tenant_id not specified")
	}

	// Validate the from address
	if _, err := mail.ParseAddress(g.FromAddress); err != nil {
		return fmt.Errorf("invalid from_address: %v", err)
	}

	// Try to get a token to validate credentials
	cache := getTokenCache(g.TenantID)
	token, err := cache.GetToken(g.ClientID, g.ClientSecret, g.TenantID)
	if err != nil {
		return fmt.Errorf("failed to validate Graph API credentials: %v", err)
	}
	if token == "" {
		return errors.New("failed to get valid token from Graph API")
	}

	return nil
}

// GetDialer returns a Dialer for the GraphAPI
func (g *GraphAPI) GetDialer() (mailer.Dialer, error) {
	if err := g.Validate(); err != nil {
		return nil, err
	}

	d := &GraphAPIDialer{
		clientID:     g.ClientID,
		clientSecret: g.ClientSecret,
		tenantID:     g.TenantID,
		fromAddress:  g.FromAddress,
	}

	return d, nil
}

// GraphAPIDialer implements the mailer.Dialer interface for Microsoft Graph API
type GraphAPIDialer struct {
	clientID     string
	clientSecret string
	tenantID     string
	fromAddress  string
}

// getTokenCache gets or creates a token cache for a tenant
func getTokenCache(tenantID string) *TokenCache {
	tokenCachesMu.RLock()
	cache, exists := tokenCaches[tenantID]
	tokenCachesMu.RUnlock()

	if !exists {
		cache = &TokenCache{}
		tokenCachesMu.Lock()
		tokenCaches[tenantID] = cache
		tokenCachesMu.Unlock()
	}

	return cache
}

// GetToken returns a valid access token, either from cache or by requesting a new one
func (c *TokenCache) GetToken(clientID, clientSecret, tenantID string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if we have a valid cached token
	if c.AccessToken != "" && time.Now().Before(c.ExpiresAt.Add(-5*time.Minute)) {
		return c.AccessToken, nil
	}

	// Get a new token
	token, expiresIn, err := getNewAccessToken(clientID, clientSecret, tenantID)
	if err != nil {
		return "", err
	}

	c.AccessToken = token
	c.ExpiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)

	return token, nil
}

// Invalidate clears the cached token
func (c *TokenCache) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.AccessToken = ""
	c.ExpiresAt = time.Time{}
}

// Dial creates a new GraphAPISender
func (d *GraphAPIDialer) Dial() (mailer.Sender, error) {
	cache := getTokenCache(d.tenantID)
	
	return &GraphAPISender{
		client:       &http.Client{},
		tokenCache:   cache,
		graphBaseURL: "https://graph.microsoft.com/v1.0",
		clientID:     d.clientID,
		clientSecret: d.clientSecret,
		tenantID:     d.tenantID,
		fromAddress:  d.fromAddress,
	}, nil
}

// Send implements the Sender interface for GraphAPISender
func (s *GraphAPISender) Send(from string, to []string, msg io.WriterTo) error {
	token, err := s.tokenCache.GetToken(s.clientID, s.clientSecret, s.tenantID)
	if err != nil {
		return fmt.Errorf("error getting token: %v", err)
	}

	var buf bytes.Buffer
	if _, err := msg.WriteTo(&buf); err != nil {
		return fmt.Errorf("error reading message: %v", err)
	}

	// Log the message being sent
	messageStr := buf.String()
	log.Infof("Preparing to send message with length: %d bytes", len(messageStr))
	
	// Extract subject from message if possible
	subject := "Test Email from Gophish"
	if lines := strings.Split(messageStr, "\n"); len(lines) > 0 {
		for _, line := range lines {
			if strings.HasPrefix(strings.ToLower(line), "subject:") {
				subject = strings.TrimSpace(strings.TrimPrefix(line, "Subject:"))
				break
			}
		}
	}

	// Convert the email message to Graph API format
	graphMessage := struct {
		Message struct {
			Subject      string   `json:"subject"`
			Body        struct {
				ContentType string `json:"contentType"`
				Content    string `json:"content"`
			} `json:"body"`
			ToRecipients []struct {
				EmailAddress struct {
					Address string `json:"address"`
				} `json:"emailAddress"`
			} `json:"toRecipients"`
			From struct {
				EmailAddress struct {
					Address string `json:"address"`
				} `json:"emailAddress"`
			} `json:"from"`
		} `json:"message"`
		SaveToSentItems bool `json:"saveToSentItems"`
	}{}

	// Prepare the message
	graphMessage.Message.Subject = subject
	graphMessage.Message.Body.ContentType = "HTML" // Change to HTML to better support formatted emails
	graphMessage.Message.Body.Content = messageStr // Use the full message content
	graphMessage.Message.From.EmailAddress.Address = s.fromAddress
	graphMessage.SaveToSentItems = false // Set to false for application permissions

	for _, recipient := range to {
		graphMessage.Message.ToRecipients = append(graphMessage.Message.ToRecipients, struct {
			EmailAddress struct {
				Address string `json:"address"`
			} `json:"emailAddress"`
		}{
			EmailAddress: struct {
				Address string `json:"address"`
			}{
				Address: recipient,
			},
		})
	}

	// Send the message via Graph API
	jsonData, err := json.Marshal(graphMessage)
	if err != nil {
		return fmt.Errorf("error marshaling message: %v", err)
	}

	// For application permissions, we need to use a specific user's email address
	// The fromAddress contains the email of the user we're sending as
	userEmailEncoded := url.QueryEscape(s.fromAddress)
	
	// Use the /users/{email}/sendMail endpoint with the specific user
	sendMailURL := fmt.Sprintf("%s/users/%s/sendMail", s.graphBaseURL, userEmailEncoded)
	
	log.Infof("Sending mail using Graph API URL: %s", sendMailURL)
	log.Infof("Using from address: %s", s.fromAddress)
	log.Infof("Message subject: %s", subject)

	req, err := http.NewRequest("POST", sendMailURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		s.tokenCache.Invalidate()
		return errors.New("unauthorized: token invalid")
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return errors.New("rate limit exceeded")
	}

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("error from Graph API: %d %s - %s", resp.StatusCode, resp.Status, string(body))
	}

	return nil
}

// Close implements the Sender interface
func (s *GraphAPISender) Close() error {
	return nil
}

// Reset implements the Sender interface
func (s *GraphAPISender) Reset() error {
	return nil
}

// getNewAccessToken gets a new access token from Microsoft identity platform
func getNewAccessToken(clientID, clientSecret, tenantID string) (string, int, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("scope", "https://graph.microsoft.com/.default")

	// Log the token request
	log.Infof("Requesting token with client_id: %s, tenantID: %s, scope: %s", 
		clientID, tenantID, "https://graph.microsoft.com/.default")

	tokenURL := fmt.Sprintf(defaultTokenEndpoint, tenantID)
	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return "", 0, fmt.Errorf("error requesting token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return "", 0, fmt.Errorf("error response from token endpoint: %d %s - %s", resp.StatusCode, resp.Status, string(body))
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
		TokenType   string `json:"token_type"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", 0, fmt.Errorf("error decoding token response: %v", err)
	}

	log.Infof("Successfully acquired token. Type: %s, Expires in: %d seconds", 
		result.TokenType, result.ExpiresIn)
	
	if result.Scope != "" {
		log.Infof("Token scopes: %s", result.Scope)
	}

	return result.AccessToken, result.ExpiresIn, nil
}

// GetGraphClientForUser returns a Graph API client for a specific user
func GetGraphClientForUser(ctx context.Context, userID int64) (*GraphClient, error) {
	// Get and refresh token if needed
	token, err := GetAndRefreshTokenIfNeeded(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %v", err)
	}

	// Get default app registration for endpoint
	defaultAppReg, err := GetDefaultAppRegistration()
	if err != nil {
		return nil, fmt.Errorf("failed to get default app registration: %v", err)
	}

	// Get provider tenant info
	providerTenant, err := GetProviderTenant(defaultAppReg.ProviderTenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider tenant: %v", err)
	}

	// Create HTTP client with token
	httpClient := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))

	return &GraphClient{
		client:         httpClient,
		providerTenant: providerTenant,
	}, nil
}

// SendMailAsUser sends an email using the Graph API on behalf of a user
func SendMailAsUser(ctx context.Context, userID int64, message *GraphMailMessage) error {
	client, err := GetGraphClientForUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get Graph client: %v", err)
	}

	return client.SendMail(ctx, message)
}

// GraphClient represents a Microsoft Graph API client
type GraphClient struct {
	client         *http.Client
	providerTenant *ProviderTenant
}

// GraphMailMessage represents an email message for the Graph API
type GraphMailMessage struct {
	Message struct {
		Subject      string `json:"subject"`
		Body         struct {
			ContentType string `json:"contentType"`
			Content     string `json:"content"`
		} `json:"body"`
		ToRecipients []struct {
			EmailAddress struct {
				Address string `json:"address"`
			} `json:"emailAddress"`
		} `json:"toRecipients"`
	} `json:"message"`
	SaveToSentItems bool `json:"saveToSentItems"`
}

// SendMail sends an email using the Graph API
func (c *GraphClient) SendMail(ctx context.Context, message *GraphMailMessage) error {
	// Convert message to JSON
	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", "https://graph.microsoft.com/v1.0/me/sendMail", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to send mail: %s - %s", resp.Status, string(body))
	}

	return nil
} 