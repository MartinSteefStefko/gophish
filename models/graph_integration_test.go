package models

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func setupMockGraphAPI() (*httptest.Server, *httptest.Server) {
	// Mock token server
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if r.Form.Get("client_id") != "client" || r.Form.Get("client_secret") != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		resp := struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
			TokenType   string `json:"token_type"`
		}{
			AccessToken: "test_token",
			ExpiresIn:   3600,
			TokenType:   "Bearer",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))

	// Mock Graph API server
	graphServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test_token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if r.URL.Path == "/v1.0/users/me/sendMail" {
			w.WriteHeader(http.StatusAccepted)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))

	return tokenServer, graphServer
}

func TestGraphAPIIntegrationSendMail(t *testing.T) {
	tokenServer, graphServer := setupMockGraphAPI()
	defer tokenServer.Close()
	defer graphServer.Close()

	// Override default token endpoint
	defaultTokenEndpoint = tokenServer.URL + "?tenant_id=%s"

	t.Run("Successful_Send", func(t *testing.T) {
		sender := &GraphAPISender{
			client:       &http.Client{},
			tokenCache:   &TokenCache{},
			graphBaseURL: graphServer.URL,
			clientID:     "client",
			clientSecret: "secret",
			tenantID:     "tenant",
		}

		msg := &mockMessage{content: "Subject: Test\nContent-Type: text/plain\n\nTest body"}
		err := sender.Send("from@example.com", []string{"to@example.com"}, msg)
		assert.NoError(t, err)
	})

	t.Run("Token_Refresh", func(t *testing.T) {
		sender := &GraphAPISender{
			client:       &http.Client{},
			tokenCache:   &TokenCache{AccessToken: "old_token", ExpiresAt: time.Now().Add(-1 * time.Hour)},
			graphBaseURL: graphServer.URL,
			clientID:     "client",
			clientSecret: "secret",
			tenantID:     "tenant",
		}

		msg := &mockMessage{content: "Subject: Test\nContent-Type: text/plain\n\nTest body"}
		err := sender.Send("from@example.com", []string{"to@example.com"}, msg)
		assert.NoError(t, err)
	})

	t.Run("Invalid_Token", func(t *testing.T) {
		sender := &GraphAPISender{
			client:       &http.Client{},
			tokenCache:   &TokenCache{AccessToken: "invalid_token", ExpiresAt: time.Now().Add(1 * time.Hour)},
			graphBaseURL: graphServer.URL,
			clientID:     "client",
			clientSecret: "secret",
			tenantID:     "tenant",
		}

		msg := &mockMessage{content: "Subject: Test\nContent-Type: text/plain\n\nTest body"}
		err := sender.Send("from@example.com", []string{"to@example.com"}, msg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unauthorized: token invalid")
	})
}

func TestGraphAPIIntegrationConcurrentSend(t *testing.T) {
	tokenServer, graphServer := setupMockGraphAPI()
	defer tokenServer.Close()
	defer graphServer.Close()

	// Override default token endpoint
	defaultTokenEndpoint = tokenServer.URL + "?tenant_id=%s"

	sender := &GraphAPISender{
		client:       &http.Client{},
		tokenCache:   &TokenCache{},
		graphBaseURL: graphServer.URL,
		clientID:     "client",
		clientSecret: "secret",
		tenantID:     "tenant",
	}

	msg := &mockMessage{content: "Subject: Test\nContent-Type: text/plain\n\nTest body"}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := sender.Send("from@example.com", []string{"to@example.com"}, msg)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
}

func TestGraphAPIIntegrationRateLimiting(t *testing.T) {
	tokenServer, graphServer := setupMockGraphAPI()
	defer tokenServer.Close()
	defer graphServer.Close()

	// Override default token endpoint
	defaultTokenEndpoint = tokenServer.URL + "?tenant_id=%s"

	// Create a new server with rate limiting
	rateLimitedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer rateLimitedServer.Close()

	sender := &GraphAPISender{
		client:       &http.Client{},
		tokenCache:   &TokenCache{},
		graphBaseURL: rateLimitedServer.URL,
		clientID:     "client",
		clientSecret: "secret",
		tenantID:     "tenant",
	}

	msg := &mockMessage{content: "Subject: Test\nContent-Type: text/plain\n\nTest body"}
	err := sender.Send("from@example.com", []string{"to@example.com"}, msg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rate limit exceeded")
} 