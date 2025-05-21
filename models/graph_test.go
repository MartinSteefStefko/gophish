package models

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"strings"
	"testing"

	"errors"

	"github.com/gophish/gomail"
	"github.com/gophish/gophish/mailer"
	"github.com/stretchr/testify/assert"
)

// mockMessage implements mailer.Mail for testing
type mockMessage struct {
	content string
}

func (m *mockMessage) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write([]byte(m.content))
	return int64(n), err
}

func (m *mockMessage) Success() error {
	return nil
}

func (m *mockMessage) Error(err error) error {
	return nil
}

func (m *mockMessage) Backoff(err error) error {
	return nil
}

func (m *mockMessage) Generate(msg *gomail.Message) error {
	// Parse the content as an email message
	email, err := mail.ReadMessage(strings.NewReader(m.content))
	if err != nil {
		return err
	}

	// Set headers
	for k, v := range email.Header {
		msg.SetHeader(k, v...)
	}

	// Set body
	body := new(strings.Builder)
	_, err = io.Copy(body, email.Body)
	if err != nil {
		return err
	}

	// Determine content type
	contentType := email.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		msg.SetBody("text/html", body.String())
	} else {
		msg.SetBody("text/plain", body.String())
	}

	return nil
}

func (m *mockMessage) GetDialer() (mailer.Dialer, error) {
	return nil, nil
}

func (m *mockMessage) GetSmtpFrom() (string, error) {
	email, err := mail.ReadMessage(strings.NewReader(m.content))
	if err != nil {
		return "", err
	}
	from := email.Header.Get("From")
	if from == "" {
		return "", errors.New("no From address found")
	}
	addr, err := mail.ParseAddress(from)
	if err != nil {
		return "", err
	}
	return addr.Address, nil
}

func setupMockTokenEndpoint() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
}



func TestGraphAPISender(t *testing.T) {
	mockServer := setupMockTokenEndpoint()
	defer mockServer.Close()

	// Override default token endpoint
	defaultTokenEndpoint = mockServer.URL + "?tenant_id=%s"

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

		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer graphServer.Close()

	t.Run("Send_Success", func(t *testing.T) {
		sender := &GraphAPISender{
			client:            &http.Client{},
			graphBaseURL:      graphServer.URL,
			clientID:          "client",
			clientSecret:      "secret",
			providerTenantID:  "tenant",
		}

		msg := &mockMessage{content: "Subject: Test\nContent-Type: text/plain\n\nTest body"}
		err := sender.Send("from@example.com", []string{"to@example.com"}, msg)
		assert.NoError(t, err)
	})

	t.Run("Send_UnauthorizedRefresh", func(t *testing.T) {
		sender := &GraphAPISender{
			client:            &http.Client{},
			graphBaseURL:      graphServer.URL,
			clientID:          "wrong_client",
			clientSecret:      "wrong_secret",
			providerTenantID:  "tenant",
		}

		msg := &mockMessage{content: "Subject: Test\nContent-Type: text/plain\n\nTest body"}
		err := sender.Send("from@example.com", []string{"to@example.com"}, msg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error getting token")
	})

	t.Run("Send_Error", func(t *testing.T) {
		sender := &GraphAPISender{
			client:            &http.Client{},
			graphBaseURL:      graphServer.URL + "/error",
			clientID:          "client",
			clientSecret:      "secret",
			providerTenantID:  "tenant",
		}

		msg := &mockMessage{content: "Invalid message"}
		err := sender.Send("from@example.com", []string{"to@example.com"}, msg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "500")
	})
} 