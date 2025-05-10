package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gophish/gophish/models"
)

func TestEncryptionAPI(t *testing.T) {
	ctx := setupTest(t)

	// Test key generation endpoint
	t.Run("Generate_Key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/encryption/keys", nil)
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		ctx.apiServer.GenerateKey(response, req)

		if response.Code != http.StatusOK {
			t.Fatalf("incorrect status code received. expected %d got %d", http.StatusOK, response.Code)
		}

		var result struct {
			Success bool   `json:"success"`
			Key     string `json:"key"`
		}
		err := json.NewDecoder(response.Body).Decode(&result)
		if err != nil {
			t.Fatalf("error decoding response: %v", err)
		}
		if !result.Success {
			t.Fatal("key generation unsuccessful")
		}
		if len(result.Key) == 0 {
			t.Fatal("no key returned in response")
		}
	})

	// Test encryption endpoint
	t.Run("Encrypt_Data", func(t *testing.T) {
		payload := struct {
			Key  string `json:"key"`
			Data string `json:"data"`
		}{
			Key:  "test-key-base64", // This should be a valid base64 encoded key
			Data: "test-data",
		}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest(http.MethodPost, "/api/encryption/encrypt", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		ctx.apiServer.EncryptData(response, req)

		if response.Code != http.StatusOK {
			t.Fatalf("incorrect status code received. expected %d got %d", http.StatusOK, response.Code)
		}

		var result struct {
			Success    bool   `json:"success"`
			Ciphertext string `json:"ciphertext"`
		}
		err := json.NewDecoder(response.Body).Decode(&result)
		if err != nil {
			t.Fatalf("error decoding response: %v", err)
		}
		if !result.Success {
			t.Fatal("encryption unsuccessful")
		}
		if len(result.Ciphertext) == 0 {
			t.Fatal("no ciphertext returned in response")
		}
	})

	// Test decryption endpoint
	t.Run("Decrypt_Data", func(t *testing.T) {
		// First encrypt some data
		key, err := models.GenerateEncryptionKey()
		if err != nil {
			t.Fatalf("error generating key: %v", err)
		}

		plaintext := []byte("test data")
		ciphertext, err := models.Encrypt(key, plaintext)
		if err != nil {
			t.Fatalf("error encrypting data: %v", err)
		}

		payload := struct {
			Key        string `json:"key"`
			Ciphertext string `json:"ciphertext"`
		}{
			Key:        base64.StdEncoding.EncodeToString(key),
			Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest(http.MethodPost, "/api/encryption/decrypt", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		ctx.apiServer.DecryptData(response, req)

		if response.Code != http.StatusOK {
			t.Fatalf("incorrect status code received. expected %d got %d", http.StatusOK, response.Code)
		}

		var result struct {
			Success   bool   `json:"success"`
			Plaintext string `json:"plaintext"`
		}
		err = json.NewDecoder(response.Body).Decode(&result)
		if err != nil {
			t.Fatalf("error decoding response: %v", err)
		}
		if !result.Success {
			t.Fatal("decryption unsuccessful")
		}
		if string(plaintext) != result.Plaintext {
			t.Fatalf("incorrect plaintext returned. expected %s got %s", string(plaintext), result.Plaintext)
		}
	})

	// Test error cases
	t.Run("Invalid_Key", func(t *testing.T) {
		payload := struct {
			Key  string `json:"key"`
			Data string `json:"data"`
		}{
			Key:  "invalid-key",
			Data: "test-data",
		}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest(http.MethodPost, "/api/encryption/encrypt", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		ctx.apiServer.EncryptData(response, req)

		if response.Code != http.StatusBadRequest {
			t.Fatalf("incorrect status code received. expected %d got %d", http.StatusBadRequest, response.Code)
		}
	})

	t.Run("Invalid_Ciphertext", func(t *testing.T) {
		key, _ := models.GenerateEncryptionKey()
		payload := struct {
			Key        string `json:"key"`
			Ciphertext string `json:"ciphertext"`
		}{
			Key:        base64.StdEncoding.EncodeToString(key),
			Ciphertext: "invalid-ciphertext",
		}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest(http.MethodPost, "/api/encryption/decrypt", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		ctx.apiServer.DecryptData(response, req)

		if response.Code != http.StatusBadRequest {
			t.Fatalf("incorrect status code received. expected %d got %d", http.StatusBadRequest, response.Code)
		}
	})
}

func TestEncryptionAPIAuthentication(t *testing.T) {
	ctx := setupTest(t)

	// Test unauthorized access
	t.Run("Unauthorized_Access", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/encryption/keys", nil)
		req.Header.Set("Content-Type", "application/json")
		// Deliberately omit authentication
		response := httptest.NewRecorder()
		ctx.apiServer.GenerateKey(response, req)

		if response.Code != http.StatusUnauthorized {
			t.Fatalf("incorrect status code received. expected %d got %d", http.StatusUnauthorized, response.Code)
		}
	})

	// Test with invalid API key
	t.Run("Invalid_API_Key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/encryption/keys", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer invalid-api-key")
		response := httptest.NewRecorder()
		ctx.apiServer.GenerateKey(response, req)

		if response.Code != http.StatusUnauthorized {
			t.Fatalf("incorrect status code received. expected %d got %d", http.StatusUnauthorized, response.Code)
		}
	})
} 