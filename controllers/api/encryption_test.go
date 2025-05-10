package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gophish/gophish/models"
	"github.com/stretchr/testify/assert"
)

func setupEncryptionTest(t *testing.T) func() {
	// Set up master encryption key for tests
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	os.Setenv("MASTER_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(masterKey))

	// Initialize encryption
	err := models.InitializeEncryption()
	assert.NoError(t, err)

	return func() {
		os.Unsetenv("MASTER_ENCRYPTION_KEY")
	}
}

func TestEncryptionAPI(t *testing.T) {
	cleanup := setupEncryptionTest(t)
	defer cleanup()

	// Create a new API server
	as := &Server{}

	t.Run("GenerateKey_Success", func(t *testing.T) {
		// Create request
		req := httptest.NewRequest("POST", "/api/encryption/key", nil)
		w := httptest.NewRecorder()

		// Call handler
		as.GenerateKey(w, req)

		// Check response
		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var result models.Response
		err := json.NewDecoder(resp.Body).Decode(&result)
		assert.NoError(t, err)
		assert.True(t, result.Success)

		// Verify key format
		key, err := base64.StdEncoding.DecodeString(result.Data.(string))
		assert.NoError(t, err)
		assert.Equal(t, 32, len(key))
	})

	t.Run("GenerateKey_InvalidMethod", func(t *testing.T) {
		// Create request with invalid method
		req := httptest.NewRequest("GET", "/api/encryption/key", nil)
		w := httptest.NewRecorder()

		// Call handler
		as.GenerateKey(w, req)

		// Check response
		resp := w.Result()
		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	})

	t.Run("EncryptDecrypt_Success", func(t *testing.T) {
		// Test data
		testData := "test data to encrypt"

		// Create encrypt request
		payload := map[string]string{"data": testData}
		body, err := json.Marshal(payload)
		assert.NoError(t, err)

		req := httptest.NewRequest("POST", "/api/encryption/encrypt", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		// Call encrypt handler
		as.EncryptData(w, req)

		// Check encrypt response
		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var result models.Response
		err = json.NewDecoder(resp.Body).Decode(&result)
		assert.NoError(t, err)
		assert.True(t, result.Success)

		// Store encrypted data for decryption test
		encryptedData := result.Data.(string)

		// Create decrypt request
		decryptPayload := map[string]string{"ciphertext": encryptedData}
		decryptBody, err := json.Marshal(decryptPayload)
		assert.NoError(t, err)

		decryptReq := httptest.NewRequest("POST", "/api/encryption/decrypt", bytes.NewBuffer(decryptBody))
		decryptW := httptest.NewRecorder()

		// Call decrypt handler
		as.DecryptData(decryptW, decryptReq)

		// Check decrypt response
		decryptResp := decryptW.Result()
		assert.Equal(t, http.StatusOK, decryptResp.StatusCode)

		var decryptResult models.Response
		err = json.NewDecoder(decryptResp.Body).Decode(&decryptResult)
		assert.NoError(t, err)
		assert.True(t, decryptResult.Success)
		assert.Equal(t, testData, decryptResult.Data)
	})

	t.Run("EncryptData_InvalidMethod", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/encryption/encrypt", nil)
		w := httptest.NewRecorder()

		as.EncryptData(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	})

	t.Run("DecryptData_InvalidMethod", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/encryption/decrypt", nil)
		w := httptest.NewRecorder()

		as.DecryptData(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	})

	t.Run("DecryptData_InvalidCiphertext", func(t *testing.T) {
		payload := map[string]string{"ciphertext": "invalid base64"}
		body, err := json.Marshal(payload)
		assert.NoError(t, err)

		req := httptest.NewRequest("POST", "/api/encryption/decrypt", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		as.DecryptData(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

func TestEncryptionAPIAuthentication(t *testing.T) {
	setupTest(t)
	apiServer := NewServer()

	// Test unauthorized access
	t.Run("Unauthorized_Access", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/encryption/key", nil)
		req.Header.Set("Content-Type", "application/json")
		// Deliberately omit authentication
		response := httptest.NewRecorder()
		apiServer.ServeHTTP(response, req)

		if response.Code != http.StatusUnauthorized {
			t.Fatalf("incorrect status code received. expected %d got %d", http.StatusUnauthorized, response.Code)
		}
	})

	// Test with invalid API key
	t.Run("Invalid_API_Key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/encryption/key", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer invalid-api-key")
		response := httptest.NewRecorder()
		apiServer.ServeHTTP(response, req)

		if response.Code != http.StatusUnauthorized {
			t.Fatalf("incorrect status code received. expected %d got %d", http.StatusUnauthorized, response.Code)
		}
	})
} 