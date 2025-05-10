package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/gophish/gophish/models"
)

// GenerateKey generates a new encryption key
func (as *Server) GenerateKey(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		key, err := models.GenerateEncryptionKey()
		if err != nil {
			JSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		keyBase64 := base64.StdEncoding.EncodeToString(key)
		JSONResponse(w, struct {
			Success bool   `json:"success"`
			Key     string `json:"key"`
		}{
			Success: true,
			Key:     keyBase64,
		}, http.StatusOK)
	default:
		w.Header().Set("Allow", "POST")
		JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// EncryptData encrypts the provided data using the given key
func (as *Server) EncryptData(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		var payload struct {
			Key  string `json:"key"`
			Data string `json:"data"`
		}

		err := json.NewDecoder(r.Body).Decode(&payload)
		if err != nil {
			JSONError(w, "Invalid request", http.StatusBadRequest)
			return
		}

		key, err := base64.StdEncoding.DecodeString(payload.Key)
		if err != nil {
			JSONError(w, "Invalid key format", http.StatusBadRequest)
			return
		}

		ciphertext, err := models.Encrypt(key, []byte(payload.Data))
		if err != nil {
			JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}

		JSONResponse(w, struct {
			Success    bool   `json:"success"`
			Ciphertext string `json:"ciphertext"`
		}{
			Success:    true,
			Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		}, http.StatusOK)
	default:
		w.Header().Set("Allow", "POST")
		JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// DecryptData decrypts the provided ciphertext using the given key
func (as *Server) DecryptData(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		var payload struct {
			Key        string `json:"key"`
			Ciphertext string `json:"ciphertext"`
		}

		err := json.NewDecoder(r.Body).Decode(&payload)
		if err != nil {
			JSONError(w, "Invalid request", http.StatusBadRequest)
			return
		}

		key, err := base64.StdEncoding.DecodeString(payload.Key)
		if err != nil {
			JSONError(w, "Invalid key format", http.StatusBadRequest)
			return
		}

		ciphertext, err := base64.StdEncoding.DecodeString(payload.Ciphertext)
		if err != nil {
			JSONError(w, "Invalid ciphertext format", http.StatusBadRequest)
			return
		}

		plaintext, err := models.Decrypt(key, ciphertext)
		if err != nil {
			JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}

		JSONResponse(w, struct {
			Success   bool   `json:"success"`
			Plaintext string `json:"plaintext"`
		}{
			Success:   true,
			Plaintext: string(plaintext),
		}, http.StatusOK)
	default:
		w.Header().Set("Allow", "POST")
		JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
} 