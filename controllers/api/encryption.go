package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/gophish/gophish/models"
)

// GenerateKey generates a new encryption key
func (as *Server) GenerateKey(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		key := make([]byte, 32) // AES-256 key size
		if _, err := rand.Read(key); err != nil {
			JSONResponse(w, models.Response{Success: false, Message: err.Error()}, http.StatusInternalServerError)
			return
		}

		keyBase64 := base64.StdEncoding.EncodeToString(key)
		JSONResponse(w, models.Response{Success: true, Data: keyBase64}, http.StatusOK)
	default:
		w.Header().Set("Allow", "POST")
		JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
	}
}

// EncryptData encrypts the provided data using the given key
func (as *Server) EncryptData(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		var payload struct {
			Data string `json:"data"`
		}

		err := json.NewDecoder(r.Body).Decode(&payload)
		if err != nil {
			JSONResponse(w, models.Response{Success: false, Message: "Invalid request"}, http.StatusBadRequest)
			return
		}

		ciphertext, err := models.Encrypt([]byte(payload.Data))
		if err != nil {
			JSONResponse(w, models.Response{Success: false, Message: err.Error()}, http.StatusBadRequest)
			return
		}

		JSONResponse(w, models.Response{
			Success: true,
			Data: base64.StdEncoding.EncodeToString(ciphertext),
		}, http.StatusOK)
	default:
		w.Header().Set("Allow", "POST")
		JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
	}
}

// DecryptData decrypts the provided ciphertext using the given key
func (as *Server) DecryptData(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		var payload struct {
			Ciphertext string `json:"ciphertext"`
		}

		err := json.NewDecoder(r.Body).Decode(&payload)
		if err != nil {
			JSONResponse(w, models.Response{Success: false, Message: "Invalid request"}, http.StatusBadRequest)
			return
		}

		ciphertext, err := base64.StdEncoding.DecodeString(payload.Ciphertext)
		if err != nil {
			JSONResponse(w, models.Response{Success: false, Message: "Invalid ciphertext format"}, http.StatusBadRequest)
			return
		}

		plaintext, err := models.Decrypt(ciphertext)
		if err != nil {
			JSONResponse(w, models.Response{Success: false, Message: err.Error()}, http.StatusBadRequest)
			return
		}

		JSONResponse(w, models.Response{
			Success: true,
			Data: string(plaintext),
		}, http.StatusOK)
	default:
		w.Header().Set("Allow", "POST")
		JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
	}
} 