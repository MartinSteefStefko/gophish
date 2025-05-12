package models

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

const (
	keyIterations = 10000
	keyLength     = 32 // AES-256
	saltLength    = 32
)

// EncryptionKey represents the master key used for encryption
type EncryptionKey struct {
	key []byte
}

var masterKey *EncryptionKey

// InitializeEncryption sets up the encryption system
func InitializeEncryption() error {
	// Get the master encryption key from environment variable
	keyStr := os.Getenv("MASTER_ENCRYPTION_KEY")
	if keyStr == "" {
		return fmt.Errorf("MASTER_ENCRYPTION_KEY environment variable not set - please run scripts/generate_encryption_key.sh to generate a key")
	}

	// Decode the base64 key
	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return fmt.Errorf("invalid master encryption key format: %v", err)
	}

	// Validate key length
	if len(key) != keyLength {
		return fmt.Errorf("master encryption key must be %d bytes (got %d bytes)", keyLength, len(key))
	}

	masterKey = &EncryptionKey{key: key}
	return nil
}

// EncryptToString encrypts data and returns base64 encoded string
func EncryptToString(data []byte) (string, error) {
	encrypted, err := Encrypt(data)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DecryptFromString decrypts base64 encoded encrypted data
func DecryptFromString(encryptedStr string) ([]byte, error) {
	encrypted, err := base64.StdEncoding.DecodeString(encryptedStr)
	if err != nil {
		return nil, fmt.Errorf("invalid encrypted data format: %v", err)
	}
	return Decrypt(encrypted)
}

// Encrypt encrypts data using AES-256-GCM
func Encrypt(data []byte) ([]byte, error) {
	if masterKey == nil {
		return nil, fmt.Errorf("encryption not initialized - MASTER_ENCRYPTION_KEY environment variable must be set")
	}

	// Generate a random salt
	salt := make([]byte, saltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	// Derive encryption key using PBKDF2
	key := pbkdf2.Key(masterKey.key, salt, keyIterations, keyLength, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// Combine salt + nonce + ciphertext
	result := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// Decrypt decrypts data using AES-256-GCM
func Decrypt(encrypted []byte) ([]byte, error) {
	if masterKey == nil {
		return nil, fmt.Errorf("encryption not initialized - MASTER_ENCRYPTION_KEY environment variable must be set")
	}

	if len(encrypted) < saltLength {
		return nil, fmt.Errorf("encrypted data too short")
	}

	// Extract salt
	salt := encrypted[:saltLength]
	remaining := encrypted[saltLength:]

	// Derive key using PBKDF2
	key := pbkdf2.Key(masterKey.key, salt, keyIterations, keyLength, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(remaining) < gcm.NonceSize() {
		return nil, fmt.Errorf("encrypted data too short")
	}

	nonce := remaining[:gcm.NonceSize()]
	ciphertext := remaining[gcm.NonceSize():]

	// Decrypt the data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Helper functions for specific use cases

// EncryptClientSecret encrypts a client secret and returns base64 encoded string
func EncryptClientSecret(secret string) (string, error) {
	return EncryptToString([]byte(secret))
}

// DecryptClientSecret decrypts a base64 encoded encrypted client secret
func DecryptClientSecret(encryptedSecret string) (string, error) {
	decrypted, err := DecryptFromString(encryptedSecret)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

// EncryptToken encrypts an OAuth token and returns base64 encoded string
func EncryptToken(token string) (string, error) {
	return EncryptToString([]byte(token))
}

// DecryptToken decrypts a base64 encoded encrypted OAuth token
func DecryptToken(encryptedToken string) (string, error) {
	decrypted, err := DecryptFromString(encryptedToken)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

// HashSecret creates a hash of a secret for verification purposes
func HashSecret(secret string) []byte {
	return pbkdf2.Key([]byte(secret), nil, keyIterations, keyLength, sha256.New)
} 