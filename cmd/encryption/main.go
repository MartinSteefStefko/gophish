package main

import (
	"fmt"
	"os"

	"github.com/gophish/gophish/models"
	"github.com/joho/godotenv"
)

func main() {
	// Load .env file from the root directory
	err := godotenv.Load("../../.env")
	if err != nil {
		fmt.Printf("Error loading .env file: %v\n", err)
		os.Exit(1)
	}

	// Get the master encryption key from environment
	masterKey := os.Getenv("MASTER_ENCRYPTION_KEY")
	if masterKey == "" {
		fmt.Printf("MASTER_ENCRYPTION_KEY not found in .env file\n")
		os.Exit(1)
	}

	// Set the master encryption key
	os.Setenv("MASTER_ENCRYPTION_KEY", masterKey)

	// Initialize encryption
	if err := models.InitializeEncryption(); err != nil {
		fmt.Printf("Failed to initialize encryption: %v\n", err)
		os.Exit(1)
	}

	// Get client secret from environment
	clientSecret := os.Getenv("OAUTH2_CLIENT_SECRET")
	if clientSecret == "" {
		fmt.Printf("OAUTH2_CLIENT_SECRET not found in .env file\n")
		os.Exit(1)
	}

	// Encrypt the client secret
	encryptedSecret, err := models.EncryptToString([]byte(clientSecret))
	if err != nil {
		fmt.Printf("Failed to encrypt client secret: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Encrypted client secret: %s\n", encryptedSecret)
} 