package models

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gophish/gophish/config"
	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
)

var testDB *gorm.DB

// setupTestDB creates a new test database connection
func setupTestDB(t *testing.T) (*gorm.DB, func()) {
	// Create a temporary directory for the test database
	tmpDir, err := os.MkdirTemp("", "gophish-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	// Create test database file
	dbPath := filepath.Join(tmpDir, "test.db")

	// Initialize the database
	conf = &config.Config{
		DBName: "sqlite3",
		DBPath: dbPath,
	}

	// Open database connection
	db, err := gorm.Open(conf.DBName, conf.DBPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to open database: %v", err)
	}

	db.LogMode(false)
	db.DB().SetMaxOpenConns(1)

	// Run migrations
	err = db.AutoMigrate(
		&Tenant{},
		&ProviderTenant{},
		&AppRegistration{},
		&Feature{},
		&OAuthToken{},
	).Error
	if err != nil {
		db.Close()
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to run migrations: %v", err)
	}

	// Return the database and cleanup function
	return db, func() {
		db.Close()
		os.RemoveAll(tmpDir)
	}
}

// setupTest initializes the test environment
func setupTest(t *testing.T) func() {
	// Initialize encryption
	err := InitializeEncryption()
	if err != nil {
		t.Fatalf("failed to initialize encryption: %v", err)
	}

	// Setup test database
	testDB, cleanup := setupTestDB(t)
	db = testDB // Set the global db variable

	return func() {
		cleanup()
	}
} 