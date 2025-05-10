package models

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/gophish/gophish/config"
	"github.com/gorilla/sessions"
	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
)

var (
	// Store is the session store for testing
	Store = sessions.NewCookieStore([]byte("gophish-test-session-key"))
	testDB *gorm.DB
)

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

// SetupTest initializes the test environment
func SetupTest(t *testing.T) func() {
	// Set up master encryption key for tests
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	os.Setenv("MASTER_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(masterKey))

	// Initialize encryption
	err := InitializeEncryption()
	assert.NoError(t, err)

	// Create a new database connection
	var err2 error
	db, err2 = gorm.Open("sqlite3", ":memory:")
	if err2 != nil {
		t.Fatalf("Failed to connect to database: %v", err2)
	}

	// Run migrations
	err = db.AutoMigrate(&Tenant{}, &ProviderTenant{}, &AppRegistration{}, &Feature{}, &OAuthToken{}).Error
	if err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	return func() {
		db.Close()
		os.Unsetenv("MASTER_ENCRYPTION_KEY")
	}
} 