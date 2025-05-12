# Gophish Testing Documentation

## Test Scenarios and Expected Outcomes

### Database Setup Tests

#### CLI Flag Tests
1. Database table creation using CLI flags
   - Expected: All required tables (tenants, provider_tenants, app_registrations, oauth2_tokens) are created
   - Verification: Check table existence and structure using SQLite queries
   - Success criteria: All tables exist with correct columns and relationships

2. Table structure verification
   - Expected: Each table has the required columns with correct data types
   - Verification: Use PRAGMA table_info to inspect table structures
   - Success criteria: All required columns present with correct types

#### Environment Variable Tests
1. Database setup using environment variables
   - Expected: Database created and tables initialized using GOPHISH_DB_* environment variables
   - Verification: Check database file creation and table existence
   - Success criteria: Database file exists at specified path with all tables

2. Environment variable precedence
   - Expected: Environment variables override CLI flags when both are present
   - Verification: Check which database file is created when both methods specify different paths
   - Success criteria: Database created at environment variable path, not CLI flag path

3. Default fallback behavior
   - Expected: System uses default values when neither CLI flags nor environment variables are set
   - Verification: Check database creation with no explicit configuration
   - Success criteria: Database created with default SQLite settings

### Master Encryption Key Tests

#### Key Management Tests
1. Environment Variable Handling
   - Expected: System requires MASTER_ENCRYPTION_KEY environment variable
   - Verification: Check error handling when variable is missing or invalid
   - Success criteria: Clear error messages directing to key generation script

2. Key Format Validation
   - Expected: System validates key format and length
   - Verification: Test with various key formats and lengths
   - Success criteria: Only accepts valid base64-encoded 32-byte keys

3. Key Generation Script
   - Expected: scripts/generate_encryption_key.sh generates valid key
   - Verification: Run script and verify key format
   - Success criteria: Script creates valid key in .env file

4. Key Preservation
   - Expected: Existing keys in .env are preserved
   - Verification: Run script with existing key
   - Success criteria: Script warns and preserves existing key

## Best Practices

1. Key Generation
   - Always use cryptographically secure random number generator
   - Generate keys of appropriate length (32 bytes for AES-256)
   - Use base64 encoding for storage/transmission

2. Key Storage
   - Never hardcode keys in source code
   - Store only in .env file
   - Back up .env file securely
   - Consider using a key management service in production

3. Key Rotation
   - Back up .env before rotation
   - Update all encrypted data with new key
   - Verify data access after rotation

## Example Test Configurations

### Environment Variable Configuration
```bash
# Generate a new key
./scripts/generate_encryption_key.sh

# Use existing key
export MASTER_ENCRYPTION_KEY=base64_encoded_key
```

### Testing Invalid Configurations
```bash
# Missing key
unset MASTER_ENCRYPTION_KEY
./gophish  # Should fail with clear error

# Invalid key format
export MASTER_ENCRYPTION_KEY="invalid-key"
./gophish  # Should fail with format error

# Wrong key length
export MASTER_ENCRYPTION_KEY=$(openssl rand -base64 16)
./gophish  # Should fail with length error
``` 