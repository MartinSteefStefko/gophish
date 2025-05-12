#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Navigate to project root (3 levels up from gophish/cmd/gophish-bootstrap)
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../../.." &> /dev/null && pwd )"

# Generate a secure 32-byte key and encode it in base64
echo -e "${GREEN}Generating new master encryption key...${NC}"
NEW_KEY=$(openssl rand -base64 32)

# Check if .env file exists in project root
if [ -f "$PROJECT_ROOT/.env" ]; then
    # Read the current value of MASTER_ENCRYPTION_KEY if it exists
    CURRENT_KEY=$(grep "^MASTER_ENCRYPTION_KEY=" "$PROJECT_ROOT/.env" | cut -d '=' -f2)
    
    if [ -n "$CURRENT_KEY" ]; then
        # Key exists and has a value
        echo -e "${YELLOW}WARNING: MASTER_ENCRYPTION_KEY already exists in .env${NC}"
        echo -e "${YELLOW}Current value will be preserved to prevent data loss${NC}"
        echo -e "${YELLOW}If you want to update it, please edit .env manually${NC}"
        exit 1
    else
        # Check if the key exists but is empty
        if grep -q "^MASTER_ENCRYPTION_KEY=" "$PROJECT_ROOT/.env"; then
            # Key exists but is empty, create a new .env with the updated key
            # First, save all other environment variables
            grep -v "^MASTER_ENCRYPTION_KEY=" "$PROJECT_ROOT/.env" > "$PROJECT_ROOT/.env.tmp"
            # Add the new key
            echo "MASTER_ENCRYPTION_KEY=${NEW_KEY}" >> "$PROJECT_ROOT/.env.tmp"
            # Replace the old .env with the new one
            mv "$PROJECT_ROOT/.env.tmp" "$PROJECT_ROOT/.env"
            echo -e "${GREEN}Updated empty MASTER_ENCRYPTION_KEY in $PROJECT_ROOT/.env${NC}"
        else
            # Key doesn't exist, append it
            echo "MASTER_ENCRYPTION_KEY=${NEW_KEY}" >> "$PROJECT_ROOT/.env"
            echo -e "${GREEN}Added MASTER_ENCRYPTION_KEY to $PROJECT_ROOT/.env${NC}"
        fi
    fi
else
    # Create new .env with the key in project root
    echo "MASTER_ENCRYPTION_KEY=${NEW_KEY}" > "$PROJECT_ROOT/.env"
    echo -e "${GREEN}Created .env with MASTER_ENCRYPTION_KEY in $PROJECT_ROOT/.env${NC}"
fi

echo -e "${GREEN}Key generation complete!${NC}"
echo -e "${YELLOW}Make sure to keep your .env file secure and backed up${NC}"
echo -e "${YELLOW}If this key is lost, encrypted data cannot be recovered${NC}" 