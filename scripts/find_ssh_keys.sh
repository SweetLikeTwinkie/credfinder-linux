#!/bin/bash
# SSH Key Finder Script
# Searches for SSH keys in common locations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}SSH Key Discovery Script${NC}"
echo "=================================="

# Common SSH key locations
SSH_PATHS=(
    "$HOME/.ssh"
    "/etc/ssh"
    "/home/*/.ssh"
    "/root/.ssh"
)

# SSH key patterns
KEY_PATTERNS=(
    "id_rsa*"
    "id_dsa*"
    "id_ecdsa*"
    "id_ed25519*"
    "id_xmss*"
    "ssh_host_*_key"
)

FOUND_KEYS=()

# Function to check if key is encrypted
is_encrypted() {
    local key_file="$1"
    if grep -q "ENCRYPTED" "$key_file" 2>/dev/null; then
        return 0
    fi
    return 1
}

# Function to check file permissions
check_permissions() {
    local file="$1"
    local perms=$(stat -c "%a" "$file" 2>/dev/null)
    if [[ "$perms" == "600" || "$perms" == "400" ]]; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC} (perms: $perms)"
    fi
}

# Search for SSH keys
echo "Searching for SSH keys..."
echo

for path in "${SSH_PATHS[@]}"; do
    expanded_path=$(eval echo "$path")
    
    if [[ -d "$expanded_path" ]]; then
        echo "Checking: $expanded_path"
        
        for pattern in "${KEY_PATTERNS[@]}"; do
            find "$expanded_path" -name "$pattern" -type f 2>/dev/null | while read -r key_file; do
                if [[ -f "$key_file" ]]; then
                    echo "  Found: $key_file"
                    
                    # Check if it's a private key (not .pub)
                    if [[ ! "$key_file" =~ \.pub$ ]]; then
                        echo -n "    Encrypted: "
                        if is_encrypted "$key_file"; then
                            echo -e "${YELLOW}Yes${NC}"
                        else
                            echo -e "${RED}No${NC}"
                        fi
                        
                        echo -n "    Secure permissions: "
                        check_permissions "$key_file"
                        
                        # Get file owner
                        owner=$(stat -c "%U" "$key_file" 2>/dev/null || echo "unknown")
                        echo "    Owner: $owner"
                        
                        FOUND_KEYS+=("$key_file")
                    else
                        echo "    Type: Public key"
                        echo -n "    Secure permissions: "
                        check_permissions "$key_file"
                    fi
                    echo
                fi
            done
        done
    fi
done

# Check SSH agent
echo "Checking SSH Agent..."
if [[ -n "$SSH_AUTH_SOCK" ]]; then
    echo "  SSH Agent is running"
    echo "  Socket: $SSH_AUTH_SOCK"
    
    if command -v ssh-add >/dev/null 2>&1; then
        echo "  Loaded identities:"
        ssh-add -l 2>/dev/null || echo "    No identities loaded"
    fi
else
    echo "  SSH Agent is not running"
fi

echo
echo "Summary:"
echo "  Total private keys found: ${#FOUND_KEYS[@]}"

if [[ ${#FOUND_KEYS[@]} -gt 0 ]]; then
    echo "  Private keys:"
    for key in "${FOUND_KEYS[@]}"; do
        echo "    - $key"
    done
fi

echo
echo -e "${GREEN}✓ SSH key discovery completed${NC}" 