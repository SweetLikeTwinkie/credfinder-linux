#!/bin/bash
# Desktop Keyring Dump Script
# Extracts passwords from GNOME Keyring and KWallet

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}Desktop Keyring Dump Script${NC}"
echo "====================================="

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to dump GNOME Keyring
dump_gnome_keyring() {
    echo "Checking GNOME Keyring..."
    
    if command_exists secret-tool; then
        echo "  Using secret-tool to search for secrets..."
        
        # Search for all items
        echo "  Searching for all secrets..."
        if secret-tool search service '*' 2>/dev/null; then
            echo -e "${GREEN}  ✓ Found secrets in GNOME Keyring${NC}"
        else
            echo -e "${YELLOW}  No secrets found or access denied${NC}"
        fi
        
        # Search for common services
        common_services=(
            "chrome" "firefox" "brave" "chromium"
            "ssh" "git" "aws" "docker"
            "mysql" "postgresql" "redis"
            "vpn" "wifi" "network"
            "email" "imap" "smtp"
        )
        
        echo "  Searching for common services..."
        for service in "${common_services[@]}"; do
            echo "    Checking service: $service"
            if secret-tool search service "$service" 2>/dev/null; then
                echo -e "${GREEN}      ✓ Found secrets for $service${NC}"
            fi
        done
        
    elif command_exists gnome-keyring-daemon; then
        echo "  GNOME Keyring daemon is available"
        echo "  Note: Use secret-tool for better access"
    else
        echo -e "${YELLOW}  GNOME Keyring tools not found${NC}"
    fi
}

# Function to dump KWallet
dump_kwallet() {
    echo "Checking KWallet..."
    
    if command_exists kwallet-query; then
        echo "  Using kwallet-query to access KWallet..."
        
        # List available wallets
        echo "  Available wallets:"
        if kwallet-query --list-wallets 2>/dev/null; then
            echo -e "${GREEN}  ✓ Found KWallet wallets${NC}"
            
            # Try to access the default wallet
            echo "  Attempting to access default wallet..."
            if kwallet-query --folder Passwords --show-password 2>/dev/null; then
                echo -e "${GREEN}  ✓ Successfully accessed KWallet${NC}"
            else
                echo -e "${YELLOW}  Could not access KWallet (may be locked)${NC}"
            fi
        else
            echo -e "${YELLOW}  No KWallet wallets found${NC}"
        fi
        
    elif command_exists kwalletmanager5; then
        echo "  KWallet Manager is available"
        echo "  Note: Use kwallet-query for command-line access"
    else
        echo -e "${YELLOW}  KWallet tools not found${NC}"
    fi
}

# Function to check for other keyring tools
check_other_keyrings() {
    echo "Checking for other keyring tools..."
    
    # Check for pass (password store)
    if command_exists pass; then
        echo "  pass (password store) is available"
        if [[ -d "$HOME/.password-store" ]]; then
            echo "  Password store found at ~/.password-store"
            echo "  Use 'pass ls' to list stored passwords"
        fi
    fi
    
    # Check for keepassxc
    if command_exists keepassxc; then
        echo "  KeePassXC is available"
    fi
    
    # Check for bitwarden CLI
    if command_exists bw; then
        echo "  Bitwarden CLI is available"
        echo "  Use 'bw list items' to see stored items"
    fi
}

# Function to check for environment variables
check_environment() {
    echo "Checking environment variables..."
    
    # Check for keyring-related environment variables
    keyring_vars=(
        "GNOME_KEYRING_SOCKET"
        "GNOME_KEYRING_PID"
        "KDE_FULL_SESSION"
        "KDEWM"
        "SSH_AUTH_SOCK"
    )
    
    for var in "${keyring_vars[@]}"; do
        if [[ -n "${!var}" ]]; then
            echo "  $var: ${!var}"
        fi
    done
}

# Function to check for D-Bus services
check_dbus() {
    echo "Checking D-Bus services..."
    
    if command_exists dbus-send; then
        echo "  D-Bus is available"
        
        # Try to list D-Bus services
        if dbus-send --session --dest=org.freedesktop.DBus --type=method_call \
           /org/freedesktop/DBus org.freedesktop.DBus.ListNames 2>/dev/null | \
           grep -E "(secret|keyring|wallet)" >/dev/null; then
            echo -e "${GREEN}  ✓ Found keyring-related D-Bus services${NC}"
        else
            echo -e "${YELLOW}  No keyring D-Bus services found${NC}"
        fi
    else
        echo -e "${YELLOW}  D-Bus tools not available${NC}"
    fi
}

# Main execution
echo "Starting desktop keyring dump..."
echo

# Check if running in a desktop environment
if [[ -n "$DISPLAY" ]]; then
    echo -e "${GREEN}✓ Running in desktop environment${NC}"
else
    echo -e "${YELLOW}Not running in desktop environment${NC}"
    echo "  Some keyring tools may not work without a display"
fi

echo

# Run checks
check_environment
check_dbus
dump_gnome_keyring
dump_kwallet
check_other_keyrings

echo
echo "Summary:"
echo "  Keyring tools checked:"
echo "    - GNOME Keyring (secret-tool)"
echo "    - KWallet (kwallet-query)"
echo "    - pass (password store)"
echo "    - KeePassXC"
echo "    - Bitwarden CLI"

echo
echo -e "${GREEN}✓ Desktop keyring dump completed${NC}"

# Tips for manual investigation
echo
echo -e "${BLUE}Tips for manual investigation:${NC}"
echo "  - Use 'secret-tool search service <service_name>' to search specific services"
echo "  - Use 'kwallet-query --folder <folder> --show-password <wallet>' for KWallet"
echo "  - Check ~/.local/share/keyrings/ for GNOME Keyring files"
echo "  - Check ~/.kde/share/apps/kwallet/ for KWallet files" 