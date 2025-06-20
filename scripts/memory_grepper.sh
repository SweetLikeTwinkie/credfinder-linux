#!/bin/bash
# Memory Grepper Script
# Searches processes and memory for secrets

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}Memory-Based Secret Hunting Script${NC}"
echo "============================================="

# Secret patterns
PATTERNS=(
    "AKIA[0-9A-Z]{16}"
    "sk_[a-zA-Z0-9]{24}"
    "ghp_[a-zA-Z0-9]{36}"
    "eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"
    "password[[:space:]]*[:=][[:space:]]*[^[:space:]]+"
    "secret[[:space:]]*[:=][[:space:]]*[^[:space:]]+"
    "token[[:space:]]*[:=][[:space:]]*[^[:space:]]+"
)

FINDINGS=()

# Function to search for patterns in content
search_patterns() {
    local content="$1"
    local source="$2"
    
    for pattern in "${PATTERNS[@]}"; do
        if echo "$content" | grep -E "$pattern" >/dev/null 2>&1; then
            echo -e "${RED}Pattern found in $source${NC}"
            echo -e "${YELLOW}Pattern: $pattern${NC}"
            echo -e "${BLUE}Matches:${NC}"
            echo "$content" | grep -E "$pattern" | head -5
            echo
            FINDINGS+=("$source:$pattern")
        fi
    done
}

# Function to check process environment variables
check_process_env() {
    echo "Checking process environment variables..."
    
    for proc in /proc/*/environ; do
        if [[ -f "$proc" ]]; then
            pid=$(echo "$proc" | cut -d'/' -f3)
            
            # Get process name
            if [[ -f "/proc/$pid/comm" ]]; then
                proc_name=$(cat "/proc/$pid/comm" 2>/dev/null || echo "unknown")
            else
                proc_name="unknown"
            fi
            
            echo "  Checking PID $pid ($proc_name)..."
            
            # Read environment variables
            if [[ -r "$proc" ]]; then
                env_content=$(cat "$proc" 2>/dev/null | tr '\0' '\n')
                if [[ -n "$env_content" ]]; then
                    search_patterns "$env_content" "PID $pid ($proc_name) environment"
                fi
            fi
        fi
    done
}

# Function to check process command lines
check_process_cmdline() {
    echo "Checking process command lines..."
    
    for proc in /proc/*/cmdline; do
        if [[ -f "$proc" ]]; then
            pid=$(echo "$proc" | cut -d'/' -f3)
            
            # Get process name
            if [[ -f "/proc/$pid/comm" ]]; then
                proc_name=$(cat "/proc/$pid/comm" 2>/dev/null || echo "unknown")
            else
                proc_name="unknown"
            fi
            
            echo "  Checking PID $pid ($proc_name)..."
            
            # Read command line
            if [[ -r "$proc" ]]; then
                cmdline=$(cat "$proc" 2>/dev/null | tr '\0' ' ')
                if [[ -n "$cmdline" ]]; then
                    search_patterns "$cmdline" "PID $pid ($proc_name) command line"
                fi
            fi
        fi
    done
}

# Function to check /proc files
check_proc_files() {
    echo "Checking /proc files..."
    
    proc_files=(
        "/proc/*/status"
        "/proc/*/maps"
        "/proc/*/fdinfo/*"
    )
    
    for pattern in "${proc_files[@]}"; do
        for file in $pattern; do
            if [[ -f "$file" && -r "$file" ]]; then
                content=$(cat "$file" 2>/dev/null)
                if [[ -n "$content" ]]; then
                    search_patterns "$content" "$file"
                fi
            fi
        done
    done
}

# Function to check shared memory
check_shared_memory() {
    echo "Checking shared memory..."
    
    if [[ -d "/dev/shm" ]]; then
        for file in /dev/shm/*; do
            if [[ -f "$file" && -r "$file" ]]; then
                content=$(cat "$file" 2>/dev/null | head -c 1000)
                if [[ -n "$content" ]]; then
                    search_patterns "$content" "$file"
                fi
            fi
        done
    fi
}

# Function to check running processes with ps
check_ps_output() {
    echo "Checking running processes..."
    
    if command -v ps >/dev/null 2>&1; then
        # Get all processes with full command line
        ps_output=$(ps aux 2>/dev/null || ps -ef 2>/dev/null)
        if [[ -n "$ps_output" ]]; then
            search_patterns "$ps_output" "ps output"
        fi
    fi
}

# Function to check environment variables
check_environment() {
    echo "Checking current environment variables..."
    
    env_output=$(env)
    if [[ -n "$env_output" ]]; then
        search_patterns "$env_output" "current environment"
    fi
}

# Main execution
echo "Starting memory-based secret hunting..."
echo

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo -e "${YELLOW}Running as root - will check all processes${NC}"
    echo
else
    echo -e "${YELLOW}Running as user - limited access to other processes${NC}"
    echo
fi

# Run checks
check_environment
check_ps_output
check_process_env
check_process_cmdline
check_proc_files
check_shared_memory

echo
echo "Summary:"
echo "  Total findings: ${#FINDINGS[@]}"

if [[ ${#FINDINGS[@]} -gt 0 ]]; then
    echo "  Findings:"
    for finding in "${FINDINGS[@]}"; do
        echo "    - $finding"
    done
else
    echo -e "${GREEN}  No secrets found in memory${NC}"
fi

echo
echo -e "${GREEN}✓ Memory-based secret hunting completed${NC}"

# Optional: Check for Volatility
if command -v vol >/dev/null 2>&1; then
    echo
    echo -e "${BLUE}Volatility is available. Consider using it for deeper memory analysis.${NC}"
fi 