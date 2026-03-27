#!/bin/bash
# Beorn Migration Script
# Upgrades an existing Heimdall installation to the Beorn Evolution.
# ------------------------------------------------------------------

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}Starting Beorn Evolution Migration...${NC}"

# 1. Install the new Beorn package
echo -e "${BLUE}[1/5] Installing Beorn package from evolution branch...${NC}"
pip install git+https://github.com/bhackerb/heimdall.git@feature/beorn-evolution --break-system-packages

# 2. Migrate Configuration
echo -e "${BLUE}[2/5] Migrating configuration from Heimdall to Beorn...${NC}"
OLD_CONFIG_DIR="$HOME/.config/heimdall"
NEW_CONFIG_DIR="$HOME/.config/beorn"

if [ -d "$OLD_CONFIG_DIR" ]; then
    mkdir -p "$NEW_CONFIG_DIR"
    if [ -f "$OLD_CONFIG_DIR/config.yaml" ]; then
        cp "$OLD_CONFIG_DIR/config.yaml" "$NEW_CONFIG_DIR/config.yaml"
        echo -e "${GREEN}  - Config migrated to $NEW_CONFIG_DIR/config.yaml${NC}"
    fi
else
    echo -e "${YELLOW}  - No existing Heimdall config found. Running 'beorn init' instead...${NC}"
    beorn init
fi

# 3. Initialize State Directory (The Carrock)
echo -p "${BLUE}[3/5] Initializing State Persistence...${NC}"
mkdir -p "$NEW_CONFIG_DIR/state"
echo -e "${GREEN}  - State directory created at $NEW_CONFIG_DIR/state${NC}"

# 4. Update Systemd Service
echo -e "${BLUE}[4/5] Updating systemd service...${NC}"
if systemctl is-active --quiet "heimdall@$USER"; then
    echo -e "${YELLOW}  - Stopping and disabling old Heimdall service...${NC}"
    sudo systemctl stop "heimdall@$USER"
    sudo systemctl disable "heimdall@$USER"
fi

# Get the directory where beorn.service is located (assumes script is run from repo root)
REPO_DIR=$(pwd)
if [ -f "$REPO_DIR/beorn.service" ]; then
    echo -e "${GREEN}  - Installing new Beorn service...${NC}"
    sudo cp "$REPO_DIR/beorn.service" "/etc/systemd/system/beorn@.service"
    sudo systemctl daemon-reload
    sudo systemctl enable "beorn@$USER"
    sudo systemctl start "beorn@$USER"
    echo -e "${GREEN}  - Beorn service is now active.${NC}"
else
    echo -e "${YELLOW}  - beorn.service not found in current directory. Skipping service update.${NC}"
    echo -e "    You can install it later with: sudo cp beorn.service /etc/systemd/system/beorn@.service${NC}"
fi

# 5. Final Scan & Verification
echo -e "${BLUE}[5/5] Running initial verification scan...${NC}"
beorn scan

echo -e "\n${GREEN}Migration Complete! Beorn is now watching over this machine.${NC}"
echo -e "${YELLOW}Note: All new 'Bees' (Eagles, Woodsman, etc.) are in AUDIT MODE.${NC}"
echo -e "${YELLOW}They will learn your 'normal' traffic over the next few days.${NC}"
