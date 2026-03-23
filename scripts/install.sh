#!/bin/bash
# Heimdall — one-line install
# curl -sSL https://raw.githubusercontent.com/bhackerb/heimdall/main/scripts/install.sh | bash
set -e

echo "Installing Heimdall..."
pip install git+https://github.com/bhackerb/heimdall.git --break-system-packages 2>/dev/null \
  || pip install git+https://github.com/bhackerb/heimdall.git

echo ""
echo "Heimdall installed. Run 'heimdall init' to configure."
heimdall init
