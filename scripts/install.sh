#!/bin/bash
# Beorn — one-line install
# curl -sSL https://raw.githubusercontent.com/bhackerb/beorn/main/scripts/install.sh | bash
set -e

echo "Installing Beorn..."
pip install git+https://github.com/bhackerb/beorn.git --break-system-packages 2>/dev/null \
  || pip install git+https://github.com/bhackerb/beorn.git

echo ""
echo "Beorn installed. Run 'beorn init' to configure."
beorn init
