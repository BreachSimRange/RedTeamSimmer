#!/bin/bash
# prepare_modules.sh
# Run this on your RedTeamSimmer server to download and prepare all required PowerShell modules
# These modules will be served to agents for offline/air-gapped operation

set -e

# Configuration - adjust this to match your server setup
MODULES_DIR="./modules"
TEMP_DIR="/tmp/ps_modules"

echo "=============================================="
echo "RedTeamSimmer - PowerShell Module Preparation"
echo "=============================================="
echo ""

# Create directories
mkdir -p "$MODULES_DIR"
mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR"

echo "[1/3] Downloading Invoke-AtomicRedTeam..."
echo "----------------------------------------------"
if [ -f "$MODULES_DIR/Invoke-AtomicRedTeam.zip" ]; then
    echo "  Already exists, skipping..."
else
    wget -q https://github.com/redcanaryco/invoke-atomicredteam/archive/refs/heads/master.zip -O iat_master.zip
    unzip -q iat_master.zip
    mv invoke-atomicredteam-master Invoke-AtomicRedTeam
    zip -rq Invoke-AtomicRedTeam.zip Invoke-AtomicRedTeam/
    mv Invoke-AtomicRedTeam.zip "$MODULES_DIR/"
    rm -rf Invoke-AtomicRedTeam iat_master.zip
    echo "  ✓ Downloaded Invoke-AtomicRedTeam"
fi

echo ""
echo "[2/3] Downloading powershell-yaml..."
echo "----------------------------------------------"
if [ -f "$MODULES_DIR/powershell-yaml.zip" ]; then
    echo "  Already exists, skipping..."
else
    wget -q https://github.com/cloudbase/powershell-yaml/archive/refs/heads/master.zip -O yaml_master.zip
    unzip -q yaml_master.zip
    mv powershell-yaml-master powershell-yaml
    zip -rq powershell-yaml.zip powershell-yaml/
    mv powershell-yaml.zip "$MODULES_DIR/"
    rm -rf powershell-yaml yaml_master.zip
    echo "  ✓ Downloaded powershell-yaml"
fi

echo ""
echo "[3/3] Downloading AtomicTestHarnesses..."
echo "----------------------------------------------"
if [ -f "$MODULES_DIR/AtomicTestHarnesses.zip" ]; then
    echo "  Already exists, skipping..."
else
    wget -q https://github.com/redcanaryco/AtomicTestHarnesses/archive/refs/heads/master.zip -O ath_master.zip
    unzip -q ath_master.zip
    mv AtomicTestHarnesses-master AtomicTestHarnesses
    zip -rq AtomicTestHarnesses.zip AtomicTestHarnesses/
    mv AtomicTestHarnesses.zip "$MODULES_DIR/"
    rm -rf AtomicTestHarnesses ath_master.zip
    echo "  ✓ Downloaded AtomicTestHarnesses"
fi

echo ""
echo "=============================================="
echo "Module Preparation Complete!"
echo "=============================================="
echo ""
echo "Files created in $MODULES_DIR:"
ls -lh "$MODULES_DIR"/*.zip 2>/dev/null || echo "  (none found - check MODULES_DIR path)"

echo ""
echo "Verify ZIP contents:"
echo "----------------------------------------------"
for zip in "$MODULES_DIR"/*.zip; do
    if [ -f "$zip" ]; then
        name=$(basename "$zip")
        count=$(unzip -l "$zip" 2>/dev/null | tail -1 | awk '{print $2}')
        echo "  $name: $count files"
    fi
done

echo ""
echo "=============================================="
echo "Next Steps:"
echo "=============================================="
echo "1. Make sure your Flask server serves the modules/ directory"
echo "2. Verify modules are accessible at:"
echo "   - http://YOUR_SERVER:5000/modules/Invoke-AtomicRedTeam.zip"
echo "   - http://YOUR_SERVER:5000/modules/powershell-yaml.zip"
echo "   - http://YOUR_SERVER:5000/modules/AtomicTestHarnesses.zip"
echo ""
echo "3. Recompile and run your agent - it will auto-download the modules!"
echo ""

# Cleanup
rm -rf "$TEMP_DIR"
