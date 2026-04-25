#!/bin/bash
# =============================================================================
# Download Detection Rules for RedTeamSimmer
# =============================================================================
# Run this script to download the latest detection rule mappings
# 
# Usage: ./download_detection_rules.sh
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DETECTION_DIR="${SCRIPT_DIR}"

echo "==================================================="
echo "RedTeamSimmer Detection Rules Downloader"
echo "==================================================="

# Create detection directory if it doesn't exist
mkdir -p "${DETECTION_DIR}"

# -----------------------------------------------------------------------------
# Download AttackRuleMap (Sigma + Splunk rules mapped to Atomic tests)
# Source: https://github.com/krdmnbrk/AttackRuleMap
# -----------------------------------------------------------------------------
echo ""
echo "[1/2] Downloading AttackRuleMap (Sigma + Splunk rules)..."
ATTACK_RULE_MAP_URL="https://raw.githubusercontent.com/krdmnbrk/AttackRuleMap/main/attack_rule_map.json"
ATTACK_RULE_MAP_FILE="${DETECTION_DIR}/attack_rule_map.json"

if curl -sL "${ATTACK_RULE_MAP_URL}" -o "${ATTACK_RULE_MAP_FILE}"; then
    ENTRIES=$(python3 -c "import json; print(len(json.load(open('${ATTACK_RULE_MAP_FILE}'))))" 2>/dev/null || echo "unknown")
    echo "    ✓ Downloaded attack_rule_map.json (${ENTRIES} entries)"
else
    echo "    ✗ Failed to download AttackRuleMap"
    exit 1
fi

# -----------------------------------------------------------------------------
# Fetch Elastic Detection Rules
# Source: https://github.com/elastic/detection-rules/tree/main/rules
# -----------------------------------------------------------------------------
echo ""
echo "[2/2] Fetching Elastic Detection Rules..."
ELASTIC_FETCHER="${DETECTION_DIR}/fetch_elastic_rules.py"

if [ -f "${ELASTIC_FETCHER}" ]; then
    # Check if git is available
    if command -v git &> /dev/null; then
        echo "    Running fetch_elastic_rules.py..."
        cd "${DETECTION_DIR}"
        python3 fetch_elastic_rules.py
        
        if [ -f "${DETECTION_DIR}/elastic_rules.json" ]; then
            TECHNIQUES=$(python3 -c "import json; d=json.load(open('${DETECTION_DIR}/elastic_rules.json')); print(len(d.get('techniques', {})))" 2>/dev/null || echo "unknown")
            echo "    ✓ Generated elastic_rules.json (${TECHNIQUES} techniques)"
        else
            echo "    ⚠ elastic_rules.json not created"
        fi
    else
        echo "    ⚠ Git not installed - cannot fetch Elastic rules"
        echo "    ℹ Install git and re-run this script"
        echo "    ℹ Or browse manually: https://elastic.github.io/detection-rules-explorer/"
        
        # Create empty placeholder
        echo '{"_info": {"note": "Run with git installed to populate"}, "techniques": {}}' > "${DETECTION_DIR}/elastic_rules.json"
        echo "    ✓ Created empty elastic_rules.json placeholder"
    fi
else
    echo "    ⚠ fetch_elastic_rules.py not found in ${DETECTION_DIR}"
    echo "    ℹ Copy fetch_elastic_rules.py to the detection folder and re-run"
    
    # Create empty placeholder
    echo '{"_info": {"note": "fetch_elastic_rules.py not found"}, "techniques": {}}' > "${DETECTION_DIR}/elastic_rules.json"
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo ""
echo "==================================================="
echo "Download Complete!"
echo "==================================================="
echo ""
echo "Files in: ${DETECTION_DIR}"
echo ""
ls -lh "${DETECTION_DIR}"/*.json 2>/dev/null || echo "No JSON files found"
echo ""

# Validate JSON files
echo "Validating JSON files..."
for f in "${DETECTION_DIR}"/*.json; do
    if [ -f "$f" ]; then
        if python3 -c "import json; json.load(open('$f'))" 2>/dev/null; then
            echo "    ✓ $(basename $f) - Valid"
        else
            echo "    ✗ $(basename $f) - Invalid JSON!"
        fi
    fi
done

echo ""
echo "==================================================="
echo "Next Steps"
echo "==================================================="
echo ""
echo "1. Add detection_module.py code to your app.py"
echo "2. Add ui_detection_panel.js code to your ui.html"
echo "3. Restart your Flask server"
echo ""
echo "See HOWTO.md for detailed integration instructions."
