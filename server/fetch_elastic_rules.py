#!/usr/bin/env python3
"""
Elastic Detection Rules Fetcher for RedTeamSimmer
==================================================
This script fetches Elastic detection rules from GitHub and extracts
MITRE ATT&CK technique mappings into a JSON file.

Source: https://github.com/elastic/detection-rules/tree/main/rules

Usage:
    python3 fetch_elastic_rules.py

Output:
    elastic_rules.json (in same directory as script)

Requirements:
    - Git installed
    - Python 3.6+
    - toml module (auto-installed if missing)
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

# Try to import toml parser
try:
    import tomllib  # Python 3.11+
    def load_toml(path):
        with open(path, 'rb') as f:
            return tomllib.load(f)
except ImportError:
    try:
        import toml
        def load_toml(path):
            return toml.load(path)
    except ImportError:
        print("[*] Installing toml module...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "toml", "--quiet", "--break-system-packages"], 
                              stderr=subprocess.DEVNULL)
        import toml
        def load_toml(path):
            return toml.load(path)


# Configuration
ELASTIC_RULES_REPO = "https://github.com/elastic/detection-rules.git"
RULES_SUBDIR = "rules"
OUTPUT_FILE = Path(__file__).resolve().parent / "elastic_rules.json"


def clone_repo(repo_url, target_dir):
    """Shallow clone the detection-rules repo (only rules directory)"""
    print(f"[*] Cloning {repo_url}...")
    print(f"    (This may take a minute...)")
    try:
        # Shallow clone with sparse checkout
        subprocess.run(
            ["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse", repo_url, target_dir],
            check=True,
            capture_output=True,
            text=True
        )
        # Only checkout the rules directory
        subprocess.run(
            ["git", "-C", target_dir, "sparse-checkout", "set", RULES_SUBDIR],
            check=True,
            capture_output=True,
            text=True
        )
        print(f"[+] Clone successful")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Git clone failed: {e.stderr}")
        return False
    except FileNotFoundError:
        print("[!] Git not found. Please install git and try again.")
        return False


def extract_technique_ids(threat_list):
    """Extract all MITRE technique IDs from threat entries"""
    techniques = []
    for threat_entry in threat_list:
        if threat_entry.get("framework") != "MITRE ATT&CK":
            continue
            
        technique_list = threat_entry.get("technique", [])
        if not isinstance(technique_list, list):
            continue
            
        for tech in technique_list:
            tech_id = tech.get("id", "")
            tactic = threat_entry.get("tactic", {})
            
            # Check for subtechniques
            subtechnique_list = tech.get("subtechnique", [])
            if isinstance(subtechnique_list, list) and subtechnique_list:
                for sub in subtechnique_list:
                    sub_id = sub.get("id", "")
                    if sub_id:
                        techniques.append({
                            "id": sub_id,
                            "tactic": tactic.get("name", ""),
                            "tactic_id": tactic.get("id", "")
                        })
            
            # Also add parent technique
            if tech_id:
                techniques.append({
                    "id": tech_id,
                    "tactic": tactic.get("name", ""),
                    "tactic_id": tactic.get("id", "")
                })
    
    return techniques


def parse_toml_rule(filepath):
    """Parse a single TOML rule file"""
    try:
        data = load_toml(filepath)
        rule = data.get("rule", {})
        
        # Skip if no rule section
        if not rule:
            return None
        
        # Extract basic info
        name = rule.get("name", "")
        if not name:
            return None
            
        rule_info = {
            "name": name,
            "description": rule.get("description", "")[:300],  # Truncate long descriptions
            "severity": rule.get("severity", ""),
            "risk_score": rule.get("risk_score", 0),
            "rule_id": rule.get("rule_id", ""),
            "type": rule.get("type", ""),
            "file": filepath.name,
            "platform": filepath.parent.name,
            "url": f"https://github.com/elastic/detection-rules/blob/main/rules/{filepath.parent.name}/{filepath.name}",
            "techniques": []
        }
        
        # Extract MITRE ATT&CK mappings
        threat = rule.get("threat", [])
        if isinstance(threat, list):
            rule_info["techniques"] = extract_technique_ids(threat)
        
        return rule_info if rule_info["techniques"] else None
        
    except Exception as e:
        # Silently skip problematic files
        return None


def process_rules_directory(rules_dir):
    """Process all TOML files in the rules directory"""
    rules_by_technique = {}
    stats = {"total_files": 0, "parsed": 0, "with_techniques": 0}
    
    # Find all .toml files
    toml_files = list(Path(rules_dir).rglob("*.toml"))
    stats["total_files"] = len(toml_files)
    print(f"[*] Processing {len(toml_files)} TOML files...")
    
    for filepath in toml_files:
        rule_info = parse_toml_rule(filepath)
        if rule_info:
            stats["parsed"] += 1
            if rule_info["techniques"]:
                stats["with_techniques"] += 1
                
                # Index by each technique
                for tech in rule_info["techniques"]:
                    tech_id = tech["id"]
                    if tech_id not in rules_by_technique:
                        rules_by_technique[tech_id] = []
                    
                    # Add rule entry (avoid duplicates)
                    rule_entry = {
                        "name": rule_info["name"],
                        "description": rule_info["description"],
                        "severity": rule_info["severity"],
                        "risk_score": rule_info["risk_score"],
                        "rule_id": rule_info["rule_id"],
                        "url": rule_info["url"],
                        "tactic": tech["tactic"],
                        "type": rule_info["type"],
                        "platform": rule_info["platform"]
                    }
                    
                    # Check for duplicates by rule_id
                    existing_ids = [r.get("rule_id") for r in rules_by_technique[tech_id]]
                    if rule_entry["rule_id"] not in existing_ids:
                        rules_by_technique[tech_id].append(rule_entry)
    
    return rules_by_technique, stats


def main():
    print("=" * 60)
    print("Elastic Detection Rules Fetcher")
    print("=" * 60)
    print(f"Source: {ELASTIC_RULES_REPO}")
    print(f"Output: {OUTPUT_FILE}")
    print()
    
    # Create temp directory for clone
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = os.path.join(tmpdir, "detection-rules")
        
        # Clone the repo
        if not clone_repo(ELASTIC_RULES_REPO, repo_dir):
            print("\n[!] Failed to clone repository. Creating empty output.")
            output = {
                "_info": {
                    "error": "Failed to clone repository",
                    "source": ELASTIC_RULES_REPO
                },
                "techniques": {}
            }
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                json.dump(output, f, indent=2)
            sys.exit(1)
        
        rules_dir = os.path.join(repo_dir, RULES_SUBDIR)
        
        if not os.path.exists(rules_dir):
            print(f"[!] Rules directory not found: {rules_dir}")
            sys.exit(1)
        
        # Process rules
        rules_by_technique, stats = process_rules_directory(rules_dir)
        
        # Count total rules
        total_rules = sum(len(rules) for rules in rules_by_technique.values())
        
        # Create output
        output = {
            "_info": {
                "source": "https://github.com/elastic/detection-rules",
                "generated_by": "fetch_elastic_rules.py",
                "total_files": stats["total_files"],
                "parsed_rules": stats["parsed"],
                "rules_with_techniques": stats["with_techniques"],
                "total_rules": total_rules,
                "total_techniques": len(rules_by_technique)
            },
            "techniques": rules_by_technique
        }
        
        # Write output
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
        
        # Print summary
        print()
        print("=" * 60)
        print("Summary")
        print("=" * 60)
        print(f"TOML files found:     {stats['total_files']}")
        print(f"Rules parsed:         {stats['parsed']}")
        print(f"Rules with ATT&CK:    {stats['with_techniques']}")
        print(f"Unique techniques:    {len(rules_by_technique)}")
        print(f"Total rule mappings:  {total_rules}")
        print()
        print(f"Output saved to: {OUTPUT_FILE}")
        
        # Top techniques
        if rules_by_technique:
            print()
            print("Top 10 techniques by rule count:")
            sorted_techs = sorted(rules_by_technique.items(), key=lambda x: len(x[1]), reverse=True)
            for tech_id, rules in sorted_techs[:10]:
                print(f"  {tech_id}: {len(rules)} rules")


if __name__ == "__main__":
    main()
