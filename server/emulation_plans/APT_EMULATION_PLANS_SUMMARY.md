# APT Emulation Plans - MITRE ATT&CK Validation Summary

## Overview
All 6 APT emulation plans have been validated against MITRE ATT&CK v19.1 with Atomic Red Team test mappings.

## Validation Results

| APT Group | MITRE ID | Attribution | Techniques | Atomic Tests | Coverage |
|-----------|----------|-------------|------------|--------------|----------|
| APT28 (Fancy Bear) | G0007 | Russia GRU Unit 26165 | 89 | 68 | 76% |
| Lazarus Group | G0032 | North Korea RGB | 112 | 89 | 79% |
| FIN7 (Carbanak) | G0046 | Financially Motivated | 67 | 56 | 84% |
| APT41 (Wicked Panda) | G0096 | China MSS | 96 | 83 | 86% |
| APT3 (Gothic Panda) | G0022 | China MSS | 44 | 41 | 93% |
| Wizard Spider | G0102 | Russia Criminal | 64 | 60 | 94% |

**Total: 472 documented techniques, 397 Atomic tests mapped**

## ATT&CK v19.1 Changes Applied

Released April 2026. Key change: **Defense Evasion (TA0003) was split into two distinct tactics:**

- **Stealth (TA0005)** - techniques focused on hiding presence, evading detection (masquerading, obfuscation, rootkits, etc.)
- **Defense Impairment (TA0112)** - techniques focused on actively degrading defensive capabilities (disabling tools, modifying security controls, policy tampering)

All existing techniques that fell under Defense Evasion have been retagged via the `v19_tactic` field in each plan. No plan retains a raw "Defense Evasion" label.

### Retagging Summary Per Plan

| Plan | Stealth Retagged | Defense Impairment Retagged | New v19 Attributions |
|------|------------------|-----------------------------|----------------------|
| APT28 | 14 | 2 | T1685, T1686 |
| APT3 | 9 | 0 | - |
| APT41 | 19 | 4 | T1685 |
| FIN7 | 12 | 3 | T1685, T1686 |
| Lazarus Group | 27 | 3 | T1685, T1686 |
| Wizard Spider | 9 | 4 | T1685 |

### New v19 Techniques Added

| Technique | Name | Tactic | Plans |
|-----------|------|--------|-------|
| T1685 | Disable or Modify Tools | Defense Impairment | APT28, APT41, FIN7, Lazarus, Wizard Spider |
| T1686 | Disable or Modify System Firewall | Defense Impairment | APT28, FIN7, Lazarus |

### v19 Attributions Without Atomic Coverage

| Plan | Techniques |
|------|------------|
| APT28 | T1211 (Exploitation for Stealth), T1684.001 (Social Engineering: Spearphishing) |
| APT41 | T1684 (Social Engineering) |
| Lazarus Group | T1684 (Social Engineering) |
| APT3, FIN7, Wizard Spider | None |

## Files

### Validated Emulation Plans (Ready for RedTeamSimmer)
1. `APT28_MITRE_VALIDATED.json` - 68 validated tests
2. `Lazarus_Group_MITRE_VALIDATED.json` - 89 validated tests
3. `FIN7_MITRE_VALIDATED.json` - 56 validated tests
4. `APT41_MITRE_VALIDATED.json` - 83 validated tests
5. `APT3_MITRE_VALIDATED.json` - 41 validated tests
6. `Wizard_Spider_MITRE_VALIDATED.json` - 60 validated tests

## Key Findings

### Techniques Without Atomic Coverage (Common Gaps)

**Infrastructure Acquisition (T1583.xxx)**
- Domains, Web Services, Serverless infrastructure
- Cannot be safely simulated in test environments

**Reconnaissance (T1595.xxx, T1591.xxx)**
- Vulnerability scanning, organization info gathering
- Pre-attack phase techniques

**Capability Development (T1587.xxx, T1608.xxx)**
- Malware development, exploit creation
- Development-phase techniques

**Advanced Persistence**
- T1542.003 - Bootkits (APT41)
- T1546.011 - Application Shimming (FIN7)

### Notable Techniques by Group

**APT28 (Russia GRU)**
- Credential harvesting via phishing
- X-Tunnel/X-Agent C2 infrastructure
- Olympic Destroyer, NotPetya associations

**Lazarus (North Korea)**
- Largest technique set (112 techniques, 89 with Atomic coverage)
- Financial theft focus (SWIFT attacks)
- Custom malware development (Destover, RATANKBA)

**FIN7 (Financial)**
- Point-of-sale targeting
- Carbanak/Cobalt Strike usage

**APT41 (China MSS - Dual Mission)**
- Both espionage and financial operations
- Supply chain compromises (T1195.002)
- Bootkit deployment capability

**APT3 (Gothic Panda)**
- Highest Atomic coverage (93%)
- MITRE official adversary emulation plan exists
- Browser exploitation focus

**Wizard Spider (Russia Criminal)**
- Highest coverage among large groups (94%)
- TrickBot, Ryuk, Conti ransomware
- MITRE Engenuity ATT&CK Evaluations 2022
- Healthcare sector targeting

## Usage with RedTeamSimmer

Each validated JSON file contains:
- Group metadata (MITRE ID, aliases, attribution, `mitre_version: 19.1`)
- `v19_tactic` field on all techniques affected by the Defense Evasion split
- `v19_changes` block documenting what changed per plan
- MITRE reference evidence for each technique
- Pre-mapped Atomic Red Team test commands

Example test execution:
```powershell
# Load emulation plan
$plan = Get-Content "APT41_MITRE_VALIDATED.json" | ConvertFrom-Json

# Execute specific tests
foreach ($test in $plan.AtomicTests) {
    Invoke-Expression $test.Command
}
```

## Data Sources
- MITRE ATT&CK v19.1 (April 2026)
- Atomic Red Team Framework
- MITRE Engenuity ATT&CK Evaluations
- CTI reports from CrowdStrike, Mandiant, FireEye, CISA

---
Generated: June 5, 2026
Validated against: MITRE ATT&CK v19.1
