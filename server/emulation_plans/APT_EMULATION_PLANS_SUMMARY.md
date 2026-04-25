# APT Emulation Plans - MITRE ATT&CK Validation Summary

## Overview
All 6 APT emulation plans have been validated against MITRE ATT&CK v18 with Atomic Red Team test mappings.

## Validation Results

| APT Group | MITRE ID | Attribution | Techniques | Atomic Tests | Coverage |
|-----------|----------|-------------|------------|--------------|----------|
| APT28 (Fancy Bear) | G0007 | Russia GRU Unit 26165 | 66 | 50 | 76% |
| Lazarus Group | G0032 | North Korea RGB | 110 | 87 | 79% |
| FIN7 (Carbanak) | G0046 | Financially Motivated | 65 | 54 | 83% |
| APT41 (Wicked Panda) | G0096 | China MSS | 95 | 82 | 86% |
| APT3 (Gothic Panda) | G0022 | China MSS | 44 | 41 | 93% |
| Wizard Spider | G0102 | Russia Criminal | 63 | 59 | 94% |

**Total: 443 documented techniques, 373 Atomic tests mapped**

## Files Generated

### Validated Emulation Plans (Ready for RedTeamSimmer)
1. `APT28_MITRE_VALIDATED.json` - 66 validated tests
2. `Lazarus_Group_MITRE_VALIDATED.json` - 87 validated tests  
3. `FIN7_MITRE_VALIDATED.json` - 54 validated tests
4. `APT41_MITRE_VALIDATED.json` - 82 validated tests
5. `APT3_MITRE_VALIDATED.json` - 41 validated tests
6. `Wizard_Spider_MITRE_VALIDATED.json` - 59 validated tests

### Original Unvalidated Plans (For Reference)
- `APT28_FancyBear.json`
- `Lazarus_Group.json`
- `FIN7_Carbanak.json`
- `APT41_WickedPanda.json`
- `APT3_GothicPanda.json`
- `Wizard_Spider_Conti.json`

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
- T1674 - Input Injection/BadUSB (FIN7)

### Notable Techniques by Group

**APT28 (Russia GRU)**
- Credential harvesting via phishing
- X-Tunnel/X-Agent C2 infrastructure
- Olympic Destroyer, NotPetya associations

**Lazarus (North Korea)**
- Most diverse technique set (110 techniques)
- Financial theft focus (SWIFT attacks)
- Custom malware development (Destover, RATANKBA)

**FIN7 (Financial)**
- Point-of-sale targeting
- Carbanak/Cobalt Strike usage
- BadUSB physical access attacks

**APT41 (China MSS - Dual Mission)**
- Both espionage and financial operations
- Supply chain compromises
- Bootkit deployment capability

**APT3 (China MSS)**
- Highest Atomic coverage (93%)
- MITRE official adversary emulation plan exists
- Browser exploitation focus

**Wizard Spider (Russia Criminal)**
- TrickBot, Ryuk, Conti ransomware
- MITRE Engenuity ATT&CK Evaluations 2022
- Healthcare sector targeting

## Usage with RedTeamSimmer

Each validated JSON file contains:
- Group metadata (MITRE ID, aliases, attribution)
- MITRE reference evidence for each technique
- Pre-mapped Atomic Red Team test commands
- Coverage statistics

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
- MITRE ATT&CK v18 (December 2025)
- Atomic Red Team Framework
- MITRE Engenuity ATT&CK Evaluations
- CTI reports from CrowdStrike, Mandiant, FireEye, CISA

---
Generated: December 21, 2025
Validated against: MITRE ATT&CK v18
