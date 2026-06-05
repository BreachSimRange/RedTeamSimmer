# RedTeamSimmer — MITRE ATT&CK v19 Migration

**Target framework:** MITRE ATT&CK **v19.1**, released **2026-04-28**
**Migration date:** 2026-05-20
**Source:** [https://attack.mitre.org/resources/updates/updates-april-2026/](https://attack.mitre.org/resources/updates/updates-april-2026/)

This document tracks the migration of the server, agent, UI, detection mapping, and adversary emulation plans from ATT&CK v18 to v19, plus the gap analysis between v19 and the local Atomic Red Team library.

---

## 1. What changed in MITRE ATT&CK v19

The April 2026 release split the **Defense Evasion** tactic into two tactics:

| New tactic | ID | Focus |
|---|---|---|
| **Stealth** | TA0005 (kept) | Concealment: masquerading, obfuscation, indicator removal, hide artifacts, process injection, valid accounts |
| **Defense Impairment** | TA0112 (new) | Active degradation of defenses: disable/modify tools, modify registry, subvert trust, weaken encryption |

Enterprise tactic count went from 14 → **15**. Reconnaissance and Resource Development remain in the framework but are hidden in the UI because no Windows atomic tests target them.

Ten of the v19-new techniques relevant to this project:

| ID | Name | Tactic |
|---|---|---|
| T1685 | Disable or Modify Tools | Defense Impairment |
| T1686 | Disable or Modify System Firewall | Defense Impairment |
| T1687 | Exploitation for Defense Impairment | Defense Impairment |
| T1688 | Safe Mode Boot | Defense Impairment |
| T1689 | Downgrade Attack | Defense Impairment |
| T1690 | Prevent Command History Logging | Defense Impairment |
| T1678 | Delay Execution | Stealth |
| T1679 | Selective Exclusion | Stealth |
| T1684 | Social Engineering | Stealth |
| T1211 | Exploitation for Stealth | Stealth |

---

## 2. Files changed in this repo

### New
| Path | Purpose |
|---|---|
| `server/mitre/attack_v19.json` | Vendored v19 dataset: 15 tactics, Stealth + Defense Impairment technique lists, crosswalk |
| `server/mitre/mitre.py` | Loader exposing `get_tactics()`, `tactic_for_technique()`, `canonical_tactic_order()` |
| `server/mitre/__init__.py` | Package init |
| `docs/UPDATES.md` | This file |

### Modified
| Path | Change |
|---|---|
| `server/app.py` | Imports v19 loader; `TACTIC_NAME_MAP` rewritten (Stealth + Defense Impairment, legacy Defense Evasion → Stealth); new `_apply_v19_tactic_mapping()` re-homes techniques per v19; new endpoints `GET /api/mitre/version` and `GET /api/mitre/tactics`; `/api/emulation_plans` listing now surfaces `mitre_version`, `mitre_released`, `v19_changes` |
| `agent/agent.go` | `const MitreVersion = "19.1"`; registration + telemetry payloads include `mitre_version` |
| `server/detection/attack_rule_map.json` | 152 entries tagged with `tactic_v19` / `tactic_v19_short` for techniques in the Stealth or Defense Impairment buckets |
| `server/detection/elastic_rules.json` | 759 Defense Evasion entries re-tagged (685 → Stealth, 74 → Defense Impairment); originals preserved in `tactic_v18`; `_info.mitre_version` set |
| `server/static/ui.html` | Hard-coded `mitreTacticOrder` updated to v19; icons 🥷 + 🧯; v19 badge near the MITRE ATT&CK pill. **Hard-coded `MITRE_TACTICS` array, `TECHNIQUE_TO_TACTIC` map (~175 entries), and the inline `techToTactic` / `tacticColors` / `tacticIcons` blocks in `renderEmulationTactics()` were all removed.** Replaced with a single client-side `mitreCache` hydrated from `/api/mitre/tactics?all=1` and `/api/mitre/technique_tactic_map`. Net result: zero hard-coded technique IDs anywhere in `ui.html`. |
| `server/static/css/style-2.css` | Replaced `.tactic-defense-evasion` with `.tactic-stealth` + `.tactic-defense-impairment` |
| `server/emulation_plans/*.json` (×6) | Top-level `mitre_version`, `mitre_released`, `v19_changes` blocks; `validation_notes` bumped to v19.1; aliases refreshed against v19 group pages; existing tests tagged with `v19_tactic` / `v19_tactic_short`; v19-new attributions appended as new `AtomicTests` flagged `v19_new: true` |

### Untouched (by design)
- `server/atomic/atomics/` — upstream Atomic Red Team library; treat as a third-party dependency. Tactic translation is done in server code, not by editing upstream files.
- `server/atomic/atomics/Indexes/Attack-Navigator-Layers/*.json` — these say `"attack":"18"` but get regenerated upstream; out of scope.

---

## 3. API surface

| Endpoint | Auth | Behavior |
|---|---|---|
| `GET /api/mitre/version` | public | Returns `{"version":"19.1","released":"2026-04-28","source":...}` |
| `GET /api/mitre/tactics` | public | Canonical v19 tactic list in display order. Reconnaissance + Resource Development hidden by default. Pass `?all=1` to include them. |
| `GET /api/mitre/technique_tactic_map` | public | Flat `{technique_id: {tactic_id, tactic_name, tactic_short}}` map derived from the live atomics index + v19 Stealth/Defense Impairment split. Replaces the previous client-side hard-coded `TECHNIQUE_TO_TACTIC` JSON blob. |
| `GET /api/techniques` | login | Adds top-level `mitre_version` and `mitre_released`; techniques are re-homed to Stealth / Defense Impairment per v19. |
| `GET /api/emulation_plans` | login | Listing now includes `mitre_version`, `mitre_released`, `v19_changes`. |

---

## 4. Adversary emulation plans

All 6 plans migrated to v19.1. Counts:

| Plan | Group | Aliases | Tests | Stealth retagged | Defense Impair. retagged | v19-new appended | Attributed w/o atomic coverage |
|---|---|---|---|---|---|---|---|
| APT28 | G0007 | 16 | 66 → **68** | 14 | 0 | T1685, T1686 | T1211, T1684.001 |
| APT3 | G0022 | 7 | 41 | 9 | 0 | — | — |
| APT41 | G0096 | 5 | 82 → **83** | 19 | 3 | T1685 | T1684 |
| FIN7 | G0046 | 6 | 54 → **56** | 12 | 1 | T1685, T1686 | — |
| Lazarus | G0032 | 7 | 87 → **89** | 27 | 1 | T1685, T1686 | T1684 |
| Wizard Spider | G0102 | 11 | 59 → **60** | 9 | 3 | T1685 | — |

Aliases refreshed against the v19 group pages (e.g. APT28 → Forest Blizzard, FROZENLAKE, GruesomeLarch; Lazarus → Diamond Sleet; Wizard Spider → Periwinkle Tempest, Pistachio Tempest, FIN12).

Each plan carries a `v19_changes` block with:
- `tactic_split` notice
- `existing_tests_retagged` counts (Stealth / Defense Impairment)
- `v19_new_attributions_added` (list of technique IDs)
- `v19_attributed_without_atomic_coverage` (technique IDs newly attributed in v19 that have no Atomic Red Team YAML yet)
- `source` (link to the live MITRE group page)

---

## 5. Gap analysis — Atomic Red Team coverage of v19

The Atomic Red Team library on this checkout is current as of upstream master, but several v19 technique IDs have no Atomic test coverage. This is split into two tiers:

### 5a. Zero coverage (no atomic folder exists)

These v19 technique IDs have no directory under `server/atomic/atomics/`, so there are no atomic tests at all.

**Stealth (TA0005) — 47 IDs with zero coverage**

T1134, T1134.001, T1134.002, T1134.003, T1134.004, T1134.005, T1678, T1480, T1480.001, T1480.002, T1211, T1574, T1574.001, T1574.004, T1574.005, T1574.006, T1574.007, T1574.008, T1574.009, T1574.010, T1574.011, T1574.012, T1574.013, T1574.014, T1542, T1542.001, T1542.002, T1542.003, T1542.004, T1542.005, T1679, T1684, T1684.001, T1684.002, T1205, T1205.001, T1205.002, T1535, T1078, T1078.001, T1078.002, T1078.003, T1078.004, T1497, T1497.001, T1497.002, T1497.003

**Defense Impairment (TA0112) — 36 IDs with zero coverage**

T1484, T1484.001, T1484.002, T1687, T1556, T1556.001–.009, T1578, T1578.001–.005, T1666, T1601, T1601.001, T1601.002, T1599, T1599.001, T1553, T1553.001–.006, T1600, T1600.001, T1600.002

### 5b. Sub-technique without a dedicated YAML

These sub-technique IDs sit under a parent folder that *does* exist, but no dedicated YAML targets the sub-tech specifically. Some are still covered by tests inside the parent YAML — manual review needed to confirm. Listed for completeness:

**Stealth (83 sub-techniques)** — under T1564, T1070, T1036, T1027, T1055, T1218, T1216, T1127.
**Defense Impairment (11 sub-techniques)** — under T1686 (.001–.003), T1685 (.001–.006), T1222 (.001, .002).

Note: where the parent YAML exists (e.g. `T1685.yaml` with 76 Windows tests), the plans can still invoke specific sub-test numbers via `Invoke-AtomicTest T1685 -TestNumbers N`. Dedicated sub-tech YAMLs are nice-to-have for cleaner mapping but not strictly required.

---

## 6. What Atomic Red Team upstream needs to do for full v19 parity

Filed as an upstream wish-list, ordered by impact:

1. **Add atomic tests for v19-new defense-impairment techniques without coverage:**
   - **T1687 Exploitation for Defense Impairment** — no folder.
   - **T1685 sub-techniques** (.001 Windows Event Log, .002 Cloud Log, .003 Tool UI, .004 Linux Audit, .005 Clear Windows Logs, .006 Clear Linux/Mac Logs) — parent has 76 Windows tests but no dedicated sub-tech YAMLs.
   - **T1686 sub-techniques** (.001 Cloud Firewall, .002 Network Device Firewall, .003 Windows Host Firewall) — same situation: parent has 25 Windows tests, no dedicated sub-tech YAMLs.

2. **Add atomic tests for v19-new stealth techniques without coverage:**
   - **T1678 Delay Execution** — no folder, but widely used (sleep-loop trojans, scheduled triggers, environmental delays).
   - **T1679 Selective Exclusion** — no folder.
   - **T1684 Social Engineering** (incl. .001 Impersonation, .002 Email Spoofing) — no folder. Hard to atomic-test ethically but at least .002 (SPF/DMARC bypass via spoofed envelope-from) is automatable.
   - **T1211 Exploitation for Stealth** — no folder.

3. **Add atomic tests for major existing Stealth techniques that gained no coverage:**
   - **T1134 Access Token Manipulation** and all 5 sub-techniques (.001–.005) — entire tree is uncovered. This is one of the most-attributed techniques across G0007, G0032, G0046, G0096, G0102 and should be the top priority.
   - **T1480 Execution Guardrails** + .001 Environmental Keying + .002 Mutual Exclusion.
   - **T1574 Hijack Execution Flow** and all 13 sub-techniques.
   - **T1542 Pre-OS Boot** and all 5 sub-techniques.
   - **T1497 Virtualization/Sandbox Evasion** and all 3 sub-techniques.
   - **T1078 Valid Accounts** and all 4 sub-techniques.
   - **T1205 Traffic Signaling** + .001 Port Knocking + .002 Socket Filters.
   - **T1535 Unused/Unsupported Cloud Regions**.

4. **Add atomic tests for Defense Impairment techniques migrated from v18 with no coverage:**
   - **T1556 Modify Authentication Process** + all 9 sub-techniques (largest gap in this bucket).
   - **T1553 Subvert Trust Controls** + all 6 sub-techniques.
   - **T1578 Modify Cloud Compute Infrastructure** + all 5 sub-techniques.
   - **T1484 Domain or Tenant Policy Modification** + .001 Group Policy + .002 Trust Modification.
   - **T1601 Modify System Image** + .001 + .002.
   - **T1599 Network Boundary Bridging** + .001 NAT Traversal.
   - **T1600 Weaken Encryption** + .001 + .002.
   - **T1666 Modify Cloud Resource Hierarchy**.

5. **Regenerate Navigator layers against v19.** The 13 files under `server/atomic/atomics/Indexes/Attack-Navigator-Layers/` declare `"attack":"18"`; they should be regenerated against the v19 STIX bundle so the `attack` field matches `windows-index.md`'s already-v19 tactic headers (`# stealth`, `# defense-impairment`).

6. **Bump the README badge.** `server/atomic/README.md` advertises `Atomics-1797`; the actual YAML count on this checkout is 1,764. Either real or just stale badge — worth aligning.

---

## 7. Validation

Smoke-tested end-to-end on 2026-05-20:

```
GET /api/mitre/version       → 200, {"version":"19.1", "released":"2026-04-28"}
GET /api/mitre/tactics       → 200, 13 tactics in canonical v19 order
GET /api/mitre/tactics?all=1 → 200, 15 tactics (Reconnaissance + Resource Development included)
GET /api/techniques          → 200, mitre_version=19.1; Stealth=68, Defense Impairment=18
GET /api/emulation_plans     → 200, all 6 plans declare mitre_version=19.1
```

Agent: `GOOS=windows go build ./...` clean.

JSON validity: all 6 emulation plan files parse; all carry `mitre_version: "19.1"`; none retain the literal `"v18"` token in `validation_notes`.

---

## 8. Next steps (open items)

- [ ] Monitor upstream Atomic Red Team for new T1685/T1686 sub-technique YAMLs and migrate the per-plan `Invoke-AtomicTest` commands from parent to sub-tech IDs when they land.
- [ ] If/when MITRE publishes v19.2 with further actor-attribution updates, refresh `aliases` and `v19_attributed_without_atomic_coverage` on each plan.
- [ ] Consider regenerating `server/atomic/atomics/Indexes/Attack-Navigator-Layers/*.json` against v19 STIX so the `attack` version field is consistent with the rest of the project. (Out of scope for this migration — atomics folder is treated as read-only.)
- [ ] Add atomic test coverage for T1687, T1678, T1679, T1684, T1211 once upstream merges them.

---

## 9. Reference

- v19 release page: [https://attack.mitre.org/resources/updates/updates-april-2026/](https://attack.mitre.org/resources/updates/updates-april-2026/)
- Stealth (TA0005): [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)
- Defense Impairment (TA0112): [https://attack.mitre.org/tactics/TA0112/](https://attack.mitre.org/tactics/TA0112/)
- Atomic Red Team upstream: [https://github.com/redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team)
