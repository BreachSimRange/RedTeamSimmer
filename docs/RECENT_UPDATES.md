[← Back to README](../README.md)

# Recent Updates

RedTeamSimmer tracks the latest MITRE ATT&CK release. The current target is **ATT&CK v19.1 (April 2026)**, which split the legacy Defense Evasion tactic into **Stealth (TA0005)** and **Defense Impairment (TA0112)**.

For full details on what changed - repo edits, API additions, per-actor emulation plan updates, atomic test coverage gaps, and what Atomic Red Team upstream still needs to ship for full v19 parity - see:

- **[UPDATES.md](UPDATES.md)** - MITRE ATT&CK v19 migration notes, coverage gap report, upstream wish-list.

Quick highlights from the v19 migration:

- Server, agent, UI, detection rule maps, and all 6 adversary emulation plans (APT3, APT28, APT41, FIN7, Lazarus Group, Wizard Spider) now declare `mitre_version: 19.1`.
- New API endpoints: `GET /api/mitre/version` and `GET /api/mitre/tactics`.
- Vendored v19 dataset at `server/mitre/attack_v19.json` with loader at `server/mitre/mitre.py`.
- Emulation plan aliases refreshed against v19 group pages (APT28 → Forest Blizzard, Lazarus → Diamond Sleet, Wizard Spider → Pistachio Tempest / FIN12, etc.).
- v19-new attributions (T1685 Disable or Modify Tools, T1686 Disable or Modify System Firewall) appended to relevant plans where Atomic Red Team coverage exists.
- Coverage gap report: 47 v19 Stealth technique IDs and 36 Defense Impairment technique IDs currently have no atomic test folder - the [UPDATES doc](UPDATES.md) lists every gap and a prioritized upstream wish-list.
