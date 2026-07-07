# BugSleep (MuddyWater) — analysis plan

Working plan for the analysis. Follows the FOR610 four-tier methodology (fully-automated → static properties → interactive behavior → manual code reversing), mapped onto our lab (REMnux static hub + FLARE-VM detonation/RE + FakeNet-NG sinkhole). Each tier feeds specific detection surfaces.

**Target:** BugSleep — MuddyWater's C/C++ backdoor (phishing-delivered since May 2024). Known traits to confirm: heavy `Sleep()` sandbox evasion, dynamic API resolution, mutex creation, decrypts a config holding C&C IP/port, supports command execution + file transfer.

**Deliverables this produces:** `yara/` (from static), `sigma/` (from behavior), `suricata/` (from network), `iocs/` (config/C2), and the report `README.md`.

---

## Tier 1 — Fully-automated triage (5 min)
**Goal:** identify the file, confirm it's our target, record provenance. *(FLARE-VM, no execution.)*
- Record **SHA-256** (`Get-FileHash`), file size, and the MalwareBazaar tags.
- File type / architecture — `magika` or DIE.
- Note VT first-seen date + detection ratio (from the sample page) — establishes how fresh/covered it is.
- **Record for report:** hash, type, first-seen, family confirmation.

## Tier 2 — Static properties analysis (the YARA + first IOCs)
**Goal:** everything we can learn *without running it*. This is where the YARA rule is born. *(FLARE-VM tools.)*
- **Packer / entropy** — Detect It Easy (DIE): packed or plain? compiler? (BugSleep is typically unpacked C/C++.)
- **PE metadata** — PEStudio / PE-bear: sections, entrypoint, compile timestamp, imphash, anomalies (flagged imports, high-entropy sections).
- **Imports (IAT)** — the API surface hints at capability: look for `Sleep`/`WaitForSingleObject` (evasion), `CreateMutex` (mutex), `GetProcAddress`/`LoadLibrary` (dynamic API resolution), `VirtualAlloc`/`WriteProcessMemory` (injection), socket APIs (C2).
- **Strings** — FLOSS (includes deobfuscated/stack strings): mutex name, C&C artifacts, command keywords, error strings, PDB path. These become YARA strings + IOCs.
- **Capabilities** — CAPA: maps observed capabilities to MITRE ATT&CK automatically — a huge head start on the TTP table.
- **Record for report:** imphash, mutex, notable strings, CAPA capabilities → **draft the YARA rule** on the durable, distinctive strings/imports (tuned `N of them`, not `all of them`).

## Tier 3 — Interactive behavioral analysis (the Sigma + Suricata surfaces)
**Goal:** run it and watch. *(FLARE-VM detonation, snapshot first, FakeNet-NG as sinkhole.)*
- **Baseline** — Regshot snapshot #1 (registry + filesystem) of the clean box.
- **Instrument** — start **Procmon** (filter to the sample + children), **Process Hacker/System Informer**, and **FakeNet-NG** (fakes DNS/HTTP/etc + logs all traffic).
- **Detonate** the sample. Watch: process tree, files dropped, registry keys (persistence), the mutex it creates, and — critically — the **C&C connection attempt** FakeNet captures (IP/port/protocol/beacon).
- **Baseline #2** — Regshot snapshot #2, diff against #1 → exact persistence + dropped-file artifacts.
- **Record for report:** process lineage, persistence mechanism, mutex, files, and the C2 request → **Sigma** (host behavior) + **Suricata** (the beacon/protocol).
- Revert FLARE-VM to `flare-clean` after.

## Tier 4 — Manual code reversing (the crown jewels)
**Goal:** understand the logic that static/behavior can't fully show. *(Ghidra / x64dbg.)*
- Confirm the **Sleep-based evasion** at entry and the **dynamic API resolution** routine.
- Find the **mutex** creation (exact name → strong IOC + detection).
- Find and understand the **config decryption routine** — the algorithm + key that reveal the **C&C IP/port**. This is the highest-value finding: it lets us decrypt configs from *other* samples and produces the best network IOCs.
- **Record for report:** the decryption method, config structure, and any config we can extract → **IOCs** + a config-extractor note for the writeup.

---

## Detection mapping (what each tier gives us)
| Surface | Comes from | Keys on |
|---|---|---|
| **YARA** | Tier 2 (static) | distinctive strings (mutex, commands), imphash, code constants |
| **Sigma** | Tier 3 (behavior) | process lineage, mutex, persistence key, dropped files |
| **Suricata** | Tier 3 (network) | the C2 beacon / protocol pattern |
| **IOCs** | Tiers 2 + 4 | hash, mutex, C&C IP/port (from config decryption) |

## Rules of engagement (safety)
- Sample stays inside FLARE-VM (isolated). Snapshot before detonation, revert after.
- Never the whole sample in the repo — hash only.
- Validate our findings against public reporting (Check Point/Group-IB) — agree where we should, and note where we go further (the multi-surface detections + measured rules).
