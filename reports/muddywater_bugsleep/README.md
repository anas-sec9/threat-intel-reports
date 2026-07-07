# BugSleep — MuddyWater's C/C++ backdoor

**Actor:** MuddyWater (Iran / MOIS; aka Static Kitten, Mercury, Seedworm, TA450) · **Malware:** BugSleep · **First seen:** May 2024
**TLP:** CLEAR · **Report date:** 2026-07-07 · **Author:** Anas · **Status:** complete (Tier 1–3 + in-memory config extraction; Tier 4 optional)

## Executive summary
BugSleep is a custom C/C++ backdoor MuddyWater (Iran-nexus) has deployed via phishing since mid-2024, built to run operator commands and move files to and from its C&C. This report documents an **independent, hands-on analysis** of a live sample in an isolated lab — not a rehash of vendor reporting. I detonated the sample, captured its C&C behavior with a network sinkhole, and dumped its **decrypted configuration straight out of memory** to recover indicators the on-disk file keeps encrypted. Key findings: the sample **injects into `msedge.exe`** and beacons to a **hardcoded IP (`91.235.234.202:443`) with no DNS lookup**, persists as a self-copy masquerading as `C:\ProgramData\PackageManager\PackageManager.exe`, and stages C&C data through `C:\Users\Public\a.txt`. The report ships **two YARA rules** (on-disk + in-memory), **four Sigma rules**, and **Suricata** coverage — mapped to MITRE ATT&CK and validated in the lab.

## Attribution
- **Assessment:** BugSleep is attributed to **MuddyWater** with high confidence by multiple vendors (Check Point, Group-IB). This report analyzes a sample from that family.
- **Basis:** family tags on the sample source, code/behavior consistency with published BugSleep reporting (to be confirmed through our own analysis).

## Sample
| | |
|---|---|
| SHA-256 | `73c677dd3b264e7eb80e26e78ac9df1dba30915b5ce3b1bc1c83db52b9c6b30e` |
| Size | 246,784 bytes (~241 KB) |
| Type | PE Windows executable (confirmed via magika) |
| First seen (VT) | _tbd_ |
| Detection at analysis | _tbd_ |

_(Sample not included — pull it from MalwareBazaar by the hash.)_

## Analysis — how it works
Following the FOR610 four-tier method (see `ANALYSIS_PLAN.md`).

**Tier 1 — triage:** done. 64-bit PE, ~241 KB, `magika` = PE Windows executable.

**Tier 2 — static properties:** done.
- **Not packed.** DIE flags high-entropy `.text` (entropy 7.46), but the code entrypoint is a normal function prologue and the binary uses **dynamic API resolution** — that's the source of the entropy, not a third-party packer.
- **Compiler:** Microsoft Visual C/C++ (VS 2019, LTCG). **Compile stamp: 2024-05-31** — consistent with BugSleep's mid-2024 emergence.
- **Minimal imports** (KERNEL32 only) — APIs resolved at runtime. CAPA confirms: *access PEB ldr_data*, *resolve function by parsing PE exports*, *link function at runtime (×5)*.
- **Executes shellcode via indirect call** (CAPA) — injection/execution primitive.
- **Anti-analysis:** references analysis-tool strings / process detection (CAPA) — checks for analysis tooling.
- **Process hit-list** (from FLOSS): `msedge.exe`, `opera.exe`, `chrome.exe`, `anydesk.exe`, `Onedrive.exe`, `svchost.exe`, `powershell.exe` — injection / masquerade targets. Basis of the v1 YARA rule.

**Tier 3 — behavior:** done (detonation + FakeNet-NG).
- **C&C: `91.235.234.202:443`.** Reached with **no preceding DNS lookup** (hardcoded IP — legit browser traffic always resolves a hostname first), beaconing every **~60–80 seconds** for hours.
- **Process injection into `msedge.exe` (T1055) — confirmed.** HollowsHunter dumped the injected region from msedge, and it **contains the C&C IP `91.235.234.202` as a literal string** (legit Edge code never does) — proving BugSleep injects its payload into Edge and hides its beacon in normal browser traffic. The dumped region is the malware's **decrypted payload in memory** (source for extracting the mutex + full config). The beacon persisted as the host msedge PID rotated (8324 → 4996 → …), re-establishing inside Edge. Custom protocol over 443 (FakeNet logged the connection but no parseable HTTP — not standard TLS).
- **Persistence + config recovered from memory (bridges Tier 3→4).** HollowsHunter scanned every process and dumped the injected region from `msedge.exe`; `strings` on that dump returned the **decrypted config** the on-disk file keeps encrypted: C&C `91.235.234.202`, self-copy path `C:\ProgramData\PackageManager\PackageManager.exe`, injection target `msedge.exe`, and staging file `C:\Users\Public\a.txt`. A base64 alphabet and `WinSock 2.0` sit adjacent to the config — consistent with base64-framed C&C over a raw socket. (Confirmed the encryption boundary: FLOSS on the *file* recovered the process hit-list but **not** the C&C — the config is only plaintext in memory.)
- **Mutex:** created via `CreateMutexW`, but the name is **built at runtime** (not a static plaintext string), so its exact value needs Tier 4 to trace the argument. Not required for the shipped detections.

**Tier 4 — code reversing:** optional / future work (Ghidra — recover the exact config-decryption algorithm + key to build a config extractor for *other* samples, and the runtime mutex name).

## TTPs (MITRE ATT&CK)
_From CAPA (static); expanded after behavioral analysis._

| Tactic | Technique | ID |
|---|---|---|
| Execution | Native API / Shared Modules | T1106 / T1129 |
| Defense Evasion | Obfuscated Files or Information (dynamic API resolution) | T1027 |
| Defense Evasion | Reflective / shellcode execution | T1620 |
| Discovery | Process Discovery (anti-analysis tool check) | T1057 |
| Discovery | Debugger/Sandbox Evasion | T1622 |
| Defense Evasion | Process Injection into msedge.exe (remote thread) | T1055 / T1055.003 |
| Persistence / Defense Evasion | Self-copy masquerading as `PackageManager.exe` | T1036.005 |
| Collection | Local data staging (`C:\Users\Public\a.txt`) | T1074.001 |
| Command & Control | Non-Application-Layer / custom protocol over 443 | T1571 / T1095 |

## Detection
Multi-surface, validated in the lab. All rules in `yara/`, `sigma/`, `suricata/`.

**YARA — `yara/bugsleep.yar`** (two rules, two surfaces):
- `BugSleep_MuddyWater_file` — the **on-disk** sample. Because the config is encrypted on disk, this keys on the plaintext process hit-list (`msedge/opera/chrome/anydesk/onedrive/svchost/powershell`, `5 of 7`) **or** the imphash `5d30c32f609687ca146ba5bde4bc6d09`, gated on MZ + `<400KB`.
- `BugSleep_MuddyWater_memory` — the **decrypted payload in memory / process dumps** (e.g. the injected msedge region). Keys on the config strings that only exist once decrypted (`91.235.234.202`, `PackageManager.exe`, `\ProgramData\PackageManager\`, `\Users\Public\a.txt`, the Edge path), `3 of them`.

**Sigma — `sigma/`:**
- `bugsleep_persistence_packagemanager.yml` — execution from `C:\ProgramData\PackageManager\PackageManager.exe` (persistence/masquerade). *high.*
- `bugsleep_msedge_remote_thread.yml` — **behavioral**: a remote thread created in `msedge.exe` by any non-Edge process (Sysmon EID 8). Catches the injection technique independent of sample/C&C. *high.*
- `bugsleep_c2_ip.yml` — outbound connection to `91.235.234.202`. *high.*
- `bugsleep_public_staging_file.yml` — creation of `\Users\Public\a.txt`. *medium; high when correlated.*

**Suricata — `suricata/bugsleep.rules`:** traffic to the C&C IP, plus non-TLS traffic on TCP/443 to it (the custom protocol on the HTTPS port).

### Evasions & limitations (honest)
- **File-YARA drift:** MuddyWater recompiles frequently — the imphash and hit-list can change across builds. The behavioral Sigma (remote thread into Edge) is the durable layer.
- **IP-based rules rot:** `91.235.234.202` will rotate. Treat the C&C IP/Suricata rules as time-boxed IOCs; the injection and persistence detections are the lasting value.
- **No payload content signature yet:** the beacon is a custom protocol, so Suricata is IP/anomaly-based, not content-based. A payload signature needs Tier 4 protocol reversing.
- **Mutex not shipped:** built at runtime, not a static string — deliberately left out rather than guessed.

## IOCs
| Indicator | Type | Context |
|---|---|---|
| `73c677dd3b264e7eb80e26e78ac9df1dba30915b5ce3b1bc1c83db52b9c6b30e` | SHA-256 | analyzed sample |
| `5d30c32f609687ca146ba5bde4bc6d09` | imphash | import-hash pivot |
| `91.235.234.202` | IPv4 | C&C (beacon over TCP/443, ~60-80s interval) |
| `91.235.234.202:443` | C&C | reached via injected `msedge.exe` |
| `C:\ProgramData\PackageManager\PackageManager.exe` | path | self-copy for persistence (masquerades as "PackageManager") |
| `C:\Users\Public\a.txt` | file | C&C command staging / output file |
| `PackageManager.exe` | filename | dropped persistence binary |

## References
- Check Point Research — MuddyWater deploys BugSleep
- Group-IB — MuddyWater 2025 tracking
