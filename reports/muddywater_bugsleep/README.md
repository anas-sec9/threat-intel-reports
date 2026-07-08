# BugSleep — MuddyWater's C/C++ backdoor

**Actor:** MuddyWater (Iran / MOIS; aka Static Kitten, Mercury, Seedworm, TA450) · **Malware:** BugSleep · **First seen:** May 2024
**TLP:** CLEAR · **Report date:** 2026-07-07 · **Author:** Anas · **Status:** complete (Tier 1–4; config cipher recovered + extractor shipped)

## Executive summary
BugSleep is a custom C/C++ backdoor MuddyWater (Iran-nexus) has deployed via phishing since mid-2024, built to run operator commands and move files to and from its C&C. This report documents an **independent, hands-on analysis** of a live sample in an isolated lab — not a rehash of vendor reporting. I detonated the sample, captured its C&C behavior with a network sinkhole, and dumped its **decrypted configuration straight out of memory** to recover indicators the on-disk file keeps encrypted. Key findings: the sample **injects into `msedge.exe`** and beacons to a **hardcoded IP (`91.235.234.202:443`) with no DNS lookup**, persists as a self-copy masquerading as `C:\ProgramData\PackageManager\PackageManager.exe`, and stages C&C data through `C:\Users\Public\a.txt`. Reversing the sample in Ghidra recovered its config cipher — a trivial per-byte subtract-6 — so the repo also ships a **config extractor** that decrypts *future* BugSleep samples from the file alone, no detonation needed. The report ships **two YARA rules** (on-disk + in-memory), **four Sigma rules**, **Suricata** coverage, and the extractor — mapped to MITRE ATT&CK and validated in the lab.

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
- **Not packed — self-decrypting.** DIE flags high-entropy `.text` (entropy 7.46) and CAPA reads "dynamic API resolution," but Tier 4 shows the real cause: the code section is stored under a **subtract-6 byte cipher** and unpacked at runtime by an unencrypted stub. Static tools only ever saw the stub — there is no third-party packer.
- **Compiler:** Microsoft Visual C/C++ (VS 2019, LTCG). **Compile stamp: 2024-05-31** — consistent with BugSleep's mid-2024 emergence.
- **Minimal imports** (KERNEL32 only) — APIs resolved at runtime. CAPA confirms: *access PEB ldr_data*, *resolve function by parsing PE exports*, *link function at runtime (×5)*.
- **Executes shellcode via indirect call** (CAPA) — injection/execution primitive.
- **Anti-analysis:** references analysis-tool strings / process detection (CAPA) — checks for analysis tooling.
- **Process hit-list** (from FLOSS): `msedge.exe`, `opera.exe`, `chrome.exe`, `anydesk.exe`, `Onedrive.exe`, `svchost.exe`, `powershell.exe` — injection / masquerade targets. Basis of the v1 YARA rule.

**Tier 3 — behavior:** done (detonation + FakeNet-NG).
- **C&C: `91.235.234.202:443`.** Reached with **no preceding DNS lookup** (hardcoded IP — legit browser traffic always resolves a hostname first). We observed reconnections every **~60–80 seconds**, but that is the **retry rate under the FakeNet sinkhole** (the handshake never completes, so it keeps reconnecting) — **not** the true beacon interval. Check Point documents a ~30-minute call-home; treat our fast interval as a sinkhole artifact.
- **Process injection into `msedge.exe` (T1055) — confirmed.** HollowsHunter dumped the injected region from msedge, and it **contains the C&C IP `91.235.234.202` as a literal string** (legit Edge code never does) — proving BugSleep injects its payload into Edge and hides its beacon in normal browser traffic. The dumped region is the malware's **decrypted payload in memory** (source for extracting the mutex + full config). The beacon persisted as the host msedge PID rotated (8324 → 4996 → …), re-establishing inside Edge. Custom protocol over 443 (FakeNet logged the connection but no parseable HTTP — not standard TLS).
- **Persistence + config recovered from memory (bridges Tier 3→4).** HollowsHunter scanned every process and dumped the injected region from `msedge.exe`; `strings` on that dump returned the **decrypted config** the on-disk file keeps encrypted: C&C `91.235.234.202`, self-copy path `C:\ProgramData\PackageManager\PackageManager.exe`, injection target `msedge.exe`, and staging file `C:\Users\Public\a.txt`. Two alpha-only alphabets (`a-z`, `A-Z`) and `WinSock 2.0` sit adjacent to the config; Tier 4 showed those alphabets feed a **random-string generator** (not base64), and `WinSock 2.0` is the raw-socket C2. **We did not reverse the C2 wire format** — per public reporting it's encrypted with the same subtract cipher; our confidence there is *moderate, from vendor reporting*, not our own analysis.
- **Mutex: `PackageManager`** (single-instance guard). Recovered in x64dbg with a breakpoint on `CreateMutexW` — the `lpName` argument (R8) pointed to `L"PackageManager"`. Session-local (no `Global\` prefix).
- **Injection-target selection loop.** In memory next to the process hit-list sit `Process32FirstW` / `Process32NextW` — BugSleep walks the running process list to locate its injection host (`msedge.exe`, `opera.exe`, …).

**Single naming theme — "PackageManager".** The mutex (`PackageManager`), the persistence copy (`PackageManager.exe`), and its folder (`\ProgramData\PackageManager\`) all share one label. Any host showing that mutex **and** that file/folder is BugSleep with near-zero false positives — the strongest host hunt in this report.

**Tier 4 — code reversing (x64dbg + Ghidra): complete.**
- **Mutex name:** `PackageManager` (x64dbg breakpoint on `CreateMutexW`, `lpName` in R8).
- **Not packed — self-decrypting via a trivial subtract-6 byte cipher.** In Ghidra the startup stub calls `VirtualProtect(image_base+0x1000, 0x23940, PAGE_EXECUTE_READWRITE)` and then subtracts `6` from every byte of the code section, and it decrypts individual config strings with an SSE loop — `PSUBB XMM0, XMM6` where `XMM6` = sixteen `0x06` bytes — over `0x30`-byte chunks (decrypt loop at RVA `0x24af0`). So:

  ```
  plaintext[i] = (ciphertext[i] - 6) & 0xFF      key = 0x06
  ```

  Verified by decrypting the on-disk ciphertext Ghidra shows at the config address: `giqgmksgtgmkxbv` → `ackagemanager\p` (the middle of `…packagemanager\packagemanager…`).
- **This explains Tier 2.** The "dynamic API resolution / high-entropy `.text`" that static tools reported is simply the `-6`-encrypted real code — the automated tools only ever saw the unencrypted stub. It was never a third-party packer.
- **Config extractor shipped:** [`tools/bugsleep_config_extractor.py`](tools/bugsleep_config_extractor.py) subtracts 6 across a sample and surfaces the config IOCs (C&C, paths, mutex, exe names). Works across the BugSleep family as long as the cipher constant holds (`--key` to adjust if a variant changes it). This is the highest-value output of the analysis: it triages *future* BugSleep samples from the file alone, without detonation.

## TTPs (MITRE ATT&CK)
_From CAPA (static); expanded after behavioral analysis._

| Tactic | Technique | ID |
|---|---|---|
| Execution | Native API / Shared Modules | T1106 / T1129 |
| Defense Evasion | Obfuscated Files or Information (subtract-6 self-encrypted code) | T1027 |
| Defense Evasion | Deobfuscate/Decode Files or Information (runtime subtract-6 unpack) | T1140 |
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
- `BugSleep_MuddyWater_file` — the **on-disk** sample. Keys on the **subtract-6 decrypt-loop code bytes** (`$decrypt` — the strongest signal, survives config/C&C changes) **or** the imphash `5d30c32f609687ca146ba5bde4bc6d09` **or** the plaintext process hit-list (`5 of 7`), gated on MZ + `<400KB`.
- `BugSleep_MuddyWater_memory` — the **decrypted payload in memory / process dumps** (e.g. the injected msedge region). Keys on the config strings that only exist once decrypted (`91.235.234.202`, `PackageManager.exe`, `\ProgramData\PackageManager\`, `\Users\Public\a.txt`, the Edge path), `3 of them`.

**Sigma — `sigma/`:**
- `bugsleep_persistence_packagemanager.yml` — execution from `C:\ProgramData\PackageManager\PackageManager.exe` (persistence/masquerade). *high.*
- `bugsleep_msedge_remote_thread.yml` — **behavioral**: a remote thread created in `msedge.exe` by any non-Edge process (Sysmon EID 8). Catches the injection technique independent of sample/C&C. *high.*
- `bugsleep_c2_ip.yml` — outbound connection to `91.235.234.202`. *high.*
- `bugsleep_public_staging_file.yml` — creation of `\Users\Public\a.txt`. *medium; high when correlated.*

**Suricata — `suricata/bugsleep.rules`:** traffic to the C&C IP, plus non-TLS traffic on TCP/443 to it (the custom protocol on the HTTPS port).

**Config extractor — `tools/bugsleep_config_extractor.py`:** applies the recovered subtract-6 cipher to a sample and surfaces its config IOCs (C&C, paths, mutex, exe names) from the file alone — triage future BugSleep samples without detonation.

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
| `91.235.234.202` | IPv4 | C&C over TCP/443 (hardcoded, no DNS; ~30-min beacon per vendor reporting) |
| `91.235.234.202:443` | C&C | reached via injected `msedge.exe` |
| `C:\ProgramData\PackageManager\PackageManager.exe` | path | self-copy for persistence (masquerades as "PackageManager") |
| `C:\Users\Public\a.txt` | file | in config; likely C&C command staging/output (inferred from nearby file APIs — not directly observed) |
| `PackageManager.exe` | filename | dropped persistence binary |
| `PackageManager` | mutex | single-instance guard (`CreateMutexW`, session-local) |

## Validation against public reporting
This analysis was done independently in a home lab, then cross-checked against vendor reporting. Where they agree, it corroborates the work; where they differ, it's noted honestly.

| Finding (ours) | Public reporting | Verdict |
|---|---|---|
| Config/code = per-byte **subtract-6** cipher (Ghidra `PSUBB XMM0,XMM6`) | Check Point/Talos: strings/config encrypted by subtracting a hardcoded byte; **shellcode subtracted by 6** | **Confirmed** — derived independently |
| Injects into `msedge`/`opera`/`chrome`/`anydesk`/`onedrive`/`powershell` via `WriteProcessMemory`+`CreateRemoteThread`+`VirtualProtectEx` | Same target list and same injection APIs | **Confirmed** |
| Edge chosen as injection host | Check Point: a failed inject only crashes the browser, safer than system processes | **Confirmed** |
| Backdoor: command exec + file transfer, sleep evasion | Same | **Confirmed** |
| Mutex `PackageManager` (x64dbg) | Not enumerated in the summaries reviewed | **Our direct observation** (sample-specific) |
| C&C `91.235.234.202:443` | Vendor IOC lists carry other IPs; ours is sample-specific | **Our direct observation** |
| Beacon `~60–80s` | Check Point: **~30 min** | **Corrected** — ours is a FakeNet retry artifact, not the real beacon |
| C2 wire format | Encrypted (vendor); Talos rebuilt a C2 server + Snort rules | **Not reversed by us** — deferred |

## References
- Check Point Research — [New BugSleep Backdoor Deployed in Recent MuddyWater Campaigns](https://research.checkpoint.com/2024/new-bugsleep-backdoor-deployed-in-recent-muddywater-campaigns/)
- Cisco Talos — [Writing a BugSleep C2 server and detecting its traffic with Snort](https://blog.talosintelligence.com/writing-a-bugsleep-c2-server/)
- BleepingComputer — [New BugSleep malware implant deployed in MuddyWater attacks](https://www.bleepingcomputer.com/news/security/new-bugsleep-malware-implant-deployed-in-muddywater-attacks/)
- MITRE ATT&CK; MalwareBazaar (sample by hash)
