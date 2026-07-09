# BugSleep (MuddyWater) — Detections & IOCs

Deployable detection content for **BugSleep**, the custom backdoor MuddyWater (aka Static Kitten / Mercury / Seedworm / Earth Vetala) has used since mid-2024. I reverse-engineered a live sample myself and validated everything here against it in a lab.

**The full story — the analysis, the screenshots, the whole walkthrough — is on Medium:**
- Part 1 · *BugSleep, Unmasked* — reverse-engineering it (and the 6-byte trick that hid it) → **_add link_**
- Part 2 · *Catching MuddyWater Live* — detonating it and catching it on SIEM, IDS & EDR → **_add link_**

This repo is just the artifacts you can drop straight into your tooling.

## What's in here
| File | What it's for |
|---|---|
| `yara/bugsleep.yar` | on-disk rule (subtract-6 decrypt-loop bytes + imphash + process hit-list) and an in-memory rule for the decrypted payload |
| `sigma/` | remote-thread injection into `msedge`, `PackageManager` persistence (drop + exec), C2 IP, `Public\a.txt` staging |
| `suricata/bugsleep.rules` | the C2 beacon to the hardcoded IP over 443 |
| `splunk/bugsleep_detections.conf` | the same detections as Splunk saved-searches |
| `tools/bugsleep_config_extractor.py` | decrypts a sample's config (subtract-6) from the file alone — no detonation needed |
| `iocs/iocs.csv` | machine-readable IOCs |

## IOCs (quick reference)
| Indicator | Type | Context |
|---|---|---|
| `73c677dd3b264e7eb80e26e78ac9df1dba30915b5ce3b1bc1c83db52b9c6b30e` | SHA-256 | analyzed sample |
| `5d30c32f609687ca146ba5bde4bc6d09` | imphash | pivot for related builds |
| `91.235.234.202` | IPv4 | C2 — hardcoded, no DNS, non-TLS over 443 |
| `PackageManager` | mutex | single-instance guard |
| `C:\ProgramData\PackageManager\PackageManager.exe` | path | persistence self-copy |
| `C:\Users\Public\a.txt` | file | C2 command staging |

Full machine-readable set is in `iocs/iocs.csv`.

## Notes
- **No sample in this repo** — pull it from MalwareBazaar by the hash above.
- The config cipher is a per-byte subtract; the key varies between samples (6 and 8 both appear in this one), so the extractor brute-forces it rather than hardcoding a key.
- Everything's mapped to MITRE ATT&CK — the *why* behind each rule is in the Medium write-ups.

TLP:CLEAR · MIT License
