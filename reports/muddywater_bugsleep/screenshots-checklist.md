# BugSleep write-up — screenshot checklist

Capture order matches the Medium post. "Have it" = you already captured this during the analysis session and can reuse it. Save each as `NN_short-name.png` in a `screenshots/` folder so I can slot them into the markers.

## Provenance
- [ ] **01 — MalwareBazaar page** for hash `73c677dd…6b30e`. Must show: the hash, the BugSleep/MuddyWater family tag, first-seen date. *(browser — need to capture)*
  - → maps to: intro `[SCREENSHOT: MalwareBazaar page…]`

## Tier 1–2 (static)
- [ ] **02 — DIE**: entropy of `.text` (7.46) + compiler = Microsoft Visual C/C++ 2019. *(have it)*
  - → `[SCREENSHOT: DIE showing the compiler + entropy]`
- [ ] **03 — PEStudio**: tiny import table (KERNEL32 only) + imphash `5d30c32f609687ca146ba5bde4bc6d09` + compile timestamp. *(recapture — clean)*
  - → `[SCREENSHOT: PEStudio — tiny import table + imphash]`
- [ ] **04 — FLOSS**: the process hit-list strings (`msedge/opera/chrome/anydesk/onedrive/svchost/powershell`). *(have it)*
  - → `[SCREENSHOT: FLOSS output with the process list]`
- [ ] **05 — CAPA**: the ATT&CK capabilities (dynamic API resolution / parse PE exports / execute shellcode). *(recapture)*
  - → `[SCREENSHOT: CAPA]`

## Tier 3 (dynamic)
- [ ] **06 — FakeNet-NG log**: the outbound to `91.235.234.202:443` with NO preceding DNS. *(have it — you pasted this)*
  - → `[SCREENSHOT: FakeNet log — outbound to 91.235.234.202 on 443]`
- [ ] **07 — HollowsHunter summary**: `Total suspicious: 10`, with `msedge.exe` in the list. *(have it)*
  - → `[SCREENSHOT: HollowsHunter summary — 10 suspicious, msedge flagged]`
- [ ] **08 — the proof**: `Select-String` finding `91.235.234.202` inside the `process_556\*.shc` msedge dump. *(have it)* ← **this is the injection proof, important**
  - → `[SCREENSHOT: the grep/Select-String hit — 91.235.234.202 found inside the msedge dump]`
- [ ] **09 — x64dbg mutex**: paused at `CreateMutexW`, Registers panel showing `R8 = L"PackageManager"`. *(have it)*
  - → `[SCREENSHOT: x64dbg paused at CreateMutexW, R8 = L"PackageManager"]`

## Tier 4 (reversing) — the money shots
- [ ] **10 — Ghidra decrypt loop** ⭐: the listing at RVA `0x24af0` — `MOVDQU / PSUBB XMM0,XMM6 / MOVDQU / ADD / CMP / JL`. Make this one crisp and readable. *(have it — recapture clean/zoomed)*
  - → `[SCREENSHOT: Ghidra listing — the decrypt loop at RVA 0x24af0]`
- [ ] **11 — hand-decrypt proof** ⭐: the little script output `giqgmksgtgmkxbv` → `ackagemanager\p`. *(recapture — run the one-liner)*
  - → `[SCREENSHOT: the little script — "giqgmksgtgmkxbv" minus 6 = "ackagemanager\p"]`

## Payoff
- [ ] **12 — extractor output** ⭐: the run you just did — plaintext hit-list + `shift 6` / `shift 8` config recovered from the encrypted file. *(have it — clean re-run is fine)*
  - → `[SCREENSHOT: bugsleep_config_extractor.py output]`
- [ ] **13 — YARA rule snippet**: the `$decrypt` hex string in `bugsleep.yar`. *(easy — open the file)*
  - → `[SCREENSHOT: a snippet of the YARA decrypt-loop rule]`

## Images (not screenshots)
- [ ] **Hero** — warrior / armored-cat APT figure (generate or grab royalty-free).
- [ ] **Memes** — (a) "everybody panic — PACKED" ; (b) malware hiding in Edge ; (c) "is this a packer? / no, arithmetic" butterfly.

---
### Priority if short on time
The three ⭐ (10 Ghidra loop, 11 hand-decrypt, 12 extractor) carry the story. Get those crisp; the rest are supporting.
