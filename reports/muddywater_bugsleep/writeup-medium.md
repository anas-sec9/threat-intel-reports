# How a 6-Byte Trick Hid an Iranian APT's Backdoor — and How I Caught It in My Home Lab

*An end-to-end walkthrough: from a raw sample to a reversed cipher, a config extractor, and detections that actually fire. No vendor sandbox, no magic button — just a lab I built and a lot of coffee.*

> [HERO IMAGE: a warrior / armored Persian-cat "APT" figure standing over a cracked laptop — set the tone. Caption idea: "MuddyWater brought a backdoor. I brought a debugger."]

---

## Before we start

I'm a SOC and detection-engineering guy. Most of my day is rules, alerts, and telling people why their "critical" isn't actually critical. But writing detections for malware I've never opened myself always felt a little like reviewing a movie from the poster. So I decided to stop doing that.

The plan was simple: take a real backdoor from a real nation-state crew, tear it apart *myself*, and only then write the detections. Everything below happened on my own machines. If I got something wrong, I left it in and corrected it — because pretending you nailed everything on the first try is how you end up sounding like a vendor press release.

The target: **BugSleep**, MuddyWater's custom backdoor.

---

## Who is MuddyWater, and what is BugSleep?

MuddyWater is an Iran-nexus group (you'll also see them as Static Kitten, Mercury, Seedworm, TA450). They're tied to Iranian intelligence and they spend a lot of their time on targets across the Middle East — including my part of the world. Phishing is their bread and butter.

BugSleep is a backdoor they started throwing around in mid-2024. It's not fancy on paper: run the operator's commands, move files in and out, phone home. But the interesting part is *how* it hides — and that's what this whole post is about.

> [MEME: "It's just a simple backdoor" — followed by "5 hours in Ghidra later" reaction image.]

---

## The lab

Nothing exotic. A Windows analysis VM (FLARE-VM) fully isolated on a host-only network, with **FakeNet-NG** playing the role of "the entire internet" so the malware talks to *me* instead of its real C2. Snapshot before detonation, revert after. The usual RE toolbox: DIE, PEStudio, FLOSS, CAPA, x64dbg, Ghidra, HollowsHunter.

I pulled the sample from MalwareBazaar by hash. Sample of the day:

```
SHA-256  73c677dd3b264e7eb80e26e78ac9df1dba30915b5ce3b1bc1c83db52b9c6b30e
Size     246,784 bytes
Type     64-bit PE, MSVC (Visual Studio 2019)
```

> [SCREENSHOT: MalwareBazaar page for the hash — proves provenance.]

I worked it in four tiers, the classic malware-analysis flow: automated triage → static properties → dynamic behavior → manual reversing. Let me take you through it the way it actually happened.

---

## Tier 1 & 2 — the "hmm, that's weird" phase

First look was normal. 64-bit PE, compiled with VS2019, timestamp around May 2024 — lines up perfectly with when BugSleep first showed up.

> [SCREENSHOT: DIE showing the compiler + entropy.]

Then the tools started disagreeing with each other. DIE flagged the `.text` section as high-entropy (7.46), which usually screams "packed." But the entry point looked like a totally normal function, and there was no packer signature anywhere. PEStudio showed almost **no imports** — just KERNEL32 — which is the classic sign of a program that resolves its API calls at runtime to stay quiet.

> [SCREENSHOT: PEStudio — tiny import table + imphash 5d30c32f609687ca146ba5bde4bc6d09.]

CAPA agreed and labeled it "dynamic API resolution," "parses PE exports," "executes shellcode." FLOSS pulled out a very telling list of strings:

```
msedge.exe   opera.exe   chrome.exe   anydesk.exe   Onedrive.exe   svchost.exe   powershell.exe
```

> [SCREENSHOT: FLOSS output with the process list.]

A backdoor carrying a hit-list of browsers and remote-access tools? That's an **injection target list**. So at this point my working theory was: this thing hides inside a normal process. Hold that thought — it comes back in a big way.

> [MEME: the "everybody stay calm — it's PACKED" panic image. Spoiler: it was not packed. It was much dumber and much more clever at the same time.]

---

## Tier 3 — let it run and watch it lie

I lit up FakeNet-NG and detonated the sample. Almost immediately, this showed up in the log:

> [SCREENSHOT: FakeNet log — outbound to 91.235.234.202 on 443.]

A connection to **91.235.234.202 on port 443**. Looks like HTTPS, right? Except two things bugged me:

1. There was **no DNS lookup** before it. None. A real browser *always* resolves a hostname first. This thing went straight to a hardcoded IP.
2. FakeNet's HTTPS listener caught the connection but couldn't parse a real TLS handshake out of it.

So: hardcoded IP, port 443 to blend in, but *not actually TLS*. That's a backdoor wearing an HTTPS costume. This is my C2.

But here's the thing that made me sit up — the beacon was coming from **msedge.exe**. The browser. And when I watched the process IDs, the beaconing Edge process kept changing. The malware wasn't running as itself. It had crawled *inside Edge*.

> [MEME: "malware hiding inside your browser like it pays rent" — the Homer-disappearing-into-the-bush gif works great here.]

---

## Proving the injection (not just assuming it)

Saying "it injects into Edge" is easy. Proving it is the job. I ran **HollowsHunter**, which scans every process for implanted/injected code and dumps it.

> [SCREENSHOT: HollowsHunter summary — 10 suspicious, msedge flagged.]

Now, HollowsHunter's aggressive mode is noisy — it flagged my PowerShell windows, FakeNet, even itself. Browsers throw false positives all day because of JavaScript JIT. So "msedge got flagged" is **not** proof on its own, and I want to be honest about that.

So I did the real test: I searched every dumped region for the C2 IP.

> [SCREENSHOT: the grep/Select-String hit — 91.235.234.202 found inside the msedge dump.]

There it was. The C2 IP `91.235.234.202`, sitting as a plaintext string **inside a memory region dumped from Edge**. Legitimate Edge code does not contain an Iranian C2 address. That's not a JIT false positive — that's BugSleep's payload, decrypted, living inside the browser. Injection: confirmed, with evidence.

That same dump handed me the rest of the config in plaintext:

```
C:\ProgramData\PackageManager\PackageManager.exe   ← persistence copy (masquerade)
C:\Users\Public\a.txt                              ← C2 staging file (likely)
C:\Program Files (x86)\Microsoft\Edge\...\msedge.exe
```

---

## The mutex — five minutes in a debugger

I wanted the mutex name (great for hunting), so I loaded the sample in x64dbg, set one breakpoint on `CreateMutexW`, and hit run. When it broke, the third argument — the mutex name — was sitting right there in a register:

> [SCREENSHOT: x64dbg paused at CreateMutexW, R8 = L"PackageManager".]

**`PackageManager`.** And that's when I noticed the joke this malware is playing: the mutex is `PackageManager`, the persistence file is `PackageManager.exe`, the folder is `\ProgramData\PackageManager\`. It picked one boring, legit-sounding name and used it for *everything*. Which — annoying for a defender to spot at a glance, but a gift once you know it. One host with that mutex **and** that file **and** that folder? That's BugSleep. Nearly zero false positives.

---

## Tier 4 — the 6-byte punchline

This is the part I actually came for. Everything above told me *what* it does. I wanted to know *how* the config was hidden — because if I could crack that, I could decrypt **any** BugSleep sample, not just this one.

I opened the sample in Ghidra, found the function that touches the config data, and stared at this little loop:

> [SCREENSHOT: Ghidra listing — the decrypt loop at RVA 0x24af0.]

```asm
MOVDQA XMM6, [key]        ; XMM6 = 0x06 repeated 16 times
LEA    RSI, [config]
loop:
  MOVDQU XMM0, [RAX+RSI]  ; read 16 encrypted bytes
  PSUBB  XMM0, XMM6       ; subtract 6 from every byte
  MOVDQU [RAX+RSI], XMM0  ; write it back
  ADD    RAX, 0x10
  CMP    RAX, 0x30
  JL     loop
```

That's it. That's the "encryption." **It subtracts 6 from every byte.**

All that entropy, all the "packed!" panic, the "dynamic API resolution" the automated tools kept reporting — the real code was just sitting there minus 6. A decryptor stub flips the whole code section back with `VirtualProtect` + subtract-6 and jumps in. There's no packer. There never was.

> [MEME: the "is this a packer?" butterfly meme — "No, it's arithmetic."]

I didn't want to take Ghidra's word for it, so I grabbed the encrypted bytes it showed me on disk and did the subtraction by hand:

> [SCREENSHOT: the little script — "giqgmksgtgmkxbv" minus 6 = "ackagemanager\p".]

`giqgmksgtgmkxbv` − 6 = `ackagemanager\p` — the middle of `...packagemanager\packagemanager...`. It decrypts cleanly. The cipher is real and it's `plaintext = ciphertext − 6`.

---

## Turning that into a weapon: a config extractor

A single decrypted sample is nice. A tool that decrypts the *whole family* is better. Since the cipher is just "subtract 6," I wrote a small extractor that applies it across any BugSleep sample and pulls the config straight out — C2, paths, mutex, everything — **without ever running the malware**.

> [SCREENSHOT: bugsleep_config_extractor.py output — C2, path, mutex recovered from the file.]

That's the difference between "I looked at one sample" and "hand me the next one and I'll triage it in ten seconds."

---

## The detections

Reversing is fun, but detection is the point. I shipped a full set, all in the repo:

- **YARA (file)** — keys on the exact **decrypt-loop code bytes**. This is the strong one: it survives the crew rotating the C2 or recompiling, because the cipher stub barely changes.
- **YARA (memory)** — catches the *decrypted* payload in a process dump (the version living inside Edge).
- **Sigma** — the behavioral winner is "a remote thread created in `msedge.exe` by a non-Edge process." That catches the *technique*, not this one sample. Plus rules for the `PackageManager` persistence path, the C2 IP, and the `Public\a.txt` staging file.
- **Suricata** — traffic to the C2, and non-TLS traffic on 443 to it.

> [SCREENSHOT: a snippet of the YARA decrypt-loop rule.]

---

## IOCs

```
SHA-256   73c677dd3b264e7eb80e26e78ac9df1dba30915b5ce3b1bc1c83db52b9c6b30e
imphash   5d30c32f609687ca146ba5bde4bc6d09
C2        91.235.234.202:443   (hardcoded, no DNS, custom non-TLS)
mutex     PackageManager
persist   C:\ProgramData\PackageManager\PackageManager.exe
staging   C:\Users\Public\a.txt
cipher    plaintext = ciphertext - 6
```

---

## Grab everything

Full report, all rules, the config extractor, and the raw IOCs are on my GitHub: **github.com/anas-sec9/threat-intel-reports** → `reports/muddywater_bugsleep`.

If you read this far — thanks. Go open a sample yourself. It's more fun than the poster.

> [FOOTER IMAGE / MEME: "one sample down, the whole APT to go" — end on something light.]
