# <Malware/Family> — <one-line what it is>

**Actor:** <group, e.g. MuddyWater> · **Malware:** <family> · **First seen:** <date>
**TLP:** CLEAR · **Report date:** <YYYY-MM-DD> · **Author:** Anas

## Executive summary
<3-5 sentences a decision-maker can read: what it is, who's behind it, what it does, why it matters, and that detections are provided.>

## Attribution
<Who, and how confident. State a level — high / moderate / low — and the *basis*: code overlap, infrastructure, targeting, TTPs, or corroborating vendor reporting. Be honest; hedged is fine.>

- **Assessment:** <e.g. Assessed with moderate confidence to be MuddyWater (Iran-nexus).>
- **Basis:** <what supports it>

## Sample
| | |
|---|---|
| SHA-256 | `<hash>` |
| Type / size | <PE / .NET / script — size> |
| First seen (VT) | <date> |
| Detection at analysis | <e.g. 3/63> |

_(Sample not included — pull it yourself from MalwareBazaar/VT by the hash.)_

## Analysis — how it works
<The heart of the report. Infection chain, capabilities, C2 protocol, persistence, anti-analysis. Reference the evidence in `evidence/`. This is what makes the report original rather than a rehash.>

## TTPs (MITRE ATT&CK)
| Tactic | Technique | ID | How it shows up here |
|---|---|---|---|
| <tactic> | <technique> | <Txxxx> | <observed behavior> |

## Detection
Multi-surface — see `yara/`, `sigma/`, `suricata/`.

- **YARA** (`yara/<name>.yar`): <what it keys on — the durable invariant, and why. Tuned with `N of them` for variant robustness.>
- **Sigma** (`sigma/<name>.yml`): <the host behavior it catches.>
- **Suricata** (`suricata/<name>.rules`): <the C2 traffic it catches.>

### Evasions & limitations (honest)
<What beats each rule. Packing/obfuscation, variant drift, encrypted C2. Naming the gaps is what makes it credible.>

## IOCs
Context, not a dump. Full machine-readable set in `iocs/iocs.csv`.

| Indicator | Type | Context |
|---|---|---|
| `<hash>` | SHA-256 | the analyzed sample |
| `<domain>` | domain | C2 |
| `<ip>` | IPv4 | C2 |

## References
<Primary sources, corroborating vendor reports, ATT&CK, LOLBAS, Malpedia.>
