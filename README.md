# Threat Intelligence & Malware Analysis

Original analysis of real malware, turned into detections and feeds. Each report takes a live sample, works out how it operates, attributes it, and ships **multi-surface detection** — YARA (file/memory), Sigma (host logs), Suricata (C2 on the wire) — plus contextualized IOCs a SOC can actually use.

No sample binaries live here (see the safety note below). What you get is the analysis, the detections, the IOCs, and the evidence.

Every report maps to **MITRE ATT&CK**, states attribution with a confidence level, and is honest about what the detection misses. Analysis is done in an isolated lab (REMnux + FLARE-VM with a sinkholed network) and the detections are validated against real telemetry.

---

## How each report is structured

```
reports/<actor>_<malware>/
  README.md            # the report: summary → attribution → analysis → TTPs → detection → IOCs
  yara/<name>.yar      # file / memory detection
  sigma/<name>.yml     # host-log detection (portable to any SIEM)
  suricata/<name>.rules# C2 network signatures
  iocs/iocs.csv        # hashes, domains, IPs - with context (+ STIX bundle where useful)
  evidence/            # screenshots of analysis + detections firing (never samples)
```

## The method (every report follows it)

1. **Acquire & verify** — pull the sample from a repository, record the hash, note first-seen and tags.
2. **Analyze** — static (Ghidra/DIE/CAPA/FLOSS) and dynamic (detonation in an isolated lab with a network sinkhole) to work out capabilities, C2, and persistence.
3. **Attribute** — tie it to an actor/family with a stated confidence level and the basis for it.
4. **Detect** — write YARA, Sigma, and Suricata against what the analysis revealed, tuned for variant robustness.
5. **Contextualize the IOCs** — not a dump; each indicator gets meaning.
6. **Map & report** — TTPs to ATT&CK, write it up honestly (including detection gaps), and export a feed.

## Reports

| Actor | Malware | ATT&CK focus | Detection | Status |
|---|---|---|---|---|
| _tbd (region-relevant APT)_ | _tbd_ | _tbd_ | YARA · Sigma · Suricata | in progress |

_More as they're published. Coverage tracked against the ATT&CK Navigator._

---

## Safety & responsible handling

- **No malware samples are published in this repository — ever.** Reports reference samples by SHA-256 only. If you want to reproduce the analysis, pull the sample yourself from a trusted repository (MalwareBazaar, VirusTotal) using the hash.
- All analysis is performed in an **isolated lab** with a sinkholed network — nothing detonates with a route to a real network.
- Detections and IOCs are shared for defensive use.

## About

Threat intelligence & detection engineering by **Anas-SEC** — building toward the SANS SCyWF Threat Management role (Threat Intelligence Analyst / Threat Hunter). Companion detection-engineering repo: the detection library.
