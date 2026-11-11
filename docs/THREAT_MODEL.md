# Q-SAFE Threat Model (MVP)

## Purpose
Q-SAFE is a defensive endpoint file-triage prototype. It inspects files as data, emits explainable indicators, and supports reversible quarantine. It does not claim to identify every malware family or prove that a file is safe.

## In scope
- Script-based droppers and suspicious command chains.
- Obfuscated/dynamically executed scripts.
- Packed or encrypted executable candidates (heuristic only).
- File mutation or replacement that changes a recorded cryptographic identity.
- Reversible evidence preservation for investigation.

## Out of scope for this MVP
Full behavioural malware detection, kernel rootkits, memory-only/fileless malware, firmware threats, exploit prevention, network intrusion detection, and guaranteed polymorphic-family attribution. No automatic deletion, process termination, firewall changes, kernel hooks, or unattended privileged operation.

## Trust boundaries
- Scanned files are untrusted data; never imported, sourced, executed, or passed to a shell.
- LLM output, if later integrated, is advisory and cannot trigger remediation.
- Quarantine requires explicit confirmation, same-filesystem atomic move, restrictive permissions, SHA-256 verification, and refuses overwrite on restore.

## Polymorphism detection strategy
Polymorphic malware changes byte-level representation while preserving behavior. Exact hashes and static strings are insufficient. A mature detector must correlate stable semantic features (imports, normalized strings, opcode/basic-block and control-flow features), packing indicators (section entropy, permissions, import sparsity, overlays), runtime behavior (process lineage, persistence writes, privilege changes, network destinations), and provenance/reputation. No single signal is decisive. Calibrate on a labeled corpus and report false-positive/false-negative rates. Unknowns remain REVIEW.

## Safety controls
Start with user-owned directories; exclude pseudo-filesystems by default; do not run as root for routine scans; avoid destructive remediation; never shell out with file paths or model-generated content; test with inert synthetic fixtures.
