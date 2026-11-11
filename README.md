# Q-SAFE — Defensive Endpoint Triage

Q-SAFE is an early-stage defensive endpoint-security project. The active implementation is the Python package in `q_safe/`. It inspects files as inert data, produces explainable static indicators, writes JSONL scan reports, and offers explicit, reversible quarantine.

> **Capability boundary:** Q-SAFE is not yet an antivirus replacement. The current release does not prove that a file is safe, does not attribute malware families, and does not reliably detect polymorphic malware. Packed/high-entropy files are triage candidates, not confirmed malware.

## Current MVP

- Static analysis without importing, sourcing, or executing scanned files.
- SHA-256 identity (sample-qualified when a file exceeds the 8 MiB inspection limit).
- File-type hints, byte entropy, packer markers, and suspicious script indicators.
- Bounded directory traversal that avoids symlinks and excludes pseudo-filesystems.
- JSONL reports and reversible quarantine with integrity-checked restore.
- Unit tests and GitHub Actions CI.

## Quick start

Requires Python 3.10+.

```bash
python -m q_safe.cli analyze ./sample.py
python -m q_safe.cli scan ~/Downloads ~/Desktop --json reports/scan.jsonl
python -m unittest discover -s tests -v
```

Quarantine only after reviewing evidence:

```bash
python -m q_safe.cli quarantine ./suspicious-file --dir ~/.local/share/qsafe/quarantine --yes
python -m q_safe.cli restore ~/.local/share/qsafe/quarantine/<id>.json
```

Do not run routine scans as root. Q-SAFE never automatically deletes files or kills processes.

## Polymorphic malware: engineering approach

A polymorphic sample can change its byte-level representation while preserving behavior. Exact hashes and fixed strings cannot solve this. A mature Q-SAFE detector must correlate normalized executable semantics (imports, strings, opcode/basic-block and control-flow features), packer/section indicators, runtime behavior (process ancestry, persistence writes, privilege changes and network activity), and provenance/reputation. It must be measured against labeled samples with family/time-separated evaluation and published false-positive/false-negative rates. Entropy alone is not a malware verdict.

See [Threat Model](docs/THREAT_MODEL.md) and [Roadmap](docs/ROADMAP.md).

## Legacy prototype components

The original assembly guardian, LLM triage scripts, control-flow hashing demo, and dashboard were research prototypes—not a safe endpoint-defense chain. They are not used by the current CLI. The old assembly flow included direct file deletion and shell-built commands; the former run script recreated a destructive shell script. Vulnerable/exploit demonstrations have been disabled or made inert on this branch. Inspect the history or original `main` branch for research context; do not execute old binaries or legacy scripts on a production host.
