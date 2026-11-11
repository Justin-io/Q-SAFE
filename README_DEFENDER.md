# Q-SAFE Defender — safe MVP

This branch adds a working defensive scanner foundation. It does **not** yet provide kernel protection, real-time process monitoring, malware-family attribution, or guaranteed detection of polymorphic malware.

## What works
- Static, non-executing analysis of files.
- SHA-256 identity (sample-qualified for files larger than 8 MiB), file-type hints, entropy, and explainable indicators.
- Bounded directory scanning without following symlinks; pseudo-filesystems are excluded.
- JSONL report output.
- Explicitly confirmed, reversible quarantine and integrity-checked restore.
- Unit tests and GitHub Actions CI.

## Install and run
Requires Python 3.10+; core scanner uses only the standard library.

```bash
python -m q_safe.cli analyze ./sample.py
python -m q_safe.cli scan ~/Downloads ~/Desktop --json reports/scan.jsonl
python -m q_safe.cli quarantine ./suspicious-file --dir ~/.local/share/qsafe/quarantine --yes
python -m q_safe.cli restore ~/.local/share/qsafe/quarantine/<id>.json
python -m unittest discover -s tests -v
```

Review every finding before quarantine. Do not run routine scans as root. Never test live malware on a daily-use machine.

## Why this helps with polymorphism
Exact byte signatures fail when malware mutates its bytes. Q-SAFE records cryptographic identity while exposing entropy and other indicators. This is only initial triage. Real polymorphic detection requires normalized executable semantics and runtime behavior correlation, plus measured performance on a labeled dataset. Entropy or a packer marker is not proof of malware.

See [Threat Model](docs/THREAT_MODEL.md) and [Roadmap](docs/ROADMAP.md).

## Legacy prototype warning
The original guardian.asm, exploit_gen.py, intentionally vulnerable protected_app.c, and rootkit_installer.sh are retained as historical research/demo artifacts, but are not part of this defender and must not be run on a real host. The old assembly flow performs direct deletion and shell/LLM heuristics; it is not a safe remediation engine. The new scanner does not call these components.
