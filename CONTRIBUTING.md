# Contributing to Q-SAFE

Thank you for helping improve Q-SAFE. Contributions should make defensive analysis safer, more reproducible, and easier to audit.

## Scope

Useful contributions include:
- Safer file-format parsing and bounded static feature extraction.
- Explainable detections with evidence, confidence limitations, and false-positive tests.
- Evaluation tooling, calibration, family-disjoint and time-based validation.
- Documentation, packaging, accessibility, CI, and reproducible benchmarks.
- Defensive integrations that do not silently execute samples or upload private files.

## Security and sample-handling rules

- Never execute, load, or interpret submitted malware samples in CI.
- Do not commit malware binaries, private samples, credentials, API keys, or personal data.
- Keep test inputs synthetic, minimal, and harmless wherever possible.
- Use a disposable, isolated lab for any dynamic analysis; do not add dynamic execution to the default scanner.
- Do not add automatic deletion, process termination, firewall changes, or other disruptive response actions.
- Any quarantine-related change must preserve explicit operator confirmation, integrity verification, and safe restore semantics.
- Treat filenames, file contents, archive metadata, strings, and model outputs as untrusted data.

## Development

Requirements: Python 3.10 or newer.

```sh
python -m unittest discover -s tests -v
python qsafe.py scan ./safe-test-fixtures
```

Optional integrations such as YARA, ClamAV, capa, Streamlit, and ssdeep must remain optional. Core scanning must not require network access or elevated privileges for user-owned files.

## Pull requests

Please include:
1. The problem and security impact.
2. A concise description of the implementation.
3. Tests covering normal, malformed, boundary, and failure cases where applicable.
4. Any new dependency and its license.
5. Evaluation data provenance and limitations for detection changes.
6. Documentation updates for changed behavior and limitations.

Do not claim detection accuracy, production readiness, or malware-family coverage without reproducible held-out evaluation results.

## Reporting vulnerabilities

Do not publish exploit details or live malware samples in public issues. Follow the private reporting instructions in [SECURITY.md](SECURITY.md).