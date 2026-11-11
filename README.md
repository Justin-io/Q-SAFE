# Q-SAFE — Local-First Malware Triage & Defense

Q-SAFE is a defensive local-first file inspection tool. It combines static file-format inspection, entropy and packing indicators, suspicious API/string analysis, script heuristics, polling-based change monitoring, and SHA-256-verified quarantine.

**It does not execute inspected samples and does not claim that a heuristic score proves malware.** Polymorphic malware mutates its representation; hashes and fixed signatures alone are insufficient. Q-SAFE therefore reports a *polymorphic candidate* only when executable-format and packing/entropy signals converge. That result is a triage lead, not proof.

## Capabilities

- Read-only recursive scan of files/directories; does not follow symlinks; 64 MiB per-file ceiling.
- SHA-256, format identification, entropy, basic PE section inspection and ELF load-segment checks.
- Script, embedded API, persistence, process-manipulation, anti-analysis and packer indicators.
- Explainable score with four levels: no-known-indicators, review, suspicious, high-risk.
- User-launched polling monitor that records created/modified/deleted-or-moved events as JSONL.
- Explicit, reversible quarantine with confirmation, private directory permissions and post-move digest verification.
- JSON reports for dashboards and offline evaluation.

## Requirements and quick start

Python 3.10+; standard library only for core scanning. Optional integrations require their own tools. No root privileges required for user-owned paths.

~~~sh
git clone https://github.com/Justin-io/Q-SAFE.git
cd Q-SAFE
python3 qsafe.py scan ./samples --archives --json reports/scan.json
python3 qsafe.py scan ./one-file
~~~

Exit status: 0 = no high-risk findings, 1 = one or more high-risk findings, 2 = operational error.

### Monitor

~~~sh
python3 qsafe.py monitor ~/Downloads --interval 3
~~~

This is a user-space polling monitor, not a kernel sensor or guaranteed real-time EDR feed. Stop with Ctrl-C. Default event log: ~/.local/state/qsafe/events.jsonl.


### Multi-engine analysis

Q-SAFE can call optional local analysis tools. It does not upload samples or make network requests.

~~~sh
# Install the tools separately using their official installation instructions.
python3 qsafe.py scan ./samples --archives --yara-rules rules/qsafe_heuristics.yar
python3 qsafe.py scan ./samples --clamav
python3 qsafe.py scan ./samples --capa
python3 qsafe.py scan ./samples --archives --yara-rules rules/qsafe_heuristics.yar --clamav --capa --json reports/deep-scan.json
~~~

- YARA applies the selected local source rules. The bundled rules are deliberately labelled low/medium confidence and are triage clues, not verdicts.
- ClamAV contributes an independent signature engine when clamscan and current signatures are installed. A confirmed signature match raises the Q-SAFE item to high risk.
- Mandiant capa describes capabilities found through static analysis. Its capability output is included for analyst review and is not converted directly into a malware verdict.
- Archive inspection reads bounded ZIP/TAR members in memory; it never extracts member paths. Entry count, member size, total expansion and nesting depth are limited.

### File integrity baseline

~~~sh
python3 qsafe.py baseline-create /path/to/application --output ~/.local/state/qsafe/app-baseline.json
python3 qsafe.py baseline-check /path/to/application --baseline ~/.local/state/qsafe/app-baseline.json
~~~

The baseline reports added, modified and removed files by SHA-256. Protect the baseline file separately; a local baseline is not cryptographically signed or tamper-proof. When the optional ssdeep module and its system library are installed, individual samples can also be compared for fuzzy similarity:

~~~sh
python3 qsafe.py similarity ./sample-A.exe ./sample-B.exe
~~~

A similarity score helps cluster near-duplicates; it does not establish common lineage or maliciousness.

### Linux runtime memory-map observer

~~~sh
python3 qsafe.py runtime-watch --interval 3
python3 qsafe.py runtime-watch --pid 1234 --once
~~~

This observes readable Linux procfs mappings and reports executable writable pages, anonymous executable mappings, executable memfd mappings, deleted-but-still-mapped objects, and executable mappings from common temporary directories. JIT engines and legitimate protected software can exhibit similar behaviour. It never terminates processes or changes memory permissions. It is a user-space observer, not eBPF, a kernel sensor, or complete behavioural sandboxing.

### Quarantine and restore

~~~sh
python3 qsafe.py quarantine /path/to/suspicious-file
python3 qsafe.py quarantine-list
python3 qsafe.py restore QUARANTINE_ID
~~~

Quarantine is a separate operation and requires typing QUARANTINE. The file is moved, never executed or automatically deleted. Restore checks its SHA-256 and refuses to overwrite an existing destination.

### Optional dashboard

The old dashboard displayed random industrial telemetry and fabricated security events. It has been replaced with a real local scan UI. Install Streamlit only when needed:

~~~sh
python3 -m pip install streamlit
streamlit run dashboard.py
~~~

### Tests

~~~sh
python3 -m unittest discover -s tests -v
~~~

## Polymorphic detection strategy and limits

Q-SAFE correlates executable format/structure, high-entropy regions, packer indicators, overlays, unusual writable+executable sections, suspicious imports/strings and script-level obfuscation/dynamic execution/persistence/network/process manipulation. Entropy by itself is not treated as malware. Legitimate installers, games, compressed files, protected software and encrypted data can exhibit these traits; sophisticated malware can evade them.

This release is a first static-analysis and user-space observation baseline, **not a validated ML classifier or production EDR**. Before claiming detection efficacy, evaluate against a labelled benign/malicious corpus spanning multiple families and variants. Publish precision, recall, false-positive rate, false-negative rate, family coverage and test-set provenance. Dynamic confirmation requires a disposable isolated VM/sandbox with snapshots, no shared folders and controlled networking. A strong unpacking analytic correlates memory allocation/protection changes with subsequent execution or injection from non-image-backed memory; Q-SAFE's procfs observer only surfaces selected mapping states and does not implement that full analytic.

## Architecture

~~~text
User-selected files / directories
             |
             v
     Safe file collector
   (no symlinks; size ceiling)
             |
             v
    Static feature extraction
   SHA256 | entropy | PE/ELF
             |
             v
 Explainable heuristic correlation
 scripts | APIs | packing | persistence
       |                   |
       v                   v
 JSON/CLI report       Polling monitor
                           |
                           v
                  Changed-file triage
                           |
                           v
             Explicit quarantine / restore
~~~

## Historical prototype warning

Do not run the old guardian.asm or original run.sh on a production system. The legacy workflow traversed the filesystem broadly and contained a direct unlink deletion path. The new launcher and Makefile do not build or invoke it. Historical C/assembly control-flow-hashing and intentionally vulnerable buffer-overflow demo files remain research artefacts only; they are not part of the new scanner or its security boundary.

For safe operation, use least privilege, begin with read-only scans, do not open suspicious files, and do not use heuristic scores as the sole reason to delete or block software. See SECURITY.md.


## Upstream references

- MITRE ATT&CK, Software Packing (T1027.002): https://attack.mitre.org/techniques/T1027/002/
- MITRE ATT&CK, Obfuscated Files and Information: https://attack.mitre.org/techniques/T1027/
- YARA command-line documentation: https://yara.readthedocs.io/en/latest/commandline.html
- Mandiant FLARE capa: https://mandiant.github.io/capa/
- capa usage and JSON output: https://github.com/mandiant/capa/blob/master/doc/usage.md
