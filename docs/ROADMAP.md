# Roadmap

## Phase 1 — Safe static MVP
Bounded file sampling, cryptographic/sample hash labeling, file-type hints, entropy, explainable indicators, normalized Python AST features, file identity baselines, bounded traversal, JSONL reporting, reversible quarantine, unit tests, CI.

## Phase 2 — Mutation and provenance
Baseline manifest (path, device/inode, size, mtime, full SHA-256, signer/package provenance); inotify/watchdog event stream; alerts on replacement and unexpected executable permission/persistence changes.

## Phase 3 — Behavioural sensor
Optional Linux audit/eBPF sensor isolated from the unprivileged scanner. Track process ancestry, exec events, writes to persistence paths, suspicious child processes, and outbound connections. Add data minimization and local retention.

## Phase 4 — Executable analysis
Optional maintained parsers such as LIEF and YARA; extract PE/ELF sections, imports, relocations, entropy by section, normalized strings, and CFG features; compare semantic fingerprints across variants. Entropy alone is not malware proof. Optional sandbox only in disposable isolated VMs.

## Phase 5 — Evaluation and release
Use a legally obtained labeled dataset (for example EMBER for PE static ML research), split by family/time, and publish confusion matrix, precision, recall, F1, ROC-AUC, false-positive rate, throughput, and resource use. Add signed releases, SBOM, dependency scanning, reproducible builds, and security review.
