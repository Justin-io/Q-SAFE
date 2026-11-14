# Q-SAFE security model

Q-SAFE treats scanned files as untrusted data. It opens regular files read-only, refuses symlinks, enforces a per-file size ceiling, and never invokes a shell, interpreter, loader or sample executable.

Scanning is non-destructive. Quarantine is a separate explicit operation, prompts for confirmation, moves one regular file to a private store, and verifies SHA-256 after the move. Restore verifies the digest again and refuses to overwrite an existing destination.

The static rules are heuristics, not a validated threat-intelligence feed. Entropy is not proof of encryption or malware. Polymorphic-candidate is not a malware verdict. Polling can miss short-lived events and only observes the selected directory. Q-SAFE does not detect kernel compromise, network intrusion, memory-only malware, or all runtime process injection.

Use least privilege. Do not scan live system directories as an initial test. Do not execute suspicious samples. Dynamic analysis belongs in a disposable isolated lab.


## Optional engines and observation
YARA rules are local files and are invoked without a shell. ClamAV and capa are separate local scanners; their executables must be installed and kept updated by the operator. Q-SAFE does not fetch rules or upload samples. capa capability matches are contextual evidence, not a malware verdict.

ZIP/TAR member inspection is performed in memory with member-count, per-member size, total expansion and nesting limits. Archive paths are never extracted. Some archive formats and nested encodings are intentionally unsupported.

The Linux runtime observer reads procfs metadata only. It does not read process memory, inject code, suspend processes, kill processes or change firewall rules. Executable anonymous mappings are common in JIT runtimes, browsers and managed language virtual machines, so findings require context.

## Response policy
Q-SAFE does not automatically kill processes, disable networking, delete files, or change system policy. Quarantine requires a separate command and confirmation. This reduces the risk of turning an uncertain heuristic into destructive action. For enterprise containment, integrate with a managed EDR or a reviewed endpoint agent and require human approval for disruptive actions.


## Reporting a vulnerability

Please do not include live malware samples, credentials, personal data, or weaponized exploit instructions in a public issue. For sensitive reports, use GitHub's private vulnerability reporting feature for this repository (Security tab → Report a vulnerability), when enabled. Include the affected commit or release, affected component, safe reproduction steps, impact, and any mitigations. If private vulnerability reporting is unavailable, contact the repository maintainer through the contact method listed on the GitHub profile. Avoid testing against systems you do not own or have explicit permission to assess.
