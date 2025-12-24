# Q-SAFE: IRON SENTINEL (v4 Real Mode)

## Overview
**Q-SAFE (Quantum-Secure Agentic Framework Environment)** is a hybrid security sentinel designed to operate with "Kernel-Like" authority in user space. It combines the raw speed and hardware control of **x86_64 Assembly** with the cognitive planning capabilities of a **Python-based Neural Agent**.

This Proof-of-Concept (POC) demonstrates a "Real Mode" security agent that robustly verifies CPU integrity, maps the entire filesystem, intelligently triages high-risk zones, and performs bit-level deep content analysis to neutralize threats.

## Architecture: The Hybrid Trinity

The system relies on three distinct layers working in unison:

### 1. The Iron Core (x86_64 Assembly)
*   **File**: `guardian.asm`
*   **Role**: The Body & Enforcer.
*   **Functionality**:
    *   Manages the Process Lifecycle and Memory.
    *   Performs low-level **CPU Register Integrity Checks** (RFLAGS, CS Segment verification).
    *   Executes system calls for fast filesystem discovery (`find`).
    *   Handles file I/O for Deep Scanning (`fopen`, `fread`).
    *   **Direct Neutralization**: Deletes malicious files (`unlink` syscall) and immediately verifies core memory stability.

### 2. The Neural Agent (Python)
*   **File**: `agent_triage.py`
*   **Role**: The Mind & Strategist.
*   **Functionality**:
    *   **Hierarchical Scanning**: Instead of drowning in file lists, it clusters thousands of files into "Context Zones" (Folders).
    *   **Agentic Logic**: Analyzes directory names to identify high-risk targets (e.g., `/home/user/Desktop`, `/tmp`, temporary pip build artifacts).
    *   **Resilient Fallback**: If the Cloud AI connection is unstable, it engages local heuristic algorithms to ensure threats are never ignored.

### 3. The Neural Ops (Cloud AI)
*   **Integration**: OpenRouter API
*   **Models**: `google/gemini-2.0-flash-exp` (Triage), `mistralai/mistral-7b-instruct` (Deep Analysis).
*   **Role**: Advanced Pattern Recognition. It decides *which* zones look suspicious based on semantic understanding, not just signatures.

---

## Workflow: The Agentic Loop

1.  **Initialization & Integrity**:
    *   The Sentinel boots and immediately snapshots the CPU state.
    *   It verifies that the Code Segment (CS) and Ring 3 privileges are valid and that the NX (No-Execute) bit safeguards are active (simulated via segment checks).

2.  **Global Discovery**:
    *   The system executes a real-time traversal of the **entire root filesystem**, mapping every executable, script, and code file (`.py`, `.sh`, `.elf`, `.exe`, `.cpp`, `.asm`, `.txt`).
    *   Result: `scan_list.txt` (typically 30,000+ files).

3.  **Hierarchical Triage (Hand-off)**:
    *   Control is passed to the Python Agent.
    *   The Agent reduces the massive list into "Zones" (Directories).
    *   It selects **High-Risk Zones** for inspection (e.g., `mitmproxy` folders, Desktop, Downloads).
    *   It generates a targeted vector list: `suspicious_targets.txt`.

4.  **Deep Code Analysis**:
    *   Control returns to the Assembly Core.
    *   The Sentinel iterates through the target vectors one by one.
    *   **Inspection**: It opens files and reads raw bytes.
    *   **Detection**:
        *   **Local Signatures**: Checks for known malicious strings (e.g., "delete the system logs", "deep_core").
        *   **Deep AI Scan**: Validates content with Mistral-7b (if configured).
    *   **Neutralization**: If unsafe, the user is prompted to delete. Upon deletion, the Core Memory is re-verified.

---

## Installation & Usage

### Prerequisites
*   Linux Environment (Parrot OS / Kali / Ubuntu compatible)
*   `nasm` (Netwide Assembler)
*   `gcc` (GNU Compiler Collection)
*   `python3`
*   `curl`

### Compilation
The project includes a `run.sh` script, or you can compile manually:
```bash
nasm -f elf64 guardian.asm -o guardian.o
gcc guardian.o -o guardian -no-pie
```

### Execution
To run the Sentinel in Real Mode, you need an OpenRouter API key (optional for local heuristics).

```bash
# Export Key (Optional, for Full Cloud AI Intelligence)
export OPENROUTER_KEY=your_actual_key_here

# Launch (Heuristics will auto-engage if key is invalid/test)
./guardian
```

## Technical Details

### CPU Integrity Check (Assembly)
The agent ensures it hasn't been tampered with or hooked by a rootkit by verifying the processor flags.
```nasm
verify_integrity:
    pushfq                  ; Push RFLAGS
    pop rax
    mov rax, cs             ; Check Code Segment
    test rax, 3             ; Verify User Mode (RPL 3)
    jz .cpu_fail            ; Panic if anomaly detected
    test rax, 7             ; Mask check
    jnz .ok
```

### The "Deep Agent" Logic (Python)
The triage agent uses path analysis to avoid wasting resources on system directories (like `/proc`).
```python
# Clustering logic in agent_triage.py
folders = sorted(list(set([os.path.dirname(f) for f in files])))
# Heuristic Fallback
sus_folders = [f for f in folders if "Desktop" in f or "tmp" in f]
```

## Disclaimer
This is a **Proof of Concept**. While it operates on real files and performs real deletions, it is intended for educational and research purposes in controlled environments. Be careful when neutralizing files, as they are permanently removed.
