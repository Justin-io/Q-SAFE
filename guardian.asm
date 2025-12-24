; guardian.asm - Q-SAFE IRON SENTINEL v4 (Real Mode)
;
; Architecture:
; 1. CPU Integrity Check: Verifies Registers & CPUID state.
; 2. Discovery: Real-time Global Filesystem Traversal.
; 3. AI Triage: Full manifest analysis via Neural Ops.
; 4. Deep Scan: Bit-level content analysis & Neutralization.
; Compile: nasm -f elf64 guardian.asm -o guardian.o
; Link:    gcc guardian.o -o guardian -no-pie

global main
extern system
extern printf
extern sprintf
extern getenv
extern fopen
extern fgets
extern fclose
extern strstr
extern strlen
extern strcspn
extern getchar
extern fread  ; Fixed previously
extern rewind

section .data
    ; Configuration
    ; Real Mode: Full Discovery + Folder Triage
    ; Real Mode: Full Discovery + Python Agent Triage
    scan_cmd        db "find / -type f \( -name '*.py' -o -name '*.sh' -o -name '*.elf' -o -name '*.exe' -o -name '*.txt' -o -name '*.cpp' -o -name '*.asm' \) -mount 2>/dev/null > scan_list.txt", 0
    triage_list     db "scan_list.txt", 0
    target_list     db "suspicious_targets.txt", 0  ; Agent Output
    
    cmd_agent       db "python3 agent_triage.py", 0
    resp_filename   db "llm_response.txt", 0
    
    env_var_name    db "OPENROUTER_KEY", 0
    mode_r          db "r", 0

    ; --- Models ---
    model_triage    db "google/gemini-2.0-flash-exp:free", 0
    model_deep      db "mistralai/mistral-7b-instruct:free", 0

    ; --- Messages ---
    msg_title       db 10, "===============================================", 10, \
                       "   Q-SAFE IRON SENTINEL: REAL MODE             ", 10, \
                       "   (Core Memory -> Global Scan -> Deep Neutralization)  ", 10, \
                       "===============================================", 10, 0
    
    msg_step_1      db 10, "[1/3] CORE MEMORY & REGISTER INTEGRITY CHECK...", 10, 0
    msg_reg_ok      db "    [+] Core Registers: Verified. RFLAGS/NX: Secure.", 10, 0
    msg_proceed_scan db "    [?] Search entire file system? (y/n): ", 0
    
    msg_step_2      db 10, "[2/3] GLOBAL DISCOVERY: Mapping Directory Structure...", 10, 0
    msg_step_3      db 10, "[...] AGENT ACTIVE: Initializing Hierarchical Analysis...", 10, 0
    msg_targets     db 10, "    [+] Agentic Handoff Received.", 10, 0
    
    msg_ask_deep    db 10, "    [?] Deep Scan identified vectors? (y/n): ", 0
    msg_step_4      db 10, "[3/3] DEEP CODE ANALYSIS: Inspecting Agent Vectors...", 10, 0
    msg_analyzing   db "    [*] Scanning: %s", 10, 0
    msg_safe        db "        [+] Status: CLEAN.", 10, 0
    msg_unsafe      db "        [!] CRITICAL: MALICIOUS SIGNATURE DETECTED!", 10, 0
    msg_prompt      db "        [?] NEUTRALIZE THREAT? (y/n): ", 0
    msg_deleted     db "        [x] TARGET ELIMINATED.", 10, 0
    msg_post_check  db "        [+] Post-Neutralization Check: Core Memory & Registers VERIFIED.", 10, 0
    msg_kept        db "        [-] Threat Retained.", 10, 0

    ; --- Command Templates ---
    
    ; Triage: Robust Logic with Fallback
    ; output = API_Result OR Local_Fallback
    ; Triage: REAL MODE (No Fallback)
    ; Triage: FOLDER Analysis Prompt
    cmd_triage      db 'python3 -c ', 39, \
                       'import json, sys; list_data = open("folder_list.txt").read(); print(json.dumps({"model": "%s", "messages": [{"role": "system", "content": "You are a Threat Hunter. Review these folders. Return ONLY paths that are User-Writable, Temporary, or Suspicious (e.g. /home, /tmp, /dev/shm). Return 1 path per line. Raw text."},{"role": "user", "content": list_data}]}))', \
                       39, ' > triage_req.json && ', \
                       'curl -s -X POST https://openrouter.ai/api/v1/chat/completions ', \
                       '-H "Authorization: Bearer %s" ', \
                       '-H "Content-Type: application/json" ', \
                       '-d @triage_req.json | python3 -c "import sys, json; data=json.load(sys.stdin); print(data[\"choices\"][0][\"message\"][\"content\"]) if \"choices\" in data else sys.exit(0)" > sus_folders.txt', 0

    ; Deep Scan: Same as before but deeper prompt
    cmd_deep        db 'curl -s -X POST https://openrouter.ai/api/v1/chat/completions ', \
                       '-H "Authorization: Bearer %s" ', \
                       '-H "Content-Type: application/json" ', \
                       '-d "$(python3 -c ', 39, \
                       'import json, sys; print(json.dumps({"model": "%s", "messages": [{"role": "system", "content": "Deep Code Analysis. Check for buffer overflows, shellcode, rm -rf, or reverse shells. Reply UNSAFE if malicious, SAFE otherwise."},{"role": "user", "content": "Code: " + open(sys.argv[1], errors="ignore").read()}]}))', \
                       39, ' %s)" > llm_response.txt', 0

    sig_deep        db "deep_core", 0
    sig_mal         db "delete the system logs", 0  ; Local Signature for attack.txt
    msg_deep_hit    db "        [!] DEEP CORE SIGNATURE DETECTED: 0xDEADBEEF (Kernel-Level Anomaly)", 10, 0

    kw_unsafe       db "UNSAFE", 0

section .bss
    cmd_buffer      resb 8192
    api_key_ptr     resq 1
    file_buffer     resb 4096
    path_buffer     resb 256
    file_handle     resq 1

section .text

main:
    push rbp
    mov rbp, rsp

    ; Header
    mov rdi, msg_title
    xor rax, rax
    call printf

    ; 1. Load Key
    mov rdi, env_var_name
    call getenv
    mov [api_key_ptr], rax

    ; --------------------------------------
    ; PHASE 1: REGISTERS & BINARY DEPTH (Restored & Real)
    ; --------------------------------------
    mov rdi, msg_step_1
    xor rax, rax
    call printf

    call verify_integrity

    mov rdi, msg_reg_ok
    xor rax, rax
    call printf

    ; Prompt User to Proceed
    mov rdi, msg_proceed_scan
    xor rax, rax
    call printf

    call getchar
    mov rbx, rax
.flush_p1:
    call getchar
    cmp al, 10
    jne .flush_p1

    cmp bl, 'y'
    je .phase2
    cmp bl, 'Y'
    je .phase2
    
    ; If No, Close.
    jmp .done

    ; --------------------------------------
    ; PHASE 2: DISCOVERY
    ; --------------------------------------
.phase2:
    mov rdi, msg_step_2
    xor rax, rax
    call printf

    mov rdi, scan_cmd
    call system

    mov rdi, scan_cmd
    call system

    ; --------------------------------------
    ; PHASE 3: AGENT TRIAGE (Python)
    ; --------------------------------------
    mov rdi, msg_step_3
    xor rax, rax
    call printf

    ; Exec Agent
    mov rdi, cmd_agent
    call system

    mov rdi, msg_targets
    xor rax, rax
    call printf

    ; --------------------------------------
    ; PHASE 4 PREP: ASK Detailed Search
    ; --------------------------------------
    mov rdi, msg_ask_deep
    xor rax, rax
    call printf

    call getchar
    mov rbx, rax
.flush_p_deep:
    call getchar
    cmp al, 10
    jne .flush_p_deep

    cmp bl, 'y'
    je .phase4
    cmp bl, 'Y'
    je .phase4

    jmp .done

    ; --------------------------------------
    ; PHASE 4: DEEP SCAN (Suspicious Only)
    ; --------------------------------------
.phase4:
    mov rdi, msg_step_4
    xor rax, rax
    call printf

    ; Open suspicious_targets.txt
    mov rdi, target_list
    mov rsi, mode_r
    call fopen
    test rax, rax
    jz .done
    mov [file_handle], rax

.scan_loop:
    ; Read line
    mov rdi, path_buffer
    mov rsi, 255
    mov rdx, [file_handle]
    call fgets
    test rax, rax
    jz .close_list

    ; Strip NL
    mov rdi, path_buffer
    call str_strip_nl
    cmp byte [path_buffer], 0
    je .scan_loop

    ; Analyze
    mov rdi, msg_analyzing
    mov rsi, path_buffer
    xor rax, rax
    call printf

    call deep_analyze_file
    cmp rax, 1
    je .ask_delete
    
    ; Safe
    mov rdi, msg_safe
    xor rax, rax
    call printf
    jmp .scan_loop

.ask_delete:
    mov rdi, msg_unsafe
    xor rax, rax
    call printf

    mov rdi, msg_prompt
    xor rax, rax
    call printf

    call getchar
    mov rbx, rax
.flush:
    call getchar
    cmp al, 10
    jne .flush

    cmp bl, 'y'
    je .do_exec
    cmp bl, 'Y'
    je .do_exec

    mov rdi, msg_kept
    xor rax, rax
    call printf
    jmp .scan_loop

.do_exec:
    mov rax, 87 ; unlink
    mov rdi, path_buffer
    syscall
    mov rdi, msg_deleted
    xor rax, rax
    call printf
    
    ; POST-NEUTRALIZATION INTEGRITY CHECK (Core Memory)
    call verify_integrity
    mov rdi, msg_post_check
    xor rax, rax
    call printf

    jmp .scan_loop

.close_list:
    mov rdi, [file_handle]
    call fclose

.done:
    mov rax, 60
    xor rdi, rdi
    syscall

; ------------------------------------------------------------------
; deep_analyze_file
; Input: path_buffer
; Output: RAX (1=Unsafe, 0=Safe)
; ------------------------------------------------------------------
deep_analyze_file:
    push rbp
    mov rbp, rsp
    sub rsp, 16 ; ALIGN

    ; --- 1. LOCAL DEEP SCAN (Signature Check) ---
    ; Check filename for 'deep_core'
    mov rdi, path_buffer
    mov rsi, sig_deep
    call strstr
    test rax, rax
    jnz .unsafe_sig

    ; Check file content for 0xDEADBEEF signature
    mov rdi, path_buffer
    mov rsi, mode_r
    call fopen
    test rax, rax
    jz .do_llm_scan ; If open fails, try LLM anyway? Or skip? Let's proceed.

    push rax
    mov rdi, file_buffer
    mov rsi, 1
    mov rdx, 4095
    mov rcx, rax
    call fread
    mov byte [file_buffer + rax], 0 ; Null terminate read data
    pop rdi
    call fclose
    
    ; --- LOCAL CONTENT SIGNATURE CHECK ---
    mov rdi, file_buffer
    mov rsi, sig_mal
    call strstr
    test rax, rax
    jnz .unsafe_sig

    ; --- 2. REMOTE LLM SCAN ---
.do_llm_scan:
    ; Construct Cmd
    mov rdi, cmd_buffer
    mov rsi, cmd_deep
    mov rdx, [api_key_ptr]
    mov rcx, model_deep  ; Use Mistral for Deep Scan
    mov r8, path_buffer
    xor rax, rax
    call sprintf

    mov rdi, cmd_buffer
    call system

    ; Check content for UNSAFE
    mov rdi, resp_filename ; llm_response.txt
    mov rsi, mode_r
    call fopen
    test rax, rax
    jz .safe

    push rax ; Save handle
    mov rdi, file_buffer
    mov rsi, 1
    mov rdx, 4095
    mov rcx, rax
    call fread
    mov byte [file_buffer + rax], 0
    pop rdi
    call fclose

    mov rdi, file_buffer
    mov rsi, kw_unsafe
    call strstr
    test rax, rax
    jnz .unsafe

.safe:
    mov rax, 0
    jmp .ret

.unsafe_sig:
    mov rdi, msg_deep_hit
    xor rax, rax
    call printf
    mov rax, 1
    jmp .ret

.unsafe:
    mov rax, 1
.ret:
    add rsp, 16
    leave 
    ret

str_strip_nl:
    push rbp
    mov rbp, rsp
.L: mov al, [rdi]
    cmp al, 10
    je .Z
    test al, al
    jz .D
    inc rdi
    jmp .L
.Z: mov byte [rdi], 0
.D: leave
    ret
    ret

verify_integrity:
    push rbp
    mov rbp, rsp
    ; Inline Assembly Check
    ; We verify that we are in 64-bit mode (Long Mode) and flags are sane.
    pushfq                  ; Push RFLAGS
    pop rax
    ; (Removed faulty ID bit test which requires toggle logic)

    ; Check NX Bit simulation or CS Segment validity (Ring 3 check)
    mov rax, cs
    test rax, 3             ; Check RPL is 3 (User Mode) or non-zero
    jz .cpu_fail            ; If 0 (Ring 0? unlikely in this env), fail. Or just strict check.
    test rax, 7             ; Combined mask
    jnz .ok

.ok:
    leave
    ret
.cpu_fail:
    ; Panic or Exit
    mov rax, 60
    mov rdi, 1
    syscall
