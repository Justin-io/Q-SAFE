; Q-SAFE Assembly Monitor (x86_64)
; Implements the "Contextual Control Flow Hashing" (CCFH) logic
; Compatible with C calling convention (System V AMD64 ABI)

section .data
    violation_msg db "Q-SAFE SECURITY VIOLATION: INVALID CONTEXT DETECTED! HALTING.", 10, 0
    violation_len equ $ - violation_msg
    
    debug_msg db "Q-SAFE: Valid Context Hash: 0x", 0

section .bss
    current_context resq 1      ; Stores the rolling hash (64-bit)
    allowlist_ptr   resq 1      ; Pointer to the allowlist array
    allowlist_size  resq 1      ; Number of entries in allowlist

section .text
    global qsafe_init
    global qsafe_hook
    
    extern printf
    extern exit
    extern putchar

; -----------------------------------------------------------------------------
; void qsafe_init(uint64_t* list, uint64_t size)
; Initializes the monitor with the allowlist.
; Data passed in RDI (list), RSI (size)
; -----------------------------------------------------------------------------
qsafe_init:
    mov [allowlist_ptr], rdi
    mov [allowlist_size], rsi
    mov qword [current_context], 0  ; Reset context
    
    ; Debug print (optional, can be removed for zero-overhead)
    ; mov rdi, debug_msg
    ; call printf 
    
    ret

; -----------------------------------------------------------------------------
; void qsafe_hook(uint64_t target_id)
; Called at critical branch points.
; Updates context and verifies against allowlist.
; Data passed in RDI (target_id)
; -----------------------------------------------------------------------------
qsafe_hook:
    push rbx
    push rcx
    push rdx
    
    ; 1. LOAD CONTEXT
    mov rbx, [current_context]
    
    ; 2. UPDATE CONTEXT (Rolling Hash)
    ; Logic must match Python: ((current << 1) & mask) ^ target_id
    shl rbx, 1
    xor rbx, rdi
    
    ; Save new context
    mov [current_context], rbx
    
    ; 3. VERIFY CONTEXT via Linear Scan (O(N) - Simplified for POC)
    ; In production, this would be a constant time Bloom Filter lookup or HashMap.
    
    mov rcx, [allowlist_size]
    mov rdx, [allowlist_ptr]
    
.scan_loop:
    test rcx, rcx
    jz .violation           ; If count reaches 0, not found -> Violation
    
    cmp rbx, [rdx]          ; Compare current hash with allowlist entry
    je .valid
    
    add rdx, 8              ; Next entry
    dec rcx
    jmp .scan_loop

.valid:
    ; Context is valid, restore regs and return
    pop rdx
    pop rcx
    pop rbx
    ret

.violation:
    ; 4. ENCLAVE VIOLATION RESPONSE
    ; Print error and exit hard
    
    ; Use syscall for independent output (write to stdout)
    mov rax, 1          ; sys_write
    mov rdi, 1          ; fd = stdout
    lea rsi, [violation_msg]
    mov rdx, violation_len
    syscall
    
    ; Terminate process
    mov rax, 60         ; sys_exit
    mov rdi, 139        ; SIGSEGV style exit code
    syscall
