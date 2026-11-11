; Legacy entry point intentionally disabled on the defense-mvp branch.
; The previous assembly sentinel could unlink arbitrary scan targets and
; constructed shell commands. It is not part of the defensive scanner.
global main
extern puts
section .data
    msg db "Q-SAFE: legacy guardian is disabled. Use python -m q_safe.cli.", 0
section .text
main:
    push rbp
    mov rbp, rsp
    lea rdi, [rel msg]
    call puts
    xor eax, eax
    pop rbp
    ret
