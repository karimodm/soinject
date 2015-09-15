bits 64
; arg 1 rdi
; arg 2 rsi
; arg 3 rdx
; arg 4 r10
; arg 5 r9
; arg 6 r8

calladdr2:
    push r12
    lea r12, [rsp+0x10] ; arguments location
    push rsi
    push rax
    push rdi
    push r9
    push r12
    mov r9, [r12]    ; address of the call
    mov rdi, [r12+0x08] ; first parameter
    mov rsi, [r12+0x10] ; second parameter
    call r9
    pop r12
    mov [r12], rax  ; return in the same location of our arguments
    pop r9
    pop rdi
    pop rax
    pop rsi
    pop r12
    ret

