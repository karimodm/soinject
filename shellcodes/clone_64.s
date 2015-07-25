bits 64

; arg 1 rdi
; arg 2 rsi
; arg 3 rdx
; arg 4 r10
; arg 5 r9
; arg 6 r8

clone:
    push r12
    mov r12, [rsp+0x10] ; target address for the new thread
    push rax
    push rdi
    push rsi
    push rdx
    push r10
    push r9
    mov rax, 56         ; __NR_clone
    xor rdi, rdi        ; no flags
    xor rsi, rsi        ; copy on write stack
    xor rdx, rdx        ; no *ptid
    xor r10, r10        ; no *ctid
    xor r9, r9
    syscall
    cmp rax, 0
    jne quit            ; we are in the parent
    jmp r12
quit:
    pop r9
    pop r10
    pop rdx
    pop rsi
    pop rdi
    pop rax
    pop r12
    ret

