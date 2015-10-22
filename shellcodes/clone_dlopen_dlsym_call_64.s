bits 64

; arg 1 rdi
; arg 2 rsi
; arg 3 rdx
; arg 4 r10
; arg 5 r9
; arg 6 r8

fork:
    push rax
    push rsi
    push rdi
    push r10
    push r9
    push r8
    mov rax, 57         ; __NR_fork
    syscall
    cmp rax, 0
    jne quit            ; we are in the parent
    jmp child
quit:
    pop r8
    pop r9
    pop r10
    pop rdi
    pop rsi
    pop rax
    ret
child:
    jmp dlopen_addr_push
dlopen_addr:
    pop r8
    jmp so_file_push
so_file:
    pop rdi
    xor rsi, rsi        ; no flags to dlopen
    call r8             ; dlopen
    mov r9, rax         ; mapped handle in r9
    jmp dlsym_addr_push
dlsym_addr:
    pop r8
    mov rdi, r9
    jmp entry_name_push
entry_name:
    pop rsi
    call r8             ; dlsym
    mov r10, rax
    call r10            ; call to the function, this should never return
    jmp quit    

dlopen_addr_push:
    call dlopen_addr
    dq 0xdeadbeefdeadbeef
dlsym_addr_push:
    call dlsym_addr
    dq 0xdeadbeefdeadbeef
so_file_push:
    call so_file
    times 100 db 0
entry_name_push:
    call entry_name
    times 100 db 0
