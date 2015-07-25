bits 64

; arg 1 rdi
; arg 2 rsi
; arg 3 rdx
; arg 4 r10
; arg 5 r9
; arg 6 r8

push 100
call mmap_memory
pop r12

mmap_memory:
    push r12            ; we choose r12 for local storage, will be preserved by the syscall
    lea r12, [rsp+0x10] ; length, argument
    push rsi
    push rax
    push rdi
    push rdx
    push r10
    push r8
    push r9         ; we use all these registers for __NR_mmap
    ;  void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
    mov rax, 9      ; __NR_mmap
    xor rdi, rdi    ; kernel chooses addr
    mov rsi, [r12]
    mov rdx, 1      ; PROT_READ
    or rdx, 2       ; PROT_WRITE
    or rdx, 4       ; PROT_EXEC
    mov r10, 2      ; MAP_PRIVATE
    or r10, 0x20    ; MAP_ANONYMOUS
    xor r9, r9
    xor r8, r8
    syscall
    mov [r12], rax  ; return in the same location of our argument
    pop r9
    pop r8
    pop r10
    pop rdx
    pop rdi
    pop rax
    pop rsi
    pop r12
    ret
