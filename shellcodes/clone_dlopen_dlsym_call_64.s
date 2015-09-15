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
	push rbx
	push rcx
	push rdx
    push rdi
    push rsi
    push rdx
    push r10
    push r9
	push r8
    mov rax, 56         ; __NR_clone
    mov rdi, 0x00002000 ; CLONE_PTRACE
    xor rsi, rsi        ; copy on write stack
    xor rdx, rdx        ; no *ptid
    xor r10, r10        ; no *ctid
    xor r9, r9
    syscall
    cmp rax, 0
    jne quit            ; we are in the parent
    jmp child
quit:
	pop r8
    pop r9
    pop r10
    pop rdx
    pop rsi
    pop rdi
	pop rdx
	pop rcx
	pop rbx
    pop rax
	pop rcx
    pop r12
    ret
child:
	lea r8, [dlopen_addr]
	lea rdi, [so_file]
	xor rsi, rsi 		; no flags to dlopen
	call r8				; dlopen
	mov r9, rax			; mapped handle in r9
	lea r8, [dlsym_addr]
	mov rdi, r9
	lea rsi, [entry_name]
	call r8				; dlsym
	mov r10, rax
	call r10			; call to the function, this should never return
	jmp quit	

dlopen_addr:
	dq 0xdeadbeefdeadbeef
dlsym_addr:
	dq 0xdeadbeefdeadbeef
so_file:
	times 100 db 0
entry_name:
	times 100 db 0
