bits 64

jmp data_dlopen_addr
dlopen:
pop rax
mov rax, [rax]
jmp data_so
so:
pop rsi
mov rsi, [rsi]
mov rdi, 1  	; RTLD_LAZY
call rax   	; dlopen

mov rsi, rax 	; handle
jmp data_dlsym_addr
dlsym_addr:
pop rax
mov rax, [rax]
jmp data_entrypoint
entrypoint:
pop rdi
mov rdi, [rdi]
call rax

mov rbx, rax 	; function pointer

mov rax, 57 	; fork syscall
syscall
test rax, rax
jnz leave		; parent

jmp rbx		; we are in the child, jump to entry point

leave:
mov rax, 39		; getpid
syscall 
mov rsi, rax	; pid
mov rax, 62		; kill
mov rdi, 10		; SIGUSR1
syscall

; throw signal for ptrace to collect us and repatch .text section
ret

; Data section, these are placeholders that will need to be patched at runtime

data_dlopen_addr:
call dlopen
dq 0xdeadbeefdeadbeef
data_dlsym_addr:
call dlsym_addr
dq 0xdeadbeefdeadbeef
data_so:
call so
times 100 db 0 ; 100 times 0?
data_entrypoint:
call entrypoint
times 100 db 0
