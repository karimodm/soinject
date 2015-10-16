bits 64

lea rax, dlopen_addr
mov rax, [rax]
lea rsi, so
mov rsi, [rsi]
mov rdi, 1  	// RTLD_LAZY
call *rax   	// dlopen

mov rsi, rax 	// handle
mov rax, dlsym_addr
mov rax, [rax]
mov rdi, entrypoint
mov rdi, [rdi]
call *rax

mov rbx, rax 	// function pointer

mov rax, 57 	// fork syscall
syscall
test rax, rax
jnz leave		// parent

jmp *rbx		// we are in the child, jump to entry point

leave:
mov rax, 39		// getpid
syscall 
mov rsi, rax	// pid
mov rdi, 10		// SIGUSR1
mov rax, 62
syscall

// throw signal for ptrace to collect us and repatch .text section
ret

// Data section, these are placeholders that will need to be patched at runtime

dlopen_addr:
dq 0xdeadbeefdeadbeef
dlsym_addr:
dq 0xdeadbeefdeadbeef
so:
dd 100 // 100 times 0?
entrypoint:
dd 100 
