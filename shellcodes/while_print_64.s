bits 64

	jmp s
l:
	mov rax, 1	; __NR_write
	mov rdi, 2	; stderr
	pop rsi 	; string
	mov rdx, 6
	syscall		; drops to call l
s:
	call l
	db "culo!", 0xa 
