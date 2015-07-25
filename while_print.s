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

mmap_memory:
	push rsi
	mov rsi, [rsp+0x10] ; length, argument
	push rdi
	push rdx
	push r10
	push r8
	push r9		; we use all this registers for __NR_mmap
	mov rax, 9	; __NR_mmap
	; DO SHIT
	mov rax, [rsp+8]
	pop r9
	pop r8
	pop r10
	pop rdx
	pop rdi
	pop rsi
	ret
