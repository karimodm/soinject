bits 64

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
