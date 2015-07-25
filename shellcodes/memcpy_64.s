bits 64

memcpy: ; (dst, src, len)
	push r12
	lea r12, [rsp+0x10]
	push rdx
	push rcx
	push rbx
	push rax
	mov rdx, [r12+0x10] ; len
	mov rax, [r12+8]	; src
	mov rbx, [r12]		; dst
	add rdx, rax		; termination address
loop:
	mov cl, [rax]
	mov [rbx], cl
	inc rbx
	inc rax
	cmp rax, rdx
	jne loop
	pop rax
	pop rbx
	pop rcx
	pop rdx
	pop r12
	ret
