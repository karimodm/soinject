bits 64
push r12 ; saves old r12
mov r12, 0xdeadbeefdeadbeef
push r12 ; second arg
mov r12, 0xdeadbeefdeadbeef
push r12 ; first arg
mov r12, 0xdeadbeefdeadbeef
push r12 ; call addr
