#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include <fcntl.h>

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

unsigned char loader_shellcode[] = {
  0xeb, 0x4d, 0x58, 0x48, 0x8b, 0x00, 0xeb, 0x61, 0x5e, 0x48, 0x8b, 0x36,
  0xbf, 0x01, 0x00, 0x00, 0x00, 0xff, 0xd0, 0x48, 0x89, 0xc6, 0xeb, 0x44,
  0x58, 0x48, 0x8b, 0x00, 0xe9, 0xb1, 0x00, 0x00, 0x00, 0x5f, 0x48, 0x8b,
  0x3f, 0xff, 0xd0, 0x48, 0x89, 0xc3, 0xb8, 0x39, 0x00, 0x00, 0x00, 0x0f,
  0x05, 0x48, 0x85, 0xc0, 0x75, 0x02, 0xff, 0xe3, 0xb8, 0x27, 0x00, 0x00,
  0x00, 0x0f, 0x05, 0x48, 0x89, 0xc6, 0xb8, 0x3e, 0x00, 0x00, 0x00, 0xbf,
  0x0a, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3, 0xe8, 0xae, 0xff, 0xff, 0xff,
  0xef, 0xbe, 0xad, 0xde, 0xef, 0xbe, 0xad, 0xde, 0xe8, 0xb7, 0xff, 0xff,
  0xff, 0xef, 0xbe, 0xad, 0xde, 0xef, 0xbe, 0xad, 0xde, 0xe8, 0x9a, 0xff,
  0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe8, 0x4a, 0xff, 0xff, 0xff, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00
};
unsigned int loader_shellcode_length = 315;

/* We expect the shellcode to end with a 5-byes call instruction, 1 processor-sized WORD, a 5-bytes call instructrion,
 * 1 processor-sized WORD, a 5-bytes call instruction, 100 bytes buffer, 5-bytes call instruction and finally a 100 byes
 * buffer. */
void patch_shellcode(unsigned char *shellcode, int len, WORD_CTYPE dlopen_addr, WORD_CTYPE dlsym_addr, char *so, char *entrypoint) {
	unsigned char *ptr;	
	ptr = &shellcode[len - 100 * 2 - sizeof(WORD_CTYPE) * 2 - 5 * 4]; /* 5 * 4 are the call instructions */
	ptr += 5; /* skip call instruction */
	*((WORD_CTYPE *)ptr) = dlopen_addr;
	ptr += sizeof(WORD_CTYPE);
	ptr += 5;
	*((WORD_CTYPE *)ptr) = dlsym_addr;
	ptr += sizeof(WORD_CTYPE);
	ptr += 5;
	strncpy(ptr, so, 100);
	ptr += 100;
	ptr += 5;
	strncpy(ptr, entrypoint, 100);
}

void pad_shellcode(unsigned char *shellcode, int len, struct padded_shellcode *dst) {
	int padded_len;
	if (len % WORD_BYTES == 0)  {
		dst->shellcode = (WORD_CTYPE *) shellcode;
		dst->size = len;
	} else {
		padded_len = len + len % WORD_BYTES;
		dst->shellcode = (WORD_CTYPE *) calloc(0, padded_len);
		memcpy(dst->shellcode, shellcode, len);
		dst->size = padded_len;
	}
}

int parse_arguments(int argc, char **argv, pid_t *pid, WORD_CTYPE *dlopen_addr, WORD_CTYPE *dlsym_addr, char **so, char **entrypoint) {
	if (argc != 6) {
		printf("Usage: injector PID 0xdlopen_address 0xdlsym_address so entrypoint\n");
		return 0;
	}

	*pid = atoi(argv[1]);
	sscanf(argv[2], "0x%llx", dlopen_addr);
	sscanf(argv[3], "0x%llx", dlsym_addr);
	*so = argv[4];
	*entrypoint = argv[5];

	if (!*pid || !*dlopen_addr || !*dlsym_addr || !*so[0] || !*entrypoint[0]) {
		printf("Could not parse arguments!\n");
		printf("Usage: injector PID 0xdlopen_address 0xdlsym_address so entrypoint\n");
		return 0;
	}
	
	return 1;
}

int main(int argc, char **argv) {
	int i, fd;
	pid_t pid;
	WORD_CTYPE dlopen_addr, dlsym_addr, textword;
	char *so, *entrypoint;
	WORD_CTYPE *clobbered_text;
	struct user_regs_struct reg_data;
	WORD_CTYPE pokeaddr;
	struct padded_shellcode padded;
	siginfo_t siginfo;

	if (!parse_arguments(argc, argv, &pid, &dlopen_addr, &dlsym_addr, &so, &entrypoint))
		exit(-1);

	fd = open(so, O_RDONLY);
	if (!fd) {
		printf("[-] Unable to find .so file %s\n", so);
		exit(-1);
	}
	close(fd);


	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
		printf("[-] Unable to attach to %d\n", pid);
		exit(-1);
	}
	printf("[+] Successfully attached to %d\n", pid);
	waitpid(pid, NULL, 0);

	ptrace(PTRACE_GETREGS, pid, NULL, &reg_data);
	if (reg_data.rip & 0xffffffff == 0xffffffff) {
		printf("[-] RIP looks broken\n");
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		exit(-1);
	}
	printf("[+] Got reg data\n[+] RIP is at 0x%016llx\n", reg_data.rip);

	/* Prepare shellcode */
	patch_shellcode(loader_shellcode, loader_shellcode_length, dlopen_addr, dlsym_addr, so, entrypoint);
	pad_shellcode(loader_shellcode, loader_shellcode_length, &padded);

	/* save clobbered .text section */
	printf("[+] Dumping clobbered code segment...\n");
	clobbered_text = (WORD_CTYPE *)malloc(padded.size);
	for (i = 0, pokeaddr = reg_data.rip; i < padded.size / WORD_BYTES; i++, pokeaddr += WORD_BYTES)
		clobbered_text[i] = ptrace(PTRACE_PEEKTEXT, pid, pokeaddr, NULL);
	printf("[+] Code dumped.\n");

	/* Inject shellcode */
	printf("[+] Injecting loader shellcode...\n");
	for (i = 0, pokeaddr = reg_data.rip; i < padded.size / WORD_BYTES; i++, pokeaddr += WORD_BYTES) 
		ptrace(PTRACE_POKETEXT, pid, pokeaddr, padded.shellcode[i]);
	printf("[+] Loader shellcode injected.\n");
	ptrace(PTRACE_CONT, pid, NULL, NULL);

	/* the shellcode will send to self a SIGUSR1 signal, upon receival we patch back the
	 * original code in the parent to resume normal execution */
	printf("[+] Waiting for SIGUSR1...\n");
	waitpid(pid, NULL, 0);
	ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo);
	if (siginfo.si_code != 10) { /* The signal received by the process is not SIGUSR1 */
		printf("[-] Received signal is not SIGUSR1, received %d instead, something went really bad, passing signal and detaching...", siginfo.si_code);
		kill(pid, siginfo.si_code); /* Pass back the signal to the process and detach */
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		exit(-1);
	}
	printf("[+] Process received SIGUSR1.\n");

	printf("[+] Restoring clobbered code...\n");
	for (i = 0, pokeaddr = reg_data.rip; i < padded.size / WORD_BYTES; i++, pokeaddr += WORD_BYTES) 
		ptrace(PTRACE_POKETEXT, pid, pokeaddr, clobbered_text[i]);
	free(clobbered_text);
	printf("[+] Clobbered coee restored.\n");

	printf("[+] Restoring registers context...\n");
	ptrace(PTRACE_SETREGS, pid, NULL, &reg_data);
	printf("[+] Restored registers context.\n");

	printf("[+] All done, hope it works! Detaching...\n");
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

