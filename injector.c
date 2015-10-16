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
};

unsigned int loader_shellcode_length = 0;

/* We expect the shellcode to end with 2 processor-sized WORDS and two buffers of 100 bytes each */
void patch_shellcode(unsigned char *shellcode, int len, WORD_CTYPE dlopen_addr, WORD_CTYPE dlsym_addr, char *so, char *entrypoint) {
	unsigned char *ptr;	
	ptr = &shellcode[len - 1 - 100 * 2 - sizeof(WORD_CTYPE) * 2];
	*((WORD_CTYPE *)ptr) = dlopen_addr;
	ptr += sizeof(WORD_CTYPE);
	*((WORD_CTYPE *)ptr) = dlsym_addr;
	ptr += sizeof(WORD_CTYPE);
	strncpy(ptr, so, 100);
	ptr += 100;
	strncpy(ptr, so, 100);
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

	if (argc != 6) {
		printf("Usage: injector PID dlopen_address dlsym_address so entrypoint\n");
		exit(1);
	}

	pid = atoi(argv[1]);
	dlopen_addr = atol(argv[2]);
	dlsym_addr = atol(argv[3]);
	so = argv[4];
	entrypoint = argv[5];

	fd = (so, O_RDONLY);
	if (!fd) {
		printf("[-] Unable to find .so file %s\n", so);
		exit(1);
	}
	close(fd);


	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
		printf("[-] Unable to attach to %d\n", pid);
		exit(1);
	}
	printf("[+] Successfully attached to %d\n", pid);
	waitpid(pid, NULL, 0);

	ptrace(PTRACE_GETREGS, pid, NULL, &reg_data);
	if (reg_data.rip & 0xffffffff == 0xffffffff) {
		printf("[-] RIP looks broken\n");
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		exit(1);
	}
	printf("[+] Got reg data\n[+] RIP is at %016llx\n", reg_data.rip);

	/* Prepare shellcode */
	patch_shellcode(loader_shellcode, loader_shellcode_length, dlopen_addr, dlsym_addr, so, entrypoint);
	pad_shellcode(loader_shellcode, loader_shellcode_length, &padded);

	/* save clobbered .text section */
	printf("[+] Dumping clobbered code segment...");
	clobbered_text = (WORD_CTYPE *)malloc(padded.size);
	for (i = 0, pokeaddr = reg_data.rip; i < padded.size / WORD_BYTES; i++, pokeaddr += WORD_BYTES)
		clobbered_text[i] = ptrace(PTRACE_PEEKTEXT, pid, pokeaddr, NULL);
	printf("[+] Code dumped.\n");

	/* Inject shellcode */
	printf("[+] Injecting loader shellcode...\n");
	for (i = 0, pokeaddr = reg_data.rip; i < padded.size / WORD_BYTES; i++, pokeaddr += WORD_BYTES) 
		ptrace(PTRACE_POKETEXT, pid, pokeaddr, padded.shellcode[i]);
	printf("[+] Loader shellcode injected.");
	ptrace(PTRACE_CONT, pid, NULL, NULL);

	/* the shellcode will send to self a SIGUSR1 signal, upon receival we patch back the
	 * original code in the parent to resume normal eecution */
	printf("[+] Waiting for SIGUSR1...\n");
	waitpid(pid, NULL, 0);
	ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo);
	if (siginfo.si_code != 10) { /* The signal received by the process is not SIGUSR1 */
		printf("[-] Received signal not SIGUSR1, something went really bad, passing signal and detaching...");
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

