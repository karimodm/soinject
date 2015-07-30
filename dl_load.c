#include <dlfcn.h>

int main() {
	unsigned long long int handle = (unsigned long long int) dlopen("/lib/x86_64-linux-gnu/libdl.so.2", RTLD_NOW);
	unsigned long long int sym = (unsigned long long int) dlsym(handle, "dlopen");
	printf("OFFSET IS: %d\n", (int) sym - handle);
}
