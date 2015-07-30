#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>

#include <bsd/vis.h>

int find_offset(char *path, char *symbol) {
	int fd, i; 
	Elf *e;
	size_t n, shstrndx;
	GElf_Phdr phdr; 
	GElf_Shdr shdr;
	Elf_Data *data;
	Elf_Scn *scn;
	unsigned long long int vaddr;
	char *section_name, *p, *name, pc[4*sizeof(char)];

	
	if ((fd = open(path, O_RDONLY, 0)) < 0) {
		printf("error opening %s\n", path);
		return -1;
	}

	elf_version(EV_CURRENT);

	if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
		printf("error reading ELF %s: %s\n", path, elf_errmsg(elf_errno()));
		return -1;
	}

	if (elf_getphdrnum(e, &n) != 0) {
		printf("error getting ELF header: %s\n", elf_errmsg(elf_errno()));
		return -1;
	}

	for (i = 0, vaddr = 0; i < n ; i++) {
		if (gelf_getphdr(e, i, &phdr) != &phdr ) {
			printf("error getting ELF program header: %s", elf_errmsg(elf_errno()));
			return -1;
		}

		if (phdr.p_type & PT_LOAD && phdr.p_flags & (PF_R | PF_X)) { /* First LOAD RX section */
			vaddr = phdr.p_vaddr;
			break;
		}
	}

	if (vaddr == 0) {
		printf("error getting a RX LOAD section: WTF?!?\n");
		return -1;
	}

	if (elf_getshdrstrndx(e, &shstrndx ) != 0) {
		printf("error in elf_getshdrstrndx: %s\n", elf_errmsg(elf_errno()));
		return -1;
	}

	scn = NULL;
	while ((scn = elf_nextscn(e, scn)) != NULL) {
		if (gelf_getshdr(scn, &shdr) != & shdr ) {
			printf("error getting section header: %s", elf_errmsg(elf_errno()));
			return -1;
		}

		/*
		if ((name = elf_strptr(e, shstrndx, shdr.sh_name)) == NULL) {
			printf("error getting section header: %s", elf_errmsg(elf_errno()));
			return -1;
		}

		//if (strcmp(name, ".dynsym") == 0) { /* Here we can get the address for the symbol exported by the ELF */
			n = 0;
			while (n < shdr.sh_size) {
				data = elf_getdata(scn, data);
				if (!data) {
					printf("error getting section data: %s", elf_errmsg(elf_errno()));
					break;
				}
				p = (char *) data->d_buf;
				while (p < ( char *) data->d_buf + data->d_size ) {
					if ( vis ( pc , *p , VIS_WHITE , 0))
						printf ( "  %s " , pc );
					n ++; p ++;
		
				}

			}
		//}

	}

}

int main(int argc, char **argv) {
	if (argc != 3) {
		printf("Usage: %s ELF SYMBOL\n", argv[0]);
		exit(1);
	}

	find_offset(argv[1], argv[2]);
}

