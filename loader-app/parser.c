#include <stdio.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <asm/prctl.h>
#include <sys/mman.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <libexplain/mmap.h>
#if defined(__LP64__)
#define ElfW(type) Elf64_ ## type
#else
#define ElfW(type) Elf32_ ## type
#endif
typedef __seg_gs char gs_str;


/**********************
 *  0 - DLSYM Loading *
 *  1 - MMAP Loading  *
 **********************/
#define LOADING 1

int main() {
	 void (*ret)() = __builtin_extract_return_addr (__builtin_return_address (0));
	// get a handle to the library that contains 'puts' function
	int fd;
	struct stat sb;
	fd = open("./enclave.signed.so", O_RDONLY);
	fstat(fd, &sb);
	void * handle = mmap (NULL, sb.st_size, PROT_WRITE | PROT_EXEC | PROT_READ, MAP_PRIVATE, fd, 0);
	ElfW(Ehdr) *header = handle;

	/* Clear out BSS */
	unsigned long long secoff = header->e_shoff;
	//section = (Elf32_Shdr *)(handle + secoff);
	Elf64_Ehdr *ehdr = (Elf64_Ehdr*) handle;
	Elf64_Shdr *shdr = (Elf64_Shdr *)(handle + ehdr->e_shoff);
	int shnum = ehdr->e_shnum;	

	Elf64_Shdr *sh_strtab = &shdr[ehdr->e_shstrndx];
	const char *const sh_strtab_p = handle + sh_strtab->sh_offset;

	int i =0;
	for (; i < shnum; ++i) {
		printf("%2d: %4d '%s'\n", i, shdr[i].sh_name,
                                sh_strtab_p + shdr[i].sh_name);
		if (strcmp(sh_strtab_p + shdr[i].sh_name,".symtab")==0)
			break;
	}
	unsigned long long symbol_base = handle + shdr[i].sh_offset; //shdr[i].sh_size
	unsigned long long size = shdr[i].sh_size;
	
	for (i=0; i < shnum; ++i) {
                if (strcmp(sh_strtab_p + shdr[i].sh_name,".strtab")==0)
                        break;
        }
	char * strtab = handle + shdr[i].sh_offset;
	//Elf_Scn *strscn;	

	int num_entries = size/sizeof(Elf64_Sym);
	unsigned long long idx =0;
	while (idx < num_entries) {
		Elf64_Sym * symbol = (sizeof(Elf64_Sym) * idx) + symbol_base;
		printf("%d:%d, %s \r\n", symbol->st_name, strtab + symbol->st_name - (unsigned char)handle, strtab + symbol->st_name);
		idx++;
	}

	printf("%s", handle + 219534);

}
