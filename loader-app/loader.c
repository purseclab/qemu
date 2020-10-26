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
typedef struct _tcs_t
{
	uint64_t            reserved0;       /* (0) */
	uint64_t            flags;           /* (8)bit 0: DBGOPTION */
	uint64_t            ossa;            /* (16)State Save Area */
	uint32_t            cssa;            /* (24)Current SSA slot */
	uint32_t            nssa;            /* (28)Number of SSA slots */
	uint64_t            oentry;          /* (32)Offset in enclave to which control is transferred on EENTER if enclave INACTIVE state */
	uint64_t            reserved1;       /* (40) */
	uint64_t            ofs_base;        /* (48)When added to the base address of the enclave, produces the base address FS segment inside the enclave */
	uint64_t            ogs_base;        /* (56)When added to the base address of the enclave, produces the base address GS segment inside the enclave */
	uint32_t            ofs_limit;       /* (64)Size to become the new FS limit in 32-bit mode */
	uint32_t            ogs_limit;       /* (68)Size to become the new GS limit in 32-bit mode */
#define TCS_RESERVED_LENGTH 4024
	uint8_t             reserved[TCS_RESERVED_LENGTH];  /* (72) */
}tcs_t;

#define ECMD_ECALL           0
#define ECMD_INIT_ENCLAVE   -1
#define ECMD_ORET           -2
#define ECMD_EXCEPT         -3
#define ECMD_MKTCS          -4
#define ECMD_UNINIT_ENCLAVE -5

typedef struct _global_data_t
{
	unsigned long long     enclave_size;
	unsigned long long     heap_offset;
	unsigned long long     heap_size;
	unsigned long long     rsrv_offset;
	unsigned long long     rsrv_size;
	unsigned long long     rsrv_executable;
	unsigned long long     thread_policy;
	unsigned long long     tcs_max_num;
	void *  td_template; //TODO: Fix this 
	uint8_t        tcs_template[200];
	uint32_t       layout_entry_num;
	uint32_t       reserved;
	uint64_t       layout_table[0];//TODO:Fix this 
} global_data_t;


/**********************
 *  0 - DLSYM Loading *
 *  1 - MMAP Loading  *
 **********************/
#define LOADING 1

int main() {
	// get a handle to the library that contains 'puts' function
#if LOADING==0
	void * handle = dlopen ("./enclave.signed.so", RTLD_NOW);
#elif LOADING==1
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

	int i=0;
	for (; i < shnum; ++i) {
#if 0
		printf("%2d: %4d '%s'\n", i, shdr[i].sh_name,
				sh_strtab_p + shdr[i].sh_name);
		printf("Base: %llx End:%llx \n", (unsigned long long)(handle + shdr[i].sh_offset), 
				(unsigned long long)(handle + shdr[i].sh_offset + shdr[i].sh_size));

		if ( (unsigned long long)(handle + shdr[i].sh_offset) < 0x7ffff7fd0fe8  && 
				(unsigned long long)(handle + shdr[i].sh_offset + shdr[i].sh_size) > 0x7ffff7fd0fe8) {
			printf("Them section is: %s \n", sh_strtab_p + shdr[i].sh_name);
		}
#endif 
		if (strcmp(sh_strtab_p + shdr[i].sh_name,".bss")==0)
			break;
	}

	memset(handle + shdr[i].sh_offset, 0, shdr[i].sh_size);

	i=0;
	for (; i < shnum; ++i) {
#if 10
		printf("%2d: %4d '%s'\n", i, shdr[i].sh_name,
				sh_strtab_p + shdr[i].sh_name);
		printf("Base: %llx End:%llx \n", (unsigned long long)(handle + shdr[i].sh_offset),
				(unsigned long long)(handle + shdr[i].sh_offset + shdr[i].sh_size));
#endif 

		if ( (unsigned long long)(handle + shdr[i].sh_offset) < 0x4002d5c800  &&
				(unsigned long long)(handle + shdr[i].sh_offset + shdr[i].sh_size) > 0x4002d5c800) {
			printf("Them section is: %s \n", sh_strtab_p + shdr[i].sh_name);
		}
#if 0
		if (shdr[i].sh_offset > 0x10fe8) {
			printf("Them section is beyond the offset: %s", sh_strtab_p + shdr[i].sh_name);
		}
#endif 
	}

	i=0;
	for (; i < shnum; ++i) {
		if (strcmp(sh_strtab_p + shdr[i].sh_name,".note.sgxmeta")==0)
			break;
	}

	memset(handle + shdr[i].sh_offset, 0, shdr[i].sh_size);

	/* Populate memset TODO: Fixme */
	unsigned long long * memset_pointer = handle + shdr[i].sh_offset + 0xf34;
	*memset_pointer = &memset;

	/* Setup heap */
	i=0;
	for (; i < shnum; ++i) {
		if (strcmp(sh_strtab_p + shdr[i].sh_name,".niprod")==0)
			break;
	}

	global_data_t * global_data = (global_data_t *) (handle + shdr[i].sh_offset);
	void * SSA= 0x680 + handle + shdr[i].sh_offset;
	global_data->heap_size = 4096;
	global_data->heap_offset = sb.st_size;
	unsigned long long heap_base = handle + sb.st_size;
	heap_base = (heap_base & ~(4096-1)) + (32*4096);

	global_data->heap_offset = heap_base - (unsigned long long)handle;

	/* TODO: Get exact size! */
	memset(SSA,0,1024);

#if 01
	/* Get anonymous mapping at the end TODO: MAP_FIXED is not too friendly */
	long long heap_handle = 
		mmap (heap_base, 4096, PROT_WRITE | PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, 0, 0);

	if (heap_handle < 0) {
		char * err = explain_mmap(heap_base, 4096, PROT_WRITE | PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, 0, 0);
		printf("%s \n",err);
	}


	long long reserved_mem_handle = 
		mmap (heap_base+4096, 4096, PROT_WRITE | PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, 0, 0);
	if (reserved_mem_handle < 0) {
		char * err = explain_mmap(heap_base+4096, 4096, PROT_WRITE | PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, 0, 0);
		printf("%s \n",err);
	}

	global_data->rsrv_size = 4096;

	global_data->rsrv_offset = reserved_mem_handle - (unsigned long long)handle;
#endif 

#if 0
	i =0;
	for (; i < shnum; ++i) {
		printf("%2d: %4d '%s'\n", i, shdr[i].sh_name,
                                sh_strtab_p + shdr[i].sh_name);
		if (strcmp(sh_strtab_p + shdr[i].sh_name,".symtab")==0)
			break;
	}
	Elf64_Sym * symbol = handle + shdr[i].sh_offset; //shdr[i].sh_size
	unsigned long long size = shdr[i].sh_size;
	
	for (i=0; i < shnum; ++i) {
                if (strcmp(sh_strtab_p + shdr[i].sh_name,".strtab")==0)
                        break;
        }
	char * strtab = handle + shdr[i].sh_offset; 

	int num_entries = size/sizeof(Elf64_Sym);
	int idx =0;
	while (idx < num_entries) {
		printf("%s \r\n", strtab[symbol[idx].st_name]);
		idx++;
	}

#endif 






#endif

#if LOADING==0
	void * test =  dlsym(handle, "enclave_entry");
#elif LOADING==1
	void * test = header->e_entry + (unsigned long long)handle;
#endif 
	uint64_t rax = 0;
	void *buffer = malloc(100 * sizeof(char));
	char *pointer = malloc(sizeof(tcs_t) + 0x20000);
	tcs_t *tcs = (tcs_t *)(pointer + 0x20000);
	int index = ECMD_INIT_ENCLAVE;
	unsigned long long ret_val= 0;
	char ms[100];
	ms[0]=1;

	arch_prctl(ARCH_SET_GS, buffer);
	/* 
	 *  *      edi >=  0 - ecall
	 *      edi == -1 - do_init_enclave
	 *      edi == -2 - oret
	 *
	 * */

	__asm__ __volatile__("mov %1, %%rax\n\t"
			"mov %3, %%rbx\n\t"
			"mov %4, %%edi\n\t"
			"mov %5, %%rsi\n\t"
			"add $2, %%rcx\n\t"
			"lea .RETPOINT(%%rip), %%rcx\n\t"
			"call *%2 \n\t"
			".RETPOINT:\n\t"
			"nop\n\t"
			"mov %%rax,%0"
			: "=r" (ret_val)
			: "r" (rax), "r" (test), "r" (tcs), "r" (index), "r" (&ms)
			: "rax", "rcx", "rsi", "edi", "rbx", "memory");


	index = 1;

	__asm__ __volatile__("mov %1, %%rax\n\t"
                        "mov %3, %%rbx\n\t"
                        "mov %4, %%edi\n\t"
                        "mov %5, %%rsi\n\t"
                        "add $2, %%rcx\n\t"
                        "lea .RETPOINT2(%%rip), %%rcx\n\t"
                        "call *%2 \n\t"
                        ".RETPOINT2:\n\t"
                        "nop\n\t"
                        "mov %%rax,%0"
                        : "=r" (ret_val)
                        : "r" (rax), "r" (test), "r" (tcs), "r" (index), "r" (&ms)
                        : "rax", "rcx", "rsi", "edi", "rbx", "memory");

	volatile int ret_comp;
	ret_comp = 100;
	ret_comp++;

	printf("Postprocessing:%d \n", ret_comp);
}
