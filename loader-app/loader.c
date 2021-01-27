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

typedef enum
{
    SDK_VERSION_1_5,
    SDK_VERSION_2_0,
    SDK_VERSION_2_1,
    SDK_VERSION_2_2
} sdk_version_t;

typedef struct _system_features
{
    uint64_t cpu_features;
    sdk_version_t version;
    /* system feature set array. MSb of each element indicates whether this is
     * the last element. This will help tRTS to know when it can stop walking
     * through the array searching for certain features.
    */
    uint64_t system_feature_set[1];
    uint32_t cpuinfo_table[8][4];
    uint8_t* sealed_key;
    uint64_t size;
    uint64_t cpu_features_ext;
    uint32_t cpu_core_num;
}system_features_t;

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


typedef struct _thread_data_t
{
    unsigned long long  self_addr;
    unsigned long long  last_sp;            /* set by urts, relative to TCS */
    unsigned long long  stack_base_addr;    /* set by urts, relative to TCS */
    unsigned long long  stack_limit_addr;   /* set by urts, relative to TCS */
    unsigned long long  first_ssa_gpr;      /* set by urts, relative to TCS */
    unsigned long long  stack_guard;        /* GCC expects start_guard at 0x14 on x86 and 0x28 on x64 */

    unsigned long long  flags;
    unsigned long long  xsave_size;         /* in bytes (se_ptrace.c needs to know its offset).*/
    unsigned long long  last_error;         /* init to be 0. Used by trts. */

#ifdef TD_SUPPORT_MULTI_PLATFORM
    unsigned long long  m_next;             /* next TD used by trusted thread library (of type "struct _thread_data *") */
#else
    struct _thread_data_t *m_next;
#endif
    unsigned long long  tls_addr;           /* points to TLS pages */
    unsigned long long  tls_array;          /* points to TD.tls_addr relative to TCS */
#ifdef TD_SUPPORT_MULTI_PLATFORM
    unsigned long long  exception_flag;     /* mark how many exceptions are being handled */
#else
    intptr_t    exception_flag;
#endif
    unsigned long long  cxx_thread_info[6];
    unsigned long long  stack_commit_addr;
} thread_data_t;

typedef struct _ocall_context_t
{
    uintptr_t shadow0;
    uintptr_t shadow1;
    uintptr_t shadow2;
    uintptr_t shadow3;
    uintptr_t ocall_flag;
    uintptr_t ocall_index;
    uintptr_t pre_last_sp;
    uintptr_t r15;
    uintptr_t r14;
    uintptr_t r13;
    uintptr_t r12;
    uintptr_t xbp;
    uintptr_t xdi;
    uintptr_t xsi;
    uintptr_t xbx;
    uintptr_t reserved[3];
    uintptr_t ocall_depth;
    uintptr_t ocall_ret;
} ocall_context_t;


/**********************
 *  0 - DLSYM Loading *
 *  1 - MMAP Loading  *
 **********************/
#define LOADING 1

unsigned long long find_symbol(char * sym, unsigned long long handle, unsigned long long strtab, unsigned long long symbol_base,int num_entries) {

	/* TODO: Use DT_GNU_HASH or DT_HASH */

        unsigned long long idx =0;
	Elf64_Sym * symbol;
        while (idx < num_entries) {
                symbol = (sizeof(Elf64_Sym) * idx) + symbol_base;
                printf("%d:%s \r\n", symbol->st_value, strtab + symbol->st_name);
		if (strcmp(strtab + symbol->st_name, sym) == 0)
			return symbol->st_value + handle;
                idx++;
        }
	return 0;

}

void mymemcpy(void *dest, void *src, size_t n)
{
   // Typecast src and dest addresses to (char *)
   char *csrc = (char *)src;
   char *cdest = (char *)dest;

   // Copy contents of src[] to dest[]
   for (int i=0; i<n; i++)
       cdest[i] = csrc[i];
}
int main(int argc, char* argv[]) {
	 void (*ret)() = __builtin_extract_return_addr (__builtin_return_address (0));
	// get a handle to the library that contains 'puts' function
#if LOADING==0
	void * handle = dlopen ("./enclave.signed.so", RTLD_NOW);
#elif LOADING==1
	int fd;
	struct stat sb;
	fd = open("./enclave.signed.so", O_RDONLY);
	printf("Starting things \n");
	fstat(fd, &sb);
	void * handle = mmap (NULL, sb.st_size + 0x400000, PROT_WRITE | PROT_EXEC | PROT_READ, MAP_PRIVATE, fd, 0);
	/* TODO: Get the exact size of loaded image instead of just doing a buffer */
#if 00
	char* pointer1 = mmap((void *) ((unsigned long long )(handle + sb.st_size) & (unsigned long long)~(4096-1)),
                          0x200000,
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,
                          -1,
                          0);

	if ((long long)pointer1 <= 0) {
                char * err = explain_mmap((void *) ((unsigned long long)(handle + sb.st_size) & (unsigned long long)~(4096-1)),
                            0x200000,
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,
                            -1,
                            0);
                printf("%s \n",err);
        }
#endif
        /* Relocate the image */
	char* pointer1 = mmap(NULL,
			sb.st_size +0x400000,
			PROT_READ | PROT_WRITE | PROT_EXEC,
			 MAP_PRIVATE|MAP_ANONYMOUS,
			 -1,
			 0);

	memset(pointer1, 0, sb.st_size +0x400000);

	memcpy(pointer1, handle, sb.st_size);


	munmap(handle, sb.st_size);

	handle = pointer1;

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
		if (SHF_ALLOC & shdr[i].sh_flags)
			printf("LMA: %llx \n",(unsigned long long)(handle + shdr[i].sh_link));

		printf("Raw offset:%llx link:%llx flags:%llx info:%llx addr: %llx \n", shdr[i].sh_offset, shdr[i].sh_link, shdr[i].sh_flags, shdr[i].sh_info, shdr[i].sh_addr);
#endif 
#define ADDR 0x4002d60e08
		if ( (unsigned long long)(handle + shdr[i].sh_offset) < ADDR  &&
				(unsigned long long)(handle + shdr[i].sh_offset + shdr[i].sh_size) > ADDR) {
			printf("Them section is: %s \n \n \n \n \n", sh_strtab_p + shdr[i].sh_name);
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

	//memset(handle + shdr[i].sh_offset, 0, shdr[i].sh_size);
	//
	unsigned long long * pcl_entry = handle + shdr[i].sh_offset + 0xeec; 
	//*pcl_entry = 0x0;
	//unsigned long long * ippcpSetCpuFeatures= handle + shdr[i].sh_offset +0xef4;
	//*ippcpSetCpuFeatures = 0x0;

	/* Populate memset TODO: Fixme */
	//unsigned long long * memset_pointer = handle + shdr[i].sh_offset + 0xf34;
	//*memset_pointer = &memset;

	/* Setup heap */
	i=0;
	for (; i < shnum; ++i) {
		if (strcmp(sh_strtab_p + shdr[i].sh_name,".niprod")==0)
			break;
	}

	global_data_t * global_data = (global_data_t *) (handle + shdr[i].sh_offset);
	void * SSA= 0x680 + handle + shdr[i].sh_offset;
	global_data->heap_size = 4096;
	global_data->enclave_size = sb.st_size;
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

#if 10
	i =0;
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

	int num_entries = size/sizeof(Elf64_Sym);

	unsigned long long * memset_sym = 0;
	memset_sym  = find_symbol("__memset_vp", handle, strtab, symbol_base, num_entries);
	if (pcl_entry)
	*pcl_entry = &memset;

	pcl_entry = find_symbol("_Z9pcl_entryPvS_",  handle, strtab, symbol_base, num_entries);
	//if (pcl_entry)
	//*pcl_entry =0;
	pcl_entry = find_symbol("g_enclave_state",  handle, strtab, symbol_base, num_entries);
	if (pcl_entry)
		*pcl_entry = 0;

	unsigned long long* heap_base_sym = find_symbol("heap_base",  handle, strtab, symbol_base, num_entries);
	*heap_base_sym = 0;

	unsigned long long * g_ife_lock_sym = find_symbol("_ZL10g_ife_lock", handle, strtab, symbol_base, num_entries);


	pointer1 = mmap(NULL,
                        sb.st_size +0x400000,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE|MAP_ANONYMOUS,
                         -1,
                         0);




	/* relocate sections */
	i=0;
	for (; i < shnum; ++i) {
                if (shdr[i].sh_addr && shdr[i].sh_addr != shdr[i].sh_offset) {
			printf("Relocating %s\n",sh_strtab_p + shdr[i].sh_name); 
                        mymemcpy(handle + shdr[i].sh_addr, handle + shdr[i].sh_offset, shdr[i].sh_size);
		}
#if 0
		else {
			mymemcpy(pointer1 + shdr[i].sh_addr, handle + shdr[i].sh_offset, shdr[i].sh_size);
		}
#endif 
        }

        if (pcl_entry)
                *pcl_entry = 0;

	pcl_entry = 0x4003513fd8;
	*pcl_entry =0;
	*heap_base_sym = 0;

	unsigned long long * ippCPUFeature = 0x4003513fe0;
	*ippCPUFeature = 0;
	*memset_sym = &memset;
	*g_ife_lock_sym = 0;


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
	unsigned int index = ECMD_INIT_ENCLAVE;
	unsigned long long ret_val= 0;
	char ms[sizeof(system_features_t)];
	/* Populate the CPU features */
	system_features_t * info = ms;
	//TODO:cmon dude read for the cpu reg
	info->cpu_features= 251658239ull;
	info->cpu_features_ext = 9007268796301311ull;
	info->system_feature_set[0] = 13835058055282163712ull;
	info->sealed_key = 0x0;
	info->size = 176;
	info->version = SDK_VERSION_1_5;

	memset(info->cpuinfo_table, 0, sizeof(info->cpuinfo_table));

	info->cpuinfo_table[0][0] = 22;
	info->cpuinfo_table[0][1] = 1970169159;
	info->cpuinfo_table[0][2] = 1818588270;
	info->cpuinfo_table[0][3] = 1231384169;
	info->cpuinfo_table[1][0] = 591593;
        info->cpuinfo_table[1][1] = 51382272;
        info->cpuinfo_table[1][2] = 2147154943;
        info->cpuinfo_table[1][3] = 3219913727;
	info->cpuinfo_table[4][0] = 469778721;
          info->cpuinfo_table[4][1] = 29360191;
          info->cpuinfo_table[4][2] = 63;
          info->cpuinfo_table[4][3] = 0;
	info->cpuinfo_table[7][0] = 0;
          info->cpuinfo_table[7][1] = 43806655;
          info->cpuinfo_table[7][2] = 0;
          info->cpuinfo_table[7][3] = 2617255424;
      	

	




	thread_data_t * data = malloc(sizeof(thread_data_t));
	*(unsigned long long *)buffer = data;
	memset(data,0,sizeof(thread_data_t));

	/* Let make this check fail: thread_data->stack_base_addr == thread_data->last_sp */
	data->stack_base_addr = buffer;

	/* Mismatch case */
	ocall_context_t * ctxt = malloc(sizeof(ocall_context_t));
	data->last_sp = ctxt;
       	memset(ctxt,0,sizeof(ocall_context_t));
	ctxt->ocall_flag = 0x4F434944;	

	/* Match case */
	data->last_sp = data->stack_base_addr;

	arch_prctl(ARCH_SET_GS, buffer);
	//arch_prctl(ARCH_SET_FS, buffer); //Some older implementations use FS instead of GS, even then use ARCH_GET_FS
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


	index = 0;

	

	/* Get index, weird indices are fine */
	fgets(&index, sizeof(index), stdin);
	index = index%3;
	fgets(ms, sizeof(ms), stdin);

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

	char * c = getchar();

	printf("Postprocessing:%d \n", ret_comp);
	ret();
}
