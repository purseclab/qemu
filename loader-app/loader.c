#include <stdio.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <asm/prctl.h>
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

int main() {
	 // get a handle to the library that contains 'puts' function
	 void * handle = dlopen ("./enclave.signed.so", RTLD_LAZY);
	 typedef int (*test_t)(int);
	 test_t test =  (test_t) dlsym(handle, "enclave_entry");
	 uint64_t rax = 0;
	 int i;
	 void *buffer = malloc(100 * sizeof(char));
	 char *pointer = malloc(sizeof(tcs_t) + 0x20000);
	 tcs_t *tcs = (tcs_t *)(pointer + 0x20000);
	 int index = 1;
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

	 volatile int ret_comp;
	 ret_comp = 100;
	 ret_comp++;

	 printf("Postprocessing:%d \n", ret_comp);
}
