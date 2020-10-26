
./enclave.so:     file format elf64-x86-64


Disassembly of section .plt:

0000000000001000 <.plt>:
    1000:	ff 35 d2 ff 00 00    	pushq  0xffd2(%rip)        # 10fd8 <_GLOBAL_OFFSET_TABLE_+0x8>
    1006:	ff 25 d4 ff 00 00    	jmpq   *0xffd4(%rip)        # 10fe0 <_GLOBAL_OFFSET_TABLE_+0x10>
    100c:	0f 1f 40 00          	nopl   0x0(%rax)

Disassembly of section .plt.got:

0000000000001010 <_Z9pcl_entryPvS_@plt>:
    1010:	ff 25 d2 ff 00 00    	jmpq   *0xffd2(%rip)        # 10fe8 <_Z9pcl_entryPvS_>
    1016:	66 90                	xchg   %ax,%ax

0000000000001018 <ippcpSetCpuFeatures@plt>:
    1018:	ff 25 d2 ff 00 00    	jmpq   *0xffd2(%rip)        # 10ff0 <ippcpSetCpuFeatures>
    101e:	66 90                	xchg   %ax,%ax

Disassembly of section .text:

0000000000001020 <sgx_test>:
typedef struct ms_test_t {
	int ms_retval;
} ms_test_t;

static sgx_status_t SGX_CDECL sgx_test(void* pms)
{
    1020:	55                   	push   %rbp
    1021:	48 89 e5             	mov    %rsp,%rbp
    1024:	48 83 ec 20          	sub    $0x20,%rsp
    1028:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
	CHECK_REF_POINTER(pms, sizeof(ms_test_t));
    102c:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    1031:	74 15                	je     1048 <sgx_test+0x28>
    1033:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1037:	be 04 00 00 00       	mov    $0x4,%esi
    103c:	48 89 c7             	mov    %rax,%rdi
    103f:	e8 1f 03 00 00       	callq  1363 <sgx_is_outside_enclave>
    1044:	85 c0                	test   %eax,%eax
    1046:	75 07                	jne    104f <sgx_test+0x2f>
    1048:	b8 02 00 00 00       	mov    $0x2,%eax
    104d:	eb 22                	jmp    1071 <sgx_test+0x51>
	//
	// fence after pointer checks
	//
	sgx_lfence();
    104f:	0f ae e8             	lfence 
	ms_test_t* ms = SGX_CAST(ms_test_t*, pms);
    1052:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1056:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
	sgx_status_t status = SGX_SUCCESS;
    105a:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)



	ms->ms_retval = test();
    1061:	e8 0d 00 00 00       	callq  1073 <test>
    1066:	89 c2                	mov    %eax,%edx
    1068:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    106c:	89 10                	mov    %edx,(%rax)


	return status;
    106e:	8b 45 f4             	mov    -0xc(%rbp),%eax
}
    1071:	c9                   	leaveq 
    1072:	c3                   	retq   

0000000000001073 <test>:
	return;
}
#pragma GCC pop_options
extern int relocate_enclave(void * base);
extern "C" int enter_enclave(int index, void *ms, void *tcs, int cssa);
int test() {
    1073:	55                   	push   %rbp
    1074:	48 89 e5             	mov    %rsp,%rbp
    1077:	48 83 ec 20          	sub    $0x20,%rsp
    107b:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    1082:	00 00 
    1084:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1088:	31 c0                	xor    %eax,%eax
	volatile int i =0;
    108a:	c7 45 e8 00 00 00 00 	movl   $0x0,-0x18(%rbp)
	i=43;
    1091:	c7 45 e8 2b 00 00 00 	movl   $0x2b,-0x18(%rbp)
	i++;
    1098:	8b 45 e8             	mov    -0x18(%rbp),%eax
    109b:	83 c0 01             	add    $0x1,%eax
    109e:	89 45 e8             	mov    %eax,-0x18(%rbp)
	//relocate_enclave((void*) 0x7ffff7fe5000);
	char buf[10];
	enter_enclave(-1,(void *)buf, (void *)buf,0);
    10a1:	48 8d 55 ee          	lea    -0x12(%rbp),%rdx
    10a5:	48 8d 45 ee          	lea    -0x12(%rbp),%rax
    10a9:	b9 00 00 00 00       	mov    $0x0,%ecx
    10ae:	48 89 c6             	mov    %rax,%rsi
    10b1:	bf ff ff ff ff       	mov    $0xffffffff,%edi
    10b6:	e8 c9 b3 00 00       	callq  c484 <enter_enclave>
	return (int)i;
    10bb:	8b 45 e8             	mov    -0x18(%rbp),%eax
}
    10be:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    10c2:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    10c9:	00 00 
    10cb:	74 05                	je     10d2 <test+0x5f>
    10cd:	e8 d6 41 00 00       	callq  52a8 <__stack_chk_fail>
    10d2:	c9                   	leaveq 
    10d3:	c3                   	retq   

00000000000010d4 <_ZL28set_global_feature_indicatormm>:
extern "C" int sgx_init_string_lib(uint64_t cpu_feature_indicator);
extern "C" sgx_status_t sgx_init_crypto_lib(uint64_t cpu_feature_indicator, uint32_t *cpuinfo_table);


static int set_global_feature_indicator(uint64_t feature_bit_array, uint64_t xfrm)
{
    10d4:	55                   	push   %rbp
    10d5:	48 89 e5             	mov    %rsp,%rbp
    10d8:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    10dc:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    // Confirm the reserved bits and the unset bits by uRTS must be 0.
    
    
    if(feature_bit_array & (RESERVED_CPU_FEATURE_BIT))
    10e0:	48 b8 00 00 00 00 00 	movabs $0xff00000000000000,%rax
    10e7:	00 00 ff 
    10ea:	48 23 45 f8          	and    -0x8(%rbp),%rax
    10ee:	48 85 c0             	test   %rax,%rax
    10f1:	74 0e                	je     1101 <_ZL28set_global_feature_indicatormm+0x2d>
    {
        // clear the reserved bits
        feature_bit_array = feature_bit_array & (~(RESERVED_CPU_FEATURE_BIT));
    10f3:	48 b8 ff ff ff ff ff 	movabs $0xffffffffffffff,%rax
    10fa:	ff ff 00 
    10fd:	48 21 45 f8          	and    %rax,-0x8(%rbp)
    }

    // Requires SSE4.1. Take SSE4.1 as the baseline.
    if(!(feature_bit_array & ~(CPU_FEATURE_SSE4_1 - 1)))
    1101:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1105:	48 25 00 fe ff ff    	and    $0xfffffffffffffe00,%rax
    110b:	48 85 c0             	test   %rax,%rax
    110e:	75 0a                	jne    111a <_ZL28set_global_feature_indicatormm+0x46>
    {
        return -1;
    1110:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    1115:	e9 02 01 00 00       	jmpq   121c <_ZL28set_global_feature_indicatormm+0x148>
    }

    // Check for inconsistencies in the CPUID feature mask.
    if ( (((feature_bit_array & CPU_FEATURE_SSE) == CPU_FEATURE_SSE) &&((feature_bit_array & (CPU_FEATURE_SSE - 1)) != (CPU_FEATURE_SSE - 1))) || 
    111a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    111e:	83 e0 20             	and    $0x20,%eax
    1121:	48 85 c0             	test   %rax,%rax
    1124:	74 11                	je     1137 <_ZL28set_global_feature_indicatormm+0x63>
    1126:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    112a:	83 e0 1f             	and    $0x1f,%eax
    112d:	48 83 f8 1f          	cmp    $0x1f,%rax
    1131:	0f 85 8f 00 00 00    	jne    11c6 <_ZL28set_global_feature_indicatormm+0xf2>
        (((feature_bit_array & CPU_FEATURE_SSE2) == CPU_FEATURE_SSE2) &&((feature_bit_array & (CPU_FEATURE_SSE2 - 1)) != (CPU_FEATURE_SSE2 - 1))) ||
    1137:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    113b:	83 e0 40             	and    $0x40,%eax
    if ( (((feature_bit_array & CPU_FEATURE_SSE) == CPU_FEATURE_SSE) &&((feature_bit_array & (CPU_FEATURE_SSE - 1)) != (CPU_FEATURE_SSE - 1))) || 
    113e:	48 85 c0             	test   %rax,%rax
    1141:	74 0d                	je     1150 <_ZL28set_global_feature_indicatormm+0x7c>
        (((feature_bit_array & CPU_FEATURE_SSE2) == CPU_FEATURE_SSE2) &&((feature_bit_array & (CPU_FEATURE_SSE2 - 1)) != (CPU_FEATURE_SSE2 - 1))) ||
    1143:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1147:	83 e0 3f             	and    $0x3f,%eax
    114a:	48 83 f8 3f          	cmp    $0x3f,%rax
    114e:	75 76                	jne    11c6 <_ZL28set_global_feature_indicatormm+0xf2>
        (((feature_bit_array & CPU_FEATURE_SSE3) == CPU_FEATURE_SSE3) &&((feature_bit_array & (CPU_FEATURE_SSE3 - 1)) != (CPU_FEATURE_SSE3 - 1))) ||
    1150:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1154:	25 80 00 00 00       	and    $0x80,%eax
        (((feature_bit_array & CPU_FEATURE_SSE2) == CPU_FEATURE_SSE2) &&((feature_bit_array & (CPU_FEATURE_SSE2 - 1)) != (CPU_FEATURE_SSE2 - 1))) ||
    1159:	48 85 c0             	test   %rax,%rax
    115c:	74 0d                	je     116b <_ZL28set_global_feature_indicatormm+0x97>
        (((feature_bit_array & CPU_FEATURE_SSE3) == CPU_FEATURE_SSE3) &&((feature_bit_array & (CPU_FEATURE_SSE3 - 1)) != (CPU_FEATURE_SSE3 - 1))) ||
    115e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1162:	83 e0 7f             	and    $0x7f,%eax
    1165:	48 83 f8 7f          	cmp    $0x7f,%rax
    1169:	75 5b                	jne    11c6 <_ZL28set_global_feature_indicatormm+0xf2>
        (((feature_bit_array & CPU_FEATURE_SSSE3) == CPU_FEATURE_SSSE3) && ((feature_bit_array & (CPU_FEATURE_SSSE3 - 1)) != (CPU_FEATURE_SSSE3 - 1))) ||
    116b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    116f:	25 00 01 00 00       	and    $0x100,%eax
        (((feature_bit_array & CPU_FEATURE_SSE3) == CPU_FEATURE_SSE3) &&((feature_bit_array & (CPU_FEATURE_SSE3 - 1)) != (CPU_FEATURE_SSE3 - 1))) ||
    1174:	48 85 c0             	test   %rax,%rax
    1177:	74 0f                	je     1188 <_ZL28set_global_feature_indicatormm+0xb4>
        (((feature_bit_array & CPU_FEATURE_SSSE3) == CPU_FEATURE_SSSE3) && ((feature_bit_array & (CPU_FEATURE_SSSE3 - 1)) != (CPU_FEATURE_SSSE3 - 1))) ||
    1179:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    117d:	0f b6 c0             	movzbl %al,%eax
    1180:	48 3d ff 00 00 00    	cmp    $0xff,%rax
    1186:	75 3e                	jne    11c6 <_ZL28set_global_feature_indicatormm+0xf2>
        (((feature_bit_array & CPU_FEATURE_SSE4_1) == CPU_FEATURE_SSE4_1) && ((feature_bit_array & (CPU_FEATURE_SSE4_1 - 1)) != (CPU_FEATURE_SSE4_1 - 1))) ||
    1188:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    118c:	25 00 02 00 00       	and    $0x200,%eax
        (((feature_bit_array & CPU_FEATURE_SSSE3) == CPU_FEATURE_SSSE3) && ((feature_bit_array & (CPU_FEATURE_SSSE3 - 1)) != (CPU_FEATURE_SSSE3 - 1))) ||
    1191:	48 85 c0             	test   %rax,%rax
    1194:	74 11                	je     11a7 <_ZL28set_global_feature_indicatormm+0xd3>
        (((feature_bit_array & CPU_FEATURE_SSE4_1) == CPU_FEATURE_SSE4_1) && ((feature_bit_array & (CPU_FEATURE_SSE4_1 - 1)) != (CPU_FEATURE_SSE4_1 - 1))) ||
    1196:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    119a:	25 ff 01 00 00       	and    $0x1ff,%eax
    119f:	48 3d ff 01 00 00    	cmp    $0x1ff,%rax
    11a5:	75 1f                	jne    11c6 <_ZL28set_global_feature_indicatormm+0xf2>
        (((feature_bit_array & CPU_FEATURE_SSE4_2) == CPU_FEATURE_SSE4_2) && ((feature_bit_array & (CPU_FEATURE_SSE4_2 - 1)) != (CPU_FEATURE_SSE4_2 - 1))) )
    11a7:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    11ab:	25 00 04 00 00       	and    $0x400,%eax
        (((feature_bit_array & CPU_FEATURE_SSE4_1) == CPU_FEATURE_SSE4_1) && ((feature_bit_array & (CPU_FEATURE_SSE4_1 - 1)) != (CPU_FEATURE_SSE4_1 - 1))) ||
    11b0:	48 85 c0             	test   %rax,%rax
    11b3:	74 18                	je     11cd <_ZL28set_global_feature_indicatormm+0xf9>
        (((feature_bit_array & CPU_FEATURE_SSE4_2) == CPU_FEATURE_SSE4_2) && ((feature_bit_array & (CPU_FEATURE_SSE4_2 - 1)) != (CPU_FEATURE_SSE4_2 - 1))) )
    11b5:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    11b9:	25 ff 03 00 00       	and    $0x3ff,%eax
    11be:	48 3d ff 03 00 00    	cmp    $0x3ff,%rax
    11c4:	74 07                	je     11cd <_ZL28set_global_feature_indicatormm+0xf9>
    {
        return -1;
    11c6:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    11cb:	eb 4f                	jmp    121c <_ZL28set_global_feature_indicatormm+0x148>
    }

    // Determine whether the OS & ENCLAVE support SAVE/RESTORE of the AVX register set
    // IF NOT, clear the advanced feature set bits corresponding to AVX and beyond
    if(!XFEATURE_ENABLED_AVX(xfrm))
    11cd:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    11d1:	83 e0 06             	and    $0x6,%eax
    11d4:	48 83 f8 06          	cmp    $0x6,%rax
    11d8:	74 10                	je     11ea <_ZL28set_global_feature_indicatormm+0x116>
    {
        // AVX is disabled by OS, so clear the AVX related feature bits
	feature_bit_array &= (~(CPU_FEATURE_AVX | CPU_FEATURE_VAES | CPU_FEATURE_VPCLMULQDQ | CPU_FEATURE_F16C | CPU_FEATURE_AVX2 |
    11da:	48 b8 ff 7f 12 86 08 	movabs $0xfffe200886127fff,%rax
    11e1:	20 fe ff 
    11e4:	48 21 45 f8          	and    %rax,-0x8(%rbp)
    11e8:	eb 1f                	jmp    1209 <_ZL28set_global_feature_indicatormm+0x135>
            CPU_FEATURE_AVX512F | CPU_FEATURE_AVX512CD | CPU_FEATURE_AVX512ER | CPU_FEATURE_AVX512PF | CPU_FEATURE_AVX512DQ | CPU_FEATURE_AVX512BW |
            CPU_FEATURE_AVX512VL | CPU_FEATURE_AVX512IFMA52 | CPU_FEATURE_AVX512VBMI | CPU_FEATURE_AVX512_VPOPCNTDQ | CPU_FEATURE_AVX512_4VNNIW |
            CPU_FEATURE_AVX512_4FMAPS | CPU_FEATURE_AVX512_BITALG | CPU_FEATURE_AVX512_VBMI2 | CPU_FEATURE_AVX512_VNNI));
    }

    else if (!XFEATURE_ENABLED_AVX3(xfrm))
    11ea:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    11ee:	25 e0 00 00 00       	and    $0xe0,%eax
    11f3:	48 3d e0 00 00 00    	cmp    $0xe0,%rax
    11f9:	74 0e                	je     1209 <_ZL28set_global_feature_indicatormm+0x135>
    {
        feature_bit_array &= (~(CPU_FEATURE_AVX512F | CPU_FEATURE_AVX512CD | CPU_FEATURE_AVX512ER | CPU_FEATURE_AVX512PF | CPU_FEATURE_AVX512DQ |
    11fb:	48 b8 ff ff ff b6 18 	movabs $0xfffee018b6ffffff,%rax
    1202:	e0 fe ff 
    1205:	48 21 45 f8          	and    %rax,-0x8(%rbp)
            CPU_FEATURE_AVX512BW | CPU_FEATURE_AVX512VL | CPU_FEATURE_AVX512IFMA52 | CPU_FEATURE_AVX512VBMI | CPU_FEATURE_AVX512_VPOPCNTDQ |
            CPU_FEATURE_AVX512_4VNNIW | CPU_FEATURE_AVX512_4FMAPS | CPU_FEATURE_AVX512_BITALG | CPU_FEATURE_AVX512_VBMI2 | CPU_FEATURE_AVX512_VNNI));
    }

    g_cpu_feature_indicator = feature_bit_array;
    1209:	48 8d 05 e8 fb 00 00 	lea    0xfbe8(%rip),%rax        # 10df8 <g_cpu_feature_indicator>
    1210:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    1214:	48 89 10             	mov    %rdx,(%rax)
    return 0;
    1217:	b8 00 00 00 00       	mov    $0x0,%eax
}
    121c:	5d                   	pop    %rbp
    121d:	c3                   	retq   

000000000000121e <init_optimized_libs>:

extern "C" int init_optimized_libs(const uint64_t feature_bit_array, uint32_t *cpuinfo_table, uint64_t xfrm)
{
    121e:	55                   	push   %rbp
    121f:	48 89 e5             	mov    %rsp,%rbp
    1222:	48 83 ec 20          	sub    $0x20,%rsp
    1226:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    122a:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    122e:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    if (g_enclave_state != ENCLAVE_INIT_IN_PROGRESS)
    1232:	48 8d 05 67 fe 00 00 	lea    0xfe67(%rip),%rax        # 110a0 <g_enclave_state>
    1239:	8b 00                	mov    (%rax),%eax
    123b:	83 f8 01             	cmp    $0x1,%eax
    123e:	74 07                	je     1247 <init_optimized_libs+0x29>
    {
        return -1;
    1240:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    1245:	eb 73                	jmp    12ba <init_optimized_libs+0x9c>
    }
    // set the global feature indicator
    if(set_global_feature_indicator(feature_bit_array, xfrm))
    1247:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    124b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    124f:	48 89 d6             	mov    %rdx,%rsi
    1252:	48 89 c7             	mov    %rax,%rdi
    1255:	e8 7a fe ff ff       	callq  10d4 <_ZL28set_global_feature_indicatormm>
    125a:	85 c0                	test   %eax,%eax
    125c:	0f 95 c0             	setne  %al
    125f:	84 c0                	test   %al,%al
    1261:	74 07                	je     126a <init_optimized_libs+0x4c>
    {
        return -1;
    1263:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    1268:	eb 50                	jmp    12ba <init_optimized_libs+0x9c>
    }

    // Init string library with the global feature indicator
    if(sgx_init_string_lib(g_cpu_feature_indicator) != 0)
    126a:	48 8d 05 87 fb 00 00 	lea    0xfb87(%rip),%rax        # 10df8 <g_cpu_feature_indicator>
    1271:	48 8b 00             	mov    (%rax),%rax
    1274:	48 89 c7             	mov    %rax,%rdi
    1277:	e8 42 a1 00 00       	callq  b3be <sgx_init_string_lib>
    127c:	85 c0                	test   %eax,%eax
    127e:	0f 95 c0             	setne  %al
    1281:	84 c0                	test   %al,%al
    1283:	74 07                	je     128c <init_optimized_libs+0x6e>
    {
        return -1;
    1285:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    128a:	eb 2e                	jmp    12ba <init_optimized_libs+0x9c>
    }

    // Init IPP crypto library with the global feature indicator	
    if(sgx_init_crypto_lib(g_cpu_feature_indicator, cpuinfo_table) != 0)
    128c:	48 8d 05 65 fb 00 00 	lea    0xfb65(%rip),%rax        # 10df8 <g_cpu_feature_indicator>
    1293:	48 8b 00             	mov    (%rax),%rax
    1296:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    129a:	48 89 d6             	mov    %rdx,%rsi
    129d:	48 89 c7             	mov    %rax,%rdi
    12a0:	e8 8c a3 00 00       	callq  b631 <sgx_init_crypto_lib>
    12a5:	85 c0                	test   %eax,%eax
    12a7:	0f 95 c0             	setne  %al
    12aa:	84 c0                	test   %al,%al
    12ac:	74 07                	je     12b5 <init_optimized_libs+0x97>
    {
        return -1;
    12ae:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    12b3:	eb 05                	jmp    12ba <init_optimized_libs+0x9c>
    }

    return 0;
    12b5:	b8 00 00 00 00       	mov    $0x0,%eax
}
    12ba:	c9                   	leaveq 
    12bb:	c3                   	retq   

00000000000012bc <trts_access_version_dummy1>:

#ifndef SE_SIM

#include "se_cdefs.h"
// add a version to trts
SGX_ACCESS_VERSION(trts, 1);
    12bc:	55                   	push   %rbp
    12bd:	48 89 e5             	mov    %rsp,%rbp
    12c0:	48 8d 05 49 fd 00 00 	lea    0xfd49(%rip),%rax        # 11010 <sgx_trts_version>
    12c7:	c6 00 73             	movb   $0x73,(%rax)
    12ca:	48 8d 05 3f fd 00 00 	lea    0xfd3f(%rip),%rax        # 11010 <sgx_trts_version>
    12d1:	5d                   	pop    %rbp
    12d2:	c3                   	retq   

00000000000012d3 <sgx_is_within_enclave>:
//      1 - the buffer is strictly within the enclave
//      0 - the whole buffer or part of the buffer is not within the enclave,
//          or the buffer is wrap around
//
int sgx_is_within_enclave(const void *addr, size_t size)
{
    12d3:	55                   	push   %rbp
    12d4:	48 89 e5             	mov    %rsp,%rbp
    12d7:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    12db:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    size_t start = reinterpret_cast<size_t>(addr);
    12df:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    12e3:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    size_t end = 0;
    12e7:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    12ee:	00 
    size_t enclave_start = (size_t)&__ImageBase;
    12ef:	48 8d 05 0a ed ff ff 	lea    -0x12f6(%rip),%rax        # 0 <enclave.so>
    12f6:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    size_t enclave_end = enclave_start + g_global_data.enclave_size - 1;
    12fa:	48 8d 05 7f be 00 00 	lea    0xbe7f(%rip),%rax        # d180 <g_global_data>
    1301:	48 8b 10             	mov    (%rax),%rdx
    1304:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1308:	48 01 d0             	add    %rdx,%rax
    130b:	48 83 e8 01          	sub    $0x1,%rax
    130f:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    // g_global_data.enclave_end = enclave_base + enclave_size - 1;
    // so the enclave range is [enclave_start, enclave_end] inclusively

    if(size > 0)
    1313:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    1318:	74 15                	je     132f <sgx_is_within_enclave+0x5c>
    {
        end = start + size - 1;
    131a:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    131e:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    1322:	48 01 d0             	add    %rdx,%rax
    1325:	48 83 e8 01          	sub    $0x1,%rax
    1329:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    132d:	eb 08                	jmp    1337 <sgx_is_within_enclave+0x64>
    }
    else
    {
        end = start;
    132f:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1333:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    }
    if( (start <= end) && (start >= enclave_start) && (end <= enclave_end) )
    1337:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    133b:	48 3b 45 e0          	cmp    -0x20(%rbp),%rax
    133f:	77 1b                	ja     135c <sgx_is_within_enclave+0x89>
    1341:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1345:	48 3b 45 f0          	cmp    -0x10(%rbp),%rax
    1349:	72 11                	jb     135c <sgx_is_within_enclave+0x89>
    134b:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    134f:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    1353:	77 07                	ja     135c <sgx_is_within_enclave+0x89>
    {
        return 1;
    1355:	b8 01 00 00 00       	mov    $0x1,%eax
    135a:	eb 05                	jmp    1361 <sgx_is_within_enclave+0x8e>
    }
    return 0;
    135c:	b8 00 00 00 00       	mov    $0x0,%eax
}
    1361:	5d                   	pop    %rbp
    1362:	c3                   	retq   

0000000000001363 <sgx_is_outside_enclave>:
//      1 - the buffer is strictly outside the enclave
//      0 - the whole buffer or part of the buffer is not outside the enclave,
//          or the buffer is wrap around
//
int sgx_is_outside_enclave(const void *addr, size_t size)
{
    1363:	55                   	push   %rbp
    1364:	48 89 e5             	mov    %rsp,%rbp
    1367:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    136b:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    size_t start = reinterpret_cast<size_t>(addr);
    136f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1373:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    size_t end = 0;
    1377:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    137e:	00 
    size_t enclave_start = (size_t)&__ImageBase;
    137f:	48 8d 05 7a ec ff ff 	lea    -0x1386(%rip),%rax        # 0 <enclave.so>
    1386:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    size_t enclave_end = enclave_start + g_global_data.enclave_size - 1;
    138a:	48 8d 05 ef bd 00 00 	lea    0xbdef(%rip),%rax        # d180 <g_global_data>
    1391:	48 8b 10             	mov    (%rax),%rdx
    1394:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1398:	48 01 d0             	add    %rdx,%rax
    139b:	48 83 e8 01          	sub    $0x1,%rax
    139f:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    // g_global_data.enclave_end = enclave_base + enclave_size - 1;
    // so the enclave range is [enclave_start, enclave_end] inclusively

    if(size > 0)
    13a3:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    13a8:	74 15                	je     13bf <sgx_is_outside_enclave+0x5c>
    {
        end = start + size - 1;
    13aa:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    13ae:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    13b2:	48 01 d0             	add    %rdx,%rax
    13b5:	48 83 e8 01          	sub    $0x1,%rax
    13b9:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    13bd:	eb 08                	jmp    13c7 <sgx_is_outside_enclave+0x64>
    }
    else
    {
        end = start;
    13bf:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    13c3:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    }
    if( (start <= end) && ((end < enclave_start) || (start > enclave_end)) )
    13c7:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    13cb:	48 3b 45 e0          	cmp    -0x20(%rbp),%rax
    13cf:	77 1b                	ja     13ec <sgx_is_outside_enclave+0x89>
    13d1:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    13d5:	48 3b 45 f0          	cmp    -0x10(%rbp),%rax
    13d9:	72 0a                	jb     13e5 <sgx_is_outside_enclave+0x82>
    13db:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    13df:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    13e3:	76 07                	jbe    13ec <sgx_is_outside_enclave+0x89>
    {
        return 1;
    13e5:	b8 01 00 00 00       	mov    $0x1,%eax
    13ea:	eb 05                	jmp    13f1 <sgx_is_outside_enclave+0x8e>
    }
    return 0;
    13ec:	b8 00 00 00 00       	mov    $0x0,%eax
}
    13f1:	5d                   	pop    %rbp
    13f2:	c3                   	retq   

00000000000013f3 <sgx_ocalloc>:
// When ECALL or exception handling returns, the stack pointer is set as the value in the ECALL stack frame and then EEXIT,
// so the outside stack is automatically unwind.
// In addition, sgx_ocalloc needs perform outside stack probe to make sure it is not allocating beyond the end of the stack.
#define OC_ROUND 16
void * sgx_ocalloc(size_t size)
{
    13f3:	55                   	push   %rbp
    13f4:	48 89 e5             	mov    %rsp,%rbp
    13f7:	48 83 ec 40          	sub    $0x40,%rsp
    13fb:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    // read the outside stack address from current SSA
    thread_data_t *thread_data = get_thread_data();
    13ff:	e8 69 b2 00 00       	callq  c66d <get_thread_data>
    1404:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    ssa_gpr_t *ssa_gpr = reinterpret_cast<ssa_gpr_t *>(thread_data->first_ssa_gpr);
    1408:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    140c:	48 8b 40 20          	mov    0x20(%rax),%rax
    1410:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    size_t addr = ssa_gpr->REG(sp_u);
    1414:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1418:	48 8b 80 90 00 00 00 	mov    0x90(%rax),%rax
    141f:	48 89 45 e8          	mov    %rax,-0x18(%rbp)

    // check u_rsp points to the untrusted address.
    // if the check fails, it should be hacked. call abort directly
    if(!sgx_is_outside_enclave(reinterpret_cast<void *>(addr), sizeof(size_t)))
    1423:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1427:	be 08 00 00 00       	mov    $0x8,%esi
    142c:	48 89 c7             	mov    %rax,%rdi
    142f:	e8 2f ff ff ff       	callq  1363 <sgx_is_outside_enclave>
    1434:	85 c0                	test   %eax,%eax
    1436:	0f 94 c0             	sete   %al
    1439:	84 c0                	test   %al,%al
    143b:	74 05                	je     1442 <sgx_ocalloc+0x4f>
    {
        abort();
    143d:	e8 5a b5 00 00       	callq  c99c <abort>
    }

    // size is too large to allocate. call abort() directly.
    if(addr < size)
    1442:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1446:	48 3b 45 c8          	cmp    -0x38(%rbp),%rax
    144a:	73 05                	jae    1451 <sgx_ocalloc+0x5e>
    {
        abort();
    144c:	e8 4b b5 00 00       	callq  c99c <abort>
    }

    // calculate the start address for the allocated memory
    addr -= size;
    1451:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    1455:	48 29 45 e8          	sub    %rax,-0x18(%rbp)
    addr &= ~(static_cast<size_t>(OC_ROUND - 1));  // for stack alignment
    1459:	48 83 65 e8 f0       	andq   $0xfffffffffffffff0,-0x18(%rbp)

    // the allocated memory has overlap with enclave, abort the enclave
    if(!sgx_is_outside_enclave(reinterpret_cast<void *>(addr), size))
    145e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1462:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    1466:	48 89 d6             	mov    %rdx,%rsi
    1469:	48 89 c7             	mov    %rax,%rdi
    146c:	e8 f2 fe ff ff       	callq  1363 <sgx_is_outside_enclave>
    1471:	85 c0                	test   %eax,%eax
    1473:	0f 94 c0             	sete   %al
    1476:	84 c0                	test   %al,%al
    1478:	74 05                	je     147f <sgx_ocalloc+0x8c>
    {
        abort();
    147a:	e8 1d b5 00 00       	callq  c99c <abort>

    // probe the outside stack to ensure that we do not skip over the stack3 guard page
    // we need to probe all the pages including the first page and the last page
    // the first page need to be probed in case uRTS didnot touch that page before EENTER enclave
    // the last page need to be probed in case the enclave didnot touch that page before another OCALLOC
    size_t first_page = TRIM_TO_PAGE(ssa_gpr->REG(sp_u) - 1);
    147f:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1483:	48 8b 80 90 00 00 00 	mov    0x90(%rax),%rax
    148a:	48 83 e8 01          	sub    $0x1,%rax
    148e:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    1494:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    size_t last_page = TRIM_TO_PAGE(addr);
    1498:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    149c:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    14a2:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

    // To avoid the dead-loop in the following for(...) loop.
    // Attacker might fake a stack address that is within address 0x4095.
    if (last_page == 0)
    14a6:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    14ab:	75 05                	jne    14b2 <sgx_ocalloc+0xbf>
    {
        abort();
    14ad:	e8 ea b4 00 00       	callq  c99c <abort>
    }

    // the compiler may optimize the following code to probe the pages in any order
    // while we only expect the probe order should be from higher addr to lower addr
    // so use volatile to avoid optimization by the compiler
    for(volatile size_t page = first_page; page >= last_page; page -= SE_PAGE_SIZE)
    14b2:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    14b6:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    14ba:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    14be:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    14c2:	0f 96 c0             	setbe  %al
    14c5:	84 c0                	test   %al,%al
    14c7:	74 26                	je     14ef <sgx_ocalloc+0xfc>
    {
        // OS may refuse to commit a physical page if the page fault address is smaller than RSP
        // So update the outside stack address before probe the page
        ssa_gpr->REG(sp_u) = page;
    14c9:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    14cd:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    14d1:	48 89 90 90 00 00 00 	mov    %rdx,0x90(%rax)

        *reinterpret_cast<uint8_t *>(page) = 0;
    14d8:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    14dc:	c6 00 00             	movb   $0x0,(%rax)
    for(volatile size_t page = first_page; page >= last_page; page -= SE_PAGE_SIZE)
    14df:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    14e3:	48 2d 00 10 00 00    	sub    $0x1000,%rax
    14e9:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    14ed:	eb cb                	jmp    14ba <sgx_ocalloc+0xc7>
    }

    // update the outside stack address in the SSA to the allocated address
    ssa_gpr->REG(sp_u) = addr;
    14ef:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    14f3:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    14f7:	48 89 90 90 00 00 00 	mov    %rdx,0x90(%rax)

    return reinterpret_cast<void *>(addr);
    14fe:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
}
    1502:	c9                   	leaveq 
    1503:	c3                   	retq   

0000000000001504 <sgx_ocfree>:
// Return Value:
//      N/A
// sgx_ocfree restores the original outside stack pointer in the SSA.
// Do not call this function if you still need the buffer allocated by sgx_ocalloc within the ECALL.
void sgx_ocfree()
{
    1504:	55                   	push   %rbp
    1505:	48 89 e5             	mov    %rsp,%rbp
    1508:	48 83 ec 20          	sub    $0x20,%rsp
    //                       -------------
    //                      | ret_addr    |
    //                      | xbp_u       |
    //                      | xsp_u       |

    thread_data_t *thread_data = get_thread_data();
    150c:	e8 5c b1 00 00       	callq  c66d <get_thread_data>
    1511:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    ssa_gpr_t *ssa_gpr = reinterpret_cast<ssa_gpr_t *>(thread_data->first_ssa_gpr);
    1515:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1519:	48 8b 40 20          	mov    0x20(%rax),%rax
    151d:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    uintptr_t *addr = reinterpret_cast<uintptr_t *>(thread_data->last_sp);
    1521:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1525:	48 8b 40 08          	mov    0x8(%rax),%rax
    1529:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    uintptr_t usp = *(addr - 3);
    152d:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1531:	48 8b 40 e8          	mov    -0x18(%rax),%rax
    1535:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if(!sgx_is_outside_enclave(reinterpret_cast<void *>(usp), sizeof(uintptr_t)))
    1539:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    153d:	be 08 00 00 00       	mov    $0x8,%esi
    1542:	48 89 c7             	mov    %rax,%rdi
    1545:	e8 19 fe ff ff       	callq  1363 <sgx_is_outside_enclave>
    154a:	85 c0                	test   %eax,%eax
    154c:	0f 94 c0             	sete   %al
    154f:	84 c0                	test   %al,%al
    1551:	74 05                	je     1558 <sgx_ocfree+0x54>
    {
        abort();
    1553:	e8 44 b4 00 00       	callq  c99c <abort>
    }
    ssa_gpr->REG(sp_u) = usp;
    1558:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    155c:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    1560:	48 89 90 90 00 00 00 	mov    %rdx,0x90(%rax)
}
    1567:	90                   	nop
    1568:	c9                   	leaveq 
    1569:	c3                   	retq   

000000000000156a <_ZL15__do_get_rand32Pj>:
    return n;
}
#endif

static sgx_status_t  __do_get_rand32(uint32_t* rand_num)
{
    156a:	55                   	push   %rbp
    156b:	48 89 e5             	mov    %rsp,%rbp
    156e:	48 83 ec 10          	sub    $0x10,%rsp
    1572:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
#ifndef SE_SIM
    /* We expect the CPU has RDRAND support for HW mode. Otherwise, an exception will be thrown
    * do_rdrand() will try to call RDRAND for 10 times
    */
    if(0 == do_rdrand(rand_num))
    1576:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    157a:	48 89 c7             	mov    %rax,%rdi
    157d:	e8 fb b3 00 00       	callq  c97d <do_rdrand>
    1582:	85 c0                	test   %eax,%eax
    1584:	0f 94 c0             	sete   %al
    1587:	84 c0                	test   %al,%al
    1589:	74 07                	je     1592 <_ZL15__do_get_rand32Pj+0x28>
        return SGX_ERROR_UNEXPECTED;
    158b:	b8 01 00 00 00       	mov    $0x1,%eax
    1590:	eb 05                	jmp    1597 <_ZL15__do_get_rand32Pj+0x2d>
    {
        /*  use LCG in simulation mode */
        *rand_num = get_rand_lcg();
    }
#endif
    return SGX_SUCCESS;
    1592:	b8 00 00 00 00       	mov    $0x0,%eax
}
    1597:	c9                   	leaveq 
    1598:	c3                   	retq   

0000000000001599 <sgx_read_rand>:

sgx_status_t sgx_read_rand(unsigned char *rand, size_t length_in_bytes)
{
    1599:	55                   	push   %rbp
    159a:	48 89 e5             	mov    %rsp,%rbp
    159d:	48 83 ec 30          	sub    $0x30,%rsp
    15a1:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    15a5:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    15a9:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    15b0:	00 00 
    15b2:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    15b6:	31 c0                	xor    %eax,%eax
    // check parameters
    //
    // rand can be within or outside the enclave
    if(!rand || !length_in_bytes)
    15b8:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    15bd:	74 07                	je     15c6 <sgx_read_rand+0x2d>
    15bf:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    15c4:	75 0a                	jne    15d0 <sgx_read_rand+0x37>
    {
        return SGX_ERROR_INVALID_PARAMETER;
    15c6:	b8 02 00 00 00       	mov    $0x2,%eax
    15cb:	e9 cc 00 00 00       	jmpq   169c <sgx_read_rand+0x103>
    }
    if(!sgx_is_within_enclave(rand, length_in_bytes) && !sgx_is_outside_enclave(rand, length_in_bytes))
    15d0:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    15d4:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    15d8:	48 89 d6             	mov    %rdx,%rsi
    15db:	48 89 c7             	mov    %rax,%rdi
    15de:	e8 f0 fc ff ff       	callq  12d3 <sgx_is_within_enclave>
    15e3:	85 c0                	test   %eax,%eax
    15e5:	75 1e                	jne    1605 <sgx_read_rand+0x6c>
    15e7:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    15eb:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    15ef:	48 89 d6             	mov    %rdx,%rsi
    15f2:	48 89 c7             	mov    %rax,%rdi
    15f5:	e8 69 fd ff ff       	callq  1363 <sgx_is_outside_enclave>
    15fa:	85 c0                	test   %eax,%eax
    15fc:	75 07                	jne    1605 <sgx_read_rand+0x6c>
    15fe:	b8 01 00 00 00       	mov    $0x1,%eax
    1603:	eb 05                	jmp    160a <sgx_read_rand+0x71>
    1605:	b8 00 00 00 00       	mov    $0x0,%eax
    160a:	84 c0                	test   %al,%al
    160c:	74 0a                	je     1618 <sgx_read_rand+0x7f>
    {
        return SGX_ERROR_INVALID_PARAMETER;
    160e:	b8 02 00 00 00       	mov    $0x2,%eax
    1613:	e9 84 00 00 00       	jmpq   169c <sgx_read_rand+0x103>
    }
    // loop to rdrand
    uint32_t rand_num = 0;
    1618:	c7 45 e8 00 00 00 00 	movl   $0x0,-0x18(%rbp)
    while(length_in_bytes > 0)
    161f:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    1624:	74 56                	je     167c <sgx_read_rand+0xe3>
    {
        sgx_status_t status = __do_get_rand32(&rand_num);
    1626:	48 8d 45 e8          	lea    -0x18(%rbp),%rax
    162a:	48 89 c7             	mov    %rax,%rdi
    162d:	e8 38 ff ff ff       	callq  156a <_ZL15__do_get_rand32Pj>
    1632:	89 45 ec             	mov    %eax,-0x14(%rbp)
        if(status != SGX_SUCCESS)
    1635:	83 7d ec 00          	cmpl   $0x0,-0x14(%rbp)
    1639:	74 05                	je     1640 <sgx_read_rand+0xa7>
        {
            return status;
    163b:	8b 45 ec             	mov    -0x14(%rbp),%eax
    163e:	eb 5c                	jmp    169c <sgx_read_rand+0x103>
        }

        size_t size = (length_in_bytes < sizeof(rand_num)) ? length_in_bytes : sizeof(rand_num);
    1640:	b8 04 00 00 00       	mov    $0x4,%eax
    1645:	48 83 7d d0 04       	cmpq   $0x4,-0x30(%rbp)
    164a:	48 0f 46 45 d0       	cmovbe -0x30(%rbp),%rax
    164f:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
        memcpy(rand, &rand_num, size);
    1653:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    1657:	48 8d 4d e8          	lea    -0x18(%rbp),%rcx
    165b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    165f:	48 89 ce             	mov    %rcx,%rsi
    1662:	48 89 c7             	mov    %rax,%rdi
    1665:	e8 96 98 00 00       	callq  af00 <memcpy>

        rand += size;
    166a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    166e:	48 01 45 d8          	add    %rax,-0x28(%rbp)
        length_in_bytes -= size;
    1672:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1676:	48 29 45 d0          	sub    %rax,-0x30(%rbp)
    while(length_in_bytes > 0)
    167a:	eb a3                	jmp    161f <sgx_read_rand+0x86>
    }
    memset_s(&rand_num, sizeof(rand_num), 0, sizeof(rand_num));
    167c:	48 8d 45 e8          	lea    -0x18(%rbp),%rax
    1680:	b9 04 00 00 00       	mov    $0x4,%ecx
    1685:	ba 00 00 00 00       	mov    $0x0,%edx
    168a:	be 04 00 00 00       	mov    $0x4,%esi
    168f:	48 89 c7             	mov    %rax,%rdi
    1692:	e8 01 99 00 00       	callq  af98 <memset_s>
    return SGX_SUCCESS;
    1697:	b8 00 00 00 00       	mov    $0x0,%eax
}
    169c:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    16a0:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    16a7:	00 00 
    16a9:	74 05                	je     16b0 <sgx_read_rand+0x117>
    16ab:	e8 f8 3b 00 00       	callq  52a8 <__stack_chk_fail>
    16b0:	c9                   	leaveq 
    16b1:	c3                   	retq   

00000000000016b2 <check_static_stack_canary>:
    return get_enclave_state() == ENCLAVE_CRASHED;
}

extern uintptr_t __stack_chk_guard;
int check_static_stack_canary(void *tcs)
{
    16b2:	55                   	push   %rbp
    16b3:	48 89 e5             	mov    %rsp,%rbp
    16b6:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    size_t *canary = TCS2CANARY(tcs);
    16ba:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    16be:	48 2d a8 02 01 00    	sub    $0x102a8,%rax
    16c4:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if ( *canary != (size_t)__stack_chk_guard)
    16c8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    16cc:	48 8b 10             	mov    (%rax),%rdx
    16cf:	48 8d 05 3a f7 00 00 	lea    0xf73a(%rip),%rax        # 10e10 <__intel_security_cookie>
    16d6:	48 8b 00             	mov    (%rax),%rax
    16d9:	48 39 c2             	cmp    %rax,%rdx
    16dc:	74 07                	je     16e5 <check_static_stack_canary+0x33>
    {
        return -1;
    16de:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    16e3:	eb 05                	jmp    16ea <check_static_stack_canary+0x38>
    }
    return 0;
    16e5:	b8 00 00 00 00       	mov    $0x0,%eax
}
    16ea:	5d                   	pop    %rbp
    16eb:	c3                   	retq   

00000000000016ec <memcpy_s>:
#ifdef __cplusplus
    extern "C" {
#endif

static inline errno_t memcpy_s(void *dest, size_t numberOfElements, const void *src, size_t count)
{
    16ec:	55                   	push   %rbp
    16ed:	48 89 e5             	mov    %rsp,%rbp
    16f0:	48 83 ec 20          	sub    $0x20,%rsp
    16f4:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    16f8:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    16fc:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    1700:	48 89 4d e0          	mov    %rcx,-0x20(%rbp)
    if(numberOfElements<count)
    1704:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1708:	48 3b 45 e0          	cmp    -0x20(%rbp),%rax
    170c:	73 07                	jae    1715 <memcpy_s+0x29>
        return -1;
    170e:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    1713:	eb 1c                	jmp    1731 <memcpy_s+0x45>
    memcpy(dest, src, count);
    1715:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    1719:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
    171d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1721:	48 89 ce             	mov    %rcx,%rsi
    1724:	48 89 c7             	mov    %rax,%rdi
    1727:	e8 d4 97 00 00       	callq  af00 <memcpy>
    return 0;
    172c:	b8 00 00 00 00       	mov    $0x0,%eax
}
    1731:	c9                   	leaveq 
    1732:	c3                   	retq   

0000000000001733 <_ZL19sgx_accept_backwardmmm>:
    uint16_t    attributes;
};

// Low level API to EACCEPT pages on grow-up region.
static int sgx_accept_backward(si_flags_t sfl, size_t lo, size_t hi)
{
    1733:	4c 8d 54 24 08       	lea    0x8(%rsp),%r10
    1738:	48 83 e4 c0          	and    $0xffffffffffffffc0,%rsp
    173c:	41 ff 72 f8          	pushq  -0x8(%r10)
    1740:	55                   	push   %rbp
    1741:	48 89 e5             	mov    %rsp,%rbp
    1744:	41 52                	push   %r10
    1746:	48 81 ec e8 00 00 00 	sub    $0xe8,%rsp
    174d:	48 89 bd 38 ff ff ff 	mov    %rdi,-0xc8(%rbp)
    1754:	48 89 b5 30 ff ff ff 	mov    %rsi,-0xd0(%rbp)
    175b:	48 89 95 28 ff ff ff 	mov    %rdx,-0xd8(%rbp)
    1762:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    1769:	00 00 
    176b:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    176f:	31 c0                	xor    %eax,%eax
    size_t addr = hi;
    1771:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    1778:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    SE_DECLSPEC_ALIGN(sizeof(sec_info_t)) sec_info_t si;
    si.flags = sfl;
    177f:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    1786:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    for (uint16_t i = 0; i < (sizeof(si.reserved)/sizeof(si.reserved[0])); i++)
    178d:	66 c7 85 42 ff ff ff 	movw   $0x0,-0xbe(%rbp)
    1794:	00 00 
    1796:	66 83 bd 42 ff ff ff 	cmpw   $0x6,-0xbe(%rbp)
    179d:	06 
    179e:	77 28                	ja     17c8 <_ZL19sgx_accept_backwardmmm+0x95>
        si.reserved[i] = 0;
    17a0:	0f b7 85 42 ff ff ff 	movzwl -0xbe(%rbp),%eax
    17a7:	48 98                	cltq   
    17a9:	48 c7 84 c5 58 ff ff 	movq   $0x0,-0xa8(%rbp,%rax,8)
    17b0:	ff 00 00 00 00 
    for (uint16_t i = 0; i < (sizeof(si.reserved)/sizeof(si.reserved[0])); i++)
    17b5:	0f b7 85 42 ff ff ff 	movzwl -0xbe(%rbp),%eax
    17bc:	83 c0 01             	add    $0x1,%eax
    17bf:	66 89 85 42 ff ff ff 	mov    %ax,-0xbe(%rbp)
    17c6:	eb ce                	jmp    1796 <_ZL19sgx_accept_backwardmmm+0x63>

    while (lo < addr)
    17c8:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    17cf:	48 3b 85 48 ff ff ff 	cmp    -0xb8(%rbp),%rax
    17d6:	73 38                	jae    1810 <_ZL19sgx_accept_backwardmmm+0xdd>
    {
        int rc = do_eaccept(&si, addr -= SE_PAGE_SIZE);
    17d8:	48 81 ad 48 ff ff ff 	subq   $0x1000,-0xb8(%rbp)
    17df:	00 10 00 00 
    17e3:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    17ea:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
    17f1:	48 89 d6             	mov    %rdx,%rsi
    17f4:	48 89 c7             	mov    %rax,%rdi
    17f7:	e8 52 b1 00 00       	callq  c94e <do_eaccept>
    17fc:	89 85 44 ff ff ff    	mov    %eax,-0xbc(%rbp)
        if (rc != 0)
    1802:	83 bd 44 ff ff ff 00 	cmpl   $0x0,-0xbc(%rbp)
    1809:	74 bd                	je     17c8 <_ZL19sgx_accept_backwardmmm+0x95>
            abort();
    180b:	e8 8c b1 00 00       	callq  c99c <abort>
    }
    return 0;
    1810:	b8 00 00 00 00       	mov    $0x0,%eax
}
    1815:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    1819:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    1820:	00 00 
    1822:	74 05                	je     1829 <_ZL19sgx_accept_backwardmmm+0xf6>
    1824:	e8 7f 3a 00 00       	callq  52a8 <__stack_chk_fail>
    1829:	48 81 c4 e8 00 00 00 	add    $0xe8,%rsp
    1830:	41 5a                	pop    %r10
    1832:	5d                   	pop    %rbp
    1833:	49 8d 62 f8          	lea    -0x8(%r10),%rsp
    1837:	c3                   	retq   

0000000000001838 <_ZL35sgx_accept_forward_within_exceptionmm>:

// Low level API to EACCEPT pages on grow-up region during exception handling.
static int sgx_accept_forward_within_exception(size_t lo, size_t hi)
{
    1838:	4c 8d 54 24 08       	lea    0x8(%rsp),%r10
    183d:	48 83 e4 c0          	and    $0xffffffffffffffc0,%rsp
    1841:	41 ff 72 f8          	pushq  -0x8(%r10)
    1845:	55                   	push   %rbp
    1846:	48 89 e5             	mov    %rsp,%rbp
    1849:	41 52                	push   %r10
    184b:	48 81 ec e8 00 00 00 	sub    $0xe8,%rsp
    1852:	48 89 bd 28 ff ff ff 	mov    %rdi,-0xd8(%rbp)
    1859:	48 89 b5 20 ff ff ff 	mov    %rsi,-0xe0(%rbp)
    1860:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    1867:	00 00 
    1869:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    186d:	31 c0                	xor    %eax,%eax
    size_t addr = lo;
    186f:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    1876:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    SE_DECLSPEC_ALIGN(sizeof(sec_info_t)) sec_info_t si;

#ifdef DEBUG
    unsigned int sp_value = 0;
    187d:	c7 85 40 ff ff ff 00 	movl   $0x0,-0xc0(%rbp)
    1884:	00 00 00 
    asm("mov %%esp, %0;" : "=r" (sp_value) :);
    1887:	89 e0                	mov    %esp,%eax
    1889:	89 85 40 ff ff ff    	mov    %eax,-0xc0(%rbp)
    if ((sp_value & (SE_PAGE_SIZE -1)) <= (SE_PAGE_SIZE - (STATIC_STACK_SIZE % SE_PAGE_SIZE)))
    188f:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    1895:	25 ff 0f 00 00       	and    $0xfff,%eax
    189a:	3d 50 0d 00 00       	cmp    $0xd50,%eax
    189f:	77 0a                	ja     18ab <_ZL35sgx_accept_forward_within_exceptionmm+0x73>
        return SGX_ERROR_UNEXPECTED;
    18a1:	b8 01 00 00 00       	mov    $0x1,%eax
    18a6:	e9 95 00 00 00       	jmpq   1940 <_ZL35sgx_accept_forward_within_exceptionmm+0x108>
#endif

    si.flags = SI_FLAGS_RW | SI_FLAG_PENDING;
    18ab:	48 c7 85 50 ff ff ff 	movq   $0x20b,-0xb0(%rbp)
    18b2:	0b 02 00 00 
    for (uint16_t i = 0; i < (sizeof(si.reserved)/sizeof(si.reserved[0])); i++)
    18b6:	66 c7 85 3e ff ff ff 	movw   $0x0,-0xc2(%rbp)
    18bd:	00 00 
    18bf:	66 83 bd 3e ff ff ff 	cmpw   $0x6,-0xc2(%rbp)
    18c6:	06 
    18c7:	77 28                	ja     18f1 <_ZL35sgx_accept_forward_within_exceptionmm+0xb9>
        si.reserved[i] = 0;
    18c9:	0f b7 85 3e ff ff ff 	movzwl -0xc2(%rbp),%eax
    18d0:	48 98                	cltq   
    18d2:	48 c7 84 c5 58 ff ff 	movq   $0x0,-0xa8(%rbp,%rax,8)
    18d9:	ff 00 00 00 00 
    for (uint16_t i = 0; i < (sizeof(si.reserved)/sizeof(si.reserved[0])); i++)
    18de:	0f b7 85 3e ff ff ff 	movzwl -0xc2(%rbp),%eax
    18e5:	83 c0 01             	add    $0x1,%eax
    18e8:	66 89 85 3e ff ff ff 	mov    %ax,-0xc2(%rbp)
    18ef:	eb ce                	jmp    18bf <_ZL35sgx_accept_forward_within_exceptionmm+0x87>

    while (addr < hi)
    18f1:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    18f8:	48 3b 85 20 ff ff ff 	cmp    -0xe0(%rbp),%rax
    18ff:	73 3a                	jae    193b <_ZL35sgx_accept_forward_within_exceptionmm+0x103>
    {
        int rc = do_eaccept(&si, addr);
    1901:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    1908:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
    190f:	48 89 d6             	mov    %rdx,%rsi
    1912:	48 89 c7             	mov    %rax,%rdi
    1915:	e8 34 b0 00 00       	callq  c94e <do_eaccept>
    191a:	89 85 44 ff ff ff    	mov    %eax,-0xbc(%rbp)
        if (rc != 0)
    1920:	83 bd 44 ff ff ff 00 	cmpl   $0x0,-0xbc(%rbp)
    1927:	74 05                	je     192e <_ZL35sgx_accept_forward_within_exceptionmm+0xf6>
            abort();
    1929:	e8 6e b0 00 00       	callq  c99c <abort>
        addr += SE_PAGE_SIZE;
    192e:	48 81 85 48 ff ff ff 	addq   $0x1000,-0xb8(%rbp)
    1935:	00 10 00 00 
    while (addr < hi)
    1939:	eb b6                	jmp    18f1 <_ZL35sgx_accept_forward_within_exceptionmm+0xb9>
    }

    return 0;
    193b:	b8 00 00 00 00       	mov    $0x0,%eax
}
    1940:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    1944:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    194b:	00 00 
    194d:	74 05                	je     1954 <_ZL35sgx_accept_forward_within_exceptionmm+0x11c>
    194f:	e8 54 39 00 00       	callq  52a8 <__stack_chk_fail>
    1954:	48 81 c4 e8 00 00 00 	add    $0xe8,%rsp
    195b:	41 5a                	pop    %r10
    195d:	5d                   	pop    %rbp
    195e:	49 8d 62 f8          	lea    -0x8(%r10),%rsp
    1962:	c3                   	retq   

0000000000001963 <_Z24get_dynamic_layout_by_idt>:

const volatile layout_t *get_dynamic_layout_by_id(uint16_t id)
{
    1963:	55                   	push   %rbp
    1964:	48 89 e5             	mov    %rsp,%rbp
    1967:	89 f8                	mov    %edi,%eax
    1969:	66 89 45 ec          	mov    %ax,-0x14(%rbp)
    for(uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    196d:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    1974:	48 8d 05 05 b8 00 00 	lea    0xb805(%rip),%rax        # d180 <g_global_data>
    197b:	8b 80 28 01 00 00    	mov    0x128(%rax),%eax
    1981:	39 45 fc             	cmp    %eax,-0x4(%rbp)
    1984:	0f 92 c0             	setb   %al
    1987:	84 c0                	test   %al,%al
    1989:	74 45                	je     19d0 <_Z24get_dynamic_layout_by_idt+0x6d>
    {
        if(g_global_data.layout_table[i].entry.id == id)
    198b:	48 8d 05 ee b7 00 00 	lea    0xb7ee(%rip),%rax        # d180 <g_global_data>
    1992:	8b 55 fc             	mov    -0x4(%rbp),%edx
    1995:	48 c1 e2 05          	shl    $0x5,%rdx
    1999:	48 01 d0             	add    %rdx,%rax
    199c:	48 05 30 01 00 00    	add    $0x130,%rax
    19a2:	0f b7 00             	movzwl (%rax),%eax
    19a5:	66 39 45 ec          	cmp    %ax,-0x14(%rbp)
    19a9:	0f 94 c0             	sete   %al
    19ac:	84 c0                	test   %al,%al
    19ae:	74 1a                	je     19ca <_Z24get_dynamic_layout_by_idt+0x67>
        {
            return &(g_global_data.layout_table[i]);
    19b0:	8b 45 fc             	mov    -0x4(%rbp),%eax
    19b3:	48 c1 e0 05          	shl    $0x5,%rax
    19b7:	48 8d 90 30 01 00 00 	lea    0x130(%rax),%rdx
    19be:	48 8d 05 bb b7 00 00 	lea    0xb7bb(%rip),%rax        # d180 <g_global_data>
    19c5:	48 01 d0             	add    %rdx,%rax
    19c8:	eb 0b                	jmp    19d5 <_Z24get_dynamic_layout_by_idt+0x72>
    for(uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    19ca:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    19ce:	eb a4                	jmp    1974 <_Z24get_dynamic_layout_by_idt+0x11>
        }
    }
    return NULL;
    19d0:	b8 00 00 00 00       	mov    $0x0,%eax
}
    19d5:	5d                   	pop    %rbp
    19d6:	c3                   	retq   

00000000000019d7 <_Z18accept_post_removePVK9_layout_tS1_m>:

// EACCEPT trim requests when the enclave completes initialization.
int accept_post_remove(const volatile layout_t *layout_start, const volatile layout_t *layout_end, size_t offset)
{
    19d7:	55                   	push   %rbp
    19d8:	48 89 e5             	mov    %rsp,%rbp
    19db:	53                   	push   %rbx
    19dc:	48 83 ec 58          	sub    $0x58,%rsp
    19e0:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    19e4:	48 89 75 b0          	mov    %rsi,-0x50(%rbp)
    19e8:	48 89 55 a8          	mov    %rdx,-0x58(%rbp)
    int ret = -1;
    19ec:	c7 45 d0 ff ff ff ff 	movl   $0xffffffff,-0x30(%rbp)
    for (const volatile layout_t *layout = layout_start; layout < layout_end; layout++)
    19f3:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    19f7:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    19fb:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    19ff:	48 3b 45 b0          	cmp    -0x50(%rbp),%rax
    1a03:	0f 83 2f 01 00 00    	jae    1b38 <_Z18accept_post_removePVK9_layout_tS1_m+0x161>
    {
        if (!IS_GROUP_ID(layout->group.id) && (layout->entry.attributes & PAGE_ATTR_POST_REMOVE))
    1a09:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1a0d:	0f b7 00             	movzwl (%rax),%eax
    1a10:	0f b7 c0             	movzwl %ax,%eax
    1a13:	25 00 10 00 00       	and    $0x1000,%eax
    1a18:	85 c0                	test   %eax,%eax
    1a1a:	75 19                	jne    1a35 <_Z18accept_post_removePVK9_layout_tS1_m+0x5e>
    1a1c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1a20:	0f b7 40 02          	movzwl 0x2(%rax),%eax
    1a24:	0f b7 c0             	movzwl %ax,%eax
    1a27:	83 e0 10             	and    $0x10,%eax
    1a2a:	85 c0                	test   %eax,%eax
    1a2c:	74 07                	je     1a35 <_Z18accept_post_removePVK9_layout_tS1_m+0x5e>
    1a2e:	b8 01 00 00 00       	mov    $0x1,%eax
    1a33:	eb 05                	jmp    1a3a <_Z18accept_post_removePVK9_layout_tS1_m+0x63>
    1a35:	b8 00 00 00 00       	mov    $0x0,%eax
    1a3a:	84 c0                	test   %al,%al
    1a3c:	74 62                	je     1aa0 <_Z18accept_post_removePVK9_layout_tS1_m+0xc9>
        {
            size_t start_addr = (size_t)layout->entry.rva + offset + (size_t)get_enclave_base();
    1a3e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1a42:	48 8b 50 08          	mov    0x8(%rax),%rdx
    1a46:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    1a4a:	48 8d 1c 02          	lea    (%rdx,%rax,1),%rbx
    1a4e:	e8 df ab 00 00       	callq  c632 <get_enclave_base>
    1a53:	48 01 d8             	add    %rbx,%rax
    1a56:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
            uint32_t page_count = layout->entry.page_count;
    1a5a:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1a5e:	8b 40 04             	mov    0x4(%rax),%eax
    1a61:	89 45 d4             	mov    %eax,-0x2c(%rbp)

            if (0 != (ret = sgx_accept_forward(SI_FLAG_TRIM | SI_FLAG_MODIFIED, start_addr, start_addr + ((size_t)page_count << SE_PAGE_SHIFT))))
    1a64:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    1a67:	48 c1 e0 0c          	shl    $0xc,%rax
    1a6b:	48 89 c2             	mov    %rax,%rdx
    1a6e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1a72:	48 01 c2             	add    %rax,%rdx
    1a75:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1a79:	48 89 c6             	mov    %rax,%rsi
    1a7c:	bf 10 04 00 00       	mov    $0x410,%edi
    1a81:	e8 ef 05 00 00       	callq  2075 <sgx_accept_forward>
    1a86:	89 45 d0             	mov    %eax,-0x30(%rbp)
    1a89:	83 7d d0 00          	cmpl   $0x0,-0x30(%rbp)
    1a8d:	0f 95 c0             	setne  %al
    1a90:	84 c0                	test   %al,%al
    1a92:	0f 84 96 00 00 00    	je     1b2e <_Z18accept_post_removePVK9_layout_tS1_m+0x157>
                return ret;
    1a98:	8b 45 d0             	mov    -0x30(%rbp),%eax
    1a9b:	e9 9d 00 00 00       	jmpq   1b3d <_Z18accept_post_removePVK9_layout_tS1_m+0x166>
        }
        else if (IS_GROUP_ID(layout->group.id))
    1aa0:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1aa4:	0f b7 00             	movzwl (%rax),%eax
    1aa7:	0f b7 c0             	movzwl %ax,%eax
    1aaa:	25 00 10 00 00       	and    $0x1000,%eax
    1aaf:	85 c0                	test   %eax,%eax
    1ab1:	0f 95 c0             	setne  %al
    1ab4:	84 c0                	test   %al,%al
    1ab6:	74 76                	je     1b2e <_Z18accept_post_removePVK9_layout_tS1_m+0x157>
        {
            size_t step = 0;
    1ab8:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    1abf:	00 
            for(uint32_t j = 0; j < layout->group.load_times; j++)
    1ac0:	c7 45 cc 00 00 00 00 	movl   $0x0,-0x34(%rbp)
    1ac7:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1acb:	8b 40 04             	mov    0x4(%rax),%eax
    1ace:	39 45 cc             	cmp    %eax,-0x34(%rbp)
    1ad1:	0f 92 c0             	setb   %al
    1ad4:	84 c0                	test   %al,%al
    1ad6:	74 56                	je     1b2e <_Z18accept_post_removePVK9_layout_tS1_m+0x157>
            {
                step += (size_t)layout->group.load_step;
    1ad8:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1adc:	48 8b 40 08          	mov    0x8(%rax),%rax
    1ae0:	48 01 45 e0          	add    %rax,-0x20(%rbp)
                if(0 != (ret = accept_post_remove(&layout[-layout->group.entry_count], layout, step)))
    1ae4:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1ae8:	0f b7 40 02          	movzwl 0x2(%rax),%eax
    1aec:	0f b7 c0             	movzwl %ax,%eax
    1aef:	f7 d8                	neg    %eax
    1af1:	48 98                	cltq   
    1af3:	48 c1 e0 05          	shl    $0x5,%rax
    1af7:	48 89 c2             	mov    %rax,%rdx
    1afa:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1afe:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
    1b02:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    1b06:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1b0a:	48 89 c6             	mov    %rax,%rsi
    1b0d:	48 89 cf             	mov    %rcx,%rdi
    1b10:	e8 c2 fe ff ff       	callq  19d7 <_Z18accept_post_removePVK9_layout_tS1_m>
    1b15:	89 45 d0             	mov    %eax,-0x30(%rbp)
    1b18:	83 7d d0 00          	cmpl   $0x0,-0x30(%rbp)
    1b1c:	0f 95 c0             	setne  %al
    1b1f:	84 c0                	test   %al,%al
    1b21:	74 05                	je     1b28 <_Z18accept_post_removePVK9_layout_tS1_m+0x151>
                    return ret;
    1b23:	8b 45 d0             	mov    -0x30(%rbp),%eax
    1b26:	eb 15                	jmp    1b3d <_Z18accept_post_removePVK9_layout_tS1_m+0x166>
            for(uint32_t j = 0; j < layout->group.load_times; j++)
    1b28:	83 45 cc 01          	addl   $0x1,-0x34(%rbp)
    1b2c:	eb 99                	jmp    1ac7 <_Z18accept_post_removePVK9_layout_tS1_m+0xf0>
    for (const volatile layout_t *layout = layout_start; layout < layout_end; layout++)
    1b2e:	48 83 45 d8 20       	addq   $0x20,-0x28(%rbp)
    1b33:	e9 c3 fe ff ff       	jmpq   19fb <_Z18accept_post_removePVK9_layout_tS1_m+0x24>
            }
        }
    }
    return 0;
    1b38:	b8 00 00 00 00       	mov    $0x0,%eax
}
    1b3d:	48 83 c4 58          	add    $0x58,%rsp
    1b41:	5b                   	pop    %rbx
    1b42:	5d                   	pop    %rbp
    1b43:	c3                   	retq   

0000000000001b44 <_ZL20check_heap_dyn_rangePvmP24dynamic_flags_attributes>:

static int check_heap_dyn_range(void *addr, size_t page_count, struct dynamic_flags_attributes *fa)
{
    1b44:	55                   	push   %rbp
    1b45:	48 89 e5             	mov    %rsp,%rbp
    1b48:	53                   	push   %rbx
    1b49:	48 83 ec 38          	sub    $0x38,%rsp
    1b4d:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    1b51:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    1b55:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
    size_t heap_dyn_start, heap_dyn_size;

    heap_dyn_start = (size_t)get_heap_base() + get_heap_min_size();
    1b59:	e8 6a 1d 00 00       	callq  38c8 <get_heap_base>
    1b5e:	48 89 c3             	mov    %rax,%rbx
    1b61:	e8 0f 1e 00 00       	callq  3975 <get_heap_min_size>
    1b66:	48 01 d8             	add    %rbx,%rax
    1b69:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    heap_dyn_size = get_heap_size() - get_heap_min_size();
    1b6d:	e8 71 1d 00 00       	callq  38e3 <get_heap_size>
    1b72:	48 89 c3             	mov    %rax,%rbx
    1b75:	e8 fb 1d 00 00       	callq  3975 <get_heap_min_size>
    1b7a:	48 29 c3             	sub    %rax,%rbx
    1b7d:	48 89 d8             	mov    %rbx,%rax
    1b80:	48 89 45 e8          	mov    %rax,-0x18(%rbp)

    if ((size_t)addr >= heap_dyn_start
    1b84:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1b88:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    1b8c:	77 46                	ja     1bd4 <_ZL20check_heap_dyn_rangePvmP24dynamic_flags_attributes+0x90>
            && (size_t)addr + (page_count << SE_PAGE_SHIFT) <= heap_dyn_start + heap_dyn_size)
    1b8e:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    1b92:	48 c1 e0 0c          	shl    $0xc,%rax
    1b96:	48 89 c2             	mov    %rax,%rdx
    1b99:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1b9d:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
    1ba1:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    1ba5:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1ba9:	48 01 d0             	add    %rdx,%rax
    1bac:	48 39 c1             	cmp    %rax,%rcx
    1baf:	77 23                	ja     1bd4 <_ZL20check_heap_dyn_rangePvmP24dynamic_flags_attributes+0x90>
    {
        if (fa != NULL)
    1bb1:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    1bb6:	74 15                	je     1bcd <_ZL20check_heap_dyn_rangePvmP24dynamic_flags_attributes+0x89>
        {
            fa->si_flags = SI_FLAGS_RW;
    1bb8:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    1bbc:	48 c7 00 03 02 00 00 	movq   $0x203,(%rax)
            fa->attributes = PAGE_ATTR_POST_ADD;
    1bc3:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    1bc7:	66 c7 40 08 08 00    	movw   $0x8,0x8(%rax)
        }
        return 0;
    1bcd:	b8 00 00 00 00       	mov    $0x0,%eax
    1bd2:	eb 05                	jmp    1bd9 <_ZL20check_heap_dyn_rangePvmP24dynamic_flags_attributes+0x95>
    }
    else
    {
        return -1;
    1bd4:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    }
}
    1bd9:	48 83 c4 38          	add    $0x38,%rsp
    1bdd:	5b                   	pop    %rbx
    1bde:	5d                   	pop    %rbp
    1bdf:	c3                   	retq   

0000000000001be0 <_ZL20check_rsrv_dyn_rangePvmP24dynamic_flags_attributes>:
extern void *rsrv_mem_base;
extern size_t rsrv_mem_size;
extern size_t rsrv_mem_min_size;

static int check_rsrv_dyn_range(void *addr, size_t page_count, struct dynamic_flags_attributes *fa)
{
    1be0:	55                   	push   %rbp
    1be1:	48 89 e5             	mov    %rsp,%rbp
    1be4:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    1be8:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    1bec:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    size_t rsrv_mem_dyn_start, rsrv_mem_dyn_size;

    rsrv_mem_dyn_start = (size_t)rsrv_mem_base + rsrv_mem_min_size;
    1bf0:	48 8d 05 41 f2 00 00 	lea    0xf241(%rip),%rax        # 10e38 <rsrv_mem_base>
    1bf7:	48 8b 00             	mov    (%rax),%rax
    1bfa:	48 89 c2             	mov    %rax,%rdx
    1bfd:	48 8d 05 44 f2 00 00 	lea    0xf244(%rip),%rax        # 10e48 <rsrv_mem_min_size>
    1c04:	48 8b 00             	mov    (%rax),%rax
    1c07:	48 01 d0             	add    %rdx,%rax
    1c0a:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    rsrv_mem_dyn_size = rsrv_mem_size - rsrv_mem_min_size;
    1c0e:	48 8d 05 2b f2 00 00 	lea    0xf22b(%rip),%rax        # 10e40 <rsrv_mem_size>
    1c15:	48 8b 10             	mov    (%rax),%rdx
    1c18:	48 8d 05 29 f2 00 00 	lea    0xf229(%rip),%rax        # 10e48 <rsrv_mem_min_size>
    1c1f:	48 8b 00             	mov    (%rax),%rax
    1c22:	48 29 c2             	sub    %rax,%rdx
    1c25:	48 89 d0             	mov    %rdx,%rax
    1c28:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

    if ((size_t)addr >= rsrv_mem_dyn_start
    1c2c:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1c30:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    1c34:	77 46                	ja     1c7c <_ZL20check_rsrv_dyn_rangePvmP24dynamic_flags_attributes+0x9c>
            && (size_t)addr + (page_count << SE_PAGE_SHIFT) <= rsrv_mem_dyn_start + rsrv_mem_dyn_size)
    1c36:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1c3a:	48 c1 e0 0c          	shl    $0xc,%rax
    1c3e:	48 89 c2             	mov    %rax,%rdx
    1c41:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1c45:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
    1c49:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    1c4d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1c51:	48 01 d0             	add    %rdx,%rax
    1c54:	48 39 c1             	cmp    %rax,%rcx
    1c57:	77 23                	ja     1c7c <_ZL20check_rsrv_dyn_rangePvmP24dynamic_flags_attributes+0x9c>
    {
        if (fa != NULL)
    1c59:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    1c5e:	74 15                	je     1c75 <_ZL20check_rsrv_dyn_rangePvmP24dynamic_flags_attributes+0x95>
        {
            fa->si_flags = SI_FLAGS_RW;
    1c60:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1c64:	48 c7 00 03 02 00 00 	movq   $0x203,(%rax)
            fa->attributes = PAGE_ATTR_POST_ADD;
    1c6b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1c6f:	66 c7 40 08 08 00    	movw   $0x8,0x8(%rax)
        }
        return 0;
    1c75:	b8 00 00 00 00       	mov    $0x0,%eax
    1c7a:	eb 05                	jmp    1c81 <_ZL20check_rsrv_dyn_rangePvmP24dynamic_flags_attributes+0xa1>
    }
    else
    {
        return -1;
    1c7c:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    }
}
    1c81:	5d                   	pop    %rbp
    1c82:	c3                   	retq   

0000000000001c83 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes>:


static int check_dynamic_entry_range(void *addr, size_t page_count, uint16_t entry_id, size_t entry_offset, struct dynamic_flags_attributes *fa)
{
    1c83:	55                   	push   %rbp
    1c84:	48 89 e5             	mov    %rsp,%rbp
    1c87:	48 83 ec 50          	sub    $0x50,%rsp
    1c8b:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    1c8f:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    1c93:	89 d0                	mov    %edx,%eax
    1c95:	48 89 4d c0          	mov    %rcx,-0x40(%rbp)
    1c99:	4c 89 45 b8          	mov    %r8,-0x48(%rbp)
    1c9d:	66 89 45 cc          	mov    %ax,-0x34(%rbp)
    const volatile layout_t *layout = NULL;
    1ca1:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
    1ca8:	00 
    size_t entry_start_addr;
    uint32_t entry_page_count;

    if (entry_id < LAYOUT_ID_HEAP_MIN
            || entry_id > LAYOUT_ID_STACK_DYN_MIN
            || (NULL == (layout = get_dynamic_layout_by_id(entry_id))))
    1ca9:	66 83 7d cc 00       	cmpw   $0x0,-0x34(%rbp)
    1cae:	74 1d                	je     1ccd <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0x4a>
            || entry_id > LAYOUT_ID_STACK_DYN_MIN
    1cb0:	66 83 7d cc 12       	cmpw   $0x12,-0x34(%rbp)
    1cb5:	77 16                	ja     1ccd <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0x4a>
            || (NULL == (layout = get_dynamic_layout_by_id(entry_id))))
    1cb7:	0f b7 45 cc          	movzwl -0x34(%rbp),%eax
    1cbb:	89 c7                	mov    %eax,%edi
    1cbd:	e8 a1 fc ff ff       	callq  1963 <_Z24get_dynamic_layout_by_idt>
    1cc2:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    1cc6:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    1ccb:	75 07                	jne    1cd4 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0x51>
    1ccd:	b8 01 00 00 00       	mov    $0x1,%eax
    1cd2:	eb 05                	jmp    1cd9 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0x56>
    1cd4:	b8 00 00 00 00       	mov    $0x0,%eax
    if (entry_id < LAYOUT_ID_HEAP_MIN
    1cd9:	84 c0                	test   %al,%al
    1cdb:	74 0a                	je     1ce7 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0x64>
    {
        return -1;
    1cdd:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    1ce2:	e9 8c 00 00 00       	jmpq   1d73 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0xf0>
    }

    entry_start_addr = (size_t)get_enclave_base() + (size_t)layout->entry.rva + entry_offset;
    1ce7:	e8 46 a9 00 00       	callq  c632 <get_enclave_base>
    1cec:	48 89 c2             	mov    %rax,%rdx
    1cef:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1cf3:	48 8b 40 08          	mov    0x8(%rax),%rax
    1cf7:	48 01 c2             	add    %rax,%rdx
    1cfa:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    1cfe:	48 01 d0             	add    %rdx,%rax
    1d01:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    entry_page_count = layout->entry.page_count;
    1d05:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1d09:	8b 40 04             	mov    0x4(%rax),%eax
    1d0c:	89 45 ec             	mov    %eax,-0x14(%rbp)
    if ((size_t)addr >= entry_start_addr
    1d0f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1d13:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    1d17:	77 55                	ja     1d6e <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0xeb>
            && (size_t)addr + (page_count << SE_PAGE_SHIFT) <= entry_start_addr + ((size_t)entry_page_count << SE_PAGE_SHIFT))
    1d19:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    1d1d:	48 c1 e0 0c          	shl    $0xc,%rax
    1d21:	48 89 c2             	mov    %rax,%rdx
    1d24:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1d28:	48 01 c2             	add    %rax,%rdx
    1d2b:	8b 45 ec             	mov    -0x14(%rbp),%eax
    1d2e:	48 c1 e0 0c          	shl    $0xc,%rax
    1d32:	48 89 c1             	mov    %rax,%rcx
    1d35:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1d39:	48 01 c8             	add    %rcx,%rax
    1d3c:	48 39 c2             	cmp    %rax,%rdx
    1d3f:	77 2d                	ja     1d6e <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0xeb>
    {
        if (fa != NULL)
    1d41:	48 83 7d b8 00       	cmpq   $0x0,-0x48(%rbp)
    1d46:	74 1f                	je     1d67 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0xe4>
        {
            fa->si_flags = layout->entry.si_flags;
    1d48:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1d4c:	48 8b 50 18          	mov    0x18(%rax),%rdx
    1d50:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    1d54:	48 89 10             	mov    %rdx,(%rax)
            fa->attributes = layout->entry.attributes;
    1d57:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1d5b:	0f b7 50 02          	movzwl 0x2(%rax),%edx
    1d5f:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    1d63:	66 89 50 08          	mov    %dx,0x8(%rax)
        }
        return 0;
    1d67:	b8 00 00 00 00       	mov    $0x0,%eax
    1d6c:	eb 05                	jmp    1d73 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0xf0>
    }
    else
    {
        return -1;
    1d6e:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    }
}
    1d73:	c9                   	leaveq 
    1d74:	c3                   	retq   

0000000000001d75 <_ZL34check_utility_thread_dynamic_stackPvmP24dynamic_flags_attributes>:

static int check_utility_thread_dynamic_stack(void *addr, size_t page_count, struct dynamic_flags_attributes *fa)
{
    1d75:	55                   	push   %rbp
    1d76:	48 89 e5             	mov    %rsp,%rbp
    1d79:	48 83 ec 20          	sub    $0x20,%rsp
    1d7d:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    1d81:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    1d85:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    return check_dynamic_entry_range(addr, page_count, LAYOUT_ID_STACK_MAX, 0, fa);
    1d89:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    1d8d:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi
    1d91:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1d95:	49 89 d0             	mov    %rdx,%r8
    1d98:	b9 00 00 00 00       	mov    $0x0,%ecx
    1d9d:	ba 07 00 00 00       	mov    $0x7,%edx
    1da2:	48 89 c7             	mov    %rax,%rdi
    1da5:	e8 d9 fe ff ff       	callq  1c83 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes>
}
    1daa:	c9                   	leaveq 
    1dab:	c3                   	retq   

0000000000001dac <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes>:

// Verify if the range specified belongs to a dynamic range recorded in metadata.
static int check_dynamic_range(void *addr, size_t page_count, size_t *offset, struct dynamic_flags_attributes *fa)
{
    1dac:	55                   	push   %rbp
    1dad:	48 89 e5             	mov    %rsp,%rbp
    1db0:	48 83 ec 30          	sub    $0x30,%rsp
    1db4:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    1db8:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    1dbc:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    1dc0:	48 89 4d d0          	mov    %rcx,-0x30(%rbp)
    const volatile layout_t *dt_layout = NULL;
    1dc4:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    1dcb:	00 

    // check for integer overflow
    if ((size_t)addr > SIZE_MAX - (page_count << SE_PAGE_SHIFT))
    1dcc:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1dd0:	48 c1 e0 0c          	shl    $0xc,%rax
    1dd4:	48 f7 d0             	not    %rax
    1dd7:	48 89 c2             	mov    %rax,%rdx
    1dda:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1dde:	48 39 c2             	cmp    %rax,%rdx
    1de1:	73 0a                	jae    1ded <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x41>
        return -1;
    1de3:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    1de8:	e9 99 01 00 00       	jmpq   1f86 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1da>

    // check heap dynamic range
    if (0 == check_heap_dyn_range(addr, page_count, fa))
    1ded:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    1df1:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    1df5:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1df9:	48 89 ce             	mov    %rcx,%rsi
    1dfc:	48 89 c7             	mov    %rax,%rdi
    1dff:	e8 40 fd ff ff       	callq  1b44 <_ZL20check_heap_dyn_rangePvmP24dynamic_flags_attributes>
    1e04:	85 c0                	test   %eax,%eax
    1e06:	0f 94 c0             	sete   %al
    1e09:	84 c0                	test   %al,%al
    1e0b:	74 0a                	je     1e17 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x6b>
        return 0;
    1e0d:	b8 00 00 00 00       	mov    $0x0,%eax
    1e12:	e9 6f 01 00 00       	jmpq   1f86 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1da>

    // check dynamic stack within utility thread
    if (0 == check_utility_thread_dynamic_stack(addr, page_count, fa))
    1e17:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    1e1b:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    1e1f:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1e23:	48 89 ce             	mov    %rcx,%rsi
    1e26:	48 89 c7             	mov    %rax,%rdi
    1e29:	e8 47 ff ff ff       	callq  1d75 <_ZL34check_utility_thread_dynamic_stackPvmP24dynamic_flags_attributes>
    1e2e:	85 c0                	test   %eax,%eax
    1e30:	0f 94 c0             	sete   %al
    1e33:	84 c0                	test   %al,%al
    1e35:	74 0a                	je     1e41 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x95>
        return 0;
    1e37:	b8 00 00 00 00       	mov    $0x0,%eax
    1e3c:	e9 45 01 00 00       	jmpq   1f86 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1da>

    if (0 == check_rsrv_dyn_range(addr, page_count, fa))
    1e41:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    1e45:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    1e49:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1e4d:	48 89 ce             	mov    %rcx,%rsi
    1e50:	48 89 c7             	mov    %rax,%rdi
    1e53:	e8 88 fd ff ff       	callq  1be0 <_ZL20check_rsrv_dyn_rangePvmP24dynamic_flags_attributes>
    1e58:	85 c0                	test   %eax,%eax
    1e5a:	0f 94 c0             	sete   %al
    1e5d:	84 c0                	test   %al,%al
    1e5f:	74 0a                	je     1e6b <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0xbf>
        return 0;
    1e61:	b8 00 00 00 00       	mov    $0x0,%eax
    1e66:	e9 1b 01 00 00       	jmpq   1f86 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1da>

    // check dynamic thread entries range
    if (NULL != (dt_layout = get_dynamic_layout_by_id(LAYOUT_ID_THREAD_GROUP_DYN)))
    1e6b:	bf 13 10 00 00       	mov    $0x1013,%edi
    1e70:	e8 ee fa ff ff       	callq  1963 <_Z24get_dynamic_layout_by_idt>
    1e75:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1e79:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    1e7e:	0f 95 c0             	setne  %al
    1e81:	84 c0                	test   %al,%al
    1e83:	0f 84 9c 00 00 00    	je     1f25 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x179>
    {
        for (uint16_t id = LAYOUT_ID_TCS_DYN; id <= LAYOUT_ID_STACK_DYN_MIN; id++)
    1e89:	66 c7 45 f0 0e 00    	movw   $0xe,-0x10(%rbp)
    1e8f:	66 83 7d f0 12       	cmpw   $0x12,-0x10(%rbp)
    1e94:	0f 87 e7 00 00 00    	ja     1f81 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1d5>
            for (uint32_t i = 0; i < dt_layout->group.load_times + 1; i++)
    1e9a:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    1ea1:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1ea5:	8b 40 04             	mov    0x4(%rax),%eax
    1ea8:	83 c0 01             	add    $0x1,%eax
    1eab:	39 45 f4             	cmp    %eax,-0xc(%rbp)
    1eae:	0f 92 c0             	setb   %al
    1eb1:	84 c0                	test   %al,%al
    1eb3:	74 60                	je     1f15 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x169>
            {
                if (0 == check_dynamic_entry_range(addr, page_count, id, i * ((size_t)dt_layout->group.load_step), fa))
    1eb5:	8b 55 f4             	mov    -0xc(%rbp),%edx
    1eb8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1ebc:	48 8b 40 08          	mov    0x8(%rax),%rax
    1ec0:	48 89 d1             	mov    %rdx,%rcx
    1ec3:	48 0f af c8          	imul   %rax,%rcx
    1ec7:	0f b7 55 f0          	movzwl -0x10(%rbp),%edx
    1ecb:	48 8b 7d d0          	mov    -0x30(%rbp),%rdi
    1ecf:	48 8b 75 e0          	mov    -0x20(%rbp),%rsi
    1ed3:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1ed7:	49 89 f8             	mov    %rdi,%r8
    1eda:	48 89 c7             	mov    %rax,%rdi
    1edd:	e8 a1 fd ff ff       	callq  1c83 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes>
    1ee2:	85 c0                	test   %eax,%eax
    1ee4:	0f 94 c0             	sete   %al
    1ee7:	84 c0                	test   %al,%al
    1ee9:	74 24                	je     1f0f <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x163>
                {
                    if (offset != NULL) *offset = i * ((size_t)dt_layout->group.load_step);
    1eeb:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    1ef0:	74 16                	je     1f08 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x15c>
    1ef2:	8b 55 f4             	mov    -0xc(%rbp),%edx
    1ef5:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1ef9:	48 8b 40 08          	mov    0x8(%rax),%rax
    1efd:	48 0f af d0          	imul   %rax,%rdx
    1f01:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1f05:	48 89 10             	mov    %rdx,(%rax)
                    return 0;
    1f08:	b8 00 00 00 00       	mov    $0x0,%eax
    1f0d:	eb 77                	jmp    1f86 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1da>
            for (uint32_t i = 0; i < dt_layout->group.load_times + 1; i++)
    1f0f:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    1f13:	eb 8c                	jmp    1ea1 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0xf5>
        for (uint16_t id = LAYOUT_ID_TCS_DYN; id <= LAYOUT_ID_STACK_DYN_MIN; id++)
    1f15:	0f b7 45 f0          	movzwl -0x10(%rbp),%eax
    1f19:	83 c0 01             	add    $0x1,%eax
    1f1c:	66 89 45 f0          	mov    %ax,-0x10(%rbp)
    1f20:	e9 6a ff ff ff       	jmpq   1e8f <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0xe3>
            }
    }
    else
    {
        // LAYOUT_ID_THREAD_GROUP_DYN does not exist, but possibly there is one single dynamic thead
        for (uint16_t id = LAYOUT_ID_TCS_DYN; id <= LAYOUT_ID_STACK_DYN_MIN; id++)
    1f25:	66 c7 45 f2 0e 00    	movw   $0xe,-0xe(%rbp)
    1f2b:	66 83 7d f2 12       	cmpw   $0x12,-0xe(%rbp)
    1f30:	77 4f                	ja     1f81 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1d5>
            if (0 == check_dynamic_entry_range(addr, page_count, id, 0, fa))
    1f32:	0f b7 55 f2          	movzwl -0xe(%rbp),%edx
    1f36:	48 8b 4d d0          	mov    -0x30(%rbp),%rcx
    1f3a:	48 8b 75 e0          	mov    -0x20(%rbp),%rsi
    1f3e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1f42:	49 89 c8             	mov    %rcx,%r8
    1f45:	b9 00 00 00 00       	mov    $0x0,%ecx
    1f4a:	48 89 c7             	mov    %rax,%rdi
    1f4d:	e8 31 fd ff ff       	callq  1c83 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes>
    1f52:	85 c0                	test   %eax,%eax
    1f54:	0f 94 c0             	sete   %al
    1f57:	84 c0                	test   %al,%al
    1f59:	74 19                	je     1f74 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1c8>
            {
                if (offset != NULL) *offset = 0;
    1f5b:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    1f60:	74 0b                	je     1f6d <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1c1>
    1f62:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1f66:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
                return 0;
    1f6d:	b8 00 00 00 00       	mov    $0x0,%eax
    1f72:	eb 12                	jmp    1f86 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1da>
        for (uint16_t id = LAYOUT_ID_TCS_DYN; id <= LAYOUT_ID_STACK_DYN_MIN; id++)
    1f74:	0f b7 45 f2          	movzwl -0xe(%rbp),%eax
    1f78:	83 c0 01             	add    $0x1,%eax
    1f7b:	66 89 45 f2          	mov    %ax,-0xe(%rbp)
    1f7f:	eb aa                	jmp    1f2b <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x17f>
            }
    }
    return -1;
    1f81:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
}
    1f86:	c9                   	leaveq 
    1f87:	c3                   	retq   

0000000000001f88 <is_dynamic_thread>:

int is_dynamic_thread(void *tcs)
{
    1f88:	55                   	push   %rbp
    1f89:	48 89 e5             	mov    %rsp,%rbp
    1f8c:	48 83 ec 30          	sub    $0x30,%rsp
    1f90:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    1f94:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    1f9b:	00 00 
    1f9d:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1fa1:	31 c0                	xor    %eax,%eax
    struct dynamic_flags_attributes fa;

    if ((tcs != NULL) && (check_dynamic_range(tcs, 1, NULL, &fa) == 0) &&
    1fa3:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    1fa8:	74 34                	je     1fde <is_dynamic_thread+0x56>
    1faa:	48 8d 55 e0          	lea    -0x20(%rbp),%rdx
    1fae:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1fb2:	48 89 d1             	mov    %rdx,%rcx
    1fb5:	ba 00 00 00 00       	mov    $0x0,%edx
    1fba:	be 01 00 00 00       	mov    $0x1,%esi
    1fbf:	48 89 c7             	mov    %rax,%rdi
    1fc2:	e8 e5 fd ff ff       	callq  1dac <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes>
    1fc7:	85 c0                	test   %eax,%eax
    1fc9:	75 13                	jne    1fde <is_dynamic_thread+0x56>
            (fa.si_flags == SI_FLAGS_TCS))
    1fcb:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    if ((tcs != NULL) && (check_dynamic_range(tcs, 1, NULL, &fa) == 0) &&
    1fcf:	48 3d 00 01 00 00    	cmp    $0x100,%rax
    1fd5:	75 07                	jne    1fde <is_dynamic_thread+0x56>
    1fd7:	b8 01 00 00 00       	mov    $0x1,%eax
    1fdc:	eb 05                	jmp    1fe3 <is_dynamic_thread+0x5b>
    1fde:	b8 00 00 00 00       	mov    $0x0,%eax
    1fe3:	84 c0                	test   %al,%al
    1fe5:	74 07                	je     1fee <is_dynamic_thread+0x66>
    {
        return true;
    1fe7:	b8 01 00 00 00       	mov    $0x1,%eax
    1fec:	eb 05                	jmp    1ff3 <is_dynamic_thread+0x6b>
    }

    return false;
    1fee:	b8 00 00 00 00       	mov    $0x0,%eax
}
    1ff3:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    1ff7:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    1ffe:	00 00 
    2000:	74 05                	je     2007 <is_dynamic_thread+0x7f>
    2002:	e8 a1 32 00 00       	callq  52a8 <__stack_chk_fail>
    2007:	c9                   	leaveq 
    2008:	c3                   	retq   

0000000000002009 <is_dynamic_thread_exist>:

int is_dynamic_thread_exist()
{
    2009:	55                   	push   %rbp
    200a:	48 89 e5             	mov    %rsp,%rbp
    200d:	48 83 ec 10          	sub    $0x10,%rsp
    if(!EDMM_supported)
    2011:	48 8d 05 e8 ed 00 00 	lea    0xede8(%rip),%rax        # 10e00 <EDMM_supported>
    2018:	8b 00                	mov    (%rax),%eax
    201a:	85 c0                	test   %eax,%eax
    201c:	75 07                	jne    2025 <is_dynamic_thread_exist+0x1c>
        return false;
    201e:	b8 00 00 00 00       	mov    $0x0,%eax
    2023:	eb 21                	jmp    2046 <is_dynamic_thread_exist+0x3d>
    const volatile layout_t * layout = get_dynamic_layout_by_id(LAYOUT_ID_STACK_DYN_MIN);
    2025:	bf 12 00 00 00       	mov    $0x12,%edi
    202a:	e8 34 f9 ff ff       	callq  1963 <_Z24get_dynamic_layout_by_idt>
    202f:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if (!layout)
    2033:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    2038:	75 07                	jne    2041 <is_dynamic_thread_exist+0x38>
        return false;
    203a:	b8 00 00 00 00       	mov    $0x0,%eax
    203f:	eb 05                	jmp    2046 <is_dynamic_thread_exist+0x3d>
    else
        return true;
    2041:	b8 01 00 00 00       	mov    $0x1,%eax
}
    2046:	c9                   	leaveq 
    2047:	c3                   	retq   

0000000000002048 <get_dynamic_stack_max_page>:


uint32_t get_dynamic_stack_max_page()
{
    2048:	55                   	push   %rbp
    2049:	48 89 e5             	mov    %rsp,%rbp
    204c:	48 83 ec 10          	sub    $0x10,%rsp
    const volatile layout_t * layout = get_dynamic_layout_by_id(LAYOUT_ID_STACK_MAX);
    2050:	bf 07 00 00 00       	mov    $0x7,%edi
    2055:	e8 09 f9 ff ff       	callq  1963 <_Z24get_dynamic_layout_by_idt>
    205a:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if (!layout)
    205e:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    2063:	75 07                	jne    206c <get_dynamic_stack_max_page+0x24>
        return 0;
    2065:	b8 00 00 00 00       	mov    $0x0,%eax
    206a:	eb 07                	jmp    2073 <get_dynamic_stack_max_page+0x2b>
    else
        return layout->entry.page_count;
    206c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    2070:	8b 40 04             	mov    0x4(%rax),%eax
}
    2073:	c9                   	leaveq 
    2074:	c3                   	retq   

0000000000002075 <sgx_accept_forward>:
#endif

int sgx_accept_forward(si_flags_t sfl, size_t lo, size_t hi)
{
    2075:	4c 8d 54 24 08       	lea    0x8(%rsp),%r10
    207a:	48 83 e4 c0          	and    $0xffffffffffffffc0,%rsp
    207e:	41 ff 72 f8          	pushq  -0x8(%r10)
    2082:	55                   	push   %rbp
    2083:	48 89 e5             	mov    %rsp,%rbp
    2086:	41 52                	push   %r10
    2088:	48 81 ec e8 00 00 00 	sub    $0xe8,%rsp
    208f:	48 89 bd 38 ff ff ff 	mov    %rdi,-0xc8(%rbp)
    2096:	48 89 b5 30 ff ff ff 	mov    %rsi,-0xd0(%rbp)
    209d:	48 89 95 28 ff ff ff 	mov    %rdx,-0xd8(%rbp)
    20a4:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    20ab:	00 00 
    20ad:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    20b1:	31 c0                	xor    %eax,%eax
    (void)sfl;
    (void)lo;
    (void)hi;
    return 0;
#else
    size_t addr = lo;
    20b3:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    20ba:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    SE_DECLSPEC_ALIGN(sizeof(sec_info_t)) sec_info_t si;
    si.flags = sfl;
    20c1:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    20c8:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    for (uint16_t i = 0; i < (sizeof(si.reserved)/sizeof(si.reserved[0])); i++)
    20cf:	66 c7 85 42 ff ff ff 	movw   $0x0,-0xbe(%rbp)
    20d6:	00 00 
    20d8:	66 83 bd 42 ff ff ff 	cmpw   $0x6,-0xbe(%rbp)
    20df:	06 
    20e0:	77 28                	ja     210a <sgx_accept_forward+0x95>
        si.reserved[i] = 0;
    20e2:	0f b7 85 42 ff ff ff 	movzwl -0xbe(%rbp),%eax
    20e9:	48 98                	cltq   
    20eb:	48 c7 84 c5 58 ff ff 	movq   $0x0,-0xa8(%rbp,%rax,8)
    20f2:	ff 00 00 00 00 
    for (uint16_t i = 0; i < (sizeof(si.reserved)/sizeof(si.reserved[0])); i++)
    20f7:	0f b7 85 42 ff ff ff 	movzwl -0xbe(%rbp),%eax
    20fe:	83 c0 01             	add    $0x1,%eax
    2101:	66 89 85 42 ff ff ff 	mov    %ax,-0xbe(%rbp)
    2108:	eb ce                	jmp    20d8 <sgx_accept_forward+0x63>

    while (addr < hi)
    210a:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    2111:	48 3b 85 28 ff ff ff 	cmp    -0xd8(%rbp),%rax
    2118:	73 3a                	jae    2154 <sgx_accept_forward+0xdf>
    {
        int rc = do_eaccept(&si, addr);
    211a:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    2121:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
    2128:	48 89 d6             	mov    %rdx,%rsi
    212b:	48 89 c7             	mov    %rax,%rdi
    212e:	e8 1b a8 00 00       	callq  c94e <do_eaccept>
    2133:	89 85 44 ff ff ff    	mov    %eax,-0xbc(%rbp)
        if (rc != 0)
    2139:	83 bd 44 ff ff ff 00 	cmpl   $0x0,-0xbc(%rbp)
    2140:	74 05                	je     2147 <sgx_accept_forward+0xd2>
            abort();
    2142:	e8 55 a8 00 00       	callq  c99c <abort>
        addr += SE_PAGE_SIZE;
    2147:	48 81 85 48 ff ff ff 	addq   $0x1000,-0xb8(%rbp)
    214e:	00 10 00 00 
    while (addr < hi)
    2152:	eb b6                	jmp    210a <sgx_accept_forward+0x95>
    }

    return 0;
    2154:	b8 00 00 00 00       	mov    $0x0,%eax
#endif
}
    2159:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    215d:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    2164:	00 00 
    2166:	74 05                	je     216d <sgx_accept_forward+0xf8>
    2168:	e8 3b 31 00 00       	callq  52a8 <__stack_chk_fail>
    216d:	48 81 c4 e8 00 00 00 	add    $0xe8,%rsp
    2174:	41 5a                	pop    %r10
    2176:	5d                   	pop    %rbp
    2177:	49 8d 62 f8          	lea    -0x8(%r10),%rsp
    217b:	c3                   	retq   

000000000000217c <apply_pages_within_exception>:

// High level API to EACCEPT pages, mainly used in exception handling
// to deal with stack expansion. 
int apply_pages_within_exception(void *start_address, size_t page_count)
{
    217c:	55                   	push   %rbp
    217d:	48 89 e5             	mov    %rsp,%rbp
    2180:	48 83 ec 30          	sub    $0x30,%rsp
    2184:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    2188:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    (void)page_count;
    return 0;
#else
    int rc;

    if (start_address == NULL)
    218c:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    2191:	75 07                	jne    219a <apply_pages_within_exception+0x1e>
        return -1;
    2193:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    2198:	eb 61                	jmp    21fb <apply_pages_within_exception+0x7f>
    
    if (check_dynamic_range(start_address, page_count, NULL, NULL) != 0)
    219a:	48 8b 75 d0          	mov    -0x30(%rbp),%rsi
    219e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    21a2:	b9 00 00 00 00       	mov    $0x0,%ecx
    21a7:	ba 00 00 00 00       	mov    $0x0,%edx
    21ac:	48 89 c7             	mov    %rax,%rdi
    21af:	e8 f8 fb ff ff       	callq  1dac <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes>
    21b4:	85 c0                	test   %eax,%eax
    21b6:	0f 95 c0             	setne  %al
    21b9:	84 c0                	test   %al,%al
    21bb:	74 07                	je     21c4 <apply_pages_within_exception+0x48>
        return -1;
    21bd:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    21c2:	eb 37                	jmp    21fb <apply_pages_within_exception+0x7f>

    size_t start = (size_t)start_address;
    21c4:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    21c8:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    size_t end = start + (page_count << SE_PAGE_SHIFT);
    21cc:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    21d0:	48 c1 e0 0c          	shl    $0xc,%rax
    21d4:	48 89 c2             	mov    %rax,%rdx
    21d7:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    21db:	48 01 d0             	add    %rdx,%rax
    21de:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

    rc = sgx_accept_forward_within_exception(start, end);
    21e2:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    21e6:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    21ea:	48 89 d6             	mov    %rdx,%rsi
    21ed:	48 89 c7             	mov    %rax,%rdi
    21f0:	e8 43 f6 ff ff       	callq  1838 <_ZL35sgx_accept_forward_within_exceptionmm>
    21f5:	89 45 ec             	mov    %eax,-0x14(%rbp)

    return rc;
    21f8:	8b 45 ec             	mov    -0x14(%rbp),%eax
#endif

}
    21fb:	c9                   	leaveq 
    21fc:	c3                   	retq   

00000000000021fd <apply_EPC_pages>:

// High level API to EACCEPT pages
int apply_EPC_pages(void *start_address, size_t page_count)
{
    21fd:	55                   	push   %rbp
    21fe:	48 89 e5             	mov    %rsp,%rbp
    2201:	48 83 ec 50          	sub    $0x50,%rsp
    2205:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    2209:	48 89 75 b0          	mov    %rsi,-0x50(%rbp)
    220d:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    2214:	00 00 
    2216:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    221a:	31 c0                	xor    %eax,%eax
    return 0;
#else
    int rc;
    struct dynamic_flags_attributes fa;

    if (start_address == NULL)
    221c:	48 83 7d b8 00       	cmpq   $0x0,-0x48(%rbp)
    2221:	75 0a                	jne    222d <apply_EPC_pages+0x30>
        return -1;
    2223:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    2228:	e9 8d 00 00 00       	jmpq   22ba <apply_EPC_pages+0xbd>
    
    if (check_dynamic_range(start_address, page_count, NULL, &fa) != 0)
    222d:	48 8d 55 e0          	lea    -0x20(%rbp),%rdx
    2231:	48 8b 75 b0          	mov    -0x50(%rbp),%rsi
    2235:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2239:	48 89 d1             	mov    %rdx,%rcx
    223c:	ba 00 00 00 00       	mov    $0x0,%edx
    2241:	48 89 c7             	mov    %rax,%rdi
    2244:	e8 63 fb ff ff       	callq  1dac <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes>
    2249:	85 c0                	test   %eax,%eax
    224b:	0f 95 c0             	setne  %al
    224e:	84 c0                	test   %al,%al
    2250:	74 07                	je     2259 <apply_EPC_pages+0x5c>
        return -1;
    2252:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    2257:	eb 61                	jmp    22ba <apply_EPC_pages+0xbd>

    size_t start = (size_t)start_address;
    2259:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    225d:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    size_t end = start + (page_count << SE_PAGE_SHIFT);
    2261:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    2265:	48 c1 e0 0c          	shl    $0xc,%rax
    2269:	48 89 c2             	mov    %rax,%rdx
    226c:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2270:	48 01 d0             	add    %rdx,%rax
    2273:	48 89 45 d8          	mov    %rax,-0x28(%rbp)

    if (fa.attributes & PAGE_DIR_GROW_DOWN)
    2277:	0f b7 45 e8          	movzwl -0x18(%rbp),%eax
    227b:	0f b7 c0             	movzwl %ax,%eax
    227e:	83 e0 40             	and    $0x40,%eax
    2281:	85 c0                	test   %eax,%eax
    2283:	74 1a                	je     229f <apply_EPC_pages+0xa2>
    {
        rc = sgx_accept_forward(SI_FLAGS_RW | SI_FLAG_PENDING, start, end);
    2285:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    2289:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    228d:	48 89 c6             	mov    %rax,%rsi
    2290:	bf 0b 02 00 00       	mov    $0x20b,%edi
    2295:	e8 db fd ff ff       	callq  2075 <sgx_accept_forward>
    229a:	89 45 cc             	mov    %eax,-0x34(%rbp)
    229d:	eb 18                	jmp    22b7 <apply_EPC_pages+0xba>
    }
    else
    {
        rc = sgx_accept_backward(SI_FLAGS_RW | SI_FLAG_PENDING, start, end);
    229f:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    22a3:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    22a7:	48 89 c6             	mov    %rax,%rsi
    22aa:	bf 0b 02 00 00       	mov    $0x20b,%edi
    22af:	e8 7f f4 ff ff       	callq  1733 <_ZL19sgx_accept_backwardmmm>
    22b4:	89 45 cc             	mov    %eax,-0x34(%rbp)
    }

    return rc;
    22b7:	8b 45 cc             	mov    -0x34(%rbp),%eax
#endif
}
    22ba:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    22be:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    22c5:	00 00 
    22c7:	74 05                	je     22ce <apply_EPC_pages+0xd1>
    22c9:	e8 da 2f 00 00       	callq  52a8 <__stack_chk_fail>
    22ce:	c9                   	leaveq 
    22cf:	c3                   	retq   

00000000000022d0 <trim_EPC_pages>:

// High level API to trim previously EAUG-ed pages.
int trim_EPC_pages(void *start_address, size_t page_count)
{
    22d0:	55                   	push   %rbp
    22d1:	48 89 e5             	mov    %rsp,%rbp
    22d4:	48 83 ec 30          	sub    $0x30,%rsp
    22d8:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    22dc:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    (void)page_count;
    return 0;
#else
    int rc;

    if (start_address == NULL)
    22e0:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    22e5:	75 0a                	jne    22f1 <trim_EPC_pages+0x21>
        return -1;
    22e7:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    22ec:	e9 16 01 00 00       	jmpq   2407 <trim_EPC_pages+0x137>

    // check range
    if (check_dynamic_range(start_address, page_count, NULL, NULL) != 0)
    22f1:	48 8b 75 d0          	mov    -0x30(%rbp),%rsi
    22f5:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    22f9:	b9 00 00 00 00       	mov    $0x0,%ecx
    22fe:	ba 00 00 00 00       	mov    $0x0,%edx
    2303:	48 89 c7             	mov    %rax,%rdi
    2306:	e8 a1 fa ff ff       	callq  1dac <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes>
    230b:	85 c0                	test   %eax,%eax
    230d:	0f 95 c0             	setne  %al
    2310:	84 c0                	test   %al,%al
    2312:	74 0a                	je     231e <trim_EPC_pages+0x4e>
        return -1;
    2314:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    2319:	e9 e9 00 00 00       	jmpq   2407 <trim_EPC_pages+0x137>

    size_t start = (size_t)start_address;
    231e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2322:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    size_t end = start + (page_count << SE_PAGE_SHIFT);
    2326:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    232a:	48 c1 e0 0c          	shl    $0xc,%rax
    232e:	48 89 c2             	mov    %rax,%rdx
    2331:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2335:	48 01 d0             	add    %rdx,%rax
    2338:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

    // trim ocall
    rc = trim_range_ocall(start, end);
    233c:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    2340:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2344:	48 89 d6             	mov    %rdx,%rsi
    2347:	48 89 c7             	mov    %rax,%rdi
    234a:	e8 9f 14 00 00       	callq  37ee <trim_range_ocall>
    234f:	89 45 e4             	mov    %eax,-0x1c(%rbp)
    assert(rc == 0);
    2352:	83 7d e4 00          	cmpl   $0x0,-0x1c(%rbp)
    2356:	74 1f                	je     2377 <trim_EPC_pages+0xa7>
    2358:	48 8d 0d a9 ac 00 00 	lea    0xaca9(%rip),%rcx        # d008 <g_dyn_entry_table+0x8>
    235f:	48 8d 15 c2 ac 00 00 	lea    0xacc2(%rip),%rdx        # d028 <_ZZ14trim_EPC_pagesE8__func__>
    2366:	be 9e 01 00 00       	mov    $0x19e,%esi
    236b:	48 8d 3d 9e ac 00 00 	lea    0xac9e(%rip),%rdi        # d010 <g_dyn_entry_table+0x10>
    2372:	e8 3a 2f 00 00       	callq  52b1 <__assert>

    rc = sgx_accept_forward(SI_FLAG_TRIM | SI_FLAG_MODIFIED, start, end);
    2377:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    237b:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    237f:	48 89 c6             	mov    %rax,%rsi
    2382:	bf 10 04 00 00       	mov    $0x410,%edi
    2387:	e8 e9 fc ff ff       	callq  2075 <sgx_accept_forward>
    238c:	89 45 e4             	mov    %eax,-0x1c(%rbp)
    assert(rc == 0);
    238f:	83 7d e4 00          	cmpl   $0x0,-0x1c(%rbp)
    2393:	74 1f                	je     23b4 <trim_EPC_pages+0xe4>
    2395:	48 8d 0d 6c ac 00 00 	lea    0xac6c(%rip),%rcx        # d008 <g_dyn_entry_table+0x8>
    239c:	48 8d 15 85 ac 00 00 	lea    0xac85(%rip),%rdx        # d028 <_ZZ14trim_EPC_pagesE8__func__>
    23a3:	be a1 01 00 00       	mov    $0x1a1,%esi
    23a8:	48 8d 3d 61 ac 00 00 	lea    0xac61(%rip),%rdi        # d010 <g_dyn_entry_table+0x10>
    23af:	e8 fd 2e 00 00       	callq  52b1 <__assert>
    
    // trim commit ocall
    size_t i = start;
    23b4:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    23b8:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    while (i < end)
    23bc:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    23c0:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    23c4:	73 3e                	jae    2404 <trim_EPC_pages+0x134>
    {
        rc = trim_range_commit_ocall(i);
    23c6:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    23ca:	48 89 c7             	mov    %rax,%rdi
    23cd:	e8 91 14 00 00       	callq  3863 <trim_range_commit_ocall>
    23d2:	89 45 e4             	mov    %eax,-0x1c(%rbp)
        assert(rc == 0);
    23d5:	83 7d e4 00          	cmpl   $0x0,-0x1c(%rbp)
    23d9:	74 1f                	je     23fa <trim_EPC_pages+0x12a>
    23db:	48 8d 0d 26 ac 00 00 	lea    0xac26(%rip),%rcx        # d008 <g_dyn_entry_table+0x8>
    23e2:	48 8d 15 3f ac 00 00 	lea    0xac3f(%rip),%rdx        # d028 <_ZZ14trim_EPC_pagesE8__func__>
    23e9:	be a8 01 00 00       	mov    $0x1a8,%esi
    23ee:	48 8d 3d 1b ac 00 00 	lea    0xac1b(%rip),%rdi        # d010 <g_dyn_entry_table+0x10>
    23f5:	e8 b7 2e 00 00       	callq  52b1 <__assert>
        i += SE_PAGE_SIZE;
    23fa:	48 81 45 e8 00 10 00 	addq   $0x1000,-0x18(%rbp)
    2401:	00 
    while (i < end)
    2402:	eb b8                	jmp    23bc <trim_EPC_pages+0xec>
    }

    return rc;
    2404:	8b 45 e4             	mov    -0x1c(%rbp),%eax
#endif
}
    2407:	c9                   	leaveq 
    2408:	c3                   	retq   

0000000000002409 <do_add_thread>:

// Create a thread dynamically.
// It will add necessary pages and transform one of them into type TCS.
sgx_status_t do_add_thread(void *ptcs)
{
    2409:	55                   	push   %rbp
    240a:	48 89 e5             	mov    %rsp,%rbp
    240d:	48 83 ec 50          	sub    $0x50,%rsp
    2411:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    2415:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    241c:	00 00 
    241e:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    2422:	31 c0                	xor    %eax,%eax
#ifdef SE_SIM
    (void)ptcs;
    return SGX_SUCCESS;
#else
    int ret = SGX_ERROR_UNEXPECTED;
    2424:	c7 45 c4 01 00 00 00 	movl   $0x1,-0x3c(%rbp)
    tcs_t *tcs = (tcs_t *)ptcs;
    242b:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    242f:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    tcs_t *tcs_template = NULL;
    2433:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    243a:	00 
    size_t offset = 0;
    243b:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    2442:	00 
    size_t enclave_base = (size_t)get_enclave_base();
    2443:	e8 ea a1 00 00       	callq  c632 <get_enclave_base>
    2448:	48 89 45 e0          	mov    %rax,-0x20(%rbp)

    if ( 0 != check_dynamic_range((void *)tcs, 1, &offset, NULL))
    244c:	48 8d 55 c8          	lea    -0x38(%rbp),%rdx
    2450:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2454:	b9 00 00 00 00       	mov    $0x0,%ecx
    2459:	be 01 00 00 00       	mov    $0x1,%esi
    245e:	48 89 c7             	mov    %rax,%rdi
    2461:	e8 46 f9 ff ff       	callq  1dac <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes>
    2466:	85 c0                	test   %eax,%eax
    2468:	0f 95 c0             	setne  %al
    246b:	84 c0                	test   %al,%al
    246d:	74 0a                	je     2479 <do_add_thread+0x70>
        return SGX_ERROR_UNEXPECTED;
    246f:	b8 01 00 00 00       	mov    $0x1,%eax
    2474:	e9 bb 01 00 00       	jmpq   2634 <do_add_thread+0x22b>

    // check if the tcs provided exactly matches the one in signtool
    const volatile layout_t *tcs_layout = get_dynamic_layout_by_id(LAYOUT_ID_TCS_DYN);
    2479:	bf 0e 00 00 00       	mov    $0xe,%edi
    247e:	e8 e0 f4 ff ff       	callq  1963 <_Z24get_dynamic_layout_by_idt>
    2483:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    if (!tcs_layout)
    2487:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    248c:	75 0a                	jne    2498 <do_add_thread+0x8f>
        return SGX_ERROR_UNEXPECTED;
    248e:	b8 01 00 00 00       	mov    $0x1,%eax
    2493:	e9 9c 01 00 00       	jmpq   2634 <do_add_thread+0x22b>

    if ((size_t)(enclave_base + tcs_layout->entry.rva + offset) != (size_t)(tcs))
    2498:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    249c:	48 8b 50 08          	mov    0x8(%rax),%rdx
    24a0:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    24a4:	48 01 c2             	add    %rax,%rdx
    24a7:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    24ab:	48 01 c2             	add    %rax,%rdx
    24ae:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    24b2:	48 39 c2             	cmp    %rax,%rdx
    24b5:	0f 95 c0             	setne  %al
    24b8:	84 c0                	test   %al,%al
    24ba:	74 0a                	je     24c6 <do_add_thread+0xbd>
        return SGX_ERROR_UNEXPECTED;
    24bc:	b8 01 00 00 00       	mov    $0x1,%eax
    24c1:	e9 6e 01 00 00       	jmpq   2634 <do_add_thread+0x22b>

    // adding page for all the dynamic entries
    for (uint16_t id = LAYOUT_ID_TCS_DYN; id <= LAYOUT_ID_STACK_DYN_MIN; id++)
    24c6:	66 c7 45 c2 0e 00    	movw   $0xe,-0x3e(%rbp)
    24cc:	66 83 7d c2 12       	cmpw   $0x12,-0x3e(%rbp)
    24d1:	0f 87 85 00 00 00    	ja     255c <do_add_thread+0x153>
    {
        const volatile layout_t *layout =  get_dynamic_layout_by_id(id);
    24d7:	0f b7 45 c2          	movzwl -0x3e(%rbp),%eax
    24db:	89 c7                	mov    %eax,%edi
    24dd:	e8 81 f4 ff ff       	callq  1963 <_Z24get_dynamic_layout_by_idt>
    24e2:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
        if (layout && (layout->entry.attributes & PAGE_ATTR_DYN_THREAD))
    24e6:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    24eb:	74 19                	je     2506 <do_add_thread+0xfd>
    24ed:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    24f1:	0f b7 40 02          	movzwl 0x2(%rax),%eax
    24f5:	0f b7 c0             	movzwl %ax,%eax
    24f8:	83 e0 20             	and    $0x20,%eax
    24fb:	85 c0                	test   %eax,%eax
    24fd:	74 07                	je     2506 <do_add_thread+0xfd>
    24ff:	b8 01 00 00 00       	mov    $0x1,%eax
    2504:	eb 05                	jmp    250b <do_add_thread+0x102>
    2506:	b8 00 00 00 00       	mov    $0x0,%eax
    250b:	84 c0                	test   %al,%al
    250d:	74 3d                	je     254c <do_add_thread+0x143>
        {
            ret = apply_EPC_pages((void *)(enclave_base + layout->entry.rva + offset), layout->entry.page_count);
    250f:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2513:	8b 40 04             	mov    0x4(%rax),%eax
    2516:	89 c1                	mov    %eax,%ecx
    2518:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    251c:	48 8b 50 08          	mov    0x8(%rax),%rdx
    2520:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    2524:	48 01 c2             	add    %rax,%rdx
    2527:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    252b:	48 01 d0             	add    %rdx,%rax
    252e:	48 89 ce             	mov    %rcx,%rsi
    2531:	48 89 c7             	mov    %rax,%rdi
    2534:	e8 c4 fc ff ff       	callq  21fd <apply_EPC_pages>
    2539:	89 45 c4             	mov    %eax,-0x3c(%rbp)
            if (ret != 0)
    253c:	83 7d c4 00          	cmpl   $0x0,-0x3c(%rbp)
    2540:	74 0a                	je     254c <do_add_thread+0x143>
                return SGX_ERROR_UNEXPECTED;
    2542:	b8 01 00 00 00       	mov    $0x1,%eax
    2547:	e9 e8 00 00 00       	jmpq   2634 <do_add_thread+0x22b>
    for (uint16_t id = LAYOUT_ID_TCS_DYN; id <= LAYOUT_ID_STACK_DYN_MIN; id++)
    254c:	0f b7 45 c2          	movzwl -0x3e(%rbp),%eax
    2550:	83 c0 01             	add    $0x1,%eax
    2553:	66 89 45 c2          	mov    %ax,-0x3e(%rbp)
    2557:	e9 70 ff ff ff       	jmpq   24cc <do_add_thread+0xc3>
        }
    }

    //Copy and initialize TCS
    tcs_template = (tcs_t *)g_global_data.tcs_template;
    255c:	48 8d 05 1d ac 00 00 	lea    0xac1d(%rip),%rax        # d180 <g_global_data>
    2563:	48 8d 80 e0 00 00 00 	lea    0xe0(%rax),%rax
    256a:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    memcpy_s(tcs, TCS_SIZE, tcs_template, sizeof(g_global_data.tcs_template));
    256e:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    2572:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2576:	b9 48 00 00 00       	mov    $0x48,%ecx
    257b:	be 00 10 00 00       	mov    $0x1000,%esi
    2580:	48 89 c7             	mov    %rax,%rdi
    2583:	e8 64 f1 ff ff       	callq  16ec <memcpy_s>

    //Adjust the tcs fields
    tcs->ossa = (size_t)GET_PTR(size_t, (void *)tcs, tcs->ossa) - enclave_base;
    2588:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    258c:	48 8b 50 10          	mov    0x10(%rax),%rdx
    2590:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2594:	48 01 d0             	add    %rdx,%rax
    2597:	48 2b 45 e0          	sub    -0x20(%rbp),%rax
    259b:	48 89 c2             	mov    %rax,%rdx
    259e:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    25a2:	48 89 50 10          	mov    %rdx,0x10(%rax)
    tcs->ofs_base = (size_t)GET_PTR(size_t, (void *)tcs, tcs->ofs_base) - enclave_base;
    25a6:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    25aa:	48 8b 50 30          	mov    0x30(%rax),%rdx
    25ae:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    25b2:	48 01 d0             	add    %rdx,%rax
    25b5:	48 2b 45 e0          	sub    -0x20(%rbp),%rax
    25b9:	48 89 c2             	mov    %rax,%rdx
    25bc:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    25c0:	48 89 50 30          	mov    %rdx,0x30(%rax)
    tcs->ogs_base = (size_t)GET_PTR(size_t, (void *)tcs, tcs->ogs_base) - enclave_base;
    25c4:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    25c8:	48 8b 50 38          	mov    0x38(%rax),%rdx
    25cc:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    25d0:	48 01 d0             	add    %rdx,%rax
    25d3:	48 2b 45 e0          	sub    -0x20(%rbp),%rax
    25d7:	48 89 c2             	mov    %rax,%rdx
    25da:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    25de:	48 89 50 38          	mov    %rdx,0x38(%rax)

    //OCALL for MKTCS
    ret = sgx_ocall(0, tcs);
    25e2:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    25e6:	48 89 c6             	mov    %rax,%rsi
    25e9:	bf 00 00 00 00       	mov    $0x0,%edi
    25ee:	e8 1d 10 00 00       	callq  3610 <sgx_ocall>
    25f3:	89 45 c4             	mov    %eax,-0x3c(%rbp)
    if (ret != 0)
    25f6:	83 7d c4 00          	cmpl   $0x0,-0x3c(%rbp)
    25fa:	74 07                	je     2603 <do_add_thread+0x1fa>
        return SGX_ERROR_UNEXPECTED;
    25fc:	b8 01 00 00 00       	mov    $0x1,%eax
    2601:	eb 31                	jmp    2634 <do_add_thread+0x22b>

    //EACCEPT for MKTCS
    ret = sgx_accept_backward(SI_FLAG_TCS | SI_FLAG_MODIFIED, (size_t)tcs, (size_t)tcs + SE_PAGE_SIZE);
    2603:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2607:	48 8d 90 00 10 00 00 	lea    0x1000(%rax),%rdx
    260e:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2612:	48 89 c6             	mov    %rax,%rsi
    2615:	bf 10 01 00 00       	mov    $0x110,%edi
    261a:	e8 14 f1 ff ff       	callq  1733 <_ZL19sgx_accept_backwardmmm>
    261f:	89 45 c4             	mov    %eax,-0x3c(%rbp)
    if (ret != 0)
    2622:	83 7d c4 00          	cmpl   $0x0,-0x3c(%rbp)
    2626:	74 07                	je     262f <do_add_thread+0x226>
        return SGX_ERROR_UNEXPECTED;
    2628:	b8 01 00 00 00       	mov    $0x1,%eax
    262d:	eb 05                	jmp    2634 <do_add_thread+0x22b>

    return SGX_SUCCESS;
    262f:	b8 00 00 00 00       	mov    $0x0,%eax

#endif
}
    2634:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    2638:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    263f:	00 00 
    2641:	74 05                	je     2648 <do_add_thread+0x23f>
    2643:	e8 60 2c 00 00       	callq  52a8 <__stack_chk_fail>
    2648:	c9                   	leaveq 
    2649:	c3                   	retq   

000000000000264a <memcpy_s>:
{
    264a:	55                   	push   %rbp
    264b:	48 89 e5             	mov    %rsp,%rbp
    264e:	48 83 ec 20          	sub    $0x20,%rsp
    2652:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    2656:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    265a:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    265e:	48 89 4d e0          	mov    %rcx,-0x20(%rbp)
    if(numberOfElements<count)
    2662:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2666:	48 3b 45 e0          	cmp    -0x20(%rbp),%rax
    266a:	73 07                	jae    2673 <memcpy_s+0x29>
        return -1;
    266c:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    2671:	eb 1c                	jmp    268f <memcpy_s+0x45>
    memcpy(dest, src, count);
    2673:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    2677:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
    267b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    267f:	48 89 ce             	mov    %rcx,%rsi
    2682:	48 89 c7             	mov    %rax,%rdi
    2685:	e8 76 88 00 00       	callq  af00 <memcpy>
    return 0;
    268a:	b8 00 00 00 00       	mov    $0x0,%eax
}
    268f:	c9                   	leaveq 
    2690:	c3                   	retq   

0000000000002691 <_pthread_thread_run>:

#include "pthread_imp.h"
#include "sgx_random_buffers.h"
#include "se_page_attr.h"

__attribute__((weak)) sgx_status_t _pthread_thread_run(void* ms) {UNUSED(ms); return SGX_SUCCESS;}
    2691:	55                   	push   %rbp
    2692:	48 89 e5             	mov    %rsp,%rbp
    2695:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    2699:	b8 00 00 00 00       	mov    $0x0,%eax
    269e:	5d                   	pop    %rbp
    269f:	c3                   	retq   

00000000000026a0 <_Z16_pthread_enabledv>:
__attribute__((weak)) bool _pthread_enabled() {return false;}
    26a0:	55                   	push   %rbp
    26a1:	48 89 e5             	mov    %rsp,%rbp
    26a4:	b8 00 00 00 00       	mov    $0x0,%eax
    26a9:	5d                   	pop    %rbp
    26aa:	c3                   	retq   

00000000000026ab <_Z24_pthread_tls_store_state9_status_t>:
__attribute__((weak)) void _pthread_tls_store_state(sgx_status_t state) {UNUSED(state);}
    26ab:	55                   	push   %rbp
    26ac:	48 89 e5             	mov    %rsp,%rbp
    26af:	89 7d fc             	mov    %edi,-0x4(%rbp)
    26b2:	90                   	nop
    26b3:	5d                   	pop    %rbp
    26b4:	c3                   	retq   

00000000000026b5 <_Z22_pthread_tls_get_statev>:
__attribute__((weak)) sgx_status_t _pthread_tls_get_state(void) {return SGX_SUCCESS;}
    26b5:	55                   	push   %rbp
    26b6:	48 89 e5             	mov    %rsp,%rbp
    26b9:	b8 00 00 00 00       	mov    $0x0,%eax
    26be:	5d                   	pop    %rbp
    26bf:	c3                   	retq   

00000000000026c0 <_Z26_pthread_tls_store_contextPv>:
__attribute__((weak)) void _pthread_tls_store_context(void* context) {UNUSED(context);}
    26c0:	55                   	push   %rbp
    26c1:	48 89 e5             	mov    %rsp,%rbp
    26c4:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    26c8:	90                   	nop
    26c9:	5d                   	pop    %rbp
    26ca:	c3                   	retq   

00000000000026cb <_Z20_pthread_wakeup_joinPv>:
__attribute__((weak)) void _pthread_wakeup_join(void* ms) {UNUSED(ms);}
    26cb:	55                   	push   %rbp
    26cc:	48 89 e5             	mov    %rsp,%rbp
    26cf:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    26d3:	90                   	nop
    26d4:	5d                   	pop    %rbp
    26d5:	c3                   	retq   

00000000000026d6 <_Z24_pthread_tls_destructorsv>:
__attribute__((weak)) void _pthread_tls_destructors(void) {}
    26d6:	55                   	push   %rbp
    26d7:	48 89 e5             	mov    %rsp,%rbp
    26da:	90                   	nop
    26db:	5d                   	pop    %rbp
    26dc:	c3                   	retq   

00000000000026dd <_ZL16is_ecall_allowedj>:

// is_ecall_allowed()
// check the index in the dynamic entry table
static sgx_status_t is_ecall_allowed(uint32_t ordinal)
{
    26dd:	55                   	push   %rbp
    26de:	48 89 e5             	mov    %rsp,%rbp
    26e1:	48 83 ec 30          	sub    $0x30,%rsp
    26e5:	89 7d dc             	mov    %edi,-0x24(%rbp)
    if(ordinal >= g_ecall_table.nr_ecall)
    26e8:	8b 55 dc             	mov    -0x24(%rbp),%edx
    26eb:	48 8d 05 ee e6 00 00 	lea    0xe6ee(%rip),%rax        # 10de0 <g_ecall_table>
    26f2:	48 8b 00             	mov    (%rax),%rax
    26f5:	48 39 c2             	cmp    %rax,%rdx
    26f8:	72 0a                	jb     2704 <_ZL16is_ecall_allowedj+0x27>
    {
        return SGX_ERROR_INVALID_FUNCTION;
    26fa:	b8 01 10 00 00       	mov    $0x1001,%eax
    26ff:	e9 c7 00 00 00       	jmpq   27cb <_ZL16is_ecall_allowedj+0xee>
    }
    thread_data_t *thread_data = get_thread_data();
    2704:	e8 64 9f 00 00       	callq  c66d <get_thread_data>
    2709:	48 89 45 e8          	mov    %rax,-0x18(%rbp)

    sgx_lfence();
    270d:	0f ae e8             	lfence 

    if(thread_data->last_sp == thread_data->stack_base_addr)
    2710:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2714:	48 8b 50 08          	mov    0x8(%rax),%rdx
    2718:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    271c:	48 8b 40 10          	mov    0x10(%rax),%rax
    2720:	48 39 c2             	cmp    %rax,%rdx
    2723:	75 2d                	jne    2752 <_ZL16is_ecall_allowedj+0x75>
    {
        // root ECALL, check the priv bits.
        if (g_ecall_table.ecall_table[ordinal].is_priv)
    2725:	48 8d 05 b4 e6 00 00 	lea    0xe6b4(%rip),%rax        # 10de0 <g_ecall_table>
    272c:	8b 55 dc             	mov    -0x24(%rbp),%edx
    272f:	48 c1 e2 04          	shl    $0x4,%rdx
    2733:	48 01 d0             	add    %rdx,%rax
    2736:	48 83 c0 10          	add    $0x10,%rax
    273a:	0f b6 00             	movzbl (%rax),%eax
    273d:	84 c0                	test   %al,%al
    273f:	74 0a                	je     274b <_ZL16is_ecall_allowedj+0x6e>
            return SGX_ERROR_ECALL_NOT_ALLOWED;
    2741:	b8 07 10 00 00       	mov    $0x1007,%eax
    2746:	e9 80 00 00 00       	jmpq   27cb <_ZL16is_ecall_allowedj+0xee>
        return SGX_SUCCESS;
    274b:	b8 00 00 00 00       	mov    $0x0,%eax
    2750:	eb 79                	jmp    27cb <_ZL16is_ecall_allowedj+0xee>
    }
    ocall_context_t *context = reinterpret_cast<ocall_context_t*>(thread_data->last_sp);
    2752:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2756:	48 8b 40 08          	mov    0x8(%rax),%rax
    275a:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    if(context->ocall_flag != OCALL_FLAG)
    275e:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2762:	48 8b 40 20          	mov    0x20(%rax),%rax
    2766:	48 3d 44 49 43 4f    	cmp    $0x4f434944,%rax
    276c:	74 05                	je     2773 <_ZL16is_ecall_allowedj+0x96>
    {
        // abort the enclave if ocall frame is invalid
        abort();
    276e:	e8 29 a2 00 00       	callq  c99c <abort>
    }
    uintptr_t ocall_index = context->ocall_index;
    2773:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2777:	48 8b 40 28          	mov    0x28(%rax),%rax
    277b:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if(ocall_index >= g_dyn_entry_table.nr_ocall)
    277f:	48 8d 05 7a a8 00 00 	lea    0xa87a(%rip),%rax        # d000 <g_dyn_entry_table>
    2786:	48 8b 00             	mov    (%rax),%rax
    2789:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    278d:	72 07                	jb     2796 <_ZL16is_ecall_allowedj+0xb9>
    {
        return SGX_ERROR_INVALID_FUNCTION;
    278f:	b8 01 10 00 00       	mov    $0x1001,%eax
    2794:	eb 35                	jmp    27cb <_ZL16is_ecall_allowedj+0xee>
    }
    return (g_dyn_entry_table.entry_table[ocall_index * g_ecall_table.nr_ecall + ordinal] ? SGX_SUCCESS : SGX_ERROR_ECALL_NOT_ALLOWED);
    2796:	48 8d 05 43 e6 00 00 	lea    0xe643(%rip),%rax        # 10de0 <g_ecall_table>
    279d:	48 8b 00             	mov    (%rax),%rax
    27a0:	48 0f af 45 f8       	imul   -0x8(%rbp),%rax
    27a5:	48 89 c2             	mov    %rax,%rdx
    27a8:	8b 45 dc             	mov    -0x24(%rbp),%eax
    27ab:	48 01 c2             	add    %rax,%rdx
    27ae:	48 8d 05 4b a8 00 00 	lea    0xa84b(%rip),%rax        # d000 <g_dyn_entry_table>
    27b5:	0f b6 44 10 08       	movzbl 0x8(%rax,%rdx,1),%eax
    27ba:	84 c0                	test   %al,%al
    27bc:	74 07                	je     27c5 <_ZL16is_ecall_allowedj+0xe8>
    27be:	b8 00 00 00 00       	mov    $0x0,%eax
    27c3:	eb 05                	jmp    27ca <_ZL16is_ecall_allowedj+0xed>
    27c5:	b8 07 10 00 00       	mov    $0x1007,%eax
    27ca:	90                   	nop
}
    27cb:	c9                   	leaveq 
    27cc:	c3                   	retq   

00000000000027cd <_ZL13get_func_addrjPPv>:
// Return Value:
//      non-zero - success
//      zero - fail
//
static sgx_status_t get_func_addr(uint32_t ordinal, void **addr)
{
    27cd:	55                   	push   %rbp
    27ce:	48 89 e5             	mov    %rsp,%rbp
    27d1:	48 83 ec 20          	sub    $0x20,%rsp
    27d5:	89 7d ec             	mov    %edi,-0x14(%rbp)
    27d8:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    if(ordinal == (uint32_t)ECMD_ECALL_PTHREAD)
    27dc:	83 7d ec fa          	cmpl   $0xfffffffa,-0x14(%rbp)
    27e0:	75 15                	jne    27f7 <_ZL13get_func_addrjPPv+0x2a>
    {
        *addr = (void*) _pthread_thread_run;
    27e2:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    27e6:	48 8d 15 a4 fe ff ff 	lea    -0x15c(%rip),%rdx        # 2691 <_pthread_thread_run>
    27ed:	48 89 10             	mov    %rdx,(%rax)
        return SGX_SUCCESS;
    27f0:	b8 00 00 00 00       	mov    $0x0,%eax
    27f5:	eb 60                	jmp    2857 <_ZL13get_func_addrjPPv+0x8a>
    }

    // Normal user-defined ECalls
    sgx_status_t status = is_ecall_allowed(ordinal);
    27f7:	8b 45 ec             	mov    -0x14(%rbp),%eax
    27fa:	89 c7                	mov    %eax,%edi
    27fc:	e8 dc fe ff ff       	callq  26dd <_ZL16is_ecall_allowedj>
    2801:	89 45 fc             	mov    %eax,-0x4(%rbp)
    if(SGX_SUCCESS != status)
    2804:	83 7d fc 00          	cmpl   $0x0,-0x4(%rbp)
    2808:	74 05                	je     280f <_ZL13get_func_addrjPPv+0x42>
    {
        return status;
    280a:	8b 45 fc             	mov    -0x4(%rbp),%eax
    280d:	eb 48                	jmp    2857 <_ZL13get_func_addrjPPv+0x8a>
    }

    *addr = const_cast<void *>(g_ecall_table.ecall_table[ordinal].ecall_addr);
    280f:	48 8d 05 ca e5 00 00 	lea    0xe5ca(%rip),%rax        # 10de0 <g_ecall_table>
    2816:	8b 55 ec             	mov    -0x14(%rbp),%edx
    2819:	48 c1 e2 04          	shl    $0x4,%rdx
    281d:	48 01 d0             	add    %rdx,%rax
    2820:	48 83 c0 08          	add    $0x8,%rax
    2824:	48 8b 10             	mov    (%rax),%rdx
    2827:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    282b:	48 89 10             	mov    %rdx,(%rax)
    if(!sgx_is_within_enclave(*addr, 0))
    282e:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    2832:	48 8b 00             	mov    (%rax),%rax
    2835:	be 00 00 00 00       	mov    $0x0,%esi
    283a:	48 89 c7             	mov    %rax,%rdi
    283d:	e8 91 ea ff ff       	callq  12d3 <sgx_is_within_enclave>
    2842:	85 c0                	test   %eax,%eax
    2844:	0f 94 c0             	sete   %al
    2847:	84 c0                	test   %al,%al
    2849:	74 07                	je     2852 <_ZL13get_func_addrjPPv+0x85>
    {
        return SGX_ERROR_UNEXPECTED;
    284b:	b8 01 00 00 00       	mov    $0x1,%eax
    2850:	eb 05                	jmp    2857 <_ZL13get_func_addrjPPv+0x8a>
    }

    return SGX_SUCCESS;
    2852:	b8 00 00 00 00       	mov    $0x0,%eax
}
    2857:	c9                   	leaveq 
    2858:	c3                   	retq   

0000000000002859 <_Z11do_save_tcsPv>:
// Return Value:
//     zero - success
//     non-zero - fail
//
sgx_status_t do_save_tcs(void *ptcs)
{
    2859:	55                   	push   %rbp
    285a:	48 89 e5             	mov    %rsp,%rbp
    285d:	48 83 ec 30          	sub    $0x30,%rsp
    2861:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    2865:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    286c:	00 00 
    286e:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    2872:	31 c0                	xor    %eax,%eax
    if(!is_utility_thread())
    2874:	e8 1c 14 00 00       	callq  3c95 <is_utility_thread>
    2879:	83 f0 01             	xor    $0x1,%eax
    287c:	84 c0                	test   %al,%al
    287e:	74 0a                	je     288a <_Z11do_save_tcsPv+0x31>
        return SGX_ERROR_UNEXPECTED;
    2880:	b8 01 00 00 00       	mov    $0x1,%eax
    2885:	e9 b0 00 00 00       	jmpq   293a <_Z11do_save_tcsPv+0xe1>

    if(unlikely(g_tcs_cookie == 0))
    288a:	48 8b 05 37 e8 00 00 	mov    0xe837(%rip),%rax        # 110c8 <_ZL12g_tcs_cookie>
    2891:	48 85 c0             	test   %rax,%rax
    2894:	0f 94 c0             	sete   %al
    2897:	0f b6 c0             	movzbl %al,%eax
    289a:	48 85 c0             	test   %rax,%rax
    289d:	74 4b                	je     28ea <_Z11do_save_tcsPv+0x91>
    {
        uintptr_t rand = 0;
    289f:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    28a6:	00 
        do
        {
            if(SGX_SUCCESS != sgx_read_rand((unsigned char *)&rand, sizeof(rand)))
    28a7:	48 8d 45 e8          	lea    -0x18(%rbp),%rax
    28ab:	be 08 00 00 00       	mov    $0x8,%esi
    28b0:	48 89 c7             	mov    %rax,%rdi
    28b3:	e8 e1 ec ff ff       	callq  1599 <sgx_read_rand>
    28b8:	85 c0                	test   %eax,%eax
    28ba:	0f 95 c0             	setne  %al
    28bd:	84 c0                	test   %al,%al
    28bf:	74 07                	je     28c8 <_Z11do_save_tcsPv+0x6f>
            {
                return SGX_ERROR_UNEXPECTED;
    28c1:	b8 01 00 00 00       	mov    $0x1,%eax
    28c6:	eb 72                	jmp    293a <_Z11do_save_tcsPv+0xe1>
            }
        } while(rand == 0);
    28c8:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    28cc:	48 85 c0             	test   %rax,%rax
    28cf:	75 02                	jne    28d3 <_Z11do_save_tcsPv+0x7a>
        do
    28d1:	eb d4                	jmp    28a7 <_Z11do_save_tcsPv+0x4e>

        if(g_tcs_cookie == 0)
    28d3:	48 8b 05 ee e7 00 00 	mov    0xe7ee(%rip),%rax        # 110c8 <_ZL12g_tcs_cookie>
    28da:	48 85 c0             	test   %rax,%rax
    28dd:	75 0b                	jne    28ea <_Z11do_save_tcsPv+0x91>
        {
            g_tcs_cookie = rand;
    28df:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    28e3:	48 89 05 de e7 00 00 	mov    %rax,0xe7de(%rip)        # 110c8 <_ZL12g_tcs_cookie>
        }
    }

    tcs_node_t *tcs_node = (tcs_node_t *)malloc(sizeof(tcs_node_t));
    28ea:	bf 10 00 00 00       	mov    $0x10,%edi
    28ef:	e8 82 64 00 00       	callq  8d76 <dlmalloc>
    28f4:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    if(!tcs_node)
    28f8:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    28fd:	75 07                	jne    2906 <_Z11do_save_tcsPv+0xad>
    {
        return SGX_ERROR_UNEXPECTED;
    28ff:	b8 01 00 00 00       	mov    $0x1,%eax
    2904:	eb 34                	jmp    293a <_Z11do_save_tcsPv+0xe1>
    }

    tcs_node->tcs = ENC_TCS_POINTER(ptcs);
    2906:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    290a:	48 8b 05 b7 e7 00 00 	mov    0xe7b7(%rip),%rax        # 110c8 <_ZL12g_tcs_cookie>
    2911:	48 31 c2             	xor    %rax,%rdx
    2914:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2918:	48 89 10             	mov    %rdx,(%rax)

    tcs_node->next = g_tcs_node;
    291b:	48 8b 15 9e e7 00 00 	mov    0xe79e(%rip),%rdx        # 110c0 <_ZL10g_tcs_node>
    2922:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2926:	48 89 50 08          	mov    %rdx,0x8(%rax)
    g_tcs_node = tcs_node;
    292a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    292e:	48 89 05 8b e7 00 00 	mov    %rax,0xe78b(%rip)        # 110c0 <_ZL10g_tcs_node>

    return SGX_SUCCESS;
    2935:	b8 00 00 00 00       	mov    $0x0,%eax
}
    293a:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    293e:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    2945:	00 00 
    2947:	74 05                	je     294e <_Z11do_save_tcsPv+0xf5>
    2949:	e8 5a 29 00 00       	callq  52a8 <__stack_chk_fail>
    294e:	c9                   	leaveq 
    294f:	c3                   	retq   

0000000000002950 <_ZL10do_del_tcsPv>:
//      [IN] ptcs - the tcs_t pointer which need to be deleted
// Return Value:
//     N/A
//
static void do_del_tcs(void *ptcs)
{
    2950:	55                   	push   %rbp
    2951:	48 89 e5             	mov    %rsp,%rbp
    2954:	48 83 ec 30          	sub    $0x30,%rsp
    2958:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    if(!is_utility_thread())
    295c:	e8 34 13 00 00       	callq  3c95 <is_utility_thread>
    2961:	83 f0 01             	xor    $0x1,%eax
    2964:	84 c0                	test   %al,%al
    2966:	0f 85 c1 00 00 00    	jne    2a2d <_ZL10do_del_tcsPv+0xdd>
        return;

    if (g_tcs_node != NULL)
    296c:	48 8b 05 4d e7 00 00 	mov    0xe74d(%rip),%rax        # 110c0 <_ZL10g_tcs_node>
    2973:	48 85 c0             	test   %rax,%rax
    2976:	0f 84 b2 00 00 00    	je     2a2e <_ZL10do_del_tcsPv+0xde>
    {
        if (DEC_TCS_POINTER(g_tcs_node->tcs) == ptcs)
    297c:	48 8b 05 3d e7 00 00 	mov    0xe73d(%rip),%rax        # 110c0 <_ZL10g_tcs_node>
    2983:	48 8b 10             	mov    (%rax),%rdx
    2986:	48 8b 05 3b e7 00 00 	mov    0xe73b(%rip),%rax        # 110c8 <_ZL12g_tcs_cookie>
    298d:	48 31 d0             	xor    %rdx,%rax
    2990:	48 39 45 d8          	cmp    %rax,-0x28(%rbp)
    2994:	75 2b                	jne    29c1 <_ZL10do_del_tcsPv+0x71>
        {
            tcs_node_t *tmp = g_tcs_node;
    2996:	48 8b 05 23 e7 00 00 	mov    0xe723(%rip),%rax        # 110c0 <_ZL10g_tcs_node>
    299d:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
            g_tcs_node = g_tcs_node->next;
    29a1:	48 8b 05 18 e7 00 00 	mov    0xe718(%rip),%rax        # 110c0 <_ZL10g_tcs_node>
    29a8:	48 8b 40 08          	mov    0x8(%rax),%rax
    29ac:	48 89 05 0d e7 00 00 	mov    %rax,0xe70d(%rip)        # 110c0 <_ZL10g_tcs_node>
            free(tmp);
    29b3:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    29b7:	48 89 c7             	mov    %rax,%rdi
    29ba:	e8 ae 6e 00 00       	callq  986d <dlfree>
    29bf:	eb 6d                	jmp    2a2e <_ZL10do_del_tcsPv+0xde>
        }
        else
        {
            tcs_node_t *tcs_node = g_tcs_node->next;
    29c1:	48 8b 05 f8 e6 00 00 	mov    0xe6f8(%rip),%rax        # 110c0 <_ZL10g_tcs_node>
    29c8:	48 8b 40 08          	mov    0x8(%rax),%rax
    29cc:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
            tcs_node_t *pre_tcs_node = g_tcs_node;
    29d0:	48 8b 05 e9 e6 00 00 	mov    0xe6e9(%rip),%rax        # 110c0 <_ZL10g_tcs_node>
    29d7:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
            while (tcs_node != NULL)
    29db:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    29e0:	74 4c                	je     2a2e <_ZL10do_del_tcsPv+0xde>
            {
                if (DEC_TCS_POINTER(tcs_node->tcs) == ptcs)
    29e2:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    29e6:	48 8b 10             	mov    (%rax),%rdx
    29e9:	48 8b 05 d8 e6 00 00 	mov    0xe6d8(%rip),%rax        # 110c8 <_ZL12g_tcs_cookie>
    29f0:	48 31 d0             	xor    %rdx,%rax
    29f3:	48 39 45 d8          	cmp    %rax,-0x28(%rbp)
    29f7:	75 1e                	jne    2a17 <_ZL10do_del_tcsPv+0xc7>
                {
                    pre_tcs_node->next = tcs_node->next;
    29f9:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    29fd:	48 8b 50 08          	mov    0x8(%rax),%rdx
    2a01:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2a05:	48 89 50 08          	mov    %rdx,0x8(%rax)
                    free(tcs_node);
    2a09:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2a0d:	48 89 c7             	mov    %rax,%rdi
    2a10:	e8 58 6e 00 00       	callq  986d <dlfree>
                    break;
    2a15:	eb 17                	jmp    2a2e <_ZL10do_del_tcsPv+0xde>
                }

                pre_tcs_node = tcs_node;
    2a17:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2a1b:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
                tcs_node = tcs_node->next;
    2a1f:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2a23:	48 8b 40 08          	mov    0x8(%rax),%rax
    2a27:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
            while (tcs_node != NULL)
    2a2b:	eb ae                	jmp    29db <_ZL10do_del_tcsPv+0x8b>
        return;
    2a2d:	90                   	nop
            }
        }
    }
}
    2a2e:	c9                   	leaveq 
    2a2f:	c3                   	retq   

0000000000002a30 <_ZL10trts_ecalljPv>:
static volatile bool           g_is_first_ecall = true;
static volatile sgx_spinlock_t g_ife_lock       = SGX_SPINLOCK_INITIALIZER;

typedef sgx_status_t (*ecall_func_t)(void *ms);
static sgx_status_t trts_ecall(uint32_t ordinal, void *ms)
{
    2a30:	55                   	push   %rbp
    2a31:	48 89 e5             	mov    %rsp,%rbp
    2a34:	48 83 ec 40          	sub    $0x40,%rsp
    2a38:	89 7d cc             	mov    %edi,-0x34(%rbp)
    2a3b:	48 89 75 c0          	mov    %rsi,-0x40(%rbp)
    2a3f:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    2a46:	00 00 
    2a48:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    2a4c:	31 c0                	xor    %eax,%eax
    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    2a4e:	c7 45 d4 01 00 00 00 	movl   $0x1,-0x2c(%rbp)

    if (unlikely(g_is_first_ecall))
    2a55:	0f b6 05 a4 e5 00 00 	movzbl 0xe5a4(%rip),%eax        # 11000 <_ZL16g_is_first_ecall>
    2a5c:	0f b6 c0             	movzbl %al,%eax
    2a5f:	48 85 c0             	test   %rax,%rax
    2a62:	0f 95 c0             	setne  %al
    2a65:	84 c0                	test   %al,%al
    2a67:	0f 84 9a 00 00 00    	je     2b07 <_ZL10trts_ecalljPv+0xd7>
    {
        // The thread performing the global initialization cannot do a nested ECall
        thread_data_t *thread_data = get_thread_data();
    2a6d:	e8 fb 9b 00 00       	callq  c66d <get_thread_data>
    2a72:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
        if (thread_data->last_sp != thread_data->stack_base_addr)
    2a76:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    2a7a:	48 8b 50 08          	mov    0x8(%rax),%rdx
    2a7e:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    2a82:	48 8b 40 10          	mov    0x10(%rax),%rax
    2a86:	48 39 c2             	cmp    %rax,%rdx
    2a89:	74 0a                	je     2a95 <_ZL10trts_ecalljPv+0x65>
        { // nested ecall
            return SGX_ERROR_ECALL_NOT_ALLOWED;
    2a8b:	b8 07 10 00 00       	mov    $0x1007,%eax
    2a90:	e9 b2 00 00 00       	jmpq   2b47 <_ZL10trts_ecalljPv+0x117>
        }

        sgx_spin_lock(&g_ife_lock);
    2a95:	48 8d 3d 34 e6 00 00 	lea    0xe634(%rip),%rdi        # 110d0 <_ZL10g_ife_lock>
    2a9c:	e8 2c 89 00 00       	callq  b3cd <sgx_spin_lock>
        if (g_is_first_ecall)
    2aa1:	0f b6 05 58 e5 00 00 	movzbl 0xe558(%rip),%eax        # 11000 <_ZL16g_is_first_ecall>
    2aa8:	84 c0                	test   %al,%al
    2aaa:	74 4f                	je     2afb <_ZL10trts_ecalljPv+0xcb>
        {
#ifndef SE_SIM
            if(EDMM_supported)
    2aac:	48 8d 05 4d e3 00 00 	lea    0xe34d(%rip),%rax        # 10e00 <EDMM_supported>
    2ab3:	8b 00                	mov    (%rax),%eax
    2ab5:	85 c0                	test   %eax,%eax
    2ab7:	74 36                	je     2aef <_ZL10trts_ecalljPv+0xbf>
            {
                //change back the page permission
                size_t enclave_start = (size_t)&__ImageBase;
    2ab9:	48 8d 05 40 d5 ff ff 	lea    -0x2ac0(%rip),%rax        # 0 <enclave.so>
    2ac0:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
                if((status = change_protection((void *)enclave_start)) != SGX_SUCCESS)
    2ac4:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2ac8:	48 89 c7             	mov    %rax,%rdi
    2acb:	e8 13 23 00 00       	callq  4de3 <change_protection>
    2ad0:	89 45 d4             	mov    %eax,-0x2c(%rbp)
    2ad3:	83 7d d4 00          	cmpl   $0x0,-0x2c(%rbp)
    2ad7:	0f 95 c0             	setne  %al
    2ada:	84 c0                	test   %al,%al
    2adc:	74 11                	je     2aef <_ZL10trts_ecalljPv+0xbf>
                {
                    sgx_spin_unlock(&g_ife_lock);
    2ade:	48 8d 3d eb e5 00 00 	lea    0xe5eb(%rip),%rdi        # 110d0 <_ZL10g_ife_lock>
    2ae5:	e8 4a 89 00 00       	callq  b434 <sgx_spin_unlock>
                    return status;
    2aea:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    2aed:	eb 58                	jmp    2b47 <_ZL10trts_ecalljPv+0x117>
                }
            }
#endif
            //invoke global object's construction
            init_global_object();
    2aef:	e8 97 27 00 00       	callq  528b <init_global_object>
            g_is_first_ecall = false;
    2af4:	c6 05 05 e5 00 00 00 	movb   $0x0,0xe505(%rip)        # 11000 <_ZL16g_is_first_ecall>
        }
        sgx_spin_unlock(&g_ife_lock);
    2afb:	48 8d 3d ce e5 00 00 	lea    0xe5ce(%rip),%rdi        # 110d0 <_ZL10g_ife_lock>
    2b02:	e8 2d 89 00 00       	callq  b434 <sgx_spin_unlock>
    }

    void *addr = NULL;
    2b07:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    2b0e:	00 
    status = get_func_addr(ordinal, &addr);
    2b0f:	48 8d 55 d8          	lea    -0x28(%rbp),%rdx
    2b13:	8b 45 cc             	mov    -0x34(%rbp),%eax
    2b16:	48 89 d6             	mov    %rdx,%rsi
    2b19:	89 c7                	mov    %eax,%edi
    2b1b:	e8 ad fc ff ff       	callq  27cd <_ZL13get_func_addrjPPv>
    2b20:	89 45 d4             	mov    %eax,-0x2c(%rbp)
    if(status == SGX_SUCCESS)
    2b23:	83 7d d4 00          	cmpl   $0x0,-0x2c(%rbp)
    2b27:	75 1b                	jne    2b44 <_ZL10trts_ecalljPv+0x114>
    {
        ecall_func_t func = (ecall_func_t)addr;
    2b29:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2b2d:	48 89 45 f0          	mov    %rax,-0x10(%rbp)

        sgx_lfence();
    2b31:	0f ae e8             	lfence 

        status = func(ms);
    2b34:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    2b38:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2b3c:	48 89 d7             	mov    %rdx,%rdi
    2b3f:	ff d0                	callq  *%rax
    2b41:	89 45 d4             	mov    %eax,-0x2c(%rbp)
    }
    
    return status;
    2b44:	8b 45 d4             	mov    -0x2c(%rbp),%eax
}
    2b47:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    2b4b:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    2b52:	00 00 
    2b54:	74 05                	je     2b5b <_ZL10trts_ecalljPv+0x12b>
    2b56:	e8 4d 27 00 00       	callq  52a8 <__stack_chk_fail>
    2b5b:	c9                   	leaveq 
    2b5c:	c3                   	retq   

0000000000002b5d <_ZL24init_static_stack_canaryPv>:

extern "C" uintptr_t __stack_chk_guard;
static void init_static_stack_canary(void *tcs)
{
    2b5d:	55                   	push   %rbp
    2b5e:	48 89 e5             	mov    %rsp,%rbp
    2b61:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    size_t *canary = TCS2CANARY(tcs);
    2b65:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2b69:	48 2d a8 02 01 00    	sub    $0x102a8,%rax
    2b6f:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    *canary = (size_t)__stack_chk_guard;
    2b73:	48 8d 05 96 e2 00 00 	lea    0xe296(%rip),%rax        # 10e10 <__intel_security_cookie>
    2b7a:	48 8b 10             	mov    (%rax),%rdx
    2b7d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    2b81:	48 89 10             	mov    %rdx,(%rax)
}
    2b84:	90                   	nop
    2b85:	5d                   	pop    %rbp
    2b86:	c3                   	retq   

0000000000002b87 <do_init_thread>:

sgx_status_t do_init_thread(void *tcs, bool enclave_init)
{
    2b87:	55                   	push   %rbp
    2b88:	48 89 e5             	mov    %rsp,%rbp
    2b8b:	48 83 ec 50          	sub    $0x50,%rsp
    2b8f:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    2b93:	89 f0                	mov    %esi,%eax
    2b95:	88 45 b4             	mov    %al,-0x4c(%rbp)
    2b98:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    2b9f:	00 00 
    2ba1:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    2ba5:	31 c0                	xor    %eax,%eax
    thread_data_t *thread_data = GET_PTR(thread_data_t, tcs, g_global_data.td_template.self_addr);
    2ba7:	48 8d 05 d2 a5 00 00 	lea    0xa5d2(%rip),%rax        # d180 <g_global_data>
    2bae:	48 8b 50 40          	mov    0x40(%rax),%rdx
    2bb2:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2bb6:	48 01 d0             	add    %rdx,%rax
    2bb9:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
#ifndef SE_SIM
    size_t saved_stack_commit_addr = thread_data->stack_commit_addr;
    2bbd:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2bc1:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    2bc8:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    bool thread_first_init = (saved_stack_commit_addr == 0) ? true : false;
    2bcc:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
    2bd1:	0f 94 c0             	sete   %al
    2bd4:	88 45 c3             	mov    %al,-0x3d(%rbp)
#endif
    size_t stack_guard = thread_data->stack_guard;
    2bd7:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2bdb:	48 8b 40 28          	mov    0x28(%rax),%rax
    2bdf:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    size_t thread_flags = thread_data->flags;
    2be3:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2be7:	48 8b 40 30          	mov    0x30(%rax),%rax
    2beb:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    memcpy_s(thread_data, SE_PAGE_SIZE, const_cast<thread_data_t *>(&g_global_data.td_template), sizeof(thread_data_t));
    2bef:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2bf3:	b9 a0 00 00 00       	mov    $0xa0,%ecx
    2bf8:	48 8d 15 81 a5 00 00 	lea    0xa581(%rip),%rdx        # d180 <g_global_data>
    2bff:	48 8d 52 40          	lea    0x40(%rdx),%rdx
    2c03:	be 00 10 00 00       	mov    $0x1000,%esi
    2c08:	48 89 c7             	mov    %rax,%rdi
    2c0b:	e8 3a fa ff ff       	callq  264a <memcpy_s>
    thread_data->last_sp += (size_t)tcs;
    2c10:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c14:	48 8b 50 08          	mov    0x8(%rax),%rdx
    2c18:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2c1c:	48 01 c2             	add    %rax,%rdx
    2c1f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c23:	48 89 50 08          	mov    %rdx,0x8(%rax)
    thread_data->self_addr += (size_t)tcs;
    2c27:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c2b:	48 8b 10             	mov    (%rax),%rdx
    2c2e:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2c32:	48 01 c2             	add    %rax,%rdx
    2c35:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c39:	48 89 10             	mov    %rdx,(%rax)
    thread_data->stack_base_addr += (size_t)tcs;
    2c3c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c40:	48 8b 50 10          	mov    0x10(%rax),%rdx
    2c44:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2c48:	48 01 c2             	add    %rax,%rdx
    2c4b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c4f:	48 89 50 10          	mov    %rdx,0x10(%rax)
    thread_data->stack_limit_addr += (size_t)tcs;
    2c53:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c57:	48 8b 50 18          	mov    0x18(%rax),%rdx
    2c5b:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2c5f:	48 01 c2             	add    %rax,%rdx
    2c62:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c66:	48 89 50 18          	mov    %rdx,0x18(%rax)
    thread_data->stack_commit_addr = thread_data->stack_limit_addr;
    2c6a:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c6e:	48 8b 50 18          	mov    0x18(%rax),%rdx
    2c72:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c76:	48 89 90 98 00 00 00 	mov    %rdx,0x98(%rax)
    thread_data->first_ssa_gpr += (size_t)tcs;
    2c7d:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c81:	48 8b 50 20          	mov    0x20(%rax),%rdx
    2c85:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2c89:	48 01 c2             	add    %rax,%rdx
    2c8c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c90:	48 89 50 20          	mov    %rdx,0x20(%rax)
    thread_data->tls_array += (size_t)tcs;
    2c94:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c98:	48 8b 50 58          	mov    0x58(%rax),%rdx
    2c9c:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2ca0:	48 01 c2             	add    %rax,%rdx
    2ca3:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2ca7:	48 89 50 58          	mov    %rdx,0x58(%rax)
    thread_data->tls_addr += (size_t)tcs;
    2cab:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2caf:	48 8b 50 50          	mov    0x50(%rax),%rdx
    2cb3:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2cb7:	48 01 c2             	add    %rax,%rdx
    2cba:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2cbe:	48 89 50 50          	mov    %rdx,0x50(%rax)
    thread_data->last_sp -= (size_t)STATIC_STACK_SIZE;
    2cc2:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2cc6:	48 8b 40 08          	mov    0x8(%rax),%rax
    2cca:	48 8d 90 50 fd ff ff 	lea    -0x2b0(%rax),%rdx
    2cd1:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2cd5:	48 89 50 08          	mov    %rdx,0x8(%rax)
    thread_data->stack_base_addr -= (size_t)STATIC_STACK_SIZE;
    2cd9:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2cdd:	48 8b 40 10          	mov    0x10(%rax),%rax
    2ce1:	48 8d 90 50 fd ff ff 	lea    -0x2b0(%rax),%rdx
    2ce8:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2cec:	48 89 50 10          	mov    %rdx,0x10(%rax)
    thread_data->stack_guard = stack_guard;
    2cf0:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2cf4:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    2cf8:	48 89 50 28          	mov    %rdx,0x28(%rax)
    thread_data->flags = thread_flags;
    2cfc:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2d00:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    2d04:	48 89 50 30          	mov    %rdx,0x30(%rax)
    init_static_stack_canary(tcs);
    2d08:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2d0c:	48 89 c7             	mov    %rax,%rdi
    2d0f:	e8 49 fe ff ff       	callq  2b5d <_ZL24init_static_stack_canaryPv>

    if (EDMM_supported && enclave_init)
    2d14:	48 8d 05 e5 e0 00 00 	lea    0xe0e5(%rip),%rax        # 10e00 <EDMM_supported>
    2d1b:	8b 00                	mov    (%rax),%eax
    2d1d:	85 c0                	test   %eax,%eax
    2d1f:	74 12                	je     2d33 <do_init_thread+0x1ac>
    2d21:	80 7d b4 00          	cmpb   $0x0,-0x4c(%rbp)
    2d25:	74 0c                	je     2d33 <do_init_thread+0x1ac>
    {
        thread_data->flags = SGX_UTILITY_THREAD;
    2d27:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2d2b:	48 c7 40 30 01 00 00 	movq   $0x1,0x30(%rax)
    2d32:	00 
    }
#ifndef SE_SIM
    if (thread_first_init)
    2d33:	80 7d c3 00          	cmpb   $0x0,-0x3d(%rbp)
    2d37:	74 5d                	je     2d96 <do_init_thread+0x20f>
    {
        if (EDMM_supported && (enclave_init || is_dynamic_thread(tcs)))
    2d39:	48 8d 05 c0 e0 00 00 	lea    0xe0c0(%rip),%rax        # 10e00 <EDMM_supported>
    2d40:	8b 00                	mov    (%rax),%eax
    2d42:	85 c0                	test   %eax,%eax
    2d44:	74 1d                	je     2d63 <do_init_thread+0x1dc>
    2d46:	80 7d b4 00          	cmpb   $0x0,-0x4c(%rbp)
    2d4a:	75 10                	jne    2d5c <do_init_thread+0x1d5>
    2d4c:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2d50:	48 89 c7             	mov    %rax,%rdi
    2d53:	e8 30 f2 ff ff       	callq  1f88 <is_dynamic_thread>
    2d58:	85 c0                	test   %eax,%eax
    2d5a:	74 07                	je     2d63 <do_init_thread+0x1dc>
    2d5c:	b8 01 00 00 00       	mov    $0x1,%eax
    2d61:	eb 05                	jmp    2d68 <do_init_thread+0x1e1>
    2d63:	b8 00 00 00 00       	mov    $0x0,%eax
    2d68:	84 c0                	test   %al,%al
    2d6a:	74 39                	je     2da5 <do_init_thread+0x21e>
        {
            uint32_t page_count = get_dynamic_stack_max_page();
    2d6c:	e8 d7 f2 ff ff       	callq  2048 <get_dynamic_stack_max_page>
    2d71:	89 45 c4             	mov    %eax,-0x3c(%rbp)
            thread_data->stack_commit_addr += ((sys_word_t)page_count << SE_PAGE_SHIFT);
    2d74:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2d78:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    2d7f:	8b 55 c4             	mov    -0x3c(%rbp),%edx
    2d82:	48 c1 e2 0c          	shl    $0xc,%rdx
    2d86:	48 01 c2             	add    %rax,%rdx
    2d89:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2d8d:	48 89 90 98 00 00 00 	mov    %rdx,0x98(%rax)
    2d94:	eb 0f                	jmp    2da5 <do_init_thread+0x21e>
        }
    }
    else
    {
        thread_data->stack_commit_addr = saved_stack_commit_addr;
    2d96:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2d9a:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    2d9e:	48 89 90 98 00 00 00 	mov    %rdx,0x98(%rax)
    }
#endif

    uintptr_t tls_addr = 0;
    2da5:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    2dac:	00 
    size_t tdata_size = 0;
    2dad:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    2db4:	00 

    if(0 != GET_TLS_INFO(&__ImageBase, &tls_addr, &tdata_size))
    2db5:	48 8d 55 d0          	lea    -0x30(%rbp),%rdx
    2db9:	48 8d 45 c8          	lea    -0x38(%rbp),%rax
    2dbd:	48 89 c6             	mov    %rax,%rsi
    2dc0:	48 8d 05 39 d2 ff ff 	lea    -0x2dc7(%rip),%rax        # 0 <enclave.so>
    2dc7:	48 89 c7             	mov    %rax,%rdi
    2dca:	e8 80 1b 00 00       	callq  494f <elf_tls_info>
    2dcf:	85 c0                	test   %eax,%eax
    2dd1:	0f 95 c0             	setne  %al
    2dd4:	84 c0                	test   %al,%al
    2dd6:	74 0a                	je     2de2 <do_init_thread+0x25b>
    {
        return SGX_ERROR_UNEXPECTED;
    2dd8:	b8 01 00 00 00       	mov    $0x1,%eax
    2ddd:	e9 83 00 00 00       	jmpq   2e65 <do_init_thread+0x2de>
    }
    if(tls_addr)
    2de2:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    2de6:	48 85 c0             	test   %rax,%rax
    2de9:	74 75                	je     2e60 <do_init_thread+0x2d9>
    {
        memset((void *)TRIM_TO_PAGE(thread_data->tls_addr), 0, ROUND_TO_PAGE(thread_data->self_addr - thread_data->tls_addr));
    2deb:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2def:	48 8b 10             	mov    (%rax),%rdx
    2df2:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2df6:	48 8b 40 50          	mov    0x50(%rax),%rax
    2dfa:	48 29 c2             	sub    %rax,%rdx
    2dfd:	48 89 d0             	mov    %rdx,%rax
    2e00:	48 05 ff 0f 00 00    	add    $0xfff,%rax
    2e06:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    2e0c:	48 89 c2             	mov    %rax,%rdx
    2e0f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2e13:	48 8b 40 50          	mov    0x50(%rax),%rax
    2e17:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    2e1d:	be 00 00 00 00       	mov    $0x0,%esi
    2e22:	48 89 c7             	mov    %rax,%rdi
    2e25:	e8 44 81 00 00       	callq  af6e <memset>
        memcpy_s((void *)(thread_data->tls_addr), thread_data->self_addr - thread_data->tls_addr, (void *)tls_addr, tdata_size);
    2e2a:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2e2e:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    2e32:	49 89 d0             	mov    %rdx,%r8
    2e35:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    2e39:	48 8b 0a             	mov    (%rdx),%rcx
    2e3c:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    2e40:	48 8b 52 50          	mov    0x50(%rdx),%rdx
    2e44:	48 29 d1             	sub    %rdx,%rcx
    2e47:	48 89 ce             	mov    %rcx,%rsi
    2e4a:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    2e4e:	48 8b 52 50          	mov    0x50(%rdx),%rdx
    2e52:	48 89 d7             	mov    %rdx,%rdi
    2e55:	48 89 c1             	mov    %rax,%rcx
    2e58:	4c 89 c2             	mov    %r8,%rdx
    2e5b:	e8 ea f7 ff ff       	callq  264a <memcpy_s>
    }

    return SGX_SUCCESS;
    2e60:	b8 00 00 00 00       	mov    $0x0,%eax
}
    2e65:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    2e69:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    2e70:	00 00 
    2e72:	74 05                	je     2e79 <do_init_thread+0x2f2>
    2e74:	e8 2f 24 00 00       	callq  52a8 <__stack_chk_fail>
    2e79:	c9                   	leaveq 
    2e7a:	c3                   	retq   

0000000000002e7b <do_ecall>:

sgx_status_t do_ecall(int index, void *ms, void *tcs)
{
    2e7b:	55                   	push   %rbp
    2e7c:	48 89 e5             	mov    %rsp,%rbp
    2e7f:	48 83 c4 80          	add    $0xffffffffffffff80,%rsp
    2e83:	89 7d 9c             	mov    %edi,-0x64(%rbp)
    2e86:	48 89 75 90          	mov    %rsi,-0x70(%rbp)
    2e8a:	48 89 55 88          	mov    %rdx,-0x78(%rbp)
    2e8e:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    2e95:	00 00 
    2e97:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    2e9b:	31 c0                	xor    %eax,%eax
    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    2e9d:	c7 45 a4 01 00 00 00 	movl   $0x1,-0x5c(%rbp)
    if(ENCLAVE_INIT_DONE != get_enclave_state())
    2ea4:	e8 91 97 00 00       	callq  c63a <get_enclave_state>
    2ea9:	83 f8 02             	cmp    $0x2,%eax
    2eac:	0f 95 c0             	setne  %al
    2eaf:	84 c0                	test   %al,%al
    2eb1:	74 08                	je     2ebb <do_ecall+0x40>
    {
        return status;
    2eb3:	8b 45 a4             	mov    -0x5c(%rbp),%eax
    2eb6:	e9 8c 01 00 00       	jmpq   3047 <do_ecall+0x1cc>
    }
    thread_data_t *thread_data = get_thread_data();
    2ebb:	e8 ad 97 00 00       	callq  c66d <get_thread_data>
    2ec0:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    if( (NULL == thread_data) || 
    2ec4:	48 83 7d a8 00       	cmpq   $0x0,-0x58(%rbp)
    2ec9:	74 37                	je     2f02 <do_ecall+0x87>
            ((thread_data->stack_base_addr == thread_data->last_sp) && 
    2ecb:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    2ecf:	48 8b 50 10          	mov    0x10(%rax),%rdx
    2ed3:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    2ed7:	48 8b 40 08          	mov    0x8(%rax),%rax
    if( (NULL == thread_data) || 
    2edb:	48 39 c2             	cmp    %rax,%rdx
    2ede:	75 29                	jne    2f09 <do_ecall+0x8e>
                    ( (0 != g_global_data.thread_policy) ||
    2ee0:	48 8d 05 99 a2 00 00 	lea    0xa299(%rip),%rax        # d180 <g_global_data>
    2ee7:	48 8b 40 30          	mov    0x30(%rax),%rax
            ((thread_data->stack_base_addr == thread_data->last_sp) && 
    2eeb:	48 85 c0             	test   %rax,%rax
    2eee:	75 12                	jne    2f02 <do_ecall+0x87>
                       (SGX_PTHREAD_EXIT == _pthread_tls_get_state()) ||    /*Force do initial thread if previous ECALL is exited by pthread_exit()*/
    2ef0:	e8 c0 f7 ff ff       	callq  26b5 <_Z22_pthread_tls_get_statev>
                    ( (0 != g_global_data.thread_policy) ||
    2ef5:	83 f8 09             	cmp    $0x9,%eax
    2ef8:	74 08                	je     2f02 <do_ecall+0x87>
                        (index == ECMD_ECALL_PTHREAD))))  /*Force do initial thread if this thread is created by SGX pthread_create() */
    2efa:	8b 45 9c             	mov    -0x64(%rbp),%eax
                       (SGX_PTHREAD_EXIT == _pthread_tls_get_state()) ||    /*Force do initial thread if previous ECALL is exited by pthread_exit()*/
    2efd:	83 f8 fa             	cmp    $0xfffffffa,%eax
    2f00:	75 07                	jne    2f09 <do_ecall+0x8e>
    if( (NULL == thread_data) || 
    2f02:	b8 01 00 00 00       	mov    $0x1,%eax
    2f07:	eb 05                	jmp    2f0e <do_ecall+0x93>
    2f09:	b8 00 00 00 00       	mov    $0x0,%eax
    2f0e:	84 c0                	test   %al,%al
    2f10:	74 22                	je     2f34 <do_ecall+0xb9>
    {
        status = do_init_thread(tcs, false);
    2f12:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    2f16:	be 00 00 00 00       	mov    $0x0,%esi
    2f1b:	48 89 c7             	mov    %rax,%rdi
    2f1e:	e8 64 fc ff ff       	callq  2b87 <do_init_thread>
    2f23:	89 45 a4             	mov    %eax,-0x5c(%rbp)
        if(0 != status)
    2f26:	83 7d a4 00          	cmpl   $0x0,-0x5c(%rbp)
    2f2a:	74 08                	je     2f34 <do_ecall+0xb9>
        {
            return status;
    2f2c:	8b 45 a4             	mov    -0x5c(%rbp),%eax
    2f2f:	e9 13 01 00 00       	jmpq   3047 <do_ecall+0x1cc>
        }
    }
    thread_data = get_thread_data();
    2f34:	e8 34 97 00 00       	callq  c66d <get_thread_data>
    2f39:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    if(thread_data->stack_base_addr == thread_data->last_sp)
    2f3d:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    2f41:	48 8b 50 10          	mov    0x10(%rax),%rdx
    2f45:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    2f49:	48 8b 40 08          	mov    0x8(%rax),%rax
    2f4d:	48 39 c2             	cmp    %rax,%rdx
    2f50:	0f 85 da 00 00 00    	jne    3030 <do_ecall+0x1b5>
    {
        //root ecall
        if(_pthread_enabled())
    2f56:	e8 45 f7 ff ff       	callq  26a0 <_Z16_pthread_enabledv>
    2f5b:	84 c0                	test   %al,%al
    2f5d:	0f 84 b1 00 00 00    	je     3014 <do_ecall+0x199>
        {
            jmp_buf     buf = {0};
    2f63:	48 c7 45 b0 00 00 00 	movq   $0x0,-0x50(%rbp)
    2f6a:	00 
    2f6b:	48 c7 45 b8 00 00 00 	movq   $0x0,-0x48(%rbp)
    2f72:	00 
    2f73:	48 c7 45 c0 00 00 00 	movq   $0x0,-0x40(%rbp)
    2f7a:	00 
    2f7b:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    2f82:	00 
    2f83:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    2f8a:	00 
    2f8b:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    2f92:	00 
    2f93:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    2f9a:	00 
    2f9b:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    2fa2:	00 
            if(0 == setjmp(buf))
    2fa3:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    2fa7:	48 89 c7             	mov    %rax,%rdi
    2faa:	e8 9e 84 00 00       	callq  b44d <_setjmp>
    2faf:	85 c0                	test   %eax,%eax
    2fb1:	0f 94 c0             	sete   %al
    2fb4:	84 c0                	test   %al,%al
    2fb6:	74 28                	je     2fe0 <do_ecall+0x165>
            {
                _pthread_tls_store_context((void*)buf);
    2fb8:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    2fbc:	48 89 c7             	mov    %rax,%rdi
    2fbf:	e8 fc f6 ff ff       	callq  26c0 <_Z26_pthread_tls_store_contextPv>
                status = random_stack_advance<0x800>(trts_ecall, index, ms);
    2fc4:	48 8d 55 90          	lea    -0x70(%rbp),%rdx
    2fc8:	48 8d 45 9c          	lea    -0x64(%rbp),%rax
    2fcc:	48 89 c6             	mov    %rax,%rsi
    2fcf:	48 8d 3d 5a fa ff ff 	lea    -0x5a6(%rip),%rdi        # 2a30 <_ZL10trts_ecalljPv>
    2fd6:	e8 78 04 00 00       	callq  3453 <_Z20random_stack_advanceILj2048E9_status_tJjPvEJRiRS1_EET0_PFS4_DpT1_EDpOT2_>
    2fdb:	89 45 a4             	mov    %eax,-0x5c(%rbp)
    2fde:	eb 21                	jmp    3001 <do_ecall+0x186>
            }
            else
            {
                //Enter here if pthread_exit() is called inside ECALL functions.
                _pthread_tls_store_state(SGX_PTHREAD_EXIT);
    2fe0:	bf 09 00 00 00       	mov    $0x9,%edi
    2fe5:	e8 c1 f6 ff ff       	callq  26ab <_Z24_pthread_tls_store_state9_status_t>
                //Important: manually reset the last_sp
                thread_data->last_sp = thread_data->stack_base_addr;
    2fea:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    2fee:	48 8b 50 10          	mov    0x10(%rax),%rdx
    2ff2:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    2ff6:	48 89 50 08          	mov    %rdx,0x8(%rax)
                status = SGX_PTHREAD_EXIT;
    2ffa:	c7 45 a4 09 00 00 00 	movl   $0x9,-0x5c(%rbp)
            }
            //-- execute some resource recycle function here, such as tls resource recycle
            _pthread_tls_destructors();
    3001:	e8 d0 f6 ff ff       	callq  26d6 <_Z24_pthread_tls_destructorsv>
            _pthread_wakeup_join(ms); 
    3006:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    300a:	48 89 c7             	mov    %rax,%rdi
    300d:	e8 b9 f6 ff ff       	callq  26cb <_Z20_pthread_wakeup_joinPv>
    3012:	eb 30                	jmp    3044 <do_ecall+0x1c9>
        }
        else 
        {
            //sgx pthread lib isn't linked
            status = random_stack_advance<0x800>(trts_ecall, index, ms);
    3014:	48 8d 55 90          	lea    -0x70(%rbp),%rdx
    3018:	48 8d 45 9c          	lea    -0x64(%rbp),%rax
    301c:	48 89 c6             	mov    %rax,%rsi
    301f:	48 8d 3d 0a fa ff ff 	lea    -0x5f6(%rip),%rdi        # 2a30 <_ZL10trts_ecalljPv>
    3026:	e8 28 04 00 00       	callq  3453 <_Z20random_stack_advanceILj2048E9_status_tJjPvEJRiRS1_EET0_PFS4_DpT1_EDpOT2_>
    302b:	89 45 a4             	mov    %eax,-0x5c(%rbp)
    302e:	eb 14                	jmp    3044 <do_ecall+0x1c9>
        }
    }
    else
    {
        status = trts_ecall(index, ms);
    3030:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    3034:	8b 55 9c             	mov    -0x64(%rbp),%edx
    3037:	48 89 c6             	mov    %rax,%rsi
    303a:	89 d7                	mov    %edx,%edi
    303c:	e8 ef f9 ff ff       	callq  2a30 <_ZL10trts_ecalljPv>
    3041:	89 45 a4             	mov    %eax,-0x5c(%rbp)
    }
    return status;
    3044:	8b 45 a4             	mov    -0x5c(%rbp),%eax
}
    3047:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    304b:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    3052:	00 00 
    3054:	74 05                	je     305b <do_ecall+0x1e0>
    3056:	e8 4d 22 00 00       	callq  52a8 <__stack_chk_fail>
    305b:	c9                   	leaveq 
    305c:	c3                   	retq   

000000000000305d <do_ecall_add_thread>:

sgx_status_t do_ecall_add_thread(void *ms)
{
    305d:	55                   	push   %rbp
    305e:	48 89 e5             	mov    %rsp,%rbp
    3061:	48 83 ec 30          	sub    $0x30,%rsp
    3065:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    3069:	c7 45 e4 01 00 00 00 	movl   $0x1,-0x1c(%rbp)

    if(!is_utility_thread())
    3070:	e8 20 0c 00 00       	callq  3c95 <is_utility_thread>
    3075:	83 f0 01             	xor    $0x1,%eax
    3078:	84 c0                	test   %al,%al
    307a:	74 08                	je     3084 <do_ecall_add_thread+0x27>
        return status;
    307c:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    307f:	e9 9b 00 00 00       	jmpq   311f <do_ecall_add_thread+0xc2>

    struct ms_tcs *tcs = (struct ms_tcs*)ms;
    3084:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3088:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    if (tcs == NULL)
    308c:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    3091:	75 08                	jne    309b <do_ecall_add_thread+0x3e>
    {
        return status;
    3093:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    3096:	e9 84 00 00 00       	jmpq   311f <do_ecall_add_thread+0xc2>
    }

    if (!sgx_is_outside_enclave(tcs, sizeof(struct ms_tcs)))
    309b:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    309f:	be 08 00 00 00       	mov    $0x8,%esi
    30a4:	48 89 c7             	mov    %rax,%rdi
    30a7:	e8 b7 e2 ff ff       	callq  1363 <sgx_is_outside_enclave>
    30ac:	85 c0                	test   %eax,%eax
    30ae:	0f 94 c0             	sete   %al
    30b1:	84 c0                	test   %al,%al
    30b3:	74 05                	je     30ba <do_ecall_add_thread+0x5d>
    {
        return status;
    30b5:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    30b8:	eb 65                	jmp    311f <do_ecall_add_thread+0xc2>
    }

    const struct ms_tcs mtcs = *tcs;
    30ba:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    30be:	48 8b 00             	mov    (%rax),%rax
    30c1:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    void* ptcs = mtcs.ptcs;
    30c5:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    30c9:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if (ptcs == NULL)
    30cd:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    30d2:	75 05                	jne    30d9 <do_ecall_add_thread+0x7c>
    {
        return status;
    30d4:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    30d7:	eb 46                	jmp    311f <do_ecall_add_thread+0xc2>
    }

    sgx_lfence();
    30d9:	0f ae e8             	lfence 

    status = do_save_tcs(ptcs);
    30dc:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    30e0:	48 89 c7             	mov    %rax,%rdi
    30e3:	e8 71 f7 ff ff       	callq  2859 <_Z11do_save_tcsPv>
    30e8:	89 45 e4             	mov    %eax,-0x1c(%rbp)
    if(SGX_SUCCESS != status)
    30eb:	83 7d e4 00          	cmpl   $0x0,-0x1c(%rbp)
    30ef:	74 05                	je     30f6 <do_ecall_add_thread+0x99>
    {
        return status;
    30f1:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    30f4:	eb 29                	jmp    311f <do_ecall_add_thread+0xc2>
    }

    status = do_add_thread(ptcs);
    30f6:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    30fa:	48 89 c7             	mov    %rax,%rdi
    30fd:	e8 07 f3 ff ff       	callq  2409 <do_add_thread>
    3102:	89 45 e4             	mov    %eax,-0x1c(%rbp)
    if (SGX_SUCCESS != status)
    3105:	83 7d e4 00          	cmpl   $0x0,-0x1c(%rbp)
    3109:	74 11                	je     311c <do_ecall_add_thread+0xbf>
    {
    	do_del_tcs(ptcs);
    310b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    310f:	48 89 c7             	mov    %rax,%rdi
    3112:	e8 39 f8 ff ff       	callq  2950 <_ZL10do_del_tcsPv>
        return status;
    3117:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    311a:	eb 03                	jmp    311f <do_ecall_add_thread+0xc2>
    }

    return status;
    311c:	8b 45 e4             	mov    -0x1c(%rbp),%eax
}
    311f:	c9                   	leaveq 
    3120:	c3                   	retq   

0000000000003121 <do_uninit_enclave>:
// Return Value:
//     zero - success
//     non-zero - fail
//
sgx_status_t do_uninit_enclave(void *tcs)
{
    3121:	55                   	push   %rbp
    3122:	48 89 e5             	mov    %rsp,%rbp
    3125:	48 83 ec 40          	sub    $0x40,%rsp
    3129:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    // This function should only be called when
    //  1. EDMM is enabled
    //  2. on HW mode
    // urts would not call this ECALL either on simulation mode
    // or on non-EDMM supported platform.
    if (!EDMM_supported)
    312d:	48 8d 05 cc dc 00 00 	lea    0xdccc(%rip),%rax        # 10e00 <EDMM_supported>
    3134:	8b 00                	mov    (%rax),%eax
    3136:	85 c0                	test   %eax,%eax
    3138:	75 14                	jne    314e <do_uninit_enclave+0x2d>
    {
        set_enclave_state(ENCLAVE_CRASHED);
    313a:	bf 03 00 00 00       	mov    $0x3,%edi
    313f:	e8 03 95 00 00       	callq  c647 <set_enclave_state>
        return SGX_ERROR_UNEXPECTED;
    3144:	b8 01 00 00 00       	mov    $0x1,%eax
    3149:	e9 4c 01 00 00       	jmpq   329a <do_uninit_enclave+0x179>
    }

    if(!is_utility_thread() && is_dynamic_thread_exist())
    314e:	e8 42 0b 00 00       	callq  3c95 <is_utility_thread>
    3153:	83 f0 01             	xor    $0x1,%eax
    3156:	84 c0                	test   %al,%al
    3158:	74 10                	je     316a <do_uninit_enclave+0x49>
    315a:	e8 aa ee ff ff       	callq  2009 <is_dynamic_thread_exist>
    315f:	85 c0                	test   %eax,%eax
    3161:	74 07                	je     316a <do_uninit_enclave+0x49>
    3163:	b8 01 00 00 00       	mov    $0x1,%eax
    3168:	eb 05                	jmp    316f <do_uninit_enclave+0x4e>
    316a:	b8 00 00 00 00       	mov    $0x0,%eax
    316f:	84 c0                	test   %al,%al
    3171:	74 14                	je     3187 <do_uninit_enclave+0x66>
    {
        set_enclave_state(ENCLAVE_CRASHED);
    3173:	bf 03 00 00 00       	mov    $0x3,%edi
    3178:	e8 ca 94 00 00       	callq  c647 <set_enclave_state>
        return SGX_ERROR_UNEXPECTED;
    317d:	b8 01 00 00 00       	mov    $0x1,%eax
    3182:	e9 13 01 00 00       	jmpq   329a <do_uninit_enclave+0x179>
    }

    // Set uninit_flag to indicate the do_uninit_enclave is called
    __sync_or_and_fetch(&g_uninit_flag, 1);
    3187:	f0 83 0d 45 df 00 00 	lock orl $0x1,0xdf45(%rip)        # 110d4 <g_uninit_flag>
    318e:	01 

    tcs_node_t *tcs_node = g_tcs_node;
    318f:	48 8b 05 2a df 00 00 	mov    0xdf2a(%rip),%rax        # 110c0 <_ZL10g_tcs_node>
    3196:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    g_tcs_node = NULL;
    319a:	48 c7 05 1b df 00 00 	movq   $0x0,0xdf1b(%rip)        # 110c0 <_ZL10g_tcs_node>
    31a1:	00 00 00 00 
    while (tcs_node != NULL)
    31a5:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    31aa:	0f 84 b0 00 00 00    	je     3260 <do_uninit_enclave+0x13f>
    {
        if (DEC_TCS_POINTER(tcs_node->tcs) == tcs)
    31b0:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    31b4:	48 8b 10             	mov    (%rax),%rdx
    31b7:	48 8b 05 0a df 00 00 	mov    0xdf0a(%rip),%rax        # 110c8 <_ZL12g_tcs_cookie>
    31be:	48 31 d0             	xor    %rdx,%rax
    31c1:	48 39 45 c8          	cmp    %rax,-0x38(%rbp)
    31c5:	75 22                	jne    31e9 <do_uninit_enclave+0xc8>
        {
            tcs_node_t *tmp = tcs_node;
    31c7:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    31cb:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
            tcs_node = tcs_node->next;
    31cf:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    31d3:	48 8b 40 08          	mov    0x8(%rax),%rax
    31d7:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
            free(tmp);
    31db:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    31df:	48 89 c7             	mov    %rax,%rdi
    31e2:	e8 86 66 00 00       	callq  986d <dlfree>
            continue;
    31e7:	eb 72                	jmp    325b <do_uninit_enclave+0x13a>
        }

        size_t start = (size_t)DEC_TCS_POINTER(tcs_node->tcs);
    31e9:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    31ed:	48 8b 10             	mov    (%rax),%rdx
    31f0:	48 8b 05 d1 de 00 00 	mov    0xded1(%rip),%rax        # 110c8 <_ZL12g_tcs_cookie>
    31f7:	48 31 d0             	xor    %rdx,%rax
    31fa:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
        size_t end = start + (1 << SE_PAGE_SHIFT);
    31fe:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3202:	48 05 00 10 00 00    	add    $0x1000,%rax
    3208:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
        int rc = sgx_accept_forward(SI_FLAG_TRIM | SI_FLAG_MODIFIED, start, end);
    320c:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    3210:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3214:	48 89 c6             	mov    %rax,%rsi
    3217:	bf 10 04 00 00       	mov    $0x410,%edi
    321c:	e8 54 ee ff ff       	callq  2075 <sgx_accept_forward>
    3221:	89 45 d4             	mov    %eax,-0x2c(%rbp)
        if(rc != 0)
    3224:	83 7d d4 00          	cmpl   $0x0,-0x2c(%rbp)
    3228:	74 11                	je     323b <do_uninit_enclave+0x11a>
        {
            set_enclave_state(ENCLAVE_CRASHED);
    322a:	bf 03 00 00 00       	mov    $0x3,%edi
    322f:	e8 13 94 00 00       	callq  c647 <set_enclave_state>
            return SGX_ERROR_UNEXPECTED;
    3234:	b8 01 00 00 00       	mov    $0x1,%eax
    3239:	eb 5f                	jmp    329a <do_uninit_enclave+0x179>
        }

        tcs_node_t *tmp = tcs_node;
    323b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    323f:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
        tcs_node = tcs_node->next;
    3243:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3247:	48 8b 40 08          	mov    0x8(%rax),%rax
    324b:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
        free(tmp);
    324f:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    3253:	48 89 c7             	mov    %rax,%rdi
    3256:	e8 12 66 00 00       	callq  986d <dlfree>
    while (tcs_node != NULL)
    325b:	e9 45 ff ff ff       	jmpq   31a5 <do_uninit_enclave+0x84>
    }

    sgx_spin_lock(&g_ife_lock);
    3260:	48 8d 3d 69 de 00 00 	lea    0xde69(%rip),%rdi        # 110d0 <_ZL10g_ife_lock>
    3267:	e8 61 81 00 00       	callq  b3cd <sgx_spin_lock>
    if (!g_is_first_ecall)
    326c:	0f b6 05 8d dd 00 00 	movzbl 0xdd8d(%rip),%eax        # 11000 <_ZL16g_is_first_ecall>
    3273:	83 f0 01             	xor    $0x1,%eax
    3276:	84 c0                	test   %al,%al
    3278:	74 05                	je     327f <do_uninit_enclave+0x15e>
    {
        uninit_global_object();
    327a:	e8 18 20 00 00       	callq  5297 <uninit_global_object>
    }
    sgx_spin_unlock(&g_ife_lock);
    327f:	48 8d 3d 4a de 00 00 	lea    0xde4a(%rip),%rdi        # 110d0 <_ZL10g_ife_lock>
    3286:	e8 a9 81 00 00       	callq  b434 <sgx_spin_unlock>
#else
    UNUSED(tcs);
#endif    
    set_enclave_state(ENCLAVE_CRASHED);
    328b:	bf 03 00 00 00       	mov    $0x3,%edi
    3290:	e8 b2 93 00 00       	callq  c647 <set_enclave_state>

    return SGX_SUCCESS;
    3295:	b8 00 00 00 00       	mov    $0x0,%eax
}
    329a:	c9                   	leaveq 
    329b:	c3                   	retq   

000000000000329c <trts_mprotect>:

extern sdk_version_t g_sdk_version;

extern "C" sgx_status_t trts_mprotect(size_t start, size_t size, uint64_t perms)
{
    329c:	4c 8d 54 24 08       	lea    0x8(%rsp),%r10
    32a1:	48 83 e4 c0          	and    $0xffffffffffffffc0,%rsp
    32a5:	41 ff 72 f8          	pushq  -0x8(%r10)
    32a9:	55                   	push   %rbp
    32aa:	48 89 e5             	mov    %rsp,%rbp
    32ad:	41 52                	push   %r10
    32af:	48 81 ec e8 00 00 00 	sub    $0xe8,%rsp
    32b6:	48 89 bd 38 ff ff ff 	mov    %rdi,-0xc8(%rbp)
    32bd:	48 89 b5 30 ff ff ff 	mov    %rsi,-0xd0(%rbp)
    32c4:	48 89 95 28 ff ff ff 	mov    %rdx,-0xd8(%rbp)
    32cb:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    32d2:	00 00 
    32d4:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    32d8:	31 c0                	xor    %eax,%eax
    int rc = -1;
    32da:	c7 85 40 ff ff ff ff 	movl   $0xffffffff,-0xc0(%rbp)
    32e1:	ff ff ff 
    size_t page;
    sgx_status_t ret = SGX_SUCCESS;
    32e4:	c7 85 44 ff ff ff 00 	movl   $0x0,-0xbc(%rbp)
    32eb:	00 00 00 
    SE_DECLSPEC_ALIGN(sizeof(sec_info_t)) sec_info_t si;

    //Error return if start or size is not page-aligned or size is zero.
    if (!IS_PAGE_ALIGNED(start) || (size == 0) || !IS_PAGE_ALIGNED(size))
    32ee:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    32f5:	25 ff 0f 00 00       	and    $0xfff,%eax
    32fa:	48 85 c0             	test   %rax,%rax
    32fd:	75 1b                	jne    331a <trts_mprotect+0x7e>
    32ff:	48 83 bd 30 ff ff ff 	cmpq   $0x0,-0xd0(%rbp)
    3306:	00 
    3307:	74 11                	je     331a <trts_mprotect+0x7e>
    3309:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    3310:	25 ff 0f 00 00       	and    $0xfff,%eax
    3315:	48 85 c0             	test   %rax,%rax
    3318:	74 0a                	je     3324 <trts_mprotect+0x88>
        return SGX_ERROR_INVALID_PARAMETER;
    331a:	b8 02 00 00 00       	mov    $0x2,%eax
    331f:	e9 0c 01 00 00       	jmpq   3430 <trts_mprotect+0x194>
    if (g_sdk_version == SDK_VERSION_2_0)
    3324:	48 8d 05 d9 da 00 00 	lea    0xdad9(%rip),%rax        # 10e04 <g_sdk_version>
    332b:	8b 00                	mov    (%rax),%eax
    332d:	83 f8 01             	cmp    $0x1,%eax
    3330:	75 3a                	jne    336c <trts_mprotect+0xd0>
    {
        ret = change_permissions_ocall(start, size, perms);
    3332:	48 8b 95 28 ff ff ff 	mov    -0xd8(%rbp),%rdx
    3339:	48 8b 8d 30 ff ff ff 	mov    -0xd0(%rbp),%rcx
    3340:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    3347:	48 89 ce             	mov    %rcx,%rsi
    334a:	48 89 c7             	mov    %rax,%rdi
    334d:	e8 39 02 00 00       	callq  358b <change_permissions_ocall>
    3352:	89 85 44 ff ff ff    	mov    %eax,-0xbc(%rbp)
        if (ret != SGX_SUCCESS)
    3358:	83 bd 44 ff ff ff 00 	cmpl   $0x0,-0xbc(%rbp)
    335f:	74 0b                	je     336c <trts_mprotect+0xd0>
            return ret;
    3361:	8b 85 44 ff ff ff    	mov    -0xbc(%rbp),%eax
    3367:	e9 c4 00 00 00       	jmpq   3430 <trts_mprotect+0x194>
    }

    si.flags = perms|SI_FLAG_REG|SI_FLAG_PR;
    336c:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    3373:	48 0d 20 02 00 00    	or     $0x220,%rax
    3379:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    memset(&si.reserved, 0, sizeof(si.reserved));
    3380:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
    3387:	48 83 c0 08          	add    $0x8,%rax
    338b:	ba 38 00 00 00       	mov    $0x38,%edx
    3390:	be 00 00 00 00       	mov    $0x0,%esi
    3395:	48 89 c7             	mov    %rax,%rdi
    3398:	e8 d1 7b 00 00       	callq  af6e <memset>

    for(page = start; page < start + size; page += SE_PAGE_SIZE)
    339d:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    33a4:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    33ab:	48 8b 95 38 ff ff ff 	mov    -0xc8(%rbp),%rdx
    33b2:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    33b9:	48 01 d0             	add    %rdx,%rax
    33bc:	48 39 85 48 ff ff ff 	cmp    %rax,-0xb8(%rbp)
    33c3:	73 66                	jae    342b <trts_mprotect+0x18f>
    {
        do_emodpe(&si, page);
    33c5:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    33cc:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
    33d3:	48 89 d6             	mov    %rdx,%rsi
    33d6:	48 89 c7             	mov    %rax,%rdi
    33d9:	e8 8a 95 00 00       	callq  c968 <do_emodpe>
        // If the target permission to set is RWX, no EMODPR, hence no EACCEPT.
        if ((perms & (SI_FLAG_W|SI_FLAG_X)) != (SI_FLAG_W|SI_FLAG_X))
    33de:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    33e5:	83 e0 06             	and    $0x6,%eax
    33e8:	48 83 f8 06          	cmp    $0x6,%rax
    33ec:	74 30                	je     341e <trts_mprotect+0x182>
        {
            rc = do_eaccept(&si, page);
    33ee:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    33f5:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
    33fc:	48 89 d6             	mov    %rdx,%rsi
    33ff:	48 89 c7             	mov    %rax,%rdi
    3402:	e8 47 95 00 00       	callq  c94e <do_eaccept>
    3407:	89 85 40 ff ff ff    	mov    %eax,-0xc0(%rbp)
            if(rc != 0)
    340d:	83 bd 40 ff ff ff 00 	cmpl   $0x0,-0xc0(%rbp)
    3414:	74 08                	je     341e <trts_mprotect+0x182>
                return (sgx_status_t)rc;
    3416:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    341c:	eb 12                	jmp    3430 <trts_mprotect+0x194>
    for(page = start; page < start + size; page += SE_PAGE_SIZE)
    341e:	48 81 85 48 ff ff ff 	addq   $0x1000,-0xb8(%rbp)
    3425:	00 10 00 00 
    3429:	eb 80                	jmp    33ab <trts_mprotect+0x10f>
        }
    }

    return SGX_SUCCESS;
    342b:	b8 00 00 00 00       	mov    $0x0,%eax
}
    3430:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    3434:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    343b:	00 00 
    343d:	74 05                	je     3444 <trts_mprotect+0x1a8>
    343f:	e8 64 1e 00 00       	callq  52a8 <__stack_chk_fail>
    3444:	48 81 c4 e8 00 00 00 	add    $0xe8,%rsp
    344b:	41 5a                	pop    %r10
    344d:	5d                   	pop    %rbp
    344e:	49 8d 62 f8          	lea    -0x8(%r10),%rsp
    3452:	c3                   	retq   

0000000000003453 <_Z20random_stack_advanceILj2048E9_status_tJjPvEJRiRS1_EET0_PFS4_DpT1_EDpOT2_>:
__attribute__((noinline)) static R _random_stack_noinline_wrapper(R(*f)(Ps...), Qs&&... args)
{
    return f(std::forward<Qs>(args)...);
}
template <unsigned M = 0x1000, class R, class... Ps, class... Qs>
R random_stack_advance(R(*f)(Ps...), Qs&&... args)
    3453:	55                   	push   %rbp
    3454:	48 89 e5             	mov    %rsp,%rbp
    3457:	41 57                	push   %r15
    3459:	41 56                	push   %r14
    345b:	41 55                	push   %r13
    345d:	41 54                	push   %r12
    345f:	53                   	push   %rbx
    3460:	48 83 ec 58          	sub    $0x58,%rsp
    3464:	48 89 7d 98          	mov    %rdi,-0x68(%rbp)
    3468:	48 89 75 90          	mov    %rsi,-0x70(%rbp)
    346c:	48 89 55 88          	mov    %rdx,-0x78(%rbp)
    3470:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    3477:	00 00 
    3479:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    347d:	31 c0                	xor    %eax,%eax
        memset((void *)dummy_vla, 0, size);
#else
    (void)(dummy_vla);
#endif

    return _random_stack_noinline_wrapper(f, std::forward<Qs>(args)...);
    347f:	48 89 e0             	mov    %rsp,%rax
    3482:	48 89 c3             	mov    %rax,%rbx
    unsigned size = rdrand() % M + 1;
    3485:	e8 b2 00 00 00       	callq  353c <_Z6rdrandIjET_v>
    348a:	25 ff 07 00 00       	and    $0x7ff,%eax
    348f:	83 c0 01             	add    $0x1,%eax
    3492:	89 45 a4             	mov    %eax,-0x5c(%rbp)
    volatile char dummy_vla[size];
    3495:	8b 45 a4             	mov    -0x5c(%rbp),%eax
    3498:	48 83 e8 01          	sub    $0x1,%rax
    349c:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    34a0:	48 89 c2             	mov    %rax,%rdx
    34a3:	48 83 c2 01          	add    $0x1,%rdx
    34a7:	49 89 d6             	mov    %rdx,%r14
    34aa:	41 bf 00 00 00 00    	mov    $0x0,%r15d
    34b0:	48 89 c2             	mov    %rax,%rdx
    34b3:	48 83 c2 01          	add    $0x1,%rdx
    34b7:	49 89 d4             	mov    %rdx,%r12
    34ba:	41 bd 00 00 00 00    	mov    $0x0,%r13d
    34c0:	48 8d 50 01          	lea    0x1(%rax),%rdx
    34c4:	b8 10 00 00 00       	mov    $0x10,%eax
    34c9:	48 83 e8 01          	sub    $0x1,%rax
    34cd:	48 01 d0             	add    %rdx,%rax
    34d0:	be 10 00 00 00       	mov    $0x10,%esi
    34d5:	ba 00 00 00 00       	mov    $0x0,%edx
    34da:	48 f7 f6             	div    %rsi
    34dd:	48 6b c0 10          	imul   $0x10,%rax,%rax
    34e1:	48 29 c4             	sub    %rax,%rsp
    34e4:	48 89 e0             	mov    %rsp,%rax
    34e7:	48 83 c0 00          	add    $0x0,%rax
    34eb:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    34ef:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    34f3:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
template <class _Tp>
inline _LIBCPP_INLINE_VISIBILITY _LIBCPP_CONSTEXPR_AFTER_CXX11
_Tp&&
forward(typename remove_reference<_Tp>::type& __t) _NOEXCEPT
{
    return static_cast<_Tp&&>(__t);
    34f7:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    34fb:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    34ff:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    3503:	48 8b 4d b8          	mov    -0x48(%rbp),%rcx
    return _random_stack_noinline_wrapper(f, std::forward<Qs>(args)...);
    3507:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    350b:	48 89 ce             	mov    %rcx,%rsi
    350e:	48 89 c7             	mov    %rax,%rdi
    3511:	e8 35 00 00 00       	callq  354b <_Z30_random_stack_noinline_wrapperI9_status_tJjPvEJRiRS1_EET_PFS4_DpT0_EDpOT1_>
    3516:	48 89 dc             	mov    %rbx,%rsp
}
    3519:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    351d:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    3524:	00 00 
    3526:	74 05                	je     352d <_Z20random_stack_advanceILj2048E9_status_tJjPvEJRiRS1_EET0_PFS4_DpT1_EDpOT2_+0xda>
    3528:	e8 7b 1d 00 00       	callq  52a8 <__stack_chk_fail>
    352d:	48 8d 65 d8          	lea    -0x28(%rbp),%rsp
    3531:	5b                   	pop    %rbx
    3532:	41 5c                	pop    %r12
    3534:	41 5d                	pop    %r13
    3536:	41 5e                	pop    %r14
    3538:	41 5f                	pop    %r15
    353a:	5d                   	pop    %rbp
    353b:	c3                   	retq   

000000000000353c <_Z6rdrandIjET_v>:
inline R rdrand(void)
    353c:	55                   	push   %rbp
    353d:	48 89 e5             	mov    %rsp,%rbp
    __asm__ volatile ("rdrand %0" : "=r"(r));
    3540:	0f c7 f0             	rdrand %eax
    3543:	89 45 fc             	mov    %eax,-0x4(%rbp)
    return r;
    3546:	8b 45 fc             	mov    -0x4(%rbp),%eax
}
    3549:	5d                   	pop    %rbp
    354a:	c3                   	retq   

000000000000354b <_Z30_random_stack_noinline_wrapperI9_status_tJjPvEJRiRS1_EET_PFS4_DpT0_EDpOT1_>:
__attribute__((noinline)) static R _random_stack_noinline_wrapper(R(*f)(Ps...), Qs&&... args)
    354b:	55                   	push   %rbp
    354c:	48 89 e5             	mov    %rsp,%rbp
    354f:	48 83 ec 30          	sub    $0x30,%rsp
    3553:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    3557:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    355b:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    355f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3563:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    3567:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    return f(std::forward<Qs>(args)...);
    356b:	48 8b 10             	mov    (%rax),%rdx
    356e:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3572:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    3576:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    357a:	8b 00                	mov    (%rax),%eax
    357c:	89 c1                	mov    %eax,%ecx
    357e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3582:	48 89 d6             	mov    %rdx,%rsi
    3585:	89 cf                	mov    %ecx,%edi
    3587:	ff d0                	callq  *%rax
}
    3589:	c9                   	leaveq 
    358a:	c3                   	retq   

000000000000358b <change_permissions_ocall>:
    size_t ms_size;
    uint64_t ms_epcm_perms;
} ms_change_permissions_ocall_t;

sgx_status_t SGXAPI change_permissions_ocall(size_t addr, size_t size, uint64_t epcm_perms)
{
    358b:	55                   	push   %rbp
    358c:	48 89 e5             	mov    %rsp,%rbp
    358f:	48 83 ec 40          	sub    $0x40,%rsp
    3593:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    3597:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    359b:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
    (void)addr;
    (void)size;
    (void)epcm_perms;
    return SGX_SUCCESS;
#else
    sgx_status_t status = SGX_SUCCESS;
    359f:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%rbp)

    ms_change_permissions_ocall_t* ms;
    OCALLOC(ms, ms_change_permissions_ocall_t*, sizeof(*ms));
    35a6:	bf 18 00 00 00       	mov    $0x18,%edi
    35ab:	e8 43 de ff ff       	callq  13f3 <sgx_ocalloc>
    35b0:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    35b4:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    35b9:	75 0c                	jne    35c7 <change_permissions_ocall+0x3c>
    35bb:	e8 44 df ff ff       	callq  1504 <sgx_ocfree>
    35c0:	b8 01 00 00 00       	mov    $0x1,%eax
    35c5:	eb 47                	jmp    360e <change_permissions_ocall+0x83>
    35c7:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    35cb:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

    ms->ms_addr = addr;
    35cf:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    35d3:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    35d7:	48 89 10             	mov    %rdx,(%rax)
    ms->ms_size = size;
    35da:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    35de:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    35e2:	48 89 50 08          	mov    %rdx,0x8(%rax)
    ms->ms_epcm_perms = epcm_perms;
    35e6:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    35ea:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    35ee:	48 89 50 10          	mov    %rdx,0x10(%rax)
    status = sgx_ocall(EDMM_MODPR, ms);
    35f2:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    35f6:	48 89 c6             	mov    %rax,%rsi
    35f9:	bf fc ff ff ff       	mov    $0xfffffffc,%edi
    35fe:	e8 0d 00 00 00       	callq  3610 <sgx_ocall>
    3603:	89 45 ec             	mov    %eax,-0x14(%rbp)


    sgx_ocfree();
    3606:	e8 f9 de ff ff       	callq  1504 <sgx_ocfree>
    return status;
    360b:	8b 45 ec             	mov    -0x14(%rbp),%eax
#endif
}
    360e:	c9                   	leaveq 
    360f:	c3                   	retq   

0000000000003610 <sgx_ocall>:
//      ms - the mashalling structure
// Return Value:
//      OCALL status
//
sgx_status_t sgx_ocall(const unsigned int index, void *ms)
{
    3610:	55                   	push   %rbp
    3611:	48 89 e5             	mov    %rsp,%rbp
    3614:	48 83 ec 20          	sub    $0x20,%rsp
    3618:	89 7d ec             	mov    %edi,-0x14(%rbp)
    361b:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    // the OCALL index should be within the ocall table range
    // -2, -3 and -4 -5 should be allowed to test SDK 2.0 features
    if((index != 0) && !is_builtin_ocall((int)index) &&
    361f:	83 7d ec 00          	cmpl   $0x0,-0x14(%rbp)
    3623:	74 29                	je     364e <sgx_ocall+0x3e>
    3625:	8b 45 ec             	mov    -0x14(%rbp),%eax
    3628:	83 f8 fc             	cmp    $0xfffffffc,%eax
    362b:	7c 08                	jl     3635 <sgx_ocall+0x25>
    362d:	8b 45 ec             	mov    -0x14(%rbp),%eax
    3630:	83 f8 ff             	cmp    $0xffffffff,%eax
    3633:	7c 19                	jl     364e <sgx_ocall+0x3e>
            static_cast<size_t>(index) >= g_dyn_entry_table.nr_ocall)
    3635:	8b 55 ec             	mov    -0x14(%rbp),%edx
    3638:	48 8d 05 c1 99 00 00 	lea    0x99c1(%rip),%rax        # d000 <g_dyn_entry_table>
    363f:	48 8b 00             	mov    (%rax),%rax
    if((index != 0) && !is_builtin_ocall((int)index) &&
    3642:	48 39 c2             	cmp    %rax,%rdx
    3645:	72 07                	jb     364e <sgx_ocall+0x3e>
    {
        return SGX_ERROR_INVALID_FUNCTION;
    3647:	b8 01 10 00 00       	mov    $0x1001,%eax
    364c:	eb 17                	jmp    3665 <sgx_ocall+0x55>
    }

    // do sgx_ocall
    sgx_status_t status = do_ocall(index, ms);
    364e:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    3652:	8b 45 ec             	mov    -0x14(%rbp),%eax
    3655:	48 89 d6             	mov    %rdx,%rsi
    3658:	89 c7                	mov    %eax,%edi
    365a:	e8 42 92 00 00       	callq  c8a1 <__morestack>
    365f:	89 45 fc             	mov    %eax,-0x4(%rbp)

    return status;
    3662:	8b 45 fc             	mov    -0x4(%rbp),%eax
}
    3665:	c9                   	leaveq 
    3666:	c3                   	retq   

0000000000003667 <update_ocall_lastsp>:


extern "C"
uintptr_t update_ocall_lastsp(ocall_context_t* context)
{
    3667:	55                   	push   %rbp
    3668:	48 89 e5             	mov    %rsp,%rbp
    366b:	48 83 ec 30          	sub    $0x30,%rsp
    366f:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    thread_data_t* thread_data = get_thread_data();
    3673:	e8 f5 8f 00 00       	callq  c66d <get_thread_data>
    3678:	48 89 45 e8          	mov    %rax,-0x18(%rbp)

    uintptr_t last_sp = 0;
    367c:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
    3683:	00 

    last_sp = thread_data->last_sp;
    3684:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3688:	48 8b 40 08          	mov    0x8(%rax),%rax
    368c:	48 89 45 f0          	mov    %rax,-0x10(%rbp)

    context->pre_last_sp = last_sp;
    3690:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3694:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    3698:	48 89 50 30          	mov    %rdx,0x30(%rax)

    if (context->pre_last_sp == thread_data->stack_base_addr)
    369c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    36a0:	48 8b 50 30          	mov    0x30(%rax),%rdx
    36a4:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    36a8:	48 8b 40 10          	mov    0x10(%rax),%rax
    36ac:	48 39 c2             	cmp    %rax,%rdx
    36af:	75 11                	jne    36c2 <update_ocall_lastsp+0x5b>
    {
        context->ocall_depth = 1;
    36b1:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    36b5:	48 c7 80 90 00 00 00 	movq   $0x1,0x90(%rax)
    36bc:	01 00 00 00 
    36c0:	eb 26                	jmp    36e8 <update_ocall_lastsp+0x81>
    } else {
        // thread_data->last_sp is only set when ocall or exception handling occurs
        // ocall is block during exception handling, so last_sp is always ocall frame here
        ocall_context_t* context_pre = reinterpret_cast<ocall_context_t*>(context->pre_last_sp);
    36c2:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    36c6:	48 8b 40 30          	mov    0x30(%rax),%rax
    36ca:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
        context->ocall_depth = context_pre->ocall_depth + 1;
    36ce:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    36d2:	48 8b 80 90 00 00 00 	mov    0x90(%rax),%rax
    36d9:	48 8d 50 01          	lea    0x1(%rax),%rdx
    36dd:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    36e1:	48 89 90 90 00 00 00 	mov    %rdx,0x90(%rax)
    }

    thread_data->last_sp = reinterpret_cast<uintptr_t>(context);
    36e8:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    36ec:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    36f0:	48 89 50 08          	mov    %rdx,0x8(%rax)

    return last_sp;
    36f4:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
}
    36f8:	c9                   	leaveq 
    36f9:	c3                   	retq   

00000000000036fa <do_oret>:

sgx_status_t do_oret(void *ms)
{
    36fa:	55                   	push   %rbp
    36fb:	48 89 e5             	mov    %rsp,%rbp
    36fe:	48 83 ec 30          	sub    $0x30,%rsp
    3702:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    3706:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    370d:	00 00 
    370f:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    3713:	31 c0                	xor    %eax,%eax
    thread_data_t *thread_data = get_thread_data();
    3715:	e8 53 8f 00 00       	callq  c66d <get_thread_data>
    371a:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    uintptr_t last_sp = thread_data->last_sp;
    371e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3722:	48 8b 40 08          	mov    0x8(%rax),%rax
    3726:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    ocall_context_t *context = reinterpret_cast<ocall_context_t*>(thread_data->last_sp);
    372a:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    372e:	48 8b 40 08          	mov    0x8(%rax),%rax
    3732:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    if(0 == last_sp || last_sp <= (uintptr_t)&context)
    3736:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    373b:	74 0a                	je     3747 <do_oret+0x4d>
    373d:	48 8d 45 e0          	lea    -0x20(%rbp),%rax
    3741:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    3745:	77 0a                	ja     3751 <do_oret+0x57>
    {
        return SGX_ERROR_UNEXPECTED;
    3747:	b8 01 00 00 00       	mov    $0x1,%eax
    374c:	e9 87 00 00 00       	jmpq   37d8 <do_oret+0xde>
    }
    // At least 1 ecall frame and 1 ocall frame are expected on stack. 
    // 30 is an estimated value: 8 for enclave_entry and 22 for do_ocall.
    if(last_sp > thread_data->stack_base_addr - 30 * sizeof(size_t))
    3751:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3755:	48 8b 40 10          	mov    0x10(%rax),%rax
    3759:	48 2d f0 00 00 00    	sub    $0xf0,%rax
    375f:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    3763:	76 07                	jbe    376c <do_oret+0x72>
    {
        return SGX_ERROR_UNEXPECTED;
    3765:	b8 01 00 00 00       	mov    $0x1,%eax
    376a:	eb 6c                	jmp    37d8 <do_oret+0xde>
    }
    if(context->ocall_flag != OCALL_FLAG)
    376c:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3770:	48 8b 40 20          	mov    0x20(%rax),%rax
    3774:	48 3d 44 49 43 4f    	cmp    $0x4f434944,%rax
    377a:	74 07                	je     3783 <do_oret+0x89>
    {
        return SGX_ERROR_UNEXPECTED;
    377c:	b8 01 00 00 00       	mov    $0x1,%eax
    3781:	eb 55                	jmp    37d8 <do_oret+0xde>
    }
    if(context->pre_last_sp > thread_data->stack_base_addr
    3783:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3787:	48 8b 50 30          	mov    0x30(%rax),%rdx
    378b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    378f:	48 8b 40 10          	mov    0x10(%rax),%rax
    3793:	48 39 c2             	cmp    %rax,%rdx
    3796:	77 11                	ja     37a9 <do_oret+0xaf>
       || context->pre_last_sp <= (uintptr_t)context)
    3798:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    379c:	48 8b 40 30          	mov    0x30(%rax),%rax
    37a0:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    37a4:	48 39 d0             	cmp    %rdx,%rax
    37a7:	77 07                	ja     37b0 <do_oret+0xb6>
    {
        return SGX_ERROR_UNEXPECTED;
    37a9:	b8 01 00 00 00       	mov    $0x1,%eax
    37ae:	eb 28                	jmp    37d8 <do_oret+0xde>
    }

    thread_data->last_sp = context->pre_last_sp;
    37b0:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    37b4:	48 8b 50 30          	mov    0x30(%rax),%rdx
    37b8:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    37bc:	48 89 50 08          	mov    %rdx,0x8(%rax)
    asm_oret(last_sp, ms);
    37c0:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    37c4:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    37c8:	48 89 d6             	mov    %rdx,%rsi
    37cb:	48 89 c7             	mov    %rax,%rdi
    37ce:	e8 dd 90 00 00       	callq  c8b0 <asm_oret>
    
    // Should not come here
    return SGX_ERROR_UNEXPECTED;
    37d3:	b8 01 00 00 00       	mov    $0x1,%eax
}
    37d8:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    37dc:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    37e3:	00 00 
    37e5:	74 05                	je     37ec <do_oret+0xf2>
    37e7:	e8 bc 1a 00 00       	callq  52a8 <__stack_chk_fail>
    37ec:	c9                   	leaveq 
    37ed:	c3                   	retq   

00000000000037ee <trim_range_ocall>:
typedef struct ms_trim_range_commit_ocall_t {
    size_t ms_addr;
} ms_trim_range_commit_ocall_t;

sgx_status_t SGXAPI trim_range_ocall(size_t fromaddr, size_t toaddr)
{
    37ee:	55                   	push   %rbp
    37ef:	48 89 e5             	mov    %rsp,%rbp
    37f2:	48 83 ec 30          	sub    $0x30,%rsp
    37f6:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    37fa:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    sgx_status_t status = SGX_SUCCESS;
    37fe:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%rbp)

    ms_trim_range_ocall_t* ms;
    OCALLOC(ms, ms_trim_range_ocall_t*, sizeof(*ms));
    3805:	bf 10 00 00 00       	mov    $0x10,%edi
    380a:	e8 e4 db ff ff       	callq  13f3 <sgx_ocalloc>
    380f:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    3813:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    3818:	75 0c                	jne    3826 <trim_range_ocall+0x38>
    381a:	e8 e5 dc ff ff       	callq  1504 <sgx_ocfree>
    381f:	b8 01 00 00 00       	mov    $0x1,%eax
    3824:	eb 3b                	jmp    3861 <trim_range_ocall+0x73>
    3826:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    382a:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

    ms->ms_fromaddr = fromaddr;
    382e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3832:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    3836:	48 89 10             	mov    %rdx,(%rax)
    ms->ms_toaddr = toaddr;
    3839:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    383d:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    3841:	48 89 50 08          	mov    %rdx,0x8(%rax)
    status = sgx_ocall(EDMM_TRIM, ms);
    3845:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3849:	48 89 c6             	mov    %rax,%rsi
    384c:	bf fe ff ff ff       	mov    $0xfffffffe,%edi
    3851:	e8 ba fd ff ff       	callq  3610 <sgx_ocall>
    3856:	89 45 ec             	mov    %eax,-0x14(%rbp)


    sgx_ocfree();
    3859:	e8 a6 dc ff ff       	callq  1504 <sgx_ocfree>
    return status;
    385e:	8b 45 ec             	mov    -0x14(%rbp),%eax
}
    3861:	c9                   	leaveq 
    3862:	c3                   	retq   

0000000000003863 <trim_range_commit_ocall>:

sgx_status_t SGXAPI trim_range_commit_ocall(size_t addr)
{
    3863:	55                   	push   %rbp
    3864:	48 89 e5             	mov    %rsp,%rbp
    3867:	48 83 ec 30          	sub    $0x30,%rsp
    386b:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    sgx_status_t status = SGX_SUCCESS;
    386f:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%rbp)

    ms_trim_range_commit_ocall_t* ms;
    OCALLOC(ms, ms_trim_range_commit_ocall_t*, sizeof(*ms));
    3876:	bf 08 00 00 00       	mov    $0x8,%edi
    387b:	e8 73 db ff ff       	callq  13f3 <sgx_ocalloc>
    3880:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    3884:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    3889:	75 0c                	jne    3897 <trim_range_commit_ocall+0x34>
    388b:	e8 74 dc ff ff       	callq  1504 <sgx_ocfree>
    3890:	b8 01 00 00 00       	mov    $0x1,%eax
    3895:	eb 2f                	jmp    38c6 <trim_range_commit_ocall+0x63>
    3897:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    389b:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

    ms->ms_addr = addr;
    389f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    38a3:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    38a7:	48 89 10             	mov    %rdx,(%rax)
    status = sgx_ocall(EDMM_TRIM_COMMIT, ms);
    38aa:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    38ae:	48 89 c6             	mov    %rax,%rsi
    38b1:	bf fd ff ff ff       	mov    $0xfffffffd,%edi
    38b6:	e8 55 fd ff ff       	callq  3610 <sgx_ocall>
    38bb:	89 45 ec             	mov    %eax,-0x14(%rbp)


    sgx_ocfree();
    38be:	e8 41 dc ff ff       	callq  1504 <sgx_ocfree>
    return status;
    38c3:	8b 45 ec             	mov    -0x14(%rbp),%eax
}
    38c6:	c9                   	leaveq 
    38c7:	c3                   	retq   

00000000000038c8 <get_heap_base>:
{
    return (size_t)get_enclave_base() + (size_t)g_global_data.enclave_size - 1;
}

void * get_heap_base(void)
{
    38c8:	55                   	push   %rbp
    38c9:	48 89 e5             	mov    %rsp,%rbp
    return GET_PTR(void, &__ImageBase, g_global_data.heap_offset);
    38cc:	48 8d 05 ad 98 00 00 	lea    0x98ad(%rip),%rax        # d180 <g_global_data>
    38d3:	48 8b 40 08          	mov    0x8(%rax),%rax
    38d7:	48 8d 15 22 c7 ff ff 	lea    -0x38de(%rip),%rdx        # 0 <enclave.so>
    38de:	48 01 d0             	add    %rdx,%rax
}
    38e1:	5d                   	pop    %rbp
    38e2:	c3                   	retq   

00000000000038e3 <get_heap_size>:

size_t get_heap_size(void)
{
    38e3:	55                   	push   %rbp
    38e4:	48 89 e5             	mov    %rsp,%rbp
    size_t heap_size = g_global_data.heap_size;
    38e7:	48 8d 05 92 98 00 00 	lea    0x9892(%rip),%rax        # d180 <g_global_data>
    38ee:	48 8b 40 10          	mov    0x10(%rax),%rax
    38f2:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if (EDMM_supported)
    38f6:	48 8d 05 03 d5 00 00 	lea    0xd503(%rip),%rax        # 10e00 <EDMM_supported>
    38fd:	8b 00                	mov    (%rax),%eax
    38ff:	85 c0                	test   %eax,%eax
    3901:	74 6c                	je     396f <get_heap_size+0x8c>
    {
        for(uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    3903:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    390a:	48 8d 05 6f 98 00 00 	lea    0x986f(%rip),%rax        # d180 <g_global_data>
    3911:	8b 80 28 01 00 00    	mov    0x128(%rax),%eax
    3917:	39 45 f4             	cmp    %eax,-0xc(%rbp)
    391a:	0f 92 c0             	setb   %al
    391d:	84 c0                	test   %al,%al
    391f:	74 4e                	je     396f <get_heap_size+0x8c>
        {
            if(g_global_data.layout_table[i].entry.id == LAYOUT_ID_HEAP_MAX)
    3921:	48 8d 05 58 98 00 00 	lea    0x9858(%rip),%rax        # d180 <g_global_data>
    3928:	8b 55 f4             	mov    -0xc(%rbp),%edx
    392b:	48 c1 e2 05          	shl    $0x5,%rdx
    392f:	48 01 d0             	add    %rdx,%rax
    3932:	48 05 30 01 00 00    	add    $0x130,%rax
    3938:	0f b7 00             	movzwl (%rax),%eax
    393b:	66 83 f8 03          	cmp    $0x3,%ax
    393f:	0f 94 c0             	sete   %al
    3942:	84 c0                	test   %al,%al
    3944:	74 23                	je     3969 <get_heap_size+0x86>
            {
                heap_size += ((size_t)g_global_data.layout_table[i].entry.page_count << SE_PAGE_SHIFT);
    3946:	48 8d 05 33 98 00 00 	lea    0x9833(%rip),%rax        # d180 <g_global_data>
    394d:	8b 55 f4             	mov    -0xc(%rbp),%edx
    3950:	48 c1 e2 05          	shl    $0x5,%rdx
    3954:	48 01 d0             	add    %rdx,%rax
    3957:	48 05 34 01 00 00    	add    $0x134,%rax
    395d:	8b 00                	mov    (%rax),%eax
    395f:	89 c0                	mov    %eax,%eax
    3961:	48 c1 e0 0c          	shl    $0xc,%rax
    3965:	48 01 45 f8          	add    %rax,-0x8(%rbp)
        for(uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    3969:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    396d:	eb 9b                	jmp    390a <get_heap_size+0x27>
            }
        }
    }
    return heap_size;
    396f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
}
    3973:	5d                   	pop    %rbp
    3974:	c3                   	retq   

0000000000003975 <get_heap_min_size>:

size_t get_heap_min_size(void)
{
    3975:	55                   	push   %rbp
    3976:	48 89 e5             	mov    %rsp,%rbp
    size_t heap_size = 0;
    3979:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    3980:	00 
    for(uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    3981:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    3988:	48 8d 05 f1 97 00 00 	lea    0x97f1(%rip),%rax        # d180 <g_global_data>
    398f:	8b 80 28 01 00 00    	mov    0x128(%rax),%eax
    3995:	39 45 f4             	cmp    %eax,-0xc(%rbp)
    3998:	0f 92 c0             	setb   %al
    399b:	84 c0                	test   %al,%al
    399d:	74 50                	je     39ef <get_heap_min_size+0x7a>
    {
        if(g_global_data.layout_table[i].entry.id == LAYOUT_ID_HEAP_MIN)
    399f:	48 8d 05 da 97 00 00 	lea    0x97da(%rip),%rax        # d180 <g_global_data>
    39a6:	8b 55 f4             	mov    -0xc(%rbp),%edx
    39a9:	48 c1 e2 05          	shl    $0x5,%rdx
    39ad:	48 01 d0             	add    %rdx,%rax
    39b0:	48 05 30 01 00 00    	add    $0x130,%rax
    39b6:	0f b7 00             	movzwl (%rax),%eax
    39b9:	66 83 f8 01          	cmp    $0x1,%ax
    39bd:	0f 94 c0             	sete   %al
    39c0:	84 c0                	test   %al,%al
    39c2:	74 25                	je     39e9 <get_heap_min_size+0x74>
        {
            heap_size = ((size_t)g_global_data.layout_table[i].entry.page_count << SE_PAGE_SHIFT);
    39c4:	48 8d 05 b5 97 00 00 	lea    0x97b5(%rip),%rax        # d180 <g_global_data>
    39cb:	8b 55 f4             	mov    -0xc(%rbp),%edx
    39ce:	48 c1 e2 05          	shl    $0x5,%rdx
    39d2:	48 01 d0             	add    %rdx,%rax
    39d5:	48 05 34 01 00 00    	add    $0x134,%rax
    39db:	8b 00                	mov    (%rax),%eax
    39dd:	89 c0                	mov    %eax,%eax
    39df:	48 c1 e0 0c          	shl    $0xc,%rax
    39e3:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
            break;
    39e7:	eb 06                	jmp    39ef <get_heap_min_size+0x7a>
    for(uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    39e9:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    39ed:	eb 99                	jmp    3988 <get_heap_min_size+0x13>
        }
    }
    return heap_size;
    39ef:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
}
    39f3:	5d                   	pop    %rbp
    39f4:	c3                   	retq   

00000000000039f5 <get_rsrv_base>:

void * get_rsrv_base(void)
{
    39f5:	55                   	push   %rbp
    39f6:	48 89 e5             	mov    %rsp,%rbp
    return GET_PTR(void, &__ImageBase, g_global_data.rsrv_offset);
    39f9:	48 8d 05 80 97 00 00 	lea    0x9780(%rip),%rax        # d180 <g_global_data>
    3a00:	48 8b 40 18          	mov    0x18(%rax),%rax
    3a04:	48 8d 15 f5 c5 ff ff 	lea    -0x3a0b(%rip),%rdx        # 0 <enclave.so>
    3a0b:	48 01 d0             	add    %rdx,%rax
}
    3a0e:	5d                   	pop    %rbp
    3a0f:	c3                   	retq   

0000000000003a10 <get_rsrv_size>:
{
    return (size_t)get_rsrv_base() + (size_t)get_rsrv_size() - 1;
}

size_t get_rsrv_size(void)
{
    3a10:	55                   	push   %rbp
    3a11:	48 89 e5             	mov    %rsp,%rbp
    size_t rsrv_size = g_global_data.rsrv_size;
    3a14:	48 8d 05 65 97 00 00 	lea    0x9765(%rip),%rax        # d180 <g_global_data>
    3a1b:	48 8b 40 20          	mov    0x20(%rax),%rax
    3a1f:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if (EDMM_supported)
    3a23:	48 8d 05 d6 d3 00 00 	lea    0xd3d6(%rip),%rax        # 10e00 <EDMM_supported>
    3a2a:	8b 00                	mov    (%rax),%eax
    3a2c:	85 c0                	test   %eax,%eax
    3a2e:	74 6c                	je     3a9c <get_rsrv_size+0x8c>
    {
        for (uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    3a30:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    3a37:	48 8d 05 42 97 00 00 	lea    0x9742(%rip),%rax        # d180 <g_global_data>
    3a3e:	8b 80 28 01 00 00    	mov    0x128(%rax),%eax
    3a44:	39 45 f4             	cmp    %eax,-0xc(%rbp)
    3a47:	0f 92 c0             	setb   %al
    3a4a:	84 c0                	test   %al,%al
    3a4c:	74 4e                	je     3a9c <get_rsrv_size+0x8c>
        {
            if (g_global_data.layout_table[i].entry.id == LAYOUT_ID_RSRV_MAX)
    3a4e:	48 8d 05 2b 97 00 00 	lea    0x972b(%rip),%rax        # d180 <g_global_data>
    3a55:	8b 55 f4             	mov    -0xc(%rbp),%edx
    3a58:	48 c1 e2 05          	shl    $0x5,%rdx
    3a5c:	48 01 d0             	add    %rdx,%rax
    3a5f:	48 05 30 01 00 00    	add    $0x130,%rax
    3a65:	0f b7 00             	movzwl (%rax),%eax
    3a68:	66 83 f8 16          	cmp    $0x16,%ax
    3a6c:	0f 94 c0             	sete   %al
    3a6f:	84 c0                	test   %al,%al
    3a71:	74 23                	je     3a96 <get_rsrv_size+0x86>
            {
                rsrv_size += ((size_t)g_global_data.layout_table[i].entry.page_count << SE_PAGE_SHIFT);
    3a73:	48 8d 05 06 97 00 00 	lea    0x9706(%rip),%rax        # d180 <g_global_data>
    3a7a:	8b 55 f4             	mov    -0xc(%rbp),%edx
    3a7d:	48 c1 e2 05          	shl    $0x5,%rdx
    3a81:	48 01 d0             	add    %rdx,%rax
    3a84:	48 05 34 01 00 00    	add    $0x134,%rax
    3a8a:	8b 00                	mov    (%rax),%eax
    3a8c:	89 c0                	mov    %eax,%eax
    3a8e:	48 c1 e0 0c          	shl    $0xc,%rax
    3a92:	48 01 45 f8          	add    %rax,-0x8(%rbp)
        for (uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    3a96:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    3a9a:	eb 9b                	jmp    3a37 <get_rsrv_size+0x27>
            }
        }
    }
    return rsrv_size;
    3a9c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
}
    3aa0:	5d                   	pop    %rbp
    3aa1:	c3                   	retq   

0000000000003aa2 <get_rsrv_min_size>:

size_t get_rsrv_min_size(void)
{
    3aa2:	55                   	push   %rbp
    3aa3:	48 89 e5             	mov    %rsp,%rbp
    size_t rsrv_size = 0;
    3aa6:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    3aad:	00 
    for (uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    3aae:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    3ab5:	48 8d 05 c4 96 00 00 	lea    0x96c4(%rip),%rax        # d180 <g_global_data>
    3abc:	8b 80 28 01 00 00    	mov    0x128(%rax),%eax
    3ac2:	39 45 f4             	cmp    %eax,-0xc(%rbp)
    3ac5:	0f 92 c0             	setb   %al
    3ac8:	84 c0                	test   %al,%al
    3aca:	74 50                	je     3b1c <get_rsrv_min_size+0x7a>
    {
        if (g_global_data.layout_table[i].entry.id == LAYOUT_ID_RSRV_MIN)
    3acc:	48 8d 05 ad 96 00 00 	lea    0x96ad(%rip),%rax        # d180 <g_global_data>
    3ad3:	8b 55 f4             	mov    -0xc(%rbp),%edx
    3ad6:	48 c1 e2 05          	shl    $0x5,%rdx
    3ada:	48 01 d0             	add    %rdx,%rax
    3add:	48 05 30 01 00 00    	add    $0x130,%rax
    3ae3:	0f b7 00             	movzwl (%rax),%eax
    3ae6:	66 83 f8 14          	cmp    $0x14,%ax
    3aea:	0f 94 c0             	sete   %al
    3aed:	84 c0                	test   %al,%al
    3aef:	74 25                	je     3b16 <get_rsrv_min_size+0x74>
        {
            rsrv_size = ((size_t)g_global_data.layout_table[i].entry.page_count << SE_PAGE_SHIFT);
    3af1:	48 8d 05 88 96 00 00 	lea    0x9688(%rip),%rax        # d180 <g_global_data>
    3af8:	8b 55 f4             	mov    -0xc(%rbp),%edx
    3afb:	48 c1 e2 05          	shl    $0x5,%rdx
    3aff:	48 01 d0             	add    %rdx,%rax
    3b02:	48 05 34 01 00 00    	add    $0x134,%rax
    3b08:	8b 00                	mov    (%rax),%eax
    3b0a:	89 c0                	mov    %eax,%eax
    3b0c:	48 c1 e0 0c          	shl    $0xc,%rax
    3b10:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
            break;
    3b14:	eb 06                	jmp    3b1c <get_rsrv_min_size+0x7a>
    for (uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    3b16:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    3b1a:	eb 99                	jmp    3ab5 <get_rsrv_min_size+0x13>
        }
    }
    return rsrv_size;
    3b1c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
}
    3b20:	5d                   	pop    %rbp
    3b21:	c3                   	retq   

0000000000003b22 <get_errno_addr>:

int * get_errno_addr(void)
{
    3b22:	55                   	push   %rbp
    3b23:	48 89 e5             	mov    %rsp,%rbp
    3b26:	48 83 ec 10          	sub    $0x10,%rsp
    thread_data_t *thread_data = get_thread_data();
    3b2a:	e8 3e 8b 00 00       	callq  c66d <get_thread_data>
    3b2f:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    return reinterpret_cast<int *>(&thread_data->last_error);
    3b33:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3b37:	48 83 c0 40          	add    $0x40,%rax
}
    3b3b:	c9                   	leaveq 
    3b3c:	c3                   	retq   

0000000000003b3d <feature_supported>:
//Features listed in array[0], counting from right-most bit  to left-most bit,
//have feature shift values 0 ~ 62, while features listed in array[1], have feature
//shift values 64 ~ 126.

int feature_supported(const uint64_t *feature_set, uint32_t feature_shift)
{
    3b3d:	55                   	push   %rbp
    3b3e:	48 89 e5             	mov    %rsp,%rbp
    3b41:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    3b45:	89 75 e4             	mov    %esi,-0x1c(%rbp)
    const uint64_t *f_set = feature_set;
    3b48:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3b4c:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    uint32_t bit_position = 0, i = 0;
    3b50:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    3b57:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%rbp)

    if (!f_set)
    3b5e:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    3b63:	75 07                	jne    3b6c <feature_supported+0x2f>
        return 0;
    3b65:	b8 00 00 00 00       	mov    $0x0,%eax
    3b6a:	eb 79                	jmp    3be5 <feature_supported+0xa8>

    while (((i+1) << 6) <= feature_shift)
    3b6c:	8b 45 f0             	mov    -0x10(%rbp),%eax
    3b6f:	83 c0 01             	add    $0x1,%eax
    3b72:	c1 e0 06             	shl    $0x6,%eax
    3b75:	39 45 e4             	cmp    %eax,-0x1c(%rbp)
    3b78:	72 27                	jb     3ba1 <feature_supported+0x64>
    {
        if (f_set[i] & (0x1ULL << 63))
    3b7a:	8b 45 f0             	mov    -0x10(%rbp),%eax
    3b7d:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3b84:	00 
    3b85:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3b89:	48 01 d0             	add    %rdx,%rax
    3b8c:	48 8b 00             	mov    (%rax),%rax
    3b8f:	48 85 c0             	test   %rax,%rax
    3b92:	79 07                	jns    3b9b <feature_supported+0x5e>
            return 0;
    3b94:	b8 00 00 00 00       	mov    $0x0,%eax
    3b99:	eb 4a                	jmp    3be5 <feature_supported+0xa8>
        i++;
    3b9b:	83 45 f0 01          	addl   $0x1,-0x10(%rbp)
    while (((i+1) << 6) <= feature_shift)
    3b9f:	eb cb                	jmp    3b6c <feature_supported+0x2f>
    }
    bit_position = feature_shift - (i << 6);
    3ba1:	8b 45 f0             	mov    -0x10(%rbp),%eax
    3ba4:	c1 e0 06             	shl    $0x6,%eax
    3ba7:	89 c2                	mov    %eax,%edx
    3ba9:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    3bac:	29 d0                	sub    %edx,%eax
    3bae:	89 45 f4             	mov    %eax,-0xc(%rbp)
    if (f_set[i] & (0x1ULL << bit_position))
    3bb1:	8b 45 f0             	mov    -0x10(%rbp),%eax
    3bb4:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3bbb:	00 
    3bbc:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3bc0:	48 01 d0             	add    %rdx,%rax
    3bc3:	48 8b 10             	mov    (%rax),%rdx
    3bc6:	8b 45 f4             	mov    -0xc(%rbp),%eax
    3bc9:	89 c1                	mov    %eax,%ecx
    3bcb:	48 d3 ea             	shr    %cl,%rdx
    3bce:	48 89 d0             	mov    %rdx,%rax
    3bd1:	83 e0 01             	and    $0x1,%eax
    3bd4:	48 85 c0             	test   %rax,%rax
    3bd7:	74 07                	je     3be0 <feature_supported+0xa3>
        return 1;
    3bd9:	b8 01 00 00 00       	mov    $0x1,%eax
    3bde:	eb 05                	jmp    3be5 <feature_supported+0xa8>
    else
        return 0;
    3be0:	b8 00 00 00 00       	mov    $0x0,%eax
}
    3be5:	5d                   	pop    %rbp
    3be6:	c3                   	retq   

0000000000003be7 <is_stack_addr>:

bool is_stack_addr(void *address, size_t size)
{
    3be7:	55                   	push   %rbp
    3be8:	48 89 e5             	mov    %rsp,%rbp
    3beb:	48 83 ec 30          	sub    $0x30,%rsp
    3bef:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    3bf3:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    thread_data_t *thread_data = get_thread_data();
    3bf7:	e8 71 8a 00 00       	callq  c66d <get_thread_data>
    3bfc:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    size_t stack_base = thread_data->stack_base_addr;
    3c00:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3c04:	48 8b 40 10          	mov    0x10(%rax),%rax
    3c08:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    size_t stack_limit  = thread_data->stack_limit_addr;
    3c0c:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3c10:	48 8b 40 18          	mov    0x18(%rax),%rax
    3c14:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    size_t addr = (size_t) address;
    3c18:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3c1c:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    return (addr <= (addr + size)) && (stack_base >= (addr + size)) && (stack_limit <= addr);
    3c20:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    3c24:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    3c28:	48 01 d0             	add    %rdx,%rax
    3c2b:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    3c2f:	77 22                	ja     3c53 <is_stack_addr+0x6c>
    3c31:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    3c35:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    3c39:	48 01 d0             	add    %rdx,%rax
    3c3c:	48 39 45 e8          	cmp    %rax,-0x18(%rbp)
    3c40:	72 11                	jb     3c53 <is_stack_addr+0x6c>
    3c42:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    3c46:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    3c4a:	77 07                	ja     3c53 <is_stack_addr+0x6c>
    3c4c:	b8 01 00 00 00       	mov    $0x1,%eax
    3c51:	eb 05                	jmp    3c58 <is_stack_addr+0x71>
    3c53:	b8 00 00 00 00       	mov    $0x0,%eax
}
    3c58:	c9                   	leaveq 
    3c59:	c3                   	retq   

0000000000003c5a <is_valid_sp>:

bool is_valid_sp(uintptr_t sp)
{
    3c5a:	55                   	push   %rbp
    3c5b:	48 89 e5             	mov    %rsp,%rbp
    3c5e:	48 83 ec 10          	sub    $0x10,%rsp
    3c62:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    return ( !(sp & (sizeof(uintptr_t) - 1))   // sp is expected to be 4/8 bytes aligned
    3c66:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3c6a:	83 e0 07             	and    $0x7,%eax
           && is_stack_addr((void*)sp, 0) );   // sp points to the top/bottom of stack are accepted
    3c6d:	48 85 c0             	test   %rax,%rax
    3c70:	75 1c                	jne    3c8e <is_valid_sp+0x34>
    3c72:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3c76:	be 00 00 00 00       	mov    $0x0,%esi
    3c7b:	48 89 c7             	mov    %rax,%rdi
    3c7e:	e8 64 ff ff ff       	callq  3be7 <is_stack_addr>
    3c83:	84 c0                	test   %al,%al
    3c85:	74 07                	je     3c8e <is_valid_sp+0x34>
    3c87:	b8 01 00 00 00       	mov    $0x1,%eax
    3c8c:	eb 05                	jmp    3c93 <is_valid_sp+0x39>
    3c8e:	b8 00 00 00 00       	mov    $0x0,%eax
}
    3c93:	c9                   	leaveq 
    3c94:	c3                   	retq   

0000000000003c95 <is_utility_thread>:


bool is_utility_thread()
{
    3c95:	55                   	push   %rbp
    3c96:	48 89 e5             	mov    %rsp,%rbp
    3c99:	48 83 ec 10          	sub    $0x10,%rsp
    thread_data_t *thread_data = get_thread_data();
    3c9d:	e8 cb 89 00 00       	callq  c66d <get_thread_data>
    3ca2:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if ((thread_data != NULL) && (thread_data->flags & SGX_UTILITY_THREAD))
    3ca6:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    3cab:	74 17                	je     3cc4 <is_utility_thread+0x2f>
    3cad:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3cb1:	48 8b 40 30          	mov    0x30(%rax),%rax
    3cb5:	83 e0 01             	and    $0x1,%eax
    3cb8:	48 85 c0             	test   %rax,%rax
    3cbb:	74 07                	je     3cc4 <is_utility_thread+0x2f>
    {
        return true;
    3cbd:	b8 01 00 00 00       	mov    $0x1,%eax
    3cc2:	eb 05                	jmp    3cc9 <is_utility_thread+0x34>
    }
    return false;
    3cc4:	b8 00 00 00 00       	mov    $0x0,%eax
}
    3cc9:	c9                   	leaveq 
    3cca:	c3                   	retq   

0000000000003ccb <internal_handle_exception>:
// internal_handle_exception(sgx_exception_info_t *info):
//      the 2nd phrase exception handing, which traverse registered exception handlers.
//      if the exception can be handled, then continue execution
//      otherwise, throw abortion, go back to 1st phrase, and call the default handler.
extern "C" __attribute__((regparm(1))) void internal_handle_exception(sgx_exception_info_t *info)
{
    3ccb:	55                   	push   %rbp
    3ccc:	48 89 e5             	mov    %rsp,%rbp
    3ccf:	48 83 ec 50          	sub    $0x50,%rsp
    3cd3:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    int status = EXCEPTION_CONTINUE_SEARCH;
    3cd7:	c7 45 c4 00 00 00 00 	movl   $0x0,-0x3c(%rbp)
    handler_node_t *node = NULL;
    3cde:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    3ce5:	00 
    thread_data_t *thread_data = get_thread_data();
    3ce6:	e8 82 89 00 00       	callq  c66d <get_thread_data>
    3ceb:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    size_t size = 0;
    3cef:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    3cf6:	00 
    uintptr_t *nhead = NULL;
    3cf7:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    3cfe:	00 
    uintptr_t *ntmp = NULL;
    3cff:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    3d06:	00 
    uintptr_t xsp = 0;
    3d07:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
    3d0e:	00 

    if (thread_data->exception_flag < 0)
    3d0f:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3d13:	48 8b 40 60          	mov    0x60(%rax),%rax
    3d17:	48 85 c0             	test   %rax,%rax
    3d1a:	0f 88 8c 01 00 00    	js     3eac <internal_handle_exception+0x1e1>
        goto failed_end;
    thread_data->exception_flag++;
    3d20:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3d24:	48 8b 40 60          	mov    0x60(%rax),%rax
    3d28:	48 8d 50 01          	lea    0x1(%rax),%rdx
    3d2c:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3d30:	48 89 50 60          	mov    %rdx,0x60(%rax)

    // read lock
    sgx_spin_lock(&g_handler_lock);
    3d34:	48 8d 3d a5 d3 00 00 	lea    0xd3a5(%rip),%rdi        # 110e0 <_ZL14g_handler_lock>
    3d3b:	e8 8d 76 00 00       	callq  b3cd <sgx_spin_lock>

    node = g_first_node;
    3d40:	48 8b 05 91 d3 00 00 	mov    0xd391(%rip),%rax        # 110d8 <_ZL12g_first_node>
    3d47:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    while(node != NULL)
    3d4b:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    3d50:	74 13                	je     3d65 <internal_handle_exception+0x9a>
    {
        size += sizeof(uintptr_t);
    3d52:	48 83 45 d0 08       	addq   $0x8,-0x30(%rbp)
        node = node->next;
    3d57:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3d5b:	48 8b 40 08          	mov    0x8(%rax),%rax
    3d5f:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    while(node != NULL)
    3d63:	eb e6                	jmp    3d4b <internal_handle_exception+0x80>
    }

    // There's no exception handler registered
    if (size == 0)
    3d65:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    3d6a:	75 24                	jne    3d90 <internal_handle_exception+0xc5>
    {
        sgx_spin_unlock(&g_handler_lock);
    3d6c:	48 8d 3d 6d d3 00 00 	lea    0xd36d(%rip),%rdi        # 110e0 <_ZL14g_handler_lock>
    3d73:	e8 bc 76 00 00       	callq  b434 <sgx_spin_unlock>

        //exception cannot be handled
        thread_data->exception_flag = -1;
    3d78:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3d7c:	48 c7 40 60 ff ff ff 	movq   $0xffffffffffffffff,0x60(%rax)
    3d83:	ff 

        //instruction triggering the exception will be executed again.
        continue_execution(info);
    3d84:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3d88:	48 89 c7             	mov    %rax,%rdi
    3d8b:	e8 1b 8c 00 00       	callq  c9ab <continue_execution>
    }

    if ((nhead = (uintptr_t *)malloc(size)) == NULL)
    3d90:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    3d94:	48 89 c7             	mov    %rax,%rdi
    3d97:	e8 da 4f 00 00       	callq  8d76 <dlmalloc>
    3d9c:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    3da0:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    3da5:	0f 94 c0             	sete   %al
    3da8:	84 c0                	test   %al,%al
    3daa:	74 11                	je     3dbd <internal_handle_exception+0xf2>
    {
        sgx_spin_unlock(&g_handler_lock);
    3dac:	48 8d 3d 2d d3 00 00 	lea    0xd32d(%rip),%rdi        # 110e0 <_ZL14g_handler_lock>
    3db3:	e8 7c 76 00 00       	callq  b434 <sgx_spin_unlock>
        goto failed_end;
    3db8:	e9 f3 00 00 00       	jmpq   3eb0 <internal_handle_exception+0x1e5>
    }
    ntmp = nhead;
    3dbd:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3dc1:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    node = g_first_node;
    3dc5:	48 8b 05 0c d3 00 00 	mov    0xd30c(%rip),%rax        # 110d8 <_ZL12g_first_node>
    3dcc:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    while(node != NULL)
    3dd0:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    3dd5:	74 21                	je     3df8 <internal_handle_exception+0x12d>
    {
        *ntmp = node->callback;
    3dd7:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3ddb:	48 8b 10             	mov    (%rax),%rdx
    3dde:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3de2:	48 89 10             	mov    %rdx,(%rax)
        ntmp++;
    3de5:	48 83 45 d8 08       	addq   $0x8,-0x28(%rbp)
        node = node->next;
    3dea:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3dee:	48 8b 40 08          	mov    0x8(%rax),%rax
    3df2:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    while(node != NULL)
    3df6:	eb d8                	jmp    3dd0 <internal_handle_exception+0x105>
    }

    // read unlock
    sgx_spin_unlock(&g_handler_lock);
    3df8:	48 8d 3d e1 d2 00 00 	lea    0xd2e1(%rip),%rdi        # 110e0 <_ZL14g_handler_lock>
    3dff:	e8 30 76 00 00       	callq  b434 <sgx_spin_unlock>

    // call exception handler until EXCEPTION_CONTINUE_EXECUTION is returned
    ntmp = nhead;
    3e04:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3e08:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    while(size > 0)
    3e0c:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    3e11:	74 38                	je     3e4b <internal_handle_exception+0x180>
    {
        sgx_exception_handler_t handler = DEC_VEH_POINTER(*ntmp);
    3e13:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3e17:	48 8b 10             	mov    (%rax),%rdx
    3e1a:	48 8b 05 c7 d2 00 00 	mov    0xd2c7(%rip),%rax        # 110e8 <_ZL12g_veh_cookie>
    3e21:	48 31 d0             	xor    %rdx,%rax
    3e24:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
        status = handler(info);
    3e28:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
    3e2c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3e30:	48 89 d7             	mov    %rdx,%rdi
    3e33:	ff d0                	callq  *%rax
    3e35:	89 45 c4             	mov    %eax,-0x3c(%rbp)
        if(EXCEPTION_CONTINUE_EXECUTION == status)
    3e38:	83 7d c4 ff          	cmpl   $0xffffffff,-0x3c(%rbp)
    3e3c:	74 0c                	je     3e4a <internal_handle_exception+0x17f>
        {
            break;
        }
        ntmp++;
    3e3e:	48 83 45 d8 08       	addq   $0x8,-0x28(%rbp)
        size -= sizeof(sgx_exception_handler_t);
    3e43:	48 83 6d d0 08       	subq   $0x8,-0x30(%rbp)
    while(size > 0)
    3e48:	eb c2                	jmp    3e0c <internal_handle_exception+0x141>
            break;
    3e4a:	90                   	nop
    }
    free(nhead);
    3e4b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3e4f:	48 89 c7             	mov    %rax,%rdi
    3e52:	e8 16 5a 00 00       	callq  986d <dlfree>

    // call default handler
    // ignore invalid return value, treat to EXCEPTION_CONTINUE_SEARCH
    // check SP to be written on SSA is pointing to the trusted stack
    xsp = info->cpu_context.REG(sp);
    3e57:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3e5b:	48 8b 40 20          	mov    0x20(%rax),%rax
    3e5f:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    if (!is_valid_sp(xsp))
    3e63:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    3e67:	48 89 c7             	mov    %rax,%rdi
    3e6a:	e8 eb fd ff ff       	callq  3c5a <is_valid_sp>
    3e6f:	83 f0 01             	xor    $0x1,%eax
    3e72:	84 c0                	test   %al,%al
    3e74:	75 39                	jne    3eaf <internal_handle_exception+0x1e4>
    {
        goto failed_end;
    }

    if(EXCEPTION_CONTINUE_EXECUTION == status)
    3e76:	83 7d c4 ff          	cmpl   $0xffffffff,-0x3c(%rbp)
    3e7a:	75 16                	jne    3e92 <internal_handle_exception+0x1c7>
    {
        //exception is handled, decrease the nested exception count
        thread_data->exception_flag--;
    3e7c:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3e80:	48 8b 40 60          	mov    0x60(%rax),%rax
    3e84:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    3e88:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3e8c:	48 89 50 60          	mov    %rdx,0x60(%rax)
    3e90:	eb 0c                	jmp    3e9e <internal_handle_exception+0x1d3>
    }
    else
    {
        //exception cannot be handled
        thread_data->exception_flag = -1;
    3e92:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3e96:	48 c7 40 60 ff ff ff 	movq   $0xffffffffffffffff,0x60(%rax)
    3e9d:	ff 
    }

    //instruction triggering the exception will be executed again.
    continue_execution(info);
    3e9e:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3ea2:	48 89 c7             	mov    %rax,%rdi
    3ea5:	e8 01 8b 00 00       	callq  c9ab <continue_execution>
    3eaa:	eb 04                	jmp    3eb0 <internal_handle_exception+0x1e5>
        goto failed_end;
    3eac:	90                   	nop
    3ead:	eb 01                	jmp    3eb0 <internal_handle_exception+0x1e5>
        goto failed_end;
    3eaf:	90                   	nop

failed_end:
    thread_data->exception_flag = -1; // mark the current exception cannot be handled
    3eb0:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3eb4:	48 c7 40 60 ff ff ff 	movq   $0xffffffffffffffff,0x60(%rax)
    3ebb:	ff 
    abort();    // throw abortion
    3ebc:	e8 db 8a 00 00       	callq  c99c <abort>

0000000000003ec1 <_ZL21expand_stack_by_pagesPvm>:
}

static int expand_stack_by_pages(void *start_addr, size_t page_count)
{
    3ec1:	55                   	push   %rbp
    3ec2:	48 89 e5             	mov    %rsp,%rbp
    3ec5:	48 83 ec 20          	sub    $0x20,%rsp
    3ec9:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    3ecd:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    int ret = -1;
    3ed1:	c7 45 fc ff ff ff ff 	movl   $0xffffffff,-0x4(%rbp)

    if ((start_addr == NULL) || (page_count == 0))
    3ed8:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    3edd:	74 07                	je     3ee6 <_ZL21expand_stack_by_pagesPvm+0x25>
    3edf:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
    3ee4:	75 07                	jne    3eed <_ZL21expand_stack_by_pagesPvm+0x2c>
        return -1;
    3ee6:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    3eeb:	eb 19                	jmp    3f06 <_ZL21expand_stack_by_pagesPvm+0x45>

    ret = apply_pages_within_exception(start_addr, page_count);
    3eed:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    3ef1:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3ef5:	48 89 d6             	mov    %rdx,%rsi
    3ef8:	48 89 c7             	mov    %rax,%rdi
    3efb:	e8 7c e2 ff ff       	callq  217c <apply_pages_within_exception>
    3f00:	89 45 fc             	mov    %eax,-0x4(%rbp)
    return ret;
    3f03:	8b 45 fc             	mov    -0x4(%rbp),%eax
}
    3f06:	c9                   	leaveq 
    3f07:	c3                   	retq   

0000000000003f08 <trts_handle_exception>:
//      the pointer of TCS
// Return Value
//      none zero - success
//              0 - fail
extern "C" sgx_status_t trts_handle_exception(void *tcs)
{
    3f08:	55                   	push   %rbp
    3f09:	48 89 e5             	mov    %rsp,%rbp
    3f0c:	48 83 ec 50          	sub    $0x50,%rsp
    3f10:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    thread_data_t *thread_data = get_thread_data();
    3f14:	e8 54 87 00 00       	callq  c66d <get_thread_data>
    3f19:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    ssa_gpr_t *ssa_gpr = NULL;
    3f1d:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    3f24:	00 
    sgx_exception_info_t *info = NULL;
    3f25:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    3f2c:	00 
    uintptr_t sp, *new_sp = NULL;
    3f2d:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    3f34:	00 
    size_t size = 0;
    3f35:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    3f3c:	00 

    if ((thread_data == NULL) || (tcs == NULL)) goto default_handler;
    3f3d:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    3f42:	0f 84 86 04 00 00    	je     43ce <trts_handle_exception+0x4c6>
    3f48:	48 83 7d b8 00       	cmpq   $0x0,-0x48(%rbp)
    3f4d:	0f 84 7b 04 00 00    	je     43ce <trts_handle_exception+0x4c6>
    if (check_static_stack_canary(tcs) != 0)
    3f53:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3f57:	48 89 c7             	mov    %rax,%rdi
    3f5a:	e8 53 d7 ff ff       	callq  16b2 <check_static_stack_canary>
    3f5f:	85 c0                	test   %eax,%eax
    3f61:	0f 95 c0             	setne  %al
    3f64:	84 c0                	test   %al,%al
    3f66:	0f 85 65 04 00 00    	jne    43d1 <trts_handle_exception+0x4c9>
        goto default_handler;
 
    if(get_enclave_state() != ENCLAVE_INIT_DONE)
    3f6c:	e8 c9 86 00 00       	callq  c63a <get_enclave_state>
    3f71:	83 f8 02             	cmp    $0x2,%eax
    3f74:	0f 95 c0             	setne  %al
    3f77:	84 c0                	test   %al,%al
    3f79:	0f 85 55 04 00 00    	jne    43d4 <trts_handle_exception+0x4cc>
    {
        goto default_handler;
    }
    
    // check if the exception is raised from 2nd phrase
    if(thread_data->exception_flag == -1) {
    3f7f:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3f83:	48 8b 40 60          	mov    0x60(%rax),%rax
    3f87:	48 83 f8 ff          	cmp    $0xffffffffffffffff,%rax
    3f8b:	0f 84 46 04 00 00    	je     43d7 <trts_handle_exception+0x4cf>
        goto default_handler;
    }
 
    if ((TD2TCS(thread_data) != tcs) 
    3f91:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3f95:	48 8b 40 10          	mov    0x10(%rax),%rax
    3f99:	48 05 b0 02 01 00    	add    $0x102b0,%rax
    3f9f:	48 39 45 b8          	cmp    %rax,-0x48(%rbp)
    3fa3:	0f 85 25 04 00 00    	jne    43ce <trts_handle_exception+0x4c6>
            || (((thread_data->first_ssa_gpr)&(~0xfff)) - SE_PAGE_SIZE) != (uintptr_t)tcs) {
    3fa9:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3fad:	48 8b 40 20          	mov    0x20(%rax),%rax
    3fb1:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    3fb7:	48 8d 90 00 f0 ff ff 	lea    -0x1000(%rax),%rdx
    3fbe:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3fc2:	48 39 c2             	cmp    %rax,%rdx
    3fc5:	0f 85 03 04 00 00    	jne    43ce <trts_handle_exception+0x4c6>
        goto default_handler;
    }

    // no need to check the result of ssa_gpr because thread_data is always trusted
    ssa_gpr = reinterpret_cast<ssa_gpr_t *>(thread_data->first_ssa_gpr);
    3fcb:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3fcf:	48 8b 40 20          	mov    0x20(%rax),%rax
    3fd3:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    
    sp = ssa_gpr->REG(sp);
    3fd7:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    3fdb:	48 8b 40 20          	mov    0x20(%rax),%rax
    3fdf:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    if(!is_stack_addr((void*)sp, 0))  // check stack overrun only, alignment will be checked after exception handled
    3fe3:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    3fe7:	be 00 00 00 00       	mov    $0x0,%esi
    3fec:	48 89 c7             	mov    %rax,%rdi
    3fef:	e8 f3 fb ff ff       	callq  3be7 <is_stack_addr>
    3ff4:	83 f0 01             	xor    $0x1,%eax
    3ff7:	84 c0                	test   %al,%al
    3ff9:	74 17                	je     4012 <trts_handle_exception+0x10a>
    {
        g_enclave_state = ENCLAVE_CRASHED;
    3ffb:	48 8d 05 9e d0 00 00 	lea    0xd09e(%rip),%rax        # 110a0 <g_enclave_state>
    4002:	c7 00 03 00 00 00    	movl   $0x3,(%rax)
        return SGX_ERROR_STACK_OVERRUN;
    4008:	b8 09 10 00 00       	mov    $0x1009,%eax
    400d:	e9 db 03 00 00       	jmpq   43ed <trts_handle_exception+0x4e5>
    }

    size = 0;
    4012:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    4019:	00 
    // x86_64 requires a 128-bytes red zone, which begins directly
    // after the return addr and includes func's arguments
    size += RED_ZONE_SIZE;
    401a:	48 83 6d e8 80       	subq   $0xffffffffffffff80,-0x18(%rbp)

    // decrease the stack to give space for info
    size += sizeof(sgx_exception_info_t);
    401f:	48 81 45 e8 98 00 00 	addq   $0x98,-0x18(%rbp)
    4026:	00 
    sp -= size;
    4027:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    402b:	48 29 45 f0          	sub    %rax,-0x10(%rbp)
    sp = sp & ~0xF;
    402f:	48 83 65 f0 f0       	andq   $0xfffffffffffffff0,-0x10(%rbp)

    // check the decreased sp to make sure it is in the trusted stack range
    if(!is_stack_addr((void *)sp, size))
    4034:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4038:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    403c:	48 89 d6             	mov    %rdx,%rsi
    403f:	48 89 c7             	mov    %rax,%rdi
    4042:	e8 a0 fb ff ff       	callq  3be7 <is_stack_addr>
    4047:	83 f0 01             	xor    $0x1,%eax
    404a:	84 c0                	test   %al,%al
    404c:	74 17                	je     4065 <trts_handle_exception+0x15d>
    {
        g_enclave_state = ENCLAVE_CRASHED;
    404e:	48 8d 05 4b d0 00 00 	lea    0xd04b(%rip),%rax        # 110a0 <g_enclave_state>
    4055:	c7 00 03 00 00 00    	movl   $0x3,(%rax)
        return SGX_ERROR_STACK_OVERRUN;
    405b:	b8 09 10 00 00       	mov    $0x1009,%eax
    4060:	e9 88 03 00 00       	jmpq   43ed <trts_handle_exception+0x4e5>
    }

    info = (sgx_exception_info_t *)sp;
    4065:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4069:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    // decrease the stack to save the SSA[0]->ip
    size = sizeof(uintptr_t);
    406d:	48 c7 45 e8 08 00 00 	movq   $0x8,-0x18(%rbp)
    4074:	00 
    sp -= size;
    4075:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4079:	48 29 45 f0          	sub    %rax,-0x10(%rbp)
    if(!is_stack_addr((void *)sp, size))
    407d:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4081:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    4085:	48 89 d6             	mov    %rdx,%rsi
    4088:	48 89 c7             	mov    %rax,%rdi
    408b:	e8 57 fb ff ff       	callq  3be7 <is_stack_addr>
    4090:	83 f0 01             	xor    $0x1,%eax
    4093:	84 c0                	test   %al,%al
    4095:	74 17                	je     40ae <trts_handle_exception+0x1a6>
    {
        g_enclave_state = ENCLAVE_CRASHED;
    4097:	48 8d 05 02 d0 00 00 	lea    0xd002(%rip),%rax        # 110a0 <g_enclave_state>
    409e:	c7 00 03 00 00 00    	movl   $0x3,(%rax)
        return SGX_ERROR_STACK_OVERRUN;
    40a4:	b8 09 10 00 00       	mov    $0x1009,%eax
    40a9:	e9 3f 03 00 00       	jmpq   43ed <trts_handle_exception+0x4e5>
    }
    
    // sp is within limit_addr and commit_addr, currently only SGX 2.0 under hardware mode will enter this branch.^M
    if((size_t)sp < thread_data->stack_commit_addr)
    40ae:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    40b2:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    40b9:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    40bd:	0f 83 ca 00 00 00    	jae    418d <trts_handle_exception+0x285>
    { 
        int ret = -1;
    40c3:	c7 45 c4 ff ff ff ff 	movl   $0xffffffff,-0x3c(%rbp)
        size_t page_aligned_delta = 0;
    40ca:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    40d1:	00 
        /* try to allocate memory dynamically */
        page_aligned_delta = ROUND_TO(thread_data->stack_commit_addr - (size_t)sp, SE_PAGE_SIZE);
    40d2:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    40d6:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    40dd:	48 2b 45 f0          	sub    -0x10(%rbp),%rax
    40e1:	48 05 ff 0f 00 00    	add    $0xfff,%rax
    40e7:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    40ed:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
        if ((thread_data->stack_commit_addr > page_aligned_delta)
    40f1:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    40f5:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    40fc:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    4100:	73 47                	jae    4149 <trts_handle_exception+0x241>
                && ((thread_data->stack_commit_addr - page_aligned_delta) >= thread_data->stack_limit_addr))
    4102:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4106:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    410d:	48 2b 45 f8          	sub    -0x8(%rbp),%rax
    4111:	48 89 c2             	mov    %rax,%rdx
    4114:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4118:	48 8b 40 18          	mov    0x18(%rax),%rax
    411c:	48 39 c2             	cmp    %rax,%rdx
    411f:	72 28                	jb     4149 <trts_handle_exception+0x241>
        {
            ret = expand_stack_by_pages((void *)(thread_data->stack_commit_addr - page_aligned_delta), (page_aligned_delta >> SE_PAGE_SHIFT));
    4121:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4125:	48 c1 e8 0c          	shr    $0xc,%rax
    4129:	48 89 c2             	mov    %rax,%rdx
    412c:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4130:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    4137:	48 2b 45 f8          	sub    -0x8(%rbp),%rax
    413b:	48 89 d6             	mov    %rdx,%rsi
    413e:	48 89 c7             	mov    %rax,%rdi
    4141:	e8 7b fd ff ff       	callq  3ec1 <_ZL21expand_stack_by_pagesPvm>
    4146:	89 45 c4             	mov    %eax,-0x3c(%rbp)
        }
        if (ret == 0)
    4149:	83 7d c4 00          	cmpl   $0x0,-0x3c(%rbp)
    414d:	75 27                	jne    4176 <trts_handle_exception+0x26e>
        {
            thread_data->stack_commit_addr -= page_aligned_delta;
    414f:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4153:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    415a:	48 2b 45 f8          	sub    -0x8(%rbp),%rax
    415e:	48 89 c2             	mov    %rax,%rdx
    4161:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4165:	48 89 90 98 00 00 00 	mov    %rdx,0x98(%rax)
            return SGX_SUCCESS;
    416c:	b8 00 00 00 00       	mov    $0x0,%eax
    4171:	e9 77 02 00 00       	jmpq   43ed <trts_handle_exception+0x4e5>
        }
        else
        {
            g_enclave_state = ENCLAVE_CRASHED;
    4176:	48 8d 05 23 cf 00 00 	lea    0xcf23(%rip),%rax        # 110a0 <g_enclave_state>
    417d:	c7 00 03 00 00 00    	movl   $0x3,(%rax)
            return SGX_ERROR_STACK_OVERRUN;
    4183:	b8 09 10 00 00       	mov    $0x1009,%eax
    4188:	e9 60 02 00 00       	jmpq   43ed <trts_handle_exception+0x4e5>
        }
    }
    if (size_t(&Lereport_inst) == ssa_gpr->REG(ip) && SE_EREPORT == ssa_gpr->REG(ax))
    418d:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4191:	48 8b 80 88 00 00 00 	mov    0x88(%rax),%rax
    4198:	48 8d 15 a5 87 00 00 	lea    0x87a5(%rip),%rdx        # c944 <Lereport_inst>
    419f:	48 39 d0             	cmp    %rdx,%rax
    41a2:	75 4d                	jne    41f1 <trts_handle_exception+0x2e9>
    41a4:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    41a8:	48 8b 00             	mov    (%rax),%rax
    41ab:	48 85 c0             	test   %rax,%rax
    41ae:	75 41                	jne    41f1 <trts_handle_exception+0x2e9>
    {
        // Handle the exception raised by EREPORT instruction
        ssa_gpr->REG(ip) += 3;     // Skip ENCLU, which is always a 3-byte instruction
    41b0:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    41b4:	48 8b 80 88 00 00 00 	mov    0x88(%rax),%rax
    41bb:	48 8d 50 03          	lea    0x3(%rax),%rdx
    41bf:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    41c3:	48 89 90 88 00 00 00 	mov    %rdx,0x88(%rax)
        ssa_gpr->REG(flags) |= 1;  // Set CF to indicate error condition, see implementation of do_report()
    41ca:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    41ce:	48 8b 80 80 00 00 00 	mov    0x80(%rax),%rax
    41d5:	48 83 c8 01          	or     $0x1,%rax
    41d9:	48 89 c2             	mov    %rax,%rdx
    41dc:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    41e0:	48 89 90 80 00 00 00 	mov    %rdx,0x80(%rax)
        return SGX_SUCCESS;
    41e7:	b8 00 00 00 00       	mov    $0x0,%eax
    41ec:	e9 fc 01 00 00       	jmpq   43ed <trts_handle_exception+0x4e5>
    }

    if(ssa_gpr->exit_info.valid != 1)
    41f1:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    41f5:	0f b6 80 a3 00 00 00 	movzbl 0xa3(%rax),%eax
    41fc:	83 e0 80             	and    $0xffffff80,%eax
    41ff:	84 c0                	test   %al,%al
    4201:	0f 84 d3 01 00 00    	je     43da <trts_handle_exception+0x4d2>
    {   // exception handlers are not allowed to call in a non-exception state
        goto default_handler;
    }

    // initialize the info with SSA[0]
    info->exception_vector = (sgx_exception_vector_t)ssa_gpr->exit_info.vector;
    4207:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    420b:	0f b6 80 a0 00 00 00 	movzbl 0xa0(%rax),%eax
    4212:	0f b6 d0             	movzbl %al,%edx
    4215:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4219:	89 90 90 00 00 00    	mov    %edx,0x90(%rax)
    info->exception_type = (sgx_exception_type_t)ssa_gpr->exit_info.exit_type;
    421f:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4223:	0f b6 80 a1 00 00 00 	movzbl 0xa1(%rax),%eax
    422a:	83 e0 07             	and    $0x7,%eax
    422d:	0f b6 d0             	movzbl %al,%edx
    4230:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4234:	89 90 94 00 00 00    	mov    %edx,0x94(%rax)

    info->cpu_context.REG(ax) = ssa_gpr->REG(ax);
    423a:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    423e:	48 8b 10             	mov    (%rax),%rdx
    4241:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4245:	48 89 10             	mov    %rdx,(%rax)
    info->cpu_context.REG(cx) = ssa_gpr->REG(cx);
    4248:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    424c:	48 8b 50 08          	mov    0x8(%rax),%rdx
    4250:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4254:	48 89 50 08          	mov    %rdx,0x8(%rax)
    info->cpu_context.REG(dx) = ssa_gpr->REG(dx);
    4258:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    425c:	48 8b 50 10          	mov    0x10(%rax),%rdx
    4260:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4264:	48 89 50 10          	mov    %rdx,0x10(%rax)
    info->cpu_context.REG(bx) = ssa_gpr->REG(bx);
    4268:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    426c:	48 8b 50 18          	mov    0x18(%rax),%rdx
    4270:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4274:	48 89 50 18          	mov    %rdx,0x18(%rax)
    info->cpu_context.REG(sp) = ssa_gpr->REG(sp);
    4278:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    427c:	48 8b 50 20          	mov    0x20(%rax),%rdx
    4280:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4284:	48 89 50 20          	mov    %rdx,0x20(%rax)
    info->cpu_context.REG(bp) = ssa_gpr->REG(bp);
    4288:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    428c:	48 8b 50 28          	mov    0x28(%rax),%rdx
    4290:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4294:	48 89 50 28          	mov    %rdx,0x28(%rax)
    info->cpu_context.REG(si) = ssa_gpr->REG(si);
    4298:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    429c:	48 8b 50 30          	mov    0x30(%rax),%rdx
    42a0:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    42a4:	48 89 50 30          	mov    %rdx,0x30(%rax)
    info->cpu_context.REG(di) = ssa_gpr->REG(di);
    42a8:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    42ac:	48 8b 50 38          	mov    0x38(%rax),%rdx
    42b0:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    42b4:	48 89 50 38          	mov    %rdx,0x38(%rax)
    info->cpu_context.REG(flags) = ssa_gpr->REG(flags);
    42b8:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    42bc:	48 8b 90 80 00 00 00 	mov    0x80(%rax),%rdx
    42c3:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    42c7:	48 89 90 80 00 00 00 	mov    %rdx,0x80(%rax)
    info->cpu_context.REG(ip) = ssa_gpr->REG(ip);
    42ce:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    42d2:	48 8b 90 88 00 00 00 	mov    0x88(%rax),%rdx
    42d9:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    42dd:	48 89 90 88 00 00 00 	mov    %rdx,0x88(%rax)
#ifdef SE_64
    info->cpu_context.r8  = ssa_gpr->r8;
    42e4:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    42e8:	48 8b 50 40          	mov    0x40(%rax),%rdx
    42ec:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    42f0:	48 89 50 40          	mov    %rdx,0x40(%rax)
    info->cpu_context.r9  = ssa_gpr->r9;
    42f4:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    42f8:	48 8b 50 48          	mov    0x48(%rax),%rdx
    42fc:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4300:	48 89 50 48          	mov    %rdx,0x48(%rax)
    info->cpu_context.r10 = ssa_gpr->r10;
    4304:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4308:	48 8b 50 50          	mov    0x50(%rax),%rdx
    430c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4310:	48 89 50 50          	mov    %rdx,0x50(%rax)
    info->cpu_context.r11 = ssa_gpr->r11;
    4314:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4318:	48 8b 50 58          	mov    0x58(%rax),%rdx
    431c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4320:	48 89 50 58          	mov    %rdx,0x58(%rax)
    info->cpu_context.r12 = ssa_gpr->r12;
    4324:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4328:	48 8b 50 60          	mov    0x60(%rax),%rdx
    432c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4330:	48 89 50 60          	mov    %rdx,0x60(%rax)
    info->cpu_context.r13 = ssa_gpr->r13;
    4334:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4338:	48 8b 50 68          	mov    0x68(%rax),%rdx
    433c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4340:	48 89 50 68          	mov    %rdx,0x68(%rax)
    info->cpu_context.r14 = ssa_gpr->r14;
    4344:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4348:	48 8b 50 70          	mov    0x70(%rax),%rdx
    434c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4350:	48 89 50 70          	mov    %rdx,0x70(%rax)
    info->cpu_context.r15 = ssa_gpr->r15;
    4354:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4358:	48 8b 50 78          	mov    0x78(%rax),%rdx
    435c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4360:	48 89 50 78          	mov    %rdx,0x78(%rax)
#endif

    new_sp = (uintptr_t *)sp;
    4364:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4368:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    ssa_gpr->REG(ip) = (size_t)internal_handle_exception; // prepare the ip for 2nd phrase handling
    436c:	48 8d 15 58 f9 ff ff 	lea    -0x6a8(%rip),%rdx        # 3ccb <internal_handle_exception>
    4373:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4377:	48 89 90 88 00 00 00 	mov    %rdx,0x88(%rax)
    ssa_gpr->REG(sp) = (size_t)new_sp;      // new stack for internal_handle_exception
    437e:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    4382:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4386:	48 89 50 20          	mov    %rdx,0x20(%rax)
    ssa_gpr->REG(ax) = (size_t)info;        // 1st parameter (info) for LINUX32
    438a:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    438e:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4392:	48 89 10             	mov    %rdx,(%rax)
    ssa_gpr->REG(di) = (size_t)info;        // 1st parameter (info) for LINUX64, LINUX32 also uses it while restoring the context
    4395:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    4399:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    439d:	48 89 50 38          	mov    %rdx,0x38(%rax)
    *new_sp = info->cpu_context.REG(ip);    // for debugger to get call trace
    43a1:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    43a5:	48 8b 90 88 00 00 00 	mov    0x88(%rax),%rdx
    43ac:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    43b0:	48 89 10             	mov    %rdx,(%rax)
    
    //mark valid to 0 to prevent eenter again
    ssa_gpr->exit_info.valid = 0;
    43b3:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    43b7:	0f b6 90 a3 00 00 00 	movzbl 0xa3(%rax),%edx
    43be:	83 e2 7f             	and    $0x7f,%edx
    43c1:	88 90 a3 00 00 00    	mov    %dl,0xa3(%rax)

    return SGX_SUCCESS;
    43c7:	b8 00 00 00 00       	mov    $0x0,%eax
    43cc:	eb 1f                	jmp    43ed <trts_handle_exception+0x4e5>
 
default_handler:
    43ce:	90                   	nop
    43cf:	eb 0a                	jmp    43db <trts_handle_exception+0x4d3>
        goto default_handler;
    43d1:	90                   	nop
    43d2:	eb 07                	jmp    43db <trts_handle_exception+0x4d3>
        goto default_handler;
    43d4:	90                   	nop
    43d5:	eb 04                	jmp    43db <trts_handle_exception+0x4d3>
        goto default_handler;
    43d7:	90                   	nop
    43d8:	eb 01                	jmp    43db <trts_handle_exception+0x4d3>
        goto default_handler;
    43da:	90                   	nop
    g_enclave_state = ENCLAVE_CRASHED;
    43db:	48 8d 05 be cc 00 00 	lea    0xccbe(%rip),%rax        # 110a0 <g_enclave_state>
    43e2:	c7 00 03 00 00 00    	movl   $0x3,(%rax)
    return SGX_ERROR_ENCLAVE_CRASHED;
    43e8:	b8 06 10 00 00       	mov    $0x1006,%eax
}
    43ed:	c9                   	leaveq 
    43ee:	c3                   	retq   

00000000000043ef <get_xfeature_state>:
#define SE_OPTIMIZE_OFF
#endif

SE_OPTIMIZE_OFF
uint64_t get_xfeature_state()
{
    43ef:	55                   	push   %rbp
    43f0:	48 89 e5             	mov    %rsp,%rbp
    43f3:	48 83 ec 10          	sub    $0x10,%rsp
    auto *report = sgx_self_report();
    43f7:	e8 83 77 00 00       	callq  bb7f <sgx_self_report>
    43fc:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    g_xsave_enabled = (report->body.attributes.xfrm == SGX_XFRM_LEGACY) ? 0 : 1;
    4400:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4404:	48 8b 40 38          	mov    0x38(%rax),%rax
    4408:	48 83 f8 03          	cmp    $0x3,%rax
    440c:	0f 95 c0             	setne  %al
    440f:	0f b6 c0             	movzbl %al,%eax
    4412:	89 05 8c cc 00 00    	mov    %eax,0xcc8c(%rip)        # 110a4 <g_xsave_enabled>
    uint64_t xfrm = report->body.attributes.xfrm;
    4418:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    441c:	48 8b 40 38          	mov    0x38(%rax),%rax
    4420:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
#endif

    // no secrets in target_info, report_data, and report. no need to clear them before return
    // tlibc functions cannot be used before calling init_optimized_libs().

    return xfrm;
    4424:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
}
    4428:	c9                   	leaveq 
    4429:	c3                   	retq   

000000000000442a <get_phdr>:

static int elf_tls_aligned_virtual_size(const void *enclave_base,
                            size_t *aligned_virtual_size);

static ElfW(Phdr)* get_phdr(const ElfW(Ehdr)* ehdr)
{
    442a:	55                   	push   %rbp
    442b:	48 89 e5             	mov    %rsp,%rbp
    442e:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    if (ehdr == NULL)
    4432:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    4437:	75 07                	jne    4440 <get_phdr+0x16>
        return NULL;  /* Invalid image. */
    4439:	b8 00 00 00 00       	mov    $0x0,%eax
    443e:	eb 5a                	jmp    449a <get_phdr+0x70>

    /* Check the ElfW Magic number. */
    if ((ehdr->e_ident[EI_MAG0] != ELFMAG0) ||
    4440:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4444:	0f b6 00             	movzbl (%rax),%eax
    4447:	3c 7f                	cmp    $0x7f,%al
    4449:	75 24                	jne    446f <get_phdr+0x45>
        (ehdr->e_ident[EI_MAG1] != ELFMAG1) ||
    444b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    444f:	0f b6 40 01          	movzbl 0x1(%rax),%eax
    if ((ehdr->e_ident[EI_MAG0] != ELFMAG0) ||
    4453:	3c 45                	cmp    $0x45,%al
    4455:	75 18                	jne    446f <get_phdr+0x45>
        (ehdr->e_ident[EI_MAG2] != ELFMAG2) ||
    4457:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    445b:	0f b6 40 02          	movzbl 0x2(%rax),%eax
        (ehdr->e_ident[EI_MAG1] != ELFMAG1) ||
    445f:	3c 4c                	cmp    $0x4c,%al
    4461:	75 0c                	jne    446f <get_phdr+0x45>
        (ehdr->e_ident[EI_MAG3] != ELFMAG3))
    4463:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4467:	0f b6 40 03          	movzbl 0x3(%rax),%eax
        (ehdr->e_ident[EI_MAG2] != ELFMAG2) ||
    446b:	3c 46                	cmp    $0x46,%al
    446d:	74 07                	je     4476 <get_phdr+0x4c>
        return NULL;
    446f:	b8 00 00 00 00       	mov    $0x0,%eax
    4474:	eb 24                	jmp    449a <get_phdr+0x70>

    /* Enclave image should be a shared object file. */
    if (ehdr->e_type != ET_DYN)
    4476:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    447a:	0f b7 40 10          	movzwl 0x10(%rax),%eax
    447e:	66 83 f8 03          	cmp    $0x3,%ax
    4482:	74 07                	je     448b <get_phdr+0x61>
        return NULL;
    4484:	b8 00 00 00 00       	mov    $0x0,%eax
    4489:	eb 0f                	jmp    449a <get_phdr+0x70>

    return GET_PTR(ElfW(Phdr), ehdr, ehdr->e_phoff);
    448b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    448f:	48 8b 50 20          	mov    0x20(%rax),%rdx
    4493:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4497:	48 01 d0             	add    %rdx,%rax
}
    449a:	5d                   	pop    %rbp
    449b:	c3                   	retq   

000000000000449c <get_sym>:

static ElfW(Sym)* get_sym(ElfW(Sym)* symtab, size_t idx)
{
    449c:	55                   	push   %rbp
    449d:	48 89 e5             	mov    %rsp,%rbp
    44a0:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    44a4:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    if(STB_WEAK == ELFW(ST_BIND)(symtab[idx].st_info)
    44a8:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    44ac:	48 89 d0             	mov    %rdx,%rax
    44af:	48 01 c0             	add    %rax,%rax
    44b2:	48 01 d0             	add    %rdx,%rax
    44b5:	48 c1 e0 03          	shl    $0x3,%rax
    44b9:	48 89 c2             	mov    %rax,%rdx
    44bc:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    44c0:	48 01 d0             	add    %rdx,%rax
    44c3:	0f b6 40 04          	movzbl 0x4(%rax),%eax
    44c7:	c0 e8 04             	shr    $0x4,%al
    44ca:	3c 02                	cmp    $0x2,%al
    44cc:	75 2b                	jne    44f9 <get_sym+0x5d>
            && 0 == symtab[idx].st_value)
    44ce:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    44d2:	48 89 d0             	mov    %rdx,%rax
    44d5:	48 01 c0             	add    %rax,%rax
    44d8:	48 01 d0             	add    %rdx,%rax
    44db:	48 c1 e0 03          	shl    $0x3,%rax
    44df:	48 89 c2             	mov    %rax,%rdx
    44e2:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    44e6:	48 01 d0             	add    %rdx,%rax
    44e9:	48 8b 40 08          	mov    0x8(%rax),%rax
    44ed:	48 85 c0             	test   %rax,%rax
    44f0:	75 07                	jne    44f9 <get_sym+0x5d>
    {
        return NULL;
    44f2:	b8 00 00 00 00       	mov    $0x0,%eax
    44f7:	eb 1b                	jmp    4514 <get_sym+0x78>
    }

    return &symtab[idx];
    44f9:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    44fd:	48 89 d0             	mov    %rdx,%rax
    4500:	48 01 c0             	add    %rax,%rax
    4503:	48 01 d0             	add    %rdx,%rax
    4506:	48 c1 e0 03          	shl    $0x3,%rax
    450a:	48 89 c2             	mov    %rax,%rdx
    450d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4511:	48 01 d0             	add    %rdx,%rax
}
    4514:	5d                   	pop    %rbp
    4515:	c3                   	retq   

0000000000004516 <do_relocs>:
/* Relocation for x64 (with addend) */
static int do_relocs(const ElfW(Addr) enclave_base,
        ElfW(Addr) rela_offset,
        ElfW(Addr) sym_offset,
        size_t nr_relocs)
{
    4516:	55                   	push   %rbp
    4517:	48 89 e5             	mov    %rsp,%rbp
    451a:	48 83 ec 60          	sub    $0x60,%rsp
    451e:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    4522:	48 89 75 b0          	mov    %rsi,-0x50(%rbp)
    4526:	48 89 55 a8          	mov    %rdx,-0x58(%rbp)
    452a:	48 89 4d a0          	mov    %rcx,-0x60(%rbp)
    452e:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    4535:	00 00 
    4537:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    453b:	31 c0                	xor    %eax,%eax
    ElfW(Rela)* rela = GET_PTR(ElfW(Rela), enclave_base, rela_offset);
    453d:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
    4541:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    4545:	48 01 d0             	add    %rdx,%rax
    4548:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    ElfW(Sym)*  symtab = GET_PTR(ElfW(Sym), enclave_base, sym_offset);
    454c:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
    4550:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4554:	48 01 d0             	add    %rdx,%rax
    4557:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    ElfW(Sym)*  sym;
    size_t      i;
    size_t aligned_virtual_size = 0;
    455b:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    4562:	00 

    for (i = 0; i < nr_relocs; ++i, ++rela)
    4563:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    456a:	00 
    456b:	e9 a2 01 00 00       	jmpq   4712 <do_relocs+0x1fc>
    {
        ElfW(Addr)* reloc_addr = GET_PTR(ElfW(Addr), enclave_base, rela->r_offset);
    4570:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4574:	48 8b 10             	mov    (%rax),%rdx
    4577:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    457b:	48 01 d0             	add    %rdx,%rax
    457e:	48 89 45 e8          	mov    %rax,-0x18(%rbp)

        switch (ELF64_R_TYPE(rela->r_info))
    4582:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4586:	48 8b 40 08          	mov    0x8(%rax),%rax
    458a:	89 c0                	mov    %eax,%eax
    458c:	48 83 f8 12          	cmp    $0x12,%rax
    4590:	0f 87 61 01 00 00    	ja     46f7 <do_relocs+0x1e1>
    4596:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
    459d:	00 
    459e:	48 8d 05 cf 8a 00 00 	lea    0x8acf(%rip),%rax        # d074 <_ZZL16init_stack_guardPvE8__func__+0x14>
    45a5:	8b 04 02             	mov    (%rdx,%rax,1),%eax
    45a8:	48 63 d0             	movslq %eax,%rdx
    45ab:	48 8d 05 c2 8a 00 00 	lea    0x8ac2(%rip),%rax        # d074 <_ZZL16init_stack_guardPvE8__func__+0x14>
    45b2:	48 01 d0             	add    %rdx,%rax
    45b5:	ff e0                	jmpq   *%rax
        {
            case R_X86_64_RELATIVE:
                *reloc_addr = enclave_base + (uintptr_t)rela->r_addend;
    45b7:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    45bb:	48 8b 40 10          	mov    0x10(%rax),%rax
    45bf:	48 89 c2             	mov    %rax,%rdx
    45c2:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    45c6:	48 01 c2             	add    %rax,%rdx
    45c9:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    45cd:	48 89 10             	mov    %rdx,(%rax)
                break;
    45d0:	e9 33 01 00 00       	jmpq   4708 <do_relocs+0x1f2>

            case R_X86_64_GLOB_DAT:
            case R_X86_64_JUMP_SLOT:
            case R_X86_64_64:
                sym = get_sym(symtab, ELF64_R_SYM(rela->r_info));
    45d5:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    45d9:	48 8b 40 08          	mov    0x8(%rax),%rax
    45dd:	48 c1 e8 20          	shr    $0x20,%rax
    45e1:	48 89 c2             	mov    %rax,%rdx
    45e4:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    45e8:	48 89 d6             	mov    %rdx,%rsi
    45eb:	48 89 c7             	mov    %rax,%rdi
    45ee:	e8 a9 fe ff ff       	callq  449c <get_sym>
    45f3:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
                if(!sym)
    45f7:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    45fc:	0f 84 ff 00 00 00    	je     4701 <do_relocs+0x1eb>
                    break;
                *reloc_addr = enclave_base + sym->st_value + (uintptr_t)rela->r_addend;
    4602:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4606:	48 8b 50 08          	mov    0x8(%rax),%rdx
    460a:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    460e:	48 01 c2             	add    %rax,%rdx
    4611:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4615:	48 8b 40 10          	mov    0x10(%rax),%rax
    4619:	48 01 c2             	add    %rax,%rdx
    461c:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4620:	48 89 10             	mov    %rdx,(%rax)
                break;
    4623:	e9 e0 00 00 00       	jmpq   4708 <do_relocs+0x1f2>

            case R_X86_64_DTPMOD64:
                *reloc_addr = 1;
    4628:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    462c:	48 c7 00 01 00 00 00 	movq   $0x1,(%rax)
                break;
    4633:	e9 d0 00 00 00       	jmpq   4708 <do_relocs+0x1f2>
 
            case R_X86_64_DTPOFF64:
                sym = get_sym(symtab, ELF64_R_SYM(rela->r_info));
    4638:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    463c:	48 8b 40 08          	mov    0x8(%rax),%rax
    4640:	48 c1 e8 20          	shr    $0x20,%rax
    4644:	48 89 c2             	mov    %rax,%rdx
    4647:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    464b:	48 89 d6             	mov    %rdx,%rsi
    464e:	48 89 c7             	mov    %rax,%rdi
    4651:	e8 46 fe ff ff       	callq  449c <get_sym>
    4656:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
                if(!sym)
    465a:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    465f:	0f 84 9f 00 00 00    	je     4704 <do_relocs+0x1ee>
                    break;
                *reloc_addr = sym->st_value + (uintptr_t)rela->r_addend;
    4665:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4669:	48 8b 50 08          	mov    0x8(%rax),%rdx
    466d:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4671:	48 8b 40 10          	mov    0x10(%rax),%rax
    4675:	48 01 c2             	add    %rax,%rdx
    4678:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    467c:	48 89 10             	mov    %rdx,(%rax)
                break;
    467f:	e9 84 00 00 00       	jmpq   4708 <do_relocs+0x1f2>

            case R_X86_64_TPOFF64:
                sym = get_sym(symtab, ELF64_R_SYM(rela->r_info));
    4684:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4688:	48 8b 40 08          	mov    0x8(%rax),%rax
    468c:	48 c1 e8 20          	shr    $0x20,%rax
    4690:	48 89 c2             	mov    %rax,%rdx
    4693:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    4697:	48 89 d6             	mov    %rdx,%rsi
    469a:	48 89 c7             	mov    %rax,%rdi
    469d:	e8 fa fd ff ff       	callq  449c <get_sym>
    46a2:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
                if(!sym)
    46a6:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    46ab:	74 5a                	je     4707 <do_relocs+0x1f1>
                    break;

                if ((0 == elf_tls_aligned_virtual_size((void *)enclave_base, &aligned_virtual_size)) && (aligned_virtual_size))
    46ad:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    46b1:	48 8d 55 c8          	lea    -0x38(%rbp),%rdx
    46b5:	48 89 d6             	mov    %rdx,%rsi
    46b8:	48 89 c7             	mov    %rax,%rdi
    46bb:	e8 4f 03 00 00       	callq  4a0f <elf_tls_aligned_virtual_size>
    46c0:	85 c0                	test   %eax,%eax
    46c2:	75 2c                	jne    46f0 <do_relocs+0x1da>
    46c4:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    46c8:	48 85 c0             	test   %rax,%rax
    46cb:	74 23                	je     46f0 <do_relocs+0x1da>
                {
                    *reloc_addr = sym->st_value + (uintptr_t)rela->r_addend - aligned_virtual_size;
    46cd:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    46d1:	48 8b 50 08          	mov    0x8(%rax),%rdx
    46d5:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    46d9:	48 8b 40 10          	mov    0x10(%rax),%rax
    46dd:	48 01 c2             	add    %rax,%rdx
    46e0:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    46e4:	48 29 c2             	sub    %rax,%rdx
    46e7:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    46eb:	48 89 10             	mov    %rdx,(%rax)
                    break;
    46ee:	eb 18                	jmp    4708 <do_relocs+0x1f2>
                }
                else
                    return -1;
    46f0:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    46f5:	eb 2e                	jmp    4725 <do_relocs+0x20f>

            case R_X86_64_NONE:
                break;

            default:    /* unsupported relocs */
                return -1;
    46f7:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    46fc:	eb 27                	jmp    4725 <do_relocs+0x20f>
                break;
    46fe:	90                   	nop
    46ff:	eb 07                	jmp    4708 <do_relocs+0x1f2>
                    break;
    4701:	90                   	nop
    4702:	eb 04                	jmp    4708 <do_relocs+0x1f2>
                    break;
    4704:	90                   	nop
    4705:	eb 01                	jmp    4708 <do_relocs+0x1f2>
                    break;
    4707:	90                   	nop
    for (i = 0; i < nr_relocs; ++i, ++rela)
    4708:	48 83 45 d8 01       	addq   $0x1,-0x28(%rbp)
    470d:	48 83 45 d0 18       	addq   $0x18,-0x30(%rbp)
    4712:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4716:	48 3b 45 a0          	cmp    -0x60(%rbp),%rax
    471a:	0f 82 50 fe ff ff    	jb     4570 <do_relocs+0x5a>
        }
    }

    return 0;
    4720:	b8 00 00 00 00       	mov    $0x0,%eax
}
    4725:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    4729:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    4730:	00 00 
    4732:	74 05                	je     4739 <do_relocs+0x223>
    4734:	e8 6f 0b 00 00       	callq  52a8 <__stack_chk_fail>
    4739:	c9                   	leaveq 
    473a:	c3                   	retq   

000000000000473b <relocate_enclave>:
 * it local symbol, so the code is like "fce3:	e8 98 12 00 00    call   10f80 <relocate_enclave>"
 * 0x9812=0x10f80-0xfce8
 */
__attribute__ ((visibility ("hidden")))
int relocate_enclave(void* enclave_base)
{
    473b:	55                   	push   %rbp
    473c:	48 89 e5             	mov    %rsp,%rbp
    473f:	48 83 c4 80          	add    $0xffffffffffffff80,%rsp
    4743:	48 89 7d 88          	mov    %rdi,-0x78(%rbp)
    ElfW(Half) phnum = 0;
    4747:	c7 45 94 00 00 00 00 	movl   $0x0,-0x6c(%rbp)
    ElfW(Ehdr) *ehdr = (ElfW(Ehdr)*)enclave_base;
    474e:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    4752:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    ElfW(Phdr) *phdr = get_phdr(ehdr);
    4756:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    475a:	48 89 c7             	mov    %rax,%rdi
    475d:	e8 c8 fc ff ff       	callq  442a <get_phdr>
    4762:	48 89 45 98          	mov    %rax,-0x68(%rbp)

    if (phdr == NULL)
    4766:	48 83 7d 98 00       	cmpq   $0x0,-0x68(%rbp)
    476b:	0f 85 c3 01 00 00    	jne    4934 <relocate_enclave+0x1f9>
        return -1;  /* Invalid image. */
    4771:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4776:	e9 d2 01 00 00       	jmpq   494d <relocate_enclave+0x212>

    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    {
        /* Search for dynamic segment */
        if (phdr->p_type == PT_DYNAMIC)
    477b:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    477f:	8b 00                	mov    (%rax),%eax
    4781:	83 f8 02             	cmp    $0x2,%eax
    4784:	0f 85 a1 01 00 00    	jne    492b <relocate_enclave+0x1f0>
        {
            size_t      count;
            size_t      n_dyn = phdr->p_filesz/sizeof(ElfW(Dyn));
    478a:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    478e:	48 8b 40 20          	mov    0x20(%rax),%rax
    4792:	48 c1 e8 04          	shr    $0x4,%rax
    4796:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
            ElfW(Dyn)   *dyn = GET_PTR(ElfW(Dyn), ehdr, phdr->p_paddr);
    479a:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    479e:	48 8b 50 18          	mov    0x18(%rax),%rdx
    47a2:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    47a6:	48 01 d0             	add    %rdx,%rax
    47a9:	48 89 45 a8          	mov    %rax,-0x58(%rbp)

            ElfW(Addr)   sym_offset = 0;
    47ad:	48 c7 45 b0 00 00 00 	movq   $0x0,-0x50(%rbp)
    47b4:	00 
            ElfW(Addr)   rel_offset = 0;
    47b5:	48 c7 45 b8 00 00 00 	movq   $0x0,-0x48(%rbp)
    47bc:	00 
            ElfW(Addr)   plt_offset = 0;
    47bd:	48 c7 45 c0 00 00 00 	movq   $0x0,-0x40(%rbp)
    47c4:	00 

            size_t   rel_total_sz = 0;
    47c5:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    47cc:	00 
            size_t   rel_entry_sz = 0;
    47cd:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    47d4:	00 
            size_t   plt_total_sz = 0;
    47d5:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    47dc:	00 

            for (count = 0; count < n_dyn; count++, dyn++)
    47dd:	48 c7 45 a0 00 00 00 	movq   $0x0,-0x60(%rbp)
    47e4:	00 
    47e5:	e9 9b 00 00 00       	jmpq   4885 <relocate_enclave+0x14a>
            {
                if (dyn->d_tag == DT_NULL)  /* End */
    47ea:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    47ee:	48 8b 00             	mov    (%rax),%rax
    47f1:	48 85 c0             	test   %rax,%rax
    47f4:	0f 84 9b 00 00 00    	je     4895 <relocate_enclave+0x15a>
                    break;

                switch (dyn->d_tag)
    47fa:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    47fe:	48 8b 00             	mov    (%rax),%rax
    4801:	48 83 f8 17          	cmp    $0x17,%rax
    4805:	77 74                	ja     487b <relocate_enclave+0x140>
    4807:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
    480e:	00 
    480f:	48 8d 05 aa 88 00 00 	lea    0x88aa(%rip),%rax        # d0c0 <_ZZL16init_stack_guardPvE8__func__+0x60>
    4816:	8b 04 02             	mov    (%rdx,%rax,1),%eax
    4819:	48 63 d0             	movslq %eax,%rdx
    481c:	48 8d 05 9d 88 00 00 	lea    0x889d(%rip),%rax        # d0c0 <_ZZL16init_stack_guardPvE8__func__+0x60>
    4823:	48 01 d0             	add    %rdx,%rax
    4826:	ff e0                	jmpq   *%rax
                {
                    case DT_SYMTAB: /* symbol table */
                        sym_offset = dyn->d_un.d_ptr;
    4828:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    482c:	48 8b 40 08          	mov    0x8(%rax),%rax
    4830:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
                        break;
    4834:	eb 45                	jmp    487b <relocate_enclave+0x140>

                    case RTS_DT_REL:/* Rel (x86) or Rela (x64) relocs */
                        rel_offset = dyn->d_un.d_ptr;
    4836:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    483a:	48 8b 40 08          	mov    0x8(%rax),%rax
    483e:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
                        break;
    4842:	eb 37                	jmp    487b <relocate_enclave+0x140>

                    case RTS_DT_RELSZ:
                        rel_total_sz = dyn->d_un.d_val;
    4844:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4848:	48 8b 40 08          	mov    0x8(%rax),%rax
    484c:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
                        break;
    4850:	eb 29                	jmp    487b <relocate_enclave+0x140>

                    case RTS_DT_RELENT:
                        rel_entry_sz = dyn->d_un.d_val;
    4852:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4856:	48 8b 40 08          	mov    0x8(%rax),%rax
    485a:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
                        break;
    485e:	eb 1b                	jmp    487b <relocate_enclave+0x140>

                    case DT_JMPREL: /* PLT relocs */
                        plt_offset = dyn->d_un.d_ptr;
    4860:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4864:	48 8b 40 08          	mov    0x8(%rax),%rax
    4868:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
                        break;
    486c:	eb 0d                	jmp    487b <relocate_enclave+0x140>

                    case DT_PLTRELSZ:
                        plt_total_sz = dyn->d_un.d_val;
    486e:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4872:	48 8b 40 08          	mov    0x8(%rax),%rax
    4876:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
                        break;
    487a:	90                   	nop
            for (count = 0; count < n_dyn; count++, dyn++)
    487b:	48 83 45 a0 01       	addq   $0x1,-0x60(%rbp)
    4880:	48 83 45 a8 10       	addq   $0x10,-0x58(%rbp)
    4885:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    4889:	48 3b 45 e8          	cmp    -0x18(%rbp),%rax
    488d:	0f 82 57 ff ff ff    	jb     47ea <relocate_enclave+0xaf>
    4893:	eb 01                	jmp    4896 <relocate_enclave+0x15b>
                    break;
    4895:	90                   	nop
                }
            }

            DO_REL(enclave_base, rel_offset, sym_offset, rel_total_sz, rel_entry_sz);
    4896:	48 83 7d b8 00       	cmpq   $0x0,-0x48(%rbp)
    489b:	74 45                	je     48e2 <relocate_enclave+0x1a7>
    489d:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    48a2:	75 0a                	jne    48ae <relocate_enclave+0x173>
    48a4:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    48a9:	e9 9f 00 00 00       	jmpq   494d <relocate_enclave+0x212>
    48ae:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    48b2:	ba 00 00 00 00       	mov    $0x0,%edx
    48b7:	48 f7 75 d0          	divq   -0x30(%rbp)
    48bb:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    48bf:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    48c3:	48 8b 4d f0          	mov    -0x10(%rbp),%rcx
    48c7:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    48cb:	48 8b 75 b8          	mov    -0x48(%rbp),%rsi
    48cf:	48 89 c7             	mov    %rax,%rdi
    48d2:	e8 3f fc ff ff       	callq  4516 <do_relocs>
    48d7:	85 c0                	test   %eax,%eax
    48d9:	74 07                	je     48e2 <relocate_enclave+0x1a7>
    48db:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    48e0:	eb 6b                	jmp    494d <relocate_enclave+0x212>
            DO_REL(enclave_base, plt_offset, sym_offset, plt_total_sz, rel_entry_sz);
    48e2:	48 83 7d c0 00       	cmpq   $0x0,-0x40(%rbp)
    48e7:	74 42                	je     492b <relocate_enclave+0x1f0>
    48e9:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    48ee:	75 07                	jne    48f7 <relocate_enclave+0x1bc>
    48f0:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    48f5:	eb 56                	jmp    494d <relocate_enclave+0x212>
    48f7:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    48fb:	ba 00 00 00 00       	mov    $0x0,%edx
    4900:	48 f7 75 d0          	divq   -0x30(%rbp)
    4904:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    4908:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    490c:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    4910:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    4914:	48 8b 75 c0          	mov    -0x40(%rbp),%rsi
    4918:	48 89 c7             	mov    %rax,%rdi
    491b:	e8 f6 fb ff ff       	callq  4516 <do_relocs>
    4920:	85 c0                	test   %eax,%eax
    4922:	74 07                	je     492b <relocate_enclave+0x1f0>
    4924:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4929:	eb 22                	jmp    494d <relocate_enclave+0x212>
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    492b:	83 45 94 01          	addl   $0x1,-0x6c(%rbp)
    492f:	48 83 45 98 38       	addq   $0x38,-0x68(%rbp)
    4934:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    4938:	0f b7 40 38          	movzwl 0x38(%rax),%eax
    493c:	0f b7 c0             	movzwl %ax,%eax
    493f:	39 45 94             	cmp    %eax,-0x6c(%rbp)
    4942:	0f 82 33 fe ff ff    	jb     477b <relocate_enclave+0x40>
        }
    }

    return 0;
    4948:	b8 00 00 00 00       	mov    $0x0,%eax
}
    494d:	c9                   	leaveq 
    494e:	c3                   	retq   

000000000000494f <elf_tls_info>:

int elf_tls_info(const void* enclave_base,
        uintptr_t *tls_addr, size_t *tdata_size)
{
    494f:	55                   	push   %rbp
    4950:	48 89 e5             	mov    %rsp,%rbp
    4953:	48 83 ec 38          	sub    $0x38,%rsp
    4957:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    495b:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    495f:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
    ElfW(Half) phnum = 0;
    4963:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%rbp)
    const ElfW(Ehdr) *ehdr = (const ElfW(Ehdr)*)enclave_base;
    496a:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    496e:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    ElfW(Phdr) *phdr = get_phdr(ehdr);
    4972:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4976:	48 89 c7             	mov    %rax,%rdi
    4979:	e8 ac fa ff ff       	callq  442a <get_phdr>
    497e:	48 89 45 f0          	mov    %rax,-0x10(%rbp)

    if (!tls_addr || !tdata_size)
    4982:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    4987:	74 07                	je     4990 <elf_tls_info+0x41>
    4989:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    498e:	75 07                	jne    4997 <elf_tls_info+0x48>
        return -1;
    4990:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4995:	eb 76                	jmp    4a0d <elf_tls_info+0xbe>

    if (phdr == NULL)
    4997:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    499c:	75 07                	jne    49a5 <elf_tls_info+0x56>
        return -1;  /* Invalid image. */
    499e:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    49a3:	eb 68                	jmp    4a0d <elf_tls_info+0xbe>

    /* Search for TLS segment */
    *tls_addr = 0;
    49a5:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    49a9:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    *tdata_size = 0;
    49b0:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    49b4:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    49bb:	eb 3b                	jmp    49f8 <elf_tls_info+0xa9>
    {
        if (phdr->p_type == PT_TLS)
    49bd:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    49c1:	8b 00                	mov    (%rax),%eax
    49c3:	83 f8 07             	cmp    $0x7,%eax
    49c6:	75 27                	jne    49ef <elf_tls_info+0xa0>
        {
            /* tls_addr here is got from the program header, the address
             * need to be added by the enclave base.
             */
            *tls_addr = (size_t)enclave_base + phdr->p_vaddr;
    49c8:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    49cc:	48 8b 50 10          	mov    0x10(%rax),%rdx
    49d0:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    49d4:	48 01 c2             	add    %rax,%rdx
    49d7:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    49db:	48 89 10             	mov    %rdx,(%rax)
            *tdata_size = phdr->p_filesz;
    49de:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    49e2:	48 8b 50 20          	mov    0x20(%rax),%rdx
    49e6:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    49ea:	48 89 10             	mov    %rdx,(%rax)
            break;
    49ed:	eb 19                	jmp    4a08 <elf_tls_info+0xb9>
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    49ef:	83 45 ec 01          	addl   $0x1,-0x14(%rbp)
    49f3:	48 83 45 f0 38       	addq   $0x38,-0x10(%rbp)
    49f8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    49fc:	0f b7 40 38          	movzwl 0x38(%rax),%eax
    4a00:	0f b7 c0             	movzwl %ax,%eax
    4a03:	39 45 ec             	cmp    %eax,-0x14(%rbp)
    4a06:	72 b5                	jb     49bd <elf_tls_info+0x6e>
        }
    }

    return 0;
    4a08:	b8 00 00 00 00       	mov    $0x0,%eax
}
    4a0d:	c9                   	leaveq 
    4a0e:	c3                   	retq   

0000000000004a0f <elf_tls_aligned_virtual_size>:

static int elf_tls_aligned_virtual_size(const void *enclave_base,
                                        size_t *aligned_virtual_size)
{
    4a0f:	55                   	push   %rbp
    4a10:	48 89 e5             	mov    %rsp,%rbp
    4a13:	48 83 ec 40          	sub    $0x40,%rsp
    4a17:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    4a1b:	48 89 75 c0          	mov    %rsi,-0x40(%rbp)
    ElfW(Half) phnum = 0;
    4a1f:	c7 45 dc 00 00 00 00 	movl   $0x0,-0x24(%rbp)
    const ElfW(Ehdr) *ehdr = (const ElfW(Ehdr)*)enclave_base;
    4a26:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4a2a:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    ElfW(Phdr) *phdr = get_phdr(ehdr);
    4a2e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4a32:	48 89 c7             	mov    %rax,%rdi
    4a35:	e8 f0 f9 ff ff       	callq  442a <get_phdr>
    4a3a:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    size_t virtual_size =0, align = 0;
    4a3e:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
    4a45:	00 
    4a46:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    4a4d:	00 

    if (phdr == NULL)
    4a4e:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
    4a53:	75 0a                	jne    4a5f <elf_tls_aligned_virtual_size+0x50>
        return -1;
    4a55:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4a5a:	e9 9c 00 00 00       	jmpq   4afb <elf_tls_aligned_virtual_size+0xec>

    if (!aligned_virtual_size)
    4a5f:	48 83 7d c0 00       	cmpq   $0x0,-0x40(%rbp)
    4a64:	75 0a                	jne    4a70 <elf_tls_aligned_virtual_size+0x61>
        return -1;
    4a66:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4a6b:	e9 8b 00 00 00       	jmpq   4afb <elf_tls_aligned_virtual_size+0xec>

    *aligned_virtual_size = 0;
    4a70:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    4a74:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4a7b:	eb 69                	jmp    4ae6 <elf_tls_aligned_virtual_size+0xd7>
    {
        if (phdr->p_type == PT_TLS)
    4a7d:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    4a81:	8b 00                	mov    (%rax),%eax
    4a83:	83 f8 07             	cmp    $0x7,%eax
    4a86:	75 55                	jne    4add <elf_tls_aligned_virtual_size+0xce>
        {
            virtual_size = phdr->p_memsz;
    4a88:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    4a8c:	48 8b 40 28          	mov    0x28(%rax),%rax
    4a90:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
            align = phdr->p_align;
    4a94:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    4a98:	48 8b 40 30          	mov    0x30(%rax),%rax
    4a9c:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

            /* p_align == 0 or p_align == 1 means no alignment is required */
            if (align == 0 || align == 1)
    4aa0:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    4aa5:	74 07                	je     4aae <elf_tls_aligned_virtual_size+0x9f>
    4aa7:	48 83 7d f8 01       	cmpq   $0x1,-0x8(%rbp)
    4aac:	75 0d                	jne    4abb <elf_tls_aligned_virtual_size+0xac>
                *aligned_virtual_size = virtual_size;
    4aae:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    4ab2:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    4ab6:	48 89 10             	mov    %rdx,(%rax)
            else
                *aligned_virtual_size = (virtual_size + align - 1) & (~(align - 1));

            break;
    4ab9:	eb 3b                	jmp    4af6 <elf_tls_aligned_virtual_size+0xe7>
                *aligned_virtual_size = (virtual_size + align - 1) & (~(align - 1));
    4abb:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    4abf:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4ac3:	48 01 d0             	add    %rdx,%rax
    4ac6:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    4aca:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4ace:	48 f7 d8             	neg    %rax
    4ad1:	48 21 c2             	and    %rax,%rdx
    4ad4:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    4ad8:	48 89 10             	mov    %rdx,(%rax)
            break;
    4adb:	eb 19                	jmp    4af6 <elf_tls_aligned_virtual_size+0xe7>
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4add:	83 45 dc 01          	addl   $0x1,-0x24(%rbp)
    4ae1:	48 83 45 e0 38       	addq   $0x38,-0x20(%rbp)
    4ae6:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4aea:	0f b7 40 38          	movzwl 0x38(%rax),%eax
    4aee:	0f b7 c0             	movzwl %ax,%eax
    4af1:	39 45 dc             	cmp    %eax,-0x24(%rbp)
    4af4:	72 87                	jb     4a7d <elf_tls_aligned_virtual_size+0x6e>
        }
    }

    return 0;
    4af6:	b8 00 00 00 00       	mov    $0x0,%eax
}
    4afb:	c9                   	leaveq 
    4afc:	c3                   	retq   

0000000000004afd <elf_get_init_array>:

int elf_get_init_array(const void* enclave_base,
        uintptr_t *init_array_addr, size_t *init_array_size)
{
    4afd:	55                   	push   %rbp
    4afe:	48 89 e5             	mov    %rsp,%rbp
    4b01:	48 83 ec 48          	sub    $0x48,%rsp
    4b05:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    4b09:	48 89 75 c0          	mov    %rsi,-0x40(%rbp)
    4b0d:	48 89 55 b8          	mov    %rdx,-0x48(%rbp)
    ElfW(Half) phnum = 0;
    4b11:	c7 45 d4 00 00 00 00 	movl   $0x0,-0x2c(%rbp)
    const ElfW(Ehdr) *ehdr = (const ElfW(Ehdr)*)enclave_base;
    4b18:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4b1c:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    ElfW(Phdr) *phdr = get_phdr(ehdr);
    4b20:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4b24:	48 89 c7             	mov    %rax,%rdi
    4b27:	e8 fe f8 ff ff       	callq  442a <get_phdr>
    4b2c:	48 89 45 d8          	mov    %rax,-0x28(%rbp)

    if (!init_array_addr || !init_array_size)
    4b30:	48 83 7d c0 00       	cmpq   $0x0,-0x40(%rbp)
    4b35:	74 07                	je     4b3e <elf_get_init_array+0x41>
    4b37:	48 83 7d b8 00       	cmpq   $0x0,-0x48(%rbp)
    4b3c:	75 0a                	jne    4b48 <elf_get_init_array+0x4b>
        return -1;
    4b3e:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4b43:	e9 d0 00 00 00       	jmpq   4c18 <elf_get_init_array+0x11b>

    if (phdr == NULL)
    4b48:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    4b4d:	75 0a                	jne    4b59 <elf_get_init_array+0x5c>
        return -1;  /* Invalid image. */
    4b4f:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4b54:	e9 bf 00 00 00       	jmpq   4c18 <elf_get_init_array+0x11b>

    *init_array_addr = 0;
    4b59:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    4b5d:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    *init_array_size = 0;
    4b64:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    4b68:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)

    /* Search for Dynamic segment */
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4b6f:	e9 8b 00 00 00       	jmpq   4bff <elf_get_init_array+0x102>
    {
        if (phdr->p_type == PT_DYNAMIC)
    4b74:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4b78:	8b 00                	mov    (%rax),%eax
    4b7a:	83 f8 02             	cmp    $0x2,%eax
    4b7d:	75 77                	jne    4bf6 <elf_get_init_array+0xf9>
        {
            size_t      count;
            size_t      n_dyn = phdr->p_filesz/sizeof(ElfW(Dyn));
    4b7f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4b83:	48 8b 40 20          	mov    0x20(%rax),%rax
    4b87:	48 c1 e8 04          	shr    $0x4,%rax
    4b8b:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
            ElfW(Dyn)   *dyn = GET_PTR(ElfW(Dyn), ehdr, phdr->p_paddr);
    4b8f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4b93:	48 8b 50 18          	mov    0x18(%rax),%rdx
    4b97:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4b9b:	48 01 d0             	add    %rdx,%rax
    4b9e:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
            
            for (count = 0; count < n_dyn; count++, dyn++)
    4ba2:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    4ba9:	00 
    4baa:	eb 40                	jmp    4bec <elf_get_init_array+0xef>
            {
                switch (dyn->d_tag)
    4bac:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4bb0:	48 8b 00             	mov    (%rax),%rax
    4bb3:	48 83 f8 19          	cmp    $0x19,%rax
    4bb7:	74 08                	je     4bc1 <elf_get_init_array+0xc4>
    4bb9:	48 83 f8 1b          	cmp    $0x1b,%rax
    4bbd:	74 13                	je     4bd2 <elf_get_init_array+0xd5>
    4bbf:	eb 21                	jmp    4be2 <elf_get_init_array+0xe5>
                {
                    case DT_INIT_ARRAY:
                        *init_array_addr = dyn->d_un.d_ptr;
    4bc1:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4bc5:	48 8b 50 08          	mov    0x8(%rax),%rdx
    4bc9:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    4bcd:	48 89 10             	mov    %rdx,(%rax)
                        break;
    4bd0:	eb 10                	jmp    4be2 <elf_get_init_array+0xe5>
                    case DT_INIT_ARRAYSZ:
                        *init_array_size = dyn->d_un.d_val;
    4bd2:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4bd6:	48 8b 50 08          	mov    0x8(%rax),%rdx
    4bda:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    4bde:	48 89 10             	mov    %rdx,(%rax)
                        break;
    4be1:	90                   	nop
            for (count = 0; count < n_dyn; count++, dyn++)
    4be2:	48 83 45 e0 01       	addq   $0x1,-0x20(%rbp)
    4be7:	48 83 45 e8 10       	addq   $0x10,-0x18(%rbp)
    4bec:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    4bf0:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    4bf4:	72 b6                	jb     4bac <elf_get_init_array+0xaf>
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4bf6:	83 45 d4 01          	addl   $0x1,-0x2c(%rbp)
    4bfa:	48 83 45 d8 38       	addq   $0x38,-0x28(%rbp)
    4bff:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4c03:	0f b7 40 38          	movzwl 0x38(%rax),%eax
    4c07:	0f b7 c0             	movzwl %ax,%eax
    4c0a:	39 45 d4             	cmp    %eax,-0x2c(%rbp)
    4c0d:	0f 82 61 ff ff ff    	jb     4b74 <elf_get_init_array+0x77>
                }
            }
        }
    }

    return 0;
    4c13:	b8 00 00 00 00       	mov    $0x0,%eax
}
    4c18:	c9                   	leaveq 
    4c19:	c3                   	retq   

0000000000004c1a <elf_get_uninit_array>:

int elf_get_uninit_array(const void* enclave_base,
        uintptr_t *uninit_array_addr, size_t *uninit_array_size)
{
    4c1a:	55                   	push   %rbp
    4c1b:	48 89 e5             	mov    %rsp,%rbp
    4c1e:	48 83 ec 48          	sub    $0x48,%rsp
    4c22:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    4c26:	48 89 75 c0          	mov    %rsi,-0x40(%rbp)
    4c2a:	48 89 55 b8          	mov    %rdx,-0x48(%rbp)
    ElfW(Half) phnum = 0;
    4c2e:	c7 45 d4 00 00 00 00 	movl   $0x0,-0x2c(%rbp)
    const ElfW(Ehdr) *ehdr = (const ElfW(Ehdr)*)enclave_base;
    4c35:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4c39:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    ElfW(Phdr) *phdr = get_phdr(ehdr);
    4c3d:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4c41:	48 89 c7             	mov    %rax,%rdi
    4c44:	e8 e1 f7 ff ff       	callq  442a <get_phdr>
    4c49:	48 89 45 d8          	mov    %rax,-0x28(%rbp)

    if (!uninit_array_addr || !uninit_array_size)
    4c4d:	48 83 7d c0 00       	cmpq   $0x0,-0x40(%rbp)
    4c52:	74 07                	je     4c5b <elf_get_uninit_array+0x41>
    4c54:	48 83 7d b8 00       	cmpq   $0x0,-0x48(%rbp)
    4c59:	75 0a                	jne    4c65 <elf_get_uninit_array+0x4b>
        return -1;
    4c5b:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4c60:	e9 d0 00 00 00       	jmpq   4d35 <elf_get_uninit_array+0x11b>

    if (phdr == NULL)
    4c65:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    4c6a:	75 0a                	jne    4c76 <elf_get_uninit_array+0x5c>
        return -1;  /* Invalid image. */
    4c6c:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4c71:	e9 bf 00 00 00       	jmpq   4d35 <elf_get_uninit_array+0x11b>

    *uninit_array_addr = 0;
    4c76:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    4c7a:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    *uninit_array_size = 0;
    4c81:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    4c85:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)

    /* Search for Dynamic segment */
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4c8c:	e9 8b 00 00 00       	jmpq   4d1c <elf_get_uninit_array+0x102>
    {
        if (phdr->p_type == PT_DYNAMIC)
    4c91:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4c95:	8b 00                	mov    (%rax),%eax
    4c97:	83 f8 02             	cmp    $0x2,%eax
    4c9a:	75 77                	jne    4d13 <elf_get_uninit_array+0xf9>
        {
            size_t      count;
            size_t      n_dyn = phdr->p_filesz/sizeof(ElfW(Dyn));
    4c9c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4ca0:	48 8b 40 20          	mov    0x20(%rax),%rax
    4ca4:	48 c1 e8 04          	shr    $0x4,%rax
    4ca8:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
            ElfW(Dyn)   *dyn = GET_PTR(ElfW(Dyn), ehdr, phdr->p_paddr);
    4cac:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4cb0:	48 8b 50 18          	mov    0x18(%rax),%rdx
    4cb4:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4cb8:	48 01 d0             	add    %rdx,%rax
    4cbb:	48 89 45 e8          	mov    %rax,-0x18(%rbp)

            for (count = 0; count < n_dyn; count++, dyn++)
    4cbf:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    4cc6:	00 
    4cc7:	eb 40                	jmp    4d09 <elf_get_uninit_array+0xef>
            {
                switch (dyn->d_tag)
    4cc9:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4ccd:	48 8b 00             	mov    (%rax),%rax
    4cd0:	48 83 f8 1a          	cmp    $0x1a,%rax
    4cd4:	74 08                	je     4cde <elf_get_uninit_array+0xc4>
    4cd6:	48 83 f8 1c          	cmp    $0x1c,%rax
    4cda:	74 13                	je     4cef <elf_get_uninit_array+0xd5>
    4cdc:	eb 21                	jmp    4cff <elf_get_uninit_array+0xe5>
                {
                    case DT_FINI_ARRAY:
                        *uninit_array_addr = dyn->d_un.d_ptr;
    4cde:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4ce2:	48 8b 50 08          	mov    0x8(%rax),%rdx
    4ce6:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    4cea:	48 89 10             	mov    %rdx,(%rax)
                        break;
    4ced:	eb 10                	jmp    4cff <elf_get_uninit_array+0xe5>
                    case DT_FINI_ARRAYSZ:
                        *uninit_array_size = dyn->d_un.d_val;
    4cef:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4cf3:	48 8b 50 08          	mov    0x8(%rax),%rdx
    4cf7:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    4cfb:	48 89 10             	mov    %rdx,(%rax)
                        break;
    4cfe:	90                   	nop
            for (count = 0; count < n_dyn; count++, dyn++)
    4cff:	48 83 45 e0 01       	addq   $0x1,-0x20(%rbp)
    4d04:	48 83 45 e8 10       	addq   $0x10,-0x18(%rbp)
    4d09:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    4d0d:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    4d11:	72 b6                	jb     4cc9 <elf_get_uninit_array+0xaf>
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4d13:	83 45 d4 01          	addl   $0x1,-0x2c(%rbp)
    4d17:	48 83 45 d8 38       	addq   $0x38,-0x28(%rbp)
    4d1c:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4d20:	0f b7 40 38          	movzwl 0x38(%rax),%eax
    4d24:	0f b7 c0             	movzwl %ax,%eax
    4d27:	39 45 d4             	cmp    %eax,-0x2c(%rbp)
    4d2a:	0f 82 61 ff ff ff    	jb     4c91 <elf_get_uninit_array+0x77>
                }
            }
        }
    }

    return 0;
    4d30:	b8 00 00 00 00       	mov    $0x0,%eax
}
    4d35:	c9                   	leaveq 
    4d36:	c3                   	retq   

0000000000004d37 <has_text_relo>:

static int has_text_relo(const ElfW(Ehdr) *ehdr, const ElfW(Phdr) *phdr, ElfW(Half) phnum)
{
    4d37:	55                   	push   %rbp
    4d38:	48 89 e5             	mov    %rsp,%rbp
    4d3b:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    4d3f:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    4d43:	89 55 cc             	mov    %edx,-0x34(%rbp)
    ElfW(Half) phi = 0;
    4d46:	c7 45 e0 00 00 00 00 	movl   $0x0,-0x20(%rbp)
    int text_relo = 0;
    4d4d:	c7 45 e4 00 00 00 00 	movl   $0x0,-0x1c(%rbp)

    for (; phi < phnum; phi++, phdr++)
    4d54:	eb 7c                	jmp    4dd2 <has_text_relo+0x9b>
    {
        if (phdr->p_type == PT_DYNAMIC)
    4d56:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4d5a:	8b 00                	mov    (%rax),%eax
    4d5c:	83 f8 02             	cmp    $0x2,%eax
    4d5f:	75 68                	jne    4dc9 <has_text_relo+0x92>
        {
            size_t count;
            size_t n_dyn = phdr->p_filesz/sizeof(ElfW(Dyn));
    4d61:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4d65:	48 8b 40 20          	mov    0x20(%rax),%rax
    4d69:	48 c1 e8 04          	shr    $0x4,%rax
    4d6d:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
            ElfW(Dyn) *dyn = GET_PTR(ElfW(Dyn), ehdr, phdr->p_paddr);
    4d71:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4d75:	48 8b 50 18          	mov    0x18(%rax),%rdx
    4d79:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4d7d:	48 01 d0             	add    %rdx,%rax
    4d80:	48 89 45 f0          	mov    %rax,-0x10(%rbp)

            for (count = 0; count < n_dyn; count++, dyn++)
    4d84:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    4d8b:	00 
    4d8c:	eb 2c                	jmp    4dba <has_text_relo+0x83>
            {
                if (dyn->d_tag == DT_NULL)
    4d8e:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4d92:	48 8b 00             	mov    (%rax),%rax
    4d95:	48 85 c0             	test   %rax,%rax
    4d98:	74 2c                	je     4dc6 <has_text_relo+0x8f>
                    break;

                if (dyn->d_tag == DT_TEXTREL)
    4d9a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4d9e:	48 8b 00             	mov    (%rax),%rax
    4da1:	48 83 f8 16          	cmp    $0x16,%rax
    4da5:	75 09                	jne    4db0 <has_text_relo+0x79>
                {
                    text_relo = 1;
    4da7:	c7 45 e4 01 00 00 00 	movl   $0x1,-0x1c(%rbp)
                    break;
    4dae:	eb 17                	jmp    4dc7 <has_text_relo+0x90>
            for (count = 0; count < n_dyn; count++, dyn++)
    4db0:	48 83 45 e8 01       	addq   $0x1,-0x18(%rbp)
    4db5:	48 83 45 f0 10       	addq   $0x10,-0x10(%rbp)
    4dba:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4dbe:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    4dc2:	72 ca                	jb     4d8e <has_text_relo+0x57>
                }
            }
            break;
    4dc4:	eb 18                	jmp    4dde <has_text_relo+0xa7>
                    break;
    4dc6:	90                   	nop
            break;
    4dc7:	eb 15                	jmp    4dde <has_text_relo+0xa7>
    for (; phi < phnum; phi++, phdr++)
    4dc9:	83 45 e0 01          	addl   $0x1,-0x20(%rbp)
    4dcd:	48 83 45 d0 38       	addq   $0x38,-0x30(%rbp)
    4dd2:	8b 45 e0             	mov    -0x20(%rbp),%eax
    4dd5:	3b 45 cc             	cmp    -0x34(%rbp),%eax
    4dd8:	0f 82 78 ff ff ff    	jb     4d56 <has_text_relo+0x1f>
        }
    }
    return text_relo;
    4dde:	8b 45 e4             	mov    -0x1c(%rbp),%eax
}
    4de1:	5d                   	pop    %rbp
    4de2:	c3                   	retq   

0000000000004de3 <change_protection>:

sgx_status_t change_protection(void *enclave_base)
{
    4de3:	55                   	push   %rbp
    4de4:	48 89 e5             	mov    %rsp,%rbp
    4de7:	48 83 ec 60          	sub    $0x60,%rsp
    4deb:	48 89 7d a8          	mov    %rdi,-0x58(%rbp)
    ElfW(Half) phnum = 0;
    4def:	c7 45 b8 00 00 00 00 	movl   $0x0,-0x48(%rbp)
    const ElfW(Ehdr) *ehdr = (const ElfW(Ehdr)*)enclave_base;
    4df6:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4dfa:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    const ElfW(Phdr) *phdr = get_phdr(ehdr);
    4dfe:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4e02:	48 89 c7             	mov    %rax,%rdi
    4e05:	e8 20 f6 ff ff       	callq  442a <get_phdr>
    4e0a:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    uint64_t perms;
    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    4e0e:	c7 45 c0 01 00 00 00 	movl   $0x1,-0x40(%rbp)

    if (phdr == NULL)
    4e15:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    4e1a:	75 08                	jne    4e24 <change_protection+0x41>
        return status;
    4e1c:	8b 45 c0             	mov    -0x40(%rbp),%eax
    4e1f:	e9 65 02 00 00       	jmpq   5089 <change_protection+0x2a6>

    int text_relocation = has_text_relo(ehdr, phdr, ehdr->e_phnum);
    4e24:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4e28:	0f b7 40 38          	movzwl 0x38(%rax),%eax
    4e2c:	0f b7 d0             	movzwl %ax,%edx
    4e2f:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    4e33:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4e37:	48 89 ce             	mov    %rcx,%rsi
    4e3a:	48 89 c7             	mov    %rax,%rdi
    4e3d:	e8 f5 fe ff ff       	callq  4d37 <has_text_relo>
    4e42:	89 45 c4             	mov    %eax,-0x3c(%rbp)

    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4e45:	e9 6e 01 00 00       	jmpq   4fb8 <change_protection+0x1d5>
    {
        if (text_relocation && (phdr->p_type == PT_LOAD) && ((phdr->p_flags & PF_W) == 0))
    4e4a:	83 7d c4 00          	cmpl   $0x0,-0x3c(%rbp)
    4e4e:	0f 84 c7 00 00 00    	je     4f1b <change_protection+0x138>
    4e54:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4e58:	8b 00                	mov    (%rax),%eax
    4e5a:	83 f8 01             	cmp    $0x1,%eax
    4e5d:	0f 85 b8 00 00 00    	jne    4f1b <change_protection+0x138>
    4e63:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4e67:	8b 40 04             	mov    0x4(%rax),%eax
    4e6a:	83 e0 02             	and    $0x2,%eax
    4e6d:	85 c0                	test   %eax,%eax
    4e6f:	0f 85 a6 00 00 00    	jne    4f1b <change_protection+0x138>
        {
            perms = 0;
    4e75:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    4e7c:	00 
            size_t start = (size_t)enclave_base + (phdr->p_vaddr & (size_t)(~(SE_PAGE_SIZE-1)));
    4e7d:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4e81:	48 8b 40 10          	mov    0x10(%rax),%rax
    4e85:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    4e8b:	48 89 c2             	mov    %rax,%rdx
    4e8e:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4e92:	48 01 d0             	add    %rdx,%rax
    4e95:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
            size_t end = (size_t)enclave_base + ((phdr->p_vaddr + phdr->p_memsz + SE_PAGE_SIZE - 1) & (size_t)(~(SE_PAGE_SIZE-1)));
    4e99:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4e9d:	48 8b 50 10          	mov    0x10(%rax),%rdx
    4ea1:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4ea5:	48 8b 40 28          	mov    0x28(%rax),%rax
    4ea9:	48 01 d0             	add    %rdx,%rax
    4eac:	48 05 ff 0f 00 00    	add    $0xfff,%rax
    4eb2:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    4eb8:	48 89 c2             	mov    %rax,%rdx
    4ebb:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4ebf:	48 01 d0             	add    %rdx,%rax
    4ec2:	48 89 45 e8          	mov    %rax,-0x18(%rbp)

            if (phdr->p_flags & PF_R)
    4ec6:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4eca:	8b 40 04             	mov    0x4(%rax),%eax
    4ecd:	83 e0 04             	and    $0x4,%eax
    4ed0:	85 c0                	test   %eax,%eax
    4ed2:	74 05                	je     4ed9 <change_protection+0xf6>
                perms |= SI_FLAG_R;
    4ed4:	48 83 4d d0 01       	orq    $0x1,-0x30(%rbp)
            if (phdr->p_flags & PF_X)
    4ed9:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4edd:	8b 40 04             	mov    0x4(%rax),%eax
    4ee0:	83 e0 01             	and    $0x1,%eax
    4ee3:	85 c0                	test   %eax,%eax
    4ee5:	74 05                	je     4eec <change_protection+0x109>
                perms |= SI_FLAG_X;
    4ee7:	48 83 4d d0 04       	orq    $0x4,-0x30(%rbp)

            if((status = trts_mprotect(start, end - start, perms)) != SGX_SUCCESS)
    4eec:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4ef0:	48 2b 45 e0          	sub    -0x20(%rbp),%rax
    4ef4:	48 89 c1             	mov    %rax,%rcx
    4ef7:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    4efb:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    4eff:	48 89 ce             	mov    %rcx,%rsi
    4f02:	48 89 c7             	mov    %rax,%rdi
    4f05:	e8 92 e3 ff ff       	callq  329c <trts_mprotect>
    4f0a:	89 45 c0             	mov    %eax,-0x40(%rbp)
    4f0d:	83 7d c0 00          	cmpl   $0x0,-0x40(%rbp)
    4f11:	74 08                	je     4f1b <change_protection+0x138>
                return status;
    4f13:	8b 45 c0             	mov    -0x40(%rbp),%eax
    4f16:	e9 6e 01 00 00       	jmpq   5089 <change_protection+0x2a6>
        }

        if (phdr->p_type == PT_GNU_RELRO)
    4f1b:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4f1f:	8b 00                	mov    (%rax),%eax
    4f21:	3d 52 e5 74 64       	cmp    $0x6474e552,%eax
    4f26:	0f 85 83 00 00 00    	jne    4faf <change_protection+0x1cc>
        {
            size_t start = (size_t)enclave_base + (phdr->p_vaddr & (size_t)(~(SE_PAGE_SIZE-1)));
    4f2c:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4f30:	48 8b 40 10          	mov    0x10(%rax),%rax
    4f34:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    4f3a:	48 89 c2             	mov    %rax,%rdx
    4f3d:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4f41:	48 01 d0             	add    %rdx,%rax
    4f44:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
            size_t end = (size_t)enclave_base + ((phdr->p_vaddr + phdr->p_memsz + SE_PAGE_SIZE - 1) & (size_t)(~(SE_PAGE_SIZE-1)));
    4f48:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4f4c:	48 8b 50 10          	mov    0x10(%rax),%rdx
    4f50:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4f54:	48 8b 40 28          	mov    0x28(%rax),%rax
    4f58:	48 01 d0             	add    %rdx,%rax
    4f5b:	48 05 ff 0f 00 00    	add    $0xfff,%rax
    4f61:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    4f67:	48 89 c2             	mov    %rax,%rdx
    4f6a:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4f6e:	48 01 d0             	add    %rdx,%rax
    4f71:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
            if ((start != end) &&
    4f75:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4f79:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    4f7d:	74 30                	je     4faf <change_protection+0x1cc>
                    (status = trts_mprotect(start, end - start, SI_FLAG_R)) != SGX_SUCCESS)
    4f7f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4f83:	48 2b 45 f0          	sub    -0x10(%rbp),%rax
    4f87:	48 89 c1             	mov    %rax,%rcx
            if ((start != end) &&
    4f8a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4f8e:	ba 01 00 00 00       	mov    $0x1,%edx
    4f93:	48 89 ce             	mov    %rcx,%rsi
    4f96:	48 89 c7             	mov    %rax,%rdi
    4f99:	e8 fe e2 ff ff       	callq  329c <trts_mprotect>
    4f9e:	89 45 c0             	mov    %eax,-0x40(%rbp)
    4fa1:	83 7d c0 00          	cmpl   $0x0,-0x40(%rbp)
    4fa5:	74 08                	je     4faf <change_protection+0x1cc>
                return status;
    4fa7:	8b 45 c0             	mov    -0x40(%rbp),%eax
    4faa:	e9 da 00 00 00       	jmpq   5089 <change_protection+0x2a6>
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4faf:	83 45 b8 01          	addl   $0x1,-0x48(%rbp)
    4fb3:	48 83 45 c8 38       	addq   $0x38,-0x38(%rbp)
    4fb8:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4fbc:	0f b7 40 38          	movzwl 0x38(%rax),%eax
    4fc0:	0f b7 c0             	movzwl %ax,%eax
    4fc3:	39 45 b8             	cmp    %eax,-0x48(%rbp)
    4fc6:	0f 82 7e fe ff ff    	jb     4e4a <change_protection+0x67>
        }
    }

    //The <ReservedMemMinSize> memory region's attributes has been set to RW if EDMM is supported by URTS.
    //So do_eaccept() to accept these pages.
    uint32_t i = 0;
    4fcc:	c7 45 bc 00 00 00 00 	movl   $0x0,-0x44(%rbp)
    for (i = 0; i < g_global_data.layout_entry_num; i++)
    4fd3:	c7 45 bc 00 00 00 00 	movl   $0x0,-0x44(%rbp)
    4fda:	e9 93 00 00 00       	jmpq   5072 <change_protection+0x28f>
    {
        if (g_global_data.layout_table[i].entry.id == LAYOUT_ID_RSRV_MIN && g_global_data.layout_table[i].entry.si_flags ==  SI_FLAGS_RWX)
    4fdf:	8b 45 bc             	mov    -0x44(%rbp),%eax
    4fe2:	48 c1 e0 05          	shl    $0x5,%rax
    4fe6:	48 89 c2             	mov    %rax,%rdx
    4fe9:	48 8d 05 c0 82 00 00 	lea    0x82c0(%rip),%rax        # d2b0 <g_global_data+0x130>
    4ff0:	0f b7 04 02          	movzwl (%rdx,%rax,1),%eax
    4ff4:	66 83 f8 14          	cmp    $0x14,%ax
    4ff8:	75 74                	jne    506e <change_protection+0x28b>
    4ffa:	8b 45 bc             	mov    -0x44(%rbp),%eax
    4ffd:	48 83 c0 0a          	add    $0xa,%rax
    5001:	48 c1 e0 05          	shl    $0x5,%rax
    5005:	48 89 c2             	mov    %rax,%rdx
    5008:	48 8d 05 79 81 00 00 	lea    0x8179(%rip),%rax        # d188 <g_global_data+0x8>
    500f:	48 8b 04 02          	mov    (%rdx,%rax,1),%rax
    5013:	48 3d 07 02 00 00    	cmp    $0x207,%rax
    5019:	75 53                	jne    506e <change_protection+0x28b>
        {
            if((status = trts_mprotect((size_t)((size_t)enclave_base + g_global_data.layout_table[i].entry.rva), 
                                                                     g_global_data.layout_table[i].entry.page_count << SE_PAGE_SHIFT, 
    501b:	8b 45 bc             	mov    -0x44(%rbp),%eax
    501e:	48 c1 e0 05          	shl    $0x5,%rax
    5022:	48 89 c2             	mov    %rax,%rdx
    5025:	48 8d 05 88 82 00 00 	lea    0x8288(%rip),%rax        # d2b4 <g_global_data+0x134>
    502c:	8b 04 02             	mov    (%rdx,%rax,1),%eax
    502f:	c1 e0 0c             	shl    $0xc,%eax
            if((status = trts_mprotect((size_t)((size_t)enclave_base + g_global_data.layout_table[i].entry.rva), 
    5032:	89 c1                	mov    %eax,%ecx
    5034:	8b 45 bc             	mov    -0x44(%rbp),%eax
    5037:	48 c1 e0 05          	shl    $0x5,%rax
    503b:	48 89 c2             	mov    %rax,%rdx
    503e:	48 8d 05 73 82 00 00 	lea    0x8273(%rip),%rax        # d2b8 <g_global_data+0x138>
    5045:	48 8b 14 02          	mov    (%rdx,%rax,1),%rdx
    5049:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    504d:	48 01 d0             	add    %rdx,%rax
    5050:	ba 03 00 00 00       	mov    $0x3,%edx
    5055:	48 89 ce             	mov    %rcx,%rsi
    5058:	48 89 c7             	mov    %rax,%rdi
    505b:	e8 3c e2 ff ff       	callq  329c <trts_mprotect>
    5060:	89 45 c0             	mov    %eax,-0x40(%rbp)
    5063:	83 7d c0 00          	cmpl   $0x0,-0x40(%rbp)
    5067:	74 1a                	je     5083 <change_protection+0x2a0>
                                                                           SI_FLAG_R|SI_FLAG_W)) != SGX_SUCCESS)
                return status;
    5069:	8b 45 c0             	mov    -0x40(%rbp),%eax
    506c:	eb 1b                	jmp    5089 <change_protection+0x2a6>
    for (i = 0; i < g_global_data.layout_entry_num; i++)
    506e:	83 45 bc 01          	addl   $0x1,-0x44(%rbp)
    5072:	8b 05 30 82 00 00    	mov    0x8230(%rip),%eax        # d2a8 <g_global_data+0x128>
    5078:	39 45 bc             	cmp    %eax,-0x44(%rbp)
    507b:	0f 82 5e ff ff ff    	jb     4fdf <change_protection+0x1fc>
    5081:	eb 01                	jmp    5084 <change_protection+0x2a1>
            break;
    5083:	90                   	nop
        }
    }

    return SGX_SUCCESS;
    5084:	b8 00 00 00 00       	mov    $0x0,%eax
}
    5089:	c9                   	leaveq 
    508a:	c3                   	retq   

000000000000508b <do_atexit_aux>:
{
    return __cxa_atexit((void (*)(void *))fun, NULL, __dso_handle);
}

static void do_atexit_aux(void)
{
    508b:	55                   	push   %rbp
    508c:	48 89 e5             	mov    %rsp,%rbp
    508f:	48 83 ec 20          	sub    $0x20,%rsp
    exit_function_t *exit_function = g_exit_function;
    5093:	48 8b 05 56 c0 00 00 	mov    0xc056(%rip),%rax        # 110f0 <g_exit_function>
    509a:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    g_exit_function = NULL;
    509e:	48 c7 05 47 c0 00 00 	movq   $0x0,0xc047(%rip)        # 110f0 <g_exit_function>
    50a5:	00 00 00 00 

    while (exit_function != NULL)
    50a9:	eb 58                	jmp    5103 <do_atexit_aux+0x78>
    {
        cxa_function_t cxa_func = DEC_CXA_FUNC_POINTER(exit_function->cxa.fun);
    50ab:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    50af:	48 8b 10             	mov    (%rax),%rdx
    50b2:	48 8b 05 3f c0 00 00 	mov    0xc03f(%rip),%rax        # 110f8 <g_exit_function_cookie>
    50b9:	48 31 d0             	xor    %rdx,%rax
    50bc:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
        void *para = DEC_CXA_PARA_POINTER(exit_function->cxa.para);
    50c0:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    50c4:	48 8b 50 08          	mov    0x8(%rax),%rdx
    50c8:	48 8b 05 29 c0 00 00 	mov    0xc029(%rip),%rax        # 110f8 <g_exit_function_cookie>
    50cf:	48 31 d0             	xor    %rdx,%rax
    50d2:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
        cxa_func(para);
    50d6:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    50da:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    50de:	48 89 d7             	mov    %rdx,%rdi
    50e1:	ff d0                	callq  *%rax

        exit_function_t *tmp = exit_function;
    50e3:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    50e7:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
        exit_function = exit_function->next;
    50eb:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    50ef:	48 8b 40 18          	mov    0x18(%rax),%rax
    50f3:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
        free(tmp);
    50f7:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    50fb:	48 89 c7             	mov    %rax,%rdi
    50fe:	e8 6a 47 00 00       	callq  986d <dlfree>
    while (exit_function != NULL)
    5103:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
    5108:	75 a1                	jne    50ab <do_atexit_aux+0x20>
    }
}
    510a:	90                   	nop
    510b:	c9                   	leaveq 
    510c:	c3                   	retq   

000000000000510d <do_ctors_aux>:

/* auxiliary routines */
static void do_ctors_aux(void)
{
    510d:	55                   	push   %rbp
    510e:	48 89 e5             	mov    %rsp,%rbp
    5111:	48 83 ec 40          	sub    $0x40,%rsp
    5115:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    511c:	00 00 
    511e:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    5122:	31 c0                	xor    %eax,%eax
    /* SGX RTS does not support .ctors currently */
   
    fp_t *p = NULL;
    5124:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    512b:	00 
    uintptr_t init_array_addr = 0;
    512c:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    5133:	00 
    size_t init_array_size = 0;
    5134:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    513b:	00 
    const void *enclave_start = (const void*)&__ImageBase;
    513c:	48 8d 05 bd ae ff ff 	lea    -0x5143(%rip),%rax        # 0 <enclave.so>
    5143:	48 89 45 e0          	mov    %rax,-0x20(%rbp)

    if (0 != elf_get_init_array(enclave_start, &init_array_addr, &init_array_size)|| init_array_addr == 0 || init_array_size == 0)
    5147:	48 8d 55 d0          	lea    -0x30(%rbp),%rdx
    514b:	48 8d 4d c8          	lea    -0x38(%rbp),%rcx
    514f:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5153:	48 89 ce             	mov    %rcx,%rsi
    5156:	48 89 c7             	mov    %rax,%rdi
    5159:	e8 9f f9 ff ff       	callq  4afd <elf_get_init_array>
    515e:	85 c0                	test   %eax,%eax
    5160:	75 5b                	jne    51bd <do_ctors_aux+0xb0>
    5162:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    5166:	48 85 c0             	test   %rax,%rax
    5169:	74 52                	je     51bd <do_ctors_aux+0xb0>
    516b:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    516f:	48 85 c0             	test   %rax,%rax
    5172:	74 49                	je     51bd <do_ctors_aux+0xb0>
        return;

    fp_t *fp_start = (fp_t*)(init_array_addr + (uintptr_t)(enclave_start));
    5174:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    5178:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    517c:	48 01 d0             	add    %rdx,%rax
    517f:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    fp_t *fp_end = fp_start + (init_array_size / sizeof(fp_t));
    5183:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    5187:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    518b:	48 89 c2             	mov    %rax,%rdx
    518e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    5192:	48 01 d0             	add    %rdx,%rax
    5195:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    
    /* traverse .init_array in forward order */
    for (p = fp_start; p < fp_end; p++)
    5199:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    519d:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    51a1:	eb 0e                	jmp    51b1 <do_ctors_aux+0xa4>
    {
        (*p)();
    51a3:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    51a7:	48 8b 00             	mov    (%rax),%rax
    51aa:	ff d0                	callq  *%rax
    for (p = fp_start; p < fp_end; p++)
    51ac:	48 83 45 d8 08       	addq   $0x8,-0x28(%rbp)
    51b1:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    51b5:	48 3b 45 f0          	cmp    -0x10(%rbp),%rax
    51b9:	72 e8                	jb     51a3 <do_ctors_aux+0x96>
    51bb:	eb 01                	jmp    51be <do_ctors_aux+0xb1>
        return;
    51bd:	90                   	nop
    }
}
    51be:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    51c2:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    51c9:	00 00 
    51cb:	74 05                	je     51d2 <do_ctors_aux+0xc5>
    51cd:	e8 d6 00 00 00       	callq  52a8 <__stack_chk_fail>
    51d2:	c9                   	leaveq 
    51d3:	c3                   	retq   

00000000000051d4 <do_dtors_aux>:

/* auxiliary routines */
static void do_dtors_aux(void)
{
    51d4:	55                   	push   %rbp
    51d5:	48 89 e5             	mov    %rsp,%rbp
    51d8:	48 83 ec 40          	sub    $0x40,%rsp
    51dc:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    51e3:	00 00 
    51e5:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    51e9:	31 c0                	xor    %eax,%eax
    fp_t *p = NULL;
    51eb:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    51f2:	00 
    uintptr_t uninit_array_addr;
    size_t uninit_array_size;
    const void *enclave_start = (const void*)&__ImageBase;
    51f3:	48 8d 05 06 ae ff ff 	lea    -0x51fa(%rip),%rax        # 0 <enclave.so>
    51fa:	48 89 45 e0          	mov    %rax,-0x20(%rbp)

    elf_get_uninit_array(enclave_start, &uninit_array_addr, &uninit_array_size);
    51fe:	48 8d 55 d0          	lea    -0x30(%rbp),%rdx
    5202:	48 8d 4d c8          	lea    -0x38(%rbp),%rcx
    5206:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    520a:	48 89 ce             	mov    %rcx,%rsi
    520d:	48 89 c7             	mov    %rax,%rdi
    5210:	e8 05 fa ff ff       	callq  4c1a <elf_get_uninit_array>

    if (uninit_array_addr == 0 || uninit_array_size == 0)
    5215:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    5219:	48 85 c0             	test   %rax,%rax
    521c:	74 56                	je     5274 <do_dtors_aux+0xa0>
    521e:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    5222:	48 85 c0             	test   %rax,%rax
    5225:	74 4d                	je     5274 <do_dtors_aux+0xa0>
        return;

    fp_t *fp_start = (fp_t*)(uninit_array_addr + (uintptr_t)(enclave_start));
    5227:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    522b:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    522f:	48 01 d0             	add    %rdx,%rax
    5232:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    fp_t *fp_end = fp_start + (uninit_array_size / sizeof(fp_t));
    5236:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    523a:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    523e:	48 89 c2             	mov    %rax,%rdx
    5241:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    5245:	48 01 d0             	add    %rdx,%rax
    5248:	48 89 45 f0          	mov    %rax,-0x10(%rbp)

    /* traverse .fini_array in reverse order */
    for (p = fp_end - 1; p >= fp_start; p--)
    524c:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5250:	48 83 e8 08          	sub    $0x8,%rax
    5254:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    5258:	eb 0e                	jmp    5268 <do_dtors_aux+0x94>
    {
        (*p)();
    525a:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    525e:	48 8b 00             	mov    (%rax),%rax
    5261:	ff d0                	callq  *%rax
    for (p = fp_end - 1; p >= fp_start; p--)
    5263:	48 83 6d d8 08       	subq   $0x8,-0x28(%rbp)
    5268:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    526c:	48 3b 45 e8          	cmp    -0x18(%rbp),%rax
    5270:	73 e8                	jae    525a <do_dtors_aux+0x86>
    5272:	eb 01                	jmp    5275 <do_dtors_aux+0xa1>
        return;
    5274:	90                   	nop
    }
}
    5275:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5279:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    5280:	00 00 
    5282:	74 05                	je     5289 <do_dtors_aux+0xb5>
    5284:	e8 1f 00 00 00       	callq  52a8 <__stack_chk_fail>
    5289:	c9                   	leaveq 
    528a:	c3                   	retq   

000000000000528b <init_global_object>:

void init_global_object(void)
{
    528b:	55                   	push   %rbp
    528c:	48 89 e5             	mov    %rsp,%rbp
    do_ctors_aux();
    528f:	e8 79 fe ff ff       	callq  510d <do_ctors_aux>
}
    5294:	90                   	nop
    5295:	5d                   	pop    %rbp
    5296:	c3                   	retq   

0000000000005297 <uninit_global_object>:

void uninit_global_object(void)
{
    5297:	55                   	push   %rbp
    5298:	48 89 e5             	mov    %rsp,%rbp
    do_atexit_aux();
    529b:	e8 eb fd ff ff       	callq  508b <do_atexit_aux>
    do_dtors_aux();
    52a0:	e8 2f ff ff ff       	callq  51d4 <do_dtors_aux>
}
    52a5:	90                   	nop
    52a6:	5d                   	pop    %rbp
    52a7:	c3                   	retq   

00000000000052a8 <__stack_chk_fail>:
#include "stdlib.h"

void
__attribute__((noreturn))
__stack_chk_fail(void)
{
    52a8:	55                   	push   %rbp
    52a9:	48 89 e5             	mov    %rsp,%rbp
    abort();
    52ac:	e8 eb 76 00 00       	callq  c99c <abort>

00000000000052b1 <__assert>:
#include <stdio.h>
#include <stdlib.h>

void
__assert(const char *file, int line, const char *func, const char *failedexpr)
{
    52b1:	55                   	push   %rbp
    52b2:	48 89 e5             	mov    %rsp,%rbp
    52b5:	48 83 ec 20          	sub    $0x20,%rsp
    52b9:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    52bd:	89 75 f4             	mov    %esi,-0xc(%rbp)
    52c0:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    52c4:	48 89 4d e0          	mov    %rcx,-0x20(%rbp)
	(void)(line);
	(void)(func);
	(void)(failedexpr);
#endif

	abort();
    52c8:	e8 cf 76 00 00       	callq  c99c <abort>

00000000000052cd <spin_acquire_lock>:
#define SPIN_LOCK_YIELD
#endif /* ... yield ... */

#if !defined(USE_RECURSIVE_LOCKS) || USE_RECURSIVE_LOCKS == 0
/* Plain spin locks use single word (embedded in malloc_states) */
static int spin_acquire_lock(int *sl) {
    52cd:	55                   	push   %rbp
    52ce:	48 89 e5             	mov    %rsp,%rbp
    52d1:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  int spins = 0;
    52d5:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  while (*(volatile int *)sl != 0 || CAS_LOCK(sl)) {
    52dc:	eb 04                	jmp    52e2 <spin_acquire_lock+0x15>
    if ((++spins & SPINS_PER_YIELD) == 0) {
    52de:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  while (*(volatile int *)sl != 0 || CAS_LOCK(sl)) {
    52e2:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    52e6:	8b 00                	mov    (%rax),%eax
    52e8:	85 c0                	test   %eax,%eax
    52ea:	75 f2                	jne    52de <spin_acquire_lock+0x11>
    52ec:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    52f0:	b8 01 00 00 00       	mov    $0x1,%eax
    52f5:	87 02                	xchg   %eax,(%rdx)
    52f7:	85 c0                	test   %eax,%eax
    52f9:	75 e3                	jne    52de <spin_acquire_lock+0x11>
      SPIN_LOCK_YIELD;
    }
  }
  return 0;
    52fb:	b8 00 00 00 00       	mov    $0x0,%eax
}
    5300:	5d                   	pop    %rbp
    5301:	c3                   	retq   

0000000000005302 <segment_holding>:
/*  True if segment S holds address A */
#define segment_holds(S, A)\
  ((char*)(A) >= S->base && (char*)(A) < S->base + S->size)

/* Return segment holding given address */
static msegmentptr segment_holding(mstate m, char* addr) {
    5302:	55                   	push   %rbp
    5303:	48 89 e5             	mov    %rsp,%rbp
    5306:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    530a:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  msegmentptr sp = &m->seg;
    530e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    5312:	48 05 78 03 00 00    	add    $0x378,%rax
    5318:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  for (;;) {
    if (addr >= sp->base && addr < sp->base + sp->size)
    531c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5320:	48 8b 00             	mov    (%rax),%rax
    5323:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    5327:	72 1e                	jb     5347 <segment_holding+0x45>
    5329:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    532d:	48 8b 10             	mov    (%rax),%rdx
    5330:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5334:	48 8b 40 08          	mov    0x8(%rax),%rax
    5338:	48 01 d0             	add    %rdx,%rax
    533b:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    533f:	73 06                	jae    5347 <segment_holding+0x45>
      return sp;
    5341:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5345:	eb 18                	jmp    535f <segment_holding+0x5d>
    if ((sp = sp->next) == 0)
    5347:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    534b:	48 8b 40 10          	mov    0x10(%rax),%rax
    534f:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    5353:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    5358:	75 c2                	jne    531c <segment_holding+0x1a>
      return 0;
    535a:	b8 00 00 00 00       	mov    $0x0,%eax
  }
}
    535f:	5d                   	pop    %rbp
    5360:	c3                   	retq   

0000000000005361 <init_mparams>:
static void post_fork_parent(void) { RELEASE_LOCK(&(gm)->mutex); }
static void post_fork_child(void)  { INITIAL_LOCK(&(gm)->mutex); }
#endif /* LOCK_AT_FORK */

/* Initialize mparams */
static int init_mparams(void) {
    5361:	55                   	push   %rbp
    5362:	48 89 e5             	mov    %rsp,%rbp
    5365:	48 83 ec 20          	sub    $0x20,%rsp
    5369:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    5370:	00 00 
    5372:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    5376:	31 c0                	xor    %eax,%eax
#ifdef NEED_GLOBAL_LOCK_INIT
  if (malloc_global_mutex_status <= 0)
    init_malloc_global_mutex();
#endif

  ACQUIRE_MALLOC_GLOBAL_LOCK();
    5378:	b8 01 00 00 00       	mov    $0x1,%eax
    537d:	87 05 7d bd 00 00    	xchg   %eax,0xbd7d(%rip)        # 11100 <malloc_global_mutex>
    5383:	85 c0                	test   %eax,%eax
    5385:	74 0c                	je     5393 <init_mparams+0x32>
    5387:	48 8d 3d 72 bd 00 00 	lea    0xbd72(%rip),%rdi        # 11100 <malloc_global_mutex>
    538e:	e8 3a ff ff ff       	callq  52cd <spin_acquire_lock>
  if (mparams.magic == 0) {
    5393:	48 8b 05 86 bd 00 00 	mov    0xbd86(%rip),%rax        # 11120 <mparams>
    539a:	48 85 c0             	test   %rax,%rax
    539d:	0f 85 d1 00 00 00    	jne    5474 <init_mparams+0x113>
    size_t magic;
    size_t psize;
    size_t gsize;

#if !defined(WIN32) || defined(_TLIBC_)
    psize = malloc_getpagesize;
    53a3:	48 c7 45 e8 00 10 00 	movq   $0x1000,-0x18(%rbp)
    53aa:	00 
    gsize = ((DEFAULT_GRANULARITY != 0)? DEFAULT_GRANULARITY : psize);
    53ab:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    53af:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
        (MAX_SIZE_T < MIN_CHUNK_SIZE)  ||
        (sizeof(int) < 4)  ||
        (MALLOC_ALIGNMENT < (size_t)8U) ||
        ((MALLOC_ALIGNMENT & (MALLOC_ALIGNMENT-SIZE_T_ONE)) != 0) ||
        ((MCHUNK_SIZE      & (MCHUNK_SIZE-SIZE_T_ONE))      != 0) ||
        ((gsize            & (gsize-SIZE_T_ONE))            != 0) ||
    53b3:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    53b7:	48 83 e8 01          	sub    $0x1,%rax
    53bb:	48 23 45 f0          	and    -0x10(%rbp),%rax
    if ((sizeof(size_t) != sizeof(char*)) ||
    53bf:	48 85 c0             	test   %rax,%rax
    53c2:	75 11                	jne    53d5 <init_mparams+0x74>
        ((psize            & (psize-SIZE_T_ONE))            != 0))
    53c4:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    53c8:	48 83 e8 01          	sub    $0x1,%rax
    53cc:	48 23 45 e8          	and    -0x18(%rbp),%rax
        ((gsize            & (gsize-SIZE_T_ONE))            != 0) ||
    53d0:	48 85 c0             	test   %rax,%rax
    53d3:	74 05                	je     53da <init_mparams+0x79>
      ABORT;
    53d5:	e8 c2 75 00 00       	callq  c99c <abort>
    mparams.granularity = gsize;
    53da:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    53de:	48 89 05 4b bd 00 00 	mov    %rax,0xbd4b(%rip)        # 11130 <mparams+0x10>
    mparams.page_size = psize;
    53e5:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    53e9:	48 89 05 38 bd 00 00 	mov    %rax,0xbd38(%rip)        # 11128 <mparams+0x8>
    mparams.mmap_threshold = DEFAULT_MMAP_THRESHOLD;
    53f0:	48 c7 05 3d bd 00 00 	movq   $0xffffffffffffffff,0xbd3d(%rip)        # 11138 <mparams+0x18>
    53f7:	ff ff ff ff 
    mparams.trim_threshold = DEFAULT_TRIM_THRESHOLD;
    53fb:	48 c7 05 3a bd 00 00 	movq   $0x200000,0xbd3a(%rip)        # 11140 <mparams+0x20>
    5402:	00 00 20 00 
#if MORECORE_CONTIGUOUS
    mparams.default_mflags = USE_LOCK_BIT|USE_MMAP_BIT;
    5406:	c7 05 38 bd 00 00 02 	movl   $0x2,0xbd38(%rip)        # 11148 <mparams+0x28>
    540d:	00 00 00 
    mparams.default_mflags = USE_LOCK_BIT|USE_MMAP_BIT|USE_NONCONTIGUOUS_BIT;
#endif /* MORECORE_CONTIGUOUS */

#if !ONLY_MSPACES
    /* Set up lock for main malloc area */
    gm->mflags = mparams.default_mflags;
    5410:	8b 05 32 bd 00 00    	mov    0xbd32(%rip),%eax        # 11148 <mparams+0x28>
    5416:	89 05 b4 c0 00 00    	mov    %eax,0xc0b4(%rip)        # 114d0 <_gm_+0x370>
    (void)INITIAL_LOCK(&gm->mutex);
    541c:	c7 05 ae c0 00 00 00 	movl   $0x0,0xc0ae(%rip)        # 114d4 <_gm_+0x374>
    5423:	00 00 00 
      else
#endif /* USE_DEV_RANDOM */
#if defined(WIN32) && !defined(_TLIBC_)
      magic = (size_t)(GetTickCount() ^ (size_t)0x55555555U);
#elif defined(LACKS_TIME_H)
      if (SGX_SUCCESS != sgx_read_rand((unsigned char *)&magic, sizeof(size_t)))
    5426:	48 8d 45 e0          	lea    -0x20(%rbp),%rax
    542a:	be 08 00 00 00       	mov    $0x8,%esi
    542f:	48 89 c7             	mov    %rax,%rdi
    5432:	e8 62 c1 ff ff       	callq  1599 <sgx_read_rand>
    5437:	85 c0                	test   %eax,%eax
    5439:	74 05                	je     5440 <init_mparams+0xdf>
          ABORT;
    543b:	e8 5c 75 00 00       	callq  c99c <abort>
      magic = (size_t)(magic ^ (size_t)0x55555555U);
    5440:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5444:	48 35 55 55 55 55    	xor    $0x55555555,%rax
    544a:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
#else
      magic = (size_t)(time(0) ^ (size_t)0x55555555U);
#endif
      magic |= (size_t)8U;    /* ensure nonzero */
    544e:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5452:	48 83 c8 08          	or     $0x8,%rax
    5456:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
      magic &= ~(size_t)7U;   /* improve chances of fault for bad values */
    545a:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    545e:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    5462:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
      /* Until memory modes commonly available, use volatile-write */
      (*(volatile size_t *)(&(mparams.magic))) = magic;
    5466:	48 8d 05 b3 bc 00 00 	lea    0xbcb3(%rip),%rax        # 11120 <mparams>
    546d:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    5471:	48 89 10             	mov    %rdx,(%rax)
    }
  }

  RELEASE_MALLOC_GLOBAL_LOCK();
    5474:	b8 00 00 00 00       	mov    $0x0,%eax
    5479:	89 05 81 bc 00 00    	mov    %eax,0xbc81(%rip)        # 11100 <malloc_global_mutex>
  return 1;
    547f:	b8 01 00 00 00       	mov    $0x1,%eax
}
    5484:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    5488:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    548f:	00 00 
    5491:	74 05                	je     5498 <init_mparams+0x137>
    5493:	e8 10 fe ff ff       	callq  52a8 <__stack_chk_fail>
    5498:	c9                   	leaveq 
    5499:	c3                   	retq   

000000000000549a <do_check_any_chunk>:

#if DEBUG
/* ------------------------- Debugging Support --------------------------- */

/* Check properties of any chunk, whether free, inuse, mmapped etc  */
static void do_check_any_chunk(mstate m, mchunkptr p) {
    549a:	55                   	push   %rbp
    549b:	48 89 e5             	mov    %rsp,%rbp
    549e:	48 83 ec 10          	sub    $0x10,%rsp
    54a2:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    54a6:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
  assert((is_aligned(chunk2mem(p))) || (p->head == FENCEPOST_HEAD));
    54aa:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    54ae:	48 83 c0 10          	add    $0x10,%rax
    54b2:	83 e0 0f             	and    $0xf,%eax
    54b5:	48 85 c0             	test   %rax,%rax
    54b8:	74 13                	je     54cd <do_check_any_chunk+0x33>
    54ba:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    54be:	48 8b 40 08          	mov    0x8(%rax),%rax
    54c2:	48 83 f8 0b          	cmp    $0xb,%rax
    54c6:	74 05                	je     54cd <do_check_any_chunk+0x33>
    54c8:	e8 cf 74 00 00       	callq  c99c <abort>
  assert(ok_address(m, p));
    54cd:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    54d1:	48 8b 40 18          	mov    0x18(%rax),%rax
    54d5:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    54d9:	73 05                	jae    54e0 <do_check_any_chunk+0x46>
    54db:	e8 bc 74 00 00       	callq  c99c <abort>
}
    54e0:	90                   	nop
    54e1:	c9                   	leaveq 
    54e2:	c3                   	retq   

00000000000054e3 <do_check_top_chunk>:

/* Check properties of top chunk */
static void do_check_top_chunk(mstate m, mchunkptr p) {
    54e3:	55                   	push   %rbp
    54e4:	48 89 e5             	mov    %rsp,%rbp
    54e7:	48 83 ec 20          	sub    $0x20,%rsp
    54eb:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    54ef:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  msegmentptr sp = segment_holding(m, (char*)p);
    54f3:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    54f7:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    54fb:	48 89 d6             	mov    %rdx,%rsi
    54fe:	48 89 c7             	mov    %rax,%rdi
    5501:	e8 fc fd ff ff       	callq  5302 <segment_holding>
    5506:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
  size_t  sz = p->head & ~INUSE_BITS; /* third-lowest bit can be set! */
    550a:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    550e:	48 8b 40 08          	mov    0x8(%rax),%rax
    5512:	48 83 e0 fc          	and    $0xfffffffffffffffc,%rax
    5516:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  assert(sp != 0);
    551a:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    551f:	75 05                	jne    5526 <do_check_top_chunk+0x43>
    5521:	e8 76 74 00 00       	callq  c99c <abort>
  assert((is_aligned(chunk2mem(p))) || (p->head == FENCEPOST_HEAD));
    5526:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    552a:	48 83 c0 10          	add    $0x10,%rax
    552e:	83 e0 0f             	and    $0xf,%eax
    5531:	48 85 c0             	test   %rax,%rax
    5534:	74 13                	je     5549 <do_check_top_chunk+0x66>
    5536:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    553a:	48 8b 40 08          	mov    0x8(%rax),%rax
    553e:	48 83 f8 0b          	cmp    $0xb,%rax
    5542:	74 05                	je     5549 <do_check_top_chunk+0x66>
    5544:	e8 53 74 00 00       	callq  c99c <abort>
  assert(ok_address(m, p));
    5549:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    554d:	48 8b 40 18          	mov    0x18(%rax),%rax
    5551:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    5555:	73 05                	jae    555c <do_check_top_chunk+0x79>
    5557:	e8 40 74 00 00       	callq  c99c <abort>
  assert(sz == m->topsize);
    555c:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    5560:	48 8b 40 10          	mov    0x10(%rax),%rax
    5564:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    5568:	74 05                	je     556f <do_check_top_chunk+0x8c>
    556a:	e8 2d 74 00 00       	callq  c99c <abort>
  assert(sz > 0);
    556f:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    5574:	75 05                	jne    557b <do_check_top_chunk+0x98>
    5576:	e8 21 74 00 00       	callq  c99c <abort>
  assert(sz == ((sp->base + sp->size) - (char*)p) - TOP_FOOT_SIZE);
    557b:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    557f:	48 8b 10             	mov    (%rax),%rdx
    5582:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5586:	48 8b 40 08          	mov    0x8(%rax),%rax
    558a:	48 01 d0             	add    %rdx,%rax
    558d:	48 89 c2             	mov    %rax,%rdx
    5590:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5594:	48 29 c2             	sub    %rax,%rdx
    5597:	48 89 d0             	mov    %rdx,%rax
    559a:	48 83 e8 50          	sub    $0x50,%rax
    559e:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    55a2:	74 05                	je     55a9 <do_check_top_chunk+0xc6>
    55a4:	e8 f3 73 00 00       	callq  c99c <abort>
  assert(pinuse(p));
    55a9:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    55ad:	48 8b 40 08          	mov    0x8(%rax),%rax
    55b1:	83 e0 01             	and    $0x1,%eax
    55b4:	48 85 c0             	test   %rax,%rax
    55b7:	75 05                	jne    55be <do_check_top_chunk+0xdb>
    55b9:	e8 de 73 00 00       	callq  c99c <abort>
  assert(!pinuse(chunk_plus_offset(p, sz)));
    55be:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    55c2:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    55c6:	48 01 d0             	add    %rdx,%rax
    55c9:	48 8b 40 08          	mov    0x8(%rax),%rax
    55cd:	83 e0 01             	and    $0x1,%eax
    55d0:	48 85 c0             	test   %rax,%rax
    55d3:	74 05                	je     55da <do_check_top_chunk+0xf7>
    55d5:	e8 c2 73 00 00       	callq  c99c <abort>
}
    55da:	90                   	nop
    55db:	c9                   	leaveq 
    55dc:	c3                   	retq   

00000000000055dd <do_check_mmapped_chunk>:

/* Check properties of (inuse) mmapped chunks */
static void do_check_mmapped_chunk(mstate m, mchunkptr p) {
    55dd:	55                   	push   %rbp
    55de:	48 89 e5             	mov    %rsp,%rbp
    55e1:	48 83 ec 20          	sub    $0x20,%rsp
    55e5:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    55e9:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  size_t  sz = chunksize(p);
    55ed:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    55f1:	48 8b 40 08          	mov    0x8(%rax),%rax
    55f5:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    55f9:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
  size_t len = (sz + (p->prev_foot) + MMAP_FOOT_PAD);
    55fd:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5601:	48 8b 10             	mov    (%rax),%rdx
    5604:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5608:	48 01 d0             	add    %rdx,%rax
    560b:	48 83 c0 20          	add    $0x20,%rax
    560f:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  assert(is_mmapped(p));
    5613:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5617:	48 8b 40 08          	mov    0x8(%rax),%rax
    561b:	83 e0 03             	and    $0x3,%eax
    561e:	48 85 c0             	test   %rax,%rax
    5621:	74 05                	je     5628 <do_check_mmapped_chunk+0x4b>
    5623:	e8 74 73 00 00       	callq  c99c <abort>
  assert(use_mmap(m));
    5628:	e8 6f 73 00 00       	callq  c99c <abort>

000000000000562d <do_check_inuse_chunk>:
  assert(chunk_plus_offset(p, sz)->head == FENCEPOST_HEAD);
  assert(chunk_plus_offset(p, sz+SIZE_T_SIZE)->head == 0);
}

/* Check properties of inuse chunks */
static void do_check_inuse_chunk(mstate m, mchunkptr p) {
    562d:	55                   	push   %rbp
    562e:	48 89 e5             	mov    %rsp,%rbp
    5631:	48 83 ec 10          	sub    $0x10,%rsp
    5635:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    5639:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
  do_check_any_chunk(m, p);
    563d:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    5641:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5645:	48 89 d6             	mov    %rdx,%rsi
    5648:	48 89 c7             	mov    %rax,%rdi
    564b:	e8 4a fe ff ff       	callq  549a <do_check_any_chunk>
  assert(is_inuse(p));
    5650:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5654:	48 8b 40 08          	mov    0x8(%rax),%rax
    5658:	83 e0 03             	and    $0x3,%eax
    565b:	48 83 f8 01          	cmp    $0x1,%rax
    565f:	75 05                	jne    5666 <do_check_inuse_chunk+0x39>
    5661:	e8 36 73 00 00       	callq  c99c <abort>
  assert(next_pinuse(p));
    5666:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    566a:	48 8b 40 08          	mov    0x8(%rax),%rax
    566e:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    5672:	48 89 c2             	mov    %rax,%rdx
    5675:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5679:	48 01 d0             	add    %rdx,%rax
    567c:	48 8b 40 08          	mov    0x8(%rax),%rax
    5680:	83 e0 01             	and    $0x1,%eax
    5683:	48 85 c0             	test   %rax,%rax
    5686:	75 05                	jne    568d <do_check_inuse_chunk+0x60>
    5688:	e8 0f 73 00 00       	callq  c99c <abort>
  /* If not pinuse and not mmapped, previous chunk has OK offset */
  assert(is_mmapped(p) || pinuse(p) || next_chunk(prev_chunk(p)) == p);
    568d:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5691:	48 8b 40 08          	mov    0x8(%rax),%rax
    5695:	83 e0 03             	and    $0x3,%eax
    5698:	48 85 c0             	test   %rax,%rax
    569b:	74 40                	je     56dd <do_check_inuse_chunk+0xb0>
    569d:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    56a1:	48 8b 40 08          	mov    0x8(%rax),%rax
    56a5:	83 e0 01             	and    $0x1,%eax
    56a8:	48 85 c0             	test   %rax,%rax
    56ab:	75 30                	jne    56dd <do_check_inuse_chunk+0xb0>
    56ad:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    56b1:	48 8b 00             	mov    (%rax),%rax
    56b4:	48 f7 d8             	neg    %rax
    56b7:	48 89 c2             	mov    %rax,%rdx
    56ba:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    56be:	48 01 d0             	add    %rdx,%rax
    56c1:	48 8b 40 08          	mov    0x8(%rax),%rax
    56c5:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    56c9:	48 89 c2             	mov    %rax,%rdx
    56cc:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    56d0:	48 8b 00             	mov    (%rax),%rax
    56d3:	48 39 c2             	cmp    %rax,%rdx
    56d6:	74 05                	je     56dd <do_check_inuse_chunk+0xb0>
    56d8:	e8 bf 72 00 00       	callq  c99c <abort>
  if (is_mmapped(p))
    56dd:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    56e1:	48 8b 40 08          	mov    0x8(%rax),%rax
    56e5:	83 e0 03             	and    $0x3,%eax
    56e8:	48 85 c0             	test   %rax,%rax
    56eb:	75 13                	jne    5700 <do_check_inuse_chunk+0xd3>
    do_check_mmapped_chunk(m, p);
    56ed:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    56f1:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    56f5:	48 89 d6             	mov    %rdx,%rsi
    56f8:	48 89 c7             	mov    %rax,%rdi
    56fb:	e8 dd fe ff ff       	callq  55dd <do_check_mmapped_chunk>
}
    5700:	90                   	nop
    5701:	c9                   	leaveq 
    5702:	c3                   	retq   

0000000000005703 <do_check_free_chunk>:

/* Check properties of free chunks */
static void do_check_free_chunk(mstate m, mchunkptr p) {
    5703:	55                   	push   %rbp
    5704:	48 89 e5             	mov    %rsp,%rbp
    5707:	48 83 ec 20          	sub    $0x20,%rsp
    570b:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    570f:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  size_t sz = chunksize(p);
    5713:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5717:	48 8b 40 08          	mov    0x8(%rax),%rax
    571b:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    571f:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
  mchunkptr next = chunk_plus_offset(p, sz);
    5723:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    5727:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    572b:	48 01 d0             	add    %rdx,%rax
    572e:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  do_check_any_chunk(m, p);
    5732:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    5736:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    573a:	48 89 d6             	mov    %rdx,%rsi
    573d:	48 89 c7             	mov    %rax,%rdi
    5740:	e8 55 fd ff ff       	callq  549a <do_check_any_chunk>
  assert(!is_inuse(p));
    5745:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5749:	48 8b 40 08          	mov    0x8(%rax),%rax
    574d:	83 e0 03             	and    $0x3,%eax
    5750:	48 83 f8 01          	cmp    $0x1,%rax
    5754:	74 05                	je     575b <do_check_free_chunk+0x58>
    5756:	e8 41 72 00 00       	callq  c99c <abort>
  assert(!next_pinuse(p));
    575b:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    575f:	48 8b 40 08          	mov    0x8(%rax),%rax
    5763:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    5767:	48 89 c2             	mov    %rax,%rdx
    576a:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    576e:	48 01 d0             	add    %rdx,%rax
    5771:	48 8b 40 08          	mov    0x8(%rax),%rax
    5775:	83 e0 01             	and    $0x1,%eax
    5778:	48 85 c0             	test   %rax,%rax
    577b:	74 05                	je     5782 <do_check_free_chunk+0x7f>
    577d:	e8 1a 72 00 00       	callq  c99c <abort>
  assert (!is_mmapped(p));
    5782:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5786:	48 8b 40 08          	mov    0x8(%rax),%rax
    578a:	83 e0 03             	and    $0x3,%eax
    578d:	48 85 c0             	test   %rax,%rax
    5790:	75 05                	jne    5797 <do_check_free_chunk+0x94>
    5792:	e8 05 72 00 00       	callq  c99c <abort>
  if (p != m->dv && p != m->top) {
    5797:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    579b:	48 8b 40 20          	mov    0x20(%rax),%rax
    579f:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    57a3:	0f 84 c8 00 00 00    	je     5871 <do_check_free_chunk+0x16e>
    57a9:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    57ad:	48 8b 40 28          	mov    0x28(%rax),%rax
    57b1:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    57b5:	0f 84 b6 00 00 00    	je     5871 <do_check_free_chunk+0x16e>
    if (sz >= MIN_CHUNK_SIZE) {
    57bb:	48 83 7d f0 1f       	cmpq   $0x1f,-0x10(%rbp)
    57c0:	0f 86 9f 00 00 00    	jbe    5865 <do_check_free_chunk+0x162>
      assert((sz & CHUNK_ALIGN_MASK) == 0);
    57c6:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    57ca:	83 e0 0f             	and    $0xf,%eax
    57cd:	48 85 c0             	test   %rax,%rax
    57d0:	74 05                	je     57d7 <do_check_free_chunk+0xd4>
    57d2:	e8 c5 71 00 00       	callq  c99c <abort>
      assert(is_aligned(chunk2mem(p)));
    57d7:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    57db:	48 83 c0 10          	add    $0x10,%rax
    57df:	83 e0 0f             	and    $0xf,%eax
    57e2:	48 85 c0             	test   %rax,%rax
    57e5:	74 05                	je     57ec <do_check_free_chunk+0xe9>
    57e7:	e8 b0 71 00 00       	callq  c99c <abort>
      assert(next->prev_foot == sz);
    57ec:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    57f0:	48 8b 00             	mov    (%rax),%rax
    57f3:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    57f7:	74 05                	je     57fe <do_check_free_chunk+0xfb>
    57f9:	e8 9e 71 00 00       	callq  c99c <abort>
      assert(pinuse(p));
    57fe:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5802:	48 8b 40 08          	mov    0x8(%rax),%rax
    5806:	83 e0 01             	and    $0x1,%eax
    5809:	48 85 c0             	test   %rax,%rax
    580c:	75 05                	jne    5813 <do_check_free_chunk+0x110>
    580e:	e8 89 71 00 00       	callq  c99c <abort>
      assert (next == m->top || is_inuse(next));
    5813:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    5817:	48 8b 40 28          	mov    0x28(%rax),%rax
    581b:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    581f:	74 16                	je     5837 <do_check_free_chunk+0x134>
    5821:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5825:	48 8b 40 08          	mov    0x8(%rax),%rax
    5829:	83 e0 03             	and    $0x3,%eax
    582c:	48 83 f8 01          	cmp    $0x1,%rax
    5830:	75 05                	jne    5837 <do_check_free_chunk+0x134>
    5832:	e8 65 71 00 00       	callq  c99c <abort>
      assert(p->fd->bk == p);
    5837:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    583b:	48 8b 40 10          	mov    0x10(%rax),%rax
    583f:	48 8b 40 18          	mov    0x18(%rax),%rax
    5843:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    5847:	74 05                	je     584e <do_check_free_chunk+0x14b>
    5849:	e8 4e 71 00 00       	callq  c99c <abort>
      assert(p->bk->fd == p);
    584e:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5852:	48 8b 40 18          	mov    0x18(%rax),%rax
    5856:	48 8b 40 10          	mov    0x10(%rax),%rax
    585a:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    585e:	74 11                	je     5871 <do_check_free_chunk+0x16e>
    5860:	e8 37 71 00 00       	callq  c99c <abort>
    }
    else  /* markers are always of size SIZE_T_SIZE */
      assert(sz == SIZE_T_SIZE);
    5865:	48 83 7d f0 08       	cmpq   $0x8,-0x10(%rbp)
    586a:	74 05                	je     5871 <do_check_free_chunk+0x16e>
    586c:	e8 2b 71 00 00       	callq  c99c <abort>
  }
}
    5871:	90                   	nop
    5872:	c9                   	leaveq 
    5873:	c3                   	retq   

0000000000005874 <do_check_malloced_chunk>:

/* Check properties of malloced chunks at the point they are malloced */
static void do_check_malloced_chunk(mstate m, void* mem, size_t s) {
    5874:	55                   	push   %rbp
    5875:	48 89 e5             	mov    %rsp,%rbp
    5878:	48 83 ec 30          	sub    $0x30,%rsp
    587c:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    5880:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    5884:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
  if (mem != 0) {
    5888:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
    588d:	74 7e                	je     590d <do_check_malloced_chunk+0x99>
    mchunkptr p = mem2chunk(mem);
    588f:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5893:	48 83 e8 10          	sub    $0x10,%rax
    5897:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    size_t sz = p->head & ~INUSE_BITS;
    589b:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    589f:	48 8b 40 08          	mov    0x8(%rax),%rax
    58a3:	48 83 e0 fc          	and    $0xfffffffffffffffc,%rax
    58a7:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    do_check_inuse_chunk(m, p);
    58ab:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    58af:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    58b3:	48 89 d6             	mov    %rdx,%rsi
    58b6:	48 89 c7             	mov    %rax,%rdi
    58b9:	e8 6f fd ff ff       	callq  562d <do_check_inuse_chunk>
    assert((sz & CHUNK_ALIGN_MASK) == 0);
    58be:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    58c2:	83 e0 0f             	and    $0xf,%eax
    58c5:	48 85 c0             	test   %rax,%rax
    58c8:	74 05                	je     58cf <do_check_malloced_chunk+0x5b>
    58ca:	e8 cd 70 00 00       	callq  c99c <abort>
    assert(sz >= MIN_CHUNK_SIZE);
    58cf:	48 83 7d f8 1f       	cmpq   $0x1f,-0x8(%rbp)
    58d4:	77 05                	ja     58db <do_check_malloced_chunk+0x67>
    58d6:	e8 c1 70 00 00       	callq  c99c <abort>
    assert(sz >= s);
    58db:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    58df:	48 3b 45 d8          	cmp    -0x28(%rbp),%rax
    58e3:	73 05                	jae    58ea <do_check_malloced_chunk+0x76>
    58e5:	e8 b2 70 00 00       	callq  c99c <abort>
    /* unless mmapped, size is less than MIN_CHUNK_SIZE more than request */
    assert(is_mmapped(p) || sz < (s + MIN_CHUNK_SIZE));
    58ea:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    58ee:	48 8b 40 08          	mov    0x8(%rax),%rax
    58f2:	83 e0 03             	and    $0x3,%eax
    58f5:	48 85 c0             	test   %rax,%rax
    58f8:	74 13                	je     590d <do_check_malloced_chunk+0x99>
    58fa:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    58fe:	48 83 c0 20          	add    $0x20,%rax
    5902:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    5906:	72 05                	jb     590d <do_check_malloced_chunk+0x99>
    5908:	e8 8f 70 00 00       	callq  c99c <abort>
  }
}
    590d:	90                   	nop
    590e:	c9                   	leaveq 
    590f:	c3                   	retq   

0000000000005910 <init_top>:


/* -------------------------- mspace management -------------------------- */

/* Initialize top chunk and its size */
static void init_top(mstate m, mchunkptr p, size_t psize) {
    5910:	55                   	push   %rbp
    5911:	48 89 e5             	mov    %rsp,%rbp
    5914:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    5918:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    591c:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
  /* Ensure alignment */
  size_t offset = align_offset(chunk2mem(p));
    5920:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5924:	48 83 c0 10          	add    $0x10,%rax
    5928:	83 e0 0f             	and    $0xf,%eax
    592b:	48 85 c0             	test   %rax,%rax
    592e:	74 10                	je     5940 <init_top+0x30>
    5930:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5934:	48 83 c0 10          	add    $0x10,%rax
    5938:	48 f7 d8             	neg    %rax
    593b:	83 e0 0f             	and    $0xf,%eax
    593e:	eb 05                	jmp    5945 <init_top+0x35>
    5940:	b8 00 00 00 00       	mov    $0x0,%eax
    5945:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  p = (mchunkptr)((char*)p + offset);
    5949:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    594d:	48 01 45 e0          	add    %rax,-0x20(%rbp)
  psize -= offset;
    5951:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5955:	48 29 45 d8          	sub    %rax,-0x28(%rbp)

  m->top = p;
    5959:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    595d:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    5961:	48 89 50 28          	mov    %rdx,0x28(%rax)
  m->topsize = psize;
    5965:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    5969:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    596d:	48 89 50 10          	mov    %rdx,0x10(%rax)
  p->head = psize | PINUSE_BIT;
    5971:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    5975:	48 83 c8 01          	or     $0x1,%rax
    5979:	48 89 c2             	mov    %rax,%rdx
    597c:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5980:	48 89 50 08          	mov    %rdx,0x8(%rax)
  /* set size of fake trailing chunk holding overhead space only once */
  chunk_plus_offset(p, psize)->head = TOP_FOOT_SIZE;
    5984:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    5988:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    598c:	48 01 d0             	add    %rdx,%rax
    598f:	48 c7 40 08 50 00 00 	movq   $0x50,0x8(%rax)
    5996:	00 
  m->trim_check = mparams.trim_threshold; /* reset on each update */
    5997:	48 8b 15 a2 b7 00 00 	mov    0xb7a2(%rip),%rdx        # 11140 <mparams+0x20>
    599e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    59a2:	48 89 50 30          	mov    %rdx,0x30(%rax)
}
    59a6:	90                   	nop
    59a7:	5d                   	pop    %rbp
    59a8:	c3                   	retq   

00000000000059a9 <init_bins>:

/* Initialize bins for a new mstate that is otherwise zeroed out */
static void init_bins(mstate m) {
    59a9:	55                   	push   %rbp
    59aa:	48 89 e5             	mov    %rsp,%rbp
    59ad:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  /* Establish circular links for smallbins */
  bindex_t i;
  for (i = 0; i < NSMALLBINS; ++i) {
    59b1:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    59b8:	eb 42                	jmp    59fc <init_bins+0x53>
    sbinptr bin = smallbin_at(m,i);
    59ba:	8b 45 f4             	mov    -0xc(%rbp),%eax
    59bd:	01 c0                	add    %eax,%eax
    59bf:	89 c0                	mov    %eax,%eax
    59c1:	48 83 c0 08          	add    $0x8,%rax
    59c5:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    59cc:	00 
    59cd:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    59d1:	48 01 d0             	add    %rdx,%rax
    59d4:	48 83 c0 08          	add    $0x8,%rax
    59d8:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    bin->fd = bin->bk = bin;
    59dc:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    59e0:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    59e4:	48 89 50 18          	mov    %rdx,0x18(%rax)
    59e8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    59ec:	48 8b 50 18          	mov    0x18(%rax),%rdx
    59f0:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    59f4:	48 89 50 10          	mov    %rdx,0x10(%rax)
  for (i = 0; i < NSMALLBINS; ++i) {
    59f8:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    59fc:	83 7d f4 1f          	cmpl   $0x1f,-0xc(%rbp)
    5a00:	76 b8                	jbe    59ba <init_bins+0x11>
  }
}
    5a02:	90                   	nop
    5a03:	5d                   	pop    %rbp
    5a04:	c3                   	retq   

0000000000005a05 <prepend_alloc>:
}
#endif /* PROCEED_ON_ERROR */

/* Allocate chunk and prepend remainder with chunk in successor base. */
static void* prepend_alloc(mstate m, char* newbase, char* oldbase,
                           size_t nb) {
    5a05:	55                   	push   %rbp
    5a06:	48 89 e5             	mov    %rsp,%rbp
    5a09:	48 81 ec 10 01 00 00 	sub    $0x110,%rsp
    5a10:	48 89 bd 08 ff ff ff 	mov    %rdi,-0xf8(%rbp)
    5a17:	48 89 b5 00 ff ff ff 	mov    %rsi,-0x100(%rbp)
    5a1e:	48 89 95 f8 fe ff ff 	mov    %rdx,-0x108(%rbp)
    5a25:	48 89 8d f0 fe ff ff 	mov    %rcx,-0x110(%rbp)
  mchunkptr p = align_as_chunk(newbase);
    5a2c:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    5a33:	48 83 c0 10          	add    $0x10,%rax
    5a37:	83 e0 0f             	and    $0xf,%eax
    5a3a:	48 85 c0             	test   %rax,%rax
    5a3d:	74 16                	je     5a55 <prepend_alloc+0x50>
    5a3f:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    5a46:	48 83 c0 10          	add    $0x10,%rax
    5a4a:	48 f7 d8             	neg    %rax
    5a4d:	83 e0 0f             	and    $0xf,%eax
    5a50:	48 89 c2             	mov    %rax,%rdx
    5a53:	eb 05                	jmp    5a5a <prepend_alloc+0x55>
    5a55:	ba 00 00 00 00       	mov    $0x0,%edx
    5a5a:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    5a61:	48 01 d0             	add    %rdx,%rax
    5a64:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
  mchunkptr oldfirst = align_as_chunk(oldbase);
    5a6b:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    5a72:	48 83 c0 10          	add    $0x10,%rax
    5a76:	83 e0 0f             	and    $0xf,%eax
    5a79:	48 85 c0             	test   %rax,%rax
    5a7c:	74 16                	je     5a94 <prepend_alloc+0x8f>
    5a7e:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    5a85:	48 83 c0 10          	add    $0x10,%rax
    5a89:	48 f7 d8             	neg    %rax
    5a8c:	83 e0 0f             	and    $0xf,%eax
    5a8f:	48 89 c2             	mov    %rax,%rdx
    5a92:	eb 05                	jmp    5a99 <prepend_alloc+0x94>
    5a94:	ba 00 00 00 00       	mov    $0x0,%edx
    5a99:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    5aa0:	48 01 d0             	add    %rdx,%rax
    5aa3:	48 89 85 28 ff ff ff 	mov    %rax,-0xd8(%rbp)
  size_t psize = (char*)oldfirst - (char*)p;
    5aaa:	48 8b 95 28 ff ff ff 	mov    -0xd8(%rbp),%rdx
    5ab1:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    5ab8:	48 29 c2             	sub    %rax,%rdx
    5abb:	48 89 d0             	mov    %rdx,%rax
    5abe:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
  mchunkptr q = chunk_plus_offset(p, nb);
    5ac5:	48 8b 95 68 ff ff ff 	mov    -0x98(%rbp),%rdx
    5acc:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    5ad3:	48 01 d0             	add    %rdx,%rax
    5ad6:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
  size_t qsize = psize - nb;
    5add:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    5ae4:	48 2b 85 f0 fe ff ff 	sub    -0x110(%rbp),%rax
    5aeb:	48 89 85 30 ff ff ff 	mov    %rax,-0xd0(%rbp)
  set_size_and_pinuse_of_inuse_chunk(m, p, nb);
    5af2:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    5af9:	48 83 c8 03          	or     $0x3,%rax
    5afd:	48 89 c2             	mov    %rax,%rdx
    5b00:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    5b07:	48 89 50 08          	mov    %rdx,0x8(%rax)
    5b0b:	48 8b 0d 0e b6 00 00 	mov    0xb60e(%rip),%rcx        # 11120 <mparams>
    5b12:	48 8b 95 08 ff ff ff 	mov    -0xf8(%rbp),%rdx
    5b19:	48 8b b5 68 ff ff ff 	mov    -0x98(%rbp),%rsi
    5b20:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    5b27:	48 01 f0             	add    %rsi,%rax
    5b2a:	48 31 ca             	xor    %rcx,%rdx
    5b2d:	48 89 10             	mov    %rdx,(%rax)

  assert((char*)oldfirst > (char*)q);
    5b30:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5b37:	48 3b 85 78 ff ff ff 	cmp    -0x88(%rbp),%rax
    5b3e:	77 05                	ja     5b45 <prepend_alloc+0x140>
    5b40:	e8 57 6e 00 00       	callq  c99c <abort>
  assert(pinuse(oldfirst));
    5b45:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5b4c:	48 8b 40 08          	mov    0x8(%rax),%rax
    5b50:	83 e0 01             	and    $0x1,%eax
    5b53:	48 85 c0             	test   %rax,%rax
    5b56:	75 05                	jne    5b5d <prepend_alloc+0x158>
    5b58:	e8 3f 6e 00 00       	callq  c99c <abort>
  assert(qsize >= MIN_CHUNK_SIZE);
    5b5d:	48 83 bd 30 ff ff ff 	cmpq   $0x1f,-0xd0(%rbp)
    5b64:	1f 
    5b65:	77 05                	ja     5b6c <prepend_alloc+0x167>
    5b67:	e8 30 6e 00 00       	callq  c99c <abort>

  /* consolidate remainder with first chunk of old base */
  if (oldfirst == m->top) {
    5b6c:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5b73:	48 8b 40 28          	mov    0x28(%rax),%rax
    5b77:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    5b7e:	75 75                	jne    5bf5 <prepend_alloc+0x1f0>
    size_t tsize = m->topsize += qsize;
    5b80:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5b87:	48 8b 50 10          	mov    0x10(%rax),%rdx
    5b8b:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    5b92:	48 01 c2             	add    %rax,%rdx
    5b95:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5b9c:	48 89 50 10          	mov    %rdx,0x10(%rax)
    5ba0:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5ba7:	48 8b 40 10          	mov    0x10(%rax),%rax
    5bab:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    m->top = q;
    5baf:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5bb6:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    5bbd:	48 89 50 28          	mov    %rdx,0x28(%rax)
    q->head = tsize | PINUSE_BIT;
    5bc1:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5bc5:	48 83 c8 01          	or     $0x1,%rax
    5bc9:	48 89 c2             	mov    %rax,%rdx
    5bcc:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    5bd3:	48 89 50 08          	mov    %rdx,0x8(%rax)
    check_top_chunk(m, q);
    5bd7:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    5bde:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5be5:	48 89 d6             	mov    %rdx,%rsi
    5be8:	48 89 c7             	mov    %rax,%rdi
    5beb:	e8 f3 f8 ff ff       	callq  54e3 <do_check_top_chunk>
    5bf0:	e9 95 0a 00 00       	jmpq   668a <prepend_alloc+0xc85>
  }
  else if (oldfirst == m->dv) {
    5bf5:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5bfc:	48 8b 40 20          	mov    0x20(%rax),%rax
    5c00:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    5c07:	75 71                	jne    5c7a <prepend_alloc+0x275>
    size_t dsize = m->dvsize += qsize;
    5c09:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5c10:	48 8b 50 08          	mov    0x8(%rax),%rdx
    5c14:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    5c1b:	48 01 c2             	add    %rax,%rdx
    5c1e:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5c25:	48 89 50 08          	mov    %rdx,0x8(%rax)
    5c29:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5c30:	48 8b 40 08          	mov    0x8(%rax),%rax
    5c34:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    m->dv = q;
    5c38:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5c3f:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    5c46:	48 89 50 20          	mov    %rdx,0x20(%rax)
    set_size_and_pinuse_of_free_chunk(q, dsize);
    5c4a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5c4e:	48 83 c8 01          	or     $0x1,%rax
    5c52:	48 89 c2             	mov    %rax,%rdx
    5c55:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    5c5c:	48 89 50 08          	mov    %rdx,0x8(%rax)
    5c60:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    5c67:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5c6b:	48 01 c2             	add    %rax,%rdx
    5c6e:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5c72:	48 89 02             	mov    %rax,(%rdx)
    5c75:	e9 10 0a 00 00       	jmpq   668a <prepend_alloc+0xc85>
  }
  else {
    if (!is_inuse(oldfirst)) {
    5c7a:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5c81:	48 8b 40 08          	mov    0x8(%rax),%rax
    5c85:	83 e0 03             	and    $0x3,%eax
    5c88:	48 83 f8 01          	cmp    $0x1,%rax
    5c8c:	0f 85 70 05 00 00    	jne    6202 <prepend_alloc+0x7fd>
      size_t nsize = chunksize(oldfirst);
    5c92:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5c99:	48 8b 40 08          	mov    0x8(%rax),%rax
    5c9d:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    5ca1:	48 89 45 80          	mov    %rax,-0x80(%rbp)
      unlink_chunk(m, oldfirst, nsize);
    5ca5:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    5ca9:	48 c1 e8 03          	shr    $0x3,%rax
    5cad:	48 83 f8 1f          	cmp    $0x1f,%rax
    5cb1:	0f 87 c6 01 00 00    	ja     5e7d <prepend_alloc+0x478>
    5cb7:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5cbe:	48 8b 40 10          	mov    0x10(%rax),%rax
    5cc2:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    5cc6:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5ccd:	48 8b 40 18          	mov    0x18(%rax),%rax
    5cd1:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    5cd5:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    5cd9:	48 c1 e8 03          	shr    $0x3,%rax
    5cdd:	89 85 18 ff ff ff    	mov    %eax,-0xe8(%rbp)
    5ce3:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5cea:	48 3b 45 c0          	cmp    -0x40(%rbp),%rax
    5cee:	75 05                	jne    5cf5 <prepend_alloc+0x2f0>
    5cf0:	e8 a7 6c 00 00       	callq  c99c <abort>
    5cf5:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5cfc:	48 3b 45 b8          	cmp    -0x48(%rbp),%rax
    5d00:	75 05                	jne    5d07 <prepend_alloc+0x302>
    5d02:	e8 95 6c 00 00       	callq  c99c <abort>
    5d07:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5d0e:	48 8b 40 08          	mov    0x8(%rax),%rax
    5d12:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    5d16:	48 89 c2             	mov    %rax,%rdx
    5d19:	8b 85 18 ff ff ff    	mov    -0xe8(%rbp),%eax
    5d1f:	c1 e0 03             	shl    $0x3,%eax
    5d22:	89 c0                	mov    %eax,%eax
    5d24:	48 39 c2             	cmp    %rax,%rdx
    5d27:	74 05                	je     5d2e <prepend_alloc+0x329>
    5d29:	e8 6e 6c 00 00       	callq  c99c <abort>
    5d2e:	8b 85 18 ff ff ff    	mov    -0xe8(%rbp),%eax
    5d34:	01 c0                	add    %eax,%eax
    5d36:	89 c0                	mov    %eax,%eax
    5d38:	48 83 c0 08          	add    $0x8,%rax
    5d3c:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    5d43:	00 
    5d44:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5d4b:	48 01 d0             	add    %rdx,%rax
    5d4e:	48 83 c0 08          	add    $0x8,%rax
    5d52:	48 39 45 b8          	cmp    %rax,-0x48(%rbp)
    5d56:	0f 94 c0             	sete   %al
    5d59:	0f b6 c0             	movzbl %al,%eax
    5d5c:	48 85 c0             	test   %rax,%rax
    5d5f:	75 48                	jne    5da9 <prepend_alloc+0x3a4>
    5d61:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5d68:	48 8b 40 18          	mov    0x18(%rax),%rax
    5d6c:	48 39 45 b8          	cmp    %rax,-0x48(%rbp)
    5d70:	0f 93 c0             	setae  %al
    5d73:	0f b6 c0             	movzbl %al,%eax
    5d76:	48 85 c0             	test   %rax,%rax
    5d79:	74 21                	je     5d9c <prepend_alloc+0x397>
    5d7b:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    5d7f:	48 8b 40 18          	mov    0x18(%rax),%rax
    5d83:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    5d8a:	0f 94 c0             	sete   %al
    5d8d:	0f b6 c0             	movzbl %al,%eax
    5d90:	48 85 c0             	test   %rax,%rax
    5d93:	74 07                	je     5d9c <prepend_alloc+0x397>
    5d95:	b8 01 00 00 00       	mov    $0x1,%eax
    5d9a:	eb 05                	jmp    5da1 <prepend_alloc+0x39c>
    5d9c:	b8 00 00 00 00       	mov    $0x0,%eax
    5da1:	85 c0                	test   %eax,%eax
    5da3:	0f 84 cf 00 00 00    	je     5e78 <prepend_alloc+0x473>
    5da9:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    5dad:	48 3b 45 b8          	cmp    -0x48(%rbp),%rax
    5db1:	75 2c                	jne    5ddf <prepend_alloc+0x3da>
    5db3:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5dba:	8b 10                	mov    (%rax),%edx
    5dbc:	8b 85 18 ff ff ff    	mov    -0xe8(%rbp),%eax
    5dc2:	be 01 00 00 00       	mov    $0x1,%esi
    5dc7:	89 c1                	mov    %eax,%ecx
    5dc9:	d3 e6                	shl    %cl,%esi
    5dcb:	89 f0                	mov    %esi,%eax
    5dcd:	f7 d0                	not    %eax
    5dcf:	21 c2                	and    %eax,%edx
    5dd1:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5dd8:	89 10                	mov    %edx,(%rax)
    5dda:	e9 0d 04 00 00       	jmpq   61ec <prepend_alloc+0x7e7>
    5ddf:	8b 85 18 ff ff ff    	mov    -0xe8(%rbp),%eax
    5de5:	01 c0                	add    %eax,%eax
    5de7:	89 c0                	mov    %eax,%eax
    5de9:	48 83 c0 08          	add    $0x8,%rax
    5ded:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    5df4:	00 
    5df5:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5dfc:	48 01 d0             	add    %rdx,%rax
    5dff:	48 83 c0 08          	add    $0x8,%rax
    5e03:	48 39 45 c0          	cmp    %rax,-0x40(%rbp)
    5e07:	0f 94 c0             	sete   %al
    5e0a:	0f b6 c0             	movzbl %al,%eax
    5e0d:	48 85 c0             	test   %rax,%rax
    5e10:	75 44                	jne    5e56 <prepend_alloc+0x451>
    5e12:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5e19:	48 8b 40 18          	mov    0x18(%rax),%rax
    5e1d:	48 39 45 c0          	cmp    %rax,-0x40(%rbp)
    5e21:	0f 93 c0             	setae  %al
    5e24:	0f b6 c0             	movzbl %al,%eax
    5e27:	48 85 c0             	test   %rax,%rax
    5e2a:	74 21                	je     5e4d <prepend_alloc+0x448>
    5e2c:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    5e30:	48 8b 40 10          	mov    0x10(%rax),%rax
    5e34:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    5e3b:	0f 94 c0             	sete   %al
    5e3e:	0f b6 c0             	movzbl %al,%eax
    5e41:	48 85 c0             	test   %rax,%rax
    5e44:	74 07                	je     5e4d <prepend_alloc+0x448>
    5e46:	b8 01 00 00 00       	mov    $0x1,%eax
    5e4b:	eb 05                	jmp    5e52 <prepend_alloc+0x44d>
    5e4d:	b8 00 00 00 00       	mov    $0x0,%eax
    5e52:	85 c0                	test   %eax,%eax
    5e54:	74 1d                	je     5e73 <prepend_alloc+0x46e>
    5e56:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    5e5a:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    5e5e:	48 89 50 18          	mov    %rdx,0x18(%rax)
    5e62:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    5e66:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
    5e6a:	48 89 50 10          	mov    %rdx,0x10(%rax)
    5e6e:	e9 79 03 00 00       	jmpq   61ec <prepend_alloc+0x7e7>
    5e73:	e8 24 6b 00 00       	callq  c99c <abort>
    5e78:	e8 1f 6b 00 00       	callq  c99c <abort>
    5e7d:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5e84:	48 89 45 88          	mov    %rax,-0x78(%rbp)
    5e88:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    5e8c:	48 8b 40 30          	mov    0x30(%rax),%rax
    5e90:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    5e94:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    5e98:	48 8b 40 18          	mov    0x18(%rax),%rax
    5e9c:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    5ea0:	0f 84 9e 00 00 00    	je     5f44 <prepend_alloc+0x53f>
    5ea6:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    5eaa:	48 8b 40 10          	mov    0x10(%rax),%rax
    5eae:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    5eb2:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    5eb6:	48 8b 40 18          	mov    0x18(%rax),%rax
    5eba:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
    5ec1:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5ec8:	48 8b 40 18          	mov    0x18(%rax),%rax
    5ecc:	48 39 45 98          	cmp    %rax,-0x68(%rbp)
    5ed0:	0f 93 c0             	setae  %al
    5ed3:	0f b6 c0             	movzbl %al,%eax
    5ed6:	48 85 c0             	test   %rax,%rax
    5ed9:	74 1e                	je     5ef9 <prepend_alloc+0x4f4>
    5edb:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    5edf:	48 8b 40 18          	mov    0x18(%rax),%rax
    5ee3:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    5ee7:	0f 94 c0             	sete   %al
    5eea:	0f b6 c0             	movzbl %al,%eax
    5eed:	48 85 c0             	test   %rax,%rax
    5ef0:	74 07                	je     5ef9 <prepend_alloc+0x4f4>
    5ef2:	b8 01 00 00 00       	mov    $0x1,%eax
    5ef7:	eb 05                	jmp    5efe <prepend_alloc+0x4f9>
    5ef9:	b8 00 00 00 00       	mov    $0x0,%eax
    5efe:	85 c0                	test   %eax,%eax
    5f00:	74 3d                	je     5f3f <prepend_alloc+0x53a>
    5f02:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    5f09:	48 8b 40 10          	mov    0x10(%rax),%rax
    5f0d:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    5f11:	0f 94 c0             	sete   %al
    5f14:	0f b6 c0             	movzbl %al,%eax
    5f17:	48 85 c0             	test   %rax,%rax
    5f1a:	74 23                	je     5f3f <prepend_alloc+0x53a>
    5f1c:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    5f20:	48 8b 95 38 ff ff ff 	mov    -0xc8(%rbp),%rdx
    5f27:	48 89 50 18          	mov    %rdx,0x18(%rax)
    5f2b:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    5f32:	48 8b 55 98          	mov    -0x68(%rbp),%rdx
    5f36:	48 89 50 10          	mov    %rdx,0x10(%rax)
    5f3a:	e9 f2 00 00 00       	jmpq   6031 <prepend_alloc+0x62c>
    5f3f:	e8 58 6a 00 00       	callq  c99c <abort>
    5f44:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    5f48:	48 83 c0 28          	add    $0x28,%rax
    5f4c:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
    5f53:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    5f5a:	48 8b 00             	mov    (%rax),%rax
    5f5d:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
    5f64:	48 83 bd 38 ff ff ff 	cmpq   $0x0,-0xc8(%rbp)
    5f6b:	00 
    5f6c:	75 4f                	jne    5fbd <prepend_alloc+0x5b8>
    5f6e:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    5f72:	48 83 c0 20          	add    $0x20,%rax
    5f76:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
    5f7d:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    5f84:	48 8b 00             	mov    (%rax),%rax
    5f87:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
    5f8e:	48 83 bd 38 ff ff ff 	cmpq   $0x0,-0xc8(%rbp)
    5f95:	00 
    5f96:	0f 84 95 00 00 00    	je     6031 <prepend_alloc+0x62c>
    5f9c:	eb 1f                	jmp    5fbd <prepend_alloc+0x5b8>
    5f9e:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    5fa5:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
    5fac:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    5fb3:	48 8b 00             	mov    (%rax),%rax
    5fb6:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
    5fbd:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    5fc4:	48 83 c0 28          	add    $0x28,%rax
    5fc8:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    5fcf:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    5fd6:	48 8b 00             	mov    (%rax),%rax
    5fd9:	48 85 c0             	test   %rax,%rax
    5fdc:	75 c0                	jne    5f9e <prepend_alloc+0x599>
    5fde:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    5fe5:	48 83 c0 20          	add    $0x20,%rax
    5fe9:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    5ff0:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    5ff7:	48 8b 00             	mov    (%rax),%rax
    5ffa:	48 85 c0             	test   %rax,%rax
    5ffd:	75 9f                	jne    5f9e <prepend_alloc+0x599>
    5fff:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6006:	48 8b 40 18          	mov    0x18(%rax),%rax
    600a:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    6011:	0f 93 c0             	setae  %al
    6014:	0f b6 c0             	movzbl %al,%eax
    6017:	48 85 c0             	test   %rax,%rax
    601a:	74 10                	je     602c <prepend_alloc+0x627>
    601c:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    6023:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    602a:	eb 05                	jmp    6031 <prepend_alloc+0x62c>
    602c:	e8 6b 69 00 00       	callq  c99c <abort>
    6031:	48 83 7d 90 00       	cmpq   $0x0,-0x70(%rbp)
    6036:	0f 84 b0 01 00 00    	je     61ec <prepend_alloc+0x7e7>
    603c:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    6040:	8b 40 38             	mov    0x38(%rax),%eax
    6043:	89 c0                	mov    %eax,%eax
    6045:	48 83 c0 4a          	add    $0x4a,%rax
    6049:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    6050:	00 
    6051:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6058:	48 01 d0             	add    %rdx,%rax
    605b:	48 83 c0 08          	add    $0x8,%rax
    605f:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
    6063:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    6067:	48 8b 00             	mov    (%rax),%rax
    606a:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    606e:	75 46                	jne    60b6 <prepend_alloc+0x6b1>
    6070:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    6074:	48 8b 95 38 ff ff ff 	mov    -0xc8(%rbp),%rdx
    607b:	48 89 10             	mov    %rdx,(%rax)
    607e:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    6082:	48 8b 00             	mov    (%rax),%rax
    6085:	48 85 c0             	test   %rax,%rax
    6088:	75 7b                	jne    6105 <prepend_alloc+0x700>
    608a:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6091:	8b 50 04             	mov    0x4(%rax),%edx
    6094:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    6098:	8b 40 38             	mov    0x38(%rax),%eax
    609b:	be 01 00 00 00       	mov    $0x1,%esi
    60a0:	89 c1                	mov    %eax,%ecx
    60a2:	d3 e6                	shl    %cl,%esi
    60a4:	89 f0                	mov    %esi,%eax
    60a6:	f7 d0                	not    %eax
    60a8:	21 c2                	and    %eax,%edx
    60aa:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    60b1:	89 50 04             	mov    %edx,0x4(%rax)
    60b4:	eb 4f                	jmp    6105 <prepend_alloc+0x700>
    60b6:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    60bd:	48 8b 40 18          	mov    0x18(%rax),%rax
    60c1:	48 39 45 90          	cmp    %rax,-0x70(%rbp)
    60c5:	0f 93 c0             	setae  %al
    60c8:	0f b6 c0             	movzbl %al,%eax
    60cb:	48 85 c0             	test   %rax,%rax
    60ce:	74 30                	je     6100 <prepend_alloc+0x6fb>
    60d0:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    60d4:	48 8b 40 20          	mov    0x20(%rax),%rax
    60d8:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    60dc:	75 11                	jne    60ef <prepend_alloc+0x6ea>
    60de:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    60e2:	48 8b 95 38 ff ff ff 	mov    -0xc8(%rbp),%rdx
    60e9:	48 89 50 20          	mov    %rdx,0x20(%rax)
    60ed:	eb 16                	jmp    6105 <prepend_alloc+0x700>
    60ef:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    60f3:	48 8b 95 38 ff ff ff 	mov    -0xc8(%rbp),%rdx
    60fa:	48 89 50 28          	mov    %rdx,0x28(%rax)
    60fe:	eb 05                	jmp    6105 <prepend_alloc+0x700>
    6100:	e8 97 68 00 00       	callq  c99c <abort>
    6105:	48 83 bd 38 ff ff ff 	cmpq   $0x0,-0xc8(%rbp)
    610c:	00 
    610d:	0f 84 d9 00 00 00    	je     61ec <prepend_alloc+0x7e7>
    6113:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    611a:	48 8b 40 18          	mov    0x18(%rax),%rax
    611e:	48 39 85 38 ff ff ff 	cmp    %rax,-0xc8(%rbp)
    6125:	0f 93 c0             	setae  %al
    6128:	0f b6 c0             	movzbl %al,%eax
    612b:	48 85 c0             	test   %rax,%rax
    612e:	0f 84 b3 00 00 00    	je     61e7 <prepend_alloc+0x7e2>
    6134:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    613b:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    613f:	48 89 50 30          	mov    %rdx,0x30(%rax)
    6143:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    6147:	48 8b 40 20          	mov    0x20(%rax),%rax
    614b:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    614f:	48 83 7d a8 00       	cmpq   $0x0,-0x58(%rbp)
    6154:	74 3f                	je     6195 <prepend_alloc+0x790>
    6156:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    615d:	48 8b 40 18          	mov    0x18(%rax),%rax
    6161:	48 39 45 a8          	cmp    %rax,-0x58(%rbp)
    6165:	0f 93 c0             	setae  %al
    6168:	0f b6 c0             	movzbl %al,%eax
    616b:	48 85 c0             	test   %rax,%rax
    616e:	74 20                	je     6190 <prepend_alloc+0x78b>
    6170:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    6177:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    617b:	48 89 50 20          	mov    %rdx,0x20(%rax)
    617f:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    6183:	48 8b 95 38 ff ff ff 	mov    -0xc8(%rbp),%rdx
    618a:	48 89 50 30          	mov    %rdx,0x30(%rax)
    618e:	eb 05                	jmp    6195 <prepend_alloc+0x790>
    6190:	e8 07 68 00 00       	callq  c99c <abort>
    6195:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    6199:	48 8b 40 28          	mov    0x28(%rax),%rax
    619d:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    61a1:	48 83 7d b0 00       	cmpq   $0x0,-0x50(%rbp)
    61a6:	74 44                	je     61ec <prepend_alloc+0x7e7>
    61a8:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    61af:	48 8b 40 18          	mov    0x18(%rax),%rax
    61b3:	48 39 45 b0          	cmp    %rax,-0x50(%rbp)
    61b7:	0f 93 c0             	setae  %al
    61ba:	0f b6 c0             	movzbl %al,%eax
    61bd:	48 85 c0             	test   %rax,%rax
    61c0:	74 20                	je     61e2 <prepend_alloc+0x7dd>
    61c2:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    61c9:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    61cd:	48 89 50 28          	mov    %rdx,0x28(%rax)
    61d1:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    61d5:	48 8b 95 38 ff ff ff 	mov    -0xc8(%rbp),%rdx
    61dc:	48 89 50 30          	mov    %rdx,0x30(%rax)
    61e0:	eb 0a                	jmp    61ec <prepend_alloc+0x7e7>
    61e2:	e8 b5 67 00 00       	callq  c99c <abort>
    61e7:	e8 b0 67 00 00       	callq  c99c <abort>
      oldfirst = chunk_plus_offset(oldfirst, nsize);
    61ec:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    61f0:	48 01 85 28 ff ff ff 	add    %rax,-0xd8(%rbp)
      qsize += nsize;
    61f7:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    61fb:	48 01 85 30 ff ff ff 	add    %rax,-0xd0(%rbp)
    }
    set_free_with_pinuse(q, qsize, oldfirst);
    6202:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    6209:	48 8b 40 08          	mov    0x8(%rax),%rax
    620d:	48 83 e0 fe          	and    $0xfffffffffffffffe,%rax
    6211:	48 89 c2             	mov    %rax,%rdx
    6214:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    621b:	48 89 50 08          	mov    %rdx,0x8(%rax)
    621f:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    6226:	48 83 c8 01          	or     $0x1,%rax
    622a:	48 89 c2             	mov    %rax,%rdx
    622d:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    6234:	48 89 50 08          	mov    %rdx,0x8(%rax)
    6238:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    623f:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    6246:	48 01 c2             	add    %rax,%rdx
    6249:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    6250:	48 89 02             	mov    %rax,(%rdx)
    insert_chunk(m, q, qsize);
    6253:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    625a:	48 c1 e8 03          	shr    $0x3,%rax
    625e:	48 83 f8 1f          	cmp    $0x1f,%rax
    6262:	0f 87 18 01 00 00    	ja     6380 <prepend_alloc+0x97b>
    6268:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    626f:	48 c1 e8 03          	shr    $0x3,%rax
    6273:	89 85 24 ff ff ff    	mov    %eax,-0xdc(%rbp)
    6279:	8b 85 24 ff ff ff    	mov    -0xdc(%rbp),%eax
    627f:	01 c0                	add    %eax,%eax
    6281:	89 c0                	mov    %eax,%eax
    6283:	48 83 c0 08          	add    $0x8,%rax
    6287:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    628e:	00 
    628f:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6296:	48 01 d0             	add    %rdx,%rax
    6299:	48 83 c0 08          	add    $0x8,%rax
    629d:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    62a1:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    62a5:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    62ac:	48 83 bd 30 ff ff ff 	cmpq   $0x1f,-0xd0(%rbp)
    62b3:	1f 
    62b4:	77 05                	ja     62bb <prepend_alloc+0x8b6>
    62b6:	e8 e1 66 00 00       	callq  c99c <abort>
    62bb:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    62c2:	8b 10                	mov    (%rax),%edx
    62c4:	8b 85 24 ff ff ff    	mov    -0xdc(%rbp),%eax
    62ca:	be 01 00 00 00       	mov    $0x1,%esi
    62cf:	89 c1                	mov    %eax,%ecx
    62d1:	d3 e6                	shl    %cl,%esi
    62d3:	89 f0                	mov    %esi,%eax
    62d5:	21 d0                	and    %edx,%eax
    62d7:	85 c0                	test   %eax,%eax
    62d9:	75 27                	jne    6302 <prepend_alloc+0x8fd>
    62db:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    62e2:	8b 10                	mov    (%rax),%edx
    62e4:	8b 85 24 ff ff ff    	mov    -0xdc(%rbp),%eax
    62ea:	be 01 00 00 00       	mov    $0x1,%esi
    62ef:	89 c1                	mov    %eax,%ecx
    62f1:	d3 e6                	shl    %cl,%esi
    62f3:	89 f0                	mov    %esi,%eax
    62f5:	09 c2                	or     %eax,%edx
    62f7:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    62fe:	89 10                	mov    %edx,(%rax)
    6300:	eb 37                	jmp    6339 <prepend_alloc+0x934>
    6302:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    6306:	48 8b 50 10          	mov    0x10(%rax),%rdx
    630a:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6311:	48 8b 40 18          	mov    0x18(%rax),%rax
    6315:	48 39 c2             	cmp    %rax,%rdx
    6318:	0f 93 c0             	setae  %al
    631b:	0f b6 c0             	movzbl %al,%eax
    631e:	48 85 c0             	test   %rax,%rax
    6321:	74 11                	je     6334 <prepend_alloc+0x92f>
    6323:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    6327:	48 8b 40 10          	mov    0x10(%rax),%rax
    632b:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    6332:	eb 05                	jmp    6339 <prepend_alloc+0x934>
    6334:	e8 63 66 00 00       	callq  c99c <abort>
    6339:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    633d:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    6344:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6348:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    634f:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    6356:	48 89 50 18          	mov    %rdx,0x18(%rax)
    635a:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    6361:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    6368:	48 89 50 10          	mov    %rdx,0x10(%rax)
    636c:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    6373:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    6377:	48 89 50 18          	mov    %rdx,0x18(%rax)
    637b:	e9 f1 02 00 00       	jmpq   6671 <prepend_alloc+0xc6c>
    6380:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    6387:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    638b:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    6392:	48 c1 e8 08          	shr    $0x8,%rax
    6396:	89 85 1c ff ff ff    	mov    %eax,-0xe4(%rbp)
    639c:	83 bd 1c ff ff ff 00 	cmpl   $0x0,-0xe4(%rbp)
    63a3:	75 0c                	jne    63b1 <prepend_alloc+0x9ac>
    63a5:	c7 85 14 ff ff ff 00 	movl   $0x0,-0xec(%rbp)
    63ac:	00 00 00 
    63af:	eb 5d                	jmp    640e <prepend_alloc+0xa09>
    63b1:	81 bd 1c ff ff ff ff 	cmpl   $0xffff,-0xe4(%rbp)
    63b8:	ff 00 00 
    63bb:	76 0c                	jbe    63c9 <prepend_alloc+0x9c4>
    63bd:	c7 85 14 ff ff ff 1f 	movl   $0x1f,-0xec(%rbp)
    63c4:	00 00 00 
    63c7:	eb 45                	jmp    640e <prepend_alloc+0xa09>
    63c9:	0f bd 85 1c ff ff ff 	bsr    -0xe4(%rbp),%eax
    63d0:	83 f0 1f             	xor    $0x1f,%eax
    63d3:	ba 1f 00 00 00       	mov    $0x1f,%edx
    63d8:	29 c2                	sub    %eax,%edx
    63da:	89 d0                	mov    %edx,%eax
    63dc:	89 85 20 ff ff ff    	mov    %eax,-0xe0(%rbp)
    63e2:	8b 85 20 ff ff ff    	mov    -0xe0(%rbp),%eax
    63e8:	8d 34 00             	lea    (%rax,%rax,1),%esi
    63eb:	8b 85 20 ff ff ff    	mov    -0xe0(%rbp),%eax
    63f1:	83 c0 07             	add    $0x7,%eax
    63f4:	48 8b 95 30 ff ff ff 	mov    -0xd0(%rbp),%rdx
    63fb:	89 c1                	mov    %eax,%ecx
    63fd:	48 d3 ea             	shr    %cl,%rdx
    6400:	48 89 d0             	mov    %rdx,%rax
    6403:	83 e0 01             	and    $0x1,%eax
    6406:	01 f0                	add    %esi,%eax
    6408:	89 85 14 ff ff ff    	mov    %eax,-0xec(%rbp)
    640e:	8b 85 14 ff ff ff    	mov    -0xec(%rbp),%eax
    6414:	48 83 c0 4a          	add    $0x4a,%rax
    6418:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    641f:	00 
    6420:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6427:	48 01 d0             	add    %rdx,%rax
    642a:	48 83 c0 08          	add    $0x8,%rax
    642e:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    6432:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6436:	8b 95 14 ff ff ff    	mov    -0xec(%rbp),%edx
    643c:	89 50 38             	mov    %edx,0x38(%rax)
    643f:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6443:	48 c7 40 28 00 00 00 	movq   $0x0,0x28(%rax)
    644a:	00 
    644b:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    644f:	48 8b 50 28          	mov    0x28(%rax),%rdx
    6453:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6457:	48 89 50 20          	mov    %rdx,0x20(%rax)
    645b:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6462:	8b 50 04             	mov    0x4(%rax),%edx
    6465:	8b 85 14 ff ff ff    	mov    -0xec(%rbp),%eax
    646b:	be 01 00 00 00       	mov    $0x1,%esi
    6470:	89 c1                	mov    %eax,%ecx
    6472:	d3 e6                	shl    %cl,%esi
    6474:	89 f0                	mov    %esi,%eax
    6476:	21 d0                	and    %edx,%eax
    6478:	85 c0                	test   %eax,%eax
    647a:	75 5f                	jne    64db <prepend_alloc+0xad6>
    647c:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6483:	8b 50 04             	mov    0x4(%rax),%edx
    6486:	8b 85 14 ff ff ff    	mov    -0xec(%rbp),%eax
    648c:	be 01 00 00 00       	mov    $0x1,%esi
    6491:	89 c1                	mov    %eax,%ecx
    6493:	d3 e6                	shl    %cl,%esi
    6495:	89 f0                	mov    %esi,%eax
    6497:	09 c2                	or     %eax,%edx
    6499:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    64a0:	89 50 04             	mov    %edx,0x4(%rax)
    64a3:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    64a7:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    64ab:	48 89 10             	mov    %rdx,(%rax)
    64ae:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    64b2:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    64b6:	48 89 50 30          	mov    %rdx,0x30(%rax)
    64ba:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    64be:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    64c2:	48 89 50 18          	mov    %rdx,0x18(%rax)
    64c6:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    64ca:	48 8b 50 18          	mov    0x18(%rax),%rdx
    64ce:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    64d2:	48 89 50 10          	mov    %rdx,0x10(%rax)
    64d6:	e9 96 01 00 00       	jmpq   6671 <prepend_alloc+0xc6c>
    64db:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    64df:	48 8b 00             	mov    (%rax),%rax
    64e2:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
    64e9:	83 bd 14 ff ff ff 1f 	cmpl   $0x1f,-0xec(%rbp)
    64f0:	74 13                	je     6505 <prepend_alloc+0xb00>
    64f2:	8b 85 14 ff ff ff    	mov    -0xec(%rbp),%eax
    64f8:	d1 e8                	shr    %eax
    64fa:	ba 39 00 00 00       	mov    $0x39,%edx
    64ff:	29 c2                	sub    %eax,%edx
    6501:	89 d0                	mov    %edx,%eax
    6503:	eb 05                	jmp    650a <prepend_alloc+0xb05>
    6505:	b8 00 00 00 00       	mov    $0x0,%eax
    650a:	48 8b 95 30 ff ff ff 	mov    -0xd0(%rbp),%rdx
    6511:	89 c1                	mov    %eax,%ecx
    6513:	48 d3 e2             	shl    %cl,%rdx
    6516:	48 89 d0             	mov    %rdx,%rax
    6519:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
    6520:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    6527:	48 8b 40 08          	mov    0x8(%rax),%rax
    652b:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    652f:	48 39 85 30 ff ff ff 	cmp    %rax,-0xd0(%rbp)
    6536:	0f 84 a2 00 00 00    	je     65de <prepend_alloc+0xbd9>
    653c:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    6543:	48 c1 e8 3f          	shr    $0x3f,%rax
    6547:	48 83 c0 04          	add    $0x4,%rax
    654b:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    6552:	00 
    6553:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    655a:	48 01 d0             	add    %rdx,%rax
    655d:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    6561:	48 d1 a5 60 ff ff ff 	shlq   -0xa0(%rbp)
    6568:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    656c:	48 8b 00             	mov    (%rax),%rax
    656f:	48 85 c0             	test   %rax,%rax
    6572:	74 10                	je     6584 <prepend_alloc+0xb7f>
    6574:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    6578:	48 8b 00             	mov    (%rax),%rax
    657b:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
    6582:	eb 9c                	jmp    6520 <prepend_alloc+0xb1b>
    6584:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    658b:	48 8b 40 18          	mov    0x18(%rax),%rax
    658f:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    6593:	0f 93 c0             	setae  %al
    6596:	0f b6 c0             	movzbl %al,%eax
    6599:	48 85 c0             	test   %rax,%rax
    659c:	74 3b                	je     65d9 <prepend_alloc+0xbd4>
    659e:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    65a2:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    65a6:	48 89 10             	mov    %rdx,(%rax)
    65a9:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    65ad:	48 8b 95 58 ff ff ff 	mov    -0xa8(%rbp),%rdx
    65b4:	48 89 50 30          	mov    %rdx,0x30(%rax)
    65b8:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    65bc:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    65c0:	48 89 50 18          	mov    %rdx,0x18(%rax)
    65c4:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    65c8:	48 8b 50 18          	mov    0x18(%rax),%rdx
    65cc:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    65d0:	48 89 50 10          	mov    %rdx,0x10(%rax)
    65d4:	e9 98 00 00 00       	jmpq   6671 <prepend_alloc+0xc6c>
    65d9:	e8 be 63 00 00       	callq  c99c <abort>
    65de:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    65e5:	48 8b 40 10          	mov    0x10(%rax),%rax
    65e9:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    65ed:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    65f4:	48 8b 40 18          	mov    0x18(%rax),%rax
    65f8:	48 39 85 58 ff ff ff 	cmp    %rax,-0xa8(%rbp)
    65ff:	0f 93 c0             	setae  %al
    6602:	0f b6 c0             	movzbl %al,%eax
    6605:	48 85 c0             	test   %rax,%rax
    6608:	74 62                	je     666c <prepend_alloc+0xc67>
    660a:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6611:	48 8b 40 18          	mov    0x18(%rax),%rax
    6615:	48 39 45 d8          	cmp    %rax,-0x28(%rbp)
    6619:	0f 93 c0             	setae  %al
    661c:	0f b6 c0             	movzbl %al,%eax
    661f:	48 85 c0             	test   %rax,%rax
    6622:	74 48                	je     666c <prepend_alloc+0xc67>
    6624:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6628:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    662c:	48 89 50 18          	mov    %rdx,0x18(%rax)
    6630:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6634:	48 8b 50 18          	mov    0x18(%rax),%rdx
    6638:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    663f:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6643:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6647:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    664b:	48 89 50 10          	mov    %rdx,0x10(%rax)
    664f:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6653:	48 8b 95 58 ff ff ff 	mov    -0xa8(%rbp),%rdx
    665a:	48 89 50 18          	mov    %rdx,0x18(%rax)
    665e:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6662:	48 c7 40 30 00 00 00 	movq   $0x0,0x30(%rax)
    6669:	00 
    666a:	eb 05                	jmp    6671 <prepend_alloc+0xc6c>
    666c:	e8 2b 63 00 00       	callq  c99c <abort>
    check_free_chunk(m, q);
    6671:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    6678:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    667f:	48 89 d6             	mov    %rdx,%rsi
    6682:	48 89 c7             	mov    %rax,%rdi
    6685:	e8 79 f0 ff ff       	callq  5703 <do_check_free_chunk>
  }

  check_malloced_chunk(m, chunk2mem(p), nb);
    668a:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    6691:	48 8d 48 10          	lea    0x10(%rax),%rcx
    6695:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    669c:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    66a3:	48 89 ce             	mov    %rcx,%rsi
    66a6:	48 89 c7             	mov    %rax,%rdi
    66a9:	e8 c6 f1 ff ff       	callq  5874 <do_check_malloced_chunk>
  return chunk2mem(p);
    66ae:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    66b5:	48 83 c0 10          	add    $0x10,%rax
}
    66b9:	c9                   	leaveq 
    66ba:	c3                   	retq   

00000000000066bb <add_segment>:

/* Add a segment to hold a new noncontiguous region */
static void add_segment(mstate m, char* tbase, size_t tsize, flag_t mmapped) {
    66bb:	55                   	push   %rbp
    66bc:	48 89 e5             	mov    %rsp,%rbp
    66bf:	48 81 ec 00 01 00 00 	sub    $0x100,%rsp
    66c6:	48 89 bd 18 ff ff ff 	mov    %rdi,-0xe8(%rbp)
    66cd:	48 89 b5 10 ff ff ff 	mov    %rsi,-0xf0(%rbp)
    66d4:	48 89 95 08 ff ff ff 	mov    %rdx,-0xf8(%rbp)
    66db:	89 8d 04 ff ff ff    	mov    %ecx,-0xfc(%rbp)
  /* Determine locations and sizes of segment, fenceposts, old top */
  char* old_top = (char*)m->top;
    66e1:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    66e8:	48 8b 40 28          	mov    0x28(%rax),%rax
    66ec:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
  msegmentptr oldsp = segment_holding(m, old_top);
    66f3:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    66fa:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6701:	48 89 d6             	mov    %rdx,%rsi
    6704:	48 89 c7             	mov    %rax,%rdi
    6707:	e8 f6 eb ff ff       	callq  5302 <segment_holding>
    670c:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
  char* old_end = oldsp->base + oldsp->size;
    6713:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    671a:	48 8b 10             	mov    (%rax),%rdx
    671d:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    6724:	48 8b 40 08          	mov    0x8(%rax),%rax
    6728:	48 01 d0             	add    %rdx,%rax
    672b:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
  size_t ssize = pad_request(sizeof(struct malloc_segment));
    6732:	48 c7 85 78 ff ff ff 	movq   $0x30,-0x88(%rbp)
    6739:	30 00 00 00 
  char* rawsp = old_end - (ssize + FOUR_SIZE_T_SIZES + CHUNK_ALIGN_MASK);
    673d:	48 c7 c0 d1 ff ff ff 	mov    $0xffffffffffffffd1,%rax
    6744:	48 2b 85 78 ff ff ff 	sub    -0x88(%rbp),%rax
    674b:	48 89 c2             	mov    %rax,%rdx
    674e:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    6755:	48 01 d0             	add    %rdx,%rax
    6758:	48 89 45 80          	mov    %rax,-0x80(%rbp)
  size_t offset = align_offset(chunk2mem(rawsp));
    675c:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    6760:	48 83 c0 10          	add    $0x10,%rax
    6764:	83 e0 0f             	and    $0xf,%eax
    6767:	48 85 c0             	test   %rax,%rax
    676a:	74 10                	je     677c <add_segment+0xc1>
    676c:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    6770:	48 83 c0 10          	add    $0x10,%rax
    6774:	48 f7 d8             	neg    %rax
    6777:	83 e0 0f             	and    $0xf,%eax
    677a:	eb 05                	jmp    6781 <add_segment+0xc6>
    677c:	b8 00 00 00 00       	mov    $0x0,%eax
    6781:	48 89 45 88          	mov    %rax,-0x78(%rbp)
  char* asp = rawsp + offset;
    6785:	48 8b 55 80          	mov    -0x80(%rbp),%rdx
    6789:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    678d:	48 01 d0             	add    %rdx,%rax
    6790:	48 89 45 90          	mov    %rax,-0x70(%rbp)
  char* csp = (asp < (old_top + MIN_CHUNK_SIZE))? old_top : asp;
    6794:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    679b:	48 83 c0 20          	add    $0x20,%rax
    679f:	48 39 45 90          	cmp    %rax,-0x70(%rbp)
    67a3:	73 09                	jae    67ae <add_segment+0xf3>
    67a5:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    67ac:	eb 04                	jmp    67b2 <add_segment+0xf7>
    67ae:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    67b2:	48 89 45 98          	mov    %rax,-0x68(%rbp)
  mchunkptr sp = (mchunkptr)csp;
    67b6:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    67ba:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
  msegmentptr ss = (msegmentptr)(chunk2mem(sp));
    67be:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    67c2:	48 83 c0 10          	add    $0x10,%rax
    67c6:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
  mchunkptr tnext = chunk_plus_offset(sp, ssize);
    67ca:	48 8b 55 a0          	mov    -0x60(%rbp),%rdx
    67ce:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    67d5:	48 01 d0             	add    %rdx,%rax
    67d8:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
  mchunkptr p = tnext;
    67dc:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    67e0:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
  int nfences = 0;
    67e7:	c7 85 2c ff ff ff 00 	movl   $0x0,-0xd4(%rbp)
    67ee:	00 00 00 

  /* reset top to new space */
  init_top(m, (mchunkptr)tbase, tsize - TOP_FOOT_SIZE);
    67f1:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    67f8:	48 8d 50 b0          	lea    -0x50(%rax),%rdx
    67fc:	48 8b 8d 10 ff ff ff 	mov    -0xf0(%rbp),%rcx
    6803:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    680a:	48 89 ce             	mov    %rcx,%rsi
    680d:	48 89 c7             	mov    %rax,%rdi
    6810:	e8 fb f0 ff ff       	callq  5910 <init_top>

  /* Set up segment record */
  assert(is_aligned(ss));
    6815:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    6819:	83 e0 0f             	and    $0xf,%eax
    681c:	48 85 c0             	test   %rax,%rax
    681f:	74 05                	je     6826 <add_segment+0x16b>
    6821:	e8 76 61 00 00       	callq  c99c <abort>
  set_size_and_pinuse_of_inuse_chunk(m, sp, ssize);
    6826:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    682d:	48 83 c8 03          	or     $0x3,%rax
    6831:	48 89 c2             	mov    %rax,%rdx
    6834:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    6838:	48 89 50 08          	mov    %rdx,0x8(%rax)
    683c:	48 8b 0d dd a8 00 00 	mov    0xa8dd(%rip),%rcx        # 11120 <mparams>
    6843:	48 8b 95 18 ff ff ff 	mov    -0xe8(%rbp),%rdx
    684a:	48 8b 75 a0          	mov    -0x60(%rbp),%rsi
    684e:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    6855:	48 01 f0             	add    %rsi,%rax
    6858:	48 31 ca             	xor    %rcx,%rdx
    685b:	48 89 10             	mov    %rdx,(%rax)
  *ss = m->seg; /* Push current record */
    685e:	48 8b 4d a8          	mov    -0x58(%rbp),%rcx
    6862:	48 8b b5 18 ff ff ff 	mov    -0xe8(%rbp),%rsi
    6869:	48 8b 86 78 03 00 00 	mov    0x378(%rsi),%rax
    6870:	48 8b 96 80 03 00 00 	mov    0x380(%rsi),%rdx
    6877:	48 89 01             	mov    %rax,(%rcx)
    687a:	48 89 51 08          	mov    %rdx,0x8(%rcx)
    687e:	48 8b 86 88 03 00 00 	mov    0x388(%rsi),%rax
    6885:	48 8b 96 90 03 00 00 	mov    0x390(%rsi),%rdx
    688c:	48 89 41 10          	mov    %rax,0x10(%rcx)
    6890:	48 89 51 18          	mov    %rdx,0x18(%rcx)
  m->seg.base = tbase;
    6894:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    689b:	48 8b 95 10 ff ff ff 	mov    -0xf0(%rbp),%rdx
    68a2:	48 89 90 78 03 00 00 	mov    %rdx,0x378(%rax)
  m->seg.size = tsize;
    68a9:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    68b0:	48 8b 95 08 ff ff ff 	mov    -0xf8(%rbp),%rdx
    68b7:	48 89 90 80 03 00 00 	mov    %rdx,0x380(%rax)
  m->seg.sflags = mmapped;
    68be:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    68c5:	8b 95 04 ff ff ff    	mov    -0xfc(%rbp),%edx
    68cb:	89 90 90 03 00 00    	mov    %edx,0x390(%rax)
  m->seg.next = ss;
    68d1:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    68d8:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    68dc:	48 89 90 88 03 00 00 	mov    %rdx,0x388(%rax)

  /* Insert trailing fenceposts */
  for (;;) {
    mchunkptr nextp = chunk_plus_offset(p, SIZE_T_SIZE);
    68e3:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    68ea:	48 83 c0 08          	add    $0x8,%rax
    68ee:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    p->head = FENCEPOST_HEAD;
    68f2:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    68f9:	48 c7 40 08 0b 00 00 	movq   $0xb,0x8(%rax)
    6900:	00 
    ++nfences;
    6901:	83 85 2c ff ff ff 01 	addl   $0x1,-0xd4(%rbp)
    if ((char*)(&(nextp->head)) < old_end)
    6908:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    690c:	48 83 c0 08          	add    $0x8,%rax
    6910:	48 39 85 70 ff ff ff 	cmp    %rax,-0x90(%rbp)
    6917:	76 0d                	jbe    6926 <add_segment+0x26b>
      p = nextp;
    6919:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    691d:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
  for (;;) {
    6924:	eb bd                	jmp    68e3 <add_segment+0x228>
    else
      break;
    6926:	90                   	nop
  }
  assert(nfences >= 2);
    6927:	83 bd 2c ff ff ff 01 	cmpl   $0x1,-0xd4(%rbp)
    692e:	7f 05                	jg     6935 <add_segment+0x27a>
    6930:	e8 67 60 00 00       	callq  c99c <abort>

  /* Insert the rest of old top into a bin as an ordinary free chunk */
  if (csp != old_top) {
    6935:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    6939:	48 3b 85 60 ff ff ff 	cmp    -0xa0(%rbp),%rax
    6940:	0f 84 65 04 00 00    	je     6dab <add_segment+0x6f0>
    mchunkptr q = (mchunkptr)old_top;
    6946:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    694d:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    size_t psize = csp - old_top;
    6951:	48 8b 55 98          	mov    -0x68(%rbp),%rdx
    6955:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    695c:	48 29 c2             	sub    %rax,%rdx
    695f:	48 89 d0             	mov    %rdx,%rax
    6962:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    mchunkptr tn = chunk_plus_offset(q, psize);
    6966:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    696a:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    696e:	48 01 d0             	add    %rdx,%rax
    6971:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    set_free_with_pinuse(q, psize, tn);
    6975:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    6979:	48 8b 40 08          	mov    0x8(%rax),%rax
    697d:	48 83 e0 fe          	and    $0xfffffffffffffffe,%rax
    6981:	48 89 c2             	mov    %rax,%rdx
    6984:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    6988:	48 89 50 08          	mov    %rdx,0x8(%rax)
    698c:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6990:	48 83 c8 01          	or     $0x1,%rax
    6994:	48 89 c2             	mov    %rax,%rdx
    6997:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    699b:	48 89 50 08          	mov    %rdx,0x8(%rax)
    699f:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    69a3:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    69a7:	48 01 c2             	add    %rax,%rdx
    69aa:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    69ae:	48 89 02             	mov    %rax,(%rdx)
    insert_chunk(m, q, psize);
    69b1:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    69b5:	48 c1 e8 03          	shr    $0x3,%rax
    69b9:	48 83 f8 1f          	cmp    $0x1f,%rax
    69bd:	0f 87 06 01 00 00    	ja     6ac9 <add_segment+0x40e>
    69c3:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    69c7:	48 c1 e8 03          	shr    $0x3,%rax
    69cb:	89 85 3c ff ff ff    	mov    %eax,-0xc4(%rbp)
    69d1:	8b 85 3c ff ff ff    	mov    -0xc4(%rbp),%eax
    69d7:	01 c0                	add    %eax,%eax
    69d9:	89 c0                	mov    %eax,%eax
    69db:	48 83 c0 08          	add    $0x8,%rax
    69df:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    69e6:	00 
    69e7:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    69ee:	48 01 d0             	add    %rdx,%rax
    69f1:	48 83 c0 08          	add    $0x8,%rax
    69f5:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    69f9:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    69fd:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    6a04:	48 83 7d c8 1f       	cmpq   $0x1f,-0x38(%rbp)
    6a09:	77 05                	ja     6a10 <add_segment+0x355>
    6a0b:	e8 8c 5f 00 00       	callq  c99c <abort>
    6a10:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6a17:	8b 10                	mov    (%rax),%edx
    6a19:	8b 85 3c ff ff ff    	mov    -0xc4(%rbp),%eax
    6a1f:	be 01 00 00 00       	mov    $0x1,%esi
    6a24:	89 c1                	mov    %eax,%ecx
    6a26:	d3 e6                	shl    %cl,%esi
    6a28:	89 f0                	mov    %esi,%eax
    6a2a:	21 d0                	and    %edx,%eax
    6a2c:	85 c0                	test   %eax,%eax
    6a2e:	75 27                	jne    6a57 <add_segment+0x39c>
    6a30:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6a37:	8b 10                	mov    (%rax),%edx
    6a39:	8b 85 3c ff ff ff    	mov    -0xc4(%rbp),%eax
    6a3f:	be 01 00 00 00       	mov    $0x1,%esi
    6a44:	89 c1                	mov    %eax,%ecx
    6a46:	d3 e6                	shl    %cl,%esi
    6a48:	89 f0                	mov    %esi,%eax
    6a4a:	09 c2                	or     %eax,%edx
    6a4c:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6a53:	89 10                	mov    %edx,(%rax)
    6a55:	eb 37                	jmp    6a8e <add_segment+0x3d3>
    6a57:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    6a5b:	48 8b 50 10          	mov    0x10(%rax),%rdx
    6a5f:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6a66:	48 8b 40 18          	mov    0x18(%rax),%rax
    6a6a:	48 39 c2             	cmp    %rax,%rdx
    6a6d:	0f 93 c0             	setae  %al
    6a70:	0f b6 c0             	movzbl %al,%eax
    6a73:	48 85 c0             	test   %rax,%rax
    6a76:	74 11                	je     6a89 <add_segment+0x3ce>
    6a78:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    6a7c:	48 8b 40 10          	mov    0x10(%rax),%rax
    6a80:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    6a87:	eb 05                	jmp    6a8e <add_segment+0x3d3>
    6a89:	e8 0e 5f 00 00       	callq  c99c <abort>
    6a8e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    6a92:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    6a96:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6a9a:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6aa1:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    6aa5:	48 89 50 18          	mov    %rdx,0x18(%rax)
    6aa9:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    6aad:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    6ab4:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6ab8:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    6abc:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    6ac0:	48 89 50 18          	mov    %rdx,0x18(%rax)
    6ac4:	e9 e2 02 00 00       	jmpq   6dab <add_segment+0x6f0>
    6ac9:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    6acd:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    6ad1:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6ad5:	48 c1 e8 08          	shr    $0x8,%rax
    6ad9:	89 85 34 ff ff ff    	mov    %eax,-0xcc(%rbp)
    6adf:	83 bd 34 ff ff ff 00 	cmpl   $0x0,-0xcc(%rbp)
    6ae6:	75 0c                	jne    6af4 <add_segment+0x439>
    6ae8:	c7 85 30 ff ff ff 00 	movl   $0x0,-0xd0(%rbp)
    6aef:	00 00 00 
    6af2:	eb 5a                	jmp    6b4e <add_segment+0x493>
    6af4:	81 bd 34 ff ff ff ff 	cmpl   $0xffff,-0xcc(%rbp)
    6afb:	ff 00 00 
    6afe:	76 0c                	jbe    6b0c <add_segment+0x451>
    6b00:	c7 85 30 ff ff ff 1f 	movl   $0x1f,-0xd0(%rbp)
    6b07:	00 00 00 
    6b0a:	eb 42                	jmp    6b4e <add_segment+0x493>
    6b0c:	0f bd 85 34 ff ff ff 	bsr    -0xcc(%rbp),%eax
    6b13:	83 f0 1f             	xor    $0x1f,%eax
    6b16:	ba 1f 00 00 00       	mov    $0x1f,%edx
    6b1b:	29 c2                	sub    %eax,%edx
    6b1d:	89 d0                	mov    %edx,%eax
    6b1f:	89 85 38 ff ff ff    	mov    %eax,-0xc8(%rbp)
    6b25:	8b 85 38 ff ff ff    	mov    -0xc8(%rbp),%eax
    6b2b:	8d 34 00             	lea    (%rax,%rax,1),%esi
    6b2e:	8b 85 38 ff ff ff    	mov    -0xc8(%rbp),%eax
    6b34:	83 c0 07             	add    $0x7,%eax
    6b37:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    6b3b:	89 c1                	mov    %eax,%ecx
    6b3d:	48 d3 ea             	shr    %cl,%rdx
    6b40:	48 89 d0             	mov    %rdx,%rax
    6b43:	83 e0 01             	and    $0x1,%eax
    6b46:	01 f0                	add    %esi,%eax
    6b48:	89 85 30 ff ff ff    	mov    %eax,-0xd0(%rbp)
    6b4e:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    6b54:	48 83 c0 4a          	add    $0x4a,%rax
    6b58:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    6b5f:	00 
    6b60:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6b67:	48 01 d0             	add    %rdx,%rax
    6b6a:	48 83 c0 08          	add    $0x8,%rax
    6b6e:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    6b72:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6b76:	8b 95 30 ff ff ff    	mov    -0xd0(%rbp),%edx
    6b7c:	89 50 38             	mov    %edx,0x38(%rax)
    6b7f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6b83:	48 c7 40 28 00 00 00 	movq   $0x0,0x28(%rax)
    6b8a:	00 
    6b8b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6b8f:	48 8b 50 28          	mov    0x28(%rax),%rdx
    6b93:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6b97:	48 89 50 20          	mov    %rdx,0x20(%rax)
    6b9b:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6ba2:	8b 50 04             	mov    0x4(%rax),%edx
    6ba5:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    6bab:	be 01 00 00 00       	mov    $0x1,%esi
    6bb0:	89 c1                	mov    %eax,%ecx
    6bb2:	d3 e6                	shl    %cl,%esi
    6bb4:	89 f0                	mov    %esi,%eax
    6bb6:	21 d0                	and    %edx,%eax
    6bb8:	85 c0                	test   %eax,%eax
    6bba:	75 5f                	jne    6c1b <add_segment+0x560>
    6bbc:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6bc3:	8b 50 04             	mov    0x4(%rax),%edx
    6bc6:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    6bcc:	be 01 00 00 00       	mov    $0x1,%esi
    6bd1:	89 c1                	mov    %eax,%ecx
    6bd3:	d3 e6                	shl    %cl,%esi
    6bd5:	89 f0                	mov    %esi,%eax
    6bd7:	09 c2                	or     %eax,%edx
    6bd9:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6be0:	89 50 04             	mov    %edx,0x4(%rax)
    6be3:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    6be7:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    6beb:	48 89 10             	mov    %rdx,(%rax)
    6bee:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6bf2:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    6bf6:	48 89 50 30          	mov    %rdx,0x30(%rax)
    6bfa:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6bfe:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    6c02:	48 89 50 18          	mov    %rdx,0x18(%rax)
    6c06:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6c0a:	48 8b 50 18          	mov    0x18(%rax),%rdx
    6c0e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6c12:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6c16:	e9 90 01 00 00       	jmpq   6dab <add_segment+0x6f0>
    6c1b:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    6c1f:	48 8b 00             	mov    (%rax),%rax
    6c22:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    6c29:	83 bd 30 ff ff ff 1f 	cmpl   $0x1f,-0xd0(%rbp)
    6c30:	74 13                	je     6c45 <add_segment+0x58a>
    6c32:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    6c38:	d1 e8                	shr    %eax
    6c3a:	ba 39 00 00 00       	mov    $0x39,%edx
    6c3f:	29 c2                	sub    %eax,%edx
    6c41:	89 d0                	mov    %edx,%eax
    6c43:	eb 05                	jmp    6c4a <add_segment+0x58f>
    6c45:	b8 00 00 00 00       	mov    $0x0,%eax
    6c4a:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    6c4e:	89 c1                	mov    %eax,%ecx
    6c50:	48 d3 e2             	shl    %cl,%rdx
    6c53:	48 89 d0             	mov    %rdx,%rax
    6c56:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
    6c5d:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    6c64:	48 8b 40 08          	mov    0x8(%rax),%rax
    6c68:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    6c6c:	48 39 45 c8          	cmp    %rax,-0x38(%rbp)
    6c70:	0f 84 a2 00 00 00    	je     6d18 <add_segment+0x65d>
    6c76:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    6c7d:	48 c1 e8 3f          	shr    $0x3f,%rax
    6c81:	48 83 c0 04          	add    $0x4,%rax
    6c85:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    6c8c:	00 
    6c8d:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    6c94:	48 01 d0             	add    %rdx,%rax
    6c97:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    6c9b:	48 d1 a5 58 ff ff ff 	shlq   -0xa8(%rbp)
    6ca2:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    6ca6:	48 8b 00             	mov    (%rax),%rax
    6ca9:	48 85 c0             	test   %rax,%rax
    6cac:	74 10                	je     6cbe <add_segment+0x603>
    6cae:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    6cb2:	48 8b 00             	mov    (%rax),%rax
    6cb5:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    6cbc:	eb 9f                	jmp    6c5d <add_segment+0x5a2>
    6cbe:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6cc5:	48 8b 40 18          	mov    0x18(%rax),%rax
    6cc9:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    6ccd:	0f 93 c0             	setae  %al
    6cd0:	0f b6 c0             	movzbl %al,%eax
    6cd3:	48 85 c0             	test   %rax,%rax
    6cd6:	74 3b                	je     6d13 <add_segment+0x658>
    6cd8:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    6cdc:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    6ce0:	48 89 10             	mov    %rdx,(%rax)
    6ce3:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6ce7:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    6cee:	48 89 50 30          	mov    %rdx,0x30(%rax)
    6cf2:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6cf6:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    6cfa:	48 89 50 18          	mov    %rdx,0x18(%rax)
    6cfe:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6d02:	48 8b 50 18          	mov    0x18(%rax),%rdx
    6d06:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6d0a:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6d0e:	e9 98 00 00 00       	jmpq   6dab <add_segment+0x6f0>
    6d13:	e8 84 5c 00 00       	callq  c99c <abort>
    6d18:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    6d1f:	48 8b 40 10          	mov    0x10(%rax),%rax
    6d23:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    6d27:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6d2e:	48 8b 40 18          	mov    0x18(%rax),%rax
    6d32:	48 39 85 50 ff ff ff 	cmp    %rax,-0xb0(%rbp)
    6d39:	0f 93 c0             	setae  %al
    6d3c:	0f b6 c0             	movzbl %al,%eax
    6d3f:	48 85 c0             	test   %rax,%rax
    6d42:	74 62                	je     6da6 <add_segment+0x6eb>
    6d44:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6d4b:	48 8b 40 18          	mov    0x18(%rax),%rax
    6d4f:	48 39 45 e8          	cmp    %rax,-0x18(%rbp)
    6d53:	0f 93 c0             	setae  %al
    6d56:	0f b6 c0             	movzbl %al,%eax
    6d59:	48 85 c0             	test   %rax,%rax
    6d5c:	74 48                	je     6da6 <add_segment+0x6eb>
    6d5e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    6d62:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    6d66:	48 89 50 18          	mov    %rdx,0x18(%rax)
    6d6a:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    6d6e:	48 8b 50 18          	mov    0x18(%rax),%rdx
    6d72:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    6d79:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6d7d:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6d81:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    6d85:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6d89:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6d8d:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    6d94:	48 89 50 18          	mov    %rdx,0x18(%rax)
    6d98:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6d9c:	48 c7 40 30 00 00 00 	movq   $0x0,0x30(%rax)
    6da3:	00 
    6da4:	eb 05                	jmp    6dab <add_segment+0x6f0>
    6da6:	e8 f1 5b 00 00       	callq  c99c <abort>
  }

  check_top_chunk(m, m->top);
    6dab:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6db2:	48 8b 50 28          	mov    0x28(%rax),%rdx
    6db6:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6dbd:	48 89 d6             	mov    %rdx,%rsi
    6dc0:	48 89 c7             	mov    %rax,%rdi
    6dc3:	e8 1b e7 ff ff       	callq  54e3 <do_check_top_chunk>
}
    6dc8:	90                   	nop
    6dc9:	c9                   	leaveq 
    6dca:	c3                   	retq   

0000000000006dcb <sys_alloc>:

/* -------------------------- System allocation -------------------------- */

/* Get memory from system using MORECORE or MMAP */
static void* sys_alloc(mstate m, size_t nb) {
    6dcb:	55                   	push   %rbp
    6dcc:	48 89 e5             	mov    %rsp,%rbp
    6dcf:	48 81 ec c0 00 00 00 	sub    $0xc0,%rsp
    6dd6:	48 89 bd 48 ff ff ff 	mov    %rdi,-0xb8(%rbp)
    6ddd:	48 89 b5 40 ff ff ff 	mov    %rsi,-0xc0(%rbp)
  char* tbase = CMFAIL;
    6de4:	48 c7 85 60 ff ff ff 	movq   $0xffffffffffffffff,-0xa0(%rbp)
    6deb:	ff ff ff ff 
  size_t tsize = 0;
    6def:	48 c7 85 68 ff ff ff 	movq   $0x0,-0x98(%rbp)
    6df6:	00 00 00 00 
  flag_t mmap_flag = 0;
    6dfa:	c7 85 5c ff ff ff 00 	movl   $0x0,-0xa4(%rbp)
    6e01:	00 00 00 
  size_t asize; /* allocation size */

  ensure_initialization();
    6e04:	48 8b 05 15 a3 00 00 	mov    0xa315(%rip),%rax        # 11120 <mparams>
    6e0b:	48 85 c0             	test   %rax,%rax
    6e0e:	75 07                	jne    6e17 <sys_alloc+0x4c>
    6e10:	e8 4c e5 ff ff       	callq  5361 <init_mparams>
    6e15:	85 c0                	test   %eax,%eax
    6e17:	90                   	nop
    void* mem = mmap_alloc(m, nb);
    if (mem != 0)
      return mem;
  }

  asize = granularity_align(nb + SYS_ALLOC_PADDING);
    6e18:	48 8b 15 11 a3 00 00 	mov    0xa311(%rip),%rdx        # 11130 <mparams+0x10>
    6e1f:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    6e26:	48 01 d0             	add    %rdx,%rax
    6e29:	48 8d 50 5f          	lea    0x5f(%rax),%rdx
    6e2d:	48 8b 05 fc a2 00 00 	mov    0xa2fc(%rip),%rax        # 11130 <mparams+0x10>
    6e34:	48 f7 d8             	neg    %rax
    6e37:	48 21 d0             	and    %rdx,%rax
    6e3a:	48 89 45 88          	mov    %rax,-0x78(%rbp)
  if (asize <= nb)
    6e3e:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    6e42:	48 3b 85 40 ff ff ff 	cmp    -0xc0(%rbp),%rax
    6e49:	77 0a                	ja     6e55 <sys_alloc+0x8a>
    return 0; /* wraparound */
    6e4b:	b8 00 00 00 00       	mov    $0x0,%eax
    6e50:	e9 50 09 00 00       	jmpq   77a5 <sys_alloc+0x9da>
  if (m->footprint_limit != 0) {
    6e55:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6e5c:	48 8b 80 68 03 00 00 	mov    0x368(%rax),%rax
    6e63:	48 85 c0             	test   %rax,%rax
    6e66:	74 4b                	je     6eb3 <sys_alloc+0xe8>
    size_t fp = m->footprint + asize;
    6e68:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6e6f:	48 8b 90 58 03 00 00 	mov    0x358(%rax),%rdx
    6e76:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    6e7a:	48 01 d0             	add    %rdx,%rax
    6e7d:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    if (fp <= m->footprint || fp > m->footprint_limit)
    6e81:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6e88:	48 8b 80 58 03 00 00 	mov    0x358(%rax),%rax
    6e8f:	48 39 45 90          	cmp    %rax,-0x70(%rbp)
    6e93:	76 14                	jbe    6ea9 <sys_alloc+0xde>
    6e95:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6e9c:	48 8b 80 68 03 00 00 	mov    0x368(%rax),%rax
    6ea3:	48 39 45 90          	cmp    %rax,-0x70(%rbp)
    6ea7:	76 0a                	jbe    6eb3 <sys_alloc+0xe8>
      return 0;
    6ea9:	b8 00 00 00 00       	mov    $0x0,%eax
    6eae:	e9 f2 08 00 00       	jmpq   77a5 <sys_alloc+0x9da>
   we can malloc nb bytes upon success, so pad with enough space for
   top_foot, plus alignment-pad to make sure we don't lose bytes if
   not on boundary, and round this up to a granularity unit.
  */

  if (MORECORE_CONTIGUOUS && !use_noncontiguous(m)) {
    6eb3:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6eba:	8b 80 70 03 00 00    	mov    0x370(%rax),%eax
    6ec0:	83 e0 04             	and    $0x4,%eax
    6ec3:	85 c0                	test   %eax,%eax
    6ec5:	0f 85 37 03 00 00    	jne    7202 <sys_alloc+0x437>
    char* br = CMFAIL;
    6ecb:	48 c7 85 70 ff ff ff 	movq   $0xffffffffffffffff,-0x90(%rbp)
    6ed2:	ff ff ff ff 
    size_t ssize = asize; /* sbrk call size */
    6ed6:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    6eda:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
    msegmentptr ss = (m->top == 0)? 0 : segment_holding(m, (char*)m->top);
    6ee1:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6ee8:	48 8b 40 28          	mov    0x28(%rax),%rax
    6eec:	48 85 c0             	test   %rax,%rax
    6eef:	74 1f                	je     6f10 <sys_alloc+0x145>
    6ef1:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6ef8:	48 8b 50 28          	mov    0x28(%rax),%rdx
    6efc:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6f03:	48 89 d6             	mov    %rdx,%rsi
    6f06:	48 89 c7             	mov    %rax,%rdi
    6f09:	e8 f4 e3 ff ff       	callq  5302 <segment_holding>
    6f0e:	eb 05                	jmp    6f15 <sys_alloc+0x14a>
    6f10:	b8 00 00 00 00       	mov    $0x0,%eax
    6f15:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    ACQUIRE_MALLOC_GLOBAL_LOCK();
    6f19:	b8 01 00 00 00       	mov    $0x1,%eax
    6f1e:	87 05 dc a1 00 00    	xchg   %eax,0xa1dc(%rip)        # 11100 <malloc_global_mutex>
    6f24:	85 c0                	test   %eax,%eax
    6f26:	74 0c                	je     6f34 <sys_alloc+0x169>
    6f28:	48 8d 3d d1 a1 00 00 	lea    0xa1d1(%rip),%rdi        # 11100 <malloc_global_mutex>
    6f2f:	e8 99 e3 ff ff       	callq  52cd <spin_acquire_lock>

    if (ss == 0) {  /* First time through or recovery */
    6f34:	48 83 7d 98 00       	cmpq   $0x0,-0x68(%rbp)
    6f39:	0f 85 2f 01 00 00    	jne    706e <sys_alloc+0x2a3>
      char* base = (char*)CALL_MORECORE(0);
    6f3f:	bf 00 00 00 00       	mov    $0x0,%edi
    6f44:	e8 83 41 00 00       	callq  b0cc <sbrk>
    6f49:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
      if (base != CMFAIL) {
    6f4d:	48 83 7d a0 ff       	cmpq   $0xffffffffffffffff,-0x60(%rbp)
    6f52:	0f 84 ad 01 00 00    	je     7105 <sys_alloc+0x33a>
        size_t fp;
        /* Adjust to end on a page boundary */
        if (!is_page_aligned(base))
    6f58:	48 8b 05 c9 a1 00 00 	mov    0xa1c9(%rip),%rax        # 11128 <mparams+0x8>
    6f5f:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    6f63:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    6f67:	48 21 d0             	and    %rdx,%rax
    6f6a:	48 85 c0             	test   %rax,%rax
    6f6d:	74 30                	je     6f9f <sys_alloc+0x1d4>
          ssize += (page_align((size_t)base) - (size_t)base);
    6f6f:	48 8b 15 b2 a1 00 00 	mov    0xa1b2(%rip),%rdx        # 11128 <mparams+0x8>
    6f76:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    6f7a:	48 01 d0             	add    %rdx,%rax
    6f7d:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    6f81:	48 8b 05 a0 a1 00 00 	mov    0xa1a0(%rip),%rax        # 11128 <mparams+0x8>
    6f88:	48 f7 d8             	neg    %rax
    6f8b:	48 21 c2             	and    %rax,%rdx
    6f8e:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    6f92:	48 29 c2             	sub    %rax,%rdx
    6f95:	48 89 d0             	mov    %rdx,%rax
    6f98:	48 01 85 78 ff ff ff 	add    %rax,-0x88(%rbp)
        fp = m->footprint + ssize; /* recheck limits */
    6f9f:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6fa6:	48 8b 90 58 03 00 00 	mov    0x358(%rax),%rdx
    6fad:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    6fb4:	48 01 d0             	add    %rdx,%rax
    6fb7:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
        if (ssize > nb && ssize < HALF_MAX_SIZE_T &&
    6fbb:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    6fc2:	48 3b 85 40 ff ff ff 	cmp    -0xc0(%rbp),%rax
    6fc9:	0f 86 36 01 00 00    	jbe    7105 <sys_alloc+0x33a>
    6fcf:	48 b8 fe ff ff ff ff 	movabs $0x7ffffffffffffffe,%rax
    6fd6:	ff ff 7f 
    6fd9:	48 39 85 78 ff ff ff 	cmp    %rax,-0x88(%rbp)
    6fe0:	0f 87 1f 01 00 00    	ja     7105 <sys_alloc+0x33a>
            (m->footprint_limit == 0 ||
    6fe6:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6fed:	48 8b 80 68 03 00 00 	mov    0x368(%rax),%rax
        if (ssize > nb && ssize < HALF_MAX_SIZE_T &&
    6ff4:	48 85 c0             	test   %rax,%rax
    6ff7:	74 30                	je     7029 <sys_alloc+0x25e>
             (fp > m->footprint && fp <= m->footprint_limit)) &&
    6ff9:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7000:	48 8b 80 58 03 00 00 	mov    0x358(%rax),%rax
            (m->footprint_limit == 0 ||
    7007:	48 39 45 a8          	cmp    %rax,-0x58(%rbp)
    700b:	0f 86 f4 00 00 00    	jbe    7105 <sys_alloc+0x33a>
             (fp > m->footprint && fp <= m->footprint_limit)) &&
    7011:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7018:	48 8b 80 68 03 00 00 	mov    0x368(%rax),%rax
    701f:	48 39 45 a8          	cmp    %rax,-0x58(%rbp)
    7023:	0f 87 dc 00 00 00    	ja     7105 <sys_alloc+0x33a>
            (br = (char*)(CALL_MORECORE(ssize))) == base) {
    7029:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
             (fp > m->footprint && fp <= m->footprint_limit)) &&
    7030:	48 89 c7             	mov    %rax,%rdi
    7033:	e8 94 40 00 00       	callq  b0cc <sbrk>
    7038:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
    703f:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    7046:	48 3b 45 a0          	cmp    -0x60(%rbp),%rax
    704a:	0f 85 b5 00 00 00    	jne    7105 <sys_alloc+0x33a>
          tbase = base;
    7050:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    7054:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
          tsize = ssize;
    705b:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    7062:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
    7069:	e9 97 00 00 00       	jmpq   7105 <sys_alloc+0x33a>
        }
      }
    }
    else {
      /* Subtract out existing available top space from MORECORE request. */
      ssize = granularity_align(nb - m->topsize + SYS_ALLOC_PADDING);
    706e:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7075:	48 8b 40 10          	mov    0x10(%rax),%rax
    7079:	48 8b 95 40 ff ff ff 	mov    -0xc0(%rbp),%rdx
    7080:	48 29 c2             	sub    %rax,%rdx
    7083:	48 8b 05 a6 a0 00 00 	mov    0xa0a6(%rip),%rax        # 11130 <mparams+0x10>
    708a:	48 01 d0             	add    %rdx,%rax
    708d:	48 8d 50 5f          	lea    0x5f(%rax),%rdx
    7091:	48 8b 05 98 a0 00 00 	mov    0xa098(%rip),%rax        # 11130 <mparams+0x10>
    7098:	48 f7 d8             	neg    %rax
    709b:	48 21 d0             	and    %rdx,%rax
    709e:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
      /* Use mem here only if it did continuously extend old space */
      if (ssize < HALF_MAX_SIZE_T &&
    70a5:	48 b8 fe ff ff ff ff 	movabs $0x7ffffffffffffffe,%rax
    70ac:	ff ff 7f 
    70af:	48 39 85 78 ff ff ff 	cmp    %rax,-0x88(%rbp)
    70b6:	77 4d                	ja     7105 <sys_alloc+0x33a>
          (br = (char*)(CALL_MORECORE(ssize))) == ss->base+ss->size) {
    70b8:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
      if (ssize < HALF_MAX_SIZE_T &&
    70bf:	48 89 c7             	mov    %rax,%rdi
    70c2:	e8 05 40 00 00       	callq  b0cc <sbrk>
    70c7:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
          (br = (char*)(CALL_MORECORE(ssize))) == ss->base+ss->size) {
    70ce:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    70d2:	48 8b 10             	mov    (%rax),%rdx
    70d5:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    70d9:	48 8b 40 08          	mov    0x8(%rax),%rax
    70dd:	48 01 d0             	add    %rdx,%rax
      if (ssize < HALF_MAX_SIZE_T &&
    70e0:	48 39 85 70 ff ff ff 	cmp    %rax,-0x90(%rbp)
    70e7:	75 1c                	jne    7105 <sys_alloc+0x33a>
        tbase = br;
    70e9:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    70f0:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
        tsize = ssize;
    70f7:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    70fe:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
      }
    }

    if (tbase == CMFAIL) {    /* Cope with partial failure */
    7105:	48 83 bd 60 ff ff ff 	cmpq   $0xffffffffffffffff,-0xa0(%rbp)
    710c:	ff 
    710d:	0f 85 e4 00 00 00    	jne    71f7 <sys_alloc+0x42c>
      if (br != CMFAIL) {    /* Try to use/extend the space we did get */
    7113:	48 83 bd 70 ff ff ff 	cmpq   $0xffffffffffffffff,-0x90(%rbp)
    711a:	ff 
    711b:	0f 84 b0 00 00 00    	je     71d1 <sys_alloc+0x406>
        if (ssize < HALF_MAX_SIZE_T &&
    7121:	48 b8 fe ff ff ff ff 	movabs $0x7ffffffffffffffe,%rax
    7128:	ff ff 7f 
    712b:	48 39 85 78 ff ff ff 	cmp    %rax,-0x88(%rbp)
    7132:	0f 87 99 00 00 00    	ja     71d1 <sys_alloc+0x406>
            ssize < nb + SYS_ALLOC_PADDING) {
    7138:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    713f:	48 83 c0 60          	add    $0x60,%rax
        if (ssize < HALF_MAX_SIZE_T &&
    7143:	48 39 85 78 ff ff ff 	cmp    %rax,-0x88(%rbp)
    714a:	0f 83 81 00 00 00    	jae    71d1 <sys_alloc+0x406>
          size_t esize = granularity_align(nb + SYS_ALLOC_PADDING - ssize);
    7150:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    7157:	48 2b 85 78 ff ff ff 	sub    -0x88(%rbp),%rax
    715e:	48 89 c2             	mov    %rax,%rdx
    7161:	48 8b 05 c8 9f 00 00 	mov    0x9fc8(%rip),%rax        # 11130 <mparams+0x10>
    7168:	48 01 d0             	add    %rdx,%rax
    716b:	48 8d 50 5f          	lea    0x5f(%rax),%rdx
    716f:	48 8b 05 ba 9f 00 00 	mov    0x9fba(%rip),%rax        # 11130 <mparams+0x10>
    7176:	48 f7 d8             	neg    %rax
    7179:	48 21 d0             	and    %rdx,%rax
    717c:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
          if (esize < HALF_MAX_SIZE_T) {
    7180:	48 b8 fe ff ff ff ff 	movabs $0x7ffffffffffffffe,%rax
    7187:	ff ff 7f 
    718a:	48 39 45 b0          	cmp    %rax,-0x50(%rbp)
    718e:	77 41                	ja     71d1 <sys_alloc+0x406>
            char* end = (char*)CALL_MORECORE(esize);
    7190:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    7194:	48 89 c7             	mov    %rax,%rdi
    7197:	e8 30 3f 00 00       	callq  b0cc <sbrk>
    719c:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
            if (end != CMFAIL)
    71a0:	48 83 7d b8 ff       	cmpq   $0xffffffffffffffff,-0x48(%rbp)
    71a5:	74 0d                	je     71b4 <sys_alloc+0x3e9>
              ssize += esize;
    71a7:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    71ab:	48 01 85 78 ff ff ff 	add    %rax,-0x88(%rbp)
    71b2:	eb 1d                	jmp    71d1 <sys_alloc+0x406>
            else {            /* Can't use; try to release */
              (void) CALL_MORECORE(-ssize);
    71b4:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    71bb:	48 f7 d8             	neg    %rax
    71be:	48 89 c7             	mov    %rax,%rdi
    71c1:	e8 06 3f 00 00       	callq  b0cc <sbrk>
              br = CMFAIL;
    71c6:	48 c7 85 70 ff ff ff 	movq   $0xffffffffffffffff,-0x90(%rbp)
    71cd:	ff ff ff ff 
            }
          }
        }
      }
      if (br != CMFAIL) {    /* Use the space we did get */
    71d1:	48 83 bd 70 ff ff ff 	cmpq   $0xffffffffffffffff,-0x90(%rbp)
    71d8:	ff 
    71d9:	74 1c                	je     71f7 <sys_alloc+0x42c>
        tbase = br;
    71db:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    71e2:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
        tsize = ssize;
    71e9:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    71f0:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
      else
        disable_contiguous(m); /* Don't try contiguous path in the future */
#endif
    }

    RELEASE_MALLOC_GLOBAL_LOCK();
    71f7:	b8 00 00 00 00       	mov    $0x0,%eax
    71fc:	89 05 fe 9e 00 00    	mov    %eax,0x9efe(%rip)        # 11100 <malloc_global_mutex>
      tsize = asize;
      mmap_flag = USE_MMAP_BIT;
    }
  }

  if (HAVE_MORECORE && tbase == CMFAIL) { /* Try noncontiguous MORECORE */
    7202:	48 83 bd 60 ff ff ff 	cmpq   $0xffffffffffffffff,-0xa0(%rbp)
    7209:	ff 
    720a:	0f 85 b9 00 00 00    	jne    72c9 <sys_alloc+0x4fe>
    if (asize < HALF_MAX_SIZE_T) {
    7210:	48 b8 fe ff ff ff ff 	movabs $0x7ffffffffffffffe,%rax
    7217:	ff ff 7f 
    721a:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    721e:	0f 87 a5 00 00 00    	ja     72c9 <sys_alloc+0x4fe>
      char* br = CMFAIL;
    7224:	48 c7 45 c0 ff ff ff 	movq   $0xffffffffffffffff,-0x40(%rbp)
    722b:	ff 
      char* end = CMFAIL;
    722c:	48 c7 45 c8 ff ff ff 	movq   $0xffffffffffffffff,-0x38(%rbp)
    7233:	ff 
      ACQUIRE_MALLOC_GLOBAL_LOCK();
    7234:	b8 01 00 00 00       	mov    $0x1,%eax
    7239:	87 05 c1 9e 00 00    	xchg   %eax,0x9ec1(%rip)        # 11100 <malloc_global_mutex>
    723f:	85 c0                	test   %eax,%eax
    7241:	74 0c                	je     724f <sys_alloc+0x484>
    7243:	48 8d 3d b6 9e 00 00 	lea    0x9eb6(%rip),%rdi        # 11100 <malloc_global_mutex>
    724a:	e8 7e e0 ff ff       	callq  52cd <spin_acquire_lock>
      br = (char*)(CALL_MORECORE(asize));
    724f:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    7253:	48 89 c7             	mov    %rax,%rdi
    7256:	e8 71 3e 00 00       	callq  b0cc <sbrk>
    725b:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
      end = (char*)(CALL_MORECORE(0));
    725f:	bf 00 00 00 00       	mov    $0x0,%edi
    7264:	e8 63 3e 00 00       	callq  b0cc <sbrk>
    7269:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
      RELEASE_MALLOC_GLOBAL_LOCK();
    726d:	b8 00 00 00 00       	mov    $0x0,%eax
    7272:	89 05 88 9e 00 00    	mov    %eax,0x9e88(%rip)        # 11100 <malloc_global_mutex>
      if (br != CMFAIL && end != CMFAIL && br < end) {
    7278:	48 83 7d c0 ff       	cmpq   $0xffffffffffffffff,-0x40(%rbp)
    727d:	74 4a                	je     72c9 <sys_alloc+0x4fe>
    727f:	48 83 7d c8 ff       	cmpq   $0xffffffffffffffff,-0x38(%rbp)
    7284:	74 43                	je     72c9 <sys_alloc+0x4fe>
    7286:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    728a:	48 3b 45 c8          	cmp    -0x38(%rbp),%rax
    728e:	73 39                	jae    72c9 <sys_alloc+0x4fe>
        size_t ssize = end - br;
    7290:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    7294:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    7298:	48 29 c2             	sub    %rax,%rdx
    729b:	48 89 d0             	mov    %rdx,%rax
    729e:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
        if (ssize > nb + TOP_FOOT_SIZE) {
    72a2:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    72a9:	48 83 c0 50          	add    $0x50,%rax
    72ad:	48 39 45 d0          	cmp    %rax,-0x30(%rbp)
    72b1:	76 16                	jbe    72c9 <sys_alloc+0x4fe>
          tbase = br;
    72b3:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    72b7:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
          tsize = ssize;
    72be:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    72c2:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
        }
      }
    }
  }

  if (tbase != CMFAIL) {
    72c9:	48 83 bd 60 ff ff ff 	cmpq   $0xffffffffffffffff,-0xa0(%rbp)
    72d0:	ff 
    72d1:	0f 84 be 04 00 00    	je     7795 <sys_alloc+0x9ca>

    if ((m->footprint += tsize) > m->max_footprint)
    72d7:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    72de:	48 8b 90 58 03 00 00 	mov    0x358(%rax),%rdx
    72e5:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    72ec:	48 01 c2             	add    %rax,%rdx
    72ef:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    72f6:	48 89 90 58 03 00 00 	mov    %rdx,0x358(%rax)
    72fd:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7304:	48 8b 90 58 03 00 00 	mov    0x358(%rax),%rdx
    730b:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7312:	48 8b 80 60 03 00 00 	mov    0x360(%rax),%rax
    7319:	48 39 c2             	cmp    %rax,%rdx
    731c:	76 1c                	jbe    733a <sys_alloc+0x56f>
      m->max_footprint = m->footprint;
    731e:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7325:	48 8b 90 58 03 00 00 	mov    0x358(%rax),%rdx
    732c:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7333:	48 89 90 60 03 00 00 	mov    %rdx,0x360(%rax)

    if (!is_initialized(m)) { /* first-time initialization */
    733a:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7341:	48 8b 40 28          	mov    0x28(%rax),%rax
    7345:	48 85 c0             	test   %rax,%rax
    7348:	0f 85 3e 01 00 00    	jne    748c <sys_alloc+0x6c1>
      if (m->least_addr == 0 || tbase < m->least_addr)
    734e:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7355:	48 8b 40 18          	mov    0x18(%rax),%rax
    7359:	48 85 c0             	test   %rax,%rax
    735c:	74 14                	je     7372 <sys_alloc+0x5a7>
    735e:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7365:	48 8b 40 18          	mov    0x18(%rax),%rax
    7369:	48 39 85 60 ff ff ff 	cmp    %rax,-0xa0(%rbp)
    7370:	73 12                	jae    7384 <sys_alloc+0x5b9>
        m->least_addr = tbase;
    7372:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7379:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    7380:	48 89 50 18          	mov    %rdx,0x18(%rax)
      m->seg.base = tbase;
    7384:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    738b:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    7392:	48 89 90 78 03 00 00 	mov    %rdx,0x378(%rax)
      m->seg.size = tsize;
    7399:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    73a0:	48 8b 95 68 ff ff ff 	mov    -0x98(%rbp),%rdx
    73a7:	48 89 90 80 03 00 00 	mov    %rdx,0x380(%rax)
      m->seg.sflags = mmap_flag;
    73ae:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    73b5:	8b 95 5c ff ff ff    	mov    -0xa4(%rbp),%edx
    73bb:	89 90 90 03 00 00    	mov    %edx,0x390(%rax)
      m->magic = mparams.magic;
    73c1:	48 8b 15 58 9d 00 00 	mov    0x9d58(%rip),%rdx        # 11120 <mparams>
    73c8:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    73cf:	48 89 50 40          	mov    %rdx,0x40(%rax)
      m->release_checks = MAX_RELEASE_CHECK_RATE;
    73d3:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    73da:	48 c7 40 38 ff ff ff 	movq   $0xffffffffffffffff,0x38(%rax)
    73e1:	ff 
      init_bins(m);
    73e2:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    73e9:	48 89 c7             	mov    %rax,%rdi
    73ec:	e8 b8 e5 ff ff       	callq  59a9 <init_bins>
#if !ONLY_MSPACES
      if (is_global(m))
    73f1:	48 8d 05 68 9d 00 00 	lea    0x9d68(%rip),%rax        # 11160 <_gm_>
    73f8:	48 39 85 48 ff ff ff 	cmp    %rax,-0xb8(%rbp)
    73ff:	75 29                	jne    742a <sys_alloc+0x65f>
        init_top(m, (mchunkptr)tbase, tsize - TOP_FOOT_SIZE);
    7401:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    7408:	48 8d 50 b0          	lea    -0x50(%rax),%rdx
    740c:	48 8b 8d 60 ff ff ff 	mov    -0xa0(%rbp),%rcx
    7413:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    741a:	48 89 ce             	mov    %rcx,%rsi
    741d:	48 89 c7             	mov    %rax,%rdi
    7420:	e8 eb e4 ff ff       	callq  5910 <init_top>
    7425:	e9 5a 02 00 00       	jmpq   7684 <sys_alloc+0x8b9>
      else
#endif
      {
        /* Offset top by embedded malloc_state */
        mchunkptr mn = next_chunk(mem2chunk(m));
    742a:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7431:	48 83 e8 10          	sub    $0x10,%rax
    7435:	48 8b 40 08          	mov    0x8(%rax),%rax
    7439:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    743d:	48 8d 50 f0          	lea    -0x10(%rax),%rdx
    7441:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7448:	48 01 d0             	add    %rdx,%rax
    744b:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
        init_top(m, mn, (size_t)((tbase + tsize) - (char*)mn) -TOP_FOOT_SIZE);
    744f:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    7456:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    745d:	48 01 d0             	add    %rdx,%rax
    7460:	48 89 c2             	mov    %rax,%rdx
    7463:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    7467:	48 29 c2             	sub    %rax,%rdx
    746a:	48 89 d0             	mov    %rdx,%rax
    746d:	48 8d 50 b0          	lea    -0x50(%rax),%rdx
    7471:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    7475:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    747c:	48 89 ce             	mov    %rcx,%rsi
    747f:	48 89 c7             	mov    %rax,%rdi
    7482:	e8 89 e4 ff ff       	callq  5910 <init_top>
    7487:	e9 f8 01 00 00       	jmpq   7684 <sys_alloc+0x8b9>
      }
    }

    else {
      /* Try to merge with an existing segment */
      msegmentptr sp = &m->seg;
    748c:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7493:	48 05 78 03 00 00    	add    $0x378,%rax
    7499:	48 89 45 80          	mov    %rax,-0x80(%rbp)
      /* Only consider most recent segment if traversal suppressed */
      while (sp != 0 && tbase != sp->base + sp->size)
    749d:	eb 0c                	jmp    74ab <sys_alloc+0x6e0>
        sp = (NO_SEGMENT_TRAVERSAL) ? 0 : sp->next;
    749f:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    74a3:	48 8b 40 10          	mov    0x10(%rax),%rax
    74a7:	48 89 45 80          	mov    %rax,-0x80(%rbp)
      while (sp != 0 && tbase != sp->base + sp->size)
    74ab:	48 83 7d 80 00       	cmpq   $0x0,-0x80(%rbp)
    74b0:	74 1b                	je     74cd <sys_alloc+0x702>
    74b2:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    74b6:	48 8b 10             	mov    (%rax),%rdx
    74b9:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    74bd:	48 8b 40 08          	mov    0x8(%rax),%rax
    74c1:	48 01 d0             	add    %rdx,%rax
    74c4:	48 39 85 60 ff ff ff 	cmp    %rax,-0xa0(%rbp)
    74cb:	75 d2                	jne    749f <sys_alloc+0x6d4>
      if (sp != 0 &&
    74cd:	48 83 7d 80 00       	cmpq   $0x0,-0x80(%rbp)
    74d2:	0f 84 a9 00 00 00    	je     7581 <sys_alloc+0x7b6>
          !is_extern_segment(sp) &&
    74d8:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    74dc:	8b 40 18             	mov    0x18(%rax),%eax
    74df:	83 e0 08             	and    $0x8,%eax
      if (sp != 0 &&
    74e2:	85 c0                	test   %eax,%eax
    74e4:	0f 85 97 00 00 00    	jne    7581 <sys_alloc+0x7b6>
          !is_extern_segment(sp) &&
    74ea:	83 bd 5c ff ff ff 00 	cmpl   $0x0,-0xa4(%rbp)
    74f1:	0f 85 8a 00 00 00    	jne    7581 <sys_alloc+0x7b6>
          (sp->sflags & USE_MMAP_BIT) == mmap_flag &&
          segment_holds(sp, m->top)) { /* append */
    74f7:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    74fe:	48 8b 50 28          	mov    0x28(%rax),%rdx
    7502:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    7506:	48 8b 00             	mov    (%rax),%rax
          (sp->sflags & USE_MMAP_BIT) == mmap_flag &&
    7509:	48 39 c2             	cmp    %rax,%rdx
    750c:	72 73                	jb     7581 <sys_alloc+0x7b6>
          segment_holds(sp, m->top)) { /* append */
    750e:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7515:	48 8b 50 28          	mov    0x28(%rax),%rdx
    7519:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    751d:	48 8b 08             	mov    (%rax),%rcx
    7520:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    7524:	48 8b 40 08          	mov    0x8(%rax),%rax
    7528:	48 01 c8             	add    %rcx,%rax
    752b:	48 39 c2             	cmp    %rax,%rdx
    752e:	73 51                	jae    7581 <sys_alloc+0x7b6>
        sp->size += tsize;
    7530:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    7534:	48 8b 50 08          	mov    0x8(%rax),%rdx
    7538:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    753f:	48 01 c2             	add    %rax,%rdx
    7542:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    7546:	48 89 50 08          	mov    %rdx,0x8(%rax)
        init_top(m, m->top, m->topsize + tsize);
    754a:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7551:	48 8b 50 10          	mov    0x10(%rax),%rdx
    7555:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    755c:	48 01 c2             	add    %rax,%rdx
    755f:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7566:	48 8b 48 28          	mov    0x28(%rax),%rcx
    756a:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7571:	48 89 ce             	mov    %rcx,%rsi
    7574:	48 89 c7             	mov    %rax,%rdi
    7577:	e8 94 e3 ff ff       	callq  5910 <init_top>
    757c:	e9 03 01 00 00       	jmpq   7684 <sys_alloc+0x8b9>
      }
      else {
        if (tbase < m->least_addr)
    7581:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7588:	48 8b 40 18          	mov    0x18(%rax),%rax
    758c:	48 39 85 60 ff ff ff 	cmp    %rax,-0xa0(%rbp)
    7593:	73 12                	jae    75a7 <sys_alloc+0x7dc>
          m->least_addr = tbase;
    7595:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    759c:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    75a3:	48 89 50 18          	mov    %rdx,0x18(%rax)
        sp = &m->seg;
    75a7:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    75ae:	48 05 78 03 00 00    	add    $0x378,%rax
    75b4:	48 89 45 80          	mov    %rax,-0x80(%rbp)
        while (sp != 0 && sp->base != tbase + tsize)
    75b8:	eb 0c                	jmp    75c6 <sys_alloc+0x7fb>
          sp = (NO_SEGMENT_TRAVERSAL) ? 0 : sp->next;
    75ba:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    75be:	48 8b 40 10          	mov    0x10(%rax),%rax
    75c2:	48 89 45 80          	mov    %rax,-0x80(%rbp)
        while (sp != 0 && sp->base != tbase + tsize)
    75c6:	48 83 7d 80 00       	cmpq   $0x0,-0x80(%rbp)
    75cb:	74 1d                	je     75ea <sys_alloc+0x81f>
    75cd:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    75d1:	48 8b 00             	mov    (%rax),%rax
    75d4:	48 8b 8d 60 ff ff ff 	mov    -0xa0(%rbp),%rcx
    75db:	48 8b 95 68 ff ff ff 	mov    -0x98(%rbp),%rdx
    75e2:	48 01 ca             	add    %rcx,%rdx
    75e5:	48 39 d0             	cmp    %rdx,%rax
    75e8:	75 d0                	jne    75ba <sys_alloc+0x7ef>
        if (sp != 0 &&
    75ea:	48 83 7d 80 00       	cmpq   $0x0,-0x80(%rbp)
    75ef:	74 70                	je     7661 <sys_alloc+0x896>
            !is_extern_segment(sp) &&
    75f1:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    75f5:	8b 40 18             	mov    0x18(%rax),%eax
    75f8:	83 e0 08             	and    $0x8,%eax
        if (sp != 0 &&
    75fb:	85 c0                	test   %eax,%eax
    75fd:	75 62                	jne    7661 <sys_alloc+0x896>
            !is_extern_segment(sp) &&
    75ff:	83 bd 5c ff ff ff 00 	cmpl   $0x0,-0xa4(%rbp)
    7606:	75 59                	jne    7661 <sys_alloc+0x896>
            (sp->sflags & USE_MMAP_BIT) == mmap_flag) {
          char* oldbase = sp->base;
    7608:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    760c:	48 8b 00             	mov    (%rax),%rax
    760f:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
          sp->base = tbase;
    7613:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    7617:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    761e:	48 89 10             	mov    %rdx,(%rax)
          sp->size += tsize;
    7621:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    7625:	48 8b 50 08          	mov    0x8(%rax),%rdx
    7629:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    7630:	48 01 c2             	add    %rax,%rdx
    7633:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    7637:	48 89 50 08          	mov    %rdx,0x8(%rax)
          return prepend_alloc(m, tbase, oldbase, nb);
    763b:	48 8b 8d 40 ff ff ff 	mov    -0xc0(%rbp),%rcx
    7642:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    7646:	48 8b b5 60 ff ff ff 	mov    -0xa0(%rbp),%rsi
    764d:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7654:	48 89 c7             	mov    %rax,%rdi
    7657:	e8 a9 e3 ff ff       	callq  5a05 <prepend_alloc>
    765c:	e9 44 01 00 00       	jmpq   77a5 <sys_alloc+0x9da>
        }
        else
          add_segment(m, tbase, tsize, mmap_flag);
    7661:	8b 8d 5c ff ff ff    	mov    -0xa4(%rbp),%ecx
    7667:	48 8b 95 68 ff ff ff 	mov    -0x98(%rbp),%rdx
    766e:	48 8b b5 60 ff ff ff 	mov    -0xa0(%rbp),%rsi
    7675:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    767c:	48 89 c7             	mov    %rax,%rdi
    767f:	e8 37 f0 ff ff       	callq  66bb <add_segment>
      }
    }

    if (nb < m->topsize) { /* Allocate from new or extended top space */
    7684:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    768b:	48 8b 40 10          	mov    0x10(%rax),%rax
    768f:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    7696:	0f 83 f9 00 00 00    	jae    7795 <sys_alloc+0x9ca>
      size_t rsize = m->topsize -= nb;
    769c:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    76a3:	48 8b 40 10          	mov    0x10(%rax),%rax
    76a7:	48 2b 85 40 ff ff ff 	sub    -0xc0(%rbp),%rax
    76ae:	48 89 c2             	mov    %rax,%rdx
    76b1:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    76b8:	48 89 50 10          	mov    %rdx,0x10(%rax)
    76bc:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    76c3:	48 8b 40 10          	mov    0x10(%rax),%rax
    76c7:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
      mchunkptr p = m->top;
    76cb:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    76d2:	48 8b 40 28          	mov    0x28(%rax),%rax
    76d6:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
      mchunkptr r = m->top = chunk_plus_offset(p, nb);
    76da:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    76de:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    76e5:	48 01 c2             	add    %rax,%rdx
    76e8:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    76ef:	48 89 50 28          	mov    %rdx,0x28(%rax)
    76f3:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    76fa:	48 8b 40 28          	mov    0x28(%rax),%rax
    76fe:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
      r->head = rsize | PINUSE_BIT;
    7702:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    7706:	48 83 c8 01          	or     $0x1,%rax
    770a:	48 89 c2             	mov    %rax,%rdx
    770d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    7711:	48 89 50 08          	mov    %rdx,0x8(%rax)
      set_size_and_pinuse_of_inuse_chunk(m, p, nb);
    7715:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    771c:	48 83 c8 03          	or     $0x3,%rax
    7720:	48 89 c2             	mov    %rax,%rdx
    7723:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    7727:	48 89 50 08          	mov    %rdx,0x8(%rax)
    772b:	48 8b 0d ee 99 00 00 	mov    0x99ee(%rip),%rcx        # 11120 <mparams>
    7732:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    7739:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi
    773d:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    7744:	48 01 f0             	add    %rsi,%rax
    7747:	48 31 ca             	xor    %rcx,%rdx
    774a:	48 89 10             	mov    %rdx,(%rax)
      check_top_chunk(m, m->top);
    774d:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7754:	48 8b 50 28          	mov    0x28(%rax),%rdx
    7758:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    775f:	48 89 d6             	mov    %rdx,%rsi
    7762:	48 89 c7             	mov    %rax,%rdi
    7765:	e8 79 dd ff ff       	callq  54e3 <do_check_top_chunk>
      check_malloced_chunk(m, chunk2mem(p), nb);
    776a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    776e:	48 8d 48 10          	lea    0x10(%rax),%rcx
    7772:	48 8b 95 40 ff ff ff 	mov    -0xc0(%rbp),%rdx
    7779:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7780:	48 89 ce             	mov    %rcx,%rsi
    7783:	48 89 c7             	mov    %rax,%rdi
    7786:	e8 e9 e0 ff ff       	callq  5874 <do_check_malloced_chunk>
      return chunk2mem(p);
    778b:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    778f:	48 83 c0 10          	add    $0x10,%rax
    7793:	eb 10                	jmp    77a5 <sys_alloc+0x9da>
    }
  }

  MALLOC_FAILURE_ACTION;
    7795:	e8 78 3e 00 00       	callq  b612 <__errno>
    779a:	c7 00 0c 00 00 00    	movl   $0xc,(%rax)
  return 0;
    77a0:	b8 00 00 00 00       	mov    $0x0,%eax
}
    77a5:	c9                   	leaveq 
    77a6:	c3                   	retq   

00000000000077a7 <release_unused_segments>:

/* -----------------------  system deallocation -------------------------- */

/* Unmap and unlink any mmapped segments that don't contain used chunks */
static size_t release_unused_segments(mstate m) {
    77a7:	55                   	push   %rbp
    77a8:	48 89 e5             	mov    %rsp,%rbp
    77ab:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
  size_t released = 0;
    77af:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    77b6:	00 
  int nsegs = 0;
    77b7:	c7 45 cc 00 00 00 00 	movl   $0x0,-0x34(%rbp)
  msegmentptr pred = &m->seg;
    77be:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    77c2:	48 05 78 03 00 00    	add    $0x378,%rax
    77c8:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
  msegmentptr sp = pred->next;
    77cc:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    77d0:	48 8b 40 10          	mov    0x10(%rax),%rax
    77d4:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
  while (sp != 0) {
    77d8:	eb 37                	jmp    7811 <release_unused_segments+0x6a>
    char* base = sp->base;
    77da:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    77de:	48 8b 00             	mov    (%rax),%rax
    77e1:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    size_t size = sp->size;
    77e5:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    77e9:	48 8b 40 08          	mov    0x8(%rax),%rax
    77ed:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    msegmentptr next = sp->next;
    77f1:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    77f5:	48 8b 40 10          	mov    0x10(%rax),%rax
    77f9:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    ++nsegs;
    77fd:	83 45 cc 01          	addl   $0x1,-0x34(%rbp)
        }
      }
    }
    if (NO_SEGMENT_TRAVERSAL) /* scan only first segment */
      break;
    pred = sp;
    7801:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    7805:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    sp = next;
    7809:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    780d:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
  while (sp != 0) {
    7811:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    7816:	75 c2                	jne    77da <release_unused_segments+0x33>
  }
  /* Reset check counter */
  m->release_checks = (((size_t) nsegs > (size_t) MAX_RELEASE_CHECK_RATE)?
    7818:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    781c:	48 c7 40 38 ff ff ff 	movq   $0xffffffffffffffff,0x38(%rax)
    7823:	ff 
                       (size_t) nsegs : (size_t) MAX_RELEASE_CHECK_RATE);
  return released;
    7824:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
}
    7828:	5d                   	pop    %rbp
    7829:	c3                   	retq   

000000000000782a <sys_trim>:

static int sys_trim(mstate m, size_t pad) {
    782a:	55                   	push   %rbp
    782b:	48 89 e5             	mov    %rsp,%rbp
    782e:	48 83 ec 50          	sub    $0x50,%rsp
    7832:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    7836:	48 89 75 b0          	mov    %rsi,-0x50(%rbp)
  size_t released = 0;
    783a:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    7841:	00 
  ensure_initialization();
    7842:	48 8b 05 d7 98 00 00 	mov    0x98d7(%rip),%rax        # 11120 <mparams>
    7849:	48 85 c0             	test   %rax,%rax
    784c:	75 07                	jne    7855 <sys_trim+0x2b>
    784e:	e8 0e db ff ff       	callq  5361 <init_mparams>
    7853:	85 c0                	test   %eax,%eax
    7855:	90                   	nop
  if (pad < MAX_REQUEST && is_initialized(m)) {
    7856:	48 81 7d b0 7f ff ff 	cmpq   $0xffffffffffffff7f,-0x50(%rbp)
    785d:	ff 
    785e:	0f 87 e5 01 00 00    	ja     7a49 <sys_trim+0x21f>
    7864:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    7868:	48 8b 40 28          	mov    0x28(%rax),%rax
    786c:	48 85 c0             	test   %rax,%rax
    786f:	0f 84 d4 01 00 00    	je     7a49 <sys_trim+0x21f>
    pad += TOP_FOOT_SIZE; /* ensure enough room for segment overhead */
    7875:	48 83 45 b0 50       	addq   $0x50,-0x50(%rbp)

    if (m->topsize > pad) {
    787a:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    787e:	48 8b 40 10          	mov    0x10(%rax),%rax
    7882:	48 39 45 b0          	cmp    %rax,-0x50(%rbp)
    7886:	0f 83 95 01 00 00    	jae    7a21 <sys_trim+0x1f7>
      /* Shrink top space in granularity-size units, keeping at least one */
      size_t unit = mparams.granularity;
    788c:	48 8b 05 9d 98 00 00 	mov    0x989d(%rip),%rax        # 11130 <mparams+0x10>
    7893:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
      size_t extra = ((m->topsize - pad + (unit - SIZE_T_ONE)) / unit -
    7897:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    789b:	48 8b 40 10          	mov    0x10(%rax),%rax
    789f:	48 2b 45 b0          	sub    -0x50(%rbp),%rax
    78a3:	48 89 c2             	mov    %rax,%rdx
    78a6:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    78aa:	48 01 d0             	add    %rdx,%rax
    78ad:	48 83 e8 01          	sub    $0x1,%rax
    78b1:	ba 00 00 00 00       	mov    $0x0,%edx
    78b6:	48 f7 75 d8          	divq   -0x28(%rbp)
    78ba:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    78be:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    78c2:	48 0f af c2          	imul   %rdx,%rax
    78c6:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
                      SIZE_T_ONE) * unit;
      msegmentptr sp = segment_holding(m, (char*)m->top);
    78ca:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    78ce:	48 8b 50 28          	mov    0x28(%rax),%rdx
    78d2:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    78d6:	48 89 d6             	mov    %rdx,%rsi
    78d9:	48 89 c7             	mov    %rax,%rdi
    78dc:	e8 21 da ff ff       	callq  5302 <segment_holding>
    78e1:	48 89 45 e0          	mov    %rax,-0x20(%rbp)

      if (!is_extern_segment(sp)) {
    78e5:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    78e9:	8b 40 18             	mov    0x18(%rax),%eax
    78ec:	83 e0 08             	and    $0x8,%eax
    78ef:	85 c0                	test   %eax,%eax
    78f1:	0f 85 b2 00 00 00    	jne    79a9 <sys_trim+0x17f>
              released = extra;
            }
          }
        }
        else if (HAVE_MORECORE) {
          if (extra >= HALF_MAX_SIZE_T) /* Avoid wrapping negative */
    78f7:	48 b8 fe ff ff ff ff 	movabs $0x7ffffffffffffffe,%rax
    78fe:	ff ff 7f 
    7901:	48 39 45 d0          	cmp    %rax,-0x30(%rbp)
    7905:	76 12                	jbe    7919 <sys_trim+0xef>
            extra = (HALF_MAX_SIZE_T) + SIZE_T_ONE - unit;
    7907:	48 b8 00 00 00 00 00 	movabs $0x8000000000000000,%rax
    790e:	00 00 80 
    7911:	48 2b 45 d8          	sub    -0x28(%rbp),%rax
    7915:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
          ACQUIRE_MALLOC_GLOBAL_LOCK();
    7919:	b8 01 00 00 00       	mov    $0x1,%eax
    791e:	87 05 dc 97 00 00    	xchg   %eax,0x97dc(%rip)        # 11100 <malloc_global_mutex>
    7924:	85 c0                	test   %eax,%eax
    7926:	74 0c                	je     7934 <sys_trim+0x10a>
    7928:	48 8d 3d d1 97 00 00 	lea    0x97d1(%rip),%rdi        # 11100 <malloc_global_mutex>
    792f:	e8 99 d9 ff ff       	callq  52cd <spin_acquire_lock>
          {
            /* Make sure end of memory is where we last set it. */
            char* old_br = (char*)(CALL_MORECORE(0));
    7934:	bf 00 00 00 00       	mov    $0x0,%edi
    7939:	e8 8e 37 00 00       	callq  b0cc <sbrk>
    793e:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
            if (old_br == sp->base + sp->size) {
    7942:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    7946:	48 8b 10             	mov    (%rax),%rdx
    7949:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    794d:	48 8b 40 08          	mov    0x8(%rax),%rax
    7951:	48 01 d0             	add    %rdx,%rax
    7954:	48 39 45 e8          	cmp    %rax,-0x18(%rbp)
    7958:	75 44                	jne    799e <sys_trim+0x174>
              char* rel_br = (char*)(CALL_MORECORE(-extra));
    795a:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    795e:	48 f7 d8             	neg    %rax
    7961:	48 89 c7             	mov    %rax,%rdi
    7964:	e8 63 37 00 00       	callq  b0cc <sbrk>
    7969:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
              char* new_br = (char*)(CALL_MORECORE(0));
    796d:	bf 00 00 00 00       	mov    $0x0,%edi
    7972:	e8 55 37 00 00       	callq  b0cc <sbrk>
    7977:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
              if (rel_br != CMFAIL && new_br < old_br)
    797b:	48 83 7d f0 ff       	cmpq   $0xffffffffffffffff,-0x10(%rbp)
    7980:	74 1c                	je     799e <sys_trim+0x174>
    7982:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    7986:	48 3b 45 e8          	cmp    -0x18(%rbp),%rax
    798a:	73 12                	jae    799e <sys_trim+0x174>
                released = old_br - new_br;
    798c:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    7990:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    7994:	48 29 c2             	sub    %rax,%rdx
    7997:	48 89 d0             	mov    %rdx,%rax
    799a:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
            }
          }
          RELEASE_MALLOC_GLOBAL_LOCK();
    799e:	b8 00 00 00 00       	mov    $0x0,%eax
    79a3:	89 05 57 97 00 00    	mov    %eax,0x9757(%rip)        # 11100 <malloc_global_mutex>
        }
      }

      if (released != 0) {
    79a9:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    79ae:	74 71                	je     7a21 <sys_trim+0x1f7>
        sp->size -= released;
    79b0:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    79b4:	48 8b 40 08          	mov    0x8(%rax),%rax
    79b8:	48 2b 45 c8          	sub    -0x38(%rbp),%rax
    79bc:	48 89 c2             	mov    %rax,%rdx
    79bf:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    79c3:	48 89 50 08          	mov    %rdx,0x8(%rax)
        m->footprint -= released;
    79c7:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    79cb:	48 8b 80 58 03 00 00 	mov    0x358(%rax),%rax
    79d2:	48 2b 45 c8          	sub    -0x38(%rbp),%rax
    79d6:	48 89 c2             	mov    %rax,%rdx
    79d9:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    79dd:	48 89 90 58 03 00 00 	mov    %rdx,0x358(%rax)
        init_top(m, m->top, m->topsize - released);
    79e4:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    79e8:	48 8b 40 10          	mov    0x10(%rax),%rax
    79ec:	48 2b 45 c8          	sub    -0x38(%rbp),%rax
    79f0:	48 89 c2             	mov    %rax,%rdx
    79f3:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    79f7:	48 8b 48 28          	mov    0x28(%rax),%rcx
    79fb:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    79ff:	48 89 ce             	mov    %rcx,%rsi
    7a02:	48 89 c7             	mov    %rax,%rdi
    7a05:	e8 06 df ff ff       	callq  5910 <init_top>
        check_top_chunk(m, m->top);
    7a0a:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    7a0e:	48 8b 50 28          	mov    0x28(%rax),%rdx
    7a12:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    7a16:	48 89 d6             	mov    %rdx,%rsi
    7a19:	48 89 c7             	mov    %rax,%rdi
    7a1c:	e8 c2 da ff ff       	callq  54e3 <do_check_top_chunk>
    /* Unmap any unused mmapped segments */
    if (HAVE_MMAP)
      released += release_unused_segments(m);

    /* On failure, disable autotrim to avoid repeated failed future calls */
    if (released == 0 && m->topsize > m->trim_check)
    7a21:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    7a26:	75 21                	jne    7a49 <sys_trim+0x21f>
    7a28:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    7a2c:	48 8b 50 10          	mov    0x10(%rax),%rdx
    7a30:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    7a34:	48 8b 40 30          	mov    0x30(%rax),%rax
    7a38:	48 39 c2             	cmp    %rax,%rdx
    7a3b:	76 0c                	jbe    7a49 <sys_trim+0x21f>
      m->trim_check = MAX_SIZE_T;
    7a3d:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    7a41:	48 c7 40 30 ff ff ff 	movq   $0xffffffffffffffff,0x30(%rax)
    7a48:	ff 
  }

  return (released != 0)? 1 : 0;
    7a49:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    7a4e:	0f 95 c0             	setne  %al
    7a51:	0f b6 c0             	movzbl %al,%eax
}
    7a54:	c9                   	leaveq 
    7a55:	c3                   	retq   

0000000000007a56 <tmalloc_large>:
}

/* ---------------------------- malloc --------------------------- */

/* allocate a large request from the best fitting chunk in a treebin */
static void* tmalloc_large(mstate m, size_t nb) {
    7a56:	55                   	push   %rbp
    7a57:	48 89 e5             	mov    %rsp,%rbp
    7a5a:	48 81 ec 10 01 00 00 	sub    $0x110,%rsp
    7a61:	48 89 bd f8 fe ff ff 	mov    %rdi,-0x108(%rbp)
    7a68:	48 89 b5 f0 fe ff ff 	mov    %rsi,-0x110(%rbp)
  tchunkptr v = 0;
    7a6f:	48 c7 85 38 ff ff ff 	movq   $0x0,-0xc8(%rbp)
    7a76:	00 00 00 00 
  size_t rsize = -nb; /* Unsigned negation */
    7a7a:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    7a81:	48 f7 d8             	neg    %rax
    7a84:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
  tchunkptr t;
  bindex_t idx;
  compute_tree_index(nb, idx);
    7a8b:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    7a92:	48 c1 e8 08          	shr    $0x8,%rax
    7a96:	89 85 14 ff ff ff    	mov    %eax,-0xec(%rbp)
    7a9c:	83 bd 14 ff ff ff 00 	cmpl   $0x0,-0xec(%rbp)
    7aa3:	75 0c                	jne    7ab1 <tmalloc_large+0x5b>
    7aa5:	c7 85 0c ff ff ff 00 	movl   $0x0,-0xf4(%rbp)
    7aac:	00 00 00 
    7aaf:	eb 5d                	jmp    7b0e <tmalloc_large+0xb8>
    7ab1:	81 bd 14 ff ff ff ff 	cmpl   $0xffff,-0xec(%rbp)
    7ab8:	ff 00 00 
    7abb:	76 0c                	jbe    7ac9 <tmalloc_large+0x73>
    7abd:	c7 85 0c ff ff ff 1f 	movl   $0x1f,-0xf4(%rbp)
    7ac4:	00 00 00 
    7ac7:	eb 45                	jmp    7b0e <tmalloc_large+0xb8>
    7ac9:	0f bd 85 14 ff ff ff 	bsr    -0xec(%rbp),%eax
    7ad0:	83 f0 1f             	xor    $0x1f,%eax
    7ad3:	ba 1f 00 00 00       	mov    $0x1f,%edx
    7ad8:	29 c2                	sub    %eax,%edx
    7ada:	89 d0                	mov    %edx,%eax
    7adc:	89 85 18 ff ff ff    	mov    %eax,-0xe8(%rbp)
    7ae2:	8b 85 18 ff ff ff    	mov    -0xe8(%rbp),%eax
    7ae8:	8d 34 00             	lea    (%rax,%rax,1),%esi
    7aeb:	8b 85 18 ff ff ff    	mov    -0xe8(%rbp),%eax
    7af1:	83 c0 07             	add    $0x7,%eax
    7af4:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    7afb:	89 c1                	mov    %eax,%ecx
    7afd:	48 d3 ea             	shr    %cl,%rdx
    7b00:	48 89 d0             	mov    %rdx,%rax
    7b03:	83 e0 01             	and    $0x1,%eax
    7b06:	01 f0                	add    %esi,%eax
    7b08:	89 85 0c ff ff ff    	mov    %eax,-0xf4(%rbp)
  if ((t = *treebin_at(m, idx)) != 0) {
    7b0e:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    7b15:	8b 95 0c ff ff ff    	mov    -0xf4(%rbp),%edx
    7b1b:	48 83 c2 4a          	add    $0x4a,%rdx
    7b1f:	48 8b 44 d0 08       	mov    0x8(%rax,%rdx,8),%rax
    7b24:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    7b2b:	48 83 bd 48 ff ff ff 	cmpq   $0x0,-0xb8(%rbp)
    7b32:	00 
    7b33:	0f 84 05 01 00 00    	je     7c3e <tmalloc_large+0x1e8>
    /* Traverse tree for this bin looking for node with size == nb */
    size_t sizebits = nb << leftshift_for_tree_index(idx);
    7b39:	83 bd 0c ff ff ff 1f 	cmpl   $0x1f,-0xf4(%rbp)
    7b40:	74 13                	je     7b55 <tmalloc_large+0xff>
    7b42:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    7b48:	d1 e8                	shr    %eax
    7b4a:	ba 39 00 00 00       	mov    $0x39,%edx
    7b4f:	29 c2                	sub    %eax,%edx
    7b51:	89 d0                	mov    %edx,%eax
    7b53:	eb 05                	jmp    7b5a <tmalloc_large+0x104>
    7b55:	b8 00 00 00 00       	mov    $0x0,%eax
    7b5a:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    7b61:	89 c1                	mov    %eax,%ecx
    7b63:	48 d3 e2             	shl    %cl,%rdx
    7b66:	48 89 d0             	mov    %rdx,%rax
    7b69:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    tchunkptr rst = 0;  /* The deepest untaken right subtree */
    7b70:	48 c7 85 58 ff ff ff 	movq   $0x0,-0xa8(%rbp)
    7b77:	00 00 00 00 
    for (;;) {
      tchunkptr rt;
      size_t trem = chunksize(t) - nb;
    7b7b:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7b82:	48 8b 40 08          	mov    0x8(%rax),%rax
    7b86:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    7b8a:	48 2b 85 f0 fe ff ff 	sub    -0x110(%rbp),%rax
    7b91:	48 89 45 90          	mov    %rax,-0x70(%rbp)
      if (trem < rsize) {
    7b95:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    7b99:	48 3b 85 40 ff ff ff 	cmp    -0xc0(%rbp),%rax
    7ba0:	73 23                	jae    7bc5 <tmalloc_large+0x16f>
        v = t;
    7ba2:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7ba9:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
        if ((rsize = trem) == 0)
    7bb0:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    7bb4:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
    7bbb:	48 83 bd 40 ff ff ff 	cmpq   $0x0,-0xc0(%rbp)
    7bc2:	00 
    7bc3:	74 78                	je     7c3d <tmalloc_large+0x1e7>
          break;
      }
      rt = t->child[1];
    7bc5:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7bcc:	48 8b 40 28          	mov    0x28(%rax),%rax
    7bd0:	48 89 45 98          	mov    %rax,-0x68(%rbp)
      t = t->child[(sizebits >> (SIZE_T_BITSIZE-SIZE_T_ONE)) & 1];
    7bd4:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    7bdb:	48 c1 e8 3f          	shr    $0x3f,%rax
    7bdf:	48 89 c2             	mov    %rax,%rdx
    7be2:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7be9:	48 83 c2 04          	add    $0x4,%rdx
    7bed:	48 8b 04 d0          	mov    (%rax,%rdx,8),%rax
    7bf1:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
      if (rt != 0 && rt != t)
    7bf8:	48 83 7d 98 00       	cmpq   $0x0,-0x68(%rbp)
    7bfd:	74 18                	je     7c17 <tmalloc_large+0x1c1>
    7bff:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    7c03:	48 3b 85 48 ff ff ff 	cmp    -0xb8(%rbp),%rax
    7c0a:	74 0b                	je     7c17 <tmalloc_large+0x1c1>
        rst = rt;
    7c0c:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    7c10:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
      if (t == 0) {
    7c17:	48 83 bd 48 ff ff ff 	cmpq   $0x0,-0xb8(%rbp)
    7c1e:	00 
    7c1f:	75 10                	jne    7c31 <tmalloc_large+0x1db>
        t = rst; /* set t to least subtree holding sizes > nb */
    7c21:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    7c28:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
        break;
    7c2f:	eb 0d                	jmp    7c3e <tmalloc_large+0x1e8>
      }
      sizebits <<= 1;
    7c31:	48 d1 a5 50 ff ff ff 	shlq   -0xb0(%rbp)
    for (;;) {
    7c38:	e9 3e ff ff ff       	jmpq   7b7b <tmalloc_large+0x125>
          break;
    7c3d:	90                   	nop
    }
  }
  if (t == 0 && v == 0) { /* set t to root of next non-empty treebin */
    7c3e:	48 83 bd 48 ff ff ff 	cmpq   $0x0,-0xb8(%rbp)
    7c45:	00 
    7c46:	0f 85 14 01 00 00    	jne    7d60 <tmalloc_large+0x30a>
    7c4c:	48 83 bd 38 ff ff ff 	cmpq   $0x0,-0xc8(%rbp)
    7c53:	00 
    7c54:	0f 85 06 01 00 00    	jne    7d60 <tmalloc_large+0x30a>
    binmap_t leftbits = left_bits(idx2bit(idx)) & m->treemap;
    7c5a:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    7c60:	ba 01 00 00 00       	mov    $0x1,%edx
    7c65:	89 c1                	mov    %eax,%ecx
    7c67:	d3 e2                	shl    %cl,%edx
    7c69:	89 d0                	mov    %edx,%eax
    7c6b:	8d 14 00             	lea    (%rax,%rax,1),%edx
    7c6e:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    7c74:	be 01 00 00 00       	mov    $0x1,%esi
    7c79:	89 c1                	mov    %eax,%ecx
    7c7b:	d3 e6                	shl    %cl,%esi
    7c7d:	89 f0                	mov    %esi,%eax
    7c7f:	01 c0                	add    %eax,%eax
    7c81:	f7 d8                	neg    %eax
    7c83:	09 c2                	or     %eax,%edx
    7c85:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    7c8c:	8b 40 04             	mov    0x4(%rax),%eax
    7c8f:	21 d0                	and    %edx,%eax
    7c91:	89 85 1c ff ff ff    	mov    %eax,-0xe4(%rbp)
    if (leftbits != 0) {
    7c97:	83 bd 1c ff ff ff 00 	cmpl   $0x0,-0xe4(%rbp)
    7c9e:	0f 84 bc 00 00 00    	je     7d60 <tmalloc_large+0x30a>
      bindex_t i;
      binmap_t leastbit = least_bit(leftbits);
    7ca4:	8b 85 1c ff ff ff    	mov    -0xe4(%rbp),%eax
    7caa:	f7 d8                	neg    %eax
    7cac:	23 85 1c ff ff ff    	and    -0xe4(%rbp),%eax
    7cb2:	89 85 20 ff ff ff    	mov    %eax,-0xe0(%rbp)
      compute_bit2idx(leastbit, i);
    7cb8:	f3 0f bc 85 20 ff ff 	tzcnt  -0xe0(%rbp),%eax
    7cbf:	ff 
    7cc0:	89 85 24 ff ff ff    	mov    %eax,-0xdc(%rbp)
    7cc6:	8b 85 24 ff ff ff    	mov    -0xdc(%rbp),%eax
    7ccc:	89 85 28 ff ff ff    	mov    %eax,-0xd8(%rbp)
      t = *treebin_at(m, i);
    7cd2:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    7cd9:	8b 95 28 ff ff ff    	mov    -0xd8(%rbp),%edx
    7cdf:	48 83 c2 4a          	add    $0x4a,%rdx
    7ce3:	48 8b 44 d0 08       	mov    0x8(%rax,%rdx,8),%rax
    7ce8:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    }
  }

  while (t != 0) { /* find smallest of tree or subtree */
    7cef:	eb 6f                	jmp    7d60 <tmalloc_large+0x30a>
    size_t trem = chunksize(t) - nb;
    7cf1:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7cf8:	48 8b 40 08          	mov    0x8(%rax),%rax
    7cfc:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    7d00:	48 2b 85 f0 fe ff ff 	sub    -0x110(%rbp),%rax
    7d07:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if (trem < rsize) {
    7d0b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    7d0f:	48 3b 85 40 ff ff ff 	cmp    -0xc0(%rbp),%rax
    7d16:	73 19                	jae    7d31 <tmalloc_large+0x2db>
      rsize = trem;
    7d18:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    7d1c:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
      v = t;
    7d23:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7d2a:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
    }
    t = leftmost_child(t);
    7d31:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7d38:	48 8b 40 20          	mov    0x20(%rax),%rax
    7d3c:	48 85 c0             	test   %rax,%rax
    7d3f:	74 0d                	je     7d4e <tmalloc_large+0x2f8>
    7d41:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7d48:	48 8b 40 20          	mov    0x20(%rax),%rax
    7d4c:	eb 0b                	jmp    7d59 <tmalloc_large+0x303>
    7d4e:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7d55:	48 8b 40 28          	mov    0x28(%rax),%rax
    7d59:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
  while (t != 0) { /* find smallest of tree or subtree */
    7d60:	48 83 bd 48 ff ff ff 	cmpq   $0x0,-0xb8(%rbp)
    7d67:	00 
    7d68:	75 87                	jne    7cf1 <tmalloc_large+0x29b>
  }

  /*  If dv is a better fit, return 0 so malloc will use it */
  if (v != 0 && rsize < (size_t)(m->dvsize - nb)) {
    7d6a:	48 83 bd 38 ff ff ff 	cmpq   $0x0,-0xc8(%rbp)
    7d71:	00 
    7d72:	0f 84 41 09 00 00    	je     86b9 <tmalloc_large+0xc63>
    7d78:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    7d7f:	48 8b 40 08          	mov    0x8(%rax),%rax
    7d83:	48 2b 85 f0 fe ff ff 	sub    -0x110(%rbp),%rax
    7d8a:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    7d91:	0f 83 22 09 00 00    	jae    86b9 <tmalloc_large+0xc63>
    if (RTCHECK(ok_address(m, v))) { /* split */
    7d97:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    7d9e:	48 8b 40 18          	mov    0x18(%rax),%rax
    7da2:	48 39 85 38 ff ff ff 	cmp    %rax,-0xc8(%rbp)
    7da9:	0f 93 c0             	setae  %al
    7dac:	0f b6 c0             	movzbl %al,%eax
    7daf:	48 85 c0             	test   %rax,%rax
    7db2:	0f 84 fc 08 00 00    	je     86b4 <tmalloc_large+0xc5e>
      mchunkptr r = chunk_plus_offset(v, nb);
    7db8:	48 8b 95 38 ff ff ff 	mov    -0xc8(%rbp),%rdx
    7dbf:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    7dc6:	48 01 d0             	add    %rdx,%rax
    7dc9:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
      assert(chunksize(v) == rsize + nb);
    7dcd:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7dd4:	48 8b 40 08          	mov    0x8(%rax),%rax
    7dd8:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    7ddc:	48 89 c1             	mov    %rax,%rcx
    7ddf:	48 8b 95 40 ff ff ff 	mov    -0xc0(%rbp),%rdx
    7de6:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    7ded:	48 01 d0             	add    %rdx,%rax
    7df0:	48 39 c1             	cmp    %rax,%rcx
    7df3:	74 05                	je     7dfa <tmalloc_large+0x3a4>
    7df5:	e8 a2 4b 00 00       	callq  c99c <abort>
      if (RTCHECK(ok_next(v, r))) {
    7dfa:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7e01:	48 3b 45 a0          	cmp    -0x60(%rbp),%rax
    7e05:	0f 92 c0             	setb   %al
    7e08:	0f b6 c0             	movzbl %al,%eax
    7e0b:	48 85 c0             	test   %rax,%rax
    7e0e:	0f 84 a0 08 00 00    	je     86b4 <tmalloc_large+0xc5e>
        unlink_large_chunk(m, v);
    7e14:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7e1b:	48 8b 40 30          	mov    0x30(%rax),%rax
    7e1f:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    7e23:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7e2a:	48 8b 40 18          	mov    0x18(%rax),%rax
    7e2e:	48 39 85 38 ff ff ff 	cmp    %rax,-0xc8(%rbp)
    7e35:	0f 84 aa 00 00 00    	je     7ee5 <tmalloc_large+0x48f>
    7e3b:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7e42:	48 8b 40 10          	mov    0x10(%rax),%rax
    7e46:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    7e4a:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7e51:	48 8b 40 18          	mov    0x18(%rax),%rax
    7e55:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
    7e5c:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    7e63:	48 8b 40 18          	mov    0x18(%rax),%rax
    7e67:	48 39 45 b0          	cmp    %rax,-0x50(%rbp)
    7e6b:	0f 93 c0             	setae  %al
    7e6e:	0f b6 c0             	movzbl %al,%eax
    7e71:	48 85 c0             	test   %rax,%rax
    7e74:	74 21                	je     7e97 <tmalloc_large+0x441>
    7e76:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    7e7a:	48 8b 40 18          	mov    0x18(%rax),%rax
    7e7e:	48 39 85 38 ff ff ff 	cmp    %rax,-0xc8(%rbp)
    7e85:	0f 94 c0             	sete   %al
    7e88:	0f b6 c0             	movzbl %al,%eax
    7e8b:	48 85 c0             	test   %rax,%rax
    7e8e:	74 07                	je     7e97 <tmalloc_large+0x441>
    7e90:	b8 01 00 00 00       	mov    $0x1,%eax
    7e95:	eb 05                	jmp    7e9c <tmalloc_large+0x446>
    7e97:	b8 00 00 00 00       	mov    $0x0,%eax
    7e9c:	85 c0                	test   %eax,%eax
    7e9e:	74 40                	je     7ee0 <tmalloc_large+0x48a>
    7ea0:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    7ea7:	48 8b 40 10          	mov    0x10(%rax),%rax
    7eab:	48 39 85 38 ff ff ff 	cmp    %rax,-0xc8(%rbp)
    7eb2:	0f 94 c0             	sete   %al
    7eb5:	0f b6 c0             	movzbl %al,%eax
    7eb8:	48 85 c0             	test   %rax,%rax
    7ebb:	74 23                	je     7ee0 <tmalloc_large+0x48a>
    7ebd:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    7ec1:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    7ec8:	48 89 50 18          	mov    %rdx,0x18(%rax)
    7ecc:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    7ed3:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    7ed7:	48 89 50 10          	mov    %rdx,0x10(%rax)
    7edb:	e9 f8 00 00 00       	jmpq   7fd8 <tmalloc_large+0x582>
    7ee0:	e8 b7 4a 00 00       	callq  c99c <abort>
    7ee5:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7eec:	48 83 c0 28          	add    $0x28,%rax
    7ef0:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
    7ef7:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    7efe:	48 8b 00             	mov    (%rax),%rax
    7f01:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
    7f08:	48 83 bd 60 ff ff ff 	cmpq   $0x0,-0xa0(%rbp)
    7f0f:	00 
    7f10:	75 52                	jne    7f64 <tmalloc_large+0x50e>
    7f12:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7f19:	48 83 c0 20          	add    $0x20,%rax
    7f1d:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
    7f24:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    7f2b:	48 8b 00             	mov    (%rax),%rax
    7f2e:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
    7f35:	48 83 bd 60 ff ff ff 	cmpq   $0x0,-0xa0(%rbp)
    7f3c:	00 
    7f3d:	0f 84 95 00 00 00    	je     7fd8 <tmalloc_large+0x582>
    7f43:	eb 1f                	jmp    7f64 <tmalloc_large+0x50e>
    7f45:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    7f4c:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
    7f53:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    7f5a:	48 8b 00             	mov    (%rax),%rax
    7f5d:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
    7f64:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    7f6b:	48 83 c0 28          	add    $0x28,%rax
    7f6f:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
    7f76:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    7f7d:	48 8b 00             	mov    (%rax),%rax
    7f80:	48 85 c0             	test   %rax,%rax
    7f83:	75 c0                	jne    7f45 <tmalloc_large+0x4ef>
    7f85:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    7f8c:	48 83 c0 20          	add    $0x20,%rax
    7f90:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
    7f97:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    7f9e:	48 8b 00             	mov    (%rax),%rax
    7fa1:	48 85 c0             	test   %rax,%rax
    7fa4:	75 9f                	jne    7f45 <tmalloc_large+0x4ef>
    7fa6:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    7fad:	48 8b 40 18          	mov    0x18(%rax),%rax
    7fb1:	48 39 85 68 ff ff ff 	cmp    %rax,-0x98(%rbp)
    7fb8:	0f 93 c0             	setae  %al
    7fbb:	0f b6 c0             	movzbl %al,%eax
    7fbe:	48 85 c0             	test   %rax,%rax
    7fc1:	74 10                	je     7fd3 <tmalloc_large+0x57d>
    7fc3:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    7fca:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    7fd1:	eb 05                	jmp    7fd8 <tmalloc_large+0x582>
    7fd3:	e8 c4 49 00 00       	callq  c99c <abort>
    7fd8:	48 83 7d a8 00       	cmpq   $0x0,-0x58(%rbp)
    7fdd:	0f 84 c6 01 00 00    	je     81a9 <tmalloc_large+0x753>
    7fe3:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7fea:	8b 40 38             	mov    0x38(%rax),%eax
    7fed:	89 c0                	mov    %eax,%eax
    7fef:	48 83 c0 4a          	add    $0x4a,%rax
    7ff3:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    7ffa:	00 
    7ffb:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    8002:	48 01 d0             	add    %rdx,%rax
    8005:	48 83 c0 08          	add    $0x8,%rax
    8009:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    800d:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    8011:	48 8b 00             	mov    (%rax),%rax
    8014:	48 39 85 38 ff ff ff 	cmp    %rax,-0xc8(%rbp)
    801b:	75 4d                	jne    806a <tmalloc_large+0x614>
    801d:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    8021:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    8028:	48 89 10             	mov    %rdx,(%rax)
    802b:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    802f:	48 8b 00             	mov    (%rax),%rax
    8032:	48 85 c0             	test   %rax,%rax
    8035:	0f 85 81 00 00 00    	jne    80bc <tmalloc_large+0x666>
    803b:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    8042:	8b 50 04             	mov    0x4(%rax),%edx
    8045:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    804c:	8b 40 38             	mov    0x38(%rax),%eax
    804f:	be 01 00 00 00       	mov    $0x1,%esi
    8054:	89 c1                	mov    %eax,%ecx
    8056:	d3 e6                	shl    %cl,%esi
    8058:	89 f0                	mov    %esi,%eax
    805a:	f7 d0                	not    %eax
    805c:	21 c2                	and    %eax,%edx
    805e:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    8065:	89 50 04             	mov    %edx,0x4(%rax)
    8068:	eb 52                	jmp    80bc <tmalloc_large+0x666>
    806a:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    8071:	48 8b 40 18          	mov    0x18(%rax),%rax
    8075:	48 39 45 a8          	cmp    %rax,-0x58(%rbp)
    8079:	0f 93 c0             	setae  %al
    807c:	0f b6 c0             	movzbl %al,%eax
    807f:	48 85 c0             	test   %rax,%rax
    8082:	74 33                	je     80b7 <tmalloc_large+0x661>
    8084:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8088:	48 8b 40 20          	mov    0x20(%rax),%rax
    808c:	48 39 85 38 ff ff ff 	cmp    %rax,-0xc8(%rbp)
    8093:	75 11                	jne    80a6 <tmalloc_large+0x650>
    8095:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8099:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    80a0:	48 89 50 20          	mov    %rdx,0x20(%rax)
    80a4:	eb 16                	jmp    80bc <tmalloc_large+0x666>
    80a6:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    80aa:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    80b1:	48 89 50 28          	mov    %rdx,0x28(%rax)
    80b5:	eb 05                	jmp    80bc <tmalloc_large+0x666>
    80b7:	e8 e0 48 00 00       	callq  c99c <abort>
    80bc:	48 83 bd 60 ff ff ff 	cmpq   $0x0,-0xa0(%rbp)
    80c3:	00 
    80c4:	0f 84 df 00 00 00    	je     81a9 <tmalloc_large+0x753>
    80ca:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    80d1:	48 8b 40 18          	mov    0x18(%rax),%rax
    80d5:	48 39 85 60 ff ff ff 	cmp    %rax,-0xa0(%rbp)
    80dc:	0f 93 c0             	setae  %al
    80df:	0f b6 c0             	movzbl %al,%eax
    80e2:	48 85 c0             	test   %rax,%rax
    80e5:	0f 84 b9 00 00 00    	je     81a4 <tmalloc_large+0x74e>
    80eb:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    80f2:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    80f6:	48 89 50 30          	mov    %rdx,0x30(%rax)
    80fa:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    8101:	48 8b 40 20          	mov    0x20(%rax),%rax
    8105:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    8109:	48 83 7d c0 00       	cmpq   $0x0,-0x40(%rbp)
    810e:	74 3f                	je     814f <tmalloc_large+0x6f9>
    8110:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    8117:	48 8b 40 18          	mov    0x18(%rax),%rax
    811b:	48 39 45 c0          	cmp    %rax,-0x40(%rbp)
    811f:	0f 93 c0             	setae  %al
    8122:	0f b6 c0             	movzbl %al,%eax
    8125:	48 85 c0             	test   %rax,%rax
    8128:	74 20                	je     814a <tmalloc_large+0x6f4>
    812a:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    8131:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    8135:	48 89 50 20          	mov    %rdx,0x20(%rax)
    8139:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    813d:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    8144:	48 89 50 30          	mov    %rdx,0x30(%rax)
    8148:	eb 05                	jmp    814f <tmalloc_large+0x6f9>
    814a:	e8 4d 48 00 00       	callq  c99c <abort>
    814f:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    8156:	48 8b 40 28          	mov    0x28(%rax),%rax
    815a:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    815e:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    8163:	74 44                	je     81a9 <tmalloc_large+0x753>
    8165:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    816c:	48 8b 40 18          	mov    0x18(%rax),%rax
    8170:	48 39 45 c8          	cmp    %rax,-0x38(%rbp)
    8174:	0f 93 c0             	setae  %al
    8177:	0f b6 c0             	movzbl %al,%eax
    817a:	48 85 c0             	test   %rax,%rax
    817d:	74 20                	je     819f <tmalloc_large+0x749>
    817f:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    8186:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    818a:	48 89 50 28          	mov    %rdx,0x28(%rax)
    818e:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    8192:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    8199:	48 89 50 30          	mov    %rdx,0x30(%rax)
    819d:	eb 0a                	jmp    81a9 <tmalloc_large+0x753>
    819f:	e8 f8 47 00 00       	callq  c99c <abort>
    81a4:	e8 f3 47 00 00       	callq  c99c <abort>
        if (rsize < MIN_CHUNK_SIZE)
    81a9:	48 83 bd 40 ff ff ff 	cmpq   $0x1f,-0xc0(%rbp)
    81b0:	1f 
    81b1:	0f 87 99 00 00 00    	ja     8250 <tmalloc_large+0x7fa>
          set_inuse_and_pinuse(m, v, (rsize + nb));
    81b7:	48 8b 95 40 ff ff ff 	mov    -0xc0(%rbp),%rdx
    81be:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    81c5:	48 01 d0             	add    %rdx,%rax
    81c8:	48 83 c8 03          	or     $0x3,%rax
    81cc:	48 89 c2             	mov    %rax,%rdx
    81cf:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    81d6:	48 89 50 08          	mov    %rdx,0x8(%rax)
    81da:	48 8b 95 40 ff ff ff 	mov    -0xc0(%rbp),%rdx
    81e1:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    81e8:	48 01 c2             	add    %rax,%rdx
    81eb:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    81f2:	48 01 d0             	add    %rdx,%rax
    81f5:	48 8b 50 08          	mov    0x8(%rax),%rdx
    81f9:	48 8b 8d 40 ff ff ff 	mov    -0xc0(%rbp),%rcx
    8200:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    8207:	48 01 c1             	add    %rax,%rcx
    820a:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    8211:	48 01 c8             	add    %rcx,%rax
    8214:	48 83 ca 01          	or     $0x1,%rdx
    8218:	48 89 50 08          	mov    %rdx,0x8(%rax)
    821c:	48 8b 0d fd 8e 00 00 	mov    0x8efd(%rip),%rcx        # 11120 <mparams>
    8223:	48 8b 95 f8 fe ff ff 	mov    -0x108(%rbp),%rdx
    822a:	48 8b b5 40 ff ff ff 	mov    -0xc0(%rbp),%rsi
    8231:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    8238:	48 01 c6             	add    %rax,%rsi
    823b:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    8242:	48 01 f0             	add    %rsi,%rax
    8245:	48 31 ca             	xor    %rcx,%rdx
    8248:	48 89 10             	mov    %rdx,(%rax)
    824b:	e9 57 04 00 00       	jmpq   86a7 <tmalloc_large+0xc51>
        else {
          set_size_and_pinuse_of_inuse_chunk(m, v, nb);
    8250:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    8257:	48 83 c8 03          	or     $0x3,%rax
    825b:	48 89 c2             	mov    %rax,%rdx
    825e:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    8265:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8269:	48 8b 0d b0 8e 00 00 	mov    0x8eb0(%rip),%rcx        # 11120 <mparams>
    8270:	48 8b 95 f8 fe ff ff 	mov    -0x108(%rbp),%rdx
    8277:	48 8b b5 38 ff ff ff 	mov    -0xc8(%rbp),%rsi
    827e:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    8285:	48 01 f0             	add    %rsi,%rax
    8288:	48 31 ca             	xor    %rcx,%rdx
    828b:	48 89 10             	mov    %rdx,(%rax)
          set_size_and_pinuse_of_free_chunk(r, rsize);
    828e:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    8295:	48 83 c8 01          	or     $0x1,%rax
    8299:	48 89 c2             	mov    %rax,%rdx
    829c:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    82a0:	48 89 50 08          	mov    %rdx,0x8(%rax)
    82a4:	48 8b 55 a0          	mov    -0x60(%rbp),%rdx
    82a8:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    82af:	48 01 c2             	add    %rax,%rdx
    82b2:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    82b9:	48 89 02             	mov    %rax,(%rdx)
          insert_chunk(m, r, rsize);
    82bc:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    82c3:	48 c1 e8 03          	shr    $0x3,%rax
    82c7:	48 83 f8 1f          	cmp    $0x1f,%rax
    82cb:	0f 87 0c 01 00 00    	ja     83dd <tmalloc_large+0x987>
    82d1:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    82d8:	48 c1 e8 03          	shr    $0x3,%rax
    82dc:	89 85 34 ff ff ff    	mov    %eax,-0xcc(%rbp)
    82e2:	8b 85 34 ff ff ff    	mov    -0xcc(%rbp),%eax
    82e8:	01 c0                	add    %eax,%eax
    82ea:	89 c0                	mov    %eax,%eax
    82ec:	48 83 c0 08          	add    $0x8,%rax
    82f0:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    82f7:	00 
    82f8:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    82ff:	48 01 d0             	add    %rdx,%rax
    8302:	48 83 c0 08          	add    $0x8,%rax
    8306:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    830a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    830e:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
    8315:	48 83 bd 40 ff ff ff 	cmpq   $0x1f,-0xc0(%rbp)
    831c:	1f 
    831d:	77 05                	ja     8324 <tmalloc_large+0x8ce>
    831f:	e8 78 46 00 00       	callq  c99c <abort>
    8324:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    832b:	8b 10                	mov    (%rax),%edx
    832d:	8b 85 34 ff ff ff    	mov    -0xcc(%rbp),%eax
    8333:	be 01 00 00 00       	mov    $0x1,%esi
    8338:	89 c1                	mov    %eax,%ecx
    833a:	d3 e6                	shl    %cl,%esi
    833c:	89 f0                	mov    %esi,%eax
    833e:	21 d0                	and    %edx,%eax
    8340:	85 c0                	test   %eax,%eax
    8342:	75 27                	jne    836b <tmalloc_large+0x915>
    8344:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    834b:	8b 10                	mov    (%rax),%edx
    834d:	8b 85 34 ff ff ff    	mov    -0xcc(%rbp),%eax
    8353:	be 01 00 00 00       	mov    $0x1,%esi
    8358:	89 c1                	mov    %eax,%ecx
    835a:	d3 e6                	shl    %cl,%esi
    835c:	89 f0                	mov    %esi,%eax
    835e:	09 c2                	or     %eax,%edx
    8360:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    8367:	89 10                	mov    %edx,(%rax)
    8369:	eb 37                	jmp    83a2 <tmalloc_large+0x94c>
    836b:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    836f:	48 8b 50 10          	mov    0x10(%rax),%rdx
    8373:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    837a:	48 8b 40 18          	mov    0x18(%rax),%rax
    837e:	48 39 c2             	cmp    %rax,%rdx
    8381:	0f 93 c0             	setae  %al
    8384:	0f b6 c0             	movzbl %al,%eax
    8387:	48 85 c0             	test   %rax,%rax
    838a:	74 11                	je     839d <tmalloc_large+0x947>
    838c:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    8390:	48 8b 40 10          	mov    0x10(%rax),%rax
    8394:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
    839b:	eb 05                	jmp    83a2 <tmalloc_large+0x94c>
    839d:	e8 fa 45 00 00       	callq  c99c <abort>
    83a2:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    83a6:	48 8b 55 a0          	mov    -0x60(%rbp),%rdx
    83aa:	48 89 50 10          	mov    %rdx,0x10(%rax)
    83ae:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    83b5:	48 8b 55 a0          	mov    -0x60(%rbp),%rdx
    83b9:	48 89 50 18          	mov    %rdx,0x18(%rax)
    83bd:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    83c1:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    83c8:	48 89 50 10          	mov    %rdx,0x10(%rax)
    83cc:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    83d0:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    83d4:	48 89 50 18          	mov    %rdx,0x18(%rax)
    83d8:	e9 ca 02 00 00       	jmpq   86a7 <tmalloc_large+0xc51>
    83dd:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    83e1:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    83e5:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    83ec:	48 c1 e8 08          	shr    $0x8,%rax
    83f0:	89 85 2c ff ff ff    	mov    %eax,-0xd4(%rbp)
    83f6:	83 bd 2c ff ff ff 00 	cmpl   $0x0,-0xd4(%rbp)
    83fd:	75 0c                	jne    840b <tmalloc_large+0x9b5>
    83ff:	c7 85 10 ff ff ff 00 	movl   $0x0,-0xf0(%rbp)
    8406:	00 00 00 
    8409:	eb 5d                	jmp    8468 <tmalloc_large+0xa12>
    840b:	81 bd 2c ff ff ff ff 	cmpl   $0xffff,-0xd4(%rbp)
    8412:	ff 00 00 
    8415:	76 0c                	jbe    8423 <tmalloc_large+0x9cd>
    8417:	c7 85 10 ff ff ff 1f 	movl   $0x1f,-0xf0(%rbp)
    841e:	00 00 00 
    8421:	eb 45                	jmp    8468 <tmalloc_large+0xa12>
    8423:	0f bd 85 2c ff ff ff 	bsr    -0xd4(%rbp),%eax
    842a:	83 f0 1f             	xor    $0x1f,%eax
    842d:	ba 1f 00 00 00       	mov    $0x1f,%edx
    8432:	29 c2                	sub    %eax,%edx
    8434:	89 d0                	mov    %edx,%eax
    8436:	89 85 30 ff ff ff    	mov    %eax,-0xd0(%rbp)
    843c:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    8442:	8d 34 00             	lea    (%rax,%rax,1),%esi
    8445:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    844b:	83 c0 07             	add    $0x7,%eax
    844e:	48 8b 95 40 ff ff ff 	mov    -0xc0(%rbp),%rdx
    8455:	89 c1                	mov    %eax,%ecx
    8457:	48 d3 ea             	shr    %cl,%rdx
    845a:	48 89 d0             	mov    %rdx,%rax
    845d:	83 e0 01             	and    $0x1,%eax
    8460:	01 f0                	add    %esi,%eax
    8462:	89 85 10 ff ff ff    	mov    %eax,-0xf0(%rbp)
    8468:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    846e:	48 83 c0 4a          	add    $0x4a,%rax
    8472:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    8479:	00 
    847a:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    8481:	48 01 d0             	add    %rdx,%rax
    8484:	48 83 c0 08          	add    $0x8,%rax
    8488:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    848c:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    8490:	8b 95 10 ff ff ff    	mov    -0xf0(%rbp),%edx
    8496:	89 50 38             	mov    %edx,0x38(%rax)
    8499:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    849d:	48 c7 40 28 00 00 00 	movq   $0x0,0x28(%rax)
    84a4:	00 
    84a5:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    84a9:	48 8b 50 28          	mov    0x28(%rax),%rdx
    84ad:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    84b1:	48 89 50 20          	mov    %rdx,0x20(%rax)
    84b5:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    84bc:	8b 50 04             	mov    0x4(%rax),%edx
    84bf:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    84c5:	be 01 00 00 00       	mov    $0x1,%esi
    84ca:	89 c1                	mov    %eax,%ecx
    84cc:	d3 e6                	shl    %cl,%esi
    84ce:	89 f0                	mov    %esi,%eax
    84d0:	21 d0                	and    %edx,%eax
    84d2:	85 c0                	test   %eax,%eax
    84d4:	75 5f                	jne    8535 <tmalloc_large+0xadf>
    84d6:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    84dd:	8b 50 04             	mov    0x4(%rax),%edx
    84e0:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    84e6:	be 01 00 00 00       	mov    $0x1,%esi
    84eb:	89 c1                	mov    %eax,%ecx
    84ed:	d3 e6                	shl    %cl,%esi
    84ef:	89 f0                	mov    %esi,%eax
    84f1:	09 c2                	or     %eax,%edx
    84f3:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    84fa:	89 50 04             	mov    %edx,0x4(%rax)
    84fd:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    8501:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    8505:	48 89 10             	mov    %rdx,(%rax)
    8508:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    850c:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    8510:	48 89 50 30          	mov    %rdx,0x30(%rax)
    8514:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    8518:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    851c:	48 89 50 18          	mov    %rdx,0x18(%rax)
    8520:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    8524:	48 8b 50 18          	mov    0x18(%rax),%rdx
    8528:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    852c:	48 89 50 10          	mov    %rdx,0x10(%rax)
    8530:	e9 72 01 00 00       	jmpq   86a7 <tmalloc_large+0xc51>
    8535:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    8539:	48 8b 00             	mov    (%rax),%rax
    853c:	48 89 45 80          	mov    %rax,-0x80(%rbp)
    8540:	83 bd 10 ff ff ff 1f 	cmpl   $0x1f,-0xf0(%rbp)
    8547:	74 13                	je     855c <tmalloc_large+0xb06>
    8549:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    854f:	d1 e8                	shr    %eax
    8551:	ba 39 00 00 00       	mov    $0x39,%edx
    8556:	29 c2                	sub    %eax,%edx
    8558:	89 d0                	mov    %edx,%eax
    855a:	eb 05                	jmp    8561 <tmalloc_large+0xb0b>
    855c:	b8 00 00 00 00       	mov    $0x0,%eax
    8561:	48 8b 95 40 ff ff ff 	mov    -0xc0(%rbp),%rdx
    8568:	89 c1                	mov    %eax,%ecx
    856a:	48 d3 e2             	shl    %cl,%rdx
    856d:	48 89 d0             	mov    %rdx,%rax
    8570:	48 89 45 88          	mov    %rax,-0x78(%rbp)
    8574:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8578:	48 8b 40 08          	mov    0x8(%rax),%rax
    857c:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    8580:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    8587:	0f 84 93 00 00 00    	je     8620 <tmalloc_large+0xbca>
    858d:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    8591:	48 c1 e8 3f          	shr    $0x3f,%rax
    8595:	48 83 c0 04          	add    $0x4,%rax
    8599:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    85a0:	00 
    85a1:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    85a5:	48 01 d0             	add    %rdx,%rax
    85a8:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    85ac:	48 d1 65 88          	shlq   -0x78(%rbp)
    85b0:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    85b4:	48 8b 00             	mov    (%rax),%rax
    85b7:	48 85 c0             	test   %rax,%rax
    85ba:	74 0d                	je     85c9 <tmalloc_large+0xb73>
    85bc:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    85c0:	48 8b 00             	mov    (%rax),%rax
    85c3:	48 89 45 80          	mov    %rax,-0x80(%rbp)
    85c7:	eb ab                	jmp    8574 <tmalloc_large+0xb1e>
    85c9:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    85d0:	48 8b 40 18          	mov    0x18(%rax),%rax
    85d4:	48 39 45 e8          	cmp    %rax,-0x18(%rbp)
    85d8:	0f 93 c0             	setae  %al
    85db:	0f b6 c0             	movzbl %al,%eax
    85de:	48 85 c0             	test   %rax,%rax
    85e1:	74 38                	je     861b <tmalloc_large+0xbc5>
    85e3:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    85e7:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    85eb:	48 89 10             	mov    %rdx,(%rax)
    85ee:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    85f2:	48 8b 55 80          	mov    -0x80(%rbp),%rdx
    85f6:	48 89 50 30          	mov    %rdx,0x30(%rax)
    85fa:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    85fe:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    8602:	48 89 50 18          	mov    %rdx,0x18(%rax)
    8606:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    860a:	48 8b 50 18          	mov    0x18(%rax),%rdx
    860e:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    8612:	48 89 50 10          	mov    %rdx,0x10(%rax)
    8616:	e9 8c 00 00 00       	jmpq   86a7 <tmalloc_large+0xc51>
    861b:	e8 7c 43 00 00       	callq  c99c <abort>
    8620:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8624:	48 8b 40 10          	mov    0x10(%rax),%rax
    8628:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    862c:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    8633:	48 8b 40 18          	mov    0x18(%rax),%rax
    8637:	48 39 45 80          	cmp    %rax,-0x80(%rbp)
    863b:	0f 93 c0             	setae  %al
    863e:	0f b6 c0             	movzbl %al,%eax
    8641:	48 85 c0             	test   %rax,%rax
    8644:	74 5c                	je     86a2 <tmalloc_large+0xc4c>
    8646:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    864d:	48 8b 40 18          	mov    0x18(%rax),%rax
    8651:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    8655:	0f 93 c0             	setae  %al
    8658:	0f b6 c0             	movzbl %al,%eax
    865b:	48 85 c0             	test   %rax,%rax
    865e:	74 42                	je     86a2 <tmalloc_large+0xc4c>
    8660:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    8664:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    8668:	48 89 50 18          	mov    %rdx,0x18(%rax)
    866c:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    8670:	48 8b 50 18          	mov    0x18(%rax),%rdx
    8674:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8678:	48 89 50 10          	mov    %rdx,0x10(%rax)
    867c:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    8680:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    8684:	48 89 50 10          	mov    %rdx,0x10(%rax)
    8688:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    868c:	48 8b 55 80          	mov    -0x80(%rbp),%rdx
    8690:	48 89 50 18          	mov    %rdx,0x18(%rax)
    8694:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    8698:	48 c7 40 30 00 00 00 	movq   $0x0,0x30(%rax)
    869f:	00 
    86a0:	eb 05                	jmp    86a7 <tmalloc_large+0xc51>
    86a2:	e8 f5 42 00 00       	callq  c99c <abort>
        }
        return chunk2mem(v);
    86a7:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    86ae:	48 83 c0 10          	add    $0x10,%rax
    86b2:	eb 0a                	jmp    86be <tmalloc_large+0xc68>
      }
    }
    CORRUPTION_ERROR_ACTION(m);
    86b4:	e8 e3 42 00 00       	callq  c99c <abort>
  }
  return 0;
    86b9:	b8 00 00 00 00       	mov    $0x0,%eax
}
    86be:	c9                   	leaveq 
    86bf:	c3                   	retq   

00000000000086c0 <tmalloc_small>:

/* allocate a small request from the best fitting chunk in a treebin */
static void* tmalloc_small(mstate m, size_t nb) {
    86c0:	55                   	push   %rbp
    86c1:	48 89 e5             	mov    %rsp,%rbp
    86c4:	48 81 ec b0 00 00 00 	sub    $0xb0,%rsp
    86cb:	48 89 bd 58 ff ff ff 	mov    %rdi,-0xa8(%rbp)
    86d2:	48 89 b5 50 ff ff ff 	mov    %rsi,-0xb0(%rbp)
  tchunkptr t, v;
  size_t rsize;
  bindex_t i;
  binmap_t leastbit = least_bit(m->treemap);
    86d9:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    86e0:	8b 50 04             	mov    0x4(%rax),%edx
    86e3:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    86ea:	8b 40 04             	mov    0x4(%rax),%eax
    86ed:	f7 d8                	neg    %eax
    86ef:	21 d0                	and    %edx,%eax
    86f1:	89 85 68 ff ff ff    	mov    %eax,-0x98(%rbp)
  compute_bit2idx(leastbit, i);
    86f7:	f3 0f bc 85 68 ff ff 	tzcnt  -0x98(%rbp),%eax
    86fe:	ff 
    86ff:	89 85 6c ff ff ff    	mov    %eax,-0x94(%rbp)
    8705:	8b 85 6c ff ff ff    	mov    -0x94(%rbp),%eax
    870b:	89 85 70 ff ff ff    	mov    %eax,-0x90(%rbp)
  v = t = *treebin_at(m, i);
    8711:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8718:	8b 95 70 ff ff ff    	mov    -0x90(%rbp),%edx
    871e:	48 83 c2 4a          	add    $0x4a,%rdx
    8722:	48 8b 44 d0 08       	mov    0x8(%rax,%rdx,8),%rax
    8727:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
    872e:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    8735:	48 89 45 80          	mov    %rax,-0x80(%rbp)
  rsize = chunksize(t) - nb;
    8739:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    8740:	48 8b 40 08          	mov    0x8(%rax),%rax
    8744:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    8748:	48 2b 85 50 ff ff ff 	sub    -0xb0(%rbp),%rax
    874f:	48 89 45 88          	mov    %rax,-0x78(%rbp)

  while ((t = leftmost_child(t)) != 0) {
    8753:	eb 37                	jmp    878c <tmalloc_small+0xcc>
    size_t trem = chunksize(t) - nb;
    8755:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    875c:	48 8b 40 08          	mov    0x8(%rax),%rax
    8760:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    8764:	48 2b 85 50 ff ff ff 	sub    -0xb0(%rbp),%rax
    876b:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if (trem < rsize) {
    876f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    8773:	48 3b 45 88          	cmp    -0x78(%rbp),%rax
    8777:	73 13                	jae    878c <tmalloc_small+0xcc>
      rsize = trem;
    8779:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    877d:	48 89 45 88          	mov    %rax,-0x78(%rbp)
      v = t;
    8781:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    8788:	48 89 45 80          	mov    %rax,-0x80(%rbp)
  while ((t = leftmost_child(t)) != 0) {
    878c:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    8793:	48 8b 40 20          	mov    0x20(%rax),%rax
    8797:	48 85 c0             	test   %rax,%rax
    879a:	74 0d                	je     87a9 <tmalloc_small+0xe9>
    879c:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    87a3:	48 8b 40 20          	mov    0x20(%rax),%rax
    87a7:	eb 0b                	jmp    87b4 <tmalloc_small+0xf4>
    87a9:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    87b0:	48 8b 40 28          	mov    0x28(%rax),%rax
    87b4:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
    87bb:	48 83 bd 78 ff ff ff 	cmpq   $0x0,-0x88(%rbp)
    87c2:	00 
    87c3:	75 90                	jne    8755 <tmalloc_small+0x95>
    }
  }

  if (RTCHECK(ok_address(m, v))) {
    87c5:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    87cc:	48 8b 40 18          	mov    0x18(%rax),%rax
    87d0:	48 39 45 80          	cmp    %rax,-0x80(%rbp)
    87d4:	0f 93 c0             	setae  %al
    87d7:	0f b6 c0             	movzbl %al,%eax
    87da:	48 85 c0             	test   %rax,%rax
    87dd:	0f 84 8c 05 00 00    	je     8d6f <tmalloc_small+0x6af>
    mchunkptr r = chunk_plus_offset(v, nb);
    87e3:	48 8b 55 80          	mov    -0x80(%rbp),%rdx
    87e7:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    87ee:	48 01 d0             	add    %rdx,%rax
    87f1:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    assert(chunksize(v) == rsize + nb);
    87f5:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    87f9:	48 8b 40 08          	mov    0x8(%rax),%rax
    87fd:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    8801:	48 89 c1             	mov    %rax,%rcx
    8804:	48 8b 55 88          	mov    -0x78(%rbp),%rdx
    8808:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    880f:	48 01 d0             	add    %rdx,%rax
    8812:	48 39 c1             	cmp    %rax,%rcx
    8815:	74 05                	je     881c <tmalloc_small+0x15c>
    8817:	e8 80 41 00 00       	callq  c99c <abort>
    if (RTCHECK(ok_next(v, r))) {
    881c:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8820:	48 3b 45 b0          	cmp    -0x50(%rbp),%rax
    8824:	0f 92 c0             	setb   %al
    8827:	0f b6 c0             	movzbl %al,%eax
    882a:	48 85 c0             	test   %rax,%rax
    882d:	0f 84 3c 05 00 00    	je     8d6f <tmalloc_small+0x6af>
      unlink_large_chunk(m, v);
    8833:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8837:	48 8b 40 30          	mov    0x30(%rax),%rax
    883b:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    883f:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8843:	48 8b 40 18          	mov    0x18(%rax),%rax
    8847:	48 39 45 80          	cmp    %rax,-0x80(%rbp)
    884b:	0f 84 92 00 00 00    	je     88e3 <tmalloc_small+0x223>
    8851:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8855:	48 8b 40 10          	mov    0x10(%rax),%rax
    8859:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    885d:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8861:	48 8b 40 18          	mov    0x18(%rax),%rax
    8865:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    8869:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8870:	48 8b 40 18          	mov    0x18(%rax),%rax
    8874:	48 39 45 c0          	cmp    %rax,-0x40(%rbp)
    8878:	0f 93 c0             	setae  %al
    887b:	0f b6 c0             	movzbl %al,%eax
    887e:	48 85 c0             	test   %rax,%rax
    8881:	74 1e                	je     88a1 <tmalloc_small+0x1e1>
    8883:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    8887:	48 8b 40 18          	mov    0x18(%rax),%rax
    888b:	48 39 45 80          	cmp    %rax,-0x80(%rbp)
    888f:	0f 94 c0             	sete   %al
    8892:	0f b6 c0             	movzbl %al,%eax
    8895:	48 85 c0             	test   %rax,%rax
    8898:	74 07                	je     88a1 <tmalloc_small+0x1e1>
    889a:	b8 01 00 00 00       	mov    $0x1,%eax
    889f:	eb 05                	jmp    88a6 <tmalloc_small+0x1e6>
    88a1:	b8 00 00 00 00       	mov    $0x0,%eax
    88a6:	85 c0                	test   %eax,%eax
    88a8:	74 34                	je     88de <tmalloc_small+0x21e>
    88aa:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    88ae:	48 8b 40 10          	mov    0x10(%rax),%rax
    88b2:	48 39 45 80          	cmp    %rax,-0x80(%rbp)
    88b6:	0f 94 c0             	sete   %al
    88b9:	0f b6 c0             	movzbl %al,%eax
    88bc:	48 85 c0             	test   %rax,%rax
    88bf:	74 1d                	je     88de <tmalloc_small+0x21e>
    88c1:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    88c5:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    88c9:	48 89 50 18          	mov    %rdx,0x18(%rax)
    88cd:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    88d1:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    88d5:	48 89 50 10          	mov    %rdx,0x10(%rax)
    88d9:	e9 b2 00 00 00       	jmpq   8990 <tmalloc_small+0x2d0>
    88de:	e8 b9 40 00 00       	callq  c99c <abort>
    88e3:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    88e7:	48 83 c0 28          	add    $0x28,%rax
    88eb:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    88ef:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    88f3:	48 8b 00             	mov    (%rax),%rax
    88f6:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    88fa:	48 83 7d 90 00       	cmpq   $0x0,-0x70(%rbp)
    88ff:	75 33                	jne    8934 <tmalloc_small+0x274>
    8901:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8905:	48 83 c0 20          	add    $0x20,%rax
    8909:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    890d:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    8911:	48 8b 00             	mov    (%rax),%rax
    8914:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    8918:	48 83 7d 90 00       	cmpq   $0x0,-0x70(%rbp)
    891d:	74 71                	je     8990 <tmalloc_small+0x2d0>
    891f:	eb 13                	jmp    8934 <tmalloc_small+0x274>
    8921:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    8925:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    8929:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    892d:	48 8b 00             	mov    (%rax),%rax
    8930:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    8934:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    8938:	48 83 c0 28          	add    $0x28,%rax
    893c:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
    8940:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    8944:	48 8b 00             	mov    (%rax),%rax
    8947:	48 85 c0             	test   %rax,%rax
    894a:	75 d5                	jne    8921 <tmalloc_small+0x261>
    894c:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    8950:	48 83 c0 20          	add    $0x20,%rax
    8954:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
    8958:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    895c:	48 8b 00             	mov    (%rax),%rax
    895f:	48 85 c0             	test   %rax,%rax
    8962:	75 bd                	jne    8921 <tmalloc_small+0x261>
    8964:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    896b:	48 8b 40 18          	mov    0x18(%rax),%rax
    896f:	48 39 45 98          	cmp    %rax,-0x68(%rbp)
    8973:	0f 93 c0             	setae  %al
    8976:	0f b6 c0             	movzbl %al,%eax
    8979:	48 85 c0             	test   %rax,%rax
    897c:	74 0d                	je     898b <tmalloc_small+0x2cb>
    897e:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    8982:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    8989:	eb 05                	jmp    8990 <tmalloc_small+0x2d0>
    898b:	e8 0c 40 00 00       	callq  c99c <abort>
    8990:	48 83 7d b8 00       	cmpq   $0x0,-0x48(%rbp)
    8995:	0f 84 92 01 00 00    	je     8b2d <tmalloc_small+0x46d>
    899b:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    899f:	8b 40 38             	mov    0x38(%rax),%eax
    89a2:	89 c0                	mov    %eax,%eax
    89a4:	48 83 c0 4a          	add    $0x4a,%rax
    89a8:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    89af:	00 
    89b0:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    89b7:	48 01 d0             	add    %rdx,%rax
    89ba:	48 83 c0 08          	add    $0x8,%rax
    89be:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    89c2:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    89c6:	48 8b 00             	mov    (%rax),%rax
    89c9:	48 39 45 80          	cmp    %rax,-0x80(%rbp)
    89cd:	75 43                	jne    8a12 <tmalloc_small+0x352>
    89cf:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    89d3:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    89d7:	48 89 10             	mov    %rdx,(%rax)
    89da:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    89de:	48 8b 00             	mov    (%rax),%rax
    89e1:	48 85 c0             	test   %rax,%rax
    89e4:	75 75                	jne    8a5b <tmalloc_small+0x39b>
    89e6:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    89ed:	8b 50 04             	mov    0x4(%rax),%edx
    89f0:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    89f4:	8b 40 38             	mov    0x38(%rax),%eax
    89f7:	be 01 00 00 00       	mov    $0x1,%esi
    89fc:	89 c1                	mov    %eax,%ecx
    89fe:	d3 e6                	shl    %cl,%esi
    8a00:	89 f0                	mov    %esi,%eax
    8a02:	f7 d0                	not    %eax
    8a04:	21 c2                	and    %eax,%edx
    8a06:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8a0d:	89 50 04             	mov    %edx,0x4(%rax)
    8a10:	eb 49                	jmp    8a5b <tmalloc_small+0x39b>
    8a12:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8a19:	48 8b 40 18          	mov    0x18(%rax),%rax
    8a1d:	48 39 45 b8          	cmp    %rax,-0x48(%rbp)
    8a21:	0f 93 c0             	setae  %al
    8a24:	0f b6 c0             	movzbl %al,%eax
    8a27:	48 85 c0             	test   %rax,%rax
    8a2a:	74 2a                	je     8a56 <tmalloc_small+0x396>
    8a2c:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    8a30:	48 8b 40 20          	mov    0x20(%rax),%rax
    8a34:	48 39 45 80          	cmp    %rax,-0x80(%rbp)
    8a38:	75 0e                	jne    8a48 <tmalloc_small+0x388>
    8a3a:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    8a3e:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    8a42:	48 89 50 20          	mov    %rdx,0x20(%rax)
    8a46:	eb 13                	jmp    8a5b <tmalloc_small+0x39b>
    8a48:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    8a4c:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    8a50:	48 89 50 28          	mov    %rdx,0x28(%rax)
    8a54:	eb 05                	jmp    8a5b <tmalloc_small+0x39b>
    8a56:	e8 41 3f 00 00       	callq  c99c <abort>
    8a5b:	48 83 7d 90 00       	cmpq   $0x0,-0x70(%rbp)
    8a60:	0f 84 c7 00 00 00    	je     8b2d <tmalloc_small+0x46d>
    8a66:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8a6d:	48 8b 40 18          	mov    0x18(%rax),%rax
    8a71:	48 39 45 90          	cmp    %rax,-0x70(%rbp)
    8a75:	0f 93 c0             	setae  %al
    8a78:	0f b6 c0             	movzbl %al,%eax
    8a7b:	48 85 c0             	test   %rax,%rax
    8a7e:	0f 84 a4 00 00 00    	je     8b28 <tmalloc_small+0x468>
    8a84:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    8a88:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
    8a8c:	48 89 50 30          	mov    %rdx,0x30(%rax)
    8a90:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8a94:	48 8b 40 20          	mov    0x20(%rax),%rax
    8a98:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    8a9c:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    8aa1:	74 39                	je     8adc <tmalloc_small+0x41c>
    8aa3:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8aaa:	48 8b 40 18          	mov    0x18(%rax),%rax
    8aae:	48 39 45 d0          	cmp    %rax,-0x30(%rbp)
    8ab2:	0f 93 c0             	setae  %al
    8ab5:	0f b6 c0             	movzbl %al,%eax
    8ab8:	48 85 c0             	test   %rax,%rax
    8abb:	74 1a                	je     8ad7 <tmalloc_small+0x417>
    8abd:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    8ac1:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    8ac5:	48 89 50 20          	mov    %rdx,0x20(%rax)
    8ac9:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    8acd:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    8ad1:	48 89 50 30          	mov    %rdx,0x30(%rax)
    8ad5:	eb 05                	jmp    8adc <tmalloc_small+0x41c>
    8ad7:	e8 c0 3e 00 00       	callq  c99c <abort>
    8adc:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8ae0:	48 8b 40 28          	mov    0x28(%rax),%rax
    8ae4:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    8ae8:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    8aed:	74 3e                	je     8b2d <tmalloc_small+0x46d>
    8aef:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8af6:	48 8b 40 18          	mov    0x18(%rax),%rax
    8afa:	48 39 45 d8          	cmp    %rax,-0x28(%rbp)
    8afe:	0f 93 c0             	setae  %al
    8b01:	0f b6 c0             	movzbl %al,%eax
    8b04:	48 85 c0             	test   %rax,%rax
    8b07:	74 1a                	je     8b23 <tmalloc_small+0x463>
    8b09:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    8b0d:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    8b11:	48 89 50 28          	mov    %rdx,0x28(%rax)
    8b15:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    8b19:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    8b1d:	48 89 50 30          	mov    %rdx,0x30(%rax)
    8b21:	eb 0a                	jmp    8b2d <tmalloc_small+0x46d>
    8b23:	e8 74 3e 00 00       	callq  c99c <abort>
    8b28:	e8 6f 3e 00 00       	callq  c99c <abort>
      if (rsize < MIN_CHUNK_SIZE)
    8b2d:	48 83 7d 88 1f       	cmpq   $0x1f,-0x78(%rbp)
    8b32:	0f 87 81 00 00 00    	ja     8bb9 <tmalloc_small+0x4f9>
        set_inuse_and_pinuse(m, v, (rsize + nb));
    8b38:	48 8b 55 88          	mov    -0x78(%rbp),%rdx
    8b3c:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    8b43:	48 01 d0             	add    %rdx,%rax
    8b46:	48 83 c8 03          	or     $0x3,%rax
    8b4a:	48 89 c2             	mov    %rax,%rdx
    8b4d:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8b51:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8b55:	48 8b 55 88          	mov    -0x78(%rbp),%rdx
    8b59:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    8b60:	48 01 c2             	add    %rax,%rdx
    8b63:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8b67:	48 01 d0             	add    %rdx,%rax
    8b6a:	48 8b 50 08          	mov    0x8(%rax),%rdx
    8b6e:	48 8b 4d 88          	mov    -0x78(%rbp),%rcx
    8b72:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    8b79:	48 01 c1             	add    %rax,%rcx
    8b7c:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8b80:	48 01 c8             	add    %rcx,%rax
    8b83:	48 83 ca 01          	or     $0x1,%rdx
    8b87:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8b8b:	48 8b 0d 8e 85 00 00 	mov    0x858e(%rip),%rcx        # 11120 <mparams>
    8b92:	48 8b 95 58 ff ff ff 	mov    -0xa8(%rbp),%rdx
    8b99:	48 8b 75 88          	mov    -0x78(%rbp),%rsi
    8b9d:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    8ba4:	48 01 c6             	add    %rax,%rsi
    8ba7:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8bab:	48 01 f0             	add    %rsi,%rax
    8bae:	48 31 ca             	xor    %rcx,%rdx
    8bb1:	48 89 10             	mov    %rdx,(%rax)
    8bb4:	e9 ac 01 00 00       	jmpq   8d65 <tmalloc_small+0x6a5>
      else {
        set_size_and_pinuse_of_inuse_chunk(m, v, nb);
    8bb9:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    8bc0:	48 83 c8 03          	or     $0x3,%rax
    8bc4:	48 89 c2             	mov    %rax,%rdx
    8bc7:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8bcb:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8bcf:	48 8b 0d 4a 85 00 00 	mov    0x854a(%rip),%rcx        # 11120 <mparams>
    8bd6:	48 8b 95 58 ff ff ff 	mov    -0xa8(%rbp),%rdx
    8bdd:	48 8b 75 80          	mov    -0x80(%rbp),%rsi
    8be1:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    8be8:	48 01 f0             	add    %rsi,%rax
    8beb:	48 31 ca             	xor    %rcx,%rdx
    8bee:	48 89 10             	mov    %rdx,(%rax)
        set_size_and_pinuse_of_free_chunk(r, rsize);
    8bf1:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    8bf5:	48 83 c8 01          	or     $0x1,%rax
    8bf9:	48 89 c2             	mov    %rax,%rdx
    8bfc:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    8c00:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8c04:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    8c08:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    8c0c:	48 01 c2             	add    %rax,%rdx
    8c0f:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    8c13:	48 89 02             	mov    %rax,(%rdx)
        replace_dv(m, r, rsize);
    8c16:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8c1d:	48 8b 40 08          	mov    0x8(%rax),%rax
    8c21:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    8c25:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    8c29:	48 c1 e8 03          	shr    $0x3,%rax
    8c2d:	48 83 f8 1f          	cmp    $0x1f,%rax
    8c31:	76 05                	jbe    8c38 <tmalloc_small+0x578>
    8c33:	e8 64 3d 00 00       	callq  c99c <abort>
    8c38:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
    8c3d:	0f 84 04 01 00 00    	je     8d47 <tmalloc_small+0x687>
    8c43:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8c4a:	48 8b 40 20          	mov    0x20(%rax),%rax
    8c4e:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    8c52:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    8c56:	48 c1 e8 03          	shr    $0x3,%rax
    8c5a:	89 85 74 ff ff ff    	mov    %eax,-0x8c(%rbp)
    8c60:	8b 85 74 ff ff ff    	mov    -0x8c(%rbp),%eax
    8c66:	01 c0                	add    %eax,%eax
    8c68:	89 c0                	mov    %eax,%eax
    8c6a:	48 83 c0 08          	add    $0x8,%rax
    8c6e:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    8c75:	00 
    8c76:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8c7d:	48 01 d0             	add    %rdx,%rax
    8c80:	48 83 c0 08          	add    $0x8,%rax
    8c84:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    8c88:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    8c8c:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    8c90:	48 83 7d e0 1f       	cmpq   $0x1f,-0x20(%rbp)
    8c95:	77 05                	ja     8c9c <tmalloc_small+0x5dc>
    8c97:	e8 00 3d 00 00       	callq  c99c <abort>
    8c9c:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8ca3:	8b 10                	mov    (%rax),%edx
    8ca5:	8b 85 74 ff ff ff    	mov    -0x8c(%rbp),%eax
    8cab:	be 01 00 00 00       	mov    $0x1,%esi
    8cb0:	89 c1                	mov    %eax,%ecx
    8cb2:	d3 e6                	shl    %cl,%esi
    8cb4:	89 f0                	mov    %esi,%eax
    8cb6:	21 d0                	and    %edx,%eax
    8cb8:	85 c0                	test   %eax,%eax
    8cba:	75 27                	jne    8ce3 <tmalloc_small+0x623>
    8cbc:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8cc3:	8b 10                	mov    (%rax),%edx
    8cc5:	8b 85 74 ff ff ff    	mov    -0x8c(%rbp),%eax
    8ccb:	be 01 00 00 00       	mov    $0x1,%esi
    8cd0:	89 c1                	mov    %eax,%ecx
    8cd2:	d3 e6                	shl    %cl,%esi
    8cd4:	89 f0                	mov    %esi,%eax
    8cd6:	09 c2                	or     %eax,%edx
    8cd8:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8cdf:	89 10                	mov    %edx,(%rax)
    8ce1:	eb 34                	jmp    8d17 <tmalloc_small+0x657>
    8ce3:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    8ce7:	48 8b 50 10          	mov    0x10(%rax),%rdx
    8ceb:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8cf2:	48 8b 40 18          	mov    0x18(%rax),%rax
    8cf6:	48 39 c2             	cmp    %rax,%rdx
    8cf9:	0f 93 c0             	setae  %al
    8cfc:	0f b6 c0             	movzbl %al,%eax
    8cff:	48 85 c0             	test   %rax,%rax
    8d02:	74 0e                	je     8d12 <tmalloc_small+0x652>
    8d04:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    8d08:	48 8b 40 10          	mov    0x10(%rax),%rax
    8d0c:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    8d10:	eb 05                	jmp    8d17 <tmalloc_small+0x657>
    8d12:	e8 85 3c 00 00       	callq  c99c <abort>
    8d17:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    8d1b:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    8d1f:	48 89 50 10          	mov    %rdx,0x10(%rax)
    8d23:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8d27:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    8d2b:	48 89 50 18          	mov    %rdx,0x18(%rax)
    8d2f:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    8d33:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    8d37:	48 89 50 10          	mov    %rdx,0x10(%rax)
    8d3b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    8d3f:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    8d43:	48 89 50 18          	mov    %rdx,0x18(%rax)
    8d47:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8d4e:	48 8b 55 88          	mov    -0x78(%rbp),%rdx
    8d52:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8d56:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8d5d:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    8d61:	48 89 50 20          	mov    %rdx,0x20(%rax)
      }
      return chunk2mem(v);
    8d65:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8d69:	48 83 c0 10          	add    $0x10,%rax
    8d6d:	eb 05                	jmp    8d74 <tmalloc_small+0x6b4>
    }
  }

  CORRUPTION_ERROR_ACTION(m);
    8d6f:	e8 28 3c 00 00       	callq  c99c <abort>
  return 0;
}
    8d74:	c9                   	leaveq 
    8d75:	c3                   	retq   

0000000000008d76 <dlmalloc>:

#if !ONLY_MSPACES

void* dlmalloc(size_t bytes) {
    8d76:	55                   	push   %rbp
    8d77:	48 89 e5             	mov    %rsp,%rbp
    8d7a:	53                   	push   %rbx
    8d7b:	48 81 ec e8 00 00 00 	sub    $0xe8,%rsp
    8d82:	48 89 bd 18 ff ff ff 	mov    %rdi,-0xe8(%rbp)

     The ugly goto's here ensure that postaction occurs along all paths.
  */

#if USE_LOCKS
  ensure_initialization(); /* initialize in sys_alloc if not using locks */
    8d89:	48 8b 05 90 83 00 00 	mov    0x8390(%rip),%rax        # 11120 <mparams>
    8d90:	48 85 c0             	test   %rax,%rax
    8d93:	75 07                	jne    8d9c <dlmalloc+0x26>
    8d95:	e8 c7 c5 ff ff       	callq  5361 <init_mparams>
    8d9a:	85 c0                	test   %eax,%eax
    8d9c:	90                   	nop
#endif

  if (!PREACTION(gm)) {
    8d9d:	8b 05 2d 87 00 00    	mov    0x872d(%rip),%eax        # 114d0 <_gm_+0x370>
    8da3:	83 e0 02             	and    $0x2,%eax
    8da6:	85 c0                	test   %eax,%eax
    8da8:	74 23                	je     8dcd <dlmalloc+0x57>
    8daa:	b8 01 00 00 00       	mov    $0x1,%eax
    8daf:	87 05 1f 87 00 00    	xchg   %eax,0x871f(%rip)        # 114d4 <_gm_+0x374>
    8db5:	85 c0                	test   %eax,%eax
    8db7:	74 14                	je     8dcd <dlmalloc+0x57>
    8db9:	48 8d 3d 14 87 00 00 	lea    0x8714(%rip),%rdi        # 114d4 <_gm_+0x374>
    8dc0:	e8 08 c5 ff ff       	callq  52cd <spin_acquire_lock>
    8dc5:	85 c0                	test   %eax,%eax
    8dc7:	0f 85 91 0a 00 00    	jne    985e <dlmalloc+0xae8>
    void* mem;
    size_t nb;
    if (bytes <= MAX_SMALL_REQUEST) {
    8dcd:	48 81 bd 18 ff ff ff 	cmpq   $0xe0,-0xe8(%rbp)
    8dd4:	e0 00 00 00 
    8dd8:	0f 87 12 07 00 00    	ja     94f0 <dlmalloc+0x77a>
      bindex_t idx;
      binmap_t smallbits;
      nb = (bytes < MIN_REQUEST)? MIN_CHUNK_SIZE : pad_request(bytes);
    8dde:	48 83 bd 18 ff ff ff 	cmpq   $0xe,-0xe8(%rbp)
    8de5:	0e 
    8de6:	76 11                	jbe    8df9 <dlmalloc+0x83>
    8de8:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    8def:	48 83 c0 1f          	add    $0x1f,%rax
    8df3:	48 83 e0 f0          	and    $0xfffffffffffffff0,%rax
    8df7:	eb 05                	jmp    8dfe <dlmalloc+0x88>
    8df9:	b8 20 00 00 00       	mov    $0x20,%eax
    8dfe:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
      idx = small_index(nb);
    8e05:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    8e0c:	48 c1 e8 03          	shr    $0x3,%rax
    8e10:	89 85 2c ff ff ff    	mov    %eax,-0xd4(%rbp)
      smallbits = gm->smallmap >> idx;
    8e16:	8b 15 44 83 00 00    	mov    0x8344(%rip),%edx        # 11160 <_gm_>
    8e1c:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8e22:	89 c1                	mov    %eax,%ecx
    8e24:	d3 ea                	shr    %cl,%edx
    8e26:	89 d0                	mov    %edx,%eax
    8e28:	89 85 30 ff ff ff    	mov    %eax,-0xd0(%rbp)

      if ((smallbits & 0x3U) != 0) { /* Remainderless fit to a smallbin. */
    8e2e:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    8e34:	83 e0 03             	and    $0x3,%eax
    8e37:	85 c0                	test   %eax,%eax
    8e39:	0f 84 d3 01 00 00    	je     9012 <dlmalloc+0x29c>
        mchunkptr b, p;
        idx += ~smallbits & 1;       /* Uses next bin if idx empty */
    8e3f:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    8e45:	83 e0 01             	and    $0x1,%eax
    8e48:	85 c0                	test   %eax,%eax
    8e4a:	0f 94 c0             	sete   %al
    8e4d:	0f b6 c0             	movzbl %al,%eax
    8e50:	01 85 2c ff ff ff    	add    %eax,-0xd4(%rbp)
        b = smallbin_at(gm, idx);
    8e56:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8e5c:	01 c0                	add    %eax,%eax
    8e5e:	89 c0                	mov    %eax,%eax
    8e60:	48 83 c0 08          	add    $0x8,%rax
    8e64:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    8e6b:	00 
    8e6c:	48 8d 05 ed 82 00 00 	lea    0x82ed(%rip),%rax        # 11160 <_gm_>
    8e73:	48 01 d0             	add    %rdx,%rax
    8e76:	48 83 c0 08          	add    $0x8,%rax
    8e7a:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
        p = b->fd;
    8e7e:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    8e82:	48 8b 40 10          	mov    0x10(%rax),%rax
    8e86:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
        assert(chunksize(p) == small_index2size(idx));
    8e8a:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8e8e:	48 8b 40 08          	mov    0x8(%rax),%rax
    8e92:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    8e96:	48 89 c2             	mov    %rax,%rdx
    8e99:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8e9f:	c1 e0 03             	shl    $0x3,%eax
    8ea2:	89 c0                	mov    %eax,%eax
    8ea4:	48 39 c2             	cmp    %rax,%rdx
    8ea7:	74 05                	je     8eae <dlmalloc+0x138>
    8ea9:	e8 ee 3a 00 00       	callq  c99c <abort>
        unlink_first_small_chunk(gm, b, p, idx);
    8eae:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8eb2:	48 8b 40 10          	mov    0x10(%rax),%rax
    8eb6:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    8eba:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8ebe:	48 3b 45 a0          	cmp    -0x60(%rbp),%rax
    8ec2:	75 05                	jne    8ec9 <dlmalloc+0x153>
    8ec4:	e8 d3 3a 00 00       	callq  c99c <abort>
    8ec9:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8ecd:	48 3b 45 b0          	cmp    -0x50(%rbp),%rax
    8ed1:	75 05                	jne    8ed8 <dlmalloc+0x162>
    8ed3:	e8 c4 3a 00 00       	callq  c99c <abort>
    8ed8:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8edc:	48 8b 40 08          	mov    0x8(%rax),%rax
    8ee0:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    8ee4:	48 89 c2             	mov    %rax,%rdx
    8ee7:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8eed:	c1 e0 03             	shl    $0x3,%eax
    8ef0:	89 c0                	mov    %eax,%eax
    8ef2:	48 39 c2             	cmp    %rax,%rdx
    8ef5:	74 05                	je     8efc <dlmalloc+0x186>
    8ef7:	e8 a0 3a 00 00       	callq  c99c <abort>
    8efc:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    8f00:	48 3b 45 b0          	cmp    -0x50(%rbp),%rax
    8f04:	75 23                	jne    8f29 <dlmalloc+0x1b3>
    8f06:	8b 15 54 82 00 00    	mov    0x8254(%rip),%edx        # 11160 <_gm_>
    8f0c:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8f12:	be 01 00 00 00       	mov    $0x1,%esi
    8f17:	89 c1                	mov    %eax,%ecx
    8f19:	d3 e6                	shl    %cl,%esi
    8f1b:	89 f0                	mov    %esi,%eax
    8f1d:	f7 d0                	not    %eax
    8f1f:	21 d0                	and    %edx,%eax
    8f21:	89 05 39 82 00 00    	mov    %eax,0x8239(%rip)        # 11160 <_gm_>
    8f27:	eb 4c                	jmp    8f75 <dlmalloc+0x1ff>
    8f29:	48 8b 05 48 82 00 00 	mov    0x8248(%rip),%rax        # 11178 <_gm_+0x18>
    8f30:	48 39 45 b0          	cmp    %rax,-0x50(%rbp)
    8f34:	0f 93 c0             	setae  %al
    8f37:	0f b6 c0             	movzbl %al,%eax
    8f3a:	48 85 c0             	test   %rax,%rax
    8f3d:	74 31                	je     8f70 <dlmalloc+0x1fa>
    8f3f:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    8f43:	48 8b 40 18          	mov    0x18(%rax),%rax
    8f47:	48 39 45 a8          	cmp    %rax,-0x58(%rbp)
    8f4b:	0f 94 c0             	sete   %al
    8f4e:	0f b6 c0             	movzbl %al,%eax
    8f51:	48 85 c0             	test   %rax,%rax
    8f54:	74 1a                	je     8f70 <dlmalloc+0x1fa>
    8f56:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    8f5a:	48 8b 55 a0          	mov    -0x60(%rbp),%rdx
    8f5e:	48 89 50 18          	mov    %rdx,0x18(%rax)
    8f62:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    8f66:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    8f6a:	48 89 50 10          	mov    %rdx,0x10(%rax)
    8f6e:	eb 05                	jmp    8f75 <dlmalloc+0x1ff>
    8f70:	e8 27 3a 00 00       	callq  c99c <abort>
        set_inuse_and_pinuse(gm, p, small_index2size(idx));
    8f75:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8f7b:	c1 e0 03             	shl    $0x3,%eax
    8f7e:	83 c8 03             	or     $0x3,%eax
    8f81:	89 c2                	mov    %eax,%edx
    8f83:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8f87:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8f8b:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8f91:	c1 e0 03             	shl    $0x3,%eax
    8f94:	89 c2                	mov    %eax,%edx
    8f96:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8f9a:	48 01 d0             	add    %rdx,%rax
    8f9d:	48 8b 50 08          	mov    0x8(%rax),%rdx
    8fa1:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8fa7:	c1 e0 03             	shl    $0x3,%eax
    8faa:	89 c1                	mov    %eax,%ecx
    8fac:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8fb0:	48 01 c8             	add    %rcx,%rax
    8fb3:	48 83 ca 01          	or     $0x1,%rdx
    8fb7:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8fbb:	48 8b 0d 5e 81 00 00 	mov    0x815e(%rip),%rcx        # 11120 <mparams>
    8fc2:	48 8d 15 97 81 00 00 	lea    0x8197(%rip),%rdx        # 11160 <_gm_>
    8fc9:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8fcf:	c1 e0 03             	shl    $0x3,%eax
    8fd2:	89 c6                	mov    %eax,%esi
    8fd4:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8fd8:	48 01 f0             	add    %rsi,%rax
    8fdb:	48 31 ca             	xor    %rcx,%rdx
    8fde:	48 89 10             	mov    %rdx,(%rax)
        mem = chunk2mem(p);
    8fe1:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8fe5:	48 83 c0 10          	add    $0x10,%rax
    8fe9:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
        check_malloced_chunk(gm, mem, nb);
    8ff0:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    8ff7:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    8ffe:	48 89 c6             	mov    %rax,%rsi
    9001:	48 8d 3d 58 81 00 00 	lea    0x8158(%rip),%rdi        # 11160 <_gm_>
    9008:	e8 67 c8 ff ff       	callq  5874 <do_check_malloced_chunk>
        goto postaction;
    900d:	e9 d8 07 00 00       	jmpq   97ea <dlmalloc+0xa74>
      }

      else if (nb > gm->dvsize) {
    9012:	48 8b 05 4f 81 00 00 	mov    0x814f(%rip),%rax        # 11168 <_gm_+0x8>
    9019:	48 39 85 50 ff ff ff 	cmp    %rax,-0xb0(%rbp)
    9020:	0f 86 4d 05 00 00    	jbe    9573 <dlmalloc+0x7fd>
        if (smallbits != 0) { /* Use chunk in next nonempty smallbin */
    9026:	83 bd 30 ff ff ff 00 	cmpl   $0x0,-0xd0(%rbp)
    902d:	0f 84 62 04 00 00    	je     9495 <dlmalloc+0x71f>
          mchunkptr b, p, r;
          size_t rsize;
          bindex_t i;
          binmap_t leftbits = (smallbits << idx) & left_bits(idx2bit(idx));
    9033:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    9039:	8b 95 30 ff ff ff    	mov    -0xd0(%rbp),%edx
    903f:	89 c1                	mov    %eax,%ecx
    9041:	d3 e2                	shl    %cl,%edx
    9043:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    9049:	be 01 00 00 00       	mov    $0x1,%esi
    904e:	89 c1                	mov    %eax,%ecx
    9050:	d3 e6                	shl    %cl,%esi
    9052:	89 f0                	mov    %esi,%eax
    9054:	8d 34 00             	lea    (%rax,%rax,1),%esi
    9057:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    905d:	bf 01 00 00 00       	mov    $0x1,%edi
    9062:	89 c1                	mov    %eax,%ecx
    9064:	d3 e7                	shl    %cl,%edi
    9066:	89 f8                	mov    %edi,%eax
    9068:	01 c0                	add    %eax,%eax
    906a:	f7 d8                	neg    %eax
    906c:	09 f0                	or     %esi,%eax
    906e:	21 d0                	and    %edx,%eax
    9070:	89 85 34 ff ff ff    	mov    %eax,-0xcc(%rbp)
          binmap_t leastbit = least_bit(leftbits);
    9076:	8b 85 34 ff ff ff    	mov    -0xcc(%rbp),%eax
    907c:	f7 d8                	neg    %eax
    907e:	23 85 34 ff ff ff    	and    -0xcc(%rbp),%eax
    9084:	89 85 38 ff ff ff    	mov    %eax,-0xc8(%rbp)
          compute_bit2idx(leastbit, i);
    908a:	f3 0f bc 85 38 ff ff 	tzcnt  -0xc8(%rbp),%eax
    9091:	ff 
    9092:	89 85 3c ff ff ff    	mov    %eax,-0xc4(%rbp)
    9098:	8b 85 3c ff ff ff    	mov    -0xc4(%rbp),%eax
    909e:	89 85 40 ff ff ff    	mov    %eax,-0xc0(%rbp)
          b = smallbin_at(gm, i);
    90a4:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    90aa:	01 c0                	add    %eax,%eax
    90ac:	89 c0                	mov    %eax,%eax
    90ae:	48 83 c0 08          	add    $0x8,%rax
    90b2:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    90b9:	00 
    90ba:	48 8d 05 9f 80 00 00 	lea    0x809f(%rip),%rax        # 11160 <_gm_>
    90c1:	48 01 d0             	add    %rdx,%rax
    90c4:	48 83 c0 08          	add    $0x8,%rax
    90c8:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
          p = b->fd;
    90cf:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    90d6:	48 8b 40 10          	mov    0x10(%rax),%rax
    90da:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
          assert(chunksize(p) == small_index2size(i));
    90e1:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    90e8:	48 8b 40 08          	mov    0x8(%rax),%rax
    90ec:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    90f0:	48 89 c2             	mov    %rax,%rdx
    90f3:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    90f9:	c1 e0 03             	shl    $0x3,%eax
    90fc:	89 c0                	mov    %eax,%eax
    90fe:	48 39 c2             	cmp    %rax,%rdx
    9101:	74 05                	je     9108 <dlmalloc+0x392>
    9103:	e8 94 38 00 00       	callq  c99c <abort>
          unlink_first_small_chunk(gm, b, p, i);
    9108:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    910f:	48 8b 40 10          	mov    0x10(%rax),%rax
    9113:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
    911a:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    9121:	48 3b 85 60 ff ff ff 	cmp    -0xa0(%rbp),%rax
    9128:	75 05                	jne    912f <dlmalloc+0x3b9>
    912a:	e8 6d 38 00 00       	callq  c99c <abort>
    912f:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    9136:	48 3b 85 70 ff ff ff 	cmp    -0x90(%rbp),%rax
    913d:	75 05                	jne    9144 <dlmalloc+0x3ce>
    913f:	e8 58 38 00 00       	callq  c99c <abort>
    9144:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    914b:	48 8b 40 08          	mov    0x8(%rax),%rax
    914f:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    9153:	48 89 c2             	mov    %rax,%rdx
    9156:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    915c:	c1 e0 03             	shl    $0x3,%eax
    915f:	89 c0                	mov    %eax,%eax
    9161:	48 39 c2             	cmp    %rax,%rdx
    9164:	74 05                	je     916b <dlmalloc+0x3f5>
    9166:	e8 31 38 00 00       	callq  c99c <abort>
    916b:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    9172:	48 3b 85 70 ff ff ff 	cmp    -0x90(%rbp),%rax
    9179:	75 23                	jne    919e <dlmalloc+0x428>
    917b:	8b 15 df 7f 00 00    	mov    0x7fdf(%rip),%edx        # 11160 <_gm_>
    9181:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    9187:	be 01 00 00 00       	mov    $0x1,%esi
    918c:	89 c1                	mov    %eax,%ecx
    918e:	d3 e6                	shl    %cl,%esi
    9190:	89 f0                	mov    %esi,%eax
    9192:	f7 d0                	not    %eax
    9194:	21 d0                	and    %edx,%eax
    9196:	89 05 c4 7f 00 00    	mov    %eax,0x7fc4(%rip)        # 11160 <_gm_>
    919c:	eb 61                	jmp    91ff <dlmalloc+0x489>
    919e:	48 8b 05 d3 7f 00 00 	mov    0x7fd3(%rip),%rax        # 11178 <_gm_+0x18>
    91a5:	48 39 85 70 ff ff ff 	cmp    %rax,-0x90(%rbp)
    91ac:	0f 93 c0             	setae  %al
    91af:	0f b6 c0             	movzbl %al,%eax
    91b2:	48 85 c0             	test   %rax,%rax
    91b5:	74 43                	je     91fa <dlmalloc+0x484>
    91b7:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    91be:	48 8b 40 18          	mov    0x18(%rax),%rax
    91c2:	48 39 85 68 ff ff ff 	cmp    %rax,-0x98(%rbp)
    91c9:	0f 94 c0             	sete   %al
    91cc:	0f b6 c0             	movzbl %al,%eax
    91cf:	48 85 c0             	test   %rax,%rax
    91d2:	74 26                	je     91fa <dlmalloc+0x484>
    91d4:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    91db:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    91e2:	48 89 50 18          	mov    %rdx,0x18(%rax)
    91e6:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    91ed:	48 8b 95 70 ff ff ff 	mov    -0x90(%rbp),%rdx
    91f4:	48 89 50 10          	mov    %rdx,0x10(%rax)
    91f8:	eb 05                	jmp    91ff <dlmalloc+0x489>
    91fa:	e8 9d 37 00 00       	callq  c99c <abort>
          rsize = small_index2size(i) - nb;
    91ff:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    9205:	c1 e0 03             	shl    $0x3,%eax
    9208:	89 c0                	mov    %eax,%eax
    920a:	48 2b 85 50 ff ff ff 	sub    -0xb0(%rbp),%rax
    9211:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
          /* Fit here cannot be remainderless if 4byte sizes */
          if (SIZE_T_SIZE != 4 && rsize < MIN_CHUNK_SIZE)
    9218:	48 83 bd 78 ff ff ff 	cmpq   $0x1f,-0x88(%rbp)
    921f:	1f 
    9220:	77 7d                	ja     929f <dlmalloc+0x529>
            set_inuse_and_pinuse(gm, p, small_index2size(i));
    9222:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    9228:	c1 e0 03             	shl    $0x3,%eax
    922b:	83 c8 03             	or     $0x3,%eax
    922e:	89 c2                	mov    %eax,%edx
    9230:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    9237:	48 89 50 08          	mov    %rdx,0x8(%rax)
    923b:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    9241:	c1 e0 03             	shl    $0x3,%eax
    9244:	89 c2                	mov    %eax,%edx
    9246:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    924d:	48 01 d0             	add    %rdx,%rax
    9250:	48 8b 50 08          	mov    0x8(%rax),%rdx
    9254:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    925a:	c1 e0 03             	shl    $0x3,%eax
    925d:	89 c1                	mov    %eax,%ecx
    925f:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    9266:	48 01 c8             	add    %rcx,%rax
    9269:	48 83 ca 01          	or     $0x1,%rdx
    926d:	48 89 50 08          	mov    %rdx,0x8(%rax)
    9271:	48 8b 0d a8 7e 00 00 	mov    0x7ea8(%rip),%rcx        # 11120 <mparams>
    9278:	48 8d 15 e1 7e 00 00 	lea    0x7ee1(%rip),%rdx        # 11160 <_gm_>
    927f:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    9285:	c1 e0 03             	shl    $0x3,%eax
    9288:	89 c6                	mov    %eax,%esi
    928a:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    9291:	48 01 f0             	add    %rsi,%rax
    9294:	48 31 ca             	xor    %rcx,%rdx
    9297:	48 89 10             	mov    %rdx,(%rax)
    929a:	e9 c2 01 00 00       	jmpq   9461 <dlmalloc+0x6eb>
          else {
            set_size_and_pinuse_of_inuse_chunk(gm, p, nb);
    929f:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    92a6:	48 83 c8 03          	or     $0x3,%rax
    92aa:	48 89 c2             	mov    %rax,%rdx
    92ad:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    92b4:	48 89 50 08          	mov    %rdx,0x8(%rax)
    92b8:	48 8b 0d 61 7e 00 00 	mov    0x7e61(%rip),%rcx        # 11120 <mparams>
    92bf:	48 8d 15 9a 7e 00 00 	lea    0x7e9a(%rip),%rdx        # 11160 <_gm_>
    92c6:	48 8b b5 68 ff ff ff 	mov    -0x98(%rbp),%rsi
    92cd:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    92d4:	48 01 f0             	add    %rsi,%rax
    92d7:	48 31 ca             	xor    %rcx,%rdx
    92da:	48 89 10             	mov    %rdx,(%rax)
            r = chunk_plus_offset(p, nb);
    92dd:	48 8b 95 68 ff ff ff 	mov    -0x98(%rbp),%rdx
    92e4:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    92eb:	48 01 d0             	add    %rdx,%rax
    92ee:	48 89 45 80          	mov    %rax,-0x80(%rbp)
            set_size_and_pinuse_of_free_chunk(r, rsize);
    92f2:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    92f9:	48 83 c8 01          	or     $0x1,%rax
    92fd:	48 89 c2             	mov    %rax,%rdx
    9300:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    9304:	48 89 50 08          	mov    %rdx,0x8(%rax)
    9308:	48 8b 55 80          	mov    -0x80(%rbp),%rdx
    930c:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    9313:	48 01 c2             	add    %rax,%rdx
    9316:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    931d:	48 89 02             	mov    %rax,(%rdx)
            replace_dv(gm, r, rsize);
    9320:	48 8b 05 41 7e 00 00 	mov    0x7e41(%rip),%rax        # 11168 <_gm_+0x8>
    9327:	48 89 45 88          	mov    %rax,-0x78(%rbp)
    932b:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    932f:	48 c1 e8 03          	shr    $0x3,%rax
    9333:	48 83 f8 1f          	cmp    $0x1f,%rax
    9337:	76 05                	jbe    933e <dlmalloc+0x5c8>
    9339:	e8 5e 36 00 00       	callq  c99c <abort>
    933e:	48 83 7d 88 00       	cmpq   $0x0,-0x78(%rbp)
    9343:	0f 84 ff 00 00 00    	je     9448 <dlmalloc+0x6d2>
    9349:	48 8b 05 30 7e 00 00 	mov    0x7e30(%rip),%rax        # 11180 <_gm_+0x20>
    9350:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    9354:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    9358:	48 c1 e8 03          	shr    $0x3,%rax
    935c:	89 85 44 ff ff ff    	mov    %eax,-0xbc(%rbp)
    9362:	8b 85 44 ff ff ff    	mov    -0xbc(%rbp),%eax
    9368:	01 c0                	add    %eax,%eax
    936a:	89 c0                	mov    %eax,%eax
    936c:	48 83 c0 08          	add    $0x8,%rax
    9370:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    9377:	00 
    9378:	48 8d 05 e1 7d 00 00 	lea    0x7de1(%rip),%rax        # 11160 <_gm_>
    937f:	48 01 d0             	add    %rdx,%rax
    9382:	48 83 c0 08          	add    $0x8,%rax
    9386:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    938a:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    938e:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
    9395:	48 83 7d 88 1f       	cmpq   $0x1f,-0x78(%rbp)
    939a:	77 05                	ja     93a1 <dlmalloc+0x62b>
    939c:	e8 fb 35 00 00       	callq  c99c <abort>
    93a1:	8b 15 b9 7d 00 00    	mov    0x7db9(%rip),%edx        # 11160 <_gm_>
    93a7:	8b 85 44 ff ff ff    	mov    -0xbc(%rbp),%eax
    93ad:	be 01 00 00 00       	mov    $0x1,%esi
    93b2:	89 c1                	mov    %eax,%ecx
    93b4:	d3 e6                	shl    %cl,%esi
    93b6:	89 f0                	mov    %esi,%eax
    93b8:	21 d0                	and    %edx,%eax
    93ba:	85 c0                	test   %eax,%eax
    93bc:	75 21                	jne    93df <dlmalloc+0x669>
    93be:	8b 15 9c 7d 00 00    	mov    0x7d9c(%rip),%edx        # 11160 <_gm_>
    93c4:	8b 85 44 ff ff ff    	mov    -0xbc(%rbp),%eax
    93ca:	be 01 00 00 00       	mov    $0x1,%esi
    93cf:	89 c1                	mov    %eax,%ecx
    93d1:	d3 e6                	shl    %cl,%esi
    93d3:	89 f0                	mov    %esi,%eax
    93d5:	09 d0                	or     %edx,%eax
    93d7:	89 05 83 7d 00 00    	mov    %eax,0x7d83(%rip)        # 11160 <_gm_>
    93dd:	eb 33                	jmp    9412 <dlmalloc+0x69c>
    93df:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    93e3:	48 8b 50 10          	mov    0x10(%rax),%rdx
    93e7:	48 8b 05 8a 7d 00 00 	mov    0x7d8a(%rip),%rax        # 11178 <_gm_+0x18>
    93ee:	48 39 c2             	cmp    %rax,%rdx
    93f1:	0f 93 c0             	setae  %al
    93f4:	0f b6 c0             	movzbl %al,%eax
    93f7:	48 85 c0             	test   %rax,%rax
    93fa:	74 11                	je     940d <dlmalloc+0x697>
    93fc:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    9400:	48 8b 40 10          	mov    0x10(%rax),%rax
    9404:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
    940b:	eb 05                	jmp    9412 <dlmalloc+0x69c>
    940d:	e8 8a 35 00 00       	callq  c99c <abort>
    9412:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    9416:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    941a:	48 89 50 10          	mov    %rdx,0x10(%rax)
    941e:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    9425:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    9429:	48 89 50 18          	mov    %rdx,0x18(%rax)
    942d:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    9431:	48 8b 95 58 ff ff ff 	mov    -0xa8(%rbp),%rdx
    9438:	48 89 50 10          	mov    %rdx,0x10(%rax)
    943c:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    9440:	48 8b 55 98          	mov    -0x68(%rbp),%rdx
    9444:	48 89 50 18          	mov    %rdx,0x18(%rax)
    9448:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    944f:	48 89 05 12 7d 00 00 	mov    %rax,0x7d12(%rip)        # 11168 <_gm_+0x8>
    9456:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    945a:	48 89 05 1f 7d 00 00 	mov    %rax,0x7d1f(%rip)        # 11180 <_gm_+0x20>
          }
          mem = chunk2mem(p);
    9461:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    9468:	48 83 c0 10          	add    $0x10,%rax
    946c:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
          check_malloced_chunk(gm, mem, nb);
    9473:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    947a:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    9481:	48 89 c6             	mov    %rax,%rsi
    9484:	48 8d 3d d5 7c 00 00 	lea    0x7cd5(%rip),%rdi        # 11160 <_gm_>
    948b:	e8 e4 c3 ff ff       	callq  5874 <do_check_malloced_chunk>
          goto postaction;
    9490:	e9 55 03 00 00       	jmpq   97ea <dlmalloc+0xa74>
        }

        else if (gm->treemap != 0 && (mem = tmalloc_small(gm, nb)) != 0) {
    9495:	8b 05 c9 7c 00 00    	mov    0x7cc9(%rip),%eax        # 11164 <_gm_+0x4>
    949b:	85 c0                	test   %eax,%eax
    949d:	0f 84 d0 00 00 00    	je     9573 <dlmalloc+0x7fd>
    94a3:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    94aa:	48 89 c6             	mov    %rax,%rsi
    94ad:	48 8d 3d ac 7c 00 00 	lea    0x7cac(%rip),%rdi        # 11160 <_gm_>
    94b4:	e8 07 f2 ff ff       	callq  86c0 <tmalloc_small>
    94b9:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    94c0:	48 83 bd 48 ff ff ff 	cmpq   $0x0,-0xb8(%rbp)
    94c7:	00 
    94c8:	0f 84 a5 00 00 00    	je     9573 <dlmalloc+0x7fd>
          check_malloced_chunk(gm, mem, nb);
    94ce:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    94d5:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    94dc:	48 89 c6             	mov    %rax,%rsi
    94df:	48 8d 3d 7a 7c 00 00 	lea    0x7c7a(%rip),%rdi        # 11160 <_gm_>
    94e6:	e8 89 c3 ff ff       	callq  5874 <do_check_malloced_chunk>
          goto postaction;
    94eb:	e9 fa 02 00 00       	jmpq   97ea <dlmalloc+0xa74>
        }
      }
    }
    else if (bytes >= MAX_REQUEST)
    94f0:	48 81 bd 18 ff ff ff 	cmpq   $0xffffffffffffff7f,-0xe8(%rbp)
    94f7:	7f ff ff ff 
    94fb:	76 0d                	jbe    950a <dlmalloc+0x794>
      nb = MAX_SIZE_T; /* Too big to allocate. Force failure (in sys alloc) */
    94fd:	48 c7 85 50 ff ff ff 	movq   $0xffffffffffffffff,-0xb0(%rbp)
    9504:	ff ff ff ff 
    9508:	eb 69                	jmp    9573 <dlmalloc+0x7fd>
    else {
      nb = pad_request(bytes);
    950a:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    9511:	48 83 c0 1f          	add    $0x1f,%rax
    9515:	48 83 e0 f0          	and    $0xfffffffffffffff0,%rax
    9519:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
      if (gm->treemap != 0 && (mem = tmalloc_large(gm, nb)) != 0) {
    9520:	8b 05 3e 7c 00 00    	mov    0x7c3e(%rip),%eax        # 11164 <_gm_+0x4>
    9526:	85 c0                	test   %eax,%eax
    9528:	74 49                	je     9573 <dlmalloc+0x7fd>
    952a:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    9531:	48 89 c6             	mov    %rax,%rsi
    9534:	48 8d 3d 25 7c 00 00 	lea    0x7c25(%rip),%rdi        # 11160 <_gm_>
    953b:	e8 16 e5 ff ff       	callq  7a56 <tmalloc_large>
    9540:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    9547:	48 83 bd 48 ff ff ff 	cmpq   $0x0,-0xb8(%rbp)
    954e:	00 
    954f:	74 22                	je     9573 <dlmalloc+0x7fd>
        check_malloced_chunk(gm, mem, nb);
    9551:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    9558:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    955f:	48 89 c6             	mov    %rax,%rsi
    9562:	48 8d 3d f7 7b 00 00 	lea    0x7bf7(%rip),%rdi        # 11160 <_gm_>
    9569:	e8 06 c3 ff ff       	callq  5874 <do_check_malloced_chunk>
        goto postaction;
    956e:	e9 77 02 00 00       	jmpq   97ea <dlmalloc+0xa74>
      }
    }

    if (nb <= gm->dvsize) {
    9573:	48 8b 05 ee 7b 00 00 	mov    0x7bee(%rip),%rax        # 11168 <_gm_+0x8>
    957a:	48 39 85 50 ff ff ff 	cmp    %rax,-0xb0(%rbp)
    9581:	0f 87 58 01 00 00    	ja     96df <dlmalloc+0x969>
      size_t rsize = gm->dvsize - nb;
    9587:	48 8b 05 da 7b 00 00 	mov    0x7bda(%rip),%rax        # 11168 <_gm_+0x8>
    958e:	48 2b 85 50 ff ff ff 	sub    -0xb0(%rbp),%rax
    9595:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
      mchunkptr p = gm->dv;
    9599:	48 8b 05 e0 7b 00 00 	mov    0x7be0(%rip),%rax        # 11180 <_gm_+0x20>
    95a0:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
      if (rsize >= MIN_CHUNK_SIZE) { /* split dv */
    95a4:	48 83 7d d0 1f       	cmpq   $0x1f,-0x30(%rbp)
    95a9:	0f 86 8a 00 00 00    	jbe    9639 <dlmalloc+0x8c3>
        mchunkptr r = gm->dv = chunk_plus_offset(p, nb);
    95af:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    95b3:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    95ba:	48 01 d0             	add    %rdx,%rax
    95bd:	48 89 05 bc 7b 00 00 	mov    %rax,0x7bbc(%rip)        # 11180 <_gm_+0x20>
    95c4:	48 8b 05 b5 7b 00 00 	mov    0x7bb5(%rip),%rax        # 11180 <_gm_+0x20>
    95cb:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
        gm->dvsize = rsize;
    95cf:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    95d3:	48 89 05 8e 7b 00 00 	mov    %rax,0x7b8e(%rip)        # 11168 <_gm_+0x8>
        set_size_and_pinuse_of_free_chunk(r, rsize);
    95da:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    95de:	48 83 c8 01          	or     $0x1,%rax
    95e2:	48 89 c2             	mov    %rax,%rdx
    95e5:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    95e9:	48 89 50 08          	mov    %rdx,0x8(%rax)
    95ed:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    95f1:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    95f5:	48 01 c2             	add    %rax,%rdx
    95f8:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    95fc:	48 89 02             	mov    %rax,(%rdx)
        set_size_and_pinuse_of_inuse_chunk(gm, p, nb);
    95ff:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    9606:	48 83 c8 03          	or     $0x3,%rax
    960a:	48 89 c2             	mov    %rax,%rdx
    960d:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    9611:	48 89 50 08          	mov    %rdx,0x8(%rax)
    9615:	48 8b 0d 04 7b 00 00 	mov    0x7b04(%rip),%rcx        # 11120 <mparams>
    961c:	48 8d 15 3d 7b 00 00 	lea    0x7b3d(%rip),%rdx        # 11160 <_gm_>
    9623:	48 8b 75 d8          	mov    -0x28(%rbp),%rsi
    9627:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    962e:	48 01 f0             	add    %rsi,%rax
    9631:	48 31 ca             	xor    %rcx,%rdx
    9634:	48 89 10             	mov    %rdx,(%rax)
    9637:	eb 75                	jmp    96ae <dlmalloc+0x938>
      }
      else { /* exhaust dv */
        size_t dvs = gm->dvsize;
    9639:	48 8b 05 28 7b 00 00 	mov    0x7b28(%rip),%rax        # 11168 <_gm_+0x8>
    9640:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
        gm->dvsize = 0;
    9644:	48 c7 05 19 7b 00 00 	movq   $0x0,0x7b19(%rip)        # 11168 <_gm_+0x8>
    964b:	00 00 00 00 
        gm->dv = 0;
    964f:	48 c7 05 26 7b 00 00 	movq   $0x0,0x7b26(%rip)        # 11180 <_gm_+0x20>
    9656:	00 00 00 00 
        set_inuse_and_pinuse(gm, p, dvs);
    965a:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    965e:	48 83 c8 03          	or     $0x3,%rax
    9662:	48 89 c2             	mov    %rax,%rdx
    9665:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    9669:	48 89 50 08          	mov    %rdx,0x8(%rax)
    966d:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    9671:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    9675:	48 01 d0             	add    %rdx,%rax
    9678:	48 8b 50 08          	mov    0x8(%rax),%rdx
    967c:	48 8b 4d d8          	mov    -0x28(%rbp),%rcx
    9680:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    9684:	48 01 c8             	add    %rcx,%rax
    9687:	48 83 ca 01          	or     $0x1,%rdx
    968b:	48 89 50 08          	mov    %rdx,0x8(%rax)
    968f:	48 8b 0d 8a 7a 00 00 	mov    0x7a8a(%rip),%rcx        # 11120 <mparams>
    9696:	48 8d 15 c3 7a 00 00 	lea    0x7ac3(%rip),%rdx        # 11160 <_gm_>
    969d:	48 8b 75 d8          	mov    -0x28(%rbp),%rsi
    96a1:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    96a5:	48 01 f0             	add    %rsi,%rax
    96a8:	48 31 ca             	xor    %rcx,%rdx
    96ab:	48 89 10             	mov    %rdx,(%rax)
      }
      mem = chunk2mem(p);
    96ae:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    96b2:	48 83 c0 10          	add    $0x10,%rax
    96b6:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
      check_malloced_chunk(gm, mem, nb);
    96bd:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    96c4:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    96cb:	48 89 c6             	mov    %rax,%rsi
    96ce:	48 8d 3d 8b 7a 00 00 	lea    0x7a8b(%rip),%rdi        # 11160 <_gm_>
    96d5:	e8 9a c1 ff ff       	callq  5874 <do_check_malloced_chunk>
      goto postaction;
    96da:	e9 0b 01 00 00       	jmpq   97ea <dlmalloc+0xa74>
    }

    else if (nb < gm->topsize) { /* Split top */
    96df:	48 8b 05 8a 7a 00 00 	mov    0x7a8a(%rip),%rax        # 11170 <_gm_+0x10>
    96e6:	48 39 85 50 ff ff ff 	cmp    %rax,-0xb0(%rbp)
    96ed:	0f 83 da 00 00 00    	jae    97cd <dlmalloc+0xa57>
      size_t rsize = gm->topsize -= nb;
    96f3:	48 8b 05 76 7a 00 00 	mov    0x7a76(%rip),%rax        # 11170 <_gm_+0x10>
    96fa:	48 2b 85 50 ff ff ff 	sub    -0xb0(%rbp),%rax
    9701:	48 89 05 68 7a 00 00 	mov    %rax,0x7a68(%rip)        # 11170 <_gm_+0x10>
    9708:	48 8b 05 61 7a 00 00 	mov    0x7a61(%rip),%rax        # 11170 <_gm_+0x10>
    970f:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
      mchunkptr p = gm->top;
    9713:	48 8b 05 6e 7a 00 00 	mov    0x7a6e(%rip),%rax        # 11188 <_gm_+0x28>
    971a:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
      mchunkptr r = gm->top = chunk_plus_offset(p, nb);
    971e:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    9722:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    9729:	48 01 d0             	add    %rdx,%rax
    972c:	48 89 05 55 7a 00 00 	mov    %rax,0x7a55(%rip)        # 11188 <_gm_+0x28>
    9733:	48 8b 05 4e 7a 00 00 	mov    0x7a4e(%rip),%rax        # 11188 <_gm_+0x28>
    973a:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
      r->head = rsize | PINUSE_BIT;
    973e:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    9742:	48 83 c8 01          	or     $0x1,%rax
    9746:	48 89 c2             	mov    %rax,%rdx
    9749:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    974d:	48 89 50 08          	mov    %rdx,0x8(%rax)
      set_size_and_pinuse_of_inuse_chunk(gm, p, nb);
    9751:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    9758:	48 83 c8 03          	or     $0x3,%rax
    975c:	48 89 c2             	mov    %rax,%rdx
    975f:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    9763:	48 89 50 08          	mov    %rdx,0x8(%rax)
    9767:	48 8b 0d b2 79 00 00 	mov    0x79b2(%rip),%rcx        # 11120 <mparams>
    976e:	48 8d 15 eb 79 00 00 	lea    0x79eb(%rip),%rdx        # 11160 <_gm_>
    9775:	48 8b 75 c0          	mov    -0x40(%rbp),%rsi
    9779:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    9780:	48 01 f0             	add    %rsi,%rax
    9783:	48 31 ca             	xor    %rcx,%rdx
    9786:	48 89 10             	mov    %rdx,(%rax)
      mem = chunk2mem(p);
    9789:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    978d:	48 83 c0 10          	add    $0x10,%rax
    9791:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
      check_top_chunk(gm, gm->top);
    9798:	48 8b 05 e9 79 00 00 	mov    0x79e9(%rip),%rax        # 11188 <_gm_+0x28>
    979f:	48 89 c6             	mov    %rax,%rsi
    97a2:	48 8d 3d b7 79 00 00 	lea    0x79b7(%rip),%rdi        # 11160 <_gm_>
    97a9:	e8 35 bd ff ff       	callq  54e3 <do_check_top_chunk>
      check_malloced_chunk(gm, mem, nb);
    97ae:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    97b5:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    97bc:	48 89 c6             	mov    %rax,%rsi
    97bf:	48 8d 3d 9a 79 00 00 	lea    0x799a(%rip),%rdi        # 11160 <_gm_>
    97c6:	e8 a9 c0 ff ff       	callq  5874 <do_check_malloced_chunk>
      goto postaction;
    97cb:	eb 1d                	jmp    97ea <dlmalloc+0xa74>
    }

    mem = sys_alloc(gm, nb);
    97cd:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    97d4:	48 89 c6             	mov    %rax,%rsi
    97d7:	48 8d 3d 82 79 00 00 	lea    0x7982(%rip),%rdi        # 11160 <_gm_>
    97de:	e8 e8 d5 ff ff       	callq  6dcb <sys_alloc>
    97e3:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)

  postaction:
    if (mem != 0 && !ok_heap_range(mem, bytes)) ABORT;
    97ea:	48 83 bd 48 ff ff ff 	cmpq   $0x0,-0xb8(%rbp)
    97f1:	00 
    97f2:	74 49                	je     983d <dlmalloc+0xac7>
    97f4:	e8 cf a0 ff ff       	callq  38c8 <get_heap_base>
    97f9:	48 39 85 48 ff ff ff 	cmp    %rax,-0xb8(%rbp)
    9800:	72 36                	jb     9838 <dlmalloc+0xac2>
    9802:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    9809:	48 f7 d0             	not    %rax
    980c:	48 39 85 18 ff ff ff 	cmp    %rax,-0xe8(%rbp)
    9813:	77 23                	ja     9838 <dlmalloc+0xac2>
    9815:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    981c:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    9823:	48 01 d0             	add    %rdx,%rax
    9826:	48 89 c3             	mov    %rax,%rbx
    9829:	bf 00 00 00 00       	mov    $0x0,%edi
    982e:	e8 99 18 00 00       	callq  b0cc <sbrk>
    9833:	48 39 c3             	cmp    %rax,%rbx
    9836:	76 05                	jbe    983d <dlmalloc+0xac7>
    9838:	e8 5f 31 00 00       	callq  c99c <abort>
    POSTACTION(gm);
    983d:	8b 05 8d 7c 00 00    	mov    0x7c8d(%rip),%eax        # 114d0 <_gm_+0x370>
    9843:	83 e0 02             	and    $0x2,%eax
    9846:	85 c0                	test   %eax,%eax
    9848:	74 0b                	je     9855 <dlmalloc+0xadf>
    984a:	b8 00 00 00 00       	mov    $0x0,%eax
    984f:	89 05 7f 7c 00 00    	mov    %eax,0x7c7f(%rip)        # 114d4 <_gm_+0x374>
    return mem;
    9855:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    985c:	eb 05                	jmp    9863 <dlmalloc+0xaed>
  }

  return 0;
    985e:	b8 00 00 00 00       	mov    $0x0,%eax
}
    9863:	48 81 c4 e8 00 00 00 	add    $0xe8,%rsp
    986a:	5b                   	pop    %rbx
    986b:	5d                   	pop    %rbp
    986c:	c3                   	retq   

000000000000986d <dlfree>:

/* ---------------------------- free --------------------------- */

void dlfree(void* mem) {
    986d:	55                   	push   %rbp
    986e:	48 89 e5             	mov    %rsp,%rbp
    9871:	48 81 ec 60 01 00 00 	sub    $0x160,%rsp
    9878:	48 89 bd a8 fe ff ff 	mov    %rdi,-0x158(%rbp)
     Consolidate freed chunks with preceeding or succeeding bordering
     free chunks, if they exist, and then place in a bin.  Intermixed
     with special cases for top, dv, mmapped chunks, and usage errors.
  */

  if (mem != 0) {
    987f:	48 83 bd a8 fe ff ff 	cmpq   $0x0,-0x158(%rbp)
    9886:	00 
    9887:	0f 84 ff 14 00 00    	je     ad8c <dlfree+0x151f>
    mchunkptr p  = mem2chunk(mem);
    988d:	48 8b 85 a8 fe ff ff 	mov    -0x158(%rbp),%rax
    9894:	48 83 e8 10          	sub    $0x10,%rax
    9898:	48 89 85 c8 fe ff ff 	mov    %rax,-0x138(%rbp)
#if FOOTERS
    mstate fm = get_mstate_for(p);
    989f:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    98a6:	48 8b 40 08          	mov    0x8(%rax),%rax
    98aa:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    98ae:	48 89 c2             	mov    %rax,%rdx
    98b1:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    98b8:	48 01 d0             	add    %rdx,%rax
    98bb:	48 8b 10             	mov    (%rax),%rdx
    98be:	48 8b 05 5b 78 00 00 	mov    0x785b(%rip),%rax        # 11120 <mparams>
    98c5:	48 31 d0             	xor    %rdx,%rax
    98c8:	48 89 85 20 ff ff ff 	mov    %rax,-0xe0(%rbp)
    if (!ok_magic(fm)) {
    98cf:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    98d6:	48 8b 50 40          	mov    0x40(%rax),%rdx
    98da:	48 8b 05 3f 78 00 00 	mov    0x783f(%rip),%rax        # 11120 <mparams>
    98e1:	48 39 c2             	cmp    %rax,%rdx
    98e4:	74 05                	je     98eb <dlfree+0x7e>
      USAGE_ERROR_ACTION(fm, p);
    98e6:	e8 b1 30 00 00       	callq  c99c <abort>
      return;
    }
#else /* FOOTERS */
#define fm gm
#endif /* FOOTERS */
    if (!PREACTION(fm)) {
    98eb:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    98f2:	8b 80 70 03 00 00    	mov    0x370(%rax),%eax
    98f8:	83 e0 02             	and    $0x2,%eax
    98fb:	85 c0                	test   %eax,%eax
    98fd:	74 36                	je     9935 <dlfree+0xc8>
    98ff:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9906:	48 8d 90 74 03 00 00 	lea    0x374(%rax),%rdx
    990d:	b8 01 00 00 00       	mov    $0x1,%eax
    9912:	87 02                	xchg   %eax,(%rdx)
    9914:	85 c0                	test   %eax,%eax
    9916:	74 1d                	je     9935 <dlfree+0xc8>
    9918:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    991f:	48 05 74 03 00 00    	add    $0x374,%rax
    9925:	48 89 c7             	mov    %rax,%rdi
    9928:	e8 a0 b9 ff ff       	callq  52cd <spin_acquire_lock>
    992d:	85 c0                	test   %eax,%eax
    992f:	0f 85 57 14 00 00    	jne    ad8c <dlfree+0x151f>
      check_inuse_chunk(fm, p);
    9935:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    993c:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9943:	48 89 d6             	mov    %rdx,%rsi
    9946:	48 89 c7             	mov    %rax,%rdi
    9949:	e8 df bc ff ff       	callq  562d <do_check_inuse_chunk>
      if (RTCHECK(ok_address(fm, p) && ok_inuse(p))) {
    994e:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9955:	48 8b 40 18          	mov    0x18(%rax),%rax
    9959:	48 39 85 c8 fe ff ff 	cmp    %rax,-0x138(%rbp)
    9960:	0f 93 c0             	setae  %al
    9963:	0f b6 c0             	movzbl %al,%eax
    9966:	48 85 c0             	test   %rax,%rax
    9969:	0f 84 e8 13 00 00    	je     ad57 <dlfree+0x14ea>
    996f:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9976:	48 8b 40 08          	mov    0x8(%rax),%rax
    997a:	83 e0 03             	and    $0x3,%eax
    997d:	48 83 f8 01          	cmp    $0x1,%rax
    9981:	0f 95 c0             	setne  %al
    9984:	0f b6 c0             	movzbl %al,%eax
    9987:	48 85 c0             	test   %rax,%rax
    998a:	0f 84 c7 13 00 00    	je     ad57 <dlfree+0x14ea>
        size_t psize = chunksize(p);
    9990:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9997:	48 8b 40 08          	mov    0x8(%rax),%rax
    999b:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    999f:	48 89 85 d0 fe ff ff 	mov    %rax,-0x130(%rbp)
        mchunkptr next = chunk_plus_offset(p, psize);
    99a6:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    99ad:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    99b4:	48 01 d0             	add    %rdx,%rax
    99b7:	48 89 85 28 ff ff ff 	mov    %rax,-0xd8(%rbp)
        if (!pinuse(p)) {
    99be:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    99c5:	48 8b 40 08          	mov    0x8(%rax),%rax
    99c9:	83 e0 01             	and    $0x1,%eax
    99cc:	48 85 c0             	test   %rax,%rax
    99cf:	0f 85 3a 07 00 00    	jne    a10f <dlfree+0x8a2>
          size_t prevsize = p->prev_foot;
    99d5:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    99dc:	48 8b 00             	mov    (%rax),%rax
    99df:	48 89 85 30 ff ff ff 	mov    %rax,-0xd0(%rbp)
          if (is_mmapped(p)) {
    99e6:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    99ed:	48 8b 40 08          	mov    0x8(%rax),%rax
    99f1:	83 e0 03             	and    $0x3,%eax
    99f4:	48 85 c0             	test   %rax,%rax
    99f7:	75 21                	jne    9a1a <dlfree+0x1ad>
            psize += prevsize + MMAP_FOOT_PAD;
    99f9:	48 8b 95 30 ff ff ff 	mov    -0xd0(%rbp),%rdx
    9a00:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    9a07:	48 01 d0             	add    %rdx,%rax
    9a0a:	48 83 c0 20          	add    $0x20,%rax
    9a0e:	48 89 85 d0 fe ff ff 	mov    %rax,-0x130(%rbp)
            if (CALL_MUNMAP((char*)p - prevsize, psize) == 0)
              fm->footprint -= psize;
            goto postaction;
    9a15:	e9 4a 13 00 00       	jmpq   ad64 <dlfree+0x14f7>
          }
          else {
            mchunkptr prev = chunk_minus_offset(p, prevsize);
    9a1a:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    9a21:	48 f7 d8             	neg    %rax
    9a24:	48 89 c2             	mov    %rax,%rdx
    9a27:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9a2e:	48 01 d0             	add    %rdx,%rax
    9a31:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
            psize += prevsize;
    9a38:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    9a3f:	48 01 85 d0 fe ff ff 	add    %rax,-0x130(%rbp)
            p = prev;
    9a46:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9a4d:	48 89 85 c8 fe ff ff 	mov    %rax,-0x138(%rbp)
            if (RTCHECK(ok_address(fm, prev))) { /* consolidate backward */
    9a54:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9a5b:	48 8b 40 18          	mov    0x18(%rax),%rax
    9a5f:	48 39 85 38 ff ff ff 	cmp    %rax,-0xc8(%rbp)
    9a66:	0f 93 c0             	setae  %al
    9a69:	0f b6 c0             	movzbl %al,%eax
    9a6c:	48 85 c0             	test   %rax,%rax
    9a6f:	0f 84 e5 12 00 00    	je     ad5a <dlfree+0x14ed>
              if (p != fm->dv) {
    9a75:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9a7c:	48 8b 40 20          	mov    0x20(%rax),%rax
    9a80:	48 39 85 c8 fe ff ff 	cmp    %rax,-0x138(%rbp)
    9a87:	0f 84 06 06 00 00    	je     a093 <dlfree+0x826>
                unlink_chunk(fm, p, prevsize);
    9a8d:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    9a94:	48 c1 e8 03          	shr    $0x3,%rax
    9a98:	48 83 f8 1f          	cmp    $0x1f,%rax
    9a9c:	0f 87 f9 01 00 00    	ja     9c9b <dlfree+0x42e>
    9aa2:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9aa9:	48 8b 40 10          	mov    0x10(%rax),%rax
    9aad:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
    9ab4:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9abb:	48 8b 40 18          	mov    0x18(%rax),%rax
    9abf:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
    9ac6:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    9acd:	48 c1 e8 03          	shr    $0x3,%rax
    9ad1:	89 85 b4 fe ff ff    	mov    %eax,-0x14c(%rbp)
    9ad7:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9ade:	48 3b 85 78 ff ff ff 	cmp    -0x88(%rbp),%rax
    9ae5:	75 05                	jne    9aec <dlfree+0x27f>
    9ae7:	e8 b0 2e 00 00       	callq  c99c <abort>
    9aec:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9af3:	48 3b 85 70 ff ff ff 	cmp    -0x90(%rbp),%rax
    9afa:	75 05                	jne    9b01 <dlfree+0x294>
    9afc:	e8 9b 2e 00 00       	callq  c99c <abort>
    9b01:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9b08:	48 8b 40 08          	mov    0x8(%rax),%rax
    9b0c:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    9b10:	48 89 c2             	mov    %rax,%rdx
    9b13:	8b 85 b4 fe ff ff    	mov    -0x14c(%rbp),%eax
    9b19:	c1 e0 03             	shl    $0x3,%eax
    9b1c:	89 c0                	mov    %eax,%eax
    9b1e:	48 39 c2             	cmp    %rax,%rdx
    9b21:	74 05                	je     9b28 <dlfree+0x2bb>
    9b23:	e8 74 2e 00 00       	callq  c99c <abort>
    9b28:	8b 85 b4 fe ff ff    	mov    -0x14c(%rbp),%eax
    9b2e:	01 c0                	add    %eax,%eax
    9b30:	89 c0                	mov    %eax,%eax
    9b32:	48 83 c0 08          	add    $0x8,%rax
    9b36:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    9b3d:	00 
    9b3e:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9b45:	48 01 d0             	add    %rdx,%rax
    9b48:	48 83 c0 08          	add    $0x8,%rax
    9b4c:	48 39 85 70 ff ff ff 	cmp    %rax,-0x90(%rbp)
    9b53:	0f 94 c0             	sete   %al
    9b56:	0f b6 c0             	movzbl %al,%eax
    9b59:	48 85 c0             	test   %rax,%rax
    9b5c:	75 4e                	jne    9bac <dlfree+0x33f>
    9b5e:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9b65:	48 8b 40 18          	mov    0x18(%rax),%rax
    9b69:	48 39 85 70 ff ff ff 	cmp    %rax,-0x90(%rbp)
    9b70:	0f 93 c0             	setae  %al
    9b73:	0f b6 c0             	movzbl %al,%eax
    9b76:	48 85 c0             	test   %rax,%rax
    9b79:	74 24                	je     9b9f <dlfree+0x332>
    9b7b:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    9b82:	48 8b 40 18          	mov    0x18(%rax),%rax
    9b86:	48 39 85 c8 fe ff ff 	cmp    %rax,-0x138(%rbp)
    9b8d:	0f 94 c0             	sete   %al
    9b90:	0f b6 c0             	movzbl %al,%eax
    9b93:	48 85 c0             	test   %rax,%rax
    9b96:	74 07                	je     9b9f <dlfree+0x332>
    9b98:	b8 01 00 00 00       	mov    $0x1,%eax
    9b9d:	eb 05                	jmp    9ba4 <dlfree+0x337>
    9b9f:	b8 00 00 00 00       	mov    $0x0,%eax
    9ba4:	85 c0                	test   %eax,%eax
    9ba6:	0f 84 ea 00 00 00    	je     9c96 <dlfree+0x429>
    9bac:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    9bb3:	48 3b 85 70 ff ff ff 	cmp    -0x90(%rbp),%rax
    9bba:	75 2c                	jne    9be8 <dlfree+0x37b>
    9bbc:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9bc3:	8b 10                	mov    (%rax),%edx
    9bc5:	8b 85 b4 fe ff ff    	mov    -0x14c(%rbp),%eax
    9bcb:	be 01 00 00 00       	mov    $0x1,%esi
    9bd0:	89 c1                	mov    %eax,%ecx
    9bd2:	d3 e6                	shl    %cl,%esi
    9bd4:	89 f0                	mov    %esi,%eax
    9bd6:	f7 d0                	not    %eax
    9bd8:	21 c2                	and    %eax,%edx
    9bda:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9be1:	89 10                	mov    %edx,(%rax)
    9be3:	e9 27 05 00 00       	jmpq   a10f <dlfree+0x8a2>
    9be8:	8b 85 b4 fe ff ff    	mov    -0x14c(%rbp),%eax
    9bee:	01 c0                	add    %eax,%eax
    9bf0:	89 c0                	mov    %eax,%eax
    9bf2:	48 83 c0 08          	add    $0x8,%rax
    9bf6:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    9bfd:	00 
    9bfe:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9c05:	48 01 d0             	add    %rdx,%rax
    9c08:	48 83 c0 08          	add    $0x8,%rax
    9c0c:	48 39 85 78 ff ff ff 	cmp    %rax,-0x88(%rbp)
    9c13:	0f 94 c0             	sete   %al
    9c16:	0f b6 c0             	movzbl %al,%eax
    9c19:	48 85 c0             	test   %rax,%rax
    9c1c:	75 4a                	jne    9c68 <dlfree+0x3fb>
    9c1e:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9c25:	48 8b 40 18          	mov    0x18(%rax),%rax
    9c29:	48 39 85 78 ff ff ff 	cmp    %rax,-0x88(%rbp)
    9c30:	0f 93 c0             	setae  %al
    9c33:	0f b6 c0             	movzbl %al,%eax
    9c36:	48 85 c0             	test   %rax,%rax
    9c39:	74 24                	je     9c5f <dlfree+0x3f2>
    9c3b:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    9c42:	48 8b 40 10          	mov    0x10(%rax),%rax
    9c46:	48 39 85 c8 fe ff ff 	cmp    %rax,-0x138(%rbp)
    9c4d:	0f 94 c0             	sete   %al
    9c50:	0f b6 c0             	movzbl %al,%eax
    9c53:	48 85 c0             	test   %rax,%rax
    9c56:	74 07                	je     9c5f <dlfree+0x3f2>
    9c58:	b8 01 00 00 00       	mov    $0x1,%eax
    9c5d:	eb 05                	jmp    9c64 <dlfree+0x3f7>
    9c5f:	b8 00 00 00 00       	mov    $0x0,%eax
    9c64:	85 c0                	test   %eax,%eax
    9c66:	74 29                	je     9c91 <dlfree+0x424>
    9c68:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    9c6f:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    9c76:	48 89 50 18          	mov    %rdx,0x18(%rax)
    9c7a:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    9c81:	48 8b 95 70 ff ff ff 	mov    -0x90(%rbp),%rdx
    9c88:	48 89 50 10          	mov    %rdx,0x10(%rax)
    9c8c:	e9 7e 04 00 00       	jmpq   a10f <dlfree+0x8a2>
    9c91:	e8 06 2d 00 00       	callq  c99c <abort>
    9c96:	e8 01 2d 00 00       	callq  c99c <abort>
    9c9b:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9ca2:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
    9ca9:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9cb0:	48 8b 40 30          	mov    0x30(%rax),%rax
    9cb4:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    9cbb:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9cc2:	48 8b 40 18          	mov    0x18(%rax),%rax
    9cc6:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    9ccd:	0f 84 b9 00 00 00    	je     9d8c <dlfree+0x51f>
    9cd3:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9cda:	48 8b 40 10          	mov    0x10(%rax),%rax
    9cde:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    9ce5:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9cec:	48 8b 40 18          	mov    0x18(%rax),%rax
    9cf0:	48 89 85 d8 fe ff ff 	mov    %rax,-0x128(%rbp)
    9cf7:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9cfe:	48 8b 40 18          	mov    0x18(%rax),%rax
    9d02:	48 39 85 50 ff ff ff 	cmp    %rax,-0xb0(%rbp)
    9d09:	0f 93 c0             	setae  %al
    9d0c:	0f b6 c0             	movzbl %al,%eax
    9d0f:	48 85 c0             	test   %rax,%rax
    9d12:	74 24                	je     9d38 <dlfree+0x4cb>
    9d14:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    9d1b:	48 8b 40 18          	mov    0x18(%rax),%rax
    9d1f:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    9d26:	0f 94 c0             	sete   %al
    9d29:	0f b6 c0             	movzbl %al,%eax
    9d2c:	48 85 c0             	test   %rax,%rax
    9d2f:	74 07                	je     9d38 <dlfree+0x4cb>
    9d31:	b8 01 00 00 00       	mov    $0x1,%eax
    9d36:	eb 05                	jmp    9d3d <dlfree+0x4d0>
    9d38:	b8 00 00 00 00       	mov    $0x0,%eax
    9d3d:	85 c0                	test   %eax,%eax
    9d3f:	74 46                	je     9d87 <dlfree+0x51a>
    9d41:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    9d48:	48 8b 40 10          	mov    0x10(%rax),%rax
    9d4c:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    9d53:	0f 94 c0             	sete   %al
    9d56:	0f b6 c0             	movzbl %al,%eax
    9d59:	48 85 c0             	test   %rax,%rax
    9d5c:	74 29                	je     9d87 <dlfree+0x51a>
    9d5e:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    9d65:	48 8b 95 d8 fe ff ff 	mov    -0x128(%rbp),%rdx
    9d6c:	48 89 50 18          	mov    %rdx,0x18(%rax)
    9d70:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    9d77:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    9d7e:	48 89 50 10          	mov    %rdx,0x10(%rax)
    9d82:	e9 f8 00 00 00       	jmpq   9e7f <dlfree+0x612>
    9d87:	e8 10 2c 00 00       	callq  c99c <abort>
    9d8c:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9d93:	48 83 c0 28          	add    $0x28,%rax
    9d97:	48 89 85 e0 fe ff ff 	mov    %rax,-0x120(%rbp)
    9d9e:	48 8b 85 e0 fe ff ff 	mov    -0x120(%rbp),%rax
    9da5:	48 8b 00             	mov    (%rax),%rax
    9da8:	48 89 85 d8 fe ff ff 	mov    %rax,-0x128(%rbp)
    9daf:	48 83 bd d8 fe ff ff 	cmpq   $0x0,-0x128(%rbp)
    9db6:	00 
    9db7:	75 52                	jne    9e0b <dlfree+0x59e>
    9db9:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9dc0:	48 83 c0 20          	add    $0x20,%rax
    9dc4:	48 89 85 e0 fe ff ff 	mov    %rax,-0x120(%rbp)
    9dcb:	48 8b 85 e0 fe ff ff 	mov    -0x120(%rbp),%rax
    9dd2:	48 8b 00             	mov    (%rax),%rax
    9dd5:	48 89 85 d8 fe ff ff 	mov    %rax,-0x128(%rbp)
    9ddc:	48 83 bd d8 fe ff ff 	cmpq   $0x0,-0x128(%rbp)
    9de3:	00 
    9de4:	0f 84 95 00 00 00    	je     9e7f <dlfree+0x612>
    9dea:	eb 1f                	jmp    9e0b <dlfree+0x59e>
    9dec:	48 8b 85 e8 fe ff ff 	mov    -0x118(%rbp),%rax
    9df3:	48 89 85 e0 fe ff ff 	mov    %rax,-0x120(%rbp)
    9dfa:	48 8b 85 e0 fe ff ff 	mov    -0x120(%rbp),%rax
    9e01:	48 8b 00             	mov    (%rax),%rax
    9e04:	48 89 85 d8 fe ff ff 	mov    %rax,-0x128(%rbp)
    9e0b:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    9e12:	48 83 c0 28          	add    $0x28,%rax
    9e16:	48 89 85 e8 fe ff ff 	mov    %rax,-0x118(%rbp)
    9e1d:	48 8b 85 e8 fe ff ff 	mov    -0x118(%rbp),%rax
    9e24:	48 8b 00             	mov    (%rax),%rax
    9e27:	48 85 c0             	test   %rax,%rax
    9e2a:	75 c0                	jne    9dec <dlfree+0x57f>
    9e2c:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    9e33:	48 83 c0 20          	add    $0x20,%rax
    9e37:	48 89 85 e8 fe ff ff 	mov    %rax,-0x118(%rbp)
    9e3e:	48 8b 85 e8 fe ff ff 	mov    -0x118(%rbp),%rax
    9e45:	48 8b 00             	mov    (%rax),%rax
    9e48:	48 85 c0             	test   %rax,%rax
    9e4b:	75 9f                	jne    9dec <dlfree+0x57f>
    9e4d:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9e54:	48 8b 40 18          	mov    0x18(%rax),%rax
    9e58:	48 39 85 e0 fe ff ff 	cmp    %rax,-0x120(%rbp)
    9e5f:	0f 93 c0             	setae  %al
    9e62:	0f b6 c0             	movzbl %al,%eax
    9e65:	48 85 c0             	test   %rax,%rax
    9e68:	74 10                	je     9e7a <dlfree+0x60d>
    9e6a:	48 8b 85 e0 fe ff ff 	mov    -0x120(%rbp),%rax
    9e71:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    9e78:	eb 05                	jmp    9e7f <dlfree+0x612>
    9e7a:	e8 1d 2b 00 00       	callq  c99c <abort>
    9e7f:	48 83 bd 48 ff ff ff 	cmpq   $0x0,-0xb8(%rbp)
    9e86:	00 
    9e87:	0f 84 82 02 00 00    	je     a10f <dlfree+0x8a2>
    9e8d:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9e94:	8b 40 38             	mov    0x38(%rax),%eax
    9e97:	89 c0                	mov    %eax,%eax
    9e99:	48 83 c0 4a          	add    $0x4a,%rax
    9e9d:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    9ea4:	00 
    9ea5:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9eac:	48 01 d0             	add    %rdx,%rax
    9eaf:	48 83 c0 08          	add    $0x8,%rax
    9eb3:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
    9eba:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    9ec1:	48 8b 00             	mov    (%rax),%rax
    9ec4:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    9ecb:	75 53                	jne    9f20 <dlfree+0x6b3>
    9ecd:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    9ed4:	48 8b 95 d8 fe ff ff 	mov    -0x128(%rbp),%rdx
    9edb:	48 89 10             	mov    %rdx,(%rax)
    9ede:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    9ee5:	48 8b 00             	mov    (%rax),%rax
    9ee8:	48 85 c0             	test   %rax,%rax
    9eeb:	0f 85 8d 00 00 00    	jne    9f7e <dlfree+0x711>
    9ef1:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9ef8:	8b 50 04             	mov    0x4(%rax),%edx
    9efb:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9f02:	8b 40 38             	mov    0x38(%rax),%eax
    9f05:	be 01 00 00 00       	mov    $0x1,%esi
    9f0a:	89 c1                	mov    %eax,%ecx
    9f0c:	d3 e6                	shl    %cl,%esi
    9f0e:	89 f0                	mov    %esi,%eax
    9f10:	f7 d0                	not    %eax
    9f12:	21 c2                	and    %eax,%edx
    9f14:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9f1b:	89 50 04             	mov    %edx,0x4(%rax)
    9f1e:	eb 5e                	jmp    9f7e <dlfree+0x711>
    9f20:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9f27:	48 8b 40 18          	mov    0x18(%rax),%rax
    9f2b:	48 39 85 48 ff ff ff 	cmp    %rax,-0xb8(%rbp)
    9f32:	0f 93 c0             	setae  %al
    9f35:	0f b6 c0             	movzbl %al,%eax
    9f38:	48 85 c0             	test   %rax,%rax
    9f3b:	74 3c                	je     9f79 <dlfree+0x70c>
    9f3d:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    9f44:	48 8b 40 20          	mov    0x20(%rax),%rax
    9f48:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    9f4f:	75 14                	jne    9f65 <dlfree+0x6f8>
    9f51:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    9f58:	48 8b 95 d8 fe ff ff 	mov    -0x128(%rbp),%rdx
    9f5f:	48 89 50 20          	mov    %rdx,0x20(%rax)
    9f63:	eb 19                	jmp    9f7e <dlfree+0x711>
    9f65:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    9f6c:	48 8b 95 d8 fe ff ff 	mov    -0x128(%rbp),%rdx
    9f73:	48 89 50 28          	mov    %rdx,0x28(%rax)
    9f77:	eb 05                	jmp    9f7e <dlfree+0x711>
    9f79:	e8 1e 2a 00 00       	callq  c99c <abort>
    9f7e:	48 83 bd d8 fe ff ff 	cmpq   $0x0,-0x128(%rbp)
    9f85:	00 
    9f86:	0f 84 83 01 00 00    	je     a10f <dlfree+0x8a2>
    9f8c:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9f93:	48 8b 40 18          	mov    0x18(%rax),%rax
    9f97:	48 39 85 d8 fe ff ff 	cmp    %rax,-0x128(%rbp)
    9f9e:	0f 93 c0             	setae  %al
    9fa1:	0f b6 c0             	movzbl %al,%eax
    9fa4:	48 85 c0             	test   %rax,%rax
    9fa7:	0f 84 e1 00 00 00    	je     a08e <dlfree+0x821>
    9fad:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    9fb4:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    9fbb:	48 89 50 30          	mov    %rdx,0x30(%rax)
    9fbf:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9fc6:	48 8b 40 20          	mov    0x20(%rax),%rax
    9fca:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
    9fd1:	48 83 bd 60 ff ff ff 	cmpq   $0x0,-0xa0(%rbp)
    9fd8:	00 
    9fd9:	74 48                	je     a023 <dlfree+0x7b6>
    9fdb:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9fe2:	48 8b 40 18          	mov    0x18(%rax),%rax
    9fe6:	48 39 85 60 ff ff ff 	cmp    %rax,-0xa0(%rbp)
    9fed:	0f 93 c0             	setae  %al
    9ff0:	0f b6 c0             	movzbl %al,%eax
    9ff3:	48 85 c0             	test   %rax,%rax
    9ff6:	74 26                	je     a01e <dlfree+0x7b1>
    9ff8:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    9fff:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    a006:	48 89 50 20          	mov    %rdx,0x20(%rax)
    a00a:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    a011:	48 8b 95 d8 fe ff ff 	mov    -0x128(%rbp),%rdx
    a018:	48 89 50 30          	mov    %rdx,0x30(%rax)
    a01c:	eb 05                	jmp    a023 <dlfree+0x7b6>
    a01e:	e8 79 29 00 00       	callq  c99c <abort>
    a023:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    a02a:	48 8b 40 28          	mov    0x28(%rax),%rax
    a02e:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
    a035:	48 83 bd 68 ff ff ff 	cmpq   $0x0,-0x98(%rbp)
    a03c:	00 
    a03d:	0f 84 cc 00 00 00    	je     a10f <dlfree+0x8a2>
    a043:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a04a:	48 8b 40 18          	mov    0x18(%rax),%rax
    a04e:	48 39 85 68 ff ff ff 	cmp    %rax,-0x98(%rbp)
    a055:	0f 93 c0             	setae  %al
    a058:	0f b6 c0             	movzbl %al,%eax
    a05b:	48 85 c0             	test   %rax,%rax
    a05e:	74 29                	je     a089 <dlfree+0x81c>
    a060:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    a067:	48 8b 95 68 ff ff ff 	mov    -0x98(%rbp),%rdx
    a06e:	48 89 50 28          	mov    %rdx,0x28(%rax)
    a072:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    a079:	48 8b 95 d8 fe ff ff 	mov    -0x128(%rbp),%rdx
    a080:	48 89 50 30          	mov    %rdx,0x30(%rax)
    a084:	e9 86 00 00 00       	jmpq   a10f <dlfree+0x8a2>
    a089:	e8 0e 29 00 00       	callq  c99c <abort>
    a08e:	e8 09 29 00 00       	callq  c99c <abort>
              }
              else if ((next->head & INUSE_BITS) == INUSE_BITS) {
    a093:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a09a:	48 8b 40 08          	mov    0x8(%rax),%rax
    a09e:	83 e0 03             	and    $0x3,%eax
    a0a1:	48 83 f8 03          	cmp    $0x3,%rax
    a0a5:	75 68                	jne    a10f <dlfree+0x8a2>
                fm->dvsize = psize;
    a0a7:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a0ae:	48 8b 95 d0 fe ff ff 	mov    -0x130(%rbp),%rdx
    a0b5:	48 89 50 08          	mov    %rdx,0x8(%rax)
                set_free_with_pinuse(p, psize, next);
    a0b9:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a0c0:	48 8b 40 08          	mov    0x8(%rax),%rax
    a0c4:	48 83 e0 fe          	and    $0xfffffffffffffffe,%rax
    a0c8:	48 89 c2             	mov    %rax,%rdx
    a0cb:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a0d2:	48 89 50 08          	mov    %rdx,0x8(%rax)
    a0d6:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a0dd:	48 83 c8 01          	or     $0x1,%rax
    a0e1:	48 89 c2             	mov    %rax,%rdx
    a0e4:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    a0eb:	48 89 50 08          	mov    %rdx,0x8(%rax)
    a0ef:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a0f6:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a0fd:	48 01 c2             	add    %rax,%rdx
    a100:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a107:	48 89 02             	mov    %rax,(%rdx)
                goto postaction;
    a10a:	e9 55 0c 00 00       	jmpq   ad64 <dlfree+0x14f7>
            else
              goto erroraction;
          }
        }

        if (RTCHECK(ok_next(p, next) && ok_pinuse(next))) {
    a10f:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    a116:	48 3b 85 28 ff ff ff 	cmp    -0xd8(%rbp),%rax
    a11d:	0f 92 c0             	setb   %al
    a120:	0f b6 c0             	movzbl %al,%eax
    a123:	48 85 c0             	test   %rax,%rax
    a126:	0f 84 2b 0c 00 00    	je     ad57 <dlfree+0x14ea>
    a12c:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a133:	48 8b 40 08          	mov    0x8(%rax),%rax
    a137:	83 e0 01             	and    $0x1,%eax
    a13a:	48 85 c0             	test   %rax,%rax
    a13d:	0f 95 c0             	setne  %al
    a140:	0f b6 c0             	movzbl %al,%eax
    a143:	48 85 c0             	test   %rax,%rax
    a146:	0f 84 0b 0c 00 00    	je     ad57 <dlfree+0x14ea>
          if (!cinuse(next)) {  /* consolidate forward */
    a14c:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a153:	48 8b 40 08          	mov    0x8(%rax),%rax
    a157:	83 e0 02             	and    $0x2,%eax
    a15a:	48 85 c0             	test   %rax,%rax
    a15d:	0f 85 18 07 00 00    	jne    a87b <dlfree+0x100e>
            if (next == fm->top) {
    a163:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a16a:	48 8b 40 28          	mov    0x28(%rax),%rax
    a16e:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    a175:	0f 85 b7 00 00 00    	jne    a232 <dlfree+0x9c5>
              size_t tsize = fm->topsize += psize;
    a17b:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a182:	48 8b 50 10          	mov    0x10(%rax),%rdx
    a186:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a18d:	48 01 c2             	add    %rax,%rdx
    a190:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a197:	48 89 50 10          	mov    %rdx,0x10(%rax)
    a19b:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a1a2:	48 8b 40 10          	mov    0x10(%rax),%rax
    a1a6:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
              fm->top = p;
    a1aa:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a1b1:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a1b8:	48 89 50 28          	mov    %rdx,0x28(%rax)
              p->head = tsize | PINUSE_BIT;
    a1bc:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    a1c0:	48 83 c8 01          	or     $0x1,%rax
    a1c4:	48 89 c2             	mov    %rax,%rdx
    a1c7:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    a1ce:	48 89 50 08          	mov    %rdx,0x8(%rax)
              if (p == fm->dv) {
    a1d2:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a1d9:	48 8b 40 20          	mov    0x20(%rax),%rax
    a1dd:	48 39 85 c8 fe ff ff 	cmp    %rax,-0x138(%rbp)
    a1e4:	75 1e                	jne    a204 <dlfree+0x997>
                fm->dv = 0;
    a1e6:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a1ed:	48 c7 40 20 00 00 00 	movq   $0x0,0x20(%rax)
    a1f4:	00 
                fm->dvsize = 0;
    a1f5:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a1fc:	48 c7 40 08 00 00 00 	movq   $0x0,0x8(%rax)
    a203:	00 
              }
              if (should_trim(fm, tsize))
    a204:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a20b:	48 8b 40 30          	mov    0x30(%rax),%rax
    a20f:	48 39 45 d0          	cmp    %rax,-0x30(%rbp)
    a213:	0f 86 47 0b 00 00    	jbe    ad60 <dlfree+0x14f3>
                sys_trim(fm, 0);
    a219:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a220:	be 00 00 00 00       	mov    $0x0,%esi
    a225:	48 89 c7             	mov    %rax,%rdi
    a228:	e8 fd d5 ff ff       	callq  782a <sys_trim>
              goto postaction;
    a22d:	e9 2e 0b 00 00       	jmpq   ad60 <dlfree+0x14f3>
            }
            else if (next == fm->dv) {
    a232:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a239:	48 8b 40 20          	mov    0x20(%rax),%rax
    a23d:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    a244:	75 71                	jne    a2b7 <dlfree+0xa4a>
              size_t dsize = fm->dvsize += psize;
    a246:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a24d:	48 8b 50 08          	mov    0x8(%rax),%rdx
    a251:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a258:	48 01 c2             	add    %rax,%rdx
    a25b:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a262:	48 89 50 08          	mov    %rdx,0x8(%rax)
    a266:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a26d:	48 8b 40 08          	mov    0x8(%rax),%rax
    a271:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
              fm->dv = p;
    a275:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a27c:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a283:	48 89 50 20          	mov    %rdx,0x20(%rax)
              set_size_and_pinuse_of_free_chunk(p, dsize);
    a287:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    a28b:	48 83 c8 01          	or     $0x1,%rax
    a28f:	48 89 c2             	mov    %rax,%rdx
    a292:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    a299:	48 89 50 08          	mov    %rdx,0x8(%rax)
    a29d:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a2a4:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    a2a8:	48 01 c2             	add    %rax,%rdx
    a2ab:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    a2af:	48 89 02             	mov    %rax,(%rdx)
              goto postaction;
    a2b2:	e9 ad 0a 00 00       	jmpq   ad64 <dlfree+0x14f7>
            }
            else {
              size_t nsize = chunksize(next);
    a2b7:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a2be:	48 8b 40 08          	mov    0x8(%rax),%rax
    a2c2:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    a2c6:	48 89 45 80          	mov    %rax,-0x80(%rbp)
              psize += nsize;
    a2ca:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    a2ce:	48 01 85 d0 fe ff ff 	add    %rax,-0x130(%rbp)
              unlink_chunk(fm, next, nsize);
    a2d5:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    a2d9:	48 c1 e8 03          	shr    $0x3,%rax
    a2dd:	48 83 f8 1f          	cmp    $0x1f,%rax
    a2e1:	0f 87 c6 01 00 00    	ja     a4ad <dlfree+0xc40>
    a2e7:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a2ee:	48 8b 40 10          	mov    0x10(%rax),%rax
    a2f2:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    a2f6:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a2fd:	48 8b 40 18          	mov    0x18(%rax),%rax
    a301:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    a305:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    a309:	48 c1 e8 03          	shr    $0x3,%rax
    a30d:	89 85 b8 fe ff ff    	mov    %eax,-0x148(%rbp)
    a313:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a31a:	48 3b 45 c0          	cmp    -0x40(%rbp),%rax
    a31e:	75 05                	jne    a325 <dlfree+0xab8>
    a320:	e8 77 26 00 00       	callq  c99c <abort>
    a325:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a32c:	48 3b 45 b8          	cmp    -0x48(%rbp),%rax
    a330:	75 05                	jne    a337 <dlfree+0xaca>
    a332:	e8 65 26 00 00       	callq  c99c <abort>
    a337:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a33e:	48 8b 40 08          	mov    0x8(%rax),%rax
    a342:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    a346:	48 89 c2             	mov    %rax,%rdx
    a349:	8b 85 b8 fe ff ff    	mov    -0x148(%rbp),%eax
    a34f:	c1 e0 03             	shl    $0x3,%eax
    a352:	89 c0                	mov    %eax,%eax
    a354:	48 39 c2             	cmp    %rax,%rdx
    a357:	74 05                	je     a35e <dlfree+0xaf1>
    a359:	e8 3e 26 00 00       	callq  c99c <abort>
    a35e:	8b 85 b8 fe ff ff    	mov    -0x148(%rbp),%eax
    a364:	01 c0                	add    %eax,%eax
    a366:	89 c0                	mov    %eax,%eax
    a368:	48 83 c0 08          	add    $0x8,%rax
    a36c:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    a373:	00 
    a374:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a37b:	48 01 d0             	add    %rdx,%rax
    a37e:	48 83 c0 08          	add    $0x8,%rax
    a382:	48 39 45 b8          	cmp    %rax,-0x48(%rbp)
    a386:	0f 94 c0             	sete   %al
    a389:	0f b6 c0             	movzbl %al,%eax
    a38c:	48 85 c0             	test   %rax,%rax
    a38f:	75 48                	jne    a3d9 <dlfree+0xb6c>
    a391:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a398:	48 8b 40 18          	mov    0x18(%rax),%rax
    a39c:	48 39 45 b8          	cmp    %rax,-0x48(%rbp)
    a3a0:	0f 93 c0             	setae  %al
    a3a3:	0f b6 c0             	movzbl %al,%eax
    a3a6:	48 85 c0             	test   %rax,%rax
    a3a9:	74 21                	je     a3cc <dlfree+0xb5f>
    a3ab:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    a3af:	48 8b 40 18          	mov    0x18(%rax),%rax
    a3b3:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    a3ba:	0f 94 c0             	sete   %al
    a3bd:	0f b6 c0             	movzbl %al,%eax
    a3c0:	48 85 c0             	test   %rax,%rax
    a3c3:	74 07                	je     a3cc <dlfree+0xb5f>
    a3c5:	b8 01 00 00 00       	mov    $0x1,%eax
    a3ca:	eb 05                	jmp    a3d1 <dlfree+0xb64>
    a3cc:	b8 00 00 00 00       	mov    $0x0,%eax
    a3d1:	85 c0                	test   %eax,%eax
    a3d3:	0f 84 cf 00 00 00    	je     a4a8 <dlfree+0xc3b>
    a3d9:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    a3dd:	48 3b 45 b8          	cmp    -0x48(%rbp),%rax
    a3e1:	75 2c                	jne    a40f <dlfree+0xba2>
    a3e3:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a3ea:	8b 10                	mov    (%rax),%edx
    a3ec:	8b 85 b8 fe ff ff    	mov    -0x148(%rbp),%eax
    a3f2:	be 01 00 00 00       	mov    $0x1,%esi
    a3f7:	89 c1                	mov    %eax,%ecx
    a3f9:	d3 e6                	shl    %cl,%esi
    a3fb:	89 f0                	mov    %esi,%eax
    a3fd:	f7 d0                	not    %eax
    a3ff:	21 c2                	and    %eax,%edx
    a401:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a408:	89 10                	mov    %edx,(%rax)
    a40a:	e9 0d 04 00 00       	jmpq   a81c <dlfree+0xfaf>
    a40f:	8b 85 b8 fe ff ff    	mov    -0x148(%rbp),%eax
    a415:	01 c0                	add    %eax,%eax
    a417:	89 c0                	mov    %eax,%eax
    a419:	48 83 c0 08          	add    $0x8,%rax
    a41d:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    a424:	00 
    a425:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a42c:	48 01 d0             	add    %rdx,%rax
    a42f:	48 83 c0 08          	add    $0x8,%rax
    a433:	48 39 45 c0          	cmp    %rax,-0x40(%rbp)
    a437:	0f 94 c0             	sete   %al
    a43a:	0f b6 c0             	movzbl %al,%eax
    a43d:	48 85 c0             	test   %rax,%rax
    a440:	75 44                	jne    a486 <dlfree+0xc19>
    a442:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a449:	48 8b 40 18          	mov    0x18(%rax),%rax
    a44d:	48 39 45 c0          	cmp    %rax,-0x40(%rbp)
    a451:	0f 93 c0             	setae  %al
    a454:	0f b6 c0             	movzbl %al,%eax
    a457:	48 85 c0             	test   %rax,%rax
    a45a:	74 21                	je     a47d <dlfree+0xc10>
    a45c:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    a460:	48 8b 40 10          	mov    0x10(%rax),%rax
    a464:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    a46b:	0f 94 c0             	sete   %al
    a46e:	0f b6 c0             	movzbl %al,%eax
    a471:	48 85 c0             	test   %rax,%rax
    a474:	74 07                	je     a47d <dlfree+0xc10>
    a476:	b8 01 00 00 00       	mov    $0x1,%eax
    a47b:	eb 05                	jmp    a482 <dlfree+0xc15>
    a47d:	b8 00 00 00 00       	mov    $0x0,%eax
    a482:	85 c0                	test   %eax,%eax
    a484:	74 1d                	je     a4a3 <dlfree+0xc36>
    a486:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    a48a:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    a48e:	48 89 50 18          	mov    %rdx,0x18(%rax)
    a492:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    a496:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
    a49a:	48 89 50 10          	mov    %rdx,0x10(%rax)
    a49e:	e9 79 03 00 00       	jmpq   a81c <dlfree+0xfaf>
    a4a3:	e8 f4 24 00 00       	callq  c99c <abort>
    a4a8:	e8 ef 24 00 00       	callq  c99c <abort>
    a4ad:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a4b4:	48 89 45 88          	mov    %rax,-0x78(%rbp)
    a4b8:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a4bc:	48 8b 40 30          	mov    0x30(%rax),%rax
    a4c0:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    a4c4:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a4c8:	48 8b 40 18          	mov    0x18(%rax),%rax
    a4cc:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    a4d0:	0f 84 9e 00 00 00    	je     a574 <dlfree+0xd07>
    a4d6:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a4da:	48 8b 40 10          	mov    0x10(%rax),%rax
    a4de:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    a4e2:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a4e6:	48 8b 40 18          	mov    0x18(%rax),%rax
    a4ea:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    a4f1:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a4f8:	48 8b 40 18          	mov    0x18(%rax),%rax
    a4fc:	48 39 45 98          	cmp    %rax,-0x68(%rbp)
    a500:	0f 93 c0             	setae  %al
    a503:	0f b6 c0             	movzbl %al,%eax
    a506:	48 85 c0             	test   %rax,%rax
    a509:	74 1e                	je     a529 <dlfree+0xcbc>
    a50b:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    a50f:	48 8b 40 18          	mov    0x18(%rax),%rax
    a513:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    a517:	0f 94 c0             	sete   %al
    a51a:	0f b6 c0             	movzbl %al,%eax
    a51d:	48 85 c0             	test   %rax,%rax
    a520:	74 07                	je     a529 <dlfree+0xcbc>
    a522:	b8 01 00 00 00       	mov    $0x1,%eax
    a527:	eb 05                	jmp    a52e <dlfree+0xcc1>
    a529:	b8 00 00 00 00       	mov    $0x0,%eax
    a52e:	85 c0                	test   %eax,%eax
    a530:	74 3d                	je     a56f <dlfree+0xd02>
    a532:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    a539:	48 8b 40 10          	mov    0x10(%rax),%rax
    a53d:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    a541:	0f 94 c0             	sete   %al
    a544:	0f b6 c0             	movzbl %al,%eax
    a547:	48 85 c0             	test   %rax,%rax
    a54a:	74 23                	je     a56f <dlfree+0xd02>
    a54c:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    a550:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    a557:	48 89 50 18          	mov    %rdx,0x18(%rax)
    a55b:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    a562:	48 8b 55 98          	mov    -0x68(%rbp),%rdx
    a566:	48 89 50 10          	mov    %rdx,0x10(%rax)
    a56a:	e9 f2 00 00 00       	jmpq   a661 <dlfree+0xdf4>
    a56f:	e8 28 24 00 00       	callq  c99c <abort>
    a574:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a578:	48 83 c0 28          	add    $0x28,%rax
    a57c:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
    a583:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    a58a:	48 8b 00             	mov    (%rax),%rax
    a58d:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    a594:	48 83 bd f0 fe ff ff 	cmpq   $0x0,-0x110(%rbp)
    a59b:	00 
    a59c:	75 4f                	jne    a5ed <dlfree+0xd80>
    a59e:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a5a2:	48 83 c0 20          	add    $0x20,%rax
    a5a6:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
    a5ad:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    a5b4:	48 8b 00             	mov    (%rax),%rax
    a5b7:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    a5be:	48 83 bd f0 fe ff ff 	cmpq   $0x0,-0x110(%rbp)
    a5c5:	00 
    a5c6:	0f 84 95 00 00 00    	je     a661 <dlfree+0xdf4>
    a5cc:	eb 1f                	jmp    a5ed <dlfree+0xd80>
    a5ce:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    a5d5:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
    a5dc:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    a5e3:	48 8b 00             	mov    (%rax),%rax
    a5e6:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    a5ed:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    a5f4:	48 83 c0 28          	add    $0x28,%rax
    a5f8:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
    a5ff:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    a606:	48 8b 00             	mov    (%rax),%rax
    a609:	48 85 c0             	test   %rax,%rax
    a60c:	75 c0                	jne    a5ce <dlfree+0xd61>
    a60e:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    a615:	48 83 c0 20          	add    $0x20,%rax
    a619:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
    a620:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    a627:	48 8b 00             	mov    (%rax),%rax
    a62a:	48 85 c0             	test   %rax,%rax
    a62d:	75 9f                	jne    a5ce <dlfree+0xd61>
    a62f:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a636:	48 8b 40 18          	mov    0x18(%rax),%rax
    a63a:	48 39 85 f8 fe ff ff 	cmp    %rax,-0x108(%rbp)
    a641:	0f 93 c0             	setae  %al
    a644:	0f b6 c0             	movzbl %al,%eax
    a647:	48 85 c0             	test   %rax,%rax
    a64a:	74 10                	je     a65c <dlfree+0xdef>
    a64c:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    a653:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    a65a:	eb 05                	jmp    a661 <dlfree+0xdf4>
    a65c:	e8 3b 23 00 00       	callq  c99c <abort>
    a661:	48 83 7d 90 00       	cmpq   $0x0,-0x70(%rbp)
    a666:	0f 84 b0 01 00 00    	je     a81c <dlfree+0xfaf>
    a66c:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a670:	8b 40 38             	mov    0x38(%rax),%eax
    a673:	89 c0                	mov    %eax,%eax
    a675:	48 83 c0 4a          	add    $0x4a,%rax
    a679:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    a680:	00 
    a681:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a688:	48 01 d0             	add    %rdx,%rax
    a68b:	48 83 c0 08          	add    $0x8,%rax
    a68f:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
    a693:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    a697:	48 8b 00             	mov    (%rax),%rax
    a69a:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    a69e:	75 46                	jne    a6e6 <dlfree+0xe79>
    a6a0:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    a6a4:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    a6ab:	48 89 10             	mov    %rdx,(%rax)
    a6ae:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    a6b2:	48 8b 00             	mov    (%rax),%rax
    a6b5:	48 85 c0             	test   %rax,%rax
    a6b8:	75 7b                	jne    a735 <dlfree+0xec8>
    a6ba:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a6c1:	8b 50 04             	mov    0x4(%rax),%edx
    a6c4:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a6c8:	8b 40 38             	mov    0x38(%rax),%eax
    a6cb:	be 01 00 00 00       	mov    $0x1,%esi
    a6d0:	89 c1                	mov    %eax,%ecx
    a6d2:	d3 e6                	shl    %cl,%esi
    a6d4:	89 f0                	mov    %esi,%eax
    a6d6:	f7 d0                	not    %eax
    a6d8:	21 c2                	and    %eax,%edx
    a6da:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a6e1:	89 50 04             	mov    %edx,0x4(%rax)
    a6e4:	eb 4f                	jmp    a735 <dlfree+0xec8>
    a6e6:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a6ed:	48 8b 40 18          	mov    0x18(%rax),%rax
    a6f1:	48 39 45 90          	cmp    %rax,-0x70(%rbp)
    a6f5:	0f 93 c0             	setae  %al
    a6f8:	0f b6 c0             	movzbl %al,%eax
    a6fb:	48 85 c0             	test   %rax,%rax
    a6fe:	74 30                	je     a730 <dlfree+0xec3>
    a700:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    a704:	48 8b 40 20          	mov    0x20(%rax),%rax
    a708:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    a70c:	75 11                	jne    a71f <dlfree+0xeb2>
    a70e:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    a712:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    a719:	48 89 50 20          	mov    %rdx,0x20(%rax)
    a71d:	eb 16                	jmp    a735 <dlfree+0xec8>
    a71f:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    a723:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    a72a:	48 89 50 28          	mov    %rdx,0x28(%rax)
    a72e:	eb 05                	jmp    a735 <dlfree+0xec8>
    a730:	e8 67 22 00 00       	callq  c99c <abort>
    a735:	48 83 bd f0 fe ff ff 	cmpq   $0x0,-0x110(%rbp)
    a73c:	00 
    a73d:	0f 84 d9 00 00 00    	je     a81c <dlfree+0xfaf>
    a743:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a74a:	48 8b 40 18          	mov    0x18(%rax),%rax
    a74e:	48 39 85 f0 fe ff ff 	cmp    %rax,-0x110(%rbp)
    a755:	0f 93 c0             	setae  %al
    a758:	0f b6 c0             	movzbl %al,%eax
    a75b:	48 85 c0             	test   %rax,%rax
    a75e:	0f 84 b3 00 00 00    	je     a817 <dlfree+0xfaa>
    a764:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    a76b:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    a76f:	48 89 50 30          	mov    %rdx,0x30(%rax)
    a773:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a777:	48 8b 40 20          	mov    0x20(%rax),%rax
    a77b:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    a77f:	48 83 7d a8 00       	cmpq   $0x0,-0x58(%rbp)
    a784:	74 3f                	je     a7c5 <dlfree+0xf58>
    a786:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a78d:	48 8b 40 18          	mov    0x18(%rax),%rax
    a791:	48 39 45 a8          	cmp    %rax,-0x58(%rbp)
    a795:	0f 93 c0             	setae  %al
    a798:	0f b6 c0             	movzbl %al,%eax
    a79b:	48 85 c0             	test   %rax,%rax
    a79e:	74 20                	je     a7c0 <dlfree+0xf53>
    a7a0:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    a7a7:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    a7ab:	48 89 50 20          	mov    %rdx,0x20(%rax)
    a7af:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    a7b3:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    a7ba:	48 89 50 30          	mov    %rdx,0x30(%rax)
    a7be:	eb 05                	jmp    a7c5 <dlfree+0xf58>
    a7c0:	e8 d7 21 00 00       	callq  c99c <abort>
    a7c5:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a7c9:	48 8b 40 28          	mov    0x28(%rax),%rax
    a7cd:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    a7d1:	48 83 7d b0 00       	cmpq   $0x0,-0x50(%rbp)
    a7d6:	74 44                	je     a81c <dlfree+0xfaf>
    a7d8:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a7df:	48 8b 40 18          	mov    0x18(%rax),%rax
    a7e3:	48 39 45 b0          	cmp    %rax,-0x50(%rbp)
    a7e7:	0f 93 c0             	setae  %al
    a7ea:	0f b6 c0             	movzbl %al,%eax
    a7ed:	48 85 c0             	test   %rax,%rax
    a7f0:	74 20                	je     a812 <dlfree+0xfa5>
    a7f2:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    a7f9:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    a7fd:	48 89 50 28          	mov    %rdx,0x28(%rax)
    a801:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    a805:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    a80c:	48 89 50 30          	mov    %rdx,0x30(%rax)
    a810:	eb 0a                	jmp    a81c <dlfree+0xfaf>
    a812:	e8 85 21 00 00       	callq  c99c <abort>
    a817:	e8 80 21 00 00       	callq  c99c <abort>
              set_size_and_pinuse_of_free_chunk(p, psize);
    a81c:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a823:	48 83 c8 01          	or     $0x1,%rax
    a827:	48 89 c2             	mov    %rax,%rdx
    a82a:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    a831:	48 89 50 08          	mov    %rdx,0x8(%rax)
    a835:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a83c:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a843:	48 01 c2             	add    %rax,%rdx
    a846:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a84d:	48 89 02             	mov    %rax,(%rdx)
              if (p == fm->dv) {
    a850:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a857:	48 8b 40 20          	mov    0x20(%rax),%rax
    a85b:	48 39 85 c8 fe ff ff 	cmp    %rax,-0x138(%rbp)
    a862:	75 68                	jne    a8cc <dlfree+0x105f>
                fm->dvsize = psize;
    a864:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a86b:	48 8b 95 d0 fe ff ff 	mov    -0x130(%rbp),%rdx
    a872:	48 89 50 08          	mov    %rdx,0x8(%rax)
                goto postaction;
    a876:	e9 e9 04 00 00       	jmpq   ad64 <dlfree+0x14f7>
              }
            }
          }
          else
            set_free_with_pinuse(p, psize, next);
    a87b:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a882:	48 8b 40 08          	mov    0x8(%rax),%rax
    a886:	48 83 e0 fe          	and    $0xfffffffffffffffe,%rax
    a88a:	48 89 c2             	mov    %rax,%rdx
    a88d:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a894:	48 89 50 08          	mov    %rdx,0x8(%rax)
    a898:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a89f:	48 83 c8 01          	or     $0x1,%rax
    a8a3:	48 89 c2             	mov    %rax,%rdx
    a8a6:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    a8ad:	48 89 50 08          	mov    %rdx,0x8(%rax)
    a8b1:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a8b8:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a8bf:	48 01 c2             	add    %rax,%rdx
    a8c2:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a8c9:	48 89 02             	mov    %rax,(%rdx)

          if (is_small(psize)) {
    a8cc:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a8d3:	48 c1 e8 03          	shr    $0x3,%rax
    a8d7:	48 83 f8 1f          	cmp    $0x1f,%rax
    a8db:	0f 87 31 01 00 00    	ja     aa12 <dlfree+0x11a5>
            insert_small_chunk(fm, p, psize);
    a8e1:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a8e8:	48 c1 e8 03          	shr    $0x3,%rax
    a8ec:	89 85 c4 fe ff ff    	mov    %eax,-0x13c(%rbp)
    a8f2:	8b 85 c4 fe ff ff    	mov    -0x13c(%rbp),%eax
    a8f8:	01 c0                	add    %eax,%eax
    a8fa:	89 c0                	mov    %eax,%eax
    a8fc:	48 83 c0 08          	add    $0x8,%rax
    a900:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    a907:	00 
    a908:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a90f:	48 01 d0             	add    %rdx,%rax
    a912:	48 83 c0 08          	add    $0x8,%rax
    a916:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    a91a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a91e:	48 89 85 08 ff ff ff 	mov    %rax,-0xf8(%rbp)
    a925:	48 83 bd d0 fe ff ff 	cmpq   $0x1f,-0x130(%rbp)
    a92c:	1f 
    a92d:	77 05                	ja     a934 <dlfree+0x10c7>
    a92f:	e8 68 20 00 00       	callq  c99c <abort>
    a934:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a93b:	8b 10                	mov    (%rax),%edx
    a93d:	8b 85 c4 fe ff ff    	mov    -0x13c(%rbp),%eax
    a943:	be 01 00 00 00       	mov    $0x1,%esi
    a948:	89 c1                	mov    %eax,%ecx
    a94a:	d3 e6                	shl    %cl,%esi
    a94c:	89 f0                	mov    %esi,%eax
    a94e:	21 d0                	and    %edx,%eax
    a950:	85 c0                	test   %eax,%eax
    a952:	75 27                	jne    a97b <dlfree+0x110e>
    a954:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a95b:	8b 10                	mov    (%rax),%edx
    a95d:	8b 85 c4 fe ff ff    	mov    -0x13c(%rbp),%eax
    a963:	be 01 00 00 00       	mov    $0x1,%esi
    a968:	89 c1                	mov    %eax,%ecx
    a96a:	d3 e6                	shl    %cl,%esi
    a96c:	89 f0                	mov    %esi,%eax
    a96e:	09 c2                	or     %eax,%edx
    a970:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a977:	89 10                	mov    %edx,(%rax)
    a979:	eb 37                	jmp    a9b2 <dlfree+0x1145>
    a97b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a97f:	48 8b 50 10          	mov    0x10(%rax),%rdx
    a983:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a98a:	48 8b 40 18          	mov    0x18(%rax),%rax
    a98e:	48 39 c2             	cmp    %rax,%rdx
    a991:	0f 93 c0             	setae  %al
    a994:	0f b6 c0             	movzbl %al,%eax
    a997:	48 85 c0             	test   %rax,%rax
    a99a:	74 11                	je     a9ad <dlfree+0x1140>
    a99c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a9a0:	48 8b 40 10          	mov    0x10(%rax),%rax
    a9a4:	48 89 85 08 ff ff ff 	mov    %rax,-0xf8(%rbp)
    a9ab:	eb 05                	jmp    a9b2 <dlfree+0x1145>
    a9ad:	e8 ea 1f 00 00       	callq  c99c <abort>
    a9b2:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a9b6:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a9bd:	48 89 50 10          	mov    %rdx,0x10(%rax)
    a9c1:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    a9c8:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a9cf:	48 89 50 18          	mov    %rdx,0x18(%rax)
    a9d3:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    a9da:	48 8b 95 08 ff ff ff 	mov    -0xf8(%rbp),%rdx
    a9e1:	48 89 50 10          	mov    %rdx,0x10(%rax)
    a9e5:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    a9ec:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    a9f0:	48 89 50 18          	mov    %rdx,0x18(%rax)
            check_free_chunk(fm, p);
    a9f4:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a9fb:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    aa02:	48 89 d6             	mov    %rdx,%rsi
    aa05:	48 89 c7             	mov    %rax,%rdi
    aa08:	e8 f6 ac ff ff       	callq  5703 <do_check_free_chunk>
            insert_large_chunk(fm, tp, psize);
            check_free_chunk(fm, p);
            if (--fm->release_checks == 0)
              release_unused_segments(fm);
          }
          goto postaction;
    aa0d:	e9 51 03 00 00       	jmpq   ad63 <dlfree+0x14f6>
            tchunkptr tp = (tchunkptr)p;
    aa12:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    aa19:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
            insert_large_chunk(fm, tp, psize);
    aa1d:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    aa24:	48 c1 e8 08          	shr    $0x8,%rax
    aa28:	89 85 bc fe ff ff    	mov    %eax,-0x144(%rbp)
    aa2e:	83 bd bc fe ff ff 00 	cmpl   $0x0,-0x144(%rbp)
    aa35:	75 0c                	jne    aa43 <dlfree+0x11d6>
    aa37:	c7 85 b0 fe ff ff 00 	movl   $0x0,-0x150(%rbp)
    aa3e:	00 00 00 
    aa41:	eb 5d                	jmp    aaa0 <dlfree+0x1233>
    aa43:	81 bd bc fe ff ff ff 	cmpl   $0xffff,-0x144(%rbp)
    aa4a:	ff 00 00 
    aa4d:	76 0c                	jbe    aa5b <dlfree+0x11ee>
    aa4f:	c7 85 b0 fe ff ff 1f 	movl   $0x1f,-0x150(%rbp)
    aa56:	00 00 00 
    aa59:	eb 45                	jmp    aaa0 <dlfree+0x1233>
    aa5b:	0f bd 85 bc fe ff ff 	bsr    -0x144(%rbp),%eax
    aa62:	83 f0 1f             	xor    $0x1f,%eax
    aa65:	ba 1f 00 00 00       	mov    $0x1f,%edx
    aa6a:	29 c2                	sub    %eax,%edx
    aa6c:	89 d0                	mov    %edx,%eax
    aa6e:	89 85 c0 fe ff ff    	mov    %eax,-0x140(%rbp)
    aa74:	8b 85 c0 fe ff ff    	mov    -0x140(%rbp),%eax
    aa7a:	8d 34 00             	lea    (%rax,%rax,1),%esi
    aa7d:	8b 85 c0 fe ff ff    	mov    -0x140(%rbp),%eax
    aa83:	83 c0 07             	add    $0x7,%eax
    aa86:	48 8b 95 d0 fe ff ff 	mov    -0x130(%rbp),%rdx
    aa8d:	89 c1                	mov    %eax,%ecx
    aa8f:	48 d3 ea             	shr    %cl,%rdx
    aa92:	48 89 d0             	mov    %rdx,%rax
    aa95:	83 e0 01             	and    $0x1,%eax
    aa98:	01 f0                	add    %esi,%eax
    aa9a:	89 85 b0 fe ff ff    	mov    %eax,-0x150(%rbp)
    aaa0:	8b 85 b0 fe ff ff    	mov    -0x150(%rbp),%eax
    aaa6:	48 83 c0 4a          	add    $0x4a,%rax
    aaaa:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    aab1:	00 
    aab2:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    aab9:	48 01 d0             	add    %rdx,%rax
    aabc:	48 83 c0 08          	add    $0x8,%rax
    aac0:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    aac4:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    aac8:	8b 95 b0 fe ff ff    	mov    -0x150(%rbp),%edx
    aace:	89 50 38             	mov    %edx,0x38(%rax)
    aad1:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    aad5:	48 c7 40 28 00 00 00 	movq   $0x0,0x28(%rax)
    aadc:	00 
    aadd:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    aae1:	48 8b 50 28          	mov    0x28(%rax),%rdx
    aae5:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    aae9:	48 89 50 20          	mov    %rdx,0x20(%rax)
    aaed:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    aaf4:	8b 50 04             	mov    0x4(%rax),%edx
    aaf7:	8b 85 b0 fe ff ff    	mov    -0x150(%rbp),%eax
    aafd:	be 01 00 00 00       	mov    $0x1,%esi
    ab02:	89 c1                	mov    %eax,%ecx
    ab04:	d3 e6                	shl    %cl,%esi
    ab06:	89 f0                	mov    %esi,%eax
    ab08:	21 d0                	and    %edx,%eax
    ab0a:	85 c0                	test   %eax,%eax
    ab0c:	75 5f                	jne    ab6d <dlfree+0x1300>
    ab0e:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ab15:	8b 50 04             	mov    0x4(%rax),%edx
    ab18:	8b 85 b0 fe ff ff    	mov    -0x150(%rbp),%eax
    ab1e:	be 01 00 00 00       	mov    $0x1,%esi
    ab23:	89 c1                	mov    %eax,%ecx
    ab25:	d3 e6                	shl    %cl,%esi
    ab27:	89 f0                	mov    %esi,%eax
    ab29:	09 c2                	or     %eax,%edx
    ab2b:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ab32:	89 50 04             	mov    %edx,0x4(%rax)
    ab35:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    ab39:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    ab3d:	48 89 10             	mov    %rdx,(%rax)
    ab40:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ab44:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    ab48:	48 89 50 30          	mov    %rdx,0x30(%rax)
    ab4c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ab50:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    ab54:	48 89 50 18          	mov    %rdx,0x18(%rax)
    ab58:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ab5c:	48 8b 50 18          	mov    0x18(%rax),%rdx
    ab60:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ab64:	48 89 50 10          	mov    %rdx,0x10(%rax)
    ab68:	e9 96 01 00 00       	jmpq   ad03 <dlfree+0x1496>
    ab6d:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    ab71:	48 8b 00             	mov    (%rax),%rax
    ab74:	48 89 85 10 ff ff ff 	mov    %rax,-0xf0(%rbp)
    ab7b:	83 bd b0 fe ff ff 1f 	cmpl   $0x1f,-0x150(%rbp)
    ab82:	74 13                	je     ab97 <dlfree+0x132a>
    ab84:	8b 85 b0 fe ff ff    	mov    -0x150(%rbp),%eax
    ab8a:	d1 e8                	shr    %eax
    ab8c:	ba 39 00 00 00       	mov    $0x39,%edx
    ab91:	29 c2                	sub    %eax,%edx
    ab93:	89 d0                	mov    %edx,%eax
    ab95:	eb 05                	jmp    ab9c <dlfree+0x132f>
    ab97:	b8 00 00 00 00       	mov    $0x0,%eax
    ab9c:	48 8b 95 d0 fe ff ff 	mov    -0x130(%rbp),%rdx
    aba3:	89 c1                	mov    %eax,%ecx
    aba5:	48 d3 e2             	shl    %cl,%rdx
    aba8:	48 89 d0             	mov    %rdx,%rax
    abab:	48 89 85 18 ff ff ff 	mov    %rax,-0xe8(%rbp)
    abb2:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    abb9:	48 8b 40 08          	mov    0x8(%rax),%rax
    abbd:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    abc1:	48 39 85 d0 fe ff ff 	cmp    %rax,-0x130(%rbp)
    abc8:	0f 84 a2 00 00 00    	je     ac70 <dlfree+0x1403>
    abce:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    abd5:	48 c1 e8 3f          	shr    $0x3f,%rax
    abd9:	48 83 c0 04          	add    $0x4,%rax
    abdd:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    abe4:	00 
    abe5:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    abec:	48 01 d0             	add    %rdx,%rax
    abef:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    abf3:	48 d1 a5 18 ff ff ff 	shlq   -0xe8(%rbp)
    abfa:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    abfe:	48 8b 00             	mov    (%rax),%rax
    ac01:	48 85 c0             	test   %rax,%rax
    ac04:	74 10                	je     ac16 <dlfree+0x13a9>
    ac06:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    ac0a:	48 8b 00             	mov    (%rax),%rax
    ac0d:	48 89 85 10 ff ff ff 	mov    %rax,-0xf0(%rbp)
    ac14:	eb 9c                	jmp    abb2 <dlfree+0x1345>
    ac16:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ac1d:	48 8b 40 18          	mov    0x18(%rax),%rax
    ac21:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    ac25:	0f 93 c0             	setae  %al
    ac28:	0f b6 c0             	movzbl %al,%eax
    ac2b:	48 85 c0             	test   %rax,%rax
    ac2e:	74 3b                	je     ac6b <dlfree+0x13fe>
    ac30:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    ac34:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    ac38:	48 89 10             	mov    %rdx,(%rax)
    ac3b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ac3f:	48 8b 95 10 ff ff ff 	mov    -0xf0(%rbp),%rdx
    ac46:	48 89 50 30          	mov    %rdx,0x30(%rax)
    ac4a:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ac4e:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    ac52:	48 89 50 18          	mov    %rdx,0x18(%rax)
    ac56:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ac5a:	48 8b 50 18          	mov    0x18(%rax),%rdx
    ac5e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ac62:	48 89 50 10          	mov    %rdx,0x10(%rax)
    ac66:	e9 98 00 00 00       	jmpq   ad03 <dlfree+0x1496>
    ac6b:	e8 2c 1d 00 00       	callq  c99c <abort>
    ac70:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    ac77:	48 8b 40 10          	mov    0x10(%rax),%rax
    ac7b:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    ac7f:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ac86:	48 8b 40 18          	mov    0x18(%rax),%rax
    ac8a:	48 39 85 10 ff ff ff 	cmp    %rax,-0xf0(%rbp)
    ac91:	0f 93 c0             	setae  %al
    ac94:	0f b6 c0             	movzbl %al,%eax
    ac97:	48 85 c0             	test   %rax,%rax
    ac9a:	74 62                	je     acfe <dlfree+0x1491>
    ac9c:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    aca3:	48 8b 40 18          	mov    0x18(%rax),%rax
    aca7:	48 39 45 e8          	cmp    %rax,-0x18(%rbp)
    acab:	0f 93 c0             	setae  %al
    acae:	0f b6 c0             	movzbl %al,%eax
    acb1:	48 85 c0             	test   %rax,%rax
    acb4:	74 48                	je     acfe <dlfree+0x1491>
    acb6:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    acba:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    acbe:	48 89 50 18          	mov    %rdx,0x18(%rax)
    acc2:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    acc6:	48 8b 50 18          	mov    0x18(%rax),%rdx
    acca:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    acd1:	48 89 50 10          	mov    %rdx,0x10(%rax)
    acd5:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    acd9:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    acdd:	48 89 50 10          	mov    %rdx,0x10(%rax)
    ace1:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ace5:	48 8b 95 10 ff ff ff 	mov    -0xf0(%rbp),%rdx
    acec:	48 89 50 18          	mov    %rdx,0x18(%rax)
    acf0:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    acf4:	48 c7 40 30 00 00 00 	movq   $0x0,0x30(%rax)
    acfb:	00 
    acfc:	eb 05                	jmp    ad03 <dlfree+0x1496>
    acfe:	e8 99 1c 00 00       	callq  c99c <abort>
            check_free_chunk(fm, p);
    ad03:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    ad0a:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ad11:	48 89 d6             	mov    %rdx,%rsi
    ad14:	48 89 c7             	mov    %rax,%rdi
    ad17:	e8 e7 a9 ff ff       	callq  5703 <do_check_free_chunk>
            if (--fm->release_checks == 0)
    ad1c:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ad23:	48 8b 40 38          	mov    0x38(%rax),%rax
    ad27:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    ad2b:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ad32:	48 89 50 38          	mov    %rdx,0x38(%rax)
    ad36:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ad3d:	48 8b 40 38          	mov    0x38(%rax),%rax
    ad41:	48 85 c0             	test   %rax,%rax
    ad44:	75 1d                	jne    ad63 <dlfree+0x14f6>
              release_unused_segments(fm);
    ad46:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ad4d:	48 89 c7             	mov    %rax,%rdi
    ad50:	e8 52 ca ff ff       	callq  77a7 <release_unused_segments>
          goto postaction;
    ad55:	eb 0c                	jmp    ad63 <dlfree+0x14f6>
        }
      }
    erroraction:
    ad57:	90                   	nop
    ad58:	eb 01                	jmp    ad5b <dlfree+0x14ee>
              goto erroraction;
    ad5a:	90                   	nop
      USAGE_ERROR_ACTION(fm, p);
    ad5b:	e8 3c 1c 00 00       	callq  c99c <abort>
              goto postaction;
    ad60:	90                   	nop
    ad61:	eb 01                	jmp    ad64 <dlfree+0x14f7>
          goto postaction;
    ad63:	90                   	nop
    postaction:
      POSTACTION(fm);
    ad64:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ad6b:	8b 80 70 03 00 00    	mov    0x370(%rax),%eax
    ad71:	83 e0 02             	and    $0x2,%eax
    ad74:	85 c0                	test   %eax,%eax
    ad76:	74 14                	je     ad8c <dlfree+0x151f>
    ad78:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ad7f:	48 05 74 03 00 00    	add    $0x374,%rax
    ad85:	ba 00 00 00 00       	mov    $0x0,%edx
    ad8a:	89 10                	mov    %edx,(%rax)
    }
  }
#if !FOOTERS
#undef fm
#endif /* FOOTERS */
}
    ad8c:	90                   	nop
    ad8d:	c9                   	leaveq 
    ad8e:	c3                   	retq   

000000000000ad8f <__memcpy>:
/*
 * Copy a block of memory, not handling overlap.
 */
void *
__memcpy(void *dst0, const void *src0, size_t length)
{
    ad8f:	55                   	push   %rbp
    ad90:	48 89 e5             	mov    %rsp,%rbp
    ad93:	48 83 ec 40          	sub    $0x40,%rsp
    ad97:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    ad9b:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    ad9f:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
	char *dst = (char *)dst0;
    ada3:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ada7:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
	const char *src = (const char *)src0;
    adab:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    adaf:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
	size_t t;

	if (length == 0 || dst == src)		/* nothing to do */
    adb3:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    adb8:	0f 84 3b 01 00 00    	je     aef9 <__memcpy+0x16a>
    adbe:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    adc2:	48 3b 45 f0          	cmp    -0x10(%rbp),%rax
    adc6:	0f 84 2d 01 00 00    	je     aef9 <__memcpy+0x16a>
		goto done;

	if ((dst < src && dst + length > src) ||
    adcc:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    add0:	48 3b 45 f0          	cmp    -0x10(%rbp),%rax
    add4:	73 11                	jae    ade7 <__memcpy+0x58>
    add6:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    adda:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    adde:	48 01 d0             	add    %rdx,%rax
    ade1:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    ade5:	72 1b                	jb     ae02 <__memcpy+0x73>
    ade7:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    adeb:	48 3b 45 e8          	cmp    -0x18(%rbp),%rax
    adef:	73 16                	jae    ae07 <__memcpy+0x78>
	    (src < dst && src + length > dst)) {
    adf1:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    adf5:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    adf9:	48 01 d0             	add    %rdx,%rax
    adfc:	48 39 45 e8          	cmp    %rax,-0x18(%rbp)
    ae00:	73 05                	jae    ae07 <__memcpy+0x78>
        /* backwards memcpy */
		abort();
    ae02:	e8 95 1b 00 00       	callq  c99c <abort>
#define	TLOOP1(s) do { s; } while (--t)

	/*
	 * Copy forward.
	 */
	t = (long)src;	/* only need low bits */
    ae07:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    ae0b:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
	if ((t | (long)dst) & wmask) {
    ae0f:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    ae13:	48 0b 45 f8          	or     -0x8(%rbp),%rax
    ae17:	83 e0 07             	and    $0x7,%eax
    ae1a:	48 85 c0             	test   %rax,%rax
    ae1d:	74 68                	je     ae87 <__memcpy+0xf8>
		/*
		 * Try to align operands.  This cannot be done
		 * unless the low bits match.
		 */
		if ((t ^ (long)dst) & wmask || length < wsize)
    ae1f:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    ae23:	48 33 45 f8          	xor    -0x8(%rbp),%rax
    ae27:	83 e0 07             	and    $0x7,%eax
    ae2a:	48 85 c0             	test   %rax,%rax
    ae2d:	75 07                	jne    ae36 <__memcpy+0xa7>
    ae2f:	48 83 7d c8 07       	cmpq   $0x7,-0x38(%rbp)
    ae34:	77 0a                	ja     ae40 <__memcpy+0xb1>
			t = length;
    ae36:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    ae3a:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    ae3e:	eb 16                	jmp    ae56 <__memcpy+0xc7>
		else
			t = wsize - (t & wmask);
    ae40:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ae44:	83 e0 07             	and    $0x7,%eax
    ae47:	ba 08 00 00 00       	mov    $0x8,%edx
    ae4c:	48 29 c2             	sub    %rax,%rdx
    ae4f:	48 89 d0             	mov    %rdx,%rax
    ae52:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
		length -= t;
    ae56:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ae5a:	48 29 45 c8          	sub    %rax,-0x38(%rbp)
		TLOOP1(*dst++ = *src++);
    ae5e:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    ae62:	48 8d 42 01          	lea    0x1(%rdx),%rax
    ae66:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    ae6a:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    ae6e:	48 8d 48 01          	lea    0x1(%rax),%rcx
    ae72:	48 89 4d e8          	mov    %rcx,-0x18(%rbp)
    ae76:	0f b6 12             	movzbl (%rdx),%edx
    ae79:	88 10                	mov    %dl,(%rax)
    ae7b:	48 83 6d f8 01       	subq   $0x1,-0x8(%rbp)
    ae80:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    ae85:	75 d7                	jne    ae5e <__memcpy+0xcf>
	}
	/*
	 * Copy whole words, then mop up any trailing bytes.
	 */
	t = length / wsize;
    ae87:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    ae8b:	48 c1 e8 03          	shr    $0x3,%rax
    ae8f:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
	TLOOP(*(word *)dst = *(word *)src; src += wsize; dst += wsize);
    ae93:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    ae98:	74 24                	je     aebe <__memcpy+0x12f>
    ae9a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    ae9e:	48 8b 10             	mov    (%rax),%rdx
    aea1:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    aea5:	48 89 10             	mov    %rdx,(%rax)
    aea8:	48 83 45 f0 08       	addq   $0x8,-0x10(%rbp)
    aead:	48 83 45 e8 08       	addq   $0x8,-0x18(%rbp)
    aeb2:	48 83 6d f8 01       	subq   $0x1,-0x8(%rbp)
    aeb7:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    aebc:	75 dc                	jne    ae9a <__memcpy+0x10b>
	t = length & wmask;
    aebe:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    aec2:	83 e0 07             	and    $0x7,%eax
    aec5:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
	TLOOP(*dst++ = *src++);
    aec9:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    aece:	74 29                	je     aef9 <__memcpy+0x16a>
    aed0:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    aed4:	48 8d 42 01          	lea    0x1(%rdx),%rax
    aed8:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    aedc:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    aee0:	48 8d 48 01          	lea    0x1(%rax),%rcx
    aee4:	48 89 4d e8          	mov    %rcx,-0x18(%rbp)
    aee8:	0f b6 12             	movzbl (%rdx),%edx
    aeeb:	88 10                	mov    %dl,(%rax)
    aeed:	48 83 6d f8 01       	subq   $0x1,-0x8(%rbp)
    aef2:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    aef7:	75 d7                	jne    aed0 <__memcpy+0x141>
done:
    aef9:	90                   	nop
	return (dst0);
    aefa:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
}
    aefe:	c9                   	leaveq 
    aeff:	c3                   	retq   

000000000000af00 <memcpy>:


void *
memcpy(void *dst0, const void *src0, size_t length)
{
    af00:	55                   	push   %rbp
    af01:	48 89 e5             	mov    %rsp,%rbp
    af04:	48 83 ec 20          	sub    $0x20,%rsp
    af08:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    af0c:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    af10:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
#ifdef _TLIBC_USE_INTEL_FAST_STRING_
 	return _intel_fast_memcpy(dst0, (void*)src0, length);
#else
	return __memcpy(dst0, src0, length);
    af14:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    af18:	48 8b 4d f0          	mov    -0x10(%rbp),%rcx
    af1c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    af20:	48 89 ce             	mov    %rcx,%rsi
    af23:	48 89 c7             	mov    %rax,%rdi
    af26:	e8 64 fe ff ff       	callq  ad8f <__memcpy>
#endif
}
    af2b:	c9                   	leaveq 
    af2c:	c3                   	retq   

000000000000af2d <__memset>:
extern void *_intel_fast_memset(void *, void *, size_t);
#endif

void * __attribute__((optimize("O0")))
__memset(void *dst, int c, size_t n)
{
    af2d:	55                   	push   %rbp
    af2e:	48 89 e5             	mov    %rsp,%rbp
    af31:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    af35:	89 75 e4             	mov    %esi,-0x1c(%rbp)
    af38:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
	if (n != 0) {
    af3c:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    af41:	74 25                	je     af68 <__memset+0x3b>
                unsigned char *d = dst;
    af43:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    af47:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

                do
                        *d++ = (unsigned char)c;
    af4b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    af4f:	48 8d 50 01          	lea    0x1(%rax),%rdx
    af53:	48 89 55 f8          	mov    %rdx,-0x8(%rbp)
    af57:	8b 55 e4             	mov    -0x1c(%rbp),%edx
    af5a:	88 10                	mov    %dl,(%rax)
                while (--n != 0);
    af5c:	48 83 6d d8 01       	subq   $0x1,-0x28(%rbp)
    af61:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    af66:	75 e3                	jne    af4b <__memset+0x1e>
        }
        return (dst);
    af68:	48 8b 45 e8          	mov    -0x18(%rbp),%rax


}
    af6c:	5d                   	pop    %rbp
    af6d:	c3                   	retq   

000000000000af6e <memset>:

void *
memset(void *dst, int c, size_t n)
{
    af6e:	55                   	push   %rbp
    af6f:	48 89 e5             	mov    %rsp,%rbp
    af72:	48 83 ec 18          	sub    $0x18,%rsp
    af76:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    af7a:	89 75 f4             	mov    %esi,-0xc(%rbp)
    af7d:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
#ifdef _TLIBC_USE_INTEL_FAST_STRING_
	return _intel_fast_memset(dst, (void*)c, n);
#else
	return __memset(dst, c, n);
    af81:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    af85:	8b 4d f4             	mov    -0xc(%rbp),%ecx
    af88:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    af8c:	89 ce                	mov    %ecx,%esi
    af8e:	48 89 c7             	mov    %rax,%rdi
    af91:	e8 97 ff ff ff       	callq  af2d <__memset>
#endif /* !_TLIBC_USE_INTEL_FAST_STRING_ */	
}
    af96:	c9                   	leaveq 
    af97:	c3                   	retq   

000000000000af98 <memset_s>:

#undef memset_s /* in case it was defined as a macro */

errno_t
memset_s(void *s, size_t smax, int c, size_t n)
{
    af98:	55                   	push   %rbp
    af99:	48 89 e5             	mov    %rsp,%rbp
    af9c:	48 83 ec 30          	sub    $0x30,%rsp
    afa0:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    afa4:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    afa8:	89 55 dc             	mov    %edx,-0x24(%rbp)
    afab:	48 89 4d d0          	mov    %rcx,-0x30(%rbp)
    errno_t err = 0;
    afaf:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)

    if (s == NULL) {
    afb6:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    afbb:	75 09                	jne    afc6 <memset_s+0x2e>
        err = EINVAL;
    afbd:	c7 45 fc 16 00 00 00 	movl   $0x16,-0x4(%rbp)
        goto out;
    afc4:	eb 30                	jmp    aff6 <memset_s+0x5e>
    }
    if (n > SIZE_MAX) {
        err = E2BIG;
        n = smax;
    }
    if (n > smax) {
    afc6:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    afca:	48 3b 45 e0          	cmp    -0x20(%rbp),%rax
    afce:	76 0f                	jbe    afdf <memset_s+0x47>
        err = EOVERFLOW;
    afd0:	c7 45 fc 4b 00 00 00 	movl   $0x4b,-0x4(%rbp)
        n = smax;
    afd7:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    afdb:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    }

    /* Calling through a volatile pointer should never be optimised away. */
    (*__memset_vp)(s, c, n);
    afdf:	48 8b 05 4a 60 00 00 	mov    0x604a(%rip),%rax        # 11030 <__memset_vp>
    afe6:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    afea:	8b 75 dc             	mov    -0x24(%rbp),%esi
    afed:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
    aff1:	48 89 cf             	mov    %rcx,%rdi
    aff4:	ff d0                	callq  *%rax

    out:
    if (err == 0)
    aff6:	83 7d fc 00          	cmpl   $0x0,-0x4(%rbp)
    affa:	75 07                	jne    b003 <memset_s+0x6b>
        return 0;
    affc:	b8 00 00 00 00       	mov    $0x0,%eax
    b001:	eb 10                	jmp    b013 <memset_s+0x7b>
    else {
        errno = err;
    b003:	e8 0a 06 00 00       	callq  b612 <__errno>
    b008:	48 89 c2             	mov    %rax,%rdx
    b00b:	8b 45 fc             	mov    -0x4(%rbp),%eax
    b00e:	89 02                	mov    %eax,(%rdx)
        /* XXX call runtime-constraint handler */
        return err;
    b010:	8b 45 fc             	mov    -0x4(%rbp),%eax
    }
}
    b013:	c9                   	leaveq 
    b014:	c3                   	retq   

000000000000b015 <heap_init>:
static size_t heap_size __attribute__((section(RELRO_SECTION_NAME))) = 0;
static int is_edmm_supported __attribute__((section(RELRO_SECTION_NAME))) = 0;
static size_t heap_min_size __attribute__((section(RELRO_SECTION_NAME))) = 0;

int heap_init(void *_heap_base, size_t _heap_size, size_t _heap_min_size, int _is_edmm_supported)
{
    b015:	55                   	push   %rbp
    b016:	48 89 e5             	mov    %rsp,%rbp
    b019:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    b01d:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    b021:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    b025:	89 4d e4             	mov    %ecx,-0x1c(%rbp)
    if (heap_base != NULL)
    b028:	48 8b 05 e9 5d 00 00 	mov    0x5de9(%rip),%rax        # 10e18 <heap_base>
    b02f:	48 85 c0             	test   %rax,%rax
    b032:	74 0a                	je     b03e <heap_init+0x29>
        return SGX_ERROR_UNEXPECTED;
    b034:	b8 01 00 00 00       	mov    $0x1,%eax
    b039:	e9 8c 00 00 00       	jmpq   b0ca <heap_init+0xb5>

    if ((_heap_base == NULL) || (((size_t) _heap_base) & (SE_PAGE_SIZE - 1)))
    b03e:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    b043:	74 0e                	je     b053 <heap_init+0x3e>
    b045:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b049:	25 ff 0f 00 00       	and    $0xfff,%eax
    b04e:	48 85 c0             	test   %rax,%rax
    b051:	74 07                	je     b05a <heap_init+0x45>
        return SGX_ERROR_UNEXPECTED;
    b053:	b8 01 00 00 00       	mov    $0x1,%eax
    b058:	eb 70                	jmp    b0ca <heap_init+0xb5>

    if (_heap_size & (SE_PAGE_SIZE - 1))
    b05a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b05e:	25 ff 0f 00 00       	and    $0xfff,%eax
    b063:	48 85 c0             	test   %rax,%rax
    b066:	74 07                	je     b06f <heap_init+0x5a>
        return SGX_ERROR_UNEXPECTED;
    b068:	b8 01 00 00 00       	mov    $0x1,%eax
    b06d:	eb 5b                	jmp    b0ca <heap_init+0xb5>

    if (_heap_min_size & (SE_PAGE_SIZE - 1))
    b06f:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b073:	25 ff 0f 00 00       	and    $0xfff,%eax
    b078:	48 85 c0             	test   %rax,%rax
    b07b:	74 07                	je     b084 <heap_init+0x6f>
        return SGX_ERROR_UNEXPECTED;
    b07d:	b8 01 00 00 00       	mov    $0x1,%eax
    b082:	eb 46                	jmp    b0ca <heap_init+0xb5>

    if (_heap_size > SIZE_MAX - (size_t)heap_base)
    b084:	48 8b 05 8d 5d 00 00 	mov    0x5d8d(%rip),%rax        # 10e18 <heap_base>
    b08b:	48 f7 d0             	not    %rax
    b08e:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    b092:	76 07                	jbe    b09b <heap_init+0x86>
        return SGX_ERROR_UNEXPECTED;
    b094:	b8 01 00 00 00       	mov    $0x1,%eax
    b099:	eb 2f                	jmp    b0ca <heap_init+0xb5>

    heap_base = _heap_base;
    b09b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b09f:	48 89 05 72 5d 00 00 	mov    %rax,0x5d72(%rip)        # 10e18 <heap_base>
    heap_size = _heap_size;
    b0a6:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b0aa:	48 89 05 6f 5d 00 00 	mov    %rax,0x5d6f(%rip)        # 10e20 <heap_size>
    heap_min_size = _heap_min_size;
    b0b1:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b0b5:	48 89 05 74 5d 00 00 	mov    %rax,0x5d74(%rip)        # 10e30 <heap_min_size>
    is_edmm_supported = _is_edmm_supported;
    b0bc:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    b0bf:	89 05 63 5d 00 00    	mov    %eax,0x5d63(%rip)        # 10e28 <is_edmm_supported>

    return SGX_SUCCESS;
    b0c5:	b8 00 00 00 00       	mov    $0x0,%eax
}
    b0ca:	5d                   	pop    %rbp
    b0cb:	c3                   	retq   

000000000000b0cc <sbrk>:

void* sbrk(intptr_t n)
{
    b0cc:	55                   	push   %rbp
    b0cd:	48 89 e5             	mov    %rsp,%rbp
    b0d0:	48 83 ec 40          	sub    $0x40,%rsp
    b0d4:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    static size_t heap_used;
    void *heap_ptr = NULL;
    b0d8:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
    b0df:	00 
    size_t prev_heap_used = heap_used;
    b0e0:	48 8b 05 29 64 00 00 	mov    0x6429(%rip),%rax        # 11510 <heap_used.2393>
    b0e7:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    void * start_addr;
    size_t size = 0;
    b0eb:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    b0f2:	00 

    if (!heap_base)
    b0f3:	48 8b 05 1e 5d 00 00 	mov    0x5d1e(%rip),%rax        # 10e18 <heap_base>
    b0fa:	48 85 c0             	test   %rax,%rax
    b0fd:	75 0c                	jne    b10b <sbrk+0x3f>
        return (void *)(~(size_t)0);
    b0ff:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
    b106:	e9 9d 02 00 00       	jmpq   b3a8 <sbrk+0x2dc>

    /* shrink the heap */
    if (n < 0) {
    b10b:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    b110:	0f 89 31 01 00 00    	jns    b247 <sbrk+0x17b>

        n *= -1;
    b116:	48 f7 5d c8          	negq   -0x38(%rbp)
        if (heap_used < n)
    b11a:	48 8b 15 ef 63 00 00 	mov    0x63ef(%rip),%rdx        # 11510 <heap_used.2393>
    b121:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b125:	48 39 c2             	cmp    %rax,%rdx
    b128:	73 0c                	jae    b136 <sbrk+0x6a>
            return (void *)(~(size_t)0);
    b12a:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
    b131:	e9 72 02 00 00       	jmpq   b3a8 <sbrk+0x2dc>

        heap_used -= n;
    b136:	48 8b 15 d3 63 00 00 	mov    0x63d3(%rip),%rdx        # 11510 <heap_used.2393>
    b13d:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b141:	48 29 c2             	sub    %rax,%rdx
    b144:	48 89 d0             	mov    %rdx,%rax
    b147:	48 89 05 c2 63 00 00 	mov    %rax,0x63c2(%rip)        # 11510 <heap_used.2393>

        /* heap_used is never larger than heap_size, and since heap_size <= SIZE_MAX - (size_t)heap_base,
           there's no integer overflow here.
         */  
        heap_ptr = (void *)((size_t)heap_base + (size_t)heap_used);
    b14e:	48 8b 05 c3 5c 00 00 	mov    0x5cc3(%rip),%rax        # 10e18 <heap_base>
    b155:	48 89 c2             	mov    %rax,%rdx
    b158:	48 8b 05 b1 63 00 00 	mov    0x63b1(%rip),%rax        # 11510 <heap_used.2393>
    b15f:	48 01 d0             	add    %rdx,%rax
    b162:	48 89 45 f0          	mov    %rax,-0x10(%rbp)

        if (is_edmm_supported && (prev_heap_used > heap_min_size)) 
    b166:	8b 05 bc 5c 00 00    	mov    0x5cbc(%rip),%eax        # 10e28 <is_edmm_supported>
    b16c:	85 c0                	test   %eax,%eax
    b16e:	0f 84 ca 00 00 00    	je     b23e <sbrk+0x172>
    b174:	48 8b 05 b5 5c 00 00 	mov    0x5cb5(%rip),%rax        # 10e30 <heap_min_size>
    b17b:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    b17f:	0f 86 b9 00 00 00    	jbe    b23e <sbrk+0x172>
        {
            assert((n & (SE_PAGE_SIZE - 1)) == 0);
    b185:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b189:	25 ff 0f 00 00       	and    $0xfff,%eax
    b18e:	48 85 c0             	test   %rax,%rax
    b191:	74 1f                	je     b1b2 <sbrk+0xe6>
    b193:	48 8d 0d 86 1f 00 00 	lea    0x1f86(%rip),%rcx        # d120 <_ZZL16init_stack_guardPvE8__func__+0xc0>
    b19a:	48 8d 15 a8 1f 00 00 	lea    0x1fa8(%rip),%rdx        # d149 <__func__.2398>
    b1a1:	be 65 00 00 00       	mov    $0x65,%esi
    b1a6:	48 8d 3d 91 1f 00 00 	lea    0x1f91(%rip),%rdi        # d13e <_ZZL16init_stack_guardPvE8__func__+0xde>
    b1ad:	e8 ff a0 ff ff       	callq  52b1 <__assert>

            if (heap_used > heap_min_size)
    b1b2:	48 8b 15 57 63 00 00 	mov    0x6357(%rip),%rdx        # 11510 <heap_used.2393>
    b1b9:	48 8b 05 70 5c 00 00 	mov    0x5c70(%rip),%rax        # 10e30 <heap_min_size>
    b1c0:	48 39 c2             	cmp    %rax,%rdx
    b1c3:	76 12                	jbe    b1d7 <sbrk+0x10b>
            {
                start_addr = heap_ptr;
    b1c5:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b1c9:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
                size = n;
    b1cd:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b1d1:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    b1d5:	eb 2d                	jmp    b204 <sbrk+0x138>
            else
            {
                /* heap_min_size is never larger than heap_size, and since heap_size <= SIZE_MAX - (size_t)heap_base,
                   there's no integer overflow here.
                 */  
                start_addr = (void *)((size_t)(heap_base) + heap_min_size);
    b1d7:	48 8b 05 3a 5c 00 00 	mov    0x5c3a(%rip),%rax        # 10e18 <heap_base>
    b1de:	48 89 c2             	mov    %rax,%rdx
    b1e1:	48 8b 05 48 5c 00 00 	mov    0x5c48(%rip),%rax        # 10e30 <heap_min_size>
    b1e8:	48 01 d0             	add    %rdx,%rax
    b1eb:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
                size = prev_heap_used - heap_min_size;
    b1ef:	48 8b 05 3a 5c 00 00 	mov    0x5c3a(%rip),%rax        # 10e30 <heap_min_size>
    b1f6:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    b1fa:	48 29 c2             	sub    %rax,%rdx
    b1fd:	48 89 d0             	mov    %rdx,%rax
    b200:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
            }
            int ret = trim_EPC_pages(start_addr, size >> SE_PAGE_SHIFT);
    b204:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b208:	48 c1 e8 0c          	shr    $0xc,%rax
    b20c:	48 89 c2             	mov    %rax,%rdx
    b20f:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    b213:	48 89 d6             	mov    %rdx,%rsi
    b216:	48 89 c7             	mov    %rax,%rdi
    b219:	e8 b2 70 ff ff       	callq  22d0 <trim_EPC_pages>
    b21e:	89 45 dc             	mov    %eax,-0x24(%rbp)
            if (ret != 0)
    b221:	83 7d dc 00          	cmpl   $0x0,-0x24(%rbp)
    b225:	74 17                	je     b23e <sbrk+0x172>
            {
                heap_used = prev_heap_used;
    b227:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b22b:	48 89 05 de 62 00 00 	mov    %rax,0x62de(%rip)        # 11510 <heap_used.2393>
                return (void *)(~(size_t)0);
    b232:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
    b239:	e9 6a 01 00 00       	jmpq   b3a8 <sbrk+0x2dc>
            }
        }
        return heap_ptr;
    b23e:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b242:	e9 61 01 00 00       	jmpq   b3a8 <sbrk+0x2dc>
    }

    /* extend the heap */
    if((heap_used > (SIZE_MAX - n)) || ((heap_used + n) > heap_size))
    b247:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b24b:	48 f7 d0             	not    %rax
    b24e:	48 89 c2             	mov    %rax,%rdx
    b251:	48 8b 05 b8 62 00 00 	mov    0x62b8(%rip),%rax        # 11510 <heap_used.2393>
    b258:	48 39 c2             	cmp    %rax,%rdx
    b25b:	72 1a                	jb     b277 <sbrk+0x1ab>
    b25d:	48 8b 15 ac 62 00 00 	mov    0x62ac(%rip),%rdx        # 11510 <heap_used.2393>
    b264:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b268:	48 01 c2             	add    %rax,%rdx
    b26b:	48 8b 05 ae 5b 00 00 	mov    0x5bae(%rip),%rax        # 10e20 <heap_size>
    b272:	48 39 c2             	cmp    %rax,%rdx
    b275:	76 0c                	jbe    b283 <sbrk+0x1b7>
        return (void *)(~(size_t)0);
    b277:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
    b27e:	e9 25 01 00 00       	jmpq   b3a8 <sbrk+0x2dc>

    /* heap_used is never larger than heap_size, and since heap_size <= SIZE_MAX - (size_t)heap_base,
       there's no integer overflow here.
     */  
    heap_ptr = (void *)((size_t)heap_base + (size_t)heap_used);
    b283:	48 8b 05 8e 5b 00 00 	mov    0x5b8e(%rip),%rax        # 10e18 <heap_base>
    b28a:	48 89 c2             	mov    %rax,%rdx
    b28d:	48 8b 05 7c 62 00 00 	mov    0x627c(%rip),%rax        # 11510 <heap_used.2393>
    b294:	48 01 d0             	add    %rdx,%rax
    b297:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    heap_used += n;
    b29b:	48 8b 15 6e 62 00 00 	mov    0x626e(%rip),%rdx        # 11510 <heap_used.2393>
    b2a2:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b2a6:	48 01 d0             	add    %rdx,%rax
    b2a9:	48 89 05 60 62 00 00 	mov    %rax,0x6260(%rip)        # 11510 <heap_used.2393>

    /* update g_peak_heap_used */
    g_peak_heap_used = (g_peak_heap_used < heap_used) ? heap_used : g_peak_heap_used;
    b2b0:	48 8b 15 51 62 00 00 	mov    0x6251(%rip),%rdx        # 11508 <g_peak_heap_used>
    b2b7:	48 8b 05 52 62 00 00 	mov    0x6252(%rip),%rax        # 11510 <heap_used.2393>
    b2be:	48 39 c2             	cmp    %rax,%rdx
    b2c1:	48 0f 43 c2          	cmovae %rdx,%rax
    b2c5:	48 89 05 3c 62 00 00 	mov    %rax,0x623c(%rip)        # 11508 <g_peak_heap_used>

    if (is_edmm_supported && heap_used > heap_min_size)
    b2cc:	8b 05 56 5b 00 00    	mov    0x5b56(%rip),%eax        # 10e28 <is_edmm_supported>
    b2d2:	85 c0                	test   %eax,%eax
    b2d4:	0f 84 ca 00 00 00    	je     b3a4 <sbrk+0x2d8>
    b2da:	48 8b 15 2f 62 00 00 	mov    0x622f(%rip),%rdx        # 11510 <heap_used.2393>
    b2e1:	48 8b 05 48 5b 00 00 	mov    0x5b48(%rip),%rax        # 10e30 <heap_min_size>
    b2e8:	48 39 c2             	cmp    %rax,%rdx
    b2eb:	0f 86 b3 00 00 00    	jbe    b3a4 <sbrk+0x2d8>
    {
        assert((n & (SE_PAGE_SIZE - 1)) == 0);
    b2f1:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b2f5:	25 ff 0f 00 00       	and    $0xfff,%eax
    b2fa:	48 85 c0             	test   %rax,%rax
    b2fd:	74 1f                	je     b31e <sbrk+0x252>
    b2ff:	48 8d 0d 1a 1e 00 00 	lea    0x1e1a(%rip),%rcx        # d120 <_ZZL16init_stack_guardPvE8__func__+0xc0>
    b306:	48 8d 15 3c 1e 00 00 	lea    0x1e3c(%rip),%rdx        # d149 <__func__.2398>
    b30d:	be 8d 00 00 00       	mov    $0x8d,%esi
    b312:	48 8d 3d 25 1e 00 00 	lea    0x1e25(%rip),%rdi        # d13e <_ZZL16init_stack_guardPvE8__func__+0xde>
    b319:	e8 93 9f ff ff       	callq  52b1 <__assert>

        if (prev_heap_used > heap_min_size)
    b31e:	48 8b 05 0b 5b 00 00 	mov    0x5b0b(%rip),%rax        # 10e30 <heap_min_size>
    b325:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    b329:	76 12                	jbe    b33d <sbrk+0x271>
        {
            start_addr = heap_ptr;
    b32b:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b32f:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
            size = n;
    b333:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b337:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    b33b:	eb 30                	jmp    b36d <sbrk+0x2a1>
        {

            /* heap_min_size is never larger than heap_size, and since heap_size <= SIZE_MAX - (size_t)heap_base,
               there's no integer overflow here.
             */  
            start_addr = (void *)((size_t)(heap_base) + heap_min_size);
    b33d:	48 8b 05 d4 5a 00 00 	mov    0x5ad4(%rip),%rax        # 10e18 <heap_base>
    b344:	48 89 c2             	mov    %rax,%rdx
    b347:	48 8b 05 e2 5a 00 00 	mov    0x5ae2(%rip),%rax        # 10e30 <heap_min_size>
    b34e:	48 01 d0             	add    %rdx,%rax
    b351:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
            size = heap_used - heap_min_size;
    b355:	48 8b 15 b4 61 00 00 	mov    0x61b4(%rip),%rdx        # 11510 <heap_used.2393>
    b35c:	48 8b 05 cd 5a 00 00 	mov    0x5acd(%rip),%rax        # 10e30 <heap_min_size>
    b363:	48 29 c2             	sub    %rax,%rdx
    b366:	48 89 d0             	mov    %rdx,%rax
    b369:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
        }
        int ret = apply_EPC_pages(start_addr, size >> SE_PAGE_SHIFT);
    b36d:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b371:	48 c1 e8 0c          	shr    $0xc,%rax
    b375:	48 89 c2             	mov    %rax,%rdx
    b378:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    b37c:	48 89 d6             	mov    %rdx,%rsi
    b37f:	48 89 c7             	mov    %rax,%rdi
    b382:	e8 76 6e ff ff       	callq  21fd <apply_EPC_pages>
    b387:	89 45 d8             	mov    %eax,-0x28(%rbp)
        if (ret != 0)
    b38a:	83 7d d8 00          	cmpl   $0x0,-0x28(%rbp)
    b38e:	74 14                	je     b3a4 <sbrk+0x2d8>
        {
            heap_used = prev_heap_used;
    b390:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b394:	48 89 05 75 61 00 00 	mov    %rax,0x6175(%rip)        # 11510 <heap_used.2393>
            return (void *)(~(size_t)0);
    b39b:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
    b3a2:	eb 04                	jmp    b3a8 <sbrk+0x2dc>
        }
    }
    return heap_ptr;
    b3a4:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
}
    b3a8:	c9                   	leaveq 
    b3a9:	c3                   	retq   

000000000000b3aa <tstdc_access_version_dummy1>:
#include "stdint.h"
#include "se_cpu_feature.h"
#include "se_cdefs.h"

// add a version to tlibc.
SGX_ACCESS_VERSION(tstdc, 1)
    b3aa:	55                   	push   %rbp
    b3ab:	48 89 e5             	mov    %rsp,%rbp
    b3ae:	c6 05 8b 5c 00 00 73 	movb   $0x73,0x5c8b(%rip)        # 11040 <sgx_tstdc_version>
    b3b5:	48 8d 05 84 5c 00 00 	lea    0x5c84(%rip),%rax        # 11040 <sgx_tstdc_version>
    b3bc:	5d                   	pop    %rbp
    b3bd:	c3                   	retq   

000000000000b3be <sgx_init_string_lib>:
    return _intel_cpu_indicator_init(cpu_feature_indicator);
}

#else
int sgx_init_string_lib(uint64_t cpu_feature_indicator)
{
    b3be:	55                   	push   %rbp
    b3bf:	48 89 e5             	mov    %rsp,%rbp
    b3c2:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    (void)cpu_feature_indicator; 
    return 0;
    b3c6:	b8 00 00 00 00       	mov    $0x0,%eax
}
    b3cb:	5d                   	pop    %rbp
    b3cc:	c3                   	retq   

000000000000b3cd <sgx_spin_lock>:
    return (res);
   
}

uint32_t sgx_spin_lock(sgx_spinlock_t *lock)
{
    b3cd:	55                   	push   %rbp
    b3ce:	48 89 e5             	mov    %rsp,%rbp
    b3d1:	48 83 ec 30          	sub    $0x30,%rsp
    b3d5:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    b3d9:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    b3e0:	00 00 
    b3e2:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    b3e6:	31 c0                	xor    %eax,%eax
    while(_InterlockedExchange((volatile int *)lock, 1) != 0) {
    b3e8:	eb 0c                	jmp    b3f6 <sgx_spin_lock+0x29>
    __asm __volatile(
    b3ea:	f3 90                	pause  
        while (*lock) {
    b3ec:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    b3f0:	8b 00                	mov    (%rax),%eax
    b3f2:	85 c0                	test   %eax,%eax
    b3f4:	75 f4                	jne    b3ea <sgx_spin_lock+0x1d>
    b3f6:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    b3fa:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    b3fe:	c7 45 ec 01 00 00 00 	movl   $0x1,-0x14(%rbp)
    __asm __volatile(
    b405:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b409:	8b 55 ec             	mov    -0x14(%rbp),%edx
    b40c:	f0 87 10             	lock xchg %edx,(%rax)
    b40f:	89 55 e8             	mov    %edx,-0x18(%rbp)
    return (res);
    b412:	8b 45 e8             	mov    -0x18(%rbp),%eax
    while(_InterlockedExchange((volatile int *)lock, 1) != 0) {
    b415:	85 c0                	test   %eax,%eax
    b417:	75 d3                	jne    b3ec <sgx_spin_lock+0x1f>
            /* tell cpu we are spinning */
            _mm_pause();
        } 
    }

    return (0);
    b419:	b8 00 00 00 00       	mov    $0x0,%eax
}
    b41e:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    b422:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    b429:	00 00 
    b42b:	74 05                	je     b432 <sgx_spin_lock+0x65>
    b42d:	e8 76 9e ff ff       	callq  52a8 <__stack_chk_fail>
    b432:	c9                   	leaveq 
    b433:	c3                   	retq   

000000000000b434 <sgx_spin_unlock>:

uint32_t sgx_spin_unlock(sgx_spinlock_t *lock)
{
    b434:	55                   	push   %rbp
    b435:	48 89 e5             	mov    %rsp,%rbp
    b438:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    *lock = 0;
    b43c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b440:	c7 00 00 00 00 00    	movl   $0x0,(%rax)

    return (0);
    b446:	b8 00 00 00 00       	mov    $0x0,%eax
}
    b44b:	5d                   	pop    %rbp
    b44c:	c3                   	retq   

000000000000b44d <_setjmp>:
    xorl    %edx, (_JB_EBP * SE_WORDSIZE)(%eax)
    xorl    %edx, (_JB_ESI * SE_WORDSIZE)(%eax)
    xorl    %edx, (_JB_EDI * SE_WORDSIZE)(%eax)
#endif
#ifdef LINUX64
    PUSHAQ
    b44d:	50                   	push   %rax
    b44e:	53                   	push   %rbx
    b44f:	51                   	push   %rcx
    b450:	52                   	push   %rdx
    b451:	56                   	push   %rsi
    b452:	57                   	push   %rdi
    b453:	41 50                	push   %r8
    b455:	41 51                	push   %r9
    b457:	41 52                	push   %r10
    b459:	41 53                	push   %r11
    b45b:	41 54                	push   %r12
    b45d:	41 55                	push   %r13
    b45f:	41 56                	push   %r14
    b461:	41 57                	push   %r15
    /* check the buf is within the enclave */
    movq    $SE_WORDSIZE, %rsi
    b463:	48 c7 c6 08 00 00 00 	mov    $0x8,%rsi
    call    sgx_is_within_enclave
    b46a:	e8 64 5e ff ff       	callq  12d3 <sgx_is_within_enclave>
    cmpl    $0, %eax
    b46f:	83 f8 00             	cmp    $0x0,%eax
    jz      .crash
    b472:	74 60                	je     b4d4 <.crash>
    POPAQ
    b474:	41 5f                	pop    %r15
    b476:	41 5e                	pop    %r14
    b478:	41 5d                	pop    %r13
    b47a:	41 5c                	pop    %r12
    b47c:	41 5b                	pop    %r11
    b47e:	41 5a                	pop    %r10
    b480:	41 59                	pop    %r9
    b482:	41 58                	pop    %r8
    b484:	5f                   	pop    %rdi
    b485:	5e                   	pop    %rsi
    b486:	5a                   	pop    %rdx
    b487:	59                   	pop    %rcx
    b488:	5b                   	pop    %rbx
    b489:	58                   	pop    %rax
    /* store the registers */
    movq    (%rsp),%r11
    b48a:	4c 8b 1c 24          	mov    (%rsp),%r11
    movq    %rbx, (_JB_RBX * SE_WORDSIZE)(%rdi)
    b48e:	48 89 1f             	mov    %rbx,(%rdi)
    movq    %rbp, (_JB_RBP * SE_WORDSIZE)(%rdi)
    b491:	48 89 6f 08          	mov    %rbp,0x8(%rdi)
    movq    %r12, (_JB_R12 * SE_WORDSIZE)(%rdi)
    b495:	4c 89 67 10          	mov    %r12,0x10(%rdi)
    movq    %r13, (_JB_R13 * SE_WORDSIZE)(%rdi)
    b499:	4c 89 6f 18          	mov    %r13,0x18(%rdi)
    movq    %r14, (_JB_R14 * SE_WORDSIZE)(%rdi)
    b49d:	4c 89 77 20          	mov    %r14,0x20(%rdi)
    movq    %r15, (_JB_R15 * SE_WORDSIZE)(%rdi)
    b4a1:	4c 89 7f 28          	mov    %r15,0x28(%rdi)
    movq    %rsp, (_JB_RSP * SE_WORDSIZE)(%rdi)
    b4a5:	48 89 67 30          	mov    %rsp,0x30(%rdi)
    movq    %r11, (_JB_PC  * SE_WORDSIZE)(%rdi)
    b4a9:	4c 89 5f 38          	mov    %r11,0x38(%rdi)
    /* use statck_guard as cookie*/
    call    get_stack_guard
    b4ad:	e8 c5 11 00 00       	callq  c677 <get_stack_guard>
    xorq    %rax, (_JB_RBX * SE_WORDSIZE)(%rdi)
    b4b2:	48 31 07             	xor    %rax,(%rdi)
    xorq    %rax, (_JB_RBP * SE_WORDSIZE)(%rdi)
    b4b5:	48 31 47 08          	xor    %rax,0x8(%rdi)
    xorq    %rax, (_JB_R12 * SE_WORDSIZE)(%rdi)
    b4b9:	48 31 47 10          	xor    %rax,0x10(%rdi)
    xorq    %rax, (_JB_R13 * SE_WORDSIZE)(%rdi)
    b4bd:	48 31 47 18          	xor    %rax,0x18(%rdi)
    xorq    %rax, (_JB_R14 * SE_WORDSIZE)(%rdi)
    b4c1:	48 31 47 20          	xor    %rax,0x20(%rdi)
    xorq    %rax, (_JB_R15 * SE_WORDSIZE)(%rdi)
    b4c5:	48 31 47 28          	xor    %rax,0x28(%rdi)
    xorq    %rax, (_JB_RSP * SE_WORDSIZE)(%rdi)
    b4c9:	48 31 47 30          	xor    %rax,0x30(%rdi)
    xorq    %rax, (_JB_PC  * SE_WORDSIZE)(%rdi)
    b4cd:	48 31 47 38          	xor    %rax,0x38(%rdi)
#endif	
    xorl    %eax,%eax
    b4d1:	31 c0                	xor    %eax,%eax
    ret
    b4d3:	c3                   	retq   

000000000000b4d4 <.crash>:
.crash:
    ud2
    b4d4:	0f 0b                	ud2    

000000000000b4d6 <_longjmp>:
    movl    %ecx, (0)(%edx)
    popl    %eax   
    movl    %edx, %esp
#endif
#ifdef LINUX64
    PUSHAQ
    b4d6:	50                   	push   %rax
    b4d7:	53                   	push   %rbx
    b4d8:	51                   	push   %rcx
    b4d9:	52                   	push   %rdx
    b4da:	56                   	push   %rsi
    b4db:	57                   	push   %rdi
    b4dc:	41 50                	push   %r8
    b4de:	41 51                	push   %r9
    b4e0:	41 52                	push   %r10
    b4e2:	41 53                	push   %r11
    b4e4:	41 54                	push   %r12
    b4e6:	41 55                	push   %r13
    b4e8:	41 56                	push   %r14
    b4ea:	41 57                	push   %r15
    pushq   %rdi
    b4ec:	57                   	push   %rdi
    /* check the buf is within the enclave */
    movq    $SE_WORDSIZE, %rsi
    b4ed:	48 c7 c6 08 00 00 00 	mov    $0x8,%rsi
    call    sgx_is_within_enclave
    b4f4:	e8 da 5d ff ff       	callq  12d3 <sgx_is_within_enclave>
    cmpl    $0, %eax
    b4f9:	83 f8 00             	cmp    $0x0,%eax
    jz      .crash
    b4fc:	74 d6                	je     b4d4 <.crash>
    popq     %rdi
    b4fe:	5f                   	pop    %rdi
    /* restore xsp*/
    movq    (_JB_RSP * SE_WORDSIZE)(%rdi),%rdx
    b4ff:	48 8b 57 30          	mov    0x30(%rdi),%rdx
    call    get_stack_guard
    b503:	e8 6f 11 00 00       	callq  c677 <get_stack_guard>
    xorq    %rax, %rdx
    b508:	48 31 c2             	xor    %rax,%rdx
    pushq   %rdx
    b50b:	52                   	push   %rdx
    /* check restored rsp is on current statck */
    popq    %rdi
    b50c:	5f                   	pop    %rdi
    call    is_valid_sp
    b50d:	e8 48 87 ff ff       	callq  3c5a <is_valid_sp>
    cmpl    $0, %eax
    b512:	83 f8 00             	cmp    $0x0,%eax
    jz      .crash
    b515:	74 bd                	je     b4d4 <.crash>
    POPAQ
    b517:	41 5f                	pop    %r15
    b519:	41 5e                	pop    %r14
    b51b:	41 5d                	pop    %r13
    b51d:	41 5c                	pop    %r12
    b51f:	41 5b                	pop    %r11
    b521:	41 5a                	pop    %r10
    b523:	41 59                	pop    %r9
    b525:	41 58                	pop    %r8
    b527:	5f                   	pop    %rdi
    b528:	5e                   	pop    %rsi
    b529:	5a                   	pop    %rdx
    b52a:	59                   	pop    %rcx
    b52b:	5b                   	pop    %rbx
    b52c:	58                   	pop    %rax
    /* restore the registers */
    movl    %esi,%eax
    b52d:	89 f0                	mov    %esi,%eax
    movq    (_JB_RBX * SE_WORDSIZE)(%rdi),%rbx
    b52f:	48 8b 1f             	mov    (%rdi),%rbx
    movq    (_JB_RBP * SE_WORDSIZE)(%rdi),%rsi
    b532:	48 8b 77 08          	mov    0x8(%rdi),%rsi
    movq    (_JB_R12 * SE_WORDSIZE)(%rdi),%r12
    b536:	4c 8b 67 10          	mov    0x10(%rdi),%r12
    movq    (_JB_R13 * SE_WORDSIZE)(%rdi),%r13
    b53a:	4c 8b 6f 18          	mov    0x18(%rdi),%r13
    movq    (_JB_R14 * SE_WORDSIZE)(%rdi),%r14
    b53e:	4c 8b 77 20          	mov    0x20(%rdi),%r14
    movq    (_JB_R15 * SE_WORDSIZE)(%rdi),%r15
    b542:	4c 8b 7f 28          	mov    0x28(%rdi),%r15
    movq    (_JB_RSP * SE_WORDSIZE)(%rdi),%rdx
    b546:	48 8b 57 30          	mov    0x30(%rdi),%rdx
    movq    (_JB_PC  * SE_WORDSIZE)(%rdi),%rcx
    b54a:	48 8b 4f 38          	mov    0x38(%rdi),%rcx
    pushq   %rax
    b54e:	50                   	push   %rax
    call    get_stack_guard
    b54f:	e8 23 11 00 00       	callq  c677 <get_stack_guard>
    xorq    %rax, %rbx
    b554:	48 31 c3             	xor    %rax,%rbx
    xorq    %rax, %rsi
    b557:	48 31 c6             	xor    %rax,%rsi
    xorq    %rax, %r12
    b55a:	49 31 c4             	xor    %rax,%r12
    xorq    %rax, %r13
    b55d:	49 31 c5             	xor    %rax,%r13
    xorq    %rax, %r14
    b560:	49 31 c6             	xor    %rax,%r14
    xorq    %rax, %r15
    b563:	49 31 c7             	xor    %rax,%r15
    xorq    %rax, %rdx
    b566:	48 31 c2             	xor    %rax,%rdx
    xorq    %rax, %rcx
    b569:	48 31 c1             	xor    %rax,%rcx
    popq    %rax
    b56c:	58                   	pop    %rax
    movq    %rsi, %rbp
    b56d:	48 89 f5             	mov    %rsi,%rbp
    movq    %rcx, 0(%rdx)
    b570:	48 89 0a             	mov    %rcx,(%rdx)
    movq    %rdx, %rsp
    b573:	48 89 d4             	mov    %rdx,%rsp
#endif
    testl   %eax,%eax
    b576:	85 c0                	test   %eax,%eax
    jnz     1f
    b578:	75 02                	jne    b57c <_longjmp+0xa6>
    incl    %eax
    b57a:	ff c0                	inc    %eax
1:  ret
    b57c:	c3                   	retq   

000000000000b57d <rsrv_mem_init>:

SE_DECLSPEC_EXPORT size_t g_peak_rsrv_mem_committed = 0;


extern "C" int rsrv_mem_init(void *_rsrv_mem_base, size_t _rsrv_mem_size, size_t _rsrv_mem_min_size)
{
    b57d:	55                   	push   %rbp
    b57e:	48 89 e5             	mov    %rsp,%rbp
    b581:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    b585:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    b589:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    if ((_rsrv_mem_base == NULL) || (((size_t) _rsrv_mem_base) & (SE_PAGE_SIZE - 1)))
    b58d:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    b592:	74 0e                	je     b5a2 <rsrv_mem_init+0x25>
    b594:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b598:	25 ff 0f 00 00       	and    $0xfff,%eax
    b59d:	48 85 c0             	test   %rax,%rax
    b5a0:	74 07                	je     b5a9 <rsrv_mem_init+0x2c>
        return SGX_ERROR_UNEXPECTED;
    b5a2:	b8 01 00 00 00       	mov    $0x1,%eax
    b5a7:	eb 67                	jmp    b610 <rsrv_mem_init+0x93>

    if (_rsrv_mem_size & (SE_PAGE_SIZE - 1))
    b5a9:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b5ad:	25 ff 0f 00 00       	and    $0xfff,%eax
    b5b2:	48 85 c0             	test   %rax,%rax
    b5b5:	74 07                	je     b5be <rsrv_mem_init+0x41>
        return SGX_ERROR_UNEXPECTED;
    b5b7:	b8 01 00 00 00       	mov    $0x1,%eax
    b5bc:	eb 52                	jmp    b610 <rsrv_mem_init+0x93>

    if (_rsrv_mem_min_size & (SE_PAGE_SIZE - 1))
    b5be:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b5c2:	25 ff 0f 00 00       	and    $0xfff,%eax
    b5c7:	48 85 c0             	test   %rax,%rax
    b5ca:	74 07                	je     b5d3 <rsrv_mem_init+0x56>
        return SGX_ERROR_UNEXPECTED;
    b5cc:	b8 01 00 00 00       	mov    $0x1,%eax
    b5d1:	eb 3d                	jmp    b610 <rsrv_mem_init+0x93>

    if (_rsrv_mem_size > SIZE_MAX - (size_t)rsrv_mem_base)
    b5d3:	48 8b 05 5e 58 00 00 	mov    0x585e(%rip),%rax        # 10e38 <rsrv_mem_base>
    b5da:	48 f7 d0             	not    %rax
    b5dd:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    b5e1:	76 07                	jbe    b5ea <rsrv_mem_init+0x6d>
        return SGX_ERROR_UNEXPECTED;
    b5e3:	b8 01 00 00 00       	mov    $0x1,%eax
    b5e8:	eb 26                	jmp    b610 <rsrv_mem_init+0x93>

    rsrv_mem_base = _rsrv_mem_base;
    b5ea:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b5ee:	48 89 05 43 58 00 00 	mov    %rax,0x5843(%rip)        # 10e38 <rsrv_mem_base>
    rsrv_mem_size = _rsrv_mem_size;
    b5f5:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b5f9:	48 89 05 40 58 00 00 	mov    %rax,0x5840(%rip)        # 10e40 <rsrv_mem_size>
    rsrv_mem_min_size = _rsrv_mem_min_size;
    b600:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b604:	48 89 05 3d 58 00 00 	mov    %rax,0x583d(%rip)        # 10e48 <rsrv_mem_min_size>

    return SGX_SUCCESS;
    b60b:	b8 00 00 00 00       	mov    $0x0,%eax
}
    b610:	5d                   	pop    %rbp
    b611:	c3                   	retq   

000000000000b612 <__errno>:
#include <errno.h>

extern int *get_errno_addr(void);

int *__errno(void)
{
    b612:	55                   	push   %rbp
    b613:	48 89 e5             	mov    %rsp,%rbp
/*
 * get errno's address from TD section.
 */
    return get_errno_addr();
    b616:	e8 07 85 ff ff       	callq  3b22 <get_errno_addr>
}
    b61b:	5d                   	pop    %rbp
    b61c:	c3                   	retq   

000000000000b61d <tcrypto_access_version_dummy1>:
#include "ippcp.h"
#include "se_cpu_feature.h"
#include "se_cdefs.h"

// add a version to tcrypto.
SGX_ACCESS_VERSION(tcrypto, 1)
    b61d:	55                   	push   %rbp
    b61e:	48 89 e5             	mov    %rsp,%rbp
    b621:	c6 05 38 5a 00 00 73 	movb   $0x73,0x5a38(%rip)        # 11060 <sgx_tcrypto_version>
    b628:	48 8d 05 31 5a 00 00 	lea    0x5a31(%rip),%rax        # 11060 <sgx_tcrypto_version>
    b62f:	5d                   	pop    %rbp
    b630:	c3                   	retq   

000000000000b631 <sgx_init_crypto_lib>:
/* Crypto Library Initialization
* Parameters:
* 	Return: sgx_status_t  - SGX_SUCCESS or failure as defined sgx_error.h
*	Inputs: uint64_t cpu_feature_indicator - Bit array of host CPU feature bits */
extern "C" sgx_status_t sgx_init_crypto_lib(uint64_t cpu_feature_indicator, uint32_t *cpuid_table)
{
    b631:	55                   	push   %rbp
    b632:	48 89 e5             	mov    %rsp,%rbp
    b635:	48 83 ec 10          	sub    $0x10,%rsp
    b639:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    b63d:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    (void)(cpuid_table);

    return init_ipp_cpuid(cpu_feature_indicator);
    b641:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b645:	48 89 c7             	mov    %rax,%rdi
    b648:	e8 02 00 00 00       	callq  b64f <init_ipp_cpuid>
}
    b64d:	c9                   	leaveq 
    b64e:	c3                   	retq   

000000000000b64f <init_ipp_cpuid>:
/* IPP library Initialization
* Parameters:
* 	Return: sgx_status_t  - SGX_SUCCESS or failure as defined sgx_error.h
*	Inputs: uint64_t cpu_feature_indicator - Bit array of host CPU feature bits */
extern "C" sgx_status_t init_ipp_cpuid(uint64_t cpu_feature_indicator)
{
    b64f:	55                   	push   %rbp
    b650:	48 89 e5             	mov    %rsp,%rbp
    b653:	48 83 ec 20          	sub    $0x20,%rsp
    b657:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    IppStatus error_code = ippStsNoOperation;
    b65b:	c7 45 f4 01 00 00 00 	movl   $0x1,-0xc(%rbp)
    if (ippcpSetCpuFeatures == NULL) {
    b662:	48 8b 05 87 59 00 00 	mov    0x5987(%rip),%rax        # 10ff0 <ippcpSetCpuFeatures>
    b669:	48 85 c0             	test   %rax,%rax
    b66c:	75 0a                	jne    b678 <init_ipp_cpuid+0x29>
        return SGX_SUCCESS;
    b66e:	b8 00 00 00 00       	mov    $0x0,%eax
    b673:	e9 81 02 00 00       	jmpq   b8f9 <init_ipp_cpuid+0x2aa>
    //       1. AVX2
    //       2. SSE4.1
    //  We set SSE4.1 as the baseline.
    // Set the IPP feature bits based on host attributes that have been collected
    // NOTE: Some sanity check
    Ipp64u ippCpuFeatures = 0;
    b678:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    b67f:	00 
    if ((cpu_feature_indicator & CPU_FEATURE_SSE4_1) == CPU_FEATURE_SSE4_1)
    b680:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b684:	25 00 02 00 00       	and    $0x200,%eax
    b689:	48 85 c0             	test   %rax,%rax
    b68c:	0f 84 31 02 00 00    	je     b8c3 <init_ipp_cpuid+0x274>
    {
        // Some sanity checking has been performed when setting the feature mask
        // If SSE4.1 is set, then all earlier SSE/MMX ISA enhancements are available
        ippCpuFeatures |= (ippCPUID_SSE41 | ippCPUID_MMX | ippCPUID_SSE |
    b692:	48 83 4d f8 5f       	orq    $0x5f,-0x8(%rbp)
            ippCPUID_SSE2 | ippCPUID_SSE3 | ippCPUID_SSSE3);
        if ((cpu_feature_indicator & CPU_FEATURE_MOVBE) == CPU_FEATURE_MOVBE)
    b697:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b69b:	25 00 08 00 00       	and    $0x800,%eax
    b6a0:	48 85 c0             	test   %rax,%rax
    b6a3:	74 05                	je     b6aa <init_ipp_cpuid+0x5b>
        {
            ippCpuFeatures |= ippCPUID_MOVBE;
    b6a5:	48 83 4d f8 20       	orq    $0x20,-0x8(%rbp)
        }
        if ((cpu_feature_indicator & CPU_FEATURE_SSE4_2) == CPU_FEATURE_SSE4_2)
    b6aa:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b6ae:	25 00 04 00 00       	and    $0x400,%eax
    b6b3:	48 85 c0             	test   %rax,%rax
    b6b6:	74 08                	je     b6c0 <init_ipp_cpuid+0x71>
        {
            ippCpuFeatures |= ippCPUID_SSE42;
    b6b8:	48 81 4d f8 80 00 00 	orq    $0x80,-0x8(%rbp)
    b6bf:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX) == CPU_FEATURE_AVX)
    b6c0:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b6c4:	25 00 00 01 00       	and    $0x10000,%eax
    b6c9:	48 85 c0             	test   %rax,%rax
    b6cc:	74 10                	je     b6de <init_ipp_cpuid+0x8f>
        {
            ippCpuFeatures |= ippCPUID_AVX;
    b6ce:	48 81 4d f8 00 01 00 	orq    $0x100,-0x8(%rbp)
    b6d5:	00 
            ippCpuFeatures |= ippAVX_ENABLEDBYOS;
    b6d6:	48 81 4d f8 00 02 00 	orq    $0x200,-0x8(%rbp)
    b6dd:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AES) == CPU_FEATURE_AES)
    b6de:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b6e2:	25 00 40 00 00       	and    $0x4000,%eax
    b6e7:	48 85 c0             	test   %rax,%rax
    b6ea:	74 08                	je     b6f4 <init_ipp_cpuid+0xa5>
        {
            ippCpuFeatures |= ippCPUID_AES;
    b6ec:	48 81 4d f8 00 04 00 	orq    $0x400,-0x8(%rbp)
    b6f3:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_PCLMULQDQ) == CPU_FEATURE_PCLMULQDQ)
    b6f4:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b6f8:	25 00 20 00 00       	and    $0x2000,%eax
    b6fd:	48 85 c0             	test   %rax,%rax
    b700:	74 08                	je     b70a <init_ipp_cpuid+0xbb>
        {
            ippCpuFeatures |= ippCPUID_CLMUL;
    b702:	48 81 4d f8 00 08 00 	orq    $0x800,-0x8(%rbp)
    b709:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_RDRND) == CPU_FEATURE_RDRND)
    b70a:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b70e:	25 00 00 02 00       	and    $0x20000,%eax
    b713:	48 85 c0             	test   %rax,%rax
    b716:	74 08                	je     b720 <init_ipp_cpuid+0xd1>
        {
            ippCpuFeatures |= ippCPUID_RDRAND;
    b718:	48 81 4d f8 00 20 00 	orq    $0x2000,-0x8(%rbp)
    b71f:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_F16C) == CPU_FEATURE_F16C)
    b720:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b724:	25 00 80 00 00       	and    $0x8000,%eax
    b729:	48 85 c0             	test   %rax,%rax
    b72c:	74 08                	je     b736 <init_ipp_cpuid+0xe7>
        {
            ippCpuFeatures |= ippCPUID_F16C;
    b72e:	48 81 4d f8 00 40 00 	orq    $0x4000,-0x8(%rbp)
    b735:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX2) == CPU_FEATURE_AVX2)
    b736:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b73a:	25 00 00 80 00       	and    $0x800000,%eax
    b73f:	48 85 c0             	test   %rax,%rax
    b742:	74 08                	je     b74c <init_ipp_cpuid+0xfd>
        {
            ippCpuFeatures |= ippCPUID_AVX2;
    b744:	48 81 4d f8 00 80 00 	orq    $0x8000,-0x8(%rbp)
    b74b:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_ADX) == CPU_FEATURE_ADX)
    b74c:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b750:	25 00 00 00 10       	and    $0x10000000,%eax
    b755:	48 85 c0             	test   %rax,%rax
    b758:	74 08                	je     b762 <init_ipp_cpuid+0x113>
        {
            ippCpuFeatures |= ippCPUID_ADCOX;
    b75a:	48 81 4d f8 00 00 01 	orq    $0x10000,-0x8(%rbp)
    b761:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_RDSEED) == CPU_FEATURE_RDSEED)
    b762:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b766:	25 00 00 00 20       	and    $0x20000000,%eax
    b76b:	48 85 c0             	test   %rax,%rax
    b76e:	74 08                	je     b778 <init_ipp_cpuid+0x129>
        {
            ippCpuFeatures |= ippCPUID_RDSEED;
    b770:	48 81 4d f8 00 00 02 	orq    $0x20000,-0x8(%rbp)
    b777:	00 
        }
	if ((cpu_feature_indicator & CPU_FEATURE_SHA) == CPU_FEATURE_SHA)
    b778:	48 b8 00 00 00 00 08 	movabs $0x800000000,%rax
    b77f:	00 00 00 
    b782:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b786:	48 85 c0             	test   %rax,%rax
    b789:	74 08                	je     b793 <init_ipp_cpuid+0x144>
        {
            ippCpuFeatures |= ippCPUID_SHA;
    b78b:	48 81 4d f8 00 00 08 	orq    $0x80000,-0x8(%rbp)
    b792:	00 
        }
        
	// AVX512
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512F) == CPU_FEATURE_AVX512F)
    b793:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b797:	25 00 00 00 08       	and    $0x8000000,%eax
    b79c:	48 85 c0             	test   %rax,%rax
    b79f:	74 16                	je     b7b7 <init_ipp_cpuid+0x168>
        {
            ippCpuFeatures |= ippCPUID_AVX512F;
    b7a1:	48 81 4d f8 00 00 10 	orq    $0x100000,-0x8(%rbp)
    b7a8:	00 
            ippCpuFeatures |= ippAVX512_ENABLEDBYOS;
    b7a9:	48 b8 00 00 00 00 02 	movabs $0x200000000,%rax
    b7b0:	00 00 00 
    b7b3:	48 09 45 f8          	or     %rax,-0x8(%rbp)
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512PF) == CPU_FEATURE_AVX512PF)
    b7b7:	48 b8 00 00 00 00 02 	movabs $0x200000000,%rax
    b7be:	00 00 00 
    b7c1:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b7c5:	48 85 c0             	test   %rax,%rax
    b7c8:	74 08                	je     b7d2 <init_ipp_cpuid+0x183>
        {
            ippCpuFeatures |= ippCPUID_AVX512PF;
    b7ca:	48 81 4d f8 00 00 80 	orq    $0x800000,-0x8(%rbp)
    b7d1:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512ER) == CPU_FEATURE_AVX512ER)
    b7d2:	48 b8 00 00 00 00 01 	movabs $0x100000000,%rax
    b7d9:	00 00 00 
    b7dc:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b7e0:	48 85 c0             	test   %rax,%rax
    b7e3:	74 08                	je     b7ed <init_ipp_cpuid+0x19e>
        {
            ippCpuFeatures |= ippCPUID_AVX512ER;
    b7e5:	48 81 4d f8 00 00 40 	orq    $0x400000,-0x8(%rbp)
    b7ec:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512CD) == CPU_FEATURE_AVX512CD)
    b7ed:	48 b8 00 00 00 00 04 	movabs $0x400000000,%rax
    b7f4:	00 00 00 
    b7f7:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b7fb:	48 85 c0             	test   %rax,%rax
    b7fe:	74 08                	je     b808 <init_ipp_cpuid+0x1b9>
        {
            ippCpuFeatures |= ippCPUID_AVX512CD;
    b800:	48 81 4d f8 00 00 20 	orq    $0x200000,-0x8(%rbp)
    b807:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512DQ) == CPU_FEATURE_AVX512DQ)
    b808:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b80c:	25 00 00 00 01       	and    $0x1000000,%eax
    b811:	48 85 c0             	test   %rax,%rax
    b814:	74 08                	je     b81e <init_ipp_cpuid+0x1cf>
        {
            ippCpuFeatures |= ippCPUID_AVX512DQ;
    b816:	48 81 4d f8 00 00 00 	orq    $0x2000000,-0x8(%rbp)
    b81d:	02 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512BW) == CPU_FEATURE_AVX512BW)
    b81e:	48 b8 00 00 00 00 20 	movabs $0x2000000000,%rax
    b825:	00 00 00 
    b828:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b82c:	48 85 c0             	test   %rax,%rax
    b82f:	74 08                	je     b839 <init_ipp_cpuid+0x1ea>
        {
            ippCpuFeatures |= ippCPUID_AVX512BW;
    b831:	48 81 4d f8 00 00 00 	orq    $0x1000000,-0x8(%rbp)
    b838:	01 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512VL) == CPU_FEATURE_AVX512VL)
    b839:	48 b8 00 00 00 00 40 	movabs $0x4000000000,%rax
    b840:	00 00 00 
    b843:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b847:	48 85 c0             	test   %rax,%rax
    b84a:	74 08                	je     b854 <init_ipp_cpuid+0x205>
        {
            ippCpuFeatures |= ippCPUID_AVX512VL;
    b84c:	48 81 4d f8 00 00 00 	orq    $0x4000000,-0x8(%rbp)
    b853:	04 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512VBMI) == CPU_FEATURE_AVX512VBMI)
    b854:	48 b8 00 00 00 00 80 	movabs $0x8000000000,%rax
    b85b:	00 00 00 
    b85e:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b862:	48 85 c0             	test   %rax,%rax
    b865:	74 08                	je     b86f <init_ipp_cpuid+0x220>
        {
            ippCpuFeatures |= ippCPUID_AVX512VBMI;
    b867:	48 81 4d f8 00 00 00 	orq    $0x8000000,-0x8(%rbp)
    b86e:	08 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512_4VNNIW) == CPU_FEATURE_AVX512_4VNNIW)
    b86f:	48 b8 00 00 00 00 00 	movabs $0x20000000000,%rax
    b876:	02 00 00 
    b879:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b87d:	48 85 c0             	test   %rax,%rax
    b880:	74 08                	je     b88a <init_ipp_cpuid+0x23b>
        {
            ippCpuFeatures |= ippCPUID_AVX512_4VNNIW;
    b882:	48 81 4d f8 00 00 00 	orq    $0x40000000,-0x8(%rbp)
    b889:	40 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512_4FMAPS) == CPU_FEATURE_AVX512_4FMAPS)
    b88a:	48 b8 00 00 00 00 00 	movabs $0x10000000000,%rax
    b891:	01 00 00 
    b894:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b898:	48 85 c0             	test   %rax,%rax
    b89b:	74 08                	je     b8a5 <init_ipp_cpuid+0x256>
        {
            ippCpuFeatures |= ippCPUID_AVX512_4FMADDPS;
    b89d:	48 81 4d f8 00 00 00 	orq    $0x20000000,-0x8(%rbp)
    b8a4:	20 
        }

        if ((cpu_feature_indicator & CPU_FEATURE_AVX512IFMA52) == CPU_FEATURE_AVX512IFMA52)
    b8a5:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b8a9:	25 00 00 00 40       	and    $0x40000000,%eax
    b8ae:	48 85 c0             	test   %rax,%rax
    b8b1:	74 17                	je     b8ca <init_ipp_cpuid+0x27b>
        {
            ippCpuFeatures |= ippCPUID_AVX512IFMA;
    b8b3:	48 b8 00 00 00 00 01 	movabs $0x100000000,%rax
    b8ba:	00 00 00 
    b8bd:	48 09 45 f8          	or     %rax,-0x8(%rbp)
    b8c1:	eb 07                	jmp    b8ca <init_ipp_cpuid+0x27b>
        }
    }
    else
    {
        // Return error if the old platoform has no SSE4.1
        return SGX_ERROR_INVALID_PARAMETER;
    b8c3:	b8 02 00 00 00       	mov    $0x2,%eax
    b8c8:	eb 2f                	jmp    b8f9 <init_ipp_cpuid+0x2aa>

    }

    // Call SetCpuFeatures() to set the IPP library with the collected CPU features
    ippCpuFeatures |= ippCPUID_NOCHECK; /* Force ippcpSetCpuFeatures to set CPU features without check */
    b8ca:	48 b8 00 00 00 00 00 	movabs $0x8000000000000000,%rax
    b8d1:	00 00 80 
    b8d4:	48 09 45 f8          	or     %rax,-0x8(%rbp)
    error_code = ippcpSetCpuFeatures(ippCpuFeatures);
    b8d8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b8dc:	48 89 c7             	mov    %rax,%rdi
    b8df:	e8 34 57 ff ff       	callq  1018 <ippcpSetCpuFeatures@plt>
    b8e4:	89 45 f4             	mov    %eax,-0xc(%rbp)

    if (error_code != ippStsNoErr)
    b8e7:	83 7d f4 00          	cmpl   $0x0,-0xc(%rbp)
    b8eb:	74 07                	je     b8f4 <init_ipp_cpuid+0x2a5>
    {
        return SGX_ERROR_INVALID_PARAMETER;
    b8ed:	b8 02 00 00 00       	mov    $0x2,%eax
    b8f2:	eb 05                	jmp    b8f9 <init_ipp_cpuid+0x2aa>
    }
    return SGX_SUCCESS;
    b8f4:	b8 00 00 00 00       	mov    $0x0,%eax
}
    b8f9:	c9                   	leaveq 
    b8fa:	c3                   	retq   

000000000000b8fb <tservice_access_version_dummy1>:
#include "sgx_trts.h"
#include "trts_inst.h"
#include "se_cdefs.h"

// add a version to tservice.
SGX_ACCESS_VERSION(tservice, 1)
    b8fb:	55                   	push   %rbp
    b8fc:	48 89 e5             	mov    %rsp,%rbp
    b8ff:	c6 05 7a 57 00 00 73 	movb   $0x73,0x577a(%rip)        # 11080 <sgx_tservice_version>
    b906:	48 8d 05 73 57 00 00 	lea    0x5773(%rip),%rax        # 11080 <sgx_tservice_version>
    b90d:	5d                   	pop    %rbp
    b90e:	c3                   	retq   

000000000000b90f <sgx_create_report>:

extern "C" void * __memset(void *dst, int c, size_t n);

sgx_status_t sgx_create_report(const sgx_target_info_t *target_info, const sgx_report_data_t *report_data, sgx_report_t *report)
{
    b90f:	4c 8d 54 24 08       	lea    0x8(%rsp),%r10
    b914:	48 81 e4 00 fe ff ff 	and    $0xfffffffffffffe00,%rsp
    b91b:	41 ff 72 f8          	pushq  -0x8(%r10)
    b91f:	55                   	push   %rbp
    b920:	48 89 e5             	mov    %rsp,%rbp
    b923:	41 52                	push   %r10
    b925:	48 81 ec e8 09 00 00 	sub    $0x9e8,%rsp
    b92c:	48 89 bd 78 f7 ff ff 	mov    %rdi,-0x888(%rbp)
    b933:	48 89 b5 70 f7 ff ff 	mov    %rsi,-0x890(%rbp)
    b93a:	48 89 95 68 f7 ff ff 	mov    %rdx,-0x898(%rbp)
    b941:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    b948:	00 00 
    b94a:	48 89 85 08 fe ff ff 	mov    %rax,-0x1f8(%rbp)
    b951:	31 c0                	xor    %eax,%eax
    static_assert(sizeof(*target_info) == 512, "sgx_target_info_t");
    static_assert(sizeof(*report_data) == 64, "sgx_report_data_t");
    static_assert(sizeof(*report) == 432, "sgx_report_t");

    alignas(REPORT_DATA_ALIGN_SIZE) sgx_report_data_t tmp_report_data;
    __memset((void *)&tmp_report_data, 0, sizeof(sgx_report_data_t));
    b953:	48 8d 85 90 f7 ff ff 	lea    -0x870(%rbp),%rax
    b95a:	ba 40 00 00 00       	mov    $0x40,%edx
    b95f:	be 00 00 00 00       	mov    $0x0,%esi
    b964:	48 89 c7             	mov    %rax,%rdi
    b967:	e8 c1 f5 ff ff       	callq  af2d <__memset>
    alignas(TARGET_INFO_ALIGN_SIZE) sgx_target_info_t tmp_target_info;
    __memset((void *)&tmp_target_info, 0, sizeof(sgx_target_info_t));    
    b96c:	48 8d 85 10 fa ff ff 	lea    -0x5f0(%rbp),%rax
    b973:	ba 00 02 00 00       	mov    $0x200,%edx
    b978:	be 00 00 00 00       	mov    $0x0,%esi
    b97d:	48 89 c7             	mov    %rax,%rdi
    b980:	e8 a8 f5 ff ff       	callq  af2d <__memset>
    alignas(REPORT_ALIGN_SIZE)sgx_report_t tmp_report;
    __memset((void *)&tmp_report, 0, sizeof(sgx_report_t));
    b985:	48 8d 85 10 f8 ff ff 	lea    -0x7f0(%rbp),%rax
    b98c:	ba b0 01 00 00       	mov    $0x1b0,%edx
    b991:	be 00 00 00 00       	mov    $0x0,%esi
    b996:	48 89 c7             	mov    %rax,%rdi
    b999:	e8 8f f5 ff ff       	callq  af2d <__memset>

    // check parameters
    //
    // target_info is allowed to be NULL, but if it is not NULL, it must be within the enclave
    if(target_info)
    b99e:	48 83 bd 78 f7 ff ff 	cmpq   $0x0,-0x888(%rbp)
    b9a5:	00 
    b9a6:	74 46                	je     b9ee <sgx_create_report+0xdf>
    {
        if (!sgx_is_within_enclave(target_info, sizeof(*target_info)))
    b9a8:	48 8b 85 78 f7 ff ff 	mov    -0x888(%rbp),%rax
    b9af:	be 00 02 00 00       	mov    $0x200,%esi
    b9b4:	48 89 c7             	mov    %rax,%rdi
    b9b7:	e8 17 59 ff ff       	callq  12d3 <sgx_is_within_enclave>
    b9bc:	85 c0                	test   %eax,%eax
    b9be:	0f 94 c0             	sete   %al
    b9c1:	84 c0                	test   %al,%al
    b9c3:	74 0a                	je     b9cf <sgx_create_report+0xc0>
            return SGX_ERROR_INVALID_PARAMETER;
    b9c5:	b8 02 00 00 00       	mov    $0x2,%eax
    b9ca:	e9 8a 01 00 00       	jmpq   bb59 <sgx_create_report+0x24a>
        tmp_target_info = *target_info;
    b9cf:	48 8b 95 78 f7 ff ff 	mov    -0x888(%rbp),%rdx
    b9d6:	48 8d 85 10 fa ff ff 	lea    -0x5f0(%rbp),%rax
    b9dd:	48 89 d6             	mov    %rdx,%rsi
    b9e0:	ba 40 00 00 00       	mov    $0x40,%edx
    b9e5:	48 89 c7             	mov    %rax,%rdi
    b9e8:	48 89 d1             	mov    %rdx,%rcx
    b9eb:	f3 48 a5             	rep movsq %ds:(%rsi),%es:(%rdi)
    }
    // report_data is allowed to be NULL, but if it is not NULL, it must be within the enclave
    if(report_data)
    b9ee:	48 83 bd 70 f7 ff ff 	cmpq   $0x0,-0x890(%rbp)
    b9f5:	00 
    b9f6:	0f 84 85 00 00 00    	je     ba81 <sgx_create_report+0x172>
    {
        if(!sgx_is_within_enclave(report_data, sizeof(*report_data)))
    b9fc:	48 8b 85 70 f7 ff ff 	mov    -0x890(%rbp),%rax
    ba03:	be 40 00 00 00       	mov    $0x40,%esi
    ba08:	48 89 c7             	mov    %rax,%rdi
    ba0b:	e8 c3 58 ff ff       	callq  12d3 <sgx_is_within_enclave>
    ba10:	85 c0                	test   %eax,%eax
    ba12:	0f 94 c0             	sete   %al
    ba15:	84 c0                	test   %al,%al
    ba17:	74 0a                	je     ba23 <sgx_create_report+0x114>
            return SGX_ERROR_INVALID_PARAMETER;
    ba19:	b8 02 00 00 00       	mov    $0x2,%eax
    ba1e:	e9 36 01 00 00       	jmpq   bb59 <sgx_create_report+0x24a>
        tmp_report_data = *report_data;
    ba23:	48 8b 8d 70 f7 ff ff 	mov    -0x890(%rbp),%rcx
    ba2a:	48 8b 01             	mov    (%rcx),%rax
    ba2d:	48 8b 51 08          	mov    0x8(%rcx),%rdx
    ba31:	48 89 85 90 f7 ff ff 	mov    %rax,-0x870(%rbp)
    ba38:	48 89 95 98 f7 ff ff 	mov    %rdx,-0x868(%rbp)
    ba3f:	48 8b 41 10          	mov    0x10(%rcx),%rax
    ba43:	48 8b 51 18          	mov    0x18(%rcx),%rdx
    ba47:	48 89 85 a0 f7 ff ff 	mov    %rax,-0x860(%rbp)
    ba4e:	48 89 95 a8 f7 ff ff 	mov    %rdx,-0x858(%rbp)
    ba55:	48 8b 41 20          	mov    0x20(%rcx),%rax
    ba59:	48 8b 51 28          	mov    0x28(%rcx),%rdx
    ba5d:	48 89 85 b0 f7 ff ff 	mov    %rax,-0x850(%rbp)
    ba64:	48 89 95 b8 f7 ff ff 	mov    %rdx,-0x848(%rbp)
    ba6b:	48 8b 41 30          	mov    0x30(%rcx),%rax
    ba6f:	48 8b 51 38          	mov    0x38(%rcx),%rdx
    ba73:	48 89 85 c0 f7 ff ff 	mov    %rax,-0x840(%rbp)
    ba7a:	48 89 95 c8 f7 ff ff 	mov    %rdx,-0x838(%rbp)
    }
    // report must be within the enclave
    if(!report || !sgx_is_within_enclave(report, sizeof(*report)))
    ba81:	48 83 bd 68 f7 ff ff 	cmpq   $0x0,-0x898(%rbp)
    ba88:	00 
    ba89:	74 18                	je     baa3 <sgx_create_report+0x194>
    ba8b:	48 8b 85 68 f7 ff ff 	mov    -0x898(%rbp),%rax
    ba92:	be b0 01 00 00       	mov    $0x1b0,%esi
    ba97:	48 89 c7             	mov    %rax,%rdi
    ba9a:	e8 34 58 ff ff       	callq  12d3 <sgx_is_within_enclave>
    ba9f:	85 c0                	test   %eax,%eax
    baa1:	75 07                	jne    baaa <sgx_create_report+0x19b>
    baa3:	b8 01 00 00 00       	mov    $0x1,%eax
    baa8:	eb 05                	jmp    baaf <sgx_create_report+0x1a0>
    baaa:	b8 00 00 00 00       	mov    $0x0,%eax
    baaf:	84 c0                	test   %al,%al
    bab1:	74 0a                	je     babd <sgx_create_report+0x1ae>
    {
        return SGX_ERROR_INVALID_PARAMETER;
    bab3:	b8 02 00 00 00       	mov    $0x2,%eax
    bab8:	e9 9c 00 00 00       	jmpq   bb59 <sgx_create_report+0x24a>
    }


    // Do EREPORT
    auto failed = do_ereport(&tmp_target_info, &tmp_report_data, &tmp_report);
    babd:	48 8d 95 10 f8 ff ff 	lea    -0x7f0(%rbp),%rdx
    bac4:	48 8d 8d 90 f7 ff ff 	lea    -0x870(%rbp),%rcx
    bacb:	48 8d 85 10 fa ff ff 	lea    -0x5f0(%rbp),%rax
    bad2:	48 89 ce             	mov    %rcx,%rsi
    bad5:	48 89 c7             	mov    %rax,%rdi
    bad8:	e8 56 0e 00 00       	callq  c933 <do_ereport>
    badd:	89 85 84 f7 ff ff    	mov    %eax,-0x87c(%rbp)
    
    // Copy data to the user buffer: *report = tmp_report; 
    // Use a loop to avoid compiler to call memcpy, 
    // which cannot be used during enclave initialization.
    // No need to cleanup the tmp_report as it is not secret.
    if (!failed)
    bae3:	83 bd 84 f7 ff ff 00 	cmpl   $0x0,-0x87c(%rbp)
    baea:	75 57                	jne    bb43 <sgx_create_report+0x234>
    {
        static_assert(sizeof(*report) % sizeof(uint64_t) == 0, "sizeof(sgx_report_t) should be multiple of 8");
        for(size_t i = 0; i < sizeof(*report)/sizeof(uint64_t); i++)
    baec:	48 c7 85 88 f7 ff ff 	movq   $0x0,-0x878(%rbp)
    baf3:	00 00 00 00 
    baf7:	48 83 bd 88 f7 ff ff 	cmpq   $0x35,-0x878(%rbp)
    bafe:	35 
    baff:	77 42                	ja     bb43 <sgx_create_report+0x234>
        {
            ((uint64_t*)report)[i] = ((uint64_t*)&tmp_report)[i];
    bb01:	48 8b 85 88 f7 ff ff 	mov    -0x878(%rbp),%rax
    bb08:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    bb0f:	00 
    bb10:	48 8d 85 10 f8 ff ff 	lea    -0x7f0(%rbp),%rax
    bb17:	48 01 d0             	add    %rdx,%rax
    bb1a:	48 8b 95 88 f7 ff ff 	mov    -0x878(%rbp),%rdx
    bb21:	48 8d 0c d5 00 00 00 	lea    0x0(,%rdx,8),%rcx
    bb28:	00 
    bb29:	48 8b 95 68 f7 ff ff 	mov    -0x898(%rbp),%rdx
    bb30:	48 01 ca             	add    %rcx,%rdx
    bb33:	48 8b 00             	mov    (%rax),%rax
    bb36:	48 89 02             	mov    %rax,(%rdx)
        for(size_t i = 0; i < sizeof(*report)/sizeof(uint64_t); i++)
    bb39:	48 83 85 88 f7 ff ff 	addq   $0x1,-0x878(%rbp)
    bb40:	01 
    bb41:	eb b4                	jmp    baf7 <sgx_create_report+0x1e8>
        }
    }


    return failed ? SGX_ERROR_UNEXPECTED : SGX_SUCCESS;
    bb43:	83 bd 84 f7 ff ff 00 	cmpl   $0x0,-0x87c(%rbp)
    bb4a:	74 07                	je     bb53 <sgx_create_report+0x244>
    bb4c:	b8 01 00 00 00       	mov    $0x1,%eax
    bb51:	eb 06                	jmp    bb59 <sgx_create_report+0x24a>
    bb53:	b8 00 00 00 00       	mov    $0x0,%eax
    bb58:	90                   	nop
}
    bb59:	48 8b b5 08 fe ff ff 	mov    -0x1f8(%rbp),%rsi
    bb60:	64 48 33 34 25 28 00 	xor    %fs:0x28,%rsi
    bb67:	00 00 
    bb69:	74 05                	je     bb70 <sgx_create_report+0x261>
    bb6b:	e8 38 97 ff ff       	callq  52a8 <__stack_chk_fail>
    bb70:	48 81 c4 e8 09 00 00 	add    $0x9e8,%rsp
    bb77:	41 5a                	pop    %r10
    bb79:	5d                   	pop    %rbp
    bb7a:	49 8d 62 f8          	lea    -0x8(%r10),%rsp
    bb7e:	c3                   	retq   

000000000000bb7f <sgx_self_report>:

const sgx_report_t *sgx_self_report(void)
{
    bb7f:	55                   	push   %rbp
    bb80:	48 89 e5             	mov    %rsp,%rbp
        .mac = {0}
    };

    // Below sgx_create_report() will be called only once during the enclave initialization,
    // so there is no potential race conditional.
    if (0 == _report.body.attributes.flags)
    bb83:	48 8b 05 c6 59 00 00 	mov    0x59c6(%rip),%rax        # 11550 <_ZZ15sgx_self_reportE7_report+0x30>
    bb8a:	48 85 c0             	test   %rax,%rax
    bb8d:	75 16                	jne    bba5 <sgx_self_report+0x26>
        sgx_create_report(nullptr, nullptr, &_report);
    bb8f:	48 8d 15 8a 59 00 00 	lea    0x598a(%rip),%rdx        # 11520 <_ZZ15sgx_self_reportE7_report>
    bb96:	be 00 00 00 00       	mov    $0x0,%esi
    bb9b:	bf 00 00 00 00       	mov    $0x0,%edi
    bba0:	e8 6a fd ff ff       	callq  b90f <sgx_create_report>

    return &_report;
    bba5:	48 8d 05 74 59 00 00 	lea    0x5974(%rip),%rax        # 11520 <_ZZ15sgx_self_reportE7_report>
}
    bbac:	5d                   	pop    %rbp
    bbad:	c3                   	retq   

Disassembly of section .nipx:

000000000000bbae <do_init_enclave>:
}

#ifndef SE_SIM
int accept_post_remove(const volatile layout_t *layout_start, const volatile layout_t *layout_end, size_t offset);
#endif

    bbae:	55                   	push   %rbp
    bbaf:	48 89 e5             	mov    %rsp,%rbp
    bbb2:	48 83 ec 20          	sub    $0x20,%rsp
    bbb6:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    bbba:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
extern size_t rsrv_mem_min_size;

sgx_status_t do_init_enclave(void *ms, void *tcs)
{
    bbbe:	e8 6f 0a 00 00       	callq  c632 <get_enclave_base>
    bbc3:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
#ifdef SE_SIM
    bbc7:	e8 85 0a 00 00       	callq  c651 <lock_enclave>
    bbcc:	85 c0                	test   %eax,%eax
    bbce:	0f 95 c0             	setne  %al
    bbd1:	84 c0                	test   %al,%al
    bbd3:	74 0a                	je     bbdf <do_init_enclave+0x31>
    UNUSED(tcs);
#endif
    bbd5:	b8 01 00 00 00       	mov    $0x1,%eax
    bbda:	e9 fa 01 00 00       	jmpq   bdd9 <do_init_enclave+0x22b>
    void *enclave_base = get_enclave_base();
    if(ENCLAVE_INIT_NOT_STARTED != lock_enclave())
    bbdf:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    bbe3:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    bbe7:	48 89 d6             	mov    %rdx,%rsi
    bbea:	48 89 c7             	mov    %rax,%rdi
    bbed:	e8 e9 01 00 00       	callq  bddb <init_enclave>
    bbf2:	85 c0                	test   %eax,%eax
    bbf4:	0f 95 c0             	setne  %al
    bbf7:	84 c0                	test   %al,%al
    bbf9:	74 0a                	je     bc05 <do_init_enclave+0x57>
    {
        return SGX_ERROR_UNEXPECTED;
    bbfb:	b8 01 00 00 00       	mov    $0x1,%eax
    bc00:	e9 d4 01 00 00       	jmpq   bdd9 <do_init_enclave+0x22b>
    }
    if(0 != init_enclave(enclave_base, ms))
    {
        return SGX_ERROR_UNEXPECTED;
    bc05:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    bc09:	be 01 00 00 00       	mov    $0x1,%esi
    bc0e:	48 89 c7             	mov    %rax,%rdi
    bc11:	e8 71 6f ff ff       	callq  2b87 <do_init_thread>
    bc16:	85 c0                	test   %eax,%eax
    bc18:	0f 95 c0             	setne  %al
    bc1b:	84 c0                	test   %al,%al
    bc1d:	74 0a                	je     bc29 <do_init_enclave+0x7b>
    }

    bc1f:	b8 01 00 00 00       	mov    $0x1,%eax
    bc24:	e9 b0 01 00 00       	jmpq   bdd9 <do_init_enclave+0x22b>
#ifndef SE_SIM
    if (SGX_SUCCESS != do_init_thread(tcs, true))
    {
        return SGX_ERROR_UNEXPECTED;
    bc29:	8b 05 d1 51 00 00    	mov    0x51d1(%rip),%eax        # 10e00 <EDMM_supported>
    bc2f:	85 c0                	test   %eax,%eax
    bc31:	0f 84 1d 01 00 00    	je     bd54 <do_init_enclave+0x1a6>
    }

    bc37:	48 8d 05 42 15 00 00 	lea    0x1542(%rip),%rax        # d180 <g_global_data>
    bc3e:	8b 80 28 01 00 00    	mov    0x128(%rax),%eax
    bc44:	89 c0                	mov    %eax,%eax
    bc46:	48 c1 e0 05          	shl    $0x5,%rax
    bc4a:	48 89 c2             	mov    %rax,%rdx
    bc4d:	48 8d 05 2c 15 00 00 	lea    0x152c(%rip),%rax        # d180 <g_global_data>
    bc54:	48 8d 80 30 01 00 00 	lea    0x130(%rax),%rax
    bc5b:	48 01 d0             	add    %rdx,%rax
    bc5e:	ba 00 00 00 00       	mov    $0x0,%edx
    bc63:	48 89 c6             	mov    %rax,%rsi
    bc66:	48 8d 05 13 15 00 00 	lea    0x1513(%rip),%rax        # d180 <g_global_data>
    bc6d:	48 8d b8 30 01 00 00 	lea    0x130(%rax),%rdi
    bc74:	e8 5e 5d ff ff       	callq  19d7 <_Z18accept_post_removePVK9_layout_tS1_m>
    bc79:	85 c0                	test   %eax,%eax
    bc7b:	0f 95 c0             	setne  %al
    bc7e:	84 c0                	test   %al,%al
    bc80:	74 0a                	je     bc8c <do_init_enclave+0xde>
    /* for EDMM, we need to accept the trimming of the POST_REMOVE pages. */
    bc82:	b8 01 00 00 00       	mov    $0x1,%eax
    bc87:	e9 4d 01 00 00       	jmpq   bdd9 <do_init_enclave+0x22b>
    if (EDMM_supported)
    {
    bc8c:	e8 e4 7c ff ff       	callq  3975 <get_heap_min_size>
    bc91:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
        if (0 != accept_post_remove(&g_global_data.layout_table[0], &g_global_data.layout_table[0] + g_global_data.layout_entry_num, 0))
    bc95:	48 8d 05 e4 14 00 00 	lea    0x14e4(%rip),%rax        # d180 <g_global_data>
    bc9c:	48 8b 50 08          	mov    0x8(%rax),%rdx
    bca0:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    bca4:	48 01 d0             	add    %rdx,%rax
    bca7:	48 89 c7             	mov    %rax,%rdi
    bcaa:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    bcae:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    bcb2:	48 89 d1             	mov    %rdx,%rcx
    bcb5:	ba 00 00 00 00       	mov    $0x0,%edx
    bcba:	48 89 c6             	mov    %rax,%rsi
    bcbd:	e8 d6 f2 ff ff       	callq  af98 <memset_s>
            return SGX_ERROR_UNEXPECTED;

    bcc2:	48 8d 05 7f 51 00 00 	lea    0x517f(%rip),%rax        # 10e48 <rsrv_mem_min_size>
    bcc9:	48 8b 10             	mov    (%rax),%rdx
    bccc:	48 8d 05 75 51 00 00 	lea    0x5175(%rip),%rax        # 10e48 <rsrv_mem_min_size>
    bcd3:	48 8b 00             	mov    (%rax),%rax
    bcd6:	48 8d 0d a3 14 00 00 	lea    0x14a3(%rip),%rcx        # d180 <g_global_data>
    bcdd:	48 8b 71 18          	mov    0x18(%rcx),%rsi
    bce1:	48 8b 4d f0          	mov    -0x10(%rbp),%rcx
    bce5:	48 01 f1             	add    %rsi,%rcx
    bce8:	48 89 cf             	mov    %rcx,%rdi
    bceb:	48 89 d1             	mov    %rdx,%rcx
    bcee:	ba 00 00 00 00       	mov    $0x0,%edx
    bcf3:	48 89 c6             	mov    %rax,%rsi
    bcf6:	e8 9d f2 ff ff       	callq  af98 <memset_s>
        size_t heap_min_size = get_heap_min_size();
        memset_s(GET_PTR(void, enclave_base, g_global_data.heap_offset), heap_min_size, 0, heap_min_size);

        memset_s(GET_PTR(void, enclave_base, g_global_data.rsrv_offset), rsrv_mem_min_size, 0, rsrv_mem_min_size);
    bcfb:	48 8d 05 7e 14 00 00 	lea    0x147e(%rip),%rax        # d180 <g_global_data>
    bd02:	8b 80 28 01 00 00    	mov    0x128(%rax),%eax
    bd08:	89 c0                	mov    %eax,%eax
    bd0a:	48 c1 e0 05          	shl    $0x5,%rax
    bd0e:	48 89 c2             	mov    %rax,%rdx
        memset_s(GET_PTR(void, enclave_base, g_global_data.heap_offset), heap_min_size, 0, heap_min_size);
    bd11:	48 8d 05 68 14 00 00 	lea    0x1468(%rip),%rax        # d180 <g_global_data>
    bd18:	48 8d 80 30 01 00 00 	lea    0x130(%rax),%rax
    bd1f:	48 01 d0             	add    %rdx,%rax
    bd22:	ba 00 00 00 00       	mov    $0x0,%edx
    bd27:	48 89 c6             	mov    %rax,%rsi
    bd2a:	48 8d 05 4f 14 00 00 	lea    0x144f(%rip),%rax        # d180 <g_global_data>
    bd31:	48 8d b8 30 01 00 00 	lea    0x130(%rax),%rdi
    bd38:	e8 16 05 00 00       	callq  c253 <_ZL18add_static_threadsPVK9_layout_tS1_m>
        // save all the static threads into the thread table. These TCS would be trimmed in the uninit flow
    bd3d:	85 c0                	test   %eax,%eax
    bd3f:	0f 95 c0             	setne  %al
        memset_s(GET_PTR(void, enclave_base, g_global_data.heap_offset), heap_min_size, 0, heap_min_size);
    bd42:	84 c0                	test   %al,%al
    bd44:	0f 84 80 00 00 00    	je     bdca <do_init_enclave+0x21c>
        if (add_static_threads(
            &g_global_data.layout_table[0],
    bd4a:	b8 01 00 00 00       	mov    $0x1,%eax
    bd4f:	e9 85 00 00 00       	jmpq   bdd9 <do_init_enclave+0x22b>
            &g_global_data.layout_table[0] + g_global_data.layout_entry_num,
            0) != 0)
        {
            return SGX_ERROR_UNEXPECTED;
        }
    }
    bd54:	48 8d 05 25 14 00 00 	lea    0x1425(%rip),%rax        # d180 <g_global_data>
    bd5b:	48 8b 50 10          	mov    0x10(%rax),%rdx
    bd5f:	48 8d 05 1a 14 00 00 	lea    0x141a(%rip),%rax        # d180 <g_global_data>
    bd66:	48 8b 40 10          	mov    0x10(%rax),%rax
    bd6a:	48 8d 0d 0f 14 00 00 	lea    0x140f(%rip),%rcx        # d180 <g_global_data>
    bd71:	48 8b 71 08          	mov    0x8(%rcx),%rsi
    bd75:	48 8b 4d f0          	mov    -0x10(%rbp),%rcx
    bd79:	48 01 f1             	add    %rsi,%rcx
    bd7c:	48 89 cf             	mov    %rcx,%rdi
    bd7f:	48 89 d1             	mov    %rdx,%rcx
    bd82:	ba 00 00 00 00       	mov    $0x0,%edx
    bd87:	48 89 c6             	mov    %rax,%rsi
    bd8a:	e8 09 f2 ff ff       	callq  af98 <memset_s>
    else
    bd8f:	48 8d 05 ea 13 00 00 	lea    0x13ea(%rip),%rax        # d180 <g_global_data>
    bd96:	48 8b 50 20          	mov    0x20(%rax),%rdx
    bd9a:	48 8d 05 df 13 00 00 	lea    0x13df(%rip),%rax        # d180 <g_global_data>
    bda1:	48 8b 40 20          	mov    0x20(%rax),%rax
    bda5:	48 8d 0d d4 13 00 00 	lea    0x13d4(%rip),%rcx        # d180 <g_global_data>
    bdac:	48 8b 71 18          	mov    0x18(%rcx),%rsi
    bdb0:	48 8b 4d f0          	mov    -0x10(%rbp),%rcx
    bdb4:	48 01 f1             	add    %rsi,%rcx
    bdb7:	48 89 cf             	mov    %rcx,%rdi
    bdba:	48 89 d1             	mov    %rdx,%rcx
    bdbd:	ba 00 00 00 00       	mov    $0x0,%edx
    bdc2:	48 89 c6             	mov    %rax,%rsi
    bdc5:	e8 ce f1 ff ff       	callq  af98 <memset_s>
    {
        memset_s(GET_PTR(void, enclave_base, g_global_data.heap_offset), g_global_data.heap_size, 0, g_global_data.heap_size);
        memset_s(GET_PTR(void, enclave_base, g_global_data.rsrv_offset), g_global_data.rsrv_size, 0, g_global_data.rsrv_size);
    bdca:	c7 05 cc 52 00 00 02 	movl   $0x2,0x52cc(%rip)        # 110a0 <g_enclave_state>
    bdd1:	00 00 00 
    }
    bdd4:	b8 00 00 00 00       	mov    $0x0,%eax
#endif
    bdd9:	c9                   	leaveq 
    bdda:	c3                   	retq   

000000000000bddb <init_enclave>:
{
    bddb:	55                   	push   %rbp
    bddc:	48 89 e5             	mov    %rsp,%rbp
    bddf:	41 55                	push   %r13
    bde1:	41 54                	push   %r12
    bde3:	53                   	push   %rbx
    bde4:	48 81 ec 18 01 00 00 	sub    $0x118,%rsp
    bdeb:	48 89 bd d8 fe ff ff 	mov    %rdi,-0x128(%rbp)
    bdf2:	48 89 b5 d0 fe ff ff 	mov    %rsi,-0x130(%rbp)
    bdf9:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    be00:	00 00 
    be02:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    be06:	31 c0                	xor    %eax,%eax
    if(enclave_base == NULL || ms == NULL)
    be08:	48 83 bd d8 fe ff ff 	cmpq   $0x0,-0x128(%rbp)
    be0f:	00 
    be10:	74 0a                	je     be1c <init_enclave+0x41>
    be12:	48 83 bd d0 fe ff ff 	cmpq   $0x0,-0x130(%rbp)
    be19:	00 
    be1a:	75 0a                	jne    be26 <init_enclave+0x4b>
        return -1;
    be1c:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    be21:	e9 0b 04 00 00       	jmpq   c231 <init_enclave+0x456>
    if(NULL != pcl_entry)
    be26:	48 8b 05 bb 51 00 00 	mov    0x51bb(%rip),%rax        # 10fe8 <_Z9pcl_entryPvS_>
    be2d:	48 85 c0             	test   %rax,%rax
    be30:	74 67                	je     be99 <init_enclave+0xbe>
        sgx_lfence();
    be32:	0f ae e8             	lfence 
        system_features_t * csi = (system_features_t *)ms;
    be35:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    be3c:	48 89 85 08 ff ff ff 	mov    %rax,-0xf8(%rbp)
        if(NULL == csi->sealed_key)
    be43:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    be4a:	48 8b 80 94 00 00 00 	mov    0x94(%rax),%rax
    be51:	48 85 c0             	test   %rax,%rax
    be54:	75 0a                	jne    be60 <init_enclave+0x85>
            return -1;
    be56:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    be5b:	e9 d1 03 00 00       	jmpq   c231 <init_enclave+0x456>
        sgx_status_t ret = pcl_entry(enclave_base, csi->sealed_key);
    be60:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    be67:	48 8b 90 94 00 00 00 	mov    0x94(%rax),%rdx
    be6e:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    be75:	48 89 d6             	mov    %rdx,%rsi
    be78:	48 89 c7             	mov    %rax,%rdi
    be7b:	e8 90 51 ff ff       	callq  1010 <_Z9pcl_entryPvS_@plt>
    be80:	89 85 ec fe ff ff    	mov    %eax,-0x114(%rbp)
        if(SGX_SUCCESS != ret)
    be86:	83 bd ec fe ff ff 00 	cmpl   $0x0,-0x114(%rbp)
    be8d:	74 0a                	je     be99 <init_enclave+0xbe>
            return -1;
    be8f:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    be94:	e9 98 03 00 00       	jmpq   c231 <init_enclave+0x456>
    if(0 != relocate_enclave(enclave_base))
    be99:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    bea0:	48 89 c7             	mov    %rax,%rdi
    bea3:	e8 93 88 ff ff       	callq  473b <relocate_enclave>
    bea8:	85 c0                	test   %eax,%eax
    beaa:	0f 95 c0             	setne  %al
    bead:	84 c0                	test   %al,%al
    beaf:	74 0a                	je     bebb <init_enclave+0xe0>
        return -1;
    beb1:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    beb6:	e9 76 03 00 00       	jmpq   c231 <init_enclave+0x456>
    system_features_t *info = (system_features_t *)ms;
    bebb:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    bec2:	48 89 85 10 ff ff ff 	mov    %rax,-0xf0(%rbp)
    if(!sgx_is_outside_enclave(info, sizeof(system_features_t)))
    bec9:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    bed0:	be b0 00 00 00       	mov    $0xb0,%esi
    bed5:	48 89 c7             	mov    %rax,%rdi
    bed8:	e8 86 54 ff ff       	callq  1363 <sgx_is_outside_enclave>
    bedd:	85 c0                	test   %eax,%eax
    bedf:	0f 94 c0             	sete   %al
    bee2:	84 c0                	test   %al,%al
    bee4:	74 0a                	je     bef0 <init_enclave+0x115>
        return -1;
    bee6:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    beeb:	e9 41 03 00 00       	jmpq   c231 <init_enclave+0x456>
    sgx_lfence();
    bef0:	0f ae e8             	lfence 
    system_features_t sys_features = *info;
    bef3:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    befa:	48 8b 10             	mov    (%rax),%rdx
    befd:	48 8b 48 08          	mov    0x8(%rax),%rcx
    bf01:	48 89 95 20 ff ff ff 	mov    %rdx,-0xe0(%rbp)
    bf08:	48 89 8d 28 ff ff ff 	mov    %rcx,-0xd8(%rbp)
    bf0f:	48 8b 50 10          	mov    0x10(%rax),%rdx
    bf13:	48 8b 48 18          	mov    0x18(%rax),%rcx
    bf17:	48 89 95 30 ff ff ff 	mov    %rdx,-0xd0(%rbp)
    bf1e:	48 89 8d 38 ff ff ff 	mov    %rcx,-0xc8(%rbp)
    bf25:	48 8b 50 20          	mov    0x20(%rax),%rdx
    bf29:	48 8b 48 28          	mov    0x28(%rax),%rcx
    bf2d:	48 89 95 40 ff ff ff 	mov    %rdx,-0xc0(%rbp)
    bf34:	48 89 8d 48 ff ff ff 	mov    %rcx,-0xb8(%rbp)
    bf3b:	48 8b 50 30          	mov    0x30(%rax),%rdx
    bf3f:	48 8b 48 38          	mov    0x38(%rax),%rcx
    bf43:	48 89 95 50 ff ff ff 	mov    %rdx,-0xb0(%rbp)
    bf4a:	48 89 8d 58 ff ff ff 	mov    %rcx,-0xa8(%rbp)
    bf51:	48 8b 50 40          	mov    0x40(%rax),%rdx
    bf55:	48 8b 48 48          	mov    0x48(%rax),%rcx
    bf59:	48 89 95 60 ff ff ff 	mov    %rdx,-0xa0(%rbp)
    bf60:	48 89 8d 68 ff ff ff 	mov    %rcx,-0x98(%rbp)
    bf67:	48 8b 50 50          	mov    0x50(%rax),%rdx
    bf6b:	48 8b 48 58          	mov    0x58(%rax),%rcx
    bf6f:	48 89 95 70 ff ff ff 	mov    %rdx,-0x90(%rbp)
    bf76:	48 89 8d 78 ff ff ff 	mov    %rcx,-0x88(%rbp)
    bf7d:	48 8b 50 60          	mov    0x60(%rax),%rdx
    bf81:	48 8b 48 68          	mov    0x68(%rax),%rcx
    bf85:	48 89 55 80          	mov    %rdx,-0x80(%rbp)
    bf89:	48 89 4d 88          	mov    %rcx,-0x78(%rbp)
    bf8d:	48 8b 50 70          	mov    0x70(%rax),%rdx
    bf91:	48 8b 48 78          	mov    0x78(%rax),%rcx
    bf95:	48 89 55 90          	mov    %rdx,-0x70(%rbp)
    bf99:	48 89 4d 98          	mov    %rcx,-0x68(%rbp)
    bf9d:	48 8b 90 80 00 00 00 	mov    0x80(%rax),%rdx
    bfa4:	48 8b 88 88 00 00 00 	mov    0x88(%rax),%rcx
    bfab:	48 89 55 a0          	mov    %rdx,-0x60(%rbp)
    bfaf:	48 89 4d a8          	mov    %rcx,-0x58(%rbp)
    bfb3:	48 8b 90 90 00 00 00 	mov    0x90(%rax),%rdx
    bfba:	48 8b 88 98 00 00 00 	mov    0x98(%rax),%rcx
    bfc1:	48 89 55 b0          	mov    %rdx,-0x50(%rbp)
    bfc5:	48 89 4d b8          	mov    %rcx,-0x48(%rbp)
    bfc9:	48 8b 90 a8 00 00 00 	mov    0xa8(%rax),%rdx
    bfd0:	48 8b 80 a0 00 00 00 	mov    0xa0(%rax),%rax
    bfd7:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    bfdb:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
    size_t offset = 0;
    bfdf:	48 c7 85 f0 fe ff ff 	movq   $0x0,-0x110(%rbp)
    bfe6:	00 00 00 00 
    if(sys_features.system_feature_set[0] & (1ULL<< SYS_FEATURE_EXTEND))
    bfea:	48 8b 95 2c ff ff ff 	mov    -0xd4(%rbp),%rdx
    bff1:	48 b8 00 00 00 00 00 	movabs $0x4000000000000000,%rax
    bff8:	00 00 40 
    bffb:	48 21 d0             	and    %rdx,%rax
    bffe:	48 85 c0             	test   %rax,%rax
    c001:	74 1c                	je     c01f <init_enclave+0x244>
        offset = (sys_features.size < sizeof(sys_features)) ? sys_features.size : sizeof(sys_features);
    c003:	48 8b 45 bc          	mov    -0x44(%rbp),%rax
    c007:	ba b0 00 00 00       	mov    $0xb0,%edx
    c00c:	48 3d b0 00 00 00    	cmp    $0xb0,%rax
    c012:	48 0f 47 c2          	cmova  %rdx,%rax
    c016:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    c01d:	eb 0b                	jmp    c02a <init_enclave+0x24f>
        offset = offsetof(system_features_t, size);
    c01f:	48 c7 85 f0 fe ff ff 	movq   $0x9c,-0x110(%rbp)
    c026:	9c 00 00 00 
    for(size_t i = 0; i < sizeof(sys_features) - offset; i++)
    c02a:	48 c7 85 f8 fe ff ff 	movq   $0x0,-0x108(%rbp)
    c031:	00 00 00 00 
    c035:	b8 b0 00 00 00       	mov    $0xb0,%eax
    c03a:	48 2b 85 f0 fe ff ff 	sub    -0x110(%rbp),%rax
    c041:	48 39 85 f8 fe ff ff 	cmp    %rax,-0x108(%rbp)
    c048:	73 28                	jae    c072 <init_enclave+0x297>
        *((uint8_t *)&sys_features + offset + i) = 0;
    c04a:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    c051:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    c058:	48 01 c2             	add    %rax,%rdx
    c05b:	48 8d 85 20 ff ff ff 	lea    -0xe0(%rbp),%rax
    c062:	48 01 d0             	add    %rdx,%rax
    c065:	c6 00 00             	movb   $0x0,(%rax)
    for(size_t i = 0; i < sizeof(sys_features) - offset; i++)
    c068:	48 83 85 f8 fe ff ff 	addq   $0x1,-0x108(%rbp)
    c06f:	01 
    c070:	eb c3                	jmp    c035 <init_enclave+0x25a>
    g_cpu_core_num = sys_features.cpu_core_num;
    c072:	8b 45 cc             	mov    -0x34(%rbp),%eax
    c075:	89 05 8d 4d 00 00    	mov    %eax,0x4d8d(%rip)        # 10e08 <g_cpu_core_num>
    g_sdk_version = sys_features.version;
    c07b:	8b 85 28 ff ff ff    	mov    -0xd8(%rbp),%eax
    c081:	89 05 7d 4d 00 00    	mov    %eax,0x4d7d(%rip)        # 10e04 <g_sdk_version>
    if (g_sdk_version == SDK_VERSION_1_5)
    c087:	8b 05 77 4d 00 00    	mov    0x4d77(%rip),%eax        # 10e04 <g_sdk_version>
    c08d:	85 c0                	test   %eax,%eax
    c08f:	75 0c                	jne    c09d <init_enclave+0x2c2>
        EDMM_supported = 0;
    c091:	c7 05 65 4d 00 00 00 	movl   $0x0,0x4d65(%rip)        # 10e00 <EDMM_supported>
    c098:	00 00 00 
    c09b:	eb 34                	jmp    c0d1 <init_enclave+0x2f6>
    else if (g_sdk_version >= SDK_VERSION_2_0)
    c09d:	8b 05 61 4d 00 00    	mov    0x4d61(%rip),%eax        # 10e04 <g_sdk_version>
    c0a3:	85 c0                	test   %eax,%eax
    c0a5:	7e 20                	jle    c0c7 <init_enclave+0x2ec>
        EDMM_supported = feature_supported((const uint64_t *)sys_features.system_feature_set, 0);
    c0a7:	48 8d 85 20 ff ff ff 	lea    -0xe0(%rbp),%rax
    c0ae:	48 83 c0 0c          	add    $0xc,%rax
    c0b2:	be 00 00 00 00       	mov    $0x0,%esi
    c0b7:	48 89 c7             	mov    %rax,%rdi
    c0ba:	e8 7e 7a ff ff       	callq  3b3d <feature_supported>
    c0bf:	89 05 3b 4d 00 00    	mov    %eax,0x4d3b(%rip)        # 10e00 <EDMM_supported>
    c0c5:	eb 0a                	jmp    c0d1 <init_enclave+0x2f6>
        return -1;
    c0c7:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c0cc:	e9 60 01 00 00       	jmpq   c231 <init_enclave+0x456>
    if (heap_init(get_heap_base(), get_heap_size(), get_heap_min_size(), EDMM_supported) != SGX_SUCCESS)
    c0d1:	8b 1d 29 4d 00 00    	mov    0x4d29(%rip),%ebx        # 10e00 <EDMM_supported>
    c0d7:	e8 99 78 ff ff       	callq  3975 <get_heap_min_size>
    c0dc:	49 89 c5             	mov    %rax,%r13
    c0df:	e8 ff 77 ff ff       	callq  38e3 <get_heap_size>
    c0e4:	49 89 c4             	mov    %rax,%r12
    c0e7:	e8 dc 77 ff ff       	callq  38c8 <get_heap_base>
    c0ec:	89 d9                	mov    %ebx,%ecx
    c0ee:	4c 89 ea             	mov    %r13,%rdx
    c0f1:	4c 89 e6             	mov    %r12,%rsi
    c0f4:	48 89 c7             	mov    %rax,%rdi
    c0f7:	e8 19 ef ff ff       	callq  b015 <heap_init>
    c0fc:	85 c0                	test   %eax,%eax
    c0fe:	0f 95 c0             	setne  %al
    c101:	84 c0                	test   %al,%al
    c103:	74 0a                	je     c10f <init_enclave+0x334>
        return -1;
    c105:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c10a:	e9 22 01 00 00       	jmpq   c231 <init_enclave+0x456>
    memset_s(GET_PTR(void, enclave_base, g_global_data.heap_offset), g_global_data.heap_size, 0, g_global_data.heap_size);
    c10f:	e8 db 82 ff ff       	callq  43ef <get_xfeature_state>
    c114:	48 89 85 18 ff ff ff 	mov    %rax,-0xe8(%rbp)
    // xsave
    c11b:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    c122:	48 0d 00 18 00 1e    	or     $0x1e001800,%rax
    c128:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)

    c12f:	48 8b 95 2c ff ff ff 	mov    -0xd4(%rbp),%rdx
    c136:	48 b8 00 00 00 00 00 	movabs $0x4000000000000000,%rax
    c13d:	00 00 40 
    c140:	48 21 d0             	and    %rdx,%rax
    c143:	48 85 c0             	test   %rax,%rax
    c146:	74 0b                	je     c153 <init_enclave+0x378>

    c148:	48 8b 45 c4          	mov    -0x3c(%rbp),%rax
    c14c:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
        cpu_features = sys_features.cpu_features_ext;
    c153:	8b 05 ab 4c 00 00    	mov    0x4cab(%rip),%eax        # 10e04 <g_sdk_version>
    c159:	83 f8 01             	cmp    $0x1,%eax
    c15c:	7f 09                	jg     c167 <init_enclave+0x38c>
    c15e:	48 8b 45 bc          	mov    -0x44(%rbp),%rax
    c162:	48 85 c0             	test   %rax,%rax
    c165:	74 37                	je     c19e <init_enclave+0x3c3>

    c167:	48 8b 95 18 ff ff ff 	mov    -0xe8(%rbp),%rdx
    c16e:	48 8d 85 20 ff ff ff 	lea    -0xe0(%rbp),%rax
    c175:	48 8d 48 14          	lea    0x14(%rax),%rcx
    c179:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    c180:	48 89 ce             	mov    %rcx,%rsi
    c183:	48 89 c7             	mov    %rax,%rdi
    c186:	e8 93 50 ff ff       	callq  121e <init_optimized_libs>
    c18b:	85 c0                	test   %eax,%eax
    c18d:	0f 95 c0             	setne  %al
    c190:	84 c0                	test   %al,%al
    c192:	74 35                	je     c1c9 <init_enclave+0x3ee>
    if (SDK_VERSION_2_0 < g_sdk_version || sys_features.size != 0)
    c194:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c199:	e9 93 00 00 00       	jmpq   c231 <init_enclave+0x456>
        }
    c19e:	48 8b 95 18 ff ff ff 	mov    -0xe8(%rbp),%rdx
    c1a5:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    c1ac:	be 00 00 00 00       	mov    $0x0,%esi
    c1b1:	48 89 c7             	mov    %rax,%rdi
    c1b4:	e8 65 50 ff ff       	callq  121e <init_optimized_libs>
    c1b9:	85 c0                	test   %eax,%eax
    c1bb:	0f 95 c0             	setne  %al
    c1be:	84 c0                	test   %al,%al
    c1c0:	74 07                	je     c1c9 <init_enclave+0x3ee>
    else 
    c1c2:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c1c7:	eb 68                	jmp    c231 <init_enclave+0x456>
            return -1;
    c1c9:	e8 42 78 ff ff       	callq  3a10 <get_rsrv_size>
    c1ce:	48 85 c0             	test   %rax,%rax
    c1d1:	0f 95 c0             	setne  %al
    c1d4:	84 c0                	test   %al,%al
    c1d6:	74 33                	je     c20b <init_enclave+0x430>
    }
    c1d8:	e8 c5 78 ff ff       	callq  3aa2 <get_rsrv_min_size>
    c1dd:	49 89 c4             	mov    %rax,%r12
    c1e0:	e8 2b 78 ff ff       	callq  3a10 <get_rsrv_size>
    c1e5:	48 89 c3             	mov    %rax,%rbx
    c1e8:	e8 08 78 ff ff       	callq  39f5 <get_rsrv_base>
    c1ed:	4c 89 e2             	mov    %r12,%rdx
    c1f0:	48 89 de             	mov    %rbx,%rsi
    c1f3:	48 89 c7             	mov    %rax,%rdi
    c1f6:	e8 82 f3 ff ff       	callq  b57d <rsrv_mem_init>
    c1fb:	85 c0                	test   %eax,%eax
    c1fd:	0f 95 c0             	setne  %al
    c200:	84 c0                	test   %al,%al
    c202:	74 07                	je     c20b <init_enclave+0x430>

    c204:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c209:	eb 26                	jmp    c231 <init_enclave+0x456>
            return -1;
    c20b:	be 08 00 00 00       	mov    $0x8,%esi
    c210:	48 8d 3d f9 4b 00 00 	lea    0x4bf9(%rip),%rdi        # 10e10 <__intel_security_cookie>
    c217:	e8 7d 53 ff ff       	callq  1599 <sgx_read_rand>
    c21c:	85 c0                	test   %eax,%eax
    c21e:	0f 95 c0             	setne  %al
    c221:	84 c0                	test   %al,%al
    c223:	74 07                	je     c22c <init_enclave+0x451>
    
    c225:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c22a:	eb 05                	jmp    c231 <init_enclave+0x456>
    {
    c22c:	b8 00 00 00 00       	mov    $0x0,%eax
        return -1;
    c231:	48 8b 4d d8          	mov    -0x28(%rbp),%rcx
    c235:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    c23c:	00 00 
    c23e:	74 05                	je     c245 <init_enclave+0x46a>
    c240:	e8 63 90 ff ff       	callq  52a8 <__stack_chk_fail>
    c245:	48 81 c4 18 01 00 00 	add    $0x118,%rsp
    c24c:	5b                   	pop    %rbx
    c24d:	41 5c                	pop    %r12
    c24f:	41 5d                	pop    %r13
    c251:	5d                   	pop    %rbp
    c252:	c3                   	retq   

000000000000c253 <_ZL18add_static_threadsPVK9_layout_tS1_m>:
{
    c253:	55                   	push   %rbp
    c254:	48 89 e5             	mov    %rsp,%rbp
    c257:	53                   	push   %rbx
    c258:	48 83 ec 48          	sub    $0x48,%rsp
    c25c:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    c260:	48 89 75 c0          	mov    %rsi,-0x40(%rbp)
    c264:	48 89 55 b8          	mov    %rdx,-0x48(%rbp)
    int ret = -1;
    c268:	c7 45 d4 ff ff ff ff 	movl   $0xffffffff,-0x2c(%rbp)
    for (const volatile layout_t *layout = layout_start; layout < layout_end; layout++)
    c26f:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    c273:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    c277:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c27b:	48 3b 45 c0          	cmp    -0x40(%rbp),%rax
    c27f:	0f 83 1a 01 00 00    	jae    c39f <_ZL18add_static_threadsPVK9_layout_tS1_m+0x14c>
        if (!IS_GROUP_ID(layout->group.id) && (layout->entry.si_flags & SI_FLAGS_TCS) && layout->entry.attributes == (PAGE_ATTR_EADD | PAGE_ATTR_EEXTEND))
    c285:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c289:	0f b7 00             	movzwl (%rax),%eax
    c28c:	0f b7 c0             	movzwl %ax,%eax
    c28f:	25 00 10 00 00       	and    $0x1000,%eax
    c294:	85 c0                	test   %eax,%eax
    c296:	75 27                	jne    c2bf <_ZL18add_static_threadsPVK9_layout_tS1_m+0x6c>
    c298:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c29c:	48 8b 40 18          	mov    0x18(%rax),%rax
    c2a0:	25 00 01 00 00       	and    $0x100,%eax
    c2a5:	48 85 c0             	test   %rax,%rax
    c2a8:	74 15                	je     c2bf <_ZL18add_static_threadsPVK9_layout_tS1_m+0x6c>
    c2aa:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c2ae:	0f b7 40 02          	movzwl 0x2(%rax),%eax
    c2b2:	66 83 f8 03          	cmp    $0x3,%ax
    c2b6:	75 07                	jne    c2bf <_ZL18add_static_threadsPVK9_layout_tS1_m+0x6c>
    c2b8:	b8 01 00 00 00       	mov    $0x1,%eax
    c2bd:	eb 05                	jmp    c2c4 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x71>
    c2bf:	b8 00 00 00 00       	mov    $0x0,%eax
    c2c4:	84 c0                	test   %al,%al
    c2c6:	74 3f                	je     c307 <_ZL18add_static_threadsPVK9_layout_tS1_m+0xb4>
            uintptr_t tcs_addr = (uintptr_t)layout->entry.rva + offset + (uintptr_t)get_enclave_base();
    c2c8:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c2cc:	48 8b 50 08          	mov    0x8(%rax),%rdx
    c2d0:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    c2d4:	48 8d 1c 02          	lea    (%rdx,%rax,1),%rbx
    c2d8:	e8 55 03 00 00       	callq  c632 <get_enclave_base>
    c2dd:	48 01 d8             	add    %rbx,%rax
    c2e0:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
            if (do_save_tcs(reinterpret_cast<void *>(tcs_addr)) != SGX_SUCCESS)
    c2e4:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    c2e8:	48 89 c7             	mov    %rax,%rdi
    c2eb:	e8 69 65 ff ff       	callq  2859 <_Z11do_save_tcsPv>
    c2f0:	85 c0                	test   %eax,%eax
    c2f2:	0f 95 c0             	setne  %al
    c2f5:	84 c0                	test   %al,%al
    c2f7:	0f 84 98 00 00 00    	je     c395 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x142>
		    return (-1);
    c2fd:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c302:	e9 9d 00 00 00       	jmpq   c3a4 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x151>
        else if (IS_GROUP_ID(layout->group.id)){
    c307:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c30b:	0f b7 00             	movzwl (%rax),%eax
    c30e:	0f b7 c0             	movzwl %ax,%eax
    c311:	25 00 10 00 00       	and    $0x1000,%eax
    c316:	85 c0                	test   %eax,%eax
    c318:	0f 95 c0             	setne  %al
    c31b:	84 c0                	test   %al,%al
    c31d:	74 76                	je     c395 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x142>
            size_t step = 0;
    c31f:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    c326:	00 
            for(uint32_t j = 0; j < layout->group.load_times; j++)
    c327:	c7 45 d0 00 00 00 00 	movl   $0x0,-0x30(%rbp)
    c32e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c332:	8b 40 04             	mov    0x4(%rax),%eax
    c335:	39 45 d0             	cmp    %eax,-0x30(%rbp)
    c338:	0f 92 c0             	setb   %al
    c33b:	84 c0                	test   %al,%al
    c33d:	74 56                	je     c395 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x142>
                step += (size_t)layout->group.load_step;
    c33f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c343:	48 8b 40 08          	mov    0x8(%rax),%rax
    c347:	48 01 45 e0          	add    %rax,-0x20(%rbp)
                if(0 != (ret = add_static_threads(&layout[-layout->group.entry_count], layout, step)))
    c34b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c34f:	0f b7 40 02          	movzwl 0x2(%rax),%eax
    c353:	0f b7 c0             	movzwl %ax,%eax
    c356:	f7 d8                	neg    %eax
    c358:	48 98                	cltq   
    c35a:	48 c1 e0 05          	shl    $0x5,%rax
    c35e:	48 89 c2             	mov    %rax,%rdx
    c361:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c365:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
    c369:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    c36d:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c371:	48 89 c6             	mov    %rax,%rsi
    c374:	48 89 cf             	mov    %rcx,%rdi
    c377:	e8 d7 fe ff ff       	callq  c253 <_ZL18add_static_threadsPVK9_layout_tS1_m>
    c37c:	89 45 d4             	mov    %eax,-0x2c(%rbp)
    c37f:	83 7d d4 00          	cmpl   $0x0,-0x2c(%rbp)
    c383:	0f 95 c0             	setne  %al
    c386:	84 c0                	test   %al,%al
    c388:	74 05                	je     c38f <_ZL18add_static_threadsPVK9_layout_tS1_m+0x13c>
                    return ret;
    c38a:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    c38d:	eb 15                	jmp    c3a4 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x151>
            for(uint32_t j = 0; j < layout->group.load_times; j++)
    c38f:	83 45 d0 01          	addl   $0x1,-0x30(%rbp)
    c393:	eb 99                	jmp    c32e <_ZL18add_static_threadsPVK9_layout_tS1_m+0xdb>
    for (const volatile layout_t *layout = layout_start; layout < layout_end; layout++)
    c395:	48 83 45 d8 20       	addq   $0x20,-0x28(%rbp)
    c39a:	e9 d8 fe ff ff       	jmpq   c277 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x24>
    return 0;
    c39f:	b8 00 00 00 00       	mov    $0x0,%eax
}
    c3a4:	48 83 c4 48          	add    $0x48,%rsp
    c3a8:	5b                   	pop    %rbx
    c3a9:	5d                   	pop    %rbp
    c3aa:	c3                   	retq   

000000000000c3ab <sgx_is_enclave_crashed>:
{
    c3ab:	55                   	push   %rbp
    c3ac:	48 89 e5             	mov    %rsp,%rbp
    return get_enclave_state() == ENCLAVE_CRASHED;
    c3af:	e8 86 02 00 00       	callq  c63a <get_enclave_state>
    c3b4:	83 f8 03             	cmp    $0x3,%eax
    c3b7:	0f 94 c0             	sete   %al
    c3ba:	0f b6 c0             	movzbl %al,%eax
}
    c3bd:	5d                   	pop    %rbp
    c3be:	c3                   	retq   

000000000000c3bf <_ZL16init_stack_guardPv>:
#include "global_data.h"
#include "trts_internal.h"
#include "internal/rts.h"

static void __attribute__((section(".nipx"))) init_stack_guard(void *tcs)
{
    c3bf:	55                   	push   %rbp
    c3c0:	48 89 e5             	mov    %rsp,%rbp
    c3c3:	48 83 ec 20          	sub    $0x20,%rsp
    c3c7:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    thread_data_t *thread_data = get_thread_data();
    c3cb:	e8 9d 02 00 00       	callq  c66d <get_thread_data>
    c3d0:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if( (NULL == thread_data) || ((thread_data->stack_base_addr == thread_data->last_sp) && (0 != g_global_data.thread_policy)))
    c3d4:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    c3d9:	74 25                	je     c400 <_ZL16init_stack_guardPv+0x41>
    c3db:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    c3df:	48 8b 50 10          	mov    0x10(%rax),%rdx
    c3e3:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    c3e7:	48 8b 40 08          	mov    0x8(%rax),%rax
    c3eb:	48 39 c2             	cmp    %rax,%rdx
    c3ee:	75 17                	jne    c407 <_ZL16init_stack_guardPv+0x48>
    c3f0:	48 8d 05 89 0d 00 00 	lea    0xd89(%rip),%rax        # d180 <g_global_data>
    c3f7:	48 8b 40 30          	mov    0x30(%rax),%rax
    c3fb:	48 85 c0             	test   %rax,%rax
    c3fe:	74 07                	je     c407 <_ZL16init_stack_guardPv+0x48>
    c400:	b8 01 00 00 00       	mov    $0x1,%eax
    c405:	eb 05                	jmp    c40c <_ZL16init_stack_guardPv+0x4d>
    c407:	b8 00 00 00 00       	mov    $0x0,%eax
    c40c:	84 c0                	test   %al,%al
    c40e:	74 71                	je     c481 <_ZL16init_stack_guardPv+0xc2>
    {
         thread_data = GET_PTR(thread_data_t, tcs, g_global_data.td_template.self_addr);
    c410:	48 8d 05 69 0d 00 00 	lea    0xd69(%rip),%rax        # d180 <g_global_data>
    c417:	48 8b 50 40          	mov    0x40(%rax),%rdx
    c41b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    c41f:	48 01 d0             	add    %rdx,%rax
    c422:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    else
    {
        return;
    }

    assert(thread_data != NULL);
    c426:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    c42b:	75 1f                	jne    c44c <_ZL16init_stack_guardPv+0x8d>
    c42d:	48 8d 0d 03 0c 00 00 	lea    0xc03(%rip),%rcx        # d037 <_ZZ14trim_EPC_pagesE8__func__+0xf>
    c434:	48 8d 15 25 0c 00 00 	lea    0xc25(%rip),%rdx        # d060 <_ZZL16init_stack_guardPvE8__func__>
    c43b:	be 3f 00 00 00       	mov    $0x3f,%esi
    c440:	48 8d 3d 04 0c 00 00 	lea    0xc04(%rip),%rdi        # d04b <_ZZ14trim_EPC_pagesE8__func__+0x23>
    c447:	e8 65 8e ff ff       	callq  52b1 <__assert>

    size_t tmp_stack_guard = 0;
    c44c:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
    c453:	00 
    if (SGX_SUCCESS != sgx_read_rand(
    c454:	48 8d 45 f0          	lea    -0x10(%rbp),%rax
    c458:	be 08 00 00 00       	mov    $0x8,%esi
    c45d:	48 89 c7             	mov    %rax,%rdi
    c460:	e8 34 51 ff ff       	callq  1599 <sgx_read_rand>
    c465:	85 c0                	test   %eax,%eax
    c467:	0f 95 c0             	setne  %al
    c46a:	84 c0                	test   %al,%al
    c46c:	74 05                	je     c473 <_ZL16init_stack_guardPv+0xb4>
                (unsigned char*)&tmp_stack_guard,
                sizeof(tmp_stack_guard)))
        abort();
    c46e:	e8 29 05 00 00       	callq  c99c <abort>

    thread_data->stack_guard = tmp_stack_guard;
    c473:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    c477:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    c47b:	48 89 50 28          	mov    %rdx,0x28(%rax)
    c47f:	eb 01                	jmp    c482 <_ZL16init_stack_guardPv+0xc3>
        return;
    c481:	90                   	nop
}
    c482:	c9                   	leaveq 
    c483:	c3                   	retq   

000000000000c484 <enter_enclave>:

extern "C" int enter_enclave(int index, void *ms, void *tcs, int cssa) __attribute__((section(".nipx")));

extern "C" int enter_enclave(int index, void *ms, void *tcs, int cssa)
{
    c484:	55                   	push   %rbp
    c485:	48 89 e5             	mov    %rsp,%rbp
    c488:	48 83 ec 30          	sub    $0x30,%rsp
    c48c:	89 7d ec             	mov    %edi,-0x14(%rbp)
    c48f:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    c493:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    c497:	89 4d e8             	mov    %ecx,-0x18(%rbp)
    sgx_status_t error = SGX_ERROR_UNEXPECTED;
    c49a:	c7 45 fc 01 00 00 00 	movl   $0x1,-0x4(%rbp)

    if(sgx_is_enclave_crashed())
    c4a1:	e8 05 ff ff ff       	callq  c3ab <sgx_is_enclave_crashed>
    c4a6:	85 c0                	test   %eax,%eax
    c4a8:	0f 95 c0             	setne  %al
    c4ab:	84 c0                	test   %al,%al
    c4ad:	74 0a                	je     c4b9 <enter_enclave+0x35>
    {
        return SGX_ERROR_ENCLAVE_CRASHED;
    c4af:	b8 06 10 00 00       	mov    $0x1006,%eax
    c4b4:	e9 1e 01 00 00       	jmpq   c5d7 <enter_enclave+0x153>
    }
    if((ECMD_INIT_ENCLAVE != index) && (ENCLAVE_INIT_DONE != get_enclave_state()))
    c4b9:	83 7d ec ff          	cmpl   $0xffffffff,-0x14(%rbp)
    c4bd:	74 11                	je     c4d0 <enter_enclave+0x4c>
    c4bf:	e8 76 01 00 00       	callq  c63a <get_enclave_state>
    c4c4:	83 f8 02             	cmp    $0x2,%eax
    c4c7:	74 07                	je     c4d0 <enter_enclave+0x4c>
    c4c9:	b8 01 00 00 00       	mov    $0x1,%eax
    c4ce:	eb 05                	jmp    c4d5 <enter_enclave+0x51>
    c4d0:	b8 00 00 00 00       	mov    $0x0,%eax
    c4d5:	84 c0                	test   %al,%al
    c4d7:	74 12                	je     c4eb <enter_enclave+0x67>
    {
        set_enclave_state(ENCLAVE_CRASHED);
    c4d9:	bf 03 00 00 00       	mov    $0x3,%edi
    c4de:	e8 64 01 00 00       	callq  c647 <set_enclave_state>
        return error;
    c4e3:	8b 45 fc             	mov    -0x4(%rbp),%eax
    c4e6:	e9 ec 00 00 00       	jmpq   c5d7 <enter_enclave+0x153>
    }

    if(cssa == 0)
    c4eb:	83 7d e8 00          	cmpl   $0x0,-0x18(%rbp)
    c4ef:	0f 85 98 00 00 00    	jne    c58d <enter_enclave+0x109>
    {
        if((index >= 0) || (index == ECMD_ECALL_PTHREAD))
    c4f5:	83 7d ec 00          	cmpl   $0x0,-0x14(%rbp)
    c4f9:	79 06                	jns    c501 <enter_enclave+0x7d>
    c4fb:	83 7d ec fa          	cmpl   $0xfffffffa,-0x14(%rbp)
    c4ff:	75 29                	jne    c52a <enter_enclave+0xa6>
        {
            // Initialize stack guard if necessary
            init_stack_guard(tcs);
    c501:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c505:	48 89 c7             	mov    %rax,%rdi
    c508:	e8 b2 fe ff ff       	callq  c3bf <_ZL16init_stack_guardPv>
            error = do_ecall(index, ms, tcs);
    c50d:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    c511:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    c515:	8b 45 ec             	mov    -0x14(%rbp),%eax
    c518:	48 89 ce             	mov    %rcx,%rsi
    c51b:	89 c7                	mov    %eax,%edi
    c51d:	e8 59 69 ff ff       	callq  2e7b <do_ecall>
    c522:	89 45 fc             	mov    %eax,-0x4(%rbp)
    c525:	e9 9a 00 00 00       	jmpq   c5c4 <enter_enclave+0x140>
        }
        else if(index == ECMD_INIT_ENCLAVE)
    c52a:	83 7d ec ff          	cmpl   $0xffffffff,-0x14(%rbp)
    c52e:	75 18                	jne    c548 <enter_enclave+0xc4>
        {
            error = do_init_enclave(ms, tcs);
    c530:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    c534:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    c538:	48 89 d6             	mov    %rdx,%rsi
    c53b:	48 89 c7             	mov    %rax,%rdi
    c53e:	e8 6b f6 ff ff       	callq  bbae <do_init_enclave>
    c543:	89 45 fc             	mov    %eax,-0x4(%rbp)
    c546:	eb 7c                	jmp    c5c4 <enter_enclave+0x140>
        }
        else if(index == ECMD_ORET)
    c548:	83 7d ec fe          	cmpl   $0xfffffffe,-0x14(%rbp)
    c54c:	75 11                	jne    c55f <enter_enclave+0xdb>
        {
            error = do_oret(ms);
    c54e:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    c552:	48 89 c7             	mov    %rax,%rdi
    c555:	e8 a0 71 ff ff       	callq  36fa <do_oret>
    c55a:	89 45 fc             	mov    %eax,-0x4(%rbp)
    c55d:	eb 65                	jmp    c5c4 <enter_enclave+0x140>
        }
        else if(index == ECMD_MKTCS)
    c55f:	83 7d ec fc          	cmpl   $0xfffffffc,-0x14(%rbp)
    c563:	75 11                	jne    c576 <enter_enclave+0xf2>
        {
            error = do_ecall_add_thread(ms);
    c565:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    c569:	48 89 c7             	mov    %rax,%rdi
    c56c:	e8 ec 6a ff ff       	callq  305d <do_ecall_add_thread>
    c571:	89 45 fc             	mov    %eax,-0x4(%rbp)
    c574:	eb 4e                	jmp    c5c4 <enter_enclave+0x140>
        }
        else if(index == ECMD_UNINIT_ENCLAVE)
    c576:	83 7d ec fb          	cmpl   $0xfffffffb,-0x14(%rbp)
    c57a:	75 48                	jne    c5c4 <enter_enclave+0x140>
        {
            error = do_uninit_enclave(tcs);
    c57c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c580:	48 89 c7             	mov    %rax,%rdi
    c583:	e8 99 6b ff ff       	callq  3121 <do_uninit_enclave>
    c588:	89 45 fc             	mov    %eax,-0x4(%rbp)
    c58b:	eb 37                	jmp    c5c4 <enter_enclave+0x140>
        }
    }
    else if((cssa == 1) && (index == ECMD_EXCEPT))
    c58d:	83 7d e8 01          	cmpl   $0x1,-0x18(%rbp)
    c591:	75 31                	jne    c5c4 <enter_enclave+0x140>
    c593:	83 7d ec fd          	cmpl   $0xfffffffd,-0x14(%rbp)
    c597:	75 2b                	jne    c5c4 <enter_enclave+0x140>
    {
        error = trts_handle_exception(tcs);
    c599:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c59d:	48 89 c7             	mov    %rax,%rdi
    c5a0:	e8 63 79 ff ff       	callq  3f08 <trts_handle_exception>
    c5a5:	89 45 fc             	mov    %eax,-0x4(%rbp)
        if (check_static_stack_canary(tcs) != 0)
    c5a8:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c5ac:	48 89 c7             	mov    %rax,%rdi
    c5af:	e8 fe 50 ff ff       	callq  16b2 <check_static_stack_canary>
    c5b4:	85 c0                	test   %eax,%eax
    c5b6:	0f 95 c0             	setne  %al
    c5b9:	84 c0                	test   %al,%al
    c5bb:	74 07                	je     c5c4 <enter_enclave+0x140>
        {
            error = SGX_ERROR_STACK_OVERRUN;
    c5bd:	c7 45 fc 09 10 00 00 	movl   $0x1009,-0x4(%rbp)
        }
    }
    if(error == SGX_ERROR_UNEXPECTED)
    c5c4:	83 7d fc 01          	cmpl   $0x1,-0x4(%rbp)
    c5c8:	75 0a                	jne    c5d4 <enter_enclave+0x150>
    {
        set_enclave_state(ENCLAVE_CRASHED);
    c5ca:	bf 03 00 00 00       	mov    $0x3,%edi
    c5cf:	e8 73 00 00 00       	callq  c647 <set_enclave_state>
    }
    return error;
    c5d4:	8b 45 fc             	mov    -0x4(%rbp),%eax
}
    c5d7:	c9                   	leaveq 
    c5d8:	c3                   	retq   

000000000000c5d9 <restore_xregs>:
DECLARE_LOCAL_FUNC restore_xregs
#if defined(LINUX32)
    mov     SE_WORDSIZE(%esp), %ecx
    lea     g_xsave_enabled, %eax
#else
    mov     %rdi, %rcx
    c5d9:	48 89 f9             	mov    %rdi,%rcx
    lea_pic g_xsave_enabled, %rax
    c5dc:	48 8d 05 c1 4a 00 00 	lea    0x4ac1(%rip),%rax        # 110a4 <g_xsave_enabled>
#endif
    movl    (%xax), %eax
    c5e3:	8b 00                	mov    (%rax),%eax
    cmpl    $0, %eax
    c5e5:	83 f8 00             	cmp    $0x0,%eax
    jz      1f
    c5e8:	74 16                	je     c600 <restore_xregs+0x27>
    SET_XSAVE_MASK
    c5ea:	48 31 c0             	xor    %rax,%rax
    c5ed:	48 31 d2             	xor    %rdx,%rdx
    c5f0:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c5f5:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    c5fa:	48 0f ae 29          	xrstor64 (%rcx)
    DO_XRSTOR
    jmp     2f
    c5fe:	eb 04                	jmp    c604 <restore_xregs+0x2b>
    c600:	48 0f ae 09          	fxrstor64 (%rcx)
1:
    DO_FXRSTOR
2:
    ret
    c604:	c3                   	retq   

000000000000c605 <save_xregs>:
DECLARE_LOCAL_FUNC save_xregs
#if defined(LINUX32)
    mov     SE_WORDSIZE(%esp), %ecx
    lea     g_xsave_enabled, %eax
#else
    mov     %rdi, %rcx
    c605:	48 89 f9             	mov    %rdi,%rcx
    lea_pic g_xsave_enabled, %rax
    c608:	48 8d 05 95 4a 00 00 	lea    0x4a95(%rip),%rax        # 110a4 <g_xsave_enabled>
#endif
    fwait
    c60f:	9b                   	fwait
    movl    (%xax), %eax
    c610:	8b 00                	mov    (%rax),%eax
    cmpl    $0, %eax
    c612:	83 f8 00             	cmp    $0x0,%eax
    jz      1f
    c615:	74 16                	je     c62d <save_xregs+0x28>
    SET_XSAVE_MASK
    c617:	48 31 c0             	xor    %rax,%rax
    c61a:	48 31 d2             	xor    %rdx,%rdx
    c61d:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c622:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    c627:	48 0f c7 21          	xsavec64 (%rcx)
    DO_XSAVEC
    jmp     2f
    c62b:	eb 04                	jmp    c631 <save_xregs+0x2c>
    c62d:	48 0f ae 01          	fxsave64 (%rcx)
1:
    DO_FXSAVE
2:
    ret
    c631:	c3                   	retq   

000000000000c632 <get_enclave_base>:

    /* .text */
    .section .nipx,"ax",@progbits

DECLARE_LOCAL_FUNC get_enclave_base
    lea_pic __ImageBase, %xax
    c632:	48 8d 05 c7 39 ff ff 	lea    -0xc639(%rip),%rax        # 0 <enclave.so>
    ret
    c639:	c3                   	retq   

000000000000c63a <get_enclave_state>:
DECLARE_LOCAL_FUNC get_enclave_state
    lea_pic g_enclave_state, %xcx
    c63a:	48 8d 0d 5f 4a 00 00 	lea    0x4a5f(%rip),%rcx        # 110a0 <g_enclave_state>
    xor     %xax, %xax
    c641:	48 31 c0             	xor    %rax,%rax
    movl    (%xcx), %eax
    c644:	8b 01                	mov    (%rcx),%eax
    ret
    c646:	c3                   	retq   

000000000000c647 <set_enclave_state>:
DECLARE_LOCAL_FUNC set_enclave_state
    lea_pic g_enclave_state, %xax
    c647:	48 8d 05 52 4a 00 00 	lea    0x4a52(%rip),%rax        # 110a0 <g_enclave_state>
#ifdef LINUX32
    mov     SE_WORDSIZE(%esp), %edi
#endif
    movl    %edi, (%xax)
    c64e:	89 38                	mov    %edi,(%rax)
    ret
    c650:	c3                   	retq   

000000000000c651 <lock_enclave>:

DECLARE_LOCAL_FUNC lock_enclave
    lea_pic g_enclave_state, %xdx
    c651:	48 8d 15 48 4a 00 00 	lea    0x4a48(%rip),%rdx        # 110a0 <g_enclave_state>
    xor     %xax, %xax
    c658:	48 31 c0             	xor    %rax,%rax
    mov     $ENCLAVE_INIT_NOT_STARTED, %eax
    c65b:	b8 00 00 00 00       	mov    $0x0,%eax
    xor     %xcx, %xcx
    c660:	48 31 c9             	xor    %rcx,%rcx
    mov     $ENCLAVE_INIT_IN_PROGRESS, %ecx     /* if (g_global_data.enclave_state == ENCLAVE_INIT_NOT_STARTED) */
    c663:	b9 01 00 00 00       	mov    $0x1,%ecx
    lock cmpxchgl %ecx, (%xdx)                  /*   g_global_data.enclave_state == ENCLAVE_INIT_IN_PROGRESS */
    c668:	f0 0f b1 0a          	lock cmpxchg %ecx,(%rdx)
    ret                                         /* xax: the initial value of enclave state */
    c66c:	c3                   	retq   

000000000000c66d <get_thread_data>:
 *
 *     Get the address of thread_data
 * ---------------------------------------------------------------------
 */
DECLARE_LOCAL_FUNC get_thread_data
    READ_TD_DATA self_addr 
    c66d:	65 48 8b 04 25 00 00 	mov    %gs:0x0,%rax
    c674:	00 00 
    ret
    c676:	c3                   	retq   

000000000000c677 <get_stack_guard>:
 *
 *     Get the value of stack_guard
 * ---------------------------------------------------------------------
 */
DECLARE_LOCAL_FUNC get_stack_guard 
    READ_TD_DATA stack_guard 
    c677:	65 48 8b 04 25 28 00 	mov    %gs:0x28,%rax
    c67e:	00 00 
    ret
    c680:	c3                   	retq   

000000000000c681 <enclave_entry>:
 * ----------------------------------------------------------------------
 */
    .cfi_startproc

    /* Clear unused general registers */
    xor     %xdx, %xdx
    c681:	48 31 d2             	xor    %rdx,%rdx
    add     %xdx, %xdx          /* OF = SF = AF = CF = 0; ZF = PF = 1 */
    c684:	48 01 d2             	add    %rdx,%rdx
    cld                         /* DF = 0 */
    c687:	fc                   	cld    
#if defined(LINUX64)
    xor     %r8, %r8
    c688:	4d 31 c0             	xor    %r8,%r8
    xor     %r9, %r9
    c68b:	4d 31 c9             	xor    %r9,%r9
    xor     %r10, %r10
    c68e:	4d 31 d2             	xor    %r10,%r10
    xor     %r11, %r11
    c691:	4d 31 db             	xor    %r11,%r11
    xor     %r12, %r12
    c694:	4d 31 e4             	xor    %r12,%r12
    xor     %r13, %r13
    c697:	4d 31 ed             	xor    %r13,%r13
    xor     %r14, %r14
    c69a:	4d 31 f6             	xor    %r14,%r14
    xor     %r15, %r15
    c69d:	4d 31 ff             	xor    %r15,%r15
#endif

    /* switch to trusted stack */
    cmp     $0, %xax
    c6a0:	48 83 f8 00          	cmp    $0x0,%rax
    jne     .Ldo_handler                /* handle exception state */
    c6a4:	0f 85 cb 00 00 00    	jne    c775 <enclave_entry+0xf4>
    /* xor     %xdx, %xdx                  xdx is cssa, make sure it is 0 */
    READ_TD_DATA last_sp
    c6aa:	65 48 8b 04 25 08 00 	mov    %gs:0x8,%rax
    c6b1:	00 00 
    cmp     $0, %xax
    c6b3:	48 83 f8 00          	cmp    $0x0,%rax
    jne .Lswitch_stack
    c6b7:	75 0f                	jne    c6c8 <enclave_entry+0x47>
    GET_STACK_BASE  %xbx                /* if last_sp == 0, set sp to stack base */
    c6b9:	48 89 d8             	mov    %rbx,%rax
    c6bc:	48 2d 00 00 01 00    	sub    $0x10000,%rax
    sub     $STATIC_STACK_SIZE, %xax    /* give space for static stack */
    c6c2:	48 2d b0 02 00 00    	sub    $0x2b0,%rax
.Lswitch_stack:
    xchg    %xsp, %xax
    c6c8:	48 94                	xchg   %rax,%rsp
    push    %xcx
    c6ca:	51                   	push   %rcx
    push    %xbp
    c6cb:	55                   	push   %rbp

    .cfi_def_cfa_offset   2 * SE_WORDSIZE
    .cfi_offset           xbp, -2 * SE_WORDSIZE
    mov     %xsp, %xbp
    c6cc:	48 89 e5             	mov    %rsp,%rbp
    .cfi_def_cfa_register xbp

    CLEAN_XFLAGS
    c6cf:	9c                   	pushfq 
    c6d0:	48 f7 14 24          	notq   (%rsp)
    c6d4:	48 81 0c 24 00 00 04 	orq    $0x40000,(%rsp)
    c6db:	00 
    c6dc:	48 f7 14 24          	notq   (%rsp)
    c6e0:	9d                   	popfq  


    /* Save the registers */
    sub     $(6*SE_WORDSIZE), %xsp
    c6e1:	48 83 ec 30          	sub    $0x30,%rsp
    mov     %xax, -1*SE_WORDSIZE(%xbp)  /* xsp_u */
    c6e5:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    mov     %xdx, -3*SE_WORDSIZE(%xbp)  /* cssa */
    c6e9:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    mov     %xbx, -4*SE_WORDSIZE(%xbp)  /* TCS */
    c6ed:	48 89 5d e0          	mov    %rbx,-0x20(%rbp)
    mov     %xsi, -5*SE_WORDSIZE(%xbp)  /* XSI */
    c6f1:	48 89 75 d8          	mov    %rsi,-0x28(%rbp)
    mov     %xdi, -6*SE_WORDSIZE(%xbp)  /* XDI */
    c6f5:	48 89 7d d0          	mov    %rdi,-0x30(%rbp)

    /* clean extended feature registers */
    sub     $(4*SE_WORDSIZE), %xsp
    c6f9:	48 83 ec 20          	sub    $0x20,%rsp

    lea_pic SYNTHETIC_STATE, %xdi
    c6fd:	48 8d 3d fc 10 00 00 	lea    0x10fc(%rip),%rdi        # d800 <SYNTHETIC_STATE>
#ifdef LINUX32
    mov     %xdi, (%xsp)
#endif
    call    restore_xregs
    c704:	e8 d0 fe ff ff       	callq  c5d9 <restore_xregs>
    add     $(4*SE_WORDSIZE), %xsp
    c709:	48 83 c4 20          	add    $0x20,%rsp

    /* switch to C code */
#ifdef LINUX64
    mov     -6*SE_WORDSIZE(%xbp), %xdi  /* index */
    c70d:	48 8b 7d d0          	mov    -0x30(%rbp),%rdi
    mov     -5*SE_WORDSIZE(%xbp), %xsi  /* ms */
    c711:	48 8b 75 d8          	mov    -0x28(%rbp),%rsi
    mov     -4*SE_WORDSIZE(%xbp), %xdx  /* TCS */
    c715:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    mov     -3*SE_WORDSIZE(%xbp), %xcx  /* cssa */
    c719:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
#endif
    call    enter_enclave
    c71d:	e8 62 fd ff ff       	callq  c484 <enter_enclave>
    mov     %xax, %xbx
    c722:	48 89 c3             	mov    %rax,%rbx

.Lexit_enclave:
/* clean extended feature registers */
    lea_pic SYNTHETIC_STATE, %xdi
    c725:	48 8d 3d d4 10 00 00 	lea    0x10d4(%rip),%rdi        # d800 <SYNTHETIC_STATE>
#ifdef LINUX32
    mov     %xdi, (%xsp)
#endif
    call    restore_xregs
    c72c:	e8 a8 fe ff ff       	callq  c5d9 <restore_xregs>

/* set xdi and xsi */
    mov     $OCMD_ERET, %xdi
    c731:	48 c7 c7 ff ff ff ff 	mov    $0xffffffffffffffff,%rdi
    mov     %xbx, %xsi
    c738:	48 89 de             	mov    %rbx,%rsi

/* restore stack */
    mov     -1*SE_WORDSIZE(%xbp), %xdx  /* xdx: xsp_u  */
    c73b:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    mov     %xbp, %xsp
    c73f:	48 89 ec             	mov    %rbp,%rsp
    pop     %xbp                        /* xbp_u */
    c742:	5d                   	pop    %rbp
    pop     %xbx                        /* ret_u */
    c743:	5b                   	pop    %rbx
    mov     %xdx, %xsp                  /* xsp_u */
    c744:	48 89 d4             	mov    %rdx,%rsp

.Lclear_and_exit_enclave:
    /* Clear all GPRs, except xax, xbx, xdi and xsi */
    xor     %xcx, %xcx
    c747:	48 31 c9             	xor    %rcx,%rcx
    xor     %xdx, %xdx
    c74a:	48 31 d2             	xor    %rdx,%rdx
#if defined(LINUX64)
    xor     %r8, %r8
    c74d:	4d 31 c0             	xor    %r8,%r8
    xor     %r9, %r9
    c750:	4d 31 c9             	xor    %r9,%r9
    xor     %r10, %r10
    c753:	4d 31 d2             	xor    %r10,%r10
    xor     %r11, %r11
    c756:	4d 31 db             	xor    %r11,%r11
    xor     %r12, %r12
    c759:	4d 31 e4             	xor    %r12,%r12
    xor     %r13, %r13
    c75c:	4d 31 ed             	xor    %r13,%r13
    xor     %r14, %r14
    c75f:	4d 31 f6             	xor    %r14,%r14
    xor     %r15, %r15
    c762:	4d 31 ff             	xor    %r15,%r15
#endif

    /* Set status flags to pre-defined values */
    add     %xdx, %xdx          /* OF = SF = AF = CF = 0; ZF = PF = 1 */
    c765:	48 01 d2             	add    %rdx,%rdx
    cld                         /* DF = 0 */
    c768:	fc                   	cld    

    /* EEXIT */
    mov     $SE_EEXIT, %xax     /* EEXIT leaf */
    c769:	48 c7 c0 04 00 00 00 	mov    $0x4,%rax
    c770:	0f 01 d7             	enclu  
    ENCLU

    /* Should not come here */
    ud2
    c773:	0f 0b                	ud2    

.Ldo_handler:
    mov     %xax, %xdx          /* XDX: cssa */
    c775:	48 89 c2             	mov    %rax,%rdx
    GET_STACK_BASE %xbx         /* XAX: static stack, set sp to stack base */
    c778:	48 89 d8             	mov    %rbx,%rax
    c77b:	48 2d 00 00 01 00    	sub    $0x10000,%rax
    jmp     .Lswitch_stack   
    c781:	e9 42 ff ff ff       	jmpq   c6c8 <enclave_entry+0x47>
 
    /* Should not come here */
    ud2
    c786:	0f 0b                	ud2    

000000000000c788 <do_ocall>:
/* 
 * 8 for GPR, 1 for TD.last_sp, 1 for ocall_index
 * 1 for OCALL_FLAG, 4 for shadow space.
 * Stack Pointer is 16-byte aligned under x86_64.
 */
    push    %xbp
    c788:	55                   	push   %rbp
    mov     %xsp, %xbp
    c789:	48 89 e5             	mov    %rsp,%rbp

/* save parameters in stack */
#ifdef LINUX64
    mov     %xdi, 2*SE_WORDSIZE(%xbp)
    c78c:	48 89 7d 10          	mov    %rdi,0x10(%rbp)
    mov     %xsi, 3*SE_WORDSIZE(%xbp)
    c790:	48 89 75 18          	mov    %rsi,0x18(%rbp)
#endif

/* save and clean extended feature registers */
    READ_TD_DATA xsave_size
    c794:	65 48 8b 04 25 38 00 	mov    %gs:0x38,%rax
    c79b:	00 00 
    sub     %xax, %xsp                 /* allocate buffer to save xregs */
    c79d:	48 29 c4             	sub    %rax,%rsp
    mov     $0x3f, %xax
    c7a0:	48 c7 c0 3f 00 00 00 	mov    $0x3f,%rax
    not     %xax
    c7a7:	48 f7 d0             	not    %rax
    and     %xax, %xsp                 /* xsave requires 64 byte aligned */
    c7aa:	48 21 c4             	and    %rax,%rsp
    mov     %xsp, %xcx                 # xsave pointer
    c7ad:	48 89 e1             	mov    %rsp,%rcx

    sub     $(20*SE_WORDSIZE), %xsp    /* 20 slots for GPRs and other info */
    c7b0:	48 81 ec a0 00 00 00 	sub    $0xa0,%rsp
    mov     %xcx, SE_WORDSIZE*19(%xsp) /* addr for xsave */
    c7b7:	48 89 8c 24 98 00 00 	mov    %rcx,0x98(%rsp)
    c7be:	00 
/* save non-volatile registers, except xsp */
    mov     %xbx, SE_WORDSIZE*14(%xsp)
    c7bf:	48 89 5c 24 70       	mov    %rbx,0x70(%rsp)
    mov     %xsi, SE_WORDSIZE*13(%xsp)
    c7c4:	48 89 74 24 68       	mov    %rsi,0x68(%rsp)
    mov     %xdi, SE_WORDSIZE*12(%xsp)
    c7c9:	48 89 7c 24 60       	mov    %rdi,0x60(%rsp)
    mov     %xbp, SE_WORDSIZE*11(%xsp)
    c7ce:	48 89 6c 24 58       	mov    %rbp,0x58(%rsp)

#ifdef LINUX64
    mov     %r12, SE_WORDSIZE*10(%rsp)
    c7d3:	4c 89 64 24 50       	mov    %r12,0x50(%rsp)
    mov     %r13, SE_WORDSIZE* 9(%rsp)
    c7d8:	4c 89 6c 24 48       	mov    %r13,0x48(%rsp)
    mov     %r14, SE_WORDSIZE* 8(%rsp)
    c7dd:	4c 89 74 24 40       	mov    %r14,0x40(%rsp)
    mov     %r15, SE_WORDSIZE* 7(%rsp)
    c7e2:	4c 89 7c 24 38       	mov    %r15,0x38(%rsp)
#endif

/* save and clean extended feature registers */
    mov     SE_WORDSIZE*19(%xsp), %xdi /* xsave pointer */
    c7e7:	48 8b bc 24 98 00 00 	mov    0x98(%rsp),%rdi
    c7ee:	00 
    READ_TD_DATA xsave_size
    c7ef:	65 48 8b 04 25 38 00 	mov    %gs:0x38,%rax
    c7f6:	00 00 
    mov     %xax, %xcx
    c7f8:	48 89 c1             	mov    %rax,%rcx
    shr     $2, %xcx                   /* xsave size in dword */
    c7fb:	48 c1 e9 02          	shr    $0x2,%rcx
    xor     %xax, %xax
    c7ff:	48 31 c0             	xor    %rax,%rax
    cld
    c802:	fc                   	cld    
    rep stos %eax, %es:(%xdi)
    c803:	f3 ab                	rep stos %eax,%es:(%rdi)

    mov     SE_WORDSIZE*19(%xsp), %xdi # xsave pointer
    c805:	48 8b bc 24 98 00 00 	mov    0x98(%rsp),%rdi
    c80c:	00 
    mov     %xdi, (%xsp)
    c80d:	48 89 3c 24          	mov    %rdi,(%rsp)
    call    save_xregs
    c811:	e8 ef fd ff ff       	callq  c605 <save_xregs>
    lea_pic SYNTHETIC_STATE, %xdi
    c816:	48 8d 3d e3 0f 00 00 	lea    0xfe3(%rip),%rdi        # d800 <SYNTHETIC_STATE>
    mov     %xdi, (%xsp)
    c81d:	48 89 3c 24          	mov    %rdi,(%rsp)
    call    restore_xregs
    c821:	e8 b3 fd ff ff       	callq  c5d9 <restore_xregs>

    /* set xdi and xsi using the input parameters */
#ifdef LINUX64
    mov     SE_WORDSIZE*12(%xsp), %xdi
    c826:	48 8b 7c 24 60       	mov    0x60(%rsp),%rdi
    mov     SE_WORDSIZE*13(%xsp), %xsi
    c82b:	48 8b 74 24 68       	mov    0x68(%rsp),%rsi
    mov     SE_WORDSIZE*2(%ebp), %edi
    mov     SE_WORDSIZE*3(%ebp), %esi
#endif

    /* save ocall index to the stack */
    mov     $OCALL_FLAG, %xax
    c830:	48 c7 c0 44 49 43 4f 	mov    $0x4f434944,%rax
    mov     %xax, SE_WORDSIZE*4(%xsp)   /* save OCALL_FLAG */
    c837:	48 89 44 24 20       	mov    %rax,0x20(%rsp)
    mov     %xdi, SE_WORDSIZE*5(%xsp)   /* save ocall_index */
    c83c:	48 89 7c 24 28       	mov    %rdi,0x28(%rsp)
    /*
     * save the inside stack context
     *     push TD.last_sp
     *     set TD.last_sp = xsp
     */
    READ_TD_DATA self_addr
    c841:	65 48 8b 04 25 00 00 	mov    %gs:0x0,%rax
    c848:	00 00 
    mov     %xax, %xbx 
    c84a:	48 89 c3             	mov    %rax,%rbx

    /* call update_ocall_lastsp */
#ifdef LINUX32
    mov     %xsp, (%xsp)
#else
    mov     %xsp, %xdi
    c84d:	48 89 e7             	mov    %rsp,%rdi
#endif
    
    call    update_ocall_lastsp         /* xax: td.last_sp */
    c850:	e8 12 6e ff ff       	callq  3667 <update_ocall_lastsp>

#ifdef LINUX64
    mov     SE_WORDSIZE*12(%xsp), %xdi   /* restore xdi */
    c855:	48 8b 7c 24 60       	mov    0x60(%rsp),%rdi
    mov     SE_WORDSIZE*13(%xsp), %xsi   /* restore xdi */
    c85a:	48 8b 74 24 68       	mov    0x68(%rsp),%rsi
#endif

    /* restore outside stack context */
    mov     first_ssa_gpr(%xbx), %xdx
    c85f:	48 8b 53 20          	mov    0x20(%rbx),%rdx
    mov     ssa_bp_u(%xdx), %xbp
    c863:	48 8b aa 98 00 00 00 	mov    0x98(%rdx),%rbp
    mov     ssa_sp_u(%xdx), %xsp
    c86a:	48 8b a2 90 00 00 00 	mov    0x90(%rdx),%rsp
     *                    | ret_addr    |
     *                    | xbp_u       |
     *                    | xsp_u       |
     *                    | ...         |
     */
    mov     -1*SE_WORDSIZE(%xax), %xbx  /* return address */
    c871:	48 8b 58 f8          	mov    -0x8(%rax),%rbx
    mov     $SE_EEXIT, %xax             /* EEXIT leaf */
    c875:	48 c7 c0 04 00 00 00 	mov    $0x4,%rax

    /* Clear all GPRs, except xax, xbx, xdi, and xsi*/
    xor     %xcx, %xcx
    c87c:	48 31 c9             	xor    %rcx,%rcx
    xor     %xdx, %xdx
    c87f:	48 31 d2             	xor    %rdx,%rdx
#ifdef LINUX64
    xor     %r8,  %r8
    c882:	4d 31 c0             	xor    %r8,%r8
    xor     %r9,  %r9
    c885:	4d 31 c9             	xor    %r9,%r9
    xor     %r10, %r10
    c888:	4d 31 d2             	xor    %r10,%r10
    xor     %r11, %r11
    c88b:	4d 31 db             	xor    %r11,%r11
    xor     %r12, %r12
    c88e:	4d 31 e4             	xor    %r12,%r12
    xor     %r13, %r13
    c891:	4d 31 ed             	xor    %r13,%r13
    xor     %r14, %r14
    c894:	4d 31 f6             	xor    %r14,%r14
    xor     %r15, %r15
    c897:	4d 31 ff             	xor    %r15,%r15
#endif

    /* Set status flags to pre-defined values */
    add     %xdx, %xdx          /* OF = SF = AF = CF = 0; ZF = PF = 1 */
    c89a:	48 01 d2             	add    %rdx,%rdx
    cld                         /* DF = 0 */
    c89d:	fc                   	cld    
    c89e:	0f 01 d7             	enclu  

000000000000c8a1 <__morestack>:
 * stick ocall bridge and proxy frame together
 * ------------------------------------------------------------------
 */
DECLARE_LOCAL_FUNC __morestack
    .cfi_startproc
    push %xbp
    c8a1:	55                   	push   %rbp
    .cfi_def_cfa_offset     2*SE_WORDSIZE
    .cfi_offset             xbp,-2*SE_WORDSIZE
    mov %xsp, %xbp
    c8a2:	48 89 e5             	mov    %rsp,%rbp
    .cfi_def_cfa_register   xbp
    sub $(4*SE_WORDSIZE), %xsp
    c8a5:	48 83 ec 20          	sub    $0x20,%rsp
    mov (2*SE_WORDSIZE)(%xbp), %xax
    mov %xax, (0*SE_WORDSIZE)(%xsp)
    mov (3*SE_WORDSIZE)(%xbp), %xax
    mov %xax, (1*SE_WORDSIZE)(%xsp)
#endif
    call        do_ocall
    c8a9:	e8 da fe ff ff       	callq  c788 <do_ocall>
    leave
    c8ae:	c9                   	leaveq 
    ret
    c8af:	c3                   	retq   

000000000000c8b0 <asm_oret>:
    .cfi_endproc

DECLARE_GLOBAL_FUNC asm_oret
    mov     %xsp, %xbx
    c8b0:	48 89 e3             	mov    %rsp,%rbx
#ifdef LINUX64
    mov     %xdi, SE_WORDSIZE(%xsp)
    c8b3:	48 89 7c 24 08       	mov    %rdi,0x8(%rsp)
    mov     %xsi, 2*SE_WORDSIZE(%xsp)
    c8b8:	48 89 74 24 10       	mov    %rsi,0x10(%rsp)
#endif
    mov     SE_WORDSIZE(%xbx), %xsp    /* restore thread_data.last_sp */
    c8bd:	48 8b 63 08          	mov    0x8(%rbx),%rsp

/* restore extended feature registers */
    mov     19*SE_WORDSIZE(%xsp), %xdi
    c8c1:	48 8b bc 24 98 00 00 	mov    0x98(%rsp),%rdi
    c8c8:	00 
#ifdef LINUX32
    mov     %xdi, (%xsp)
#endif
    call    restore_xregs
    c8c9:	e8 0b fd ff ff       	callq  c5d9 <restore_xregs>

/* memset_s */
    xor     %xax, %xax
    c8ce:	48 31 c0             	xor    %rax,%rax
    mov     11*SE_WORDSIZE(%xsp), %xcx
    c8d1:	48 8b 4c 24 58       	mov    0x58(%rsp),%rcx
    sub     %xdi, %xcx
    c8d6:	48 29 f9             	sub    %rdi,%rcx
    sub     $SE_WORDSIZE, %xcx
    c8d9:	48 83 e9 08          	sub    $0x8,%rcx
    shr     $2, %xcx
    c8dd:	48 c1 e9 02          	shr    $0x2,%rcx
    cld
    c8e1:	fc                   	cld    
    rep stos %eax,%es:(%xdi)
    c8e2:	f3 ab                	rep stos %eax,%es:(%rdi)

    mov     2*SE_WORDSIZE(%xbx), %xax  /* ocall return value */
    c8e4:	48 8b 43 10          	mov    0x10(%rbx),%rax

#ifdef LINUX64
    mov     7*SE_WORDSIZE(%xsp), %r15
    c8e8:	4c 8b 7c 24 38       	mov    0x38(%rsp),%r15
    mov     8*SE_WORDSIZE(%xsp), %r14
    c8ed:	4c 8b 74 24 40       	mov    0x40(%rsp),%r14
    mov     9*SE_WORDSIZE(%xsp), %r13
    c8f2:	4c 8b 6c 24 48       	mov    0x48(%rsp),%r13
    mov    10*SE_WORDSIZE(%xsp), %r12
    c8f7:	4c 8b 64 24 50       	mov    0x50(%rsp),%r12
#endif

    mov    11*SE_WORDSIZE(%xsp), %xbp
    c8fc:	48 8b 6c 24 58       	mov    0x58(%rsp),%rbp
    mov    12*SE_WORDSIZE(%xsp), %xdi
    c901:	48 8b 7c 24 60       	mov    0x60(%rsp),%rdi
    mov    13*SE_WORDSIZE(%xsp), %xsi
    c906:	48 8b 74 24 68       	mov    0x68(%rsp),%rsi
    mov    14*SE_WORDSIZE(%xsp), %xbx
    c90b:	48 8b 5c 24 70       	mov    0x70(%rsp),%rbx

    mov     %xbp, %xsp
    c910:	48 89 ec             	mov    %rbp,%rsp
    pop     %xbp
    c913:	5d                   	pop    %rbp

    ret
    c914:	c3                   	retq   
    /* should not come here */
    ud2
    c915:	0f 0b                	ud2    

000000000000c917 <do_egetkey>:
 * EGETKEY: rbx - the address of KEYREQUEST structure
 *	   rcx - the address where the key is outputted
 * ------------------------------------------------------------------------
 */
DECLARE_LOCAL_FUNC do_egetkey
    SE_PROLOG
    c917:	53                   	push   %rbx
    c918:	51                   	push   %rcx
    c919:	52                   	push   %rdx
    c91a:	48 89 fb             	mov    %rdi,%rbx
    c91d:	48 89 f1             	mov    %rsi,%rcx
    mov  $SE_EGETKEY, %xax      /* EGETKEY leaf */
    c920:	48 c7 c0 01 00 00 00 	mov    $0x1,%rax
    c927:	0f 01 d7             	enclu  
    ENCLU
#ifdef SE_SIM
    cmp  $SGX_SUCCESS, %xax     /* In simulation mode, ZF flag will not be set */
    jnz	 .Legetkey_done         /* because the stack clean operation will always clean ZF flag */
#else
    jz   .Legetkey_done         /* if EGETKEY error, ZF flag is set and error code is set to xax */
    c92a:	74 03                	je     c92f <do_egetkey+0x18>
#endif
    xor  %xax, %xax
    c92c:	48 31 c0             	xor    %rax,%rax
.Legetkey_done:
    SE_EPILOG
    c92f:	5a                   	pop    %rdx
    c930:	59                   	pop    %rcx
    c931:	5b                   	pop    %rbx
    c932:	c3                   	retq   

000000000000c933 <do_ereport>:
 *          non-zero: failure
 * -------------------------------------------------------------------------
 */
.global Lereport_inst
DECLARE_LOCAL_FUNC do_ereport
    SE_PROLOG
    c933:	53                   	push   %rbx
    c934:	51                   	push   %rcx
    c935:	52                   	push   %rdx
    c936:	48 89 fb             	mov    %rdi,%rbx
    c939:	48 89 f1             	mov    %rsi,%rcx
    mov       $SE_EREPORT, %xax  /* EREPORT leaf */
    c93c:	48 c7 c0 00 00 00 00 	mov    $0x0,%rax
    clc
    c943:	f8                   	clc    

000000000000c944 <Lereport_inst>:
    c944:	0f 01 d7             	enclu  
Lereport_inst:
    ENCLU
    setc      %al
    c947:	0f 92 c0             	setb   %al
    SE_EPILOG
    c94a:	5a                   	pop    %rdx
    c94b:	59                   	pop    %rcx
    c94c:	5b                   	pop    %rbx
    c94d:	c3                   	retq   

000000000000c94e <do_eaccept>:
    
DECLARE_GLOBAL_FUNC do_eaccept
    SE_PROLOG
    c94e:	53                   	push   %rbx
    c94f:	51                   	push   %rcx
    c950:	52                   	push   %rdx
    c951:	48 89 fb             	mov    %rdi,%rbx
    c954:	48 89 f1             	mov    %rsi,%rcx
    mov     $SE_EACCEPT, %eax
    c957:	b8 05 00 00 00       	mov    $0x5,%eax
    c95c:	0f 01 d7             	enclu  
    ENCLU
    cmp  $SGX_SUCCESS, %eax 
    c95f:	83 f8 00             	cmp    $0x0,%eax
    jnz	 abort 
    c962:	75 38                	jne    c99c <abort>
    SE_EPILOG
    c964:	5a                   	pop    %rdx
    c965:	59                   	pop    %rcx
    c966:	5b                   	pop    %rbx
    c967:	c3                   	retq   

000000000000c968 <do_emodpe>:

DECLARE_GLOBAL_FUNC do_emodpe
    SE_PROLOG
    c968:	53                   	push   %rbx
    c969:	51                   	push   %rcx
    c96a:	52                   	push   %rdx
    c96b:	48 89 fb             	mov    %rdi,%rbx
    c96e:	48 89 f1             	mov    %rsi,%rcx
    mov     $SE_EMODPE, %eax 
    c971:	b8 06 00 00 00       	mov    $0x6,%eax
    c976:	0f 01 d7             	enclu  
    ENCLU
    SE_EPILOG
    c979:	5a                   	pop    %rdx
    c97a:	59                   	pop    %rcx
    c97b:	5b                   	pop    %rbx
    c97c:	c3                   	retq   

000000000000c97d <do_rdrand>:
 *	non-zero: rdrand succeeded
 *	zero: rdrand failed
 * -------------------------------------
 */
DECLARE_LOCAL_FUNC do_rdrand
    mov $_RDRAND_RETRY_TIMES, %ecx
    c97d:	b9 0a 00 00 00       	mov    $0xa,%ecx
    c982:	0f c7 f0             	rdrand %eax
.Lrdrand_retry:
    .byte 0x0F, 0xC7, 0xF0	    /* rdrand %eax */
    jc	.Lrdrand_return
    c985:	72 08                	jb     c98f <do_rdrand+0x12>
    dec	%ecx
    c987:	ff c9                	dec    %ecx
    jnz 	.Lrdrand_retry
    c989:	75 f7                	jne    c982 <do_rdrand+0x5>
    xor 	%xax, %xax
    c98b:	48 31 c0             	xor    %rax,%rax
    ret
    c98e:	c3                   	retq   
.Lrdrand_return:
#ifdef LINUX32
    mov     SE_WORDSIZE(%esp), %ecx
#else
    mov     %rdi, %rcx
    c98f:	48 89 f9             	mov    %rdi,%rcx
#endif
    movl    %eax, (%xcx)
    c992:	89 01                	mov    %eax,(%rcx)
    mov     $1, %xax
    c994:	48 c7 c0 01 00 00 00 	mov    $0x1,%rax
    ret
    c99b:	c3                   	retq   

000000000000c99c <abort>:
 * -------------------------------------------------------------------------
 * extern "C" void abort(void) __attribute__(__noreturn__);
 * -------------------------------------------------------------------------
 */
DECLARE_LOCAL_FUNC abort
    lea_pic g_enclave_state, %xax
    c99c:	48 8d 05 fd 46 00 00 	lea    0x46fd(%rip),%rax        # 110a0 <g_enclave_state>
    movl    $ENCLAVE_CRASHED, (%xax)
    c9a3:	c7 00 03 00 00 00    	movl   $0x3,(%rax)
    ud2
    c9a9:	0f 0b                	ud2    

000000000000c9ab <continue_execution>:
 */
DECLARE_LOCAL_FUNC continue_execution
#ifdef LINUX32
    mov     %xax, %xcx
#else
    mov     %xdi, %xcx
    c9ab:	48 89 f9             	mov    %rdi,%rcx
#endif
    mov     SE_WORDSIZE*0(%xcx), %xax
    c9ae:	48 8b 01             	mov    (%rcx),%rax
    push    %xax                       /* push xax */
    c9b1:	50                   	push   %rax
    mov     SE_WORDSIZE*1(%xcx), %xax
    c9b2:	48 8b 41 08          	mov    0x8(%rcx),%rax
    push    %xax                       /* push xcx */
    c9b6:	50                   	push   %rax
    mov     SE_WORDSIZE*4(%xcx), %xax  /* xax: xsp */
    c9b7:	48 8b 41 20          	mov    0x20(%rcx),%rax
/* x86_64 requires a 128-bytes red zone. We need to allocate buffer to avoid touching the red zone. */
    sub     $(SE_WORDSIZE + RED_ZONE_SIZE), %xax   /* allocate buffer to skip red zone and save xip */
    c9bb:	48 2d 88 00 00 00    	sub    $0x88,%rax

/* restore registers except xax, xcx, xsp */
    mov     SE_WORDSIZE*2(%xcx), %xdx
    c9c1:	48 8b 51 10          	mov    0x10(%rcx),%rdx
    mov     SE_WORDSIZE*3(%xcx), %xbx
    c9c5:	48 8b 59 18          	mov    0x18(%rcx),%rbx
    mov     SE_WORDSIZE*5(%xcx), %xbp
    c9c9:	48 8b 69 28          	mov    0x28(%rcx),%rbp
    mov     SE_WORDSIZE*6(%xcx), %xsi
    c9cd:	48 8b 71 30          	mov    0x30(%rcx),%rsi
    mov     SE_WORDSIZE*7(%xcx), %xdi
    c9d1:	48 8b 79 38          	mov    0x38(%rcx),%rdi
#ifdef LINUX64
    mov     SE_WORDSIZE*8(%xcx), %r8
    c9d5:	4c 8b 41 40          	mov    0x40(%rcx),%r8
    mov     SE_WORDSIZE*9(%xcx), %r9
    c9d9:	4c 8b 49 48          	mov    0x48(%rcx),%r9
    mov     SE_WORDSIZE*10(%xcx), %r10
    c9dd:	4c 8b 51 50          	mov    0x50(%rcx),%r10
    mov     SE_WORDSIZE*11(%xcx), %r11
    c9e1:	4c 8b 59 58          	mov    0x58(%rcx),%r11
    mov     SE_WORDSIZE*12(%xcx), %r12
    c9e5:	4c 8b 61 60          	mov    0x60(%rcx),%r12
    mov     SE_WORDSIZE*13(%xcx), %r13
    c9e9:	4c 8b 69 68          	mov    0x68(%rcx),%r13
    mov     SE_WORDSIZE*14(%xcx), %r14
    c9ed:	4c 8b 71 70          	mov    0x70(%rcx),%r14
    mov     SE_WORDSIZE*15(%xcx), %r15
    c9f1:	4c 8b 79 78          	mov    0x78(%rcx),%r15
    push    SE_WORDSIZE*16(%xcx)
    c9f5:	ff b1 80 00 00 00    	pushq  0x80(%rcx)
    popf    /* make sure the following instructions do not affect flags */
    c9fb:	9d                   	popfq  
    push    SE_WORDSIZE*8(%xcx)
    popf
#endif

#ifdef LINUX64
    mov     SE_WORDSIZE*17(%xcx), %xcx
    c9fc:	48 8b 89 88 00 00 00 	mov    0x88(%rcx),%rcx
#endif

/* do not setup the new stack until info is not needed any more
 * otherwise, info will be overwritten
 */
    mov     %xcx, (%xax)               /* save xip to the new stack */
    ca03:	48 89 08             	mov    %rcx,(%rax)
    pop     %xcx                       /* restore xcx */
    ca06:	59                   	pop    %rcx
    pop     %xsp                       /* xsp: xax */
    ca07:	5c                   	pop    %rsp
    xchg    %xax, %xsp
    ca08:	48 94                	xchg   %rax,%rsp
    ret     $(RED_ZONE_SIZE)           /* pop xip and red zone (if any) */
    ca0a:	c2 80 00             	retq   $0x80
