
./enclave.signed.so:     file format elf64-x86-64


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
    103f:	e8 de 02 00 00       	callq  1322 <sgx_is_outside_enclave>
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
	i++;
	return;
}
#pragma GCC pop_options

int test() {
    1073:	55                   	push   %rbp
    1074:	48 89 e5             	mov    %rsp,%rbp
	volatile int i =0;
    1077:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
	i=43;
    107e:	c7 45 fc 2b 00 00 00 	movl   $0x2b,-0x4(%rbp)
	i++;
    1085:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1088:	83 c0 01             	add    $0x1,%eax
    108b:	89 45 fc             	mov    %eax,-0x4(%rbp)
	return (int)i;
    108e:	8b 45 fc             	mov    -0x4(%rbp),%eax
}
    1091:	5d                   	pop    %rbp
    1092:	c3                   	retq   

0000000000001093 <_ZL28set_global_feature_indicatormm>:
extern "C" int sgx_init_string_lib(uint64_t cpu_feature_indicator);
extern "C" sgx_status_t sgx_init_crypto_lib(uint64_t cpu_feature_indicator, uint32_t *cpuinfo_table);


static int set_global_feature_indicator(uint64_t feature_bit_array, uint64_t xfrm)
{
    1093:	55                   	push   %rbp
    1094:	48 89 e5             	mov    %rsp,%rbp
    1097:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    109b:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    // Confirm the reserved bits and the unset bits by uRTS must be 0.
    
    
    if(feature_bit_array & (RESERVED_CPU_FEATURE_BIT))
    109f:	48 b8 00 00 00 00 00 	movabs $0xff00000000000000,%rax
    10a6:	00 00 ff 
    10a9:	48 23 45 f8          	and    -0x8(%rbp),%rax
    10ad:	48 85 c0             	test   %rax,%rax
    10b0:	74 0e                	je     10c0 <_ZL28set_global_feature_indicatormm+0x2d>
    {
        // clear the reserved bits
        feature_bit_array = feature_bit_array & (~(RESERVED_CPU_FEATURE_BIT));
    10b2:	48 b8 ff ff ff ff ff 	movabs $0xffffffffffffff,%rax
    10b9:	ff ff 00 
    10bc:	48 21 45 f8          	and    %rax,-0x8(%rbp)
    }

    // Requires SSE4.1. Take SSE4.1 as the baseline.
    if(!(feature_bit_array & ~(CPU_FEATURE_SSE4_1 - 1)))
    10c0:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    10c4:	48 25 00 fe ff ff    	and    $0xfffffffffffffe00,%rax
    10ca:	48 85 c0             	test   %rax,%rax
    10cd:	75 0a                	jne    10d9 <_ZL28set_global_feature_indicatormm+0x46>
    {
        return -1;
    10cf:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    10d4:	e9 02 01 00 00       	jmpq   11db <_ZL28set_global_feature_indicatormm+0x148>
    }

    // Check for inconsistencies in the CPUID feature mask.
    if ( (((feature_bit_array & CPU_FEATURE_SSE) == CPU_FEATURE_SSE) &&((feature_bit_array & (CPU_FEATURE_SSE - 1)) != (CPU_FEATURE_SSE - 1))) || 
    10d9:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    10dd:	83 e0 20             	and    $0x20,%eax
    10e0:	48 85 c0             	test   %rax,%rax
    10e3:	74 11                	je     10f6 <_ZL28set_global_feature_indicatormm+0x63>
    10e5:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    10e9:	83 e0 1f             	and    $0x1f,%eax
    10ec:	48 83 f8 1f          	cmp    $0x1f,%rax
    10f0:	0f 85 8f 00 00 00    	jne    1185 <_ZL28set_global_feature_indicatormm+0xf2>
        (((feature_bit_array & CPU_FEATURE_SSE2) == CPU_FEATURE_SSE2) &&((feature_bit_array & (CPU_FEATURE_SSE2 - 1)) != (CPU_FEATURE_SSE2 - 1))) ||
    10f6:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    10fa:	83 e0 40             	and    $0x40,%eax
    if ( (((feature_bit_array & CPU_FEATURE_SSE) == CPU_FEATURE_SSE) &&((feature_bit_array & (CPU_FEATURE_SSE - 1)) != (CPU_FEATURE_SSE - 1))) || 
    10fd:	48 85 c0             	test   %rax,%rax
    1100:	74 0d                	je     110f <_ZL28set_global_feature_indicatormm+0x7c>
        (((feature_bit_array & CPU_FEATURE_SSE2) == CPU_FEATURE_SSE2) &&((feature_bit_array & (CPU_FEATURE_SSE2 - 1)) != (CPU_FEATURE_SSE2 - 1))) ||
    1102:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1106:	83 e0 3f             	and    $0x3f,%eax
    1109:	48 83 f8 3f          	cmp    $0x3f,%rax
    110d:	75 76                	jne    1185 <_ZL28set_global_feature_indicatormm+0xf2>
        (((feature_bit_array & CPU_FEATURE_SSE3) == CPU_FEATURE_SSE3) &&((feature_bit_array & (CPU_FEATURE_SSE3 - 1)) != (CPU_FEATURE_SSE3 - 1))) ||
    110f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1113:	25 80 00 00 00       	and    $0x80,%eax
        (((feature_bit_array & CPU_FEATURE_SSE2) == CPU_FEATURE_SSE2) &&((feature_bit_array & (CPU_FEATURE_SSE2 - 1)) != (CPU_FEATURE_SSE2 - 1))) ||
    1118:	48 85 c0             	test   %rax,%rax
    111b:	74 0d                	je     112a <_ZL28set_global_feature_indicatormm+0x97>
        (((feature_bit_array & CPU_FEATURE_SSE3) == CPU_FEATURE_SSE3) &&((feature_bit_array & (CPU_FEATURE_SSE3 - 1)) != (CPU_FEATURE_SSE3 - 1))) ||
    111d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1121:	83 e0 7f             	and    $0x7f,%eax
    1124:	48 83 f8 7f          	cmp    $0x7f,%rax
    1128:	75 5b                	jne    1185 <_ZL28set_global_feature_indicatormm+0xf2>
        (((feature_bit_array & CPU_FEATURE_SSSE3) == CPU_FEATURE_SSSE3) && ((feature_bit_array & (CPU_FEATURE_SSSE3 - 1)) != (CPU_FEATURE_SSSE3 - 1))) ||
    112a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    112e:	25 00 01 00 00       	and    $0x100,%eax
        (((feature_bit_array & CPU_FEATURE_SSE3) == CPU_FEATURE_SSE3) &&((feature_bit_array & (CPU_FEATURE_SSE3 - 1)) != (CPU_FEATURE_SSE3 - 1))) ||
    1133:	48 85 c0             	test   %rax,%rax
    1136:	74 0f                	je     1147 <_ZL28set_global_feature_indicatormm+0xb4>
        (((feature_bit_array & CPU_FEATURE_SSSE3) == CPU_FEATURE_SSSE3) && ((feature_bit_array & (CPU_FEATURE_SSSE3 - 1)) != (CPU_FEATURE_SSSE3 - 1))) ||
    1138:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    113c:	0f b6 c0             	movzbl %al,%eax
    113f:	48 3d ff 00 00 00    	cmp    $0xff,%rax
    1145:	75 3e                	jne    1185 <_ZL28set_global_feature_indicatormm+0xf2>
        (((feature_bit_array & CPU_FEATURE_SSE4_1) == CPU_FEATURE_SSE4_1) && ((feature_bit_array & (CPU_FEATURE_SSE4_1 - 1)) != (CPU_FEATURE_SSE4_1 - 1))) ||
    1147:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    114b:	25 00 02 00 00       	and    $0x200,%eax
        (((feature_bit_array & CPU_FEATURE_SSSE3) == CPU_FEATURE_SSSE3) && ((feature_bit_array & (CPU_FEATURE_SSSE3 - 1)) != (CPU_FEATURE_SSSE3 - 1))) ||
    1150:	48 85 c0             	test   %rax,%rax
    1153:	74 11                	je     1166 <_ZL28set_global_feature_indicatormm+0xd3>
        (((feature_bit_array & CPU_FEATURE_SSE4_1) == CPU_FEATURE_SSE4_1) && ((feature_bit_array & (CPU_FEATURE_SSE4_1 - 1)) != (CPU_FEATURE_SSE4_1 - 1))) ||
    1155:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1159:	25 ff 01 00 00       	and    $0x1ff,%eax
    115e:	48 3d ff 01 00 00    	cmp    $0x1ff,%rax
    1164:	75 1f                	jne    1185 <_ZL28set_global_feature_indicatormm+0xf2>
        (((feature_bit_array & CPU_FEATURE_SSE4_2) == CPU_FEATURE_SSE4_2) && ((feature_bit_array & (CPU_FEATURE_SSE4_2 - 1)) != (CPU_FEATURE_SSE4_2 - 1))) )
    1166:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    116a:	25 00 04 00 00       	and    $0x400,%eax
        (((feature_bit_array & CPU_FEATURE_SSE4_1) == CPU_FEATURE_SSE4_1) && ((feature_bit_array & (CPU_FEATURE_SSE4_1 - 1)) != (CPU_FEATURE_SSE4_1 - 1))) ||
    116f:	48 85 c0             	test   %rax,%rax
    1172:	74 18                	je     118c <_ZL28set_global_feature_indicatormm+0xf9>
        (((feature_bit_array & CPU_FEATURE_SSE4_2) == CPU_FEATURE_SSE4_2) && ((feature_bit_array & (CPU_FEATURE_SSE4_2 - 1)) != (CPU_FEATURE_SSE4_2 - 1))) )
    1174:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1178:	25 ff 03 00 00       	and    $0x3ff,%eax
    117d:	48 3d ff 03 00 00    	cmp    $0x3ff,%rax
    1183:	74 07                	je     118c <_ZL28set_global_feature_indicatormm+0xf9>
    {
        return -1;
    1185:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    118a:	eb 4f                	jmp    11db <_ZL28set_global_feature_indicatormm+0x148>
    }

    // Determine whether the OS & ENCLAVE support SAVE/RESTORE of the AVX register set
    // IF NOT, clear the advanced feature set bits corresponding to AVX and beyond
    if(!XFEATURE_ENABLED_AVX(xfrm))
    118c:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1190:	83 e0 06             	and    $0x6,%eax
    1193:	48 83 f8 06          	cmp    $0x6,%rax
    1197:	74 10                	je     11a9 <_ZL28set_global_feature_indicatormm+0x116>
    {
        // AVX is disabled by OS, so clear the AVX related feature bits
	feature_bit_array &= (~(CPU_FEATURE_AVX | CPU_FEATURE_VAES | CPU_FEATURE_VPCLMULQDQ | CPU_FEATURE_F16C | CPU_FEATURE_AVX2 |
    1199:	48 b8 ff 7f 12 86 08 	movabs $0xfffe200886127fff,%rax
    11a0:	20 fe ff 
    11a3:	48 21 45 f8          	and    %rax,-0x8(%rbp)
    11a7:	eb 1f                	jmp    11c8 <_ZL28set_global_feature_indicatormm+0x135>
            CPU_FEATURE_AVX512F | CPU_FEATURE_AVX512CD | CPU_FEATURE_AVX512ER | CPU_FEATURE_AVX512PF | CPU_FEATURE_AVX512DQ | CPU_FEATURE_AVX512BW |
            CPU_FEATURE_AVX512VL | CPU_FEATURE_AVX512IFMA52 | CPU_FEATURE_AVX512VBMI | CPU_FEATURE_AVX512_VPOPCNTDQ | CPU_FEATURE_AVX512_4VNNIW |
            CPU_FEATURE_AVX512_4FMAPS | CPU_FEATURE_AVX512_BITALG | CPU_FEATURE_AVX512_VBMI2 | CPU_FEATURE_AVX512_VNNI));
    }

    else if (!XFEATURE_ENABLED_AVX3(xfrm))
    11a9:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    11ad:	25 e0 00 00 00       	and    $0xe0,%eax
    11b2:	48 3d e0 00 00 00    	cmp    $0xe0,%rax
    11b8:	74 0e                	je     11c8 <_ZL28set_global_feature_indicatormm+0x135>
    {
        feature_bit_array &= (~(CPU_FEATURE_AVX512F | CPU_FEATURE_AVX512CD | CPU_FEATURE_AVX512ER | CPU_FEATURE_AVX512PF | CPU_FEATURE_AVX512DQ |
    11ba:	48 b8 ff ff ff b6 18 	movabs $0xfffee018b6ffffff,%rax
    11c1:	e0 fe ff 
    11c4:	48 21 45 f8          	and    %rax,-0x8(%rbp)
            CPU_FEATURE_AVX512BW | CPU_FEATURE_AVX512VL | CPU_FEATURE_AVX512IFMA52 | CPU_FEATURE_AVX512VBMI | CPU_FEATURE_AVX512_VPOPCNTDQ |
            CPU_FEATURE_AVX512_4VNNIW | CPU_FEATURE_AVX512_4FMAPS | CPU_FEATURE_AVX512_BITALG | CPU_FEATURE_AVX512_VBMI2 | CPU_FEATURE_AVX512_VNNI));
    }

    g_cpu_feature_indicator = feature_bit_array;
    11c8:	48 8d 05 29 fc 00 00 	lea    0xfc29(%rip),%rax        # 10df8 <g_cpu_feature_indicator>
    11cf:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    11d3:	48 89 10             	mov    %rdx,(%rax)
    return 0;
    11d6:	b8 00 00 00 00       	mov    $0x0,%eax
}
    11db:	5d                   	pop    %rbp
    11dc:	c3                   	retq   

00000000000011dd <init_optimized_libs>:

extern "C" int init_optimized_libs(const uint64_t feature_bit_array, uint32_t *cpuinfo_table, uint64_t xfrm)
{
    11dd:	55                   	push   %rbp
    11de:	48 89 e5             	mov    %rsp,%rbp
    11e1:	48 83 ec 20          	sub    $0x20,%rsp
    11e5:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    11e9:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    11ed:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    if (g_enclave_state != ENCLAVE_INIT_IN_PROGRESS)
    11f1:	48 8d 05 a8 fe 00 00 	lea    0xfea8(%rip),%rax        # 110a0 <g_enclave_state>
    11f8:	8b 00                	mov    (%rax),%eax
    11fa:	83 f8 01             	cmp    $0x1,%eax
    11fd:	74 07                	je     1206 <init_optimized_libs+0x29>
    {
        return -1;
    11ff:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    1204:	eb 73                	jmp    1279 <init_optimized_libs+0x9c>
    }
    // set the global feature indicator
    if(set_global_feature_indicator(feature_bit_array, xfrm))
    1206:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    120a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    120e:	48 89 d6             	mov    %rdx,%rsi
    1211:	48 89 c7             	mov    %rax,%rdi
    1214:	e8 7a fe ff ff       	callq  1093 <_ZL28set_global_feature_indicatormm>
    1219:	85 c0                	test   %eax,%eax
    121b:	0f 95 c0             	setne  %al
    121e:	84 c0                	test   %al,%al
    1220:	74 07                	je     1229 <init_optimized_libs+0x4c>
    {
        return -1;
    1222:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    1227:	eb 50                	jmp    1279 <init_optimized_libs+0x9c>
    }

    // Init string library with the global feature indicator
    if(sgx_init_string_lib(g_cpu_feature_indicator) != 0)
    1229:	48 8d 05 c8 fb 00 00 	lea    0xfbc8(%rip),%rax        # 10df8 <g_cpu_feature_indicator>
    1230:	48 8b 00             	mov    (%rax),%rax
    1233:	48 89 c7             	mov    %rax,%rdi
    1236:	e8 42 a1 00 00       	callq  b37d <sgx_init_string_lib>
    123b:	85 c0                	test   %eax,%eax
    123d:	0f 95 c0             	setne  %al
    1240:	84 c0                	test   %al,%al
    1242:	74 07                	je     124b <init_optimized_libs+0x6e>
    {
        return -1;
    1244:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    1249:	eb 2e                	jmp    1279 <init_optimized_libs+0x9c>
    }

    // Init IPP crypto library with the global feature indicator	
    if(sgx_init_crypto_lib(g_cpu_feature_indicator, cpuinfo_table) != 0)
    124b:	48 8d 05 a6 fb 00 00 	lea    0xfba6(%rip),%rax        # 10df8 <g_cpu_feature_indicator>
    1252:	48 8b 00             	mov    (%rax),%rax
    1255:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    1259:	48 89 d6             	mov    %rdx,%rsi
    125c:	48 89 c7             	mov    %rax,%rdi
    125f:	e8 8c a3 00 00       	callq  b5f0 <sgx_init_crypto_lib>
    1264:	85 c0                	test   %eax,%eax
    1266:	0f 95 c0             	setne  %al
    1269:	84 c0                	test   %al,%al
    126b:	74 07                	je     1274 <init_optimized_libs+0x97>
    {
        return -1;
    126d:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    1272:	eb 05                	jmp    1279 <init_optimized_libs+0x9c>
    }

    return 0;
    1274:	b8 00 00 00 00       	mov    $0x0,%eax
}
    1279:	c9                   	leaveq 
    127a:	c3                   	retq   

000000000000127b <trts_access_version_dummy1>:

#ifndef SE_SIM

#include "se_cdefs.h"
// add a version to trts
SGX_ACCESS_VERSION(trts, 1);
    127b:	55                   	push   %rbp
    127c:	48 89 e5             	mov    %rsp,%rbp
    127f:	48 8d 05 8a fd 00 00 	lea    0xfd8a(%rip),%rax        # 11010 <sgx_trts_version>
    1286:	c6 00 73             	movb   $0x73,(%rax)
    1289:	48 8d 05 80 fd 00 00 	lea    0xfd80(%rip),%rax        # 11010 <sgx_trts_version>
    1290:	5d                   	pop    %rbp
    1291:	c3                   	retq   

0000000000001292 <sgx_is_within_enclave>:
//      1 - the buffer is strictly within the enclave
//      0 - the whole buffer or part of the buffer is not within the enclave,
//          or the buffer is wrap around
//
int sgx_is_within_enclave(const void *addr, size_t size)
{
    1292:	55                   	push   %rbp
    1293:	48 89 e5             	mov    %rsp,%rbp
    1296:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    129a:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    size_t start = reinterpret_cast<size_t>(addr);
    129e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    12a2:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    size_t end = 0;
    12a6:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    12ad:	00 
    size_t enclave_start = (size_t)&__ImageBase;
    12ae:	48 8d 05 4b ed ff ff 	lea    -0x12b5(%rip),%rax        # 0 <enclave.so>
    12b5:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    size_t enclave_end = enclave_start + g_global_data.enclave_size - 1;
    12b9:	48 8d 05 c0 be 00 00 	lea    0xbec0(%rip),%rax        # d180 <g_global_data>
    12c0:	48 8b 10             	mov    (%rax),%rdx
    12c3:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    12c7:	48 01 d0             	add    %rdx,%rax
    12ca:	48 83 e8 01          	sub    $0x1,%rax
    12ce:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    // g_global_data.enclave_end = enclave_base + enclave_size - 1;
    // so the enclave range is [enclave_start, enclave_end] inclusively

    if(size > 0)
    12d2:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    12d7:	74 15                	je     12ee <sgx_is_within_enclave+0x5c>
    {
        end = start + size - 1;
    12d9:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    12dd:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    12e1:	48 01 d0             	add    %rdx,%rax
    12e4:	48 83 e8 01          	sub    $0x1,%rax
    12e8:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    12ec:	eb 08                	jmp    12f6 <sgx_is_within_enclave+0x64>
    }
    else
    {
        end = start;
    12ee:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    12f2:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    }
    if( (start <= end) && (start >= enclave_start) && (end <= enclave_end) )
    12f6:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    12fa:	48 3b 45 e0          	cmp    -0x20(%rbp),%rax
    12fe:	77 1b                	ja     131b <sgx_is_within_enclave+0x89>
    1300:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1304:	48 3b 45 f0          	cmp    -0x10(%rbp),%rax
    1308:	72 11                	jb     131b <sgx_is_within_enclave+0x89>
    130a:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    130e:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    1312:	77 07                	ja     131b <sgx_is_within_enclave+0x89>
    {
        return 1;
    1314:	b8 01 00 00 00       	mov    $0x1,%eax
    1319:	eb 05                	jmp    1320 <sgx_is_within_enclave+0x8e>
    }
    return 0;
    131b:	b8 00 00 00 00       	mov    $0x0,%eax
}
    1320:	5d                   	pop    %rbp
    1321:	c3                   	retq   

0000000000001322 <sgx_is_outside_enclave>:
//      1 - the buffer is strictly outside the enclave
//      0 - the whole buffer or part of the buffer is not outside the enclave,
//          or the buffer is wrap around
//
int sgx_is_outside_enclave(const void *addr, size_t size)
{
    1322:	55                   	push   %rbp
    1323:	48 89 e5             	mov    %rsp,%rbp
    1326:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    132a:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    size_t start = reinterpret_cast<size_t>(addr);
    132e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1332:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    size_t end = 0;
    1336:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    133d:	00 
    size_t enclave_start = (size_t)&__ImageBase;
    133e:	48 8d 05 bb ec ff ff 	lea    -0x1345(%rip),%rax        # 0 <enclave.so>
    1345:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    size_t enclave_end = enclave_start + g_global_data.enclave_size - 1;
    1349:	48 8d 05 30 be 00 00 	lea    0xbe30(%rip),%rax        # d180 <g_global_data>
    1350:	48 8b 10             	mov    (%rax),%rdx
    1353:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1357:	48 01 d0             	add    %rdx,%rax
    135a:	48 83 e8 01          	sub    $0x1,%rax
    135e:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    // g_global_data.enclave_end = enclave_base + enclave_size - 1;
    // so the enclave range is [enclave_start, enclave_end] inclusively

    if(size > 0)
    1362:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    1367:	74 15                	je     137e <sgx_is_outside_enclave+0x5c>
    {
        end = start + size - 1;
    1369:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    136d:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    1371:	48 01 d0             	add    %rdx,%rax
    1374:	48 83 e8 01          	sub    $0x1,%rax
    1378:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    137c:	eb 08                	jmp    1386 <sgx_is_outside_enclave+0x64>
    }
    else
    {
        end = start;
    137e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1382:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    }
    if( (start <= end) && ((end < enclave_start) || (start > enclave_end)) )
    1386:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    138a:	48 3b 45 e0          	cmp    -0x20(%rbp),%rax
    138e:	77 1b                	ja     13ab <sgx_is_outside_enclave+0x89>
    1390:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1394:	48 3b 45 f0          	cmp    -0x10(%rbp),%rax
    1398:	72 0a                	jb     13a4 <sgx_is_outside_enclave+0x82>
    139a:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    139e:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    13a2:	76 07                	jbe    13ab <sgx_is_outside_enclave+0x89>
    {
        return 1;
    13a4:	b8 01 00 00 00       	mov    $0x1,%eax
    13a9:	eb 05                	jmp    13b0 <sgx_is_outside_enclave+0x8e>
    }
    return 0;
    13ab:	b8 00 00 00 00       	mov    $0x0,%eax
}
    13b0:	5d                   	pop    %rbp
    13b1:	c3                   	retq   

00000000000013b2 <sgx_ocalloc>:
// When ECALL or exception handling returns, the stack pointer is set as the value in the ECALL stack frame and then EEXIT,
// so the outside stack is automatically unwind.
// In addition, sgx_ocalloc needs perform outside stack probe to make sure it is not allocating beyond the end of the stack.
#define OC_ROUND 16
void * sgx_ocalloc(size_t size)
{
    13b2:	55                   	push   %rbp
    13b3:	48 89 e5             	mov    %rsp,%rbp
    13b6:	48 83 ec 40          	sub    $0x40,%rsp
    13ba:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    // read the outside stack address from current SSA
    thread_data_t *thread_data = get_thread_data();
    13be:	e8 69 b2 00 00       	callq  c62c <get_thread_data>
    13c3:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    ssa_gpr_t *ssa_gpr = reinterpret_cast<ssa_gpr_t *>(thread_data->first_ssa_gpr);
    13c7:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    13cb:	48 8b 40 20          	mov    0x20(%rax),%rax
    13cf:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    size_t addr = ssa_gpr->REG(sp_u);
    13d3:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    13d7:	48 8b 80 90 00 00 00 	mov    0x90(%rax),%rax
    13de:	48 89 45 e8          	mov    %rax,-0x18(%rbp)

    // check u_rsp points to the untrusted address.
    // if the check fails, it should be hacked. call abort directly
    if(!sgx_is_outside_enclave(reinterpret_cast<void *>(addr), sizeof(size_t)))
    13e2:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    13e6:	be 08 00 00 00       	mov    $0x8,%esi
    13eb:	48 89 c7             	mov    %rax,%rdi
    13ee:	e8 2f ff ff ff       	callq  1322 <sgx_is_outside_enclave>
    13f3:	85 c0                	test   %eax,%eax
    13f5:	0f 94 c0             	sete   %al
    13f8:	84 c0                	test   %al,%al
    13fa:	74 05                	je     1401 <sgx_ocalloc+0x4f>
    {
        abort();
    13fc:	e8 5a b5 00 00       	callq  c95b <abort>
    }

    // size is too large to allocate. call abort() directly.
    if(addr < size)
    1401:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1405:	48 3b 45 c8          	cmp    -0x38(%rbp),%rax
    1409:	73 05                	jae    1410 <sgx_ocalloc+0x5e>
    {
        abort();
    140b:	e8 4b b5 00 00       	callq  c95b <abort>
    }

    // calculate the start address for the allocated memory
    addr -= size;
    1410:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    1414:	48 29 45 e8          	sub    %rax,-0x18(%rbp)
    addr &= ~(static_cast<size_t>(OC_ROUND - 1));  // for stack alignment
    1418:	48 83 65 e8 f0       	andq   $0xfffffffffffffff0,-0x18(%rbp)

    // the allocated memory has overlap with enclave, abort the enclave
    if(!sgx_is_outside_enclave(reinterpret_cast<void *>(addr), size))
    141d:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1421:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    1425:	48 89 d6             	mov    %rdx,%rsi
    1428:	48 89 c7             	mov    %rax,%rdi
    142b:	e8 f2 fe ff ff       	callq  1322 <sgx_is_outside_enclave>
    1430:	85 c0                	test   %eax,%eax
    1432:	0f 94 c0             	sete   %al
    1435:	84 c0                	test   %al,%al
    1437:	74 05                	je     143e <sgx_ocalloc+0x8c>
    {
        abort();
    1439:	e8 1d b5 00 00       	callq  c95b <abort>

    // probe the outside stack to ensure that we do not skip over the stack3 guard page
    // we need to probe all the pages including the first page and the last page
    // the first page need to be probed in case uRTS didnot touch that page before EENTER enclave
    // the last page need to be probed in case the enclave didnot touch that page before another OCALLOC
    size_t first_page = TRIM_TO_PAGE(ssa_gpr->REG(sp_u) - 1);
    143e:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1442:	48 8b 80 90 00 00 00 	mov    0x90(%rax),%rax
    1449:	48 83 e8 01          	sub    $0x1,%rax
    144d:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    1453:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    size_t last_page = TRIM_TO_PAGE(addr);
    1457:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    145b:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    1461:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

    // To avoid the dead-loop in the following for(...) loop.
    // Attacker might fake a stack address that is within address 0x4095.
    if (last_page == 0)
    1465:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    146a:	75 05                	jne    1471 <sgx_ocalloc+0xbf>
    {
        abort();
    146c:	e8 ea b4 00 00       	callq  c95b <abort>
    }

    // the compiler may optimize the following code to probe the pages in any order
    // while we only expect the probe order should be from higher addr to lower addr
    // so use volatile to avoid optimization by the compiler
    for(volatile size_t page = first_page; page >= last_page; page -= SE_PAGE_SIZE)
    1471:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1475:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    1479:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    147d:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    1481:	0f 96 c0             	setbe  %al
    1484:	84 c0                	test   %al,%al
    1486:	74 26                	je     14ae <sgx_ocalloc+0xfc>
    {
        // OS may refuse to commit a physical page if the page fault address is smaller than RSP
        // So update the outside stack address before probe the page
        ssa_gpr->REG(sp_u) = page;
    1488:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    148c:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1490:	48 89 90 90 00 00 00 	mov    %rdx,0x90(%rax)

        *reinterpret_cast<uint8_t *>(page) = 0;
    1497:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    149b:	c6 00 00             	movb   $0x0,(%rax)
    for(volatile size_t page = first_page; page >= last_page; page -= SE_PAGE_SIZE)
    149e:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    14a2:	48 2d 00 10 00 00    	sub    $0x1000,%rax
    14a8:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    14ac:	eb cb                	jmp    1479 <sgx_ocalloc+0xc7>
    }

    // update the outside stack address in the SSA to the allocated address
    ssa_gpr->REG(sp_u) = addr;
    14ae:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    14b2:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    14b6:	48 89 90 90 00 00 00 	mov    %rdx,0x90(%rax)

    return reinterpret_cast<void *>(addr);
    14bd:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
}
    14c1:	c9                   	leaveq 
    14c2:	c3                   	retq   

00000000000014c3 <sgx_ocfree>:
// Return Value:
//      N/A
// sgx_ocfree restores the original outside stack pointer in the SSA.
// Do not call this function if you still need the buffer allocated by sgx_ocalloc within the ECALL.
void sgx_ocfree()
{
    14c3:	55                   	push   %rbp
    14c4:	48 89 e5             	mov    %rsp,%rbp
    14c7:	48 83 ec 20          	sub    $0x20,%rsp
    //                       -------------
    //                      | ret_addr    |
    //                      | xbp_u       |
    //                      | xsp_u       |

    thread_data_t *thread_data = get_thread_data();
    14cb:	e8 5c b1 00 00       	callq  c62c <get_thread_data>
    14d0:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    ssa_gpr_t *ssa_gpr = reinterpret_cast<ssa_gpr_t *>(thread_data->first_ssa_gpr);
    14d4:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    14d8:	48 8b 40 20          	mov    0x20(%rax),%rax
    14dc:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    uintptr_t *addr = reinterpret_cast<uintptr_t *>(thread_data->last_sp);
    14e0:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    14e4:	48 8b 40 08          	mov    0x8(%rax),%rax
    14e8:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    uintptr_t usp = *(addr - 3);
    14ec:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    14f0:	48 8b 40 e8          	mov    -0x18(%rax),%rax
    14f4:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if(!sgx_is_outside_enclave(reinterpret_cast<void *>(usp), sizeof(uintptr_t)))
    14f8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    14fc:	be 08 00 00 00       	mov    $0x8,%esi
    1501:	48 89 c7             	mov    %rax,%rdi
    1504:	e8 19 fe ff ff       	callq  1322 <sgx_is_outside_enclave>
    1509:	85 c0                	test   %eax,%eax
    150b:	0f 94 c0             	sete   %al
    150e:	84 c0                	test   %al,%al
    1510:	74 05                	je     1517 <sgx_ocfree+0x54>
    {
        abort();
    1512:	e8 44 b4 00 00       	callq  c95b <abort>
    }
    ssa_gpr->REG(sp_u) = usp;
    1517:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    151b:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    151f:	48 89 90 90 00 00 00 	mov    %rdx,0x90(%rax)
}
    1526:	90                   	nop
    1527:	c9                   	leaveq 
    1528:	c3                   	retq   

0000000000001529 <_ZL15__do_get_rand32Pj>:
    return n;
}
#endif

static sgx_status_t  __do_get_rand32(uint32_t* rand_num)
{
    1529:	55                   	push   %rbp
    152a:	48 89 e5             	mov    %rsp,%rbp
    152d:	48 83 ec 10          	sub    $0x10,%rsp
    1531:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
#ifndef SE_SIM
    /* We expect the CPU has RDRAND support for HW mode. Otherwise, an exception will be thrown
    * do_rdrand() will try to call RDRAND for 10 times
    */
    if(0 == do_rdrand(rand_num))
    1535:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1539:	48 89 c7             	mov    %rax,%rdi
    153c:	e8 fb b3 00 00       	callq  c93c <do_rdrand>
    1541:	85 c0                	test   %eax,%eax
    1543:	0f 94 c0             	sete   %al
    1546:	84 c0                	test   %al,%al
    1548:	74 07                	je     1551 <_ZL15__do_get_rand32Pj+0x28>
        return SGX_ERROR_UNEXPECTED;
    154a:	b8 01 00 00 00       	mov    $0x1,%eax
    154f:	eb 05                	jmp    1556 <_ZL15__do_get_rand32Pj+0x2d>
    {
        /*  use LCG in simulation mode */
        *rand_num = get_rand_lcg();
    }
#endif
    return SGX_SUCCESS;
    1551:	b8 00 00 00 00       	mov    $0x0,%eax
}
    1556:	c9                   	leaveq 
    1557:	c3                   	retq   

0000000000001558 <sgx_read_rand>:

sgx_status_t sgx_read_rand(unsigned char *rand, size_t length_in_bytes)
{
    1558:	55                   	push   %rbp
    1559:	48 89 e5             	mov    %rsp,%rbp
    155c:	48 83 ec 30          	sub    $0x30,%rsp
    1560:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    1564:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    1568:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    156f:	00 00 
    1571:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1575:	31 c0                	xor    %eax,%eax
    // check parameters
    //
    // rand can be within or outside the enclave
    if(!rand || !length_in_bytes)
    1577:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    157c:	74 07                	je     1585 <sgx_read_rand+0x2d>
    157e:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    1583:	75 0a                	jne    158f <sgx_read_rand+0x37>
    {
        return SGX_ERROR_INVALID_PARAMETER;
    1585:	b8 02 00 00 00       	mov    $0x2,%eax
    158a:	e9 cc 00 00 00       	jmpq   165b <sgx_read_rand+0x103>
    }
    if(!sgx_is_within_enclave(rand, length_in_bytes) && !sgx_is_outside_enclave(rand, length_in_bytes))
    158f:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    1593:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1597:	48 89 d6             	mov    %rdx,%rsi
    159a:	48 89 c7             	mov    %rax,%rdi
    159d:	e8 f0 fc ff ff       	callq  1292 <sgx_is_within_enclave>
    15a2:	85 c0                	test   %eax,%eax
    15a4:	75 1e                	jne    15c4 <sgx_read_rand+0x6c>
    15a6:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    15aa:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    15ae:	48 89 d6             	mov    %rdx,%rsi
    15b1:	48 89 c7             	mov    %rax,%rdi
    15b4:	e8 69 fd ff ff       	callq  1322 <sgx_is_outside_enclave>
    15b9:	85 c0                	test   %eax,%eax
    15bb:	75 07                	jne    15c4 <sgx_read_rand+0x6c>
    15bd:	b8 01 00 00 00       	mov    $0x1,%eax
    15c2:	eb 05                	jmp    15c9 <sgx_read_rand+0x71>
    15c4:	b8 00 00 00 00       	mov    $0x0,%eax
    15c9:	84 c0                	test   %al,%al
    15cb:	74 0a                	je     15d7 <sgx_read_rand+0x7f>
    {
        return SGX_ERROR_INVALID_PARAMETER;
    15cd:	b8 02 00 00 00       	mov    $0x2,%eax
    15d2:	e9 84 00 00 00       	jmpq   165b <sgx_read_rand+0x103>
    }
    // loop to rdrand
    uint32_t rand_num = 0;
    15d7:	c7 45 e8 00 00 00 00 	movl   $0x0,-0x18(%rbp)
    while(length_in_bytes > 0)
    15de:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    15e3:	74 56                	je     163b <sgx_read_rand+0xe3>
    {
        sgx_status_t status = __do_get_rand32(&rand_num);
    15e5:	48 8d 45 e8          	lea    -0x18(%rbp),%rax
    15e9:	48 89 c7             	mov    %rax,%rdi
    15ec:	e8 38 ff ff ff       	callq  1529 <_ZL15__do_get_rand32Pj>
    15f1:	89 45 ec             	mov    %eax,-0x14(%rbp)
        if(status != SGX_SUCCESS)
    15f4:	83 7d ec 00          	cmpl   $0x0,-0x14(%rbp)
    15f8:	74 05                	je     15ff <sgx_read_rand+0xa7>
        {
            return status;
    15fa:	8b 45 ec             	mov    -0x14(%rbp),%eax
    15fd:	eb 5c                	jmp    165b <sgx_read_rand+0x103>
        }

        size_t size = (length_in_bytes < sizeof(rand_num)) ? length_in_bytes : sizeof(rand_num);
    15ff:	b8 04 00 00 00       	mov    $0x4,%eax
    1604:	48 83 7d d0 04       	cmpq   $0x4,-0x30(%rbp)
    1609:	48 0f 46 45 d0       	cmovbe -0x30(%rbp),%rax
    160e:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
        memcpy(rand, &rand_num, size);
    1612:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    1616:	48 8d 4d e8          	lea    -0x18(%rbp),%rcx
    161a:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    161e:	48 89 ce             	mov    %rcx,%rsi
    1621:	48 89 c7             	mov    %rax,%rdi
    1624:	e8 96 98 00 00       	callq  aebf <memcpy>

        rand += size;
    1629:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    162d:	48 01 45 d8          	add    %rax,-0x28(%rbp)
        length_in_bytes -= size;
    1631:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1635:	48 29 45 d0          	sub    %rax,-0x30(%rbp)
    while(length_in_bytes > 0)
    1639:	eb a3                	jmp    15de <sgx_read_rand+0x86>
    }
    memset_s(&rand_num, sizeof(rand_num), 0, sizeof(rand_num));
    163b:	48 8d 45 e8          	lea    -0x18(%rbp),%rax
    163f:	b9 04 00 00 00       	mov    $0x4,%ecx
    1644:	ba 00 00 00 00       	mov    $0x0,%edx
    1649:	be 04 00 00 00       	mov    $0x4,%esi
    164e:	48 89 c7             	mov    %rax,%rdi
    1651:	e8 01 99 00 00       	callq  af57 <memset_s>
    return SGX_SUCCESS;
    1656:	b8 00 00 00 00       	mov    $0x0,%eax
}
    165b:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    165f:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    1666:	00 00 
    1668:	74 05                	je     166f <sgx_read_rand+0x117>
    166a:	e8 f8 3b 00 00       	callq  5267 <__stack_chk_fail>
    166f:	c9                   	leaveq 
    1670:	c3                   	retq   

0000000000001671 <check_static_stack_canary>:
    return get_enclave_state() == ENCLAVE_CRASHED;
}

extern uintptr_t __stack_chk_guard;
int check_static_stack_canary(void *tcs)
{
    1671:	55                   	push   %rbp
    1672:	48 89 e5             	mov    %rsp,%rbp
    1675:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    size_t *canary = TCS2CANARY(tcs);
    1679:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    167d:	48 2d a8 02 01 00    	sub    $0x102a8,%rax
    1683:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if ( *canary != (size_t)__stack_chk_guard)
    1687:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    168b:	48 8b 10             	mov    (%rax),%rdx
    168e:	48 8d 05 7b f7 00 00 	lea    0xf77b(%rip),%rax        # 10e10 <__intel_security_cookie>
    1695:	48 8b 00             	mov    (%rax),%rax
    1698:	48 39 c2             	cmp    %rax,%rdx
    169b:	74 07                	je     16a4 <check_static_stack_canary+0x33>
    {
        return -1;
    169d:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    16a2:	eb 05                	jmp    16a9 <check_static_stack_canary+0x38>
    }
    return 0;
    16a4:	b8 00 00 00 00       	mov    $0x0,%eax
}
    16a9:	5d                   	pop    %rbp
    16aa:	c3                   	retq   

00000000000016ab <memcpy_s>:
#ifdef __cplusplus
    extern "C" {
#endif

static inline errno_t memcpy_s(void *dest, size_t numberOfElements, const void *src, size_t count)
{
    16ab:	55                   	push   %rbp
    16ac:	48 89 e5             	mov    %rsp,%rbp
    16af:	48 83 ec 20          	sub    $0x20,%rsp
    16b3:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    16b7:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    16bb:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    16bf:	48 89 4d e0          	mov    %rcx,-0x20(%rbp)
    if(numberOfElements<count)
    16c3:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    16c7:	48 3b 45 e0          	cmp    -0x20(%rbp),%rax
    16cb:	73 07                	jae    16d4 <memcpy_s+0x29>
        return -1;
    16cd:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    16d2:	eb 1c                	jmp    16f0 <memcpy_s+0x45>
    memcpy(dest, src, count);
    16d4:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    16d8:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
    16dc:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    16e0:	48 89 ce             	mov    %rcx,%rsi
    16e3:	48 89 c7             	mov    %rax,%rdi
    16e6:	e8 d4 97 00 00       	callq  aebf <memcpy>
    return 0;
    16eb:	b8 00 00 00 00       	mov    $0x0,%eax
}
    16f0:	c9                   	leaveq 
    16f1:	c3                   	retq   

00000000000016f2 <_ZL19sgx_accept_backwardmmm>:
    uint16_t    attributes;
};

// Low level API to EACCEPT pages on grow-up region.
static int sgx_accept_backward(si_flags_t sfl, size_t lo, size_t hi)
{
    16f2:	4c 8d 54 24 08       	lea    0x8(%rsp),%r10
    16f7:	48 83 e4 c0          	and    $0xffffffffffffffc0,%rsp
    16fb:	41 ff 72 f8          	pushq  -0x8(%r10)
    16ff:	55                   	push   %rbp
    1700:	48 89 e5             	mov    %rsp,%rbp
    1703:	41 52                	push   %r10
    1705:	48 81 ec e8 00 00 00 	sub    $0xe8,%rsp
    170c:	48 89 bd 38 ff ff ff 	mov    %rdi,-0xc8(%rbp)
    1713:	48 89 b5 30 ff ff ff 	mov    %rsi,-0xd0(%rbp)
    171a:	48 89 95 28 ff ff ff 	mov    %rdx,-0xd8(%rbp)
    1721:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    1728:	00 00 
    172a:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    172e:	31 c0                	xor    %eax,%eax
    size_t addr = hi;
    1730:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    1737:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    SE_DECLSPEC_ALIGN(sizeof(sec_info_t)) sec_info_t si;
    si.flags = sfl;
    173e:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    1745:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    for (uint16_t i = 0; i < (sizeof(si.reserved)/sizeof(si.reserved[0])); i++)
    174c:	66 c7 85 42 ff ff ff 	movw   $0x0,-0xbe(%rbp)
    1753:	00 00 
    1755:	66 83 bd 42 ff ff ff 	cmpw   $0x6,-0xbe(%rbp)
    175c:	06 
    175d:	77 28                	ja     1787 <_ZL19sgx_accept_backwardmmm+0x95>
        si.reserved[i] = 0;
    175f:	0f b7 85 42 ff ff ff 	movzwl -0xbe(%rbp),%eax
    1766:	48 98                	cltq   
    1768:	48 c7 84 c5 58 ff ff 	movq   $0x0,-0xa8(%rbp,%rax,8)
    176f:	ff 00 00 00 00 
    for (uint16_t i = 0; i < (sizeof(si.reserved)/sizeof(si.reserved[0])); i++)
    1774:	0f b7 85 42 ff ff ff 	movzwl -0xbe(%rbp),%eax
    177b:	83 c0 01             	add    $0x1,%eax
    177e:	66 89 85 42 ff ff ff 	mov    %ax,-0xbe(%rbp)
    1785:	eb ce                	jmp    1755 <_ZL19sgx_accept_backwardmmm+0x63>

    while (lo < addr)
    1787:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    178e:	48 3b 85 48 ff ff ff 	cmp    -0xb8(%rbp),%rax
    1795:	73 38                	jae    17cf <_ZL19sgx_accept_backwardmmm+0xdd>
    {
        int rc = do_eaccept(&si, addr -= SE_PAGE_SIZE);
    1797:	48 81 ad 48 ff ff ff 	subq   $0x1000,-0xb8(%rbp)
    179e:	00 10 00 00 
    17a2:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    17a9:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
    17b0:	48 89 d6             	mov    %rdx,%rsi
    17b3:	48 89 c7             	mov    %rax,%rdi
    17b6:	e8 52 b1 00 00       	callq  c90d <do_eaccept>
    17bb:	89 85 44 ff ff ff    	mov    %eax,-0xbc(%rbp)
        if (rc != 0)
    17c1:	83 bd 44 ff ff ff 00 	cmpl   $0x0,-0xbc(%rbp)
    17c8:	74 bd                	je     1787 <_ZL19sgx_accept_backwardmmm+0x95>
            abort();
    17ca:	e8 8c b1 00 00       	callq  c95b <abort>
    }
    return 0;
    17cf:	b8 00 00 00 00       	mov    $0x0,%eax
}
    17d4:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    17d8:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    17df:	00 00 
    17e1:	74 05                	je     17e8 <_ZL19sgx_accept_backwardmmm+0xf6>
    17e3:	e8 7f 3a 00 00       	callq  5267 <__stack_chk_fail>
    17e8:	48 81 c4 e8 00 00 00 	add    $0xe8,%rsp
    17ef:	41 5a                	pop    %r10
    17f1:	5d                   	pop    %rbp
    17f2:	49 8d 62 f8          	lea    -0x8(%r10),%rsp
    17f6:	c3                   	retq   

00000000000017f7 <_ZL35sgx_accept_forward_within_exceptionmm>:

// Low level API to EACCEPT pages on grow-up region during exception handling.
static int sgx_accept_forward_within_exception(size_t lo, size_t hi)
{
    17f7:	4c 8d 54 24 08       	lea    0x8(%rsp),%r10
    17fc:	48 83 e4 c0          	and    $0xffffffffffffffc0,%rsp
    1800:	41 ff 72 f8          	pushq  -0x8(%r10)
    1804:	55                   	push   %rbp
    1805:	48 89 e5             	mov    %rsp,%rbp
    1808:	41 52                	push   %r10
    180a:	48 81 ec e8 00 00 00 	sub    $0xe8,%rsp
    1811:	48 89 bd 28 ff ff ff 	mov    %rdi,-0xd8(%rbp)
    1818:	48 89 b5 20 ff ff ff 	mov    %rsi,-0xe0(%rbp)
    181f:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    1826:	00 00 
    1828:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    182c:	31 c0                	xor    %eax,%eax
    size_t addr = lo;
    182e:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    1835:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    SE_DECLSPEC_ALIGN(sizeof(sec_info_t)) sec_info_t si;

#ifdef DEBUG
    unsigned int sp_value = 0;
    183c:	c7 85 40 ff ff ff 00 	movl   $0x0,-0xc0(%rbp)
    1843:	00 00 00 
    asm("mov %%esp, %0;" : "=r" (sp_value) :);
    1846:	89 e0                	mov    %esp,%eax
    1848:	89 85 40 ff ff ff    	mov    %eax,-0xc0(%rbp)
    if ((sp_value & (SE_PAGE_SIZE -1)) <= (SE_PAGE_SIZE - (STATIC_STACK_SIZE % SE_PAGE_SIZE)))
    184e:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    1854:	25 ff 0f 00 00       	and    $0xfff,%eax
    1859:	3d 50 0d 00 00       	cmp    $0xd50,%eax
    185e:	77 0a                	ja     186a <_ZL35sgx_accept_forward_within_exceptionmm+0x73>
        return SGX_ERROR_UNEXPECTED;
    1860:	b8 01 00 00 00       	mov    $0x1,%eax
    1865:	e9 95 00 00 00       	jmpq   18ff <_ZL35sgx_accept_forward_within_exceptionmm+0x108>
#endif

    si.flags = SI_FLAGS_RW | SI_FLAG_PENDING;
    186a:	48 c7 85 50 ff ff ff 	movq   $0x20b,-0xb0(%rbp)
    1871:	0b 02 00 00 
    for (uint16_t i = 0; i < (sizeof(si.reserved)/sizeof(si.reserved[0])); i++)
    1875:	66 c7 85 3e ff ff ff 	movw   $0x0,-0xc2(%rbp)
    187c:	00 00 
    187e:	66 83 bd 3e ff ff ff 	cmpw   $0x6,-0xc2(%rbp)
    1885:	06 
    1886:	77 28                	ja     18b0 <_ZL35sgx_accept_forward_within_exceptionmm+0xb9>
        si.reserved[i] = 0;
    1888:	0f b7 85 3e ff ff ff 	movzwl -0xc2(%rbp),%eax
    188f:	48 98                	cltq   
    1891:	48 c7 84 c5 58 ff ff 	movq   $0x0,-0xa8(%rbp,%rax,8)
    1898:	ff 00 00 00 00 
    for (uint16_t i = 0; i < (sizeof(si.reserved)/sizeof(si.reserved[0])); i++)
    189d:	0f b7 85 3e ff ff ff 	movzwl -0xc2(%rbp),%eax
    18a4:	83 c0 01             	add    $0x1,%eax
    18a7:	66 89 85 3e ff ff ff 	mov    %ax,-0xc2(%rbp)
    18ae:	eb ce                	jmp    187e <_ZL35sgx_accept_forward_within_exceptionmm+0x87>

    while (addr < hi)
    18b0:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    18b7:	48 3b 85 20 ff ff ff 	cmp    -0xe0(%rbp),%rax
    18be:	73 3a                	jae    18fa <_ZL35sgx_accept_forward_within_exceptionmm+0x103>
    {
        int rc = do_eaccept(&si, addr);
    18c0:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    18c7:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
    18ce:	48 89 d6             	mov    %rdx,%rsi
    18d1:	48 89 c7             	mov    %rax,%rdi
    18d4:	e8 34 b0 00 00       	callq  c90d <do_eaccept>
    18d9:	89 85 44 ff ff ff    	mov    %eax,-0xbc(%rbp)
        if (rc != 0)
    18df:	83 bd 44 ff ff ff 00 	cmpl   $0x0,-0xbc(%rbp)
    18e6:	74 05                	je     18ed <_ZL35sgx_accept_forward_within_exceptionmm+0xf6>
            abort();
    18e8:	e8 6e b0 00 00       	callq  c95b <abort>
        addr += SE_PAGE_SIZE;
    18ed:	48 81 85 48 ff ff ff 	addq   $0x1000,-0xb8(%rbp)
    18f4:	00 10 00 00 
    while (addr < hi)
    18f8:	eb b6                	jmp    18b0 <_ZL35sgx_accept_forward_within_exceptionmm+0xb9>
    }

    return 0;
    18fa:	b8 00 00 00 00       	mov    $0x0,%eax
}
    18ff:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    1903:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    190a:	00 00 
    190c:	74 05                	je     1913 <_ZL35sgx_accept_forward_within_exceptionmm+0x11c>
    190e:	e8 54 39 00 00       	callq  5267 <__stack_chk_fail>
    1913:	48 81 c4 e8 00 00 00 	add    $0xe8,%rsp
    191a:	41 5a                	pop    %r10
    191c:	5d                   	pop    %rbp
    191d:	49 8d 62 f8          	lea    -0x8(%r10),%rsp
    1921:	c3                   	retq   

0000000000001922 <_Z24get_dynamic_layout_by_idt>:

const volatile layout_t *get_dynamic_layout_by_id(uint16_t id)
{
    1922:	55                   	push   %rbp
    1923:	48 89 e5             	mov    %rsp,%rbp
    1926:	89 f8                	mov    %edi,%eax
    1928:	66 89 45 ec          	mov    %ax,-0x14(%rbp)
    for(uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    192c:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    1933:	48 8d 05 46 b8 00 00 	lea    0xb846(%rip),%rax        # d180 <g_global_data>
    193a:	8b 80 28 01 00 00    	mov    0x128(%rax),%eax
    1940:	39 45 fc             	cmp    %eax,-0x4(%rbp)
    1943:	0f 92 c0             	setb   %al
    1946:	84 c0                	test   %al,%al
    1948:	74 45                	je     198f <_Z24get_dynamic_layout_by_idt+0x6d>
    {
        if(g_global_data.layout_table[i].entry.id == id)
    194a:	48 8d 05 2f b8 00 00 	lea    0xb82f(%rip),%rax        # d180 <g_global_data>
    1951:	8b 55 fc             	mov    -0x4(%rbp),%edx
    1954:	48 c1 e2 05          	shl    $0x5,%rdx
    1958:	48 01 d0             	add    %rdx,%rax
    195b:	48 05 30 01 00 00    	add    $0x130,%rax
    1961:	0f b7 00             	movzwl (%rax),%eax
    1964:	66 39 45 ec          	cmp    %ax,-0x14(%rbp)
    1968:	0f 94 c0             	sete   %al
    196b:	84 c0                	test   %al,%al
    196d:	74 1a                	je     1989 <_Z24get_dynamic_layout_by_idt+0x67>
        {
            return &(g_global_data.layout_table[i]);
    196f:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1972:	48 c1 e0 05          	shl    $0x5,%rax
    1976:	48 8d 90 30 01 00 00 	lea    0x130(%rax),%rdx
    197d:	48 8d 05 fc b7 00 00 	lea    0xb7fc(%rip),%rax        # d180 <g_global_data>
    1984:	48 01 d0             	add    %rdx,%rax
    1987:	eb 0b                	jmp    1994 <_Z24get_dynamic_layout_by_idt+0x72>
    for(uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    1989:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    198d:	eb a4                	jmp    1933 <_Z24get_dynamic_layout_by_idt+0x11>
        }
    }
    return NULL;
    198f:	b8 00 00 00 00       	mov    $0x0,%eax
}
    1994:	5d                   	pop    %rbp
    1995:	c3                   	retq   

0000000000001996 <_Z18accept_post_removePVK9_layout_tS1_m>:

// EACCEPT trim requests when the enclave completes initialization.
int accept_post_remove(const volatile layout_t *layout_start, const volatile layout_t *layout_end, size_t offset)
{
    1996:	55                   	push   %rbp
    1997:	48 89 e5             	mov    %rsp,%rbp
    199a:	53                   	push   %rbx
    199b:	48 83 ec 58          	sub    $0x58,%rsp
    199f:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    19a3:	48 89 75 b0          	mov    %rsi,-0x50(%rbp)
    19a7:	48 89 55 a8          	mov    %rdx,-0x58(%rbp)
    int ret = -1;
    19ab:	c7 45 d0 ff ff ff ff 	movl   $0xffffffff,-0x30(%rbp)
    for (const volatile layout_t *layout = layout_start; layout < layout_end; layout++)
    19b2:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    19b6:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    19ba:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    19be:	48 3b 45 b0          	cmp    -0x50(%rbp),%rax
    19c2:	0f 83 2f 01 00 00    	jae    1af7 <_Z18accept_post_removePVK9_layout_tS1_m+0x161>
    {
        if (!IS_GROUP_ID(layout->group.id) && (layout->entry.attributes & PAGE_ATTR_POST_REMOVE))
    19c8:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    19cc:	0f b7 00             	movzwl (%rax),%eax
    19cf:	0f b7 c0             	movzwl %ax,%eax
    19d2:	25 00 10 00 00       	and    $0x1000,%eax
    19d7:	85 c0                	test   %eax,%eax
    19d9:	75 19                	jne    19f4 <_Z18accept_post_removePVK9_layout_tS1_m+0x5e>
    19db:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    19df:	0f b7 40 02          	movzwl 0x2(%rax),%eax
    19e3:	0f b7 c0             	movzwl %ax,%eax
    19e6:	83 e0 10             	and    $0x10,%eax
    19e9:	85 c0                	test   %eax,%eax
    19eb:	74 07                	je     19f4 <_Z18accept_post_removePVK9_layout_tS1_m+0x5e>
    19ed:	b8 01 00 00 00       	mov    $0x1,%eax
    19f2:	eb 05                	jmp    19f9 <_Z18accept_post_removePVK9_layout_tS1_m+0x63>
    19f4:	b8 00 00 00 00       	mov    $0x0,%eax
    19f9:	84 c0                	test   %al,%al
    19fb:	74 62                	je     1a5f <_Z18accept_post_removePVK9_layout_tS1_m+0xc9>
        {
            size_t start_addr = (size_t)layout->entry.rva + offset + (size_t)get_enclave_base();
    19fd:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1a01:	48 8b 50 08          	mov    0x8(%rax),%rdx
    1a05:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    1a09:	48 8d 1c 02          	lea    (%rdx,%rax,1),%rbx
    1a0d:	e8 df ab 00 00       	callq  c5f1 <get_enclave_base>
    1a12:	48 01 d8             	add    %rbx,%rax
    1a15:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
            uint32_t page_count = layout->entry.page_count;
    1a19:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1a1d:	8b 40 04             	mov    0x4(%rax),%eax
    1a20:	89 45 d4             	mov    %eax,-0x2c(%rbp)

            if (0 != (ret = sgx_accept_forward(SI_FLAG_TRIM | SI_FLAG_MODIFIED, start_addr, start_addr + ((size_t)page_count << SE_PAGE_SHIFT))))
    1a23:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    1a26:	48 c1 e0 0c          	shl    $0xc,%rax
    1a2a:	48 89 c2             	mov    %rax,%rdx
    1a2d:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1a31:	48 01 c2             	add    %rax,%rdx
    1a34:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1a38:	48 89 c6             	mov    %rax,%rsi
    1a3b:	bf 10 04 00 00       	mov    $0x410,%edi
    1a40:	e8 ef 05 00 00       	callq  2034 <sgx_accept_forward>
    1a45:	89 45 d0             	mov    %eax,-0x30(%rbp)
    1a48:	83 7d d0 00          	cmpl   $0x0,-0x30(%rbp)
    1a4c:	0f 95 c0             	setne  %al
    1a4f:	84 c0                	test   %al,%al
    1a51:	0f 84 96 00 00 00    	je     1aed <_Z18accept_post_removePVK9_layout_tS1_m+0x157>
                return ret;
    1a57:	8b 45 d0             	mov    -0x30(%rbp),%eax
    1a5a:	e9 9d 00 00 00       	jmpq   1afc <_Z18accept_post_removePVK9_layout_tS1_m+0x166>
        }
        else if (IS_GROUP_ID(layout->group.id))
    1a5f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1a63:	0f b7 00             	movzwl (%rax),%eax
    1a66:	0f b7 c0             	movzwl %ax,%eax
    1a69:	25 00 10 00 00       	and    $0x1000,%eax
    1a6e:	85 c0                	test   %eax,%eax
    1a70:	0f 95 c0             	setne  %al
    1a73:	84 c0                	test   %al,%al
    1a75:	74 76                	je     1aed <_Z18accept_post_removePVK9_layout_tS1_m+0x157>
        {
            size_t step = 0;
    1a77:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    1a7e:	00 
            for(uint32_t j = 0; j < layout->group.load_times; j++)
    1a7f:	c7 45 cc 00 00 00 00 	movl   $0x0,-0x34(%rbp)
    1a86:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1a8a:	8b 40 04             	mov    0x4(%rax),%eax
    1a8d:	39 45 cc             	cmp    %eax,-0x34(%rbp)
    1a90:	0f 92 c0             	setb   %al
    1a93:	84 c0                	test   %al,%al
    1a95:	74 56                	je     1aed <_Z18accept_post_removePVK9_layout_tS1_m+0x157>
            {
                step += (size_t)layout->group.load_step;
    1a97:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1a9b:	48 8b 40 08          	mov    0x8(%rax),%rax
    1a9f:	48 01 45 e0          	add    %rax,-0x20(%rbp)
                if(0 != (ret = accept_post_remove(&layout[-layout->group.entry_count], layout, step)))
    1aa3:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1aa7:	0f b7 40 02          	movzwl 0x2(%rax),%eax
    1aab:	0f b7 c0             	movzwl %ax,%eax
    1aae:	f7 d8                	neg    %eax
    1ab0:	48 98                	cltq   
    1ab2:	48 c1 e0 05          	shl    $0x5,%rax
    1ab6:	48 89 c2             	mov    %rax,%rdx
    1ab9:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1abd:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
    1ac1:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    1ac5:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1ac9:	48 89 c6             	mov    %rax,%rsi
    1acc:	48 89 cf             	mov    %rcx,%rdi
    1acf:	e8 c2 fe ff ff       	callq  1996 <_Z18accept_post_removePVK9_layout_tS1_m>
    1ad4:	89 45 d0             	mov    %eax,-0x30(%rbp)
    1ad7:	83 7d d0 00          	cmpl   $0x0,-0x30(%rbp)
    1adb:	0f 95 c0             	setne  %al
    1ade:	84 c0                	test   %al,%al
    1ae0:	74 05                	je     1ae7 <_Z18accept_post_removePVK9_layout_tS1_m+0x151>
                    return ret;
    1ae2:	8b 45 d0             	mov    -0x30(%rbp),%eax
    1ae5:	eb 15                	jmp    1afc <_Z18accept_post_removePVK9_layout_tS1_m+0x166>
            for(uint32_t j = 0; j < layout->group.load_times; j++)
    1ae7:	83 45 cc 01          	addl   $0x1,-0x34(%rbp)
    1aeb:	eb 99                	jmp    1a86 <_Z18accept_post_removePVK9_layout_tS1_m+0xf0>
    for (const volatile layout_t *layout = layout_start; layout < layout_end; layout++)
    1aed:	48 83 45 d8 20       	addq   $0x20,-0x28(%rbp)
    1af2:	e9 c3 fe ff ff       	jmpq   19ba <_Z18accept_post_removePVK9_layout_tS1_m+0x24>
            }
        }
    }
    return 0;
    1af7:	b8 00 00 00 00       	mov    $0x0,%eax
}
    1afc:	48 83 c4 58          	add    $0x58,%rsp
    1b00:	5b                   	pop    %rbx
    1b01:	5d                   	pop    %rbp
    1b02:	c3                   	retq   

0000000000001b03 <_ZL20check_heap_dyn_rangePvmP24dynamic_flags_attributes>:

static int check_heap_dyn_range(void *addr, size_t page_count, struct dynamic_flags_attributes *fa)
{
    1b03:	55                   	push   %rbp
    1b04:	48 89 e5             	mov    %rsp,%rbp
    1b07:	53                   	push   %rbx
    1b08:	48 83 ec 38          	sub    $0x38,%rsp
    1b0c:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    1b10:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    1b14:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
    size_t heap_dyn_start, heap_dyn_size;

    heap_dyn_start = (size_t)get_heap_base() + get_heap_min_size();
    1b18:	e8 6a 1d 00 00       	callq  3887 <get_heap_base>
    1b1d:	48 89 c3             	mov    %rax,%rbx
    1b20:	e8 0f 1e 00 00       	callq  3934 <get_heap_min_size>
    1b25:	48 01 d8             	add    %rbx,%rax
    1b28:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    heap_dyn_size = get_heap_size() - get_heap_min_size();
    1b2c:	e8 71 1d 00 00       	callq  38a2 <get_heap_size>
    1b31:	48 89 c3             	mov    %rax,%rbx
    1b34:	e8 fb 1d 00 00       	callq  3934 <get_heap_min_size>
    1b39:	48 29 c3             	sub    %rax,%rbx
    1b3c:	48 89 d8             	mov    %rbx,%rax
    1b3f:	48 89 45 e8          	mov    %rax,-0x18(%rbp)

    if ((size_t)addr >= heap_dyn_start
    1b43:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1b47:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    1b4b:	77 46                	ja     1b93 <_ZL20check_heap_dyn_rangePvmP24dynamic_flags_attributes+0x90>
            && (size_t)addr + (page_count << SE_PAGE_SHIFT) <= heap_dyn_start + heap_dyn_size)
    1b4d:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    1b51:	48 c1 e0 0c          	shl    $0xc,%rax
    1b55:	48 89 c2             	mov    %rax,%rdx
    1b58:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1b5c:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
    1b60:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    1b64:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1b68:	48 01 d0             	add    %rdx,%rax
    1b6b:	48 39 c1             	cmp    %rax,%rcx
    1b6e:	77 23                	ja     1b93 <_ZL20check_heap_dyn_rangePvmP24dynamic_flags_attributes+0x90>
    {
        if (fa != NULL)
    1b70:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    1b75:	74 15                	je     1b8c <_ZL20check_heap_dyn_rangePvmP24dynamic_flags_attributes+0x89>
        {
            fa->si_flags = SI_FLAGS_RW;
    1b77:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    1b7b:	48 c7 00 03 02 00 00 	movq   $0x203,(%rax)
            fa->attributes = PAGE_ATTR_POST_ADD;
    1b82:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    1b86:	66 c7 40 08 08 00    	movw   $0x8,0x8(%rax)
        }
        return 0;
    1b8c:	b8 00 00 00 00       	mov    $0x0,%eax
    1b91:	eb 05                	jmp    1b98 <_ZL20check_heap_dyn_rangePvmP24dynamic_flags_attributes+0x95>
    }
    else
    {
        return -1;
    1b93:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    }
}
    1b98:	48 83 c4 38          	add    $0x38,%rsp
    1b9c:	5b                   	pop    %rbx
    1b9d:	5d                   	pop    %rbp
    1b9e:	c3                   	retq   

0000000000001b9f <_ZL20check_rsrv_dyn_rangePvmP24dynamic_flags_attributes>:
extern void *rsrv_mem_base;
extern size_t rsrv_mem_size;
extern size_t rsrv_mem_min_size;

static int check_rsrv_dyn_range(void *addr, size_t page_count, struct dynamic_flags_attributes *fa)
{
    1b9f:	55                   	push   %rbp
    1ba0:	48 89 e5             	mov    %rsp,%rbp
    1ba3:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    1ba7:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    1bab:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    size_t rsrv_mem_dyn_start, rsrv_mem_dyn_size;

    rsrv_mem_dyn_start = (size_t)rsrv_mem_base + rsrv_mem_min_size;
    1baf:	48 8d 05 82 f2 00 00 	lea    0xf282(%rip),%rax        # 10e38 <rsrv_mem_base>
    1bb6:	48 8b 00             	mov    (%rax),%rax
    1bb9:	48 89 c2             	mov    %rax,%rdx
    1bbc:	48 8d 05 85 f2 00 00 	lea    0xf285(%rip),%rax        # 10e48 <rsrv_mem_min_size>
    1bc3:	48 8b 00             	mov    (%rax),%rax
    1bc6:	48 01 d0             	add    %rdx,%rax
    1bc9:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    rsrv_mem_dyn_size = rsrv_mem_size - rsrv_mem_min_size;
    1bcd:	48 8d 05 6c f2 00 00 	lea    0xf26c(%rip),%rax        # 10e40 <rsrv_mem_size>
    1bd4:	48 8b 10             	mov    (%rax),%rdx
    1bd7:	48 8d 05 6a f2 00 00 	lea    0xf26a(%rip),%rax        # 10e48 <rsrv_mem_min_size>
    1bde:	48 8b 00             	mov    (%rax),%rax
    1be1:	48 29 c2             	sub    %rax,%rdx
    1be4:	48 89 d0             	mov    %rdx,%rax
    1be7:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

    if ((size_t)addr >= rsrv_mem_dyn_start
    1beb:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1bef:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    1bf3:	77 46                	ja     1c3b <_ZL20check_rsrv_dyn_rangePvmP24dynamic_flags_attributes+0x9c>
            && (size_t)addr + (page_count << SE_PAGE_SHIFT) <= rsrv_mem_dyn_start + rsrv_mem_dyn_size)
    1bf5:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1bf9:	48 c1 e0 0c          	shl    $0xc,%rax
    1bfd:	48 89 c2             	mov    %rax,%rdx
    1c00:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1c04:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
    1c08:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    1c0c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1c10:	48 01 d0             	add    %rdx,%rax
    1c13:	48 39 c1             	cmp    %rax,%rcx
    1c16:	77 23                	ja     1c3b <_ZL20check_rsrv_dyn_rangePvmP24dynamic_flags_attributes+0x9c>
    {
        if (fa != NULL)
    1c18:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    1c1d:	74 15                	je     1c34 <_ZL20check_rsrv_dyn_rangePvmP24dynamic_flags_attributes+0x95>
        {
            fa->si_flags = SI_FLAGS_RW;
    1c1f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1c23:	48 c7 00 03 02 00 00 	movq   $0x203,(%rax)
            fa->attributes = PAGE_ATTR_POST_ADD;
    1c2a:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1c2e:	66 c7 40 08 08 00    	movw   $0x8,0x8(%rax)
        }
        return 0;
    1c34:	b8 00 00 00 00       	mov    $0x0,%eax
    1c39:	eb 05                	jmp    1c40 <_ZL20check_rsrv_dyn_rangePvmP24dynamic_flags_attributes+0xa1>
    }
    else
    {
        return -1;
    1c3b:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    }
}
    1c40:	5d                   	pop    %rbp
    1c41:	c3                   	retq   

0000000000001c42 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes>:


static int check_dynamic_entry_range(void *addr, size_t page_count, uint16_t entry_id, size_t entry_offset, struct dynamic_flags_attributes *fa)
{
    1c42:	55                   	push   %rbp
    1c43:	48 89 e5             	mov    %rsp,%rbp
    1c46:	48 83 ec 50          	sub    $0x50,%rsp
    1c4a:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    1c4e:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    1c52:	89 d0                	mov    %edx,%eax
    1c54:	48 89 4d c0          	mov    %rcx,-0x40(%rbp)
    1c58:	4c 89 45 b8          	mov    %r8,-0x48(%rbp)
    1c5c:	66 89 45 cc          	mov    %ax,-0x34(%rbp)
    const volatile layout_t *layout = NULL;
    1c60:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
    1c67:	00 
    size_t entry_start_addr;
    uint32_t entry_page_count;

    if (entry_id < LAYOUT_ID_HEAP_MIN
            || entry_id > LAYOUT_ID_STACK_DYN_MIN
            || (NULL == (layout = get_dynamic_layout_by_id(entry_id))))
    1c68:	66 83 7d cc 00       	cmpw   $0x0,-0x34(%rbp)
    1c6d:	74 1d                	je     1c8c <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0x4a>
            || entry_id > LAYOUT_ID_STACK_DYN_MIN
    1c6f:	66 83 7d cc 12       	cmpw   $0x12,-0x34(%rbp)
    1c74:	77 16                	ja     1c8c <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0x4a>
            || (NULL == (layout = get_dynamic_layout_by_id(entry_id))))
    1c76:	0f b7 45 cc          	movzwl -0x34(%rbp),%eax
    1c7a:	89 c7                	mov    %eax,%edi
    1c7c:	e8 a1 fc ff ff       	callq  1922 <_Z24get_dynamic_layout_by_idt>
    1c81:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    1c85:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    1c8a:	75 07                	jne    1c93 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0x51>
    1c8c:	b8 01 00 00 00       	mov    $0x1,%eax
    1c91:	eb 05                	jmp    1c98 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0x56>
    1c93:	b8 00 00 00 00       	mov    $0x0,%eax
    if (entry_id < LAYOUT_ID_HEAP_MIN
    1c98:	84 c0                	test   %al,%al
    1c9a:	74 0a                	je     1ca6 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0x64>
    {
        return -1;
    1c9c:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    1ca1:	e9 8c 00 00 00       	jmpq   1d32 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0xf0>
    }

    entry_start_addr = (size_t)get_enclave_base() + (size_t)layout->entry.rva + entry_offset;
    1ca6:	e8 46 a9 00 00       	callq  c5f1 <get_enclave_base>
    1cab:	48 89 c2             	mov    %rax,%rdx
    1cae:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1cb2:	48 8b 40 08          	mov    0x8(%rax),%rax
    1cb6:	48 01 c2             	add    %rax,%rdx
    1cb9:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    1cbd:	48 01 d0             	add    %rdx,%rax
    1cc0:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    entry_page_count = layout->entry.page_count;
    1cc4:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1cc8:	8b 40 04             	mov    0x4(%rax),%eax
    1ccb:	89 45 ec             	mov    %eax,-0x14(%rbp)
    if ((size_t)addr >= entry_start_addr
    1cce:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1cd2:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    1cd6:	77 55                	ja     1d2d <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0xeb>
            && (size_t)addr + (page_count << SE_PAGE_SHIFT) <= entry_start_addr + ((size_t)entry_page_count << SE_PAGE_SHIFT))
    1cd8:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    1cdc:	48 c1 e0 0c          	shl    $0xc,%rax
    1ce0:	48 89 c2             	mov    %rax,%rdx
    1ce3:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1ce7:	48 01 c2             	add    %rax,%rdx
    1cea:	8b 45 ec             	mov    -0x14(%rbp),%eax
    1ced:	48 c1 e0 0c          	shl    $0xc,%rax
    1cf1:	48 89 c1             	mov    %rax,%rcx
    1cf4:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1cf8:	48 01 c8             	add    %rcx,%rax
    1cfb:	48 39 c2             	cmp    %rax,%rdx
    1cfe:	77 2d                	ja     1d2d <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0xeb>
    {
        if (fa != NULL)
    1d00:	48 83 7d b8 00       	cmpq   $0x0,-0x48(%rbp)
    1d05:	74 1f                	je     1d26 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0xe4>
        {
            fa->si_flags = layout->entry.si_flags;
    1d07:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1d0b:	48 8b 50 18          	mov    0x18(%rax),%rdx
    1d0f:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    1d13:	48 89 10             	mov    %rdx,(%rax)
            fa->attributes = layout->entry.attributes;
    1d16:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1d1a:	0f b7 50 02          	movzwl 0x2(%rax),%edx
    1d1e:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    1d22:	66 89 50 08          	mov    %dx,0x8(%rax)
        }
        return 0;
    1d26:	b8 00 00 00 00       	mov    $0x0,%eax
    1d2b:	eb 05                	jmp    1d32 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0xf0>
    }
    else
    {
        return -1;
    1d2d:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    }
}
    1d32:	c9                   	leaveq 
    1d33:	c3                   	retq   

0000000000001d34 <_ZL34check_utility_thread_dynamic_stackPvmP24dynamic_flags_attributes>:

static int check_utility_thread_dynamic_stack(void *addr, size_t page_count, struct dynamic_flags_attributes *fa)
{
    1d34:	55                   	push   %rbp
    1d35:	48 89 e5             	mov    %rsp,%rbp
    1d38:	48 83 ec 20          	sub    $0x20,%rsp
    1d3c:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    1d40:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    1d44:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    return check_dynamic_entry_range(addr, page_count, LAYOUT_ID_STACK_MAX, 0, fa);
    1d48:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    1d4c:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi
    1d50:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1d54:	49 89 d0             	mov    %rdx,%r8
    1d57:	b9 00 00 00 00       	mov    $0x0,%ecx
    1d5c:	ba 07 00 00 00       	mov    $0x7,%edx
    1d61:	48 89 c7             	mov    %rax,%rdi
    1d64:	e8 d9 fe ff ff       	callq  1c42 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes>
}
    1d69:	c9                   	leaveq 
    1d6a:	c3                   	retq   

0000000000001d6b <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes>:

// Verify if the range specified belongs to a dynamic range recorded in metadata.
static int check_dynamic_range(void *addr, size_t page_count, size_t *offset, struct dynamic_flags_attributes *fa)
{
    1d6b:	55                   	push   %rbp
    1d6c:	48 89 e5             	mov    %rsp,%rbp
    1d6f:	48 83 ec 30          	sub    $0x30,%rsp
    1d73:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    1d77:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    1d7b:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    1d7f:	48 89 4d d0          	mov    %rcx,-0x30(%rbp)
    const volatile layout_t *dt_layout = NULL;
    1d83:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    1d8a:	00 

    // check for integer overflow
    if ((size_t)addr > SIZE_MAX - (page_count << SE_PAGE_SHIFT))
    1d8b:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1d8f:	48 c1 e0 0c          	shl    $0xc,%rax
    1d93:	48 f7 d0             	not    %rax
    1d96:	48 89 c2             	mov    %rax,%rdx
    1d99:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1d9d:	48 39 c2             	cmp    %rax,%rdx
    1da0:	73 0a                	jae    1dac <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x41>
        return -1;
    1da2:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    1da7:	e9 99 01 00 00       	jmpq   1f45 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1da>

    // check heap dynamic range
    if (0 == check_heap_dyn_range(addr, page_count, fa))
    1dac:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    1db0:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    1db4:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1db8:	48 89 ce             	mov    %rcx,%rsi
    1dbb:	48 89 c7             	mov    %rax,%rdi
    1dbe:	e8 40 fd ff ff       	callq  1b03 <_ZL20check_heap_dyn_rangePvmP24dynamic_flags_attributes>
    1dc3:	85 c0                	test   %eax,%eax
    1dc5:	0f 94 c0             	sete   %al
    1dc8:	84 c0                	test   %al,%al
    1dca:	74 0a                	je     1dd6 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x6b>
        return 0;
    1dcc:	b8 00 00 00 00       	mov    $0x0,%eax
    1dd1:	e9 6f 01 00 00       	jmpq   1f45 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1da>

    // check dynamic stack within utility thread
    if (0 == check_utility_thread_dynamic_stack(addr, page_count, fa))
    1dd6:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    1dda:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    1dde:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1de2:	48 89 ce             	mov    %rcx,%rsi
    1de5:	48 89 c7             	mov    %rax,%rdi
    1de8:	e8 47 ff ff ff       	callq  1d34 <_ZL34check_utility_thread_dynamic_stackPvmP24dynamic_flags_attributes>
    1ded:	85 c0                	test   %eax,%eax
    1def:	0f 94 c0             	sete   %al
    1df2:	84 c0                	test   %al,%al
    1df4:	74 0a                	je     1e00 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x95>
        return 0;
    1df6:	b8 00 00 00 00       	mov    $0x0,%eax
    1dfb:	e9 45 01 00 00       	jmpq   1f45 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1da>

    if (0 == check_rsrv_dyn_range(addr, page_count, fa))
    1e00:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    1e04:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    1e08:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1e0c:	48 89 ce             	mov    %rcx,%rsi
    1e0f:	48 89 c7             	mov    %rax,%rdi
    1e12:	e8 88 fd ff ff       	callq  1b9f <_ZL20check_rsrv_dyn_rangePvmP24dynamic_flags_attributes>
    1e17:	85 c0                	test   %eax,%eax
    1e19:	0f 94 c0             	sete   %al
    1e1c:	84 c0                	test   %al,%al
    1e1e:	74 0a                	je     1e2a <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0xbf>
        return 0;
    1e20:	b8 00 00 00 00       	mov    $0x0,%eax
    1e25:	e9 1b 01 00 00       	jmpq   1f45 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1da>

    // check dynamic thread entries range
    if (NULL != (dt_layout = get_dynamic_layout_by_id(LAYOUT_ID_THREAD_GROUP_DYN)))
    1e2a:	bf 13 10 00 00       	mov    $0x1013,%edi
    1e2f:	e8 ee fa ff ff       	callq  1922 <_Z24get_dynamic_layout_by_idt>
    1e34:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1e38:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    1e3d:	0f 95 c0             	setne  %al
    1e40:	84 c0                	test   %al,%al
    1e42:	0f 84 9c 00 00 00    	je     1ee4 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x179>
    {
        for (uint16_t id = LAYOUT_ID_TCS_DYN; id <= LAYOUT_ID_STACK_DYN_MIN; id++)
    1e48:	66 c7 45 f0 0e 00    	movw   $0xe,-0x10(%rbp)
    1e4e:	66 83 7d f0 12       	cmpw   $0x12,-0x10(%rbp)
    1e53:	0f 87 e7 00 00 00    	ja     1f40 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1d5>
            for (uint32_t i = 0; i < dt_layout->group.load_times + 1; i++)
    1e59:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    1e60:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1e64:	8b 40 04             	mov    0x4(%rax),%eax
    1e67:	83 c0 01             	add    $0x1,%eax
    1e6a:	39 45 f4             	cmp    %eax,-0xc(%rbp)
    1e6d:	0f 92 c0             	setb   %al
    1e70:	84 c0                	test   %al,%al
    1e72:	74 60                	je     1ed4 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x169>
            {
                if (0 == check_dynamic_entry_range(addr, page_count, id, i * ((size_t)dt_layout->group.load_step), fa))
    1e74:	8b 55 f4             	mov    -0xc(%rbp),%edx
    1e77:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1e7b:	48 8b 40 08          	mov    0x8(%rax),%rax
    1e7f:	48 89 d1             	mov    %rdx,%rcx
    1e82:	48 0f af c8          	imul   %rax,%rcx
    1e86:	0f b7 55 f0          	movzwl -0x10(%rbp),%edx
    1e8a:	48 8b 7d d0          	mov    -0x30(%rbp),%rdi
    1e8e:	48 8b 75 e0          	mov    -0x20(%rbp),%rsi
    1e92:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1e96:	49 89 f8             	mov    %rdi,%r8
    1e99:	48 89 c7             	mov    %rax,%rdi
    1e9c:	e8 a1 fd ff ff       	callq  1c42 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes>
    1ea1:	85 c0                	test   %eax,%eax
    1ea3:	0f 94 c0             	sete   %al
    1ea6:	84 c0                	test   %al,%al
    1ea8:	74 24                	je     1ece <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x163>
                {
                    if (offset != NULL) *offset = i * ((size_t)dt_layout->group.load_step);
    1eaa:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    1eaf:	74 16                	je     1ec7 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x15c>
    1eb1:	8b 55 f4             	mov    -0xc(%rbp),%edx
    1eb4:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1eb8:	48 8b 40 08          	mov    0x8(%rax),%rax
    1ebc:	48 0f af d0          	imul   %rax,%rdx
    1ec0:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1ec4:	48 89 10             	mov    %rdx,(%rax)
                    return 0;
    1ec7:	b8 00 00 00 00       	mov    $0x0,%eax
    1ecc:	eb 77                	jmp    1f45 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1da>
            for (uint32_t i = 0; i < dt_layout->group.load_times + 1; i++)
    1ece:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    1ed2:	eb 8c                	jmp    1e60 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0xf5>
        for (uint16_t id = LAYOUT_ID_TCS_DYN; id <= LAYOUT_ID_STACK_DYN_MIN; id++)
    1ed4:	0f b7 45 f0          	movzwl -0x10(%rbp),%eax
    1ed8:	83 c0 01             	add    $0x1,%eax
    1edb:	66 89 45 f0          	mov    %ax,-0x10(%rbp)
    1edf:	e9 6a ff ff ff       	jmpq   1e4e <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0xe3>
            }
    }
    else
    {
        // LAYOUT_ID_THREAD_GROUP_DYN does not exist, but possibly there is one single dynamic thead
        for (uint16_t id = LAYOUT_ID_TCS_DYN; id <= LAYOUT_ID_STACK_DYN_MIN; id++)
    1ee4:	66 c7 45 f2 0e 00    	movw   $0xe,-0xe(%rbp)
    1eea:	66 83 7d f2 12       	cmpw   $0x12,-0xe(%rbp)
    1eef:	77 4f                	ja     1f40 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1d5>
            if (0 == check_dynamic_entry_range(addr, page_count, id, 0, fa))
    1ef1:	0f b7 55 f2          	movzwl -0xe(%rbp),%edx
    1ef5:	48 8b 4d d0          	mov    -0x30(%rbp),%rcx
    1ef9:	48 8b 75 e0          	mov    -0x20(%rbp),%rsi
    1efd:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1f01:	49 89 c8             	mov    %rcx,%r8
    1f04:	b9 00 00 00 00       	mov    $0x0,%ecx
    1f09:	48 89 c7             	mov    %rax,%rdi
    1f0c:	e8 31 fd ff ff       	callq  1c42 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes>
    1f11:	85 c0                	test   %eax,%eax
    1f13:	0f 94 c0             	sete   %al
    1f16:	84 c0                	test   %al,%al
    1f18:	74 19                	je     1f33 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1c8>
            {
                if (offset != NULL) *offset = 0;
    1f1a:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    1f1f:	74 0b                	je     1f2c <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1c1>
    1f21:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1f25:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
                return 0;
    1f2c:	b8 00 00 00 00       	mov    $0x0,%eax
    1f31:	eb 12                	jmp    1f45 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1da>
        for (uint16_t id = LAYOUT_ID_TCS_DYN; id <= LAYOUT_ID_STACK_DYN_MIN; id++)
    1f33:	0f b7 45 f2          	movzwl -0xe(%rbp),%eax
    1f37:	83 c0 01             	add    $0x1,%eax
    1f3a:	66 89 45 f2          	mov    %ax,-0xe(%rbp)
    1f3e:	eb aa                	jmp    1eea <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x17f>
            }
    }
    return -1;
    1f40:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
}
    1f45:	c9                   	leaveq 
    1f46:	c3                   	retq   

0000000000001f47 <is_dynamic_thread>:

int is_dynamic_thread(void *tcs)
{
    1f47:	55                   	push   %rbp
    1f48:	48 89 e5             	mov    %rsp,%rbp
    1f4b:	48 83 ec 30          	sub    $0x30,%rsp
    1f4f:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    1f53:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    1f5a:	00 00 
    1f5c:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1f60:	31 c0                	xor    %eax,%eax
    struct dynamic_flags_attributes fa;

    if ((tcs != NULL) && (check_dynamic_range(tcs, 1, NULL, &fa) == 0) &&
    1f62:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    1f67:	74 34                	je     1f9d <is_dynamic_thread+0x56>
    1f69:	48 8d 55 e0          	lea    -0x20(%rbp),%rdx
    1f6d:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1f71:	48 89 d1             	mov    %rdx,%rcx
    1f74:	ba 00 00 00 00       	mov    $0x0,%edx
    1f79:	be 01 00 00 00       	mov    $0x1,%esi
    1f7e:	48 89 c7             	mov    %rax,%rdi
    1f81:	e8 e5 fd ff ff       	callq  1d6b <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes>
    1f86:	85 c0                	test   %eax,%eax
    1f88:	75 13                	jne    1f9d <is_dynamic_thread+0x56>
            (fa.si_flags == SI_FLAGS_TCS))
    1f8a:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    if ((tcs != NULL) && (check_dynamic_range(tcs, 1, NULL, &fa) == 0) &&
    1f8e:	48 3d 00 01 00 00    	cmp    $0x100,%rax
    1f94:	75 07                	jne    1f9d <is_dynamic_thread+0x56>
    1f96:	b8 01 00 00 00       	mov    $0x1,%eax
    1f9b:	eb 05                	jmp    1fa2 <is_dynamic_thread+0x5b>
    1f9d:	b8 00 00 00 00       	mov    $0x0,%eax
    1fa2:	84 c0                	test   %al,%al
    1fa4:	74 07                	je     1fad <is_dynamic_thread+0x66>
    {
        return true;
    1fa6:	b8 01 00 00 00       	mov    $0x1,%eax
    1fab:	eb 05                	jmp    1fb2 <is_dynamic_thread+0x6b>
    }

    return false;
    1fad:	b8 00 00 00 00       	mov    $0x0,%eax
}
    1fb2:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    1fb6:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    1fbd:	00 00 
    1fbf:	74 05                	je     1fc6 <is_dynamic_thread+0x7f>
    1fc1:	e8 a1 32 00 00       	callq  5267 <__stack_chk_fail>
    1fc6:	c9                   	leaveq 
    1fc7:	c3                   	retq   

0000000000001fc8 <is_dynamic_thread_exist>:

int is_dynamic_thread_exist()
{
    1fc8:	55                   	push   %rbp
    1fc9:	48 89 e5             	mov    %rsp,%rbp
    1fcc:	48 83 ec 10          	sub    $0x10,%rsp
    if(!EDMM_supported)
    1fd0:	48 8d 05 29 ee 00 00 	lea    0xee29(%rip),%rax        # 10e00 <EDMM_supported>
    1fd7:	8b 00                	mov    (%rax),%eax
    1fd9:	85 c0                	test   %eax,%eax
    1fdb:	75 07                	jne    1fe4 <is_dynamic_thread_exist+0x1c>
        return false;
    1fdd:	b8 00 00 00 00       	mov    $0x0,%eax
    1fe2:	eb 21                	jmp    2005 <is_dynamic_thread_exist+0x3d>
    const volatile layout_t * layout = get_dynamic_layout_by_id(LAYOUT_ID_STACK_DYN_MIN);
    1fe4:	bf 12 00 00 00       	mov    $0x12,%edi
    1fe9:	e8 34 f9 ff ff       	callq  1922 <_Z24get_dynamic_layout_by_idt>
    1fee:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if (!layout)
    1ff2:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    1ff7:	75 07                	jne    2000 <is_dynamic_thread_exist+0x38>
        return false;
    1ff9:	b8 00 00 00 00       	mov    $0x0,%eax
    1ffe:	eb 05                	jmp    2005 <is_dynamic_thread_exist+0x3d>
    else
        return true;
    2000:	b8 01 00 00 00       	mov    $0x1,%eax
}
    2005:	c9                   	leaveq 
    2006:	c3                   	retq   

0000000000002007 <get_dynamic_stack_max_page>:


uint32_t get_dynamic_stack_max_page()
{
    2007:	55                   	push   %rbp
    2008:	48 89 e5             	mov    %rsp,%rbp
    200b:	48 83 ec 10          	sub    $0x10,%rsp
    const volatile layout_t * layout = get_dynamic_layout_by_id(LAYOUT_ID_STACK_MAX);
    200f:	bf 07 00 00 00       	mov    $0x7,%edi
    2014:	e8 09 f9 ff ff       	callq  1922 <_Z24get_dynamic_layout_by_idt>
    2019:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if (!layout)
    201d:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    2022:	75 07                	jne    202b <get_dynamic_stack_max_page+0x24>
        return 0;
    2024:	b8 00 00 00 00       	mov    $0x0,%eax
    2029:	eb 07                	jmp    2032 <get_dynamic_stack_max_page+0x2b>
    else
        return layout->entry.page_count;
    202b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    202f:	8b 40 04             	mov    0x4(%rax),%eax
}
    2032:	c9                   	leaveq 
    2033:	c3                   	retq   

0000000000002034 <sgx_accept_forward>:
#endif

int sgx_accept_forward(si_flags_t sfl, size_t lo, size_t hi)
{
    2034:	4c 8d 54 24 08       	lea    0x8(%rsp),%r10
    2039:	48 83 e4 c0          	and    $0xffffffffffffffc0,%rsp
    203d:	41 ff 72 f8          	pushq  -0x8(%r10)
    2041:	55                   	push   %rbp
    2042:	48 89 e5             	mov    %rsp,%rbp
    2045:	41 52                	push   %r10
    2047:	48 81 ec e8 00 00 00 	sub    $0xe8,%rsp
    204e:	48 89 bd 38 ff ff ff 	mov    %rdi,-0xc8(%rbp)
    2055:	48 89 b5 30 ff ff ff 	mov    %rsi,-0xd0(%rbp)
    205c:	48 89 95 28 ff ff ff 	mov    %rdx,-0xd8(%rbp)
    2063:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    206a:	00 00 
    206c:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    2070:	31 c0                	xor    %eax,%eax
    (void)sfl;
    (void)lo;
    (void)hi;
    return 0;
#else
    size_t addr = lo;
    2072:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    2079:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    SE_DECLSPEC_ALIGN(sizeof(sec_info_t)) sec_info_t si;
    si.flags = sfl;
    2080:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    2087:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    for (uint16_t i = 0; i < (sizeof(si.reserved)/sizeof(si.reserved[0])); i++)
    208e:	66 c7 85 42 ff ff ff 	movw   $0x0,-0xbe(%rbp)
    2095:	00 00 
    2097:	66 83 bd 42 ff ff ff 	cmpw   $0x6,-0xbe(%rbp)
    209e:	06 
    209f:	77 28                	ja     20c9 <sgx_accept_forward+0x95>
        si.reserved[i] = 0;
    20a1:	0f b7 85 42 ff ff ff 	movzwl -0xbe(%rbp),%eax
    20a8:	48 98                	cltq   
    20aa:	48 c7 84 c5 58 ff ff 	movq   $0x0,-0xa8(%rbp,%rax,8)
    20b1:	ff 00 00 00 00 
    for (uint16_t i = 0; i < (sizeof(si.reserved)/sizeof(si.reserved[0])); i++)
    20b6:	0f b7 85 42 ff ff ff 	movzwl -0xbe(%rbp),%eax
    20bd:	83 c0 01             	add    $0x1,%eax
    20c0:	66 89 85 42 ff ff ff 	mov    %ax,-0xbe(%rbp)
    20c7:	eb ce                	jmp    2097 <sgx_accept_forward+0x63>

    while (addr < hi)
    20c9:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    20d0:	48 3b 85 28 ff ff ff 	cmp    -0xd8(%rbp),%rax
    20d7:	73 3a                	jae    2113 <sgx_accept_forward+0xdf>
    {
        int rc = do_eaccept(&si, addr);
    20d9:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    20e0:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
    20e7:	48 89 d6             	mov    %rdx,%rsi
    20ea:	48 89 c7             	mov    %rax,%rdi
    20ed:	e8 1b a8 00 00       	callq  c90d <do_eaccept>
    20f2:	89 85 44 ff ff ff    	mov    %eax,-0xbc(%rbp)
        if (rc != 0)
    20f8:	83 bd 44 ff ff ff 00 	cmpl   $0x0,-0xbc(%rbp)
    20ff:	74 05                	je     2106 <sgx_accept_forward+0xd2>
            abort();
    2101:	e8 55 a8 00 00       	callq  c95b <abort>
        addr += SE_PAGE_SIZE;
    2106:	48 81 85 48 ff ff ff 	addq   $0x1000,-0xb8(%rbp)
    210d:	00 10 00 00 
    while (addr < hi)
    2111:	eb b6                	jmp    20c9 <sgx_accept_forward+0x95>
    }

    return 0;
    2113:	b8 00 00 00 00       	mov    $0x0,%eax
#endif
}
    2118:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    211c:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    2123:	00 00 
    2125:	74 05                	je     212c <sgx_accept_forward+0xf8>
    2127:	e8 3b 31 00 00       	callq  5267 <__stack_chk_fail>
    212c:	48 81 c4 e8 00 00 00 	add    $0xe8,%rsp
    2133:	41 5a                	pop    %r10
    2135:	5d                   	pop    %rbp
    2136:	49 8d 62 f8          	lea    -0x8(%r10),%rsp
    213a:	c3                   	retq   

000000000000213b <apply_pages_within_exception>:

// High level API to EACCEPT pages, mainly used in exception handling
// to deal with stack expansion. 
int apply_pages_within_exception(void *start_address, size_t page_count)
{
    213b:	55                   	push   %rbp
    213c:	48 89 e5             	mov    %rsp,%rbp
    213f:	48 83 ec 30          	sub    $0x30,%rsp
    2143:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    2147:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    (void)page_count;
    return 0;
#else
    int rc;

    if (start_address == NULL)
    214b:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    2150:	75 07                	jne    2159 <apply_pages_within_exception+0x1e>
        return -1;
    2152:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    2157:	eb 61                	jmp    21ba <apply_pages_within_exception+0x7f>
    
    if (check_dynamic_range(start_address, page_count, NULL, NULL) != 0)
    2159:	48 8b 75 d0          	mov    -0x30(%rbp),%rsi
    215d:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2161:	b9 00 00 00 00       	mov    $0x0,%ecx
    2166:	ba 00 00 00 00       	mov    $0x0,%edx
    216b:	48 89 c7             	mov    %rax,%rdi
    216e:	e8 f8 fb ff ff       	callq  1d6b <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes>
    2173:	85 c0                	test   %eax,%eax
    2175:	0f 95 c0             	setne  %al
    2178:	84 c0                	test   %al,%al
    217a:	74 07                	je     2183 <apply_pages_within_exception+0x48>
        return -1;
    217c:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    2181:	eb 37                	jmp    21ba <apply_pages_within_exception+0x7f>

    size_t start = (size_t)start_address;
    2183:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2187:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    size_t end = start + (page_count << SE_PAGE_SHIFT);
    218b:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    218f:	48 c1 e0 0c          	shl    $0xc,%rax
    2193:	48 89 c2             	mov    %rax,%rdx
    2196:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    219a:	48 01 d0             	add    %rdx,%rax
    219d:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

    rc = sgx_accept_forward_within_exception(start, end);
    21a1:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    21a5:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    21a9:	48 89 d6             	mov    %rdx,%rsi
    21ac:	48 89 c7             	mov    %rax,%rdi
    21af:	e8 43 f6 ff ff       	callq  17f7 <_ZL35sgx_accept_forward_within_exceptionmm>
    21b4:	89 45 ec             	mov    %eax,-0x14(%rbp)

    return rc;
    21b7:	8b 45 ec             	mov    -0x14(%rbp),%eax
#endif

}
    21ba:	c9                   	leaveq 
    21bb:	c3                   	retq   

00000000000021bc <apply_EPC_pages>:

// High level API to EACCEPT pages
int apply_EPC_pages(void *start_address, size_t page_count)
{
    21bc:	55                   	push   %rbp
    21bd:	48 89 e5             	mov    %rsp,%rbp
    21c0:	48 83 ec 50          	sub    $0x50,%rsp
    21c4:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    21c8:	48 89 75 b0          	mov    %rsi,-0x50(%rbp)
    21cc:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    21d3:	00 00 
    21d5:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    21d9:	31 c0                	xor    %eax,%eax
    return 0;
#else
    int rc;
    struct dynamic_flags_attributes fa;

    if (start_address == NULL)
    21db:	48 83 7d b8 00       	cmpq   $0x0,-0x48(%rbp)
    21e0:	75 0a                	jne    21ec <apply_EPC_pages+0x30>
        return -1;
    21e2:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    21e7:	e9 8d 00 00 00       	jmpq   2279 <apply_EPC_pages+0xbd>
    
    if (check_dynamic_range(start_address, page_count, NULL, &fa) != 0)
    21ec:	48 8d 55 e0          	lea    -0x20(%rbp),%rdx
    21f0:	48 8b 75 b0          	mov    -0x50(%rbp),%rsi
    21f4:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    21f8:	48 89 d1             	mov    %rdx,%rcx
    21fb:	ba 00 00 00 00       	mov    $0x0,%edx
    2200:	48 89 c7             	mov    %rax,%rdi
    2203:	e8 63 fb ff ff       	callq  1d6b <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes>
    2208:	85 c0                	test   %eax,%eax
    220a:	0f 95 c0             	setne  %al
    220d:	84 c0                	test   %al,%al
    220f:	74 07                	je     2218 <apply_EPC_pages+0x5c>
        return -1;
    2211:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    2216:	eb 61                	jmp    2279 <apply_EPC_pages+0xbd>

    size_t start = (size_t)start_address;
    2218:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    221c:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    size_t end = start + (page_count << SE_PAGE_SHIFT);
    2220:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    2224:	48 c1 e0 0c          	shl    $0xc,%rax
    2228:	48 89 c2             	mov    %rax,%rdx
    222b:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    222f:	48 01 d0             	add    %rdx,%rax
    2232:	48 89 45 d8          	mov    %rax,-0x28(%rbp)

    if (fa.attributes & PAGE_DIR_GROW_DOWN)
    2236:	0f b7 45 e8          	movzwl -0x18(%rbp),%eax
    223a:	0f b7 c0             	movzwl %ax,%eax
    223d:	83 e0 40             	and    $0x40,%eax
    2240:	85 c0                	test   %eax,%eax
    2242:	74 1a                	je     225e <apply_EPC_pages+0xa2>
    {
        rc = sgx_accept_forward(SI_FLAGS_RW | SI_FLAG_PENDING, start, end);
    2244:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    2248:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    224c:	48 89 c6             	mov    %rax,%rsi
    224f:	bf 0b 02 00 00       	mov    $0x20b,%edi
    2254:	e8 db fd ff ff       	callq  2034 <sgx_accept_forward>
    2259:	89 45 cc             	mov    %eax,-0x34(%rbp)
    225c:	eb 18                	jmp    2276 <apply_EPC_pages+0xba>
    }
    else
    {
        rc = sgx_accept_backward(SI_FLAGS_RW | SI_FLAG_PENDING, start, end);
    225e:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    2262:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2266:	48 89 c6             	mov    %rax,%rsi
    2269:	bf 0b 02 00 00       	mov    $0x20b,%edi
    226e:	e8 7f f4 ff ff       	callq  16f2 <_ZL19sgx_accept_backwardmmm>
    2273:	89 45 cc             	mov    %eax,-0x34(%rbp)
    }

    return rc;
    2276:	8b 45 cc             	mov    -0x34(%rbp),%eax
#endif
}
    2279:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    227d:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    2284:	00 00 
    2286:	74 05                	je     228d <apply_EPC_pages+0xd1>
    2288:	e8 da 2f 00 00       	callq  5267 <__stack_chk_fail>
    228d:	c9                   	leaveq 
    228e:	c3                   	retq   

000000000000228f <trim_EPC_pages>:

// High level API to trim previously EAUG-ed pages.
int trim_EPC_pages(void *start_address, size_t page_count)
{
    228f:	55                   	push   %rbp
    2290:	48 89 e5             	mov    %rsp,%rbp
    2293:	48 83 ec 30          	sub    $0x30,%rsp
    2297:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    229b:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    (void)page_count;
    return 0;
#else
    int rc;

    if (start_address == NULL)
    229f:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    22a4:	75 0a                	jne    22b0 <trim_EPC_pages+0x21>
        return -1;
    22a6:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    22ab:	e9 16 01 00 00       	jmpq   23c6 <trim_EPC_pages+0x137>

    // check range
    if (check_dynamic_range(start_address, page_count, NULL, NULL) != 0)
    22b0:	48 8b 75 d0          	mov    -0x30(%rbp),%rsi
    22b4:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    22b8:	b9 00 00 00 00       	mov    $0x0,%ecx
    22bd:	ba 00 00 00 00       	mov    $0x0,%edx
    22c2:	48 89 c7             	mov    %rax,%rdi
    22c5:	e8 a1 fa ff ff       	callq  1d6b <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes>
    22ca:	85 c0                	test   %eax,%eax
    22cc:	0f 95 c0             	setne  %al
    22cf:	84 c0                	test   %al,%al
    22d1:	74 0a                	je     22dd <trim_EPC_pages+0x4e>
        return -1;
    22d3:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    22d8:	e9 e9 00 00 00       	jmpq   23c6 <trim_EPC_pages+0x137>

    size_t start = (size_t)start_address;
    22dd:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    22e1:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    size_t end = start + (page_count << SE_PAGE_SHIFT);
    22e5:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    22e9:	48 c1 e0 0c          	shl    $0xc,%rax
    22ed:	48 89 c2             	mov    %rax,%rdx
    22f0:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    22f4:	48 01 d0             	add    %rdx,%rax
    22f7:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

    // trim ocall
    rc = trim_range_ocall(start, end);
    22fb:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    22ff:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2303:	48 89 d6             	mov    %rdx,%rsi
    2306:	48 89 c7             	mov    %rax,%rdi
    2309:	e8 9f 14 00 00       	callq  37ad <trim_range_ocall>
    230e:	89 45 e4             	mov    %eax,-0x1c(%rbp)
    assert(rc == 0);
    2311:	83 7d e4 00          	cmpl   $0x0,-0x1c(%rbp)
    2315:	74 1f                	je     2336 <trim_EPC_pages+0xa7>
    2317:	48 8d 0d ea ac 00 00 	lea    0xacea(%rip),%rcx        # d008 <g_dyn_entry_table+0x8>
    231e:	48 8d 15 03 ad 00 00 	lea    0xad03(%rip),%rdx        # d028 <_ZZ14trim_EPC_pagesE8__func__>
    2325:	be 9e 01 00 00       	mov    $0x19e,%esi
    232a:	48 8d 3d df ac 00 00 	lea    0xacdf(%rip),%rdi        # d010 <g_dyn_entry_table+0x10>
    2331:	e8 3a 2f 00 00       	callq  5270 <__assert>

    rc = sgx_accept_forward(SI_FLAG_TRIM | SI_FLAG_MODIFIED, start, end);
    2336:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    233a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    233e:	48 89 c6             	mov    %rax,%rsi
    2341:	bf 10 04 00 00       	mov    $0x410,%edi
    2346:	e8 e9 fc ff ff       	callq  2034 <sgx_accept_forward>
    234b:	89 45 e4             	mov    %eax,-0x1c(%rbp)
    assert(rc == 0);
    234e:	83 7d e4 00          	cmpl   $0x0,-0x1c(%rbp)
    2352:	74 1f                	je     2373 <trim_EPC_pages+0xe4>
    2354:	48 8d 0d ad ac 00 00 	lea    0xacad(%rip),%rcx        # d008 <g_dyn_entry_table+0x8>
    235b:	48 8d 15 c6 ac 00 00 	lea    0xacc6(%rip),%rdx        # d028 <_ZZ14trim_EPC_pagesE8__func__>
    2362:	be a1 01 00 00       	mov    $0x1a1,%esi
    2367:	48 8d 3d a2 ac 00 00 	lea    0xaca2(%rip),%rdi        # d010 <g_dyn_entry_table+0x10>
    236e:	e8 fd 2e 00 00       	callq  5270 <__assert>
    
    // trim commit ocall
    size_t i = start;
    2373:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2377:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    while (i < end)
    237b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    237f:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    2383:	73 3e                	jae    23c3 <trim_EPC_pages+0x134>
    {
        rc = trim_range_commit_ocall(i);
    2385:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2389:	48 89 c7             	mov    %rax,%rdi
    238c:	e8 91 14 00 00       	callq  3822 <trim_range_commit_ocall>
    2391:	89 45 e4             	mov    %eax,-0x1c(%rbp)
        assert(rc == 0);
    2394:	83 7d e4 00          	cmpl   $0x0,-0x1c(%rbp)
    2398:	74 1f                	je     23b9 <trim_EPC_pages+0x12a>
    239a:	48 8d 0d 67 ac 00 00 	lea    0xac67(%rip),%rcx        # d008 <g_dyn_entry_table+0x8>
    23a1:	48 8d 15 80 ac 00 00 	lea    0xac80(%rip),%rdx        # d028 <_ZZ14trim_EPC_pagesE8__func__>
    23a8:	be a8 01 00 00       	mov    $0x1a8,%esi
    23ad:	48 8d 3d 5c ac 00 00 	lea    0xac5c(%rip),%rdi        # d010 <g_dyn_entry_table+0x10>
    23b4:	e8 b7 2e 00 00       	callq  5270 <__assert>
        i += SE_PAGE_SIZE;
    23b9:	48 81 45 e8 00 10 00 	addq   $0x1000,-0x18(%rbp)
    23c0:	00 
    while (i < end)
    23c1:	eb b8                	jmp    237b <trim_EPC_pages+0xec>
    }

    return rc;
    23c3:	8b 45 e4             	mov    -0x1c(%rbp),%eax
#endif
}
    23c6:	c9                   	leaveq 
    23c7:	c3                   	retq   

00000000000023c8 <do_add_thread>:

// Create a thread dynamically.
// It will add necessary pages and transform one of them into type TCS.
sgx_status_t do_add_thread(void *ptcs)
{
    23c8:	55                   	push   %rbp
    23c9:	48 89 e5             	mov    %rsp,%rbp
    23cc:	48 83 ec 50          	sub    $0x50,%rsp
    23d0:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    23d4:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    23db:	00 00 
    23dd:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    23e1:	31 c0                	xor    %eax,%eax
#ifdef SE_SIM
    (void)ptcs;
    return SGX_SUCCESS;
#else
    int ret = SGX_ERROR_UNEXPECTED;
    23e3:	c7 45 c4 01 00 00 00 	movl   $0x1,-0x3c(%rbp)
    tcs_t *tcs = (tcs_t *)ptcs;
    23ea:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    23ee:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    tcs_t *tcs_template = NULL;
    23f2:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    23f9:	00 
    size_t offset = 0;
    23fa:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    2401:	00 
    size_t enclave_base = (size_t)get_enclave_base();
    2402:	e8 ea a1 00 00       	callq  c5f1 <get_enclave_base>
    2407:	48 89 45 e0          	mov    %rax,-0x20(%rbp)

    if ( 0 != check_dynamic_range((void *)tcs, 1, &offset, NULL))
    240b:	48 8d 55 c8          	lea    -0x38(%rbp),%rdx
    240f:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2413:	b9 00 00 00 00       	mov    $0x0,%ecx
    2418:	be 01 00 00 00       	mov    $0x1,%esi
    241d:	48 89 c7             	mov    %rax,%rdi
    2420:	e8 46 f9 ff ff       	callq  1d6b <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes>
    2425:	85 c0                	test   %eax,%eax
    2427:	0f 95 c0             	setne  %al
    242a:	84 c0                	test   %al,%al
    242c:	74 0a                	je     2438 <do_add_thread+0x70>
        return SGX_ERROR_UNEXPECTED;
    242e:	b8 01 00 00 00       	mov    $0x1,%eax
    2433:	e9 bb 01 00 00       	jmpq   25f3 <do_add_thread+0x22b>

    // check if the tcs provided exactly matches the one in signtool
    const volatile layout_t *tcs_layout = get_dynamic_layout_by_id(LAYOUT_ID_TCS_DYN);
    2438:	bf 0e 00 00 00       	mov    $0xe,%edi
    243d:	e8 e0 f4 ff ff       	callq  1922 <_Z24get_dynamic_layout_by_idt>
    2442:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    if (!tcs_layout)
    2446:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    244b:	75 0a                	jne    2457 <do_add_thread+0x8f>
        return SGX_ERROR_UNEXPECTED;
    244d:	b8 01 00 00 00       	mov    $0x1,%eax
    2452:	e9 9c 01 00 00       	jmpq   25f3 <do_add_thread+0x22b>

    if ((size_t)(enclave_base + tcs_layout->entry.rva + offset) != (size_t)(tcs))
    2457:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    245b:	48 8b 50 08          	mov    0x8(%rax),%rdx
    245f:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    2463:	48 01 c2             	add    %rax,%rdx
    2466:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    246a:	48 01 c2             	add    %rax,%rdx
    246d:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2471:	48 39 c2             	cmp    %rax,%rdx
    2474:	0f 95 c0             	setne  %al
    2477:	84 c0                	test   %al,%al
    2479:	74 0a                	je     2485 <do_add_thread+0xbd>
        return SGX_ERROR_UNEXPECTED;
    247b:	b8 01 00 00 00       	mov    $0x1,%eax
    2480:	e9 6e 01 00 00       	jmpq   25f3 <do_add_thread+0x22b>

    // adding page for all the dynamic entries
    for (uint16_t id = LAYOUT_ID_TCS_DYN; id <= LAYOUT_ID_STACK_DYN_MIN; id++)
    2485:	66 c7 45 c2 0e 00    	movw   $0xe,-0x3e(%rbp)
    248b:	66 83 7d c2 12       	cmpw   $0x12,-0x3e(%rbp)
    2490:	0f 87 85 00 00 00    	ja     251b <do_add_thread+0x153>
    {
        const volatile layout_t *layout =  get_dynamic_layout_by_id(id);
    2496:	0f b7 45 c2          	movzwl -0x3e(%rbp),%eax
    249a:	89 c7                	mov    %eax,%edi
    249c:	e8 81 f4 ff ff       	callq  1922 <_Z24get_dynamic_layout_by_idt>
    24a1:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
        if (layout && (layout->entry.attributes & PAGE_ATTR_DYN_THREAD))
    24a5:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    24aa:	74 19                	je     24c5 <do_add_thread+0xfd>
    24ac:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    24b0:	0f b7 40 02          	movzwl 0x2(%rax),%eax
    24b4:	0f b7 c0             	movzwl %ax,%eax
    24b7:	83 e0 20             	and    $0x20,%eax
    24ba:	85 c0                	test   %eax,%eax
    24bc:	74 07                	je     24c5 <do_add_thread+0xfd>
    24be:	b8 01 00 00 00       	mov    $0x1,%eax
    24c3:	eb 05                	jmp    24ca <do_add_thread+0x102>
    24c5:	b8 00 00 00 00       	mov    $0x0,%eax
    24ca:	84 c0                	test   %al,%al
    24cc:	74 3d                	je     250b <do_add_thread+0x143>
        {
            ret = apply_EPC_pages((void *)(enclave_base + layout->entry.rva + offset), layout->entry.page_count);
    24ce:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    24d2:	8b 40 04             	mov    0x4(%rax),%eax
    24d5:	89 c1                	mov    %eax,%ecx
    24d7:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    24db:	48 8b 50 08          	mov    0x8(%rax),%rdx
    24df:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    24e3:	48 01 c2             	add    %rax,%rdx
    24e6:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    24ea:	48 01 d0             	add    %rdx,%rax
    24ed:	48 89 ce             	mov    %rcx,%rsi
    24f0:	48 89 c7             	mov    %rax,%rdi
    24f3:	e8 c4 fc ff ff       	callq  21bc <apply_EPC_pages>
    24f8:	89 45 c4             	mov    %eax,-0x3c(%rbp)
            if (ret != 0)
    24fb:	83 7d c4 00          	cmpl   $0x0,-0x3c(%rbp)
    24ff:	74 0a                	je     250b <do_add_thread+0x143>
                return SGX_ERROR_UNEXPECTED;
    2501:	b8 01 00 00 00       	mov    $0x1,%eax
    2506:	e9 e8 00 00 00       	jmpq   25f3 <do_add_thread+0x22b>
    for (uint16_t id = LAYOUT_ID_TCS_DYN; id <= LAYOUT_ID_STACK_DYN_MIN; id++)
    250b:	0f b7 45 c2          	movzwl -0x3e(%rbp),%eax
    250f:	83 c0 01             	add    $0x1,%eax
    2512:	66 89 45 c2          	mov    %ax,-0x3e(%rbp)
    2516:	e9 70 ff ff ff       	jmpq   248b <do_add_thread+0xc3>
        }
    }

    //Copy and initialize TCS
    tcs_template = (tcs_t *)g_global_data.tcs_template;
    251b:	48 8d 05 5e ac 00 00 	lea    0xac5e(%rip),%rax        # d180 <g_global_data>
    2522:	48 8d 80 e0 00 00 00 	lea    0xe0(%rax),%rax
    2529:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    memcpy_s(tcs, TCS_SIZE, tcs_template, sizeof(g_global_data.tcs_template));
    252d:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    2531:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2535:	b9 48 00 00 00       	mov    $0x48,%ecx
    253a:	be 00 10 00 00       	mov    $0x1000,%esi
    253f:	48 89 c7             	mov    %rax,%rdi
    2542:	e8 64 f1 ff ff       	callq  16ab <memcpy_s>

    //Adjust the tcs fields
    tcs->ossa = (size_t)GET_PTR(size_t, (void *)tcs, tcs->ossa) - enclave_base;
    2547:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    254b:	48 8b 50 10          	mov    0x10(%rax),%rdx
    254f:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2553:	48 01 d0             	add    %rdx,%rax
    2556:	48 2b 45 e0          	sub    -0x20(%rbp),%rax
    255a:	48 89 c2             	mov    %rax,%rdx
    255d:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2561:	48 89 50 10          	mov    %rdx,0x10(%rax)
    tcs->ofs_base = (size_t)GET_PTR(size_t, (void *)tcs, tcs->ofs_base) - enclave_base;
    2565:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2569:	48 8b 50 30          	mov    0x30(%rax),%rdx
    256d:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2571:	48 01 d0             	add    %rdx,%rax
    2574:	48 2b 45 e0          	sub    -0x20(%rbp),%rax
    2578:	48 89 c2             	mov    %rax,%rdx
    257b:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    257f:	48 89 50 30          	mov    %rdx,0x30(%rax)
    tcs->ogs_base = (size_t)GET_PTR(size_t, (void *)tcs, tcs->ogs_base) - enclave_base;
    2583:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2587:	48 8b 50 38          	mov    0x38(%rax),%rdx
    258b:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    258f:	48 01 d0             	add    %rdx,%rax
    2592:	48 2b 45 e0          	sub    -0x20(%rbp),%rax
    2596:	48 89 c2             	mov    %rax,%rdx
    2599:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    259d:	48 89 50 38          	mov    %rdx,0x38(%rax)

    //OCALL for MKTCS
    ret = sgx_ocall(0, tcs);
    25a1:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    25a5:	48 89 c6             	mov    %rax,%rsi
    25a8:	bf 00 00 00 00       	mov    $0x0,%edi
    25ad:	e8 1d 10 00 00       	callq  35cf <sgx_ocall>
    25b2:	89 45 c4             	mov    %eax,-0x3c(%rbp)
    if (ret != 0)
    25b5:	83 7d c4 00          	cmpl   $0x0,-0x3c(%rbp)
    25b9:	74 07                	je     25c2 <do_add_thread+0x1fa>
        return SGX_ERROR_UNEXPECTED;
    25bb:	b8 01 00 00 00       	mov    $0x1,%eax
    25c0:	eb 31                	jmp    25f3 <do_add_thread+0x22b>

    //EACCEPT for MKTCS
    ret = sgx_accept_backward(SI_FLAG_TCS | SI_FLAG_MODIFIED, (size_t)tcs, (size_t)tcs + SE_PAGE_SIZE);
    25c2:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    25c6:	48 8d 90 00 10 00 00 	lea    0x1000(%rax),%rdx
    25cd:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    25d1:	48 89 c6             	mov    %rax,%rsi
    25d4:	bf 10 01 00 00       	mov    $0x110,%edi
    25d9:	e8 14 f1 ff ff       	callq  16f2 <_ZL19sgx_accept_backwardmmm>
    25de:	89 45 c4             	mov    %eax,-0x3c(%rbp)
    if (ret != 0)
    25e1:	83 7d c4 00          	cmpl   $0x0,-0x3c(%rbp)
    25e5:	74 07                	je     25ee <do_add_thread+0x226>
        return SGX_ERROR_UNEXPECTED;
    25e7:	b8 01 00 00 00       	mov    $0x1,%eax
    25ec:	eb 05                	jmp    25f3 <do_add_thread+0x22b>

    return SGX_SUCCESS;
    25ee:	b8 00 00 00 00       	mov    $0x0,%eax

#endif
}
    25f3:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    25f7:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    25fe:	00 00 
    2600:	74 05                	je     2607 <do_add_thread+0x23f>
    2602:	e8 60 2c 00 00       	callq  5267 <__stack_chk_fail>
    2607:	c9                   	leaveq 
    2608:	c3                   	retq   

0000000000002609 <memcpy_s>:
{
    2609:	55                   	push   %rbp
    260a:	48 89 e5             	mov    %rsp,%rbp
    260d:	48 83 ec 20          	sub    $0x20,%rsp
    2611:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    2615:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    2619:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    261d:	48 89 4d e0          	mov    %rcx,-0x20(%rbp)
    if(numberOfElements<count)
    2621:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2625:	48 3b 45 e0          	cmp    -0x20(%rbp),%rax
    2629:	73 07                	jae    2632 <memcpy_s+0x29>
        return -1;
    262b:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    2630:	eb 1c                	jmp    264e <memcpy_s+0x45>
    memcpy(dest, src, count);
    2632:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    2636:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
    263a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    263e:	48 89 ce             	mov    %rcx,%rsi
    2641:	48 89 c7             	mov    %rax,%rdi
    2644:	e8 76 88 00 00       	callq  aebf <memcpy>
    return 0;
    2649:	b8 00 00 00 00       	mov    $0x0,%eax
}
    264e:	c9                   	leaveq 
    264f:	c3                   	retq   

0000000000002650 <_pthread_thread_run>:

#include "pthread_imp.h"
#include "sgx_random_buffers.h"
#include "se_page_attr.h"

__attribute__((weak)) sgx_status_t _pthread_thread_run(void* ms) {UNUSED(ms); return SGX_SUCCESS;}
    2650:	55                   	push   %rbp
    2651:	48 89 e5             	mov    %rsp,%rbp
    2654:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    2658:	b8 00 00 00 00       	mov    $0x0,%eax
    265d:	5d                   	pop    %rbp
    265e:	c3                   	retq   

000000000000265f <_Z16_pthread_enabledv>:
__attribute__((weak)) bool _pthread_enabled() {return false;}
    265f:	55                   	push   %rbp
    2660:	48 89 e5             	mov    %rsp,%rbp
    2663:	b8 00 00 00 00       	mov    $0x0,%eax
    2668:	5d                   	pop    %rbp
    2669:	c3                   	retq   

000000000000266a <_Z24_pthread_tls_store_state9_status_t>:
__attribute__((weak)) void _pthread_tls_store_state(sgx_status_t state) {UNUSED(state);}
    266a:	55                   	push   %rbp
    266b:	48 89 e5             	mov    %rsp,%rbp
    266e:	89 7d fc             	mov    %edi,-0x4(%rbp)
    2671:	90                   	nop
    2672:	5d                   	pop    %rbp
    2673:	c3                   	retq   

0000000000002674 <_Z22_pthread_tls_get_statev>:
__attribute__((weak)) sgx_status_t _pthread_tls_get_state(void) {return SGX_SUCCESS;}
    2674:	55                   	push   %rbp
    2675:	48 89 e5             	mov    %rsp,%rbp
    2678:	b8 00 00 00 00       	mov    $0x0,%eax
    267d:	5d                   	pop    %rbp
    267e:	c3                   	retq   

000000000000267f <_Z26_pthread_tls_store_contextPv>:
__attribute__((weak)) void _pthread_tls_store_context(void* context) {UNUSED(context);}
    267f:	55                   	push   %rbp
    2680:	48 89 e5             	mov    %rsp,%rbp
    2683:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    2687:	90                   	nop
    2688:	5d                   	pop    %rbp
    2689:	c3                   	retq   

000000000000268a <_Z20_pthread_wakeup_joinPv>:
__attribute__((weak)) void _pthread_wakeup_join(void* ms) {UNUSED(ms);}
    268a:	55                   	push   %rbp
    268b:	48 89 e5             	mov    %rsp,%rbp
    268e:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    2692:	90                   	nop
    2693:	5d                   	pop    %rbp
    2694:	c3                   	retq   

0000000000002695 <_Z24_pthread_tls_destructorsv>:
__attribute__((weak)) void _pthread_tls_destructors(void) {}
    2695:	55                   	push   %rbp
    2696:	48 89 e5             	mov    %rsp,%rbp
    2699:	90                   	nop
    269a:	5d                   	pop    %rbp
    269b:	c3                   	retq   

000000000000269c <_ZL16is_ecall_allowedj>:

// is_ecall_allowed()
// check the index in the dynamic entry table
static sgx_status_t is_ecall_allowed(uint32_t ordinal)
{
    269c:	55                   	push   %rbp
    269d:	48 89 e5             	mov    %rsp,%rbp
    26a0:	48 83 ec 30          	sub    $0x30,%rsp
    26a4:	89 7d dc             	mov    %edi,-0x24(%rbp)
    if(ordinal >= g_ecall_table.nr_ecall)
    26a7:	8b 55 dc             	mov    -0x24(%rbp),%edx
    26aa:	48 8d 05 2f e7 00 00 	lea    0xe72f(%rip),%rax        # 10de0 <g_ecall_table>
    26b1:	48 8b 00             	mov    (%rax),%rax
    26b4:	48 39 c2             	cmp    %rax,%rdx
    26b7:	72 0a                	jb     26c3 <_ZL16is_ecall_allowedj+0x27>
    {
        return SGX_ERROR_INVALID_FUNCTION;
    26b9:	b8 01 10 00 00       	mov    $0x1001,%eax
    26be:	e9 c7 00 00 00       	jmpq   278a <_ZL16is_ecall_allowedj+0xee>
    }
    thread_data_t *thread_data = get_thread_data();
    26c3:	e8 64 9f 00 00       	callq  c62c <get_thread_data>
    26c8:	48 89 45 e8          	mov    %rax,-0x18(%rbp)

    sgx_lfence();
    26cc:	0f ae e8             	lfence 

    if(thread_data->last_sp == thread_data->stack_base_addr)
    26cf:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    26d3:	48 8b 50 08          	mov    0x8(%rax),%rdx
    26d7:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    26db:	48 8b 40 10          	mov    0x10(%rax),%rax
    26df:	48 39 c2             	cmp    %rax,%rdx
    26e2:	75 2d                	jne    2711 <_ZL16is_ecall_allowedj+0x75>
    {
        // root ECALL, check the priv bits.
        if (g_ecall_table.ecall_table[ordinal].is_priv)
    26e4:	48 8d 05 f5 e6 00 00 	lea    0xe6f5(%rip),%rax        # 10de0 <g_ecall_table>
    26eb:	8b 55 dc             	mov    -0x24(%rbp),%edx
    26ee:	48 c1 e2 04          	shl    $0x4,%rdx
    26f2:	48 01 d0             	add    %rdx,%rax
    26f5:	48 83 c0 10          	add    $0x10,%rax
    26f9:	0f b6 00             	movzbl (%rax),%eax
    26fc:	84 c0                	test   %al,%al
    26fe:	74 0a                	je     270a <_ZL16is_ecall_allowedj+0x6e>
            return SGX_ERROR_ECALL_NOT_ALLOWED;
    2700:	b8 07 10 00 00       	mov    $0x1007,%eax
    2705:	e9 80 00 00 00       	jmpq   278a <_ZL16is_ecall_allowedj+0xee>
        return SGX_SUCCESS;
    270a:	b8 00 00 00 00       	mov    $0x0,%eax
    270f:	eb 79                	jmp    278a <_ZL16is_ecall_allowedj+0xee>
    }
    ocall_context_t *context = reinterpret_cast<ocall_context_t*>(thread_data->last_sp);
    2711:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2715:	48 8b 40 08          	mov    0x8(%rax),%rax
    2719:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    if(context->ocall_flag != OCALL_FLAG)
    271d:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2721:	48 8b 40 20          	mov    0x20(%rax),%rax
    2725:	48 3d 44 49 43 4f    	cmp    $0x4f434944,%rax
    272b:	74 05                	je     2732 <_ZL16is_ecall_allowedj+0x96>
    {
        // abort the enclave if ocall frame is invalid
        abort();
    272d:	e8 29 a2 00 00       	callq  c95b <abort>
    }
    uintptr_t ocall_index = context->ocall_index;
    2732:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2736:	48 8b 40 28          	mov    0x28(%rax),%rax
    273a:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if(ocall_index >= g_dyn_entry_table.nr_ocall)
    273e:	48 8d 05 bb a8 00 00 	lea    0xa8bb(%rip),%rax        # d000 <g_dyn_entry_table>
    2745:	48 8b 00             	mov    (%rax),%rax
    2748:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    274c:	72 07                	jb     2755 <_ZL16is_ecall_allowedj+0xb9>
    {
        return SGX_ERROR_INVALID_FUNCTION;
    274e:	b8 01 10 00 00       	mov    $0x1001,%eax
    2753:	eb 35                	jmp    278a <_ZL16is_ecall_allowedj+0xee>
    }
    return (g_dyn_entry_table.entry_table[ocall_index * g_ecall_table.nr_ecall + ordinal] ? SGX_SUCCESS : SGX_ERROR_ECALL_NOT_ALLOWED);
    2755:	48 8d 05 84 e6 00 00 	lea    0xe684(%rip),%rax        # 10de0 <g_ecall_table>
    275c:	48 8b 00             	mov    (%rax),%rax
    275f:	48 0f af 45 f8       	imul   -0x8(%rbp),%rax
    2764:	48 89 c2             	mov    %rax,%rdx
    2767:	8b 45 dc             	mov    -0x24(%rbp),%eax
    276a:	48 01 c2             	add    %rax,%rdx
    276d:	48 8d 05 8c a8 00 00 	lea    0xa88c(%rip),%rax        # d000 <g_dyn_entry_table>
    2774:	0f b6 44 10 08       	movzbl 0x8(%rax,%rdx,1),%eax
    2779:	84 c0                	test   %al,%al
    277b:	74 07                	je     2784 <_ZL16is_ecall_allowedj+0xe8>
    277d:	b8 00 00 00 00       	mov    $0x0,%eax
    2782:	eb 05                	jmp    2789 <_ZL16is_ecall_allowedj+0xed>
    2784:	b8 07 10 00 00       	mov    $0x1007,%eax
    2789:	90                   	nop
}
    278a:	c9                   	leaveq 
    278b:	c3                   	retq   

000000000000278c <_ZL13get_func_addrjPPv>:
// Return Value:
//      non-zero - success
//      zero - fail
//
static sgx_status_t get_func_addr(uint32_t ordinal, void **addr)
{
    278c:	55                   	push   %rbp
    278d:	48 89 e5             	mov    %rsp,%rbp
    2790:	48 83 ec 20          	sub    $0x20,%rsp
    2794:	89 7d ec             	mov    %edi,-0x14(%rbp)
    2797:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    if(ordinal == (uint32_t)ECMD_ECALL_PTHREAD)
    279b:	83 7d ec fa          	cmpl   $0xfffffffa,-0x14(%rbp)
    279f:	75 15                	jne    27b6 <_ZL13get_func_addrjPPv+0x2a>
    {
        *addr = (void*) _pthread_thread_run;
    27a1:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    27a5:	48 8d 15 a4 fe ff ff 	lea    -0x15c(%rip),%rdx        # 2650 <_pthread_thread_run>
    27ac:	48 89 10             	mov    %rdx,(%rax)
        return SGX_SUCCESS;
    27af:	b8 00 00 00 00       	mov    $0x0,%eax
    27b4:	eb 60                	jmp    2816 <_ZL13get_func_addrjPPv+0x8a>
    }

    // Normal user-defined ECalls
    sgx_status_t status = is_ecall_allowed(ordinal);
    27b6:	8b 45 ec             	mov    -0x14(%rbp),%eax
    27b9:	89 c7                	mov    %eax,%edi
    27bb:	e8 dc fe ff ff       	callq  269c <_ZL16is_ecall_allowedj>
    27c0:	89 45 fc             	mov    %eax,-0x4(%rbp)
    if(SGX_SUCCESS != status)
    27c3:	83 7d fc 00          	cmpl   $0x0,-0x4(%rbp)
    27c7:	74 05                	je     27ce <_ZL13get_func_addrjPPv+0x42>
    {
        return status;
    27c9:	8b 45 fc             	mov    -0x4(%rbp),%eax
    27cc:	eb 48                	jmp    2816 <_ZL13get_func_addrjPPv+0x8a>
    }

    *addr = const_cast<void *>(g_ecall_table.ecall_table[ordinal].ecall_addr);
    27ce:	48 8d 05 0b e6 00 00 	lea    0xe60b(%rip),%rax        # 10de0 <g_ecall_table>
    27d5:	8b 55 ec             	mov    -0x14(%rbp),%edx
    27d8:	48 c1 e2 04          	shl    $0x4,%rdx
    27dc:	48 01 d0             	add    %rdx,%rax
    27df:	48 83 c0 08          	add    $0x8,%rax
    27e3:	48 8b 10             	mov    (%rax),%rdx
    27e6:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    27ea:	48 89 10             	mov    %rdx,(%rax)
    if(!sgx_is_within_enclave(*addr, 0))
    27ed:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    27f1:	48 8b 00             	mov    (%rax),%rax
    27f4:	be 00 00 00 00       	mov    $0x0,%esi
    27f9:	48 89 c7             	mov    %rax,%rdi
    27fc:	e8 91 ea ff ff       	callq  1292 <sgx_is_within_enclave>
    2801:	85 c0                	test   %eax,%eax
    2803:	0f 94 c0             	sete   %al
    2806:	84 c0                	test   %al,%al
    2808:	74 07                	je     2811 <_ZL13get_func_addrjPPv+0x85>
    {
        return SGX_ERROR_UNEXPECTED;
    280a:	b8 01 00 00 00       	mov    $0x1,%eax
    280f:	eb 05                	jmp    2816 <_ZL13get_func_addrjPPv+0x8a>
    }

    return SGX_SUCCESS;
    2811:	b8 00 00 00 00       	mov    $0x0,%eax
}
    2816:	c9                   	leaveq 
    2817:	c3                   	retq   

0000000000002818 <_Z11do_save_tcsPv>:
// Return Value:
//     zero - success
//     non-zero - fail
//
sgx_status_t do_save_tcs(void *ptcs)
{
    2818:	55                   	push   %rbp
    2819:	48 89 e5             	mov    %rsp,%rbp
    281c:	48 83 ec 30          	sub    $0x30,%rsp
    2820:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    2824:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    282b:	00 00 
    282d:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    2831:	31 c0                	xor    %eax,%eax
    if(!is_utility_thread())
    2833:	e8 1c 14 00 00       	callq  3c54 <is_utility_thread>
    2838:	83 f0 01             	xor    $0x1,%eax
    283b:	84 c0                	test   %al,%al
    283d:	74 0a                	je     2849 <_Z11do_save_tcsPv+0x31>
        return SGX_ERROR_UNEXPECTED;
    283f:	b8 01 00 00 00       	mov    $0x1,%eax
    2844:	e9 b0 00 00 00       	jmpq   28f9 <_Z11do_save_tcsPv+0xe1>

    if(unlikely(g_tcs_cookie == 0))
    2849:	48 8b 05 78 e8 00 00 	mov    0xe878(%rip),%rax        # 110c8 <_ZL12g_tcs_cookie>
    2850:	48 85 c0             	test   %rax,%rax
    2853:	0f 94 c0             	sete   %al
    2856:	0f b6 c0             	movzbl %al,%eax
    2859:	48 85 c0             	test   %rax,%rax
    285c:	74 4b                	je     28a9 <_Z11do_save_tcsPv+0x91>
    {
        uintptr_t rand = 0;
    285e:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    2865:	00 
        do
        {
            if(SGX_SUCCESS != sgx_read_rand((unsigned char *)&rand, sizeof(rand)))
    2866:	48 8d 45 e8          	lea    -0x18(%rbp),%rax
    286a:	be 08 00 00 00       	mov    $0x8,%esi
    286f:	48 89 c7             	mov    %rax,%rdi
    2872:	e8 e1 ec ff ff       	callq  1558 <sgx_read_rand>
    2877:	85 c0                	test   %eax,%eax
    2879:	0f 95 c0             	setne  %al
    287c:	84 c0                	test   %al,%al
    287e:	74 07                	je     2887 <_Z11do_save_tcsPv+0x6f>
            {
                return SGX_ERROR_UNEXPECTED;
    2880:	b8 01 00 00 00       	mov    $0x1,%eax
    2885:	eb 72                	jmp    28f9 <_Z11do_save_tcsPv+0xe1>
            }
        } while(rand == 0);
    2887:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    288b:	48 85 c0             	test   %rax,%rax
    288e:	75 02                	jne    2892 <_Z11do_save_tcsPv+0x7a>
        do
    2890:	eb d4                	jmp    2866 <_Z11do_save_tcsPv+0x4e>

        if(g_tcs_cookie == 0)
    2892:	48 8b 05 2f e8 00 00 	mov    0xe82f(%rip),%rax        # 110c8 <_ZL12g_tcs_cookie>
    2899:	48 85 c0             	test   %rax,%rax
    289c:	75 0b                	jne    28a9 <_Z11do_save_tcsPv+0x91>
        {
            g_tcs_cookie = rand;
    289e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    28a2:	48 89 05 1f e8 00 00 	mov    %rax,0xe81f(%rip)        # 110c8 <_ZL12g_tcs_cookie>
        }
    }

    tcs_node_t *tcs_node = (tcs_node_t *)malloc(sizeof(tcs_node_t));
    28a9:	bf 10 00 00 00       	mov    $0x10,%edi
    28ae:	e8 82 64 00 00       	callq  8d35 <dlmalloc>
    28b3:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    if(!tcs_node)
    28b7:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    28bc:	75 07                	jne    28c5 <_Z11do_save_tcsPv+0xad>
    {
        return SGX_ERROR_UNEXPECTED;
    28be:	b8 01 00 00 00       	mov    $0x1,%eax
    28c3:	eb 34                	jmp    28f9 <_Z11do_save_tcsPv+0xe1>
    }

    tcs_node->tcs = ENC_TCS_POINTER(ptcs);
    28c5:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    28c9:	48 8b 05 f8 e7 00 00 	mov    0xe7f8(%rip),%rax        # 110c8 <_ZL12g_tcs_cookie>
    28d0:	48 31 c2             	xor    %rax,%rdx
    28d3:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    28d7:	48 89 10             	mov    %rdx,(%rax)

    tcs_node->next = g_tcs_node;
    28da:	48 8b 15 df e7 00 00 	mov    0xe7df(%rip),%rdx        # 110c0 <_ZL10g_tcs_node>
    28e1:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    28e5:	48 89 50 08          	mov    %rdx,0x8(%rax)
    g_tcs_node = tcs_node;
    28e9:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    28ed:	48 89 05 cc e7 00 00 	mov    %rax,0xe7cc(%rip)        # 110c0 <_ZL10g_tcs_node>

    return SGX_SUCCESS;
    28f4:	b8 00 00 00 00       	mov    $0x0,%eax
}
    28f9:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    28fd:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    2904:	00 00 
    2906:	74 05                	je     290d <_Z11do_save_tcsPv+0xf5>
    2908:	e8 5a 29 00 00       	callq  5267 <__stack_chk_fail>
    290d:	c9                   	leaveq 
    290e:	c3                   	retq   

000000000000290f <_ZL10do_del_tcsPv>:
//      [IN] ptcs - the tcs_t pointer which need to be deleted
// Return Value:
//     N/A
//
static void do_del_tcs(void *ptcs)
{
    290f:	55                   	push   %rbp
    2910:	48 89 e5             	mov    %rsp,%rbp
    2913:	48 83 ec 30          	sub    $0x30,%rsp
    2917:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    if(!is_utility_thread())
    291b:	e8 34 13 00 00       	callq  3c54 <is_utility_thread>
    2920:	83 f0 01             	xor    $0x1,%eax
    2923:	84 c0                	test   %al,%al
    2925:	0f 85 c1 00 00 00    	jne    29ec <_ZL10do_del_tcsPv+0xdd>
        return;

    if (g_tcs_node != NULL)
    292b:	48 8b 05 8e e7 00 00 	mov    0xe78e(%rip),%rax        # 110c0 <_ZL10g_tcs_node>
    2932:	48 85 c0             	test   %rax,%rax
    2935:	0f 84 b2 00 00 00    	je     29ed <_ZL10do_del_tcsPv+0xde>
    {
        if (DEC_TCS_POINTER(g_tcs_node->tcs) == ptcs)
    293b:	48 8b 05 7e e7 00 00 	mov    0xe77e(%rip),%rax        # 110c0 <_ZL10g_tcs_node>
    2942:	48 8b 10             	mov    (%rax),%rdx
    2945:	48 8b 05 7c e7 00 00 	mov    0xe77c(%rip),%rax        # 110c8 <_ZL12g_tcs_cookie>
    294c:	48 31 d0             	xor    %rdx,%rax
    294f:	48 39 45 d8          	cmp    %rax,-0x28(%rbp)
    2953:	75 2b                	jne    2980 <_ZL10do_del_tcsPv+0x71>
        {
            tcs_node_t *tmp = g_tcs_node;
    2955:	48 8b 05 64 e7 00 00 	mov    0xe764(%rip),%rax        # 110c0 <_ZL10g_tcs_node>
    295c:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
            g_tcs_node = g_tcs_node->next;
    2960:	48 8b 05 59 e7 00 00 	mov    0xe759(%rip),%rax        # 110c0 <_ZL10g_tcs_node>
    2967:	48 8b 40 08          	mov    0x8(%rax),%rax
    296b:	48 89 05 4e e7 00 00 	mov    %rax,0xe74e(%rip)        # 110c0 <_ZL10g_tcs_node>
            free(tmp);
    2972:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    2976:	48 89 c7             	mov    %rax,%rdi
    2979:	e8 ae 6e 00 00       	callq  982c <dlfree>
    297e:	eb 6d                	jmp    29ed <_ZL10do_del_tcsPv+0xde>
        }
        else
        {
            tcs_node_t *tcs_node = g_tcs_node->next;
    2980:	48 8b 05 39 e7 00 00 	mov    0xe739(%rip),%rax        # 110c0 <_ZL10g_tcs_node>
    2987:	48 8b 40 08          	mov    0x8(%rax),%rax
    298b:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
            tcs_node_t *pre_tcs_node = g_tcs_node;
    298f:	48 8b 05 2a e7 00 00 	mov    0xe72a(%rip),%rax        # 110c0 <_ZL10g_tcs_node>
    2996:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
            while (tcs_node != NULL)
    299a:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    299f:	74 4c                	je     29ed <_ZL10do_del_tcsPv+0xde>
            {
                if (DEC_TCS_POINTER(tcs_node->tcs) == ptcs)
    29a1:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    29a5:	48 8b 10             	mov    (%rax),%rdx
    29a8:	48 8b 05 19 e7 00 00 	mov    0xe719(%rip),%rax        # 110c8 <_ZL12g_tcs_cookie>
    29af:	48 31 d0             	xor    %rdx,%rax
    29b2:	48 39 45 d8          	cmp    %rax,-0x28(%rbp)
    29b6:	75 1e                	jne    29d6 <_ZL10do_del_tcsPv+0xc7>
                {
                    pre_tcs_node->next = tcs_node->next;
    29b8:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    29bc:	48 8b 50 08          	mov    0x8(%rax),%rdx
    29c0:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    29c4:	48 89 50 08          	mov    %rdx,0x8(%rax)
                    free(tcs_node);
    29c8:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    29cc:	48 89 c7             	mov    %rax,%rdi
    29cf:	e8 58 6e 00 00       	callq  982c <dlfree>
                    break;
    29d4:	eb 17                	jmp    29ed <_ZL10do_del_tcsPv+0xde>
                }

                pre_tcs_node = tcs_node;
    29d6:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    29da:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
                tcs_node = tcs_node->next;
    29de:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    29e2:	48 8b 40 08          	mov    0x8(%rax),%rax
    29e6:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
            while (tcs_node != NULL)
    29ea:	eb ae                	jmp    299a <_ZL10do_del_tcsPv+0x8b>
        return;
    29ec:	90                   	nop
            }
        }
    }
}
    29ed:	c9                   	leaveq 
    29ee:	c3                   	retq   

00000000000029ef <_ZL10trts_ecalljPv>:
static volatile bool           g_is_first_ecall = true;
static volatile sgx_spinlock_t g_ife_lock       = SGX_SPINLOCK_INITIALIZER;

typedef sgx_status_t (*ecall_func_t)(void *ms);
static sgx_status_t trts_ecall(uint32_t ordinal, void *ms)
{
    29ef:	55                   	push   %rbp
    29f0:	48 89 e5             	mov    %rsp,%rbp
    29f3:	48 83 ec 40          	sub    $0x40,%rsp
    29f7:	89 7d cc             	mov    %edi,-0x34(%rbp)
    29fa:	48 89 75 c0          	mov    %rsi,-0x40(%rbp)
    29fe:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    2a05:	00 00 
    2a07:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    2a0b:	31 c0                	xor    %eax,%eax
    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    2a0d:	c7 45 d4 01 00 00 00 	movl   $0x1,-0x2c(%rbp)

    if (unlikely(g_is_first_ecall))
    2a14:	0f b6 05 e5 e5 00 00 	movzbl 0xe5e5(%rip),%eax        # 11000 <_ZL16g_is_first_ecall>
    2a1b:	0f b6 c0             	movzbl %al,%eax
    2a1e:	48 85 c0             	test   %rax,%rax
    2a21:	0f 95 c0             	setne  %al
    2a24:	84 c0                	test   %al,%al
    2a26:	0f 84 9a 00 00 00    	je     2ac6 <_ZL10trts_ecalljPv+0xd7>
    {
        // The thread performing the global initialization cannot do a nested ECall
        thread_data_t *thread_data = get_thread_data();
    2a2c:	e8 fb 9b 00 00       	callq  c62c <get_thread_data>
    2a31:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
        if (thread_data->last_sp != thread_data->stack_base_addr)
    2a35:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    2a39:	48 8b 50 08          	mov    0x8(%rax),%rdx
    2a3d:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    2a41:	48 8b 40 10          	mov    0x10(%rax),%rax
    2a45:	48 39 c2             	cmp    %rax,%rdx
    2a48:	74 0a                	je     2a54 <_ZL10trts_ecalljPv+0x65>
        { // nested ecall
            return SGX_ERROR_ECALL_NOT_ALLOWED;
    2a4a:	b8 07 10 00 00       	mov    $0x1007,%eax
    2a4f:	e9 b2 00 00 00       	jmpq   2b06 <_ZL10trts_ecalljPv+0x117>
        }

        sgx_spin_lock(&g_ife_lock);
    2a54:	48 8d 3d 75 e6 00 00 	lea    0xe675(%rip),%rdi        # 110d0 <_ZL10g_ife_lock>
    2a5b:	e8 2c 89 00 00       	callq  b38c <sgx_spin_lock>
        if (g_is_first_ecall)
    2a60:	0f b6 05 99 e5 00 00 	movzbl 0xe599(%rip),%eax        # 11000 <_ZL16g_is_first_ecall>
    2a67:	84 c0                	test   %al,%al
    2a69:	74 4f                	je     2aba <_ZL10trts_ecalljPv+0xcb>
        {
#ifndef SE_SIM
            if(EDMM_supported)
    2a6b:	48 8d 05 8e e3 00 00 	lea    0xe38e(%rip),%rax        # 10e00 <EDMM_supported>
    2a72:	8b 00                	mov    (%rax),%eax
    2a74:	85 c0                	test   %eax,%eax
    2a76:	74 36                	je     2aae <_ZL10trts_ecalljPv+0xbf>
            {
                //change back the page permission
                size_t enclave_start = (size_t)&__ImageBase;
    2a78:	48 8d 05 81 d5 ff ff 	lea    -0x2a7f(%rip),%rax        # 0 <enclave.so>
    2a7f:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
                if((status = change_protection((void *)enclave_start)) != SGX_SUCCESS)
    2a83:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2a87:	48 89 c7             	mov    %rax,%rdi
    2a8a:	e8 13 23 00 00       	callq  4da2 <change_protection>
    2a8f:	89 45 d4             	mov    %eax,-0x2c(%rbp)
    2a92:	83 7d d4 00          	cmpl   $0x0,-0x2c(%rbp)
    2a96:	0f 95 c0             	setne  %al
    2a99:	84 c0                	test   %al,%al
    2a9b:	74 11                	je     2aae <_ZL10trts_ecalljPv+0xbf>
                {
                    sgx_spin_unlock(&g_ife_lock);
    2a9d:	48 8d 3d 2c e6 00 00 	lea    0xe62c(%rip),%rdi        # 110d0 <_ZL10g_ife_lock>
    2aa4:	e8 4a 89 00 00       	callq  b3f3 <sgx_spin_unlock>
                    return status;
    2aa9:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    2aac:	eb 58                	jmp    2b06 <_ZL10trts_ecalljPv+0x117>
                }
            }
#endif
            //invoke global object's construction
            init_global_object();
    2aae:	e8 97 27 00 00       	callq  524a <init_global_object>
            g_is_first_ecall = false;
    2ab3:	c6 05 46 e5 00 00 00 	movb   $0x0,0xe546(%rip)        # 11000 <_ZL16g_is_first_ecall>
        }
        sgx_spin_unlock(&g_ife_lock);
    2aba:	48 8d 3d 0f e6 00 00 	lea    0xe60f(%rip),%rdi        # 110d0 <_ZL10g_ife_lock>
    2ac1:	e8 2d 89 00 00       	callq  b3f3 <sgx_spin_unlock>
    }

    void *addr = NULL;
    2ac6:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    2acd:	00 
    status = get_func_addr(ordinal, &addr);
    2ace:	48 8d 55 d8          	lea    -0x28(%rbp),%rdx
    2ad2:	8b 45 cc             	mov    -0x34(%rbp),%eax
    2ad5:	48 89 d6             	mov    %rdx,%rsi
    2ad8:	89 c7                	mov    %eax,%edi
    2ada:	e8 ad fc ff ff       	callq  278c <_ZL13get_func_addrjPPv>
    2adf:	89 45 d4             	mov    %eax,-0x2c(%rbp)
    if(status == SGX_SUCCESS)
    2ae2:	83 7d d4 00          	cmpl   $0x0,-0x2c(%rbp)
    2ae6:	75 1b                	jne    2b03 <_ZL10trts_ecalljPv+0x114>
    {
        ecall_func_t func = (ecall_func_t)addr;
    2ae8:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2aec:	48 89 45 f0          	mov    %rax,-0x10(%rbp)

        sgx_lfence();
    2af0:	0f ae e8             	lfence 

        status = func(ms);
    2af3:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    2af7:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2afb:	48 89 d7             	mov    %rdx,%rdi
    2afe:	ff d0                	callq  *%rax
    2b00:	89 45 d4             	mov    %eax,-0x2c(%rbp)
    }
    
    return status;
    2b03:	8b 45 d4             	mov    -0x2c(%rbp),%eax
}
    2b06:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    2b0a:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    2b11:	00 00 
    2b13:	74 05                	je     2b1a <_ZL10trts_ecalljPv+0x12b>
    2b15:	e8 4d 27 00 00       	callq  5267 <__stack_chk_fail>
    2b1a:	c9                   	leaveq 
    2b1b:	c3                   	retq   

0000000000002b1c <_ZL24init_static_stack_canaryPv>:

extern "C" uintptr_t __stack_chk_guard;
static void init_static_stack_canary(void *tcs)
{
    2b1c:	55                   	push   %rbp
    2b1d:	48 89 e5             	mov    %rsp,%rbp
    2b20:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    size_t *canary = TCS2CANARY(tcs);
    2b24:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2b28:	48 2d a8 02 01 00    	sub    $0x102a8,%rax
    2b2e:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    *canary = (size_t)__stack_chk_guard;
    2b32:	48 8d 05 d7 e2 00 00 	lea    0xe2d7(%rip),%rax        # 10e10 <__intel_security_cookie>
    2b39:	48 8b 10             	mov    (%rax),%rdx
    2b3c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    2b40:	48 89 10             	mov    %rdx,(%rax)
}
    2b43:	90                   	nop
    2b44:	5d                   	pop    %rbp
    2b45:	c3                   	retq   

0000000000002b46 <do_init_thread>:

sgx_status_t do_init_thread(void *tcs, bool enclave_init)
{
    2b46:	55                   	push   %rbp
    2b47:	48 89 e5             	mov    %rsp,%rbp
    2b4a:	48 83 ec 50          	sub    $0x50,%rsp
    2b4e:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    2b52:	89 f0                	mov    %esi,%eax
    2b54:	88 45 b4             	mov    %al,-0x4c(%rbp)
    2b57:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    2b5e:	00 00 
    2b60:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    2b64:	31 c0                	xor    %eax,%eax
    thread_data_t *thread_data = GET_PTR(thread_data_t, tcs, g_global_data.td_template.self_addr);
    2b66:	48 8d 05 13 a6 00 00 	lea    0xa613(%rip),%rax        # d180 <g_global_data>
    2b6d:	48 8b 50 40          	mov    0x40(%rax),%rdx
    2b71:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2b75:	48 01 d0             	add    %rdx,%rax
    2b78:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
#ifndef SE_SIM
    size_t saved_stack_commit_addr = thread_data->stack_commit_addr;
    2b7c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2b80:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    2b87:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    bool thread_first_init = (saved_stack_commit_addr == 0) ? true : false;
    2b8b:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
    2b90:	0f 94 c0             	sete   %al
    2b93:	88 45 c3             	mov    %al,-0x3d(%rbp)
#endif
    size_t stack_guard = thread_data->stack_guard;
    2b96:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2b9a:	48 8b 40 28          	mov    0x28(%rax),%rax
    2b9e:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    size_t thread_flags = thread_data->flags;
    2ba2:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2ba6:	48 8b 40 30          	mov    0x30(%rax),%rax
    2baa:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    memcpy_s(thread_data, SE_PAGE_SIZE, const_cast<thread_data_t *>(&g_global_data.td_template), sizeof(thread_data_t));
    2bae:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2bb2:	b9 a0 00 00 00       	mov    $0xa0,%ecx
    2bb7:	48 8d 15 c2 a5 00 00 	lea    0xa5c2(%rip),%rdx        # d180 <g_global_data>
    2bbe:	48 8d 52 40          	lea    0x40(%rdx),%rdx
    2bc2:	be 00 10 00 00       	mov    $0x1000,%esi
    2bc7:	48 89 c7             	mov    %rax,%rdi
    2bca:	e8 3a fa ff ff       	callq  2609 <memcpy_s>
    thread_data->last_sp += (size_t)tcs;
    2bcf:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2bd3:	48 8b 50 08          	mov    0x8(%rax),%rdx
    2bd7:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2bdb:	48 01 c2             	add    %rax,%rdx
    2bde:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2be2:	48 89 50 08          	mov    %rdx,0x8(%rax)
    thread_data->self_addr += (size_t)tcs;
    2be6:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2bea:	48 8b 10             	mov    (%rax),%rdx
    2bed:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2bf1:	48 01 c2             	add    %rax,%rdx
    2bf4:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2bf8:	48 89 10             	mov    %rdx,(%rax)
    thread_data->stack_base_addr += (size_t)tcs;
    2bfb:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2bff:	48 8b 50 10          	mov    0x10(%rax),%rdx
    2c03:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2c07:	48 01 c2             	add    %rax,%rdx
    2c0a:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c0e:	48 89 50 10          	mov    %rdx,0x10(%rax)
    thread_data->stack_limit_addr += (size_t)tcs;
    2c12:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c16:	48 8b 50 18          	mov    0x18(%rax),%rdx
    2c1a:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2c1e:	48 01 c2             	add    %rax,%rdx
    2c21:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c25:	48 89 50 18          	mov    %rdx,0x18(%rax)
    thread_data->stack_commit_addr = thread_data->stack_limit_addr;
    2c29:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c2d:	48 8b 50 18          	mov    0x18(%rax),%rdx
    2c31:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c35:	48 89 90 98 00 00 00 	mov    %rdx,0x98(%rax)
    thread_data->first_ssa_gpr += (size_t)tcs;
    2c3c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c40:	48 8b 50 20          	mov    0x20(%rax),%rdx
    2c44:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2c48:	48 01 c2             	add    %rax,%rdx
    2c4b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c4f:	48 89 50 20          	mov    %rdx,0x20(%rax)
    thread_data->tls_array += (size_t)tcs;
    2c53:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c57:	48 8b 50 58          	mov    0x58(%rax),%rdx
    2c5b:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2c5f:	48 01 c2             	add    %rax,%rdx
    2c62:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c66:	48 89 50 58          	mov    %rdx,0x58(%rax)
    thread_data->tls_addr += (size_t)tcs;
    2c6a:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c6e:	48 8b 50 50          	mov    0x50(%rax),%rdx
    2c72:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2c76:	48 01 c2             	add    %rax,%rdx
    2c79:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c7d:	48 89 50 50          	mov    %rdx,0x50(%rax)
    thread_data->last_sp -= (size_t)STATIC_STACK_SIZE;
    2c81:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c85:	48 8b 40 08          	mov    0x8(%rax),%rax
    2c89:	48 8d 90 50 fd ff ff 	lea    -0x2b0(%rax),%rdx
    2c90:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c94:	48 89 50 08          	mov    %rdx,0x8(%rax)
    thread_data->stack_base_addr -= (size_t)STATIC_STACK_SIZE;
    2c98:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c9c:	48 8b 40 10          	mov    0x10(%rax),%rax
    2ca0:	48 8d 90 50 fd ff ff 	lea    -0x2b0(%rax),%rdx
    2ca7:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2cab:	48 89 50 10          	mov    %rdx,0x10(%rax)
    thread_data->stack_guard = stack_guard;
    2caf:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2cb3:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    2cb7:	48 89 50 28          	mov    %rdx,0x28(%rax)
    thread_data->flags = thread_flags;
    2cbb:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2cbf:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    2cc3:	48 89 50 30          	mov    %rdx,0x30(%rax)
    init_static_stack_canary(tcs);
    2cc7:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2ccb:	48 89 c7             	mov    %rax,%rdi
    2cce:	e8 49 fe ff ff       	callq  2b1c <_ZL24init_static_stack_canaryPv>

    if (EDMM_supported && enclave_init)
    2cd3:	48 8d 05 26 e1 00 00 	lea    0xe126(%rip),%rax        # 10e00 <EDMM_supported>
    2cda:	8b 00                	mov    (%rax),%eax
    2cdc:	85 c0                	test   %eax,%eax
    2cde:	74 12                	je     2cf2 <do_init_thread+0x1ac>
    2ce0:	80 7d b4 00          	cmpb   $0x0,-0x4c(%rbp)
    2ce4:	74 0c                	je     2cf2 <do_init_thread+0x1ac>
    {
        thread_data->flags = SGX_UTILITY_THREAD;
    2ce6:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2cea:	48 c7 40 30 01 00 00 	movq   $0x1,0x30(%rax)
    2cf1:	00 
    }
#ifndef SE_SIM
    if (thread_first_init)
    2cf2:	80 7d c3 00          	cmpb   $0x0,-0x3d(%rbp)
    2cf6:	74 5d                	je     2d55 <do_init_thread+0x20f>
    {
        if (EDMM_supported && (enclave_init || is_dynamic_thread(tcs)))
    2cf8:	48 8d 05 01 e1 00 00 	lea    0xe101(%rip),%rax        # 10e00 <EDMM_supported>
    2cff:	8b 00                	mov    (%rax),%eax
    2d01:	85 c0                	test   %eax,%eax
    2d03:	74 1d                	je     2d22 <do_init_thread+0x1dc>
    2d05:	80 7d b4 00          	cmpb   $0x0,-0x4c(%rbp)
    2d09:	75 10                	jne    2d1b <do_init_thread+0x1d5>
    2d0b:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2d0f:	48 89 c7             	mov    %rax,%rdi
    2d12:	e8 30 f2 ff ff       	callq  1f47 <is_dynamic_thread>
    2d17:	85 c0                	test   %eax,%eax
    2d19:	74 07                	je     2d22 <do_init_thread+0x1dc>
    2d1b:	b8 01 00 00 00       	mov    $0x1,%eax
    2d20:	eb 05                	jmp    2d27 <do_init_thread+0x1e1>
    2d22:	b8 00 00 00 00       	mov    $0x0,%eax
    2d27:	84 c0                	test   %al,%al
    2d29:	74 39                	je     2d64 <do_init_thread+0x21e>
        {
            uint32_t page_count = get_dynamic_stack_max_page();
    2d2b:	e8 d7 f2 ff ff       	callq  2007 <get_dynamic_stack_max_page>
    2d30:	89 45 c4             	mov    %eax,-0x3c(%rbp)
            thread_data->stack_commit_addr += ((sys_word_t)page_count << SE_PAGE_SHIFT);
    2d33:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2d37:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    2d3e:	8b 55 c4             	mov    -0x3c(%rbp),%edx
    2d41:	48 c1 e2 0c          	shl    $0xc,%rdx
    2d45:	48 01 c2             	add    %rax,%rdx
    2d48:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2d4c:	48 89 90 98 00 00 00 	mov    %rdx,0x98(%rax)
    2d53:	eb 0f                	jmp    2d64 <do_init_thread+0x21e>
        }
    }
    else
    {
        thread_data->stack_commit_addr = saved_stack_commit_addr;
    2d55:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2d59:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    2d5d:	48 89 90 98 00 00 00 	mov    %rdx,0x98(%rax)
    }
#endif

    uintptr_t tls_addr = 0;
    2d64:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    2d6b:	00 
    size_t tdata_size = 0;
    2d6c:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    2d73:	00 

    if(0 != GET_TLS_INFO(&__ImageBase, &tls_addr, &tdata_size))
    2d74:	48 8d 55 d0          	lea    -0x30(%rbp),%rdx
    2d78:	48 8d 45 c8          	lea    -0x38(%rbp),%rax
    2d7c:	48 89 c6             	mov    %rax,%rsi
    2d7f:	48 8d 05 7a d2 ff ff 	lea    -0x2d86(%rip),%rax        # 0 <enclave.so>
    2d86:	48 89 c7             	mov    %rax,%rdi
    2d89:	e8 80 1b 00 00       	callq  490e <elf_tls_info>
    2d8e:	85 c0                	test   %eax,%eax
    2d90:	0f 95 c0             	setne  %al
    2d93:	84 c0                	test   %al,%al
    2d95:	74 0a                	je     2da1 <do_init_thread+0x25b>
    {
        return SGX_ERROR_UNEXPECTED;
    2d97:	b8 01 00 00 00       	mov    $0x1,%eax
    2d9c:	e9 83 00 00 00       	jmpq   2e24 <do_init_thread+0x2de>
    }
    if(tls_addr)
    2da1:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    2da5:	48 85 c0             	test   %rax,%rax
    2da8:	74 75                	je     2e1f <do_init_thread+0x2d9>
    {
        memset((void *)TRIM_TO_PAGE(thread_data->tls_addr), 0, ROUND_TO_PAGE(thread_data->self_addr - thread_data->tls_addr));
    2daa:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2dae:	48 8b 10             	mov    (%rax),%rdx
    2db1:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2db5:	48 8b 40 50          	mov    0x50(%rax),%rax
    2db9:	48 29 c2             	sub    %rax,%rdx
    2dbc:	48 89 d0             	mov    %rdx,%rax
    2dbf:	48 05 ff 0f 00 00    	add    $0xfff,%rax
    2dc5:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    2dcb:	48 89 c2             	mov    %rax,%rdx
    2dce:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2dd2:	48 8b 40 50          	mov    0x50(%rax),%rax
    2dd6:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    2ddc:	be 00 00 00 00       	mov    $0x0,%esi
    2de1:	48 89 c7             	mov    %rax,%rdi
    2de4:	e8 44 81 00 00       	callq  af2d <memset>
        memcpy_s((void *)(thread_data->tls_addr), thread_data->self_addr - thread_data->tls_addr, (void *)tls_addr, tdata_size);
    2de9:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2ded:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    2df1:	49 89 d0             	mov    %rdx,%r8
    2df4:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    2df8:	48 8b 0a             	mov    (%rdx),%rcx
    2dfb:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    2dff:	48 8b 52 50          	mov    0x50(%rdx),%rdx
    2e03:	48 29 d1             	sub    %rdx,%rcx
    2e06:	48 89 ce             	mov    %rcx,%rsi
    2e09:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    2e0d:	48 8b 52 50          	mov    0x50(%rdx),%rdx
    2e11:	48 89 d7             	mov    %rdx,%rdi
    2e14:	48 89 c1             	mov    %rax,%rcx
    2e17:	4c 89 c2             	mov    %r8,%rdx
    2e1a:	e8 ea f7 ff ff       	callq  2609 <memcpy_s>
    }

    return SGX_SUCCESS;
    2e1f:	b8 00 00 00 00       	mov    $0x0,%eax
}
    2e24:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    2e28:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    2e2f:	00 00 
    2e31:	74 05                	je     2e38 <do_init_thread+0x2f2>
    2e33:	e8 2f 24 00 00       	callq  5267 <__stack_chk_fail>
    2e38:	c9                   	leaveq 
    2e39:	c3                   	retq   

0000000000002e3a <do_ecall>:

sgx_status_t do_ecall(int index, void *ms, void *tcs)
{
    2e3a:	55                   	push   %rbp
    2e3b:	48 89 e5             	mov    %rsp,%rbp
    2e3e:	48 83 c4 80          	add    $0xffffffffffffff80,%rsp
    2e42:	89 7d 9c             	mov    %edi,-0x64(%rbp)
    2e45:	48 89 75 90          	mov    %rsi,-0x70(%rbp)
    2e49:	48 89 55 88          	mov    %rdx,-0x78(%rbp)
    2e4d:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    2e54:	00 00 
    2e56:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    2e5a:	31 c0                	xor    %eax,%eax
    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    2e5c:	c7 45 a4 01 00 00 00 	movl   $0x1,-0x5c(%rbp)
    if(ENCLAVE_INIT_DONE != get_enclave_state())
    2e63:	e8 91 97 00 00       	callq  c5f9 <get_enclave_state>
    2e68:	83 f8 02             	cmp    $0x2,%eax
    2e6b:	0f 95 c0             	setne  %al
    2e6e:	84 c0                	test   %al,%al
    2e70:	74 08                	je     2e7a <do_ecall+0x40>
    {
        return status;
    2e72:	8b 45 a4             	mov    -0x5c(%rbp),%eax
    2e75:	e9 8c 01 00 00       	jmpq   3006 <do_ecall+0x1cc>
    }
    thread_data_t *thread_data = get_thread_data();
    2e7a:	e8 ad 97 00 00       	callq  c62c <get_thread_data>
    2e7f:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    if( (NULL == thread_data) || 
    2e83:	48 83 7d a8 00       	cmpq   $0x0,-0x58(%rbp)
    2e88:	74 37                	je     2ec1 <do_ecall+0x87>
            ((thread_data->stack_base_addr == thread_data->last_sp) && 
    2e8a:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    2e8e:	48 8b 50 10          	mov    0x10(%rax),%rdx
    2e92:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    2e96:	48 8b 40 08          	mov    0x8(%rax),%rax
    if( (NULL == thread_data) || 
    2e9a:	48 39 c2             	cmp    %rax,%rdx
    2e9d:	75 29                	jne    2ec8 <do_ecall+0x8e>
                    ( (0 != g_global_data.thread_policy) ||
    2e9f:	48 8d 05 da a2 00 00 	lea    0xa2da(%rip),%rax        # d180 <g_global_data>
    2ea6:	48 8b 40 30          	mov    0x30(%rax),%rax
            ((thread_data->stack_base_addr == thread_data->last_sp) && 
    2eaa:	48 85 c0             	test   %rax,%rax
    2ead:	75 12                	jne    2ec1 <do_ecall+0x87>
                       (SGX_PTHREAD_EXIT == _pthread_tls_get_state()) ||    /*Force do initial thread if previous ECALL is exited by pthread_exit()*/
    2eaf:	e8 c0 f7 ff ff       	callq  2674 <_Z22_pthread_tls_get_statev>
                    ( (0 != g_global_data.thread_policy) ||
    2eb4:	83 f8 09             	cmp    $0x9,%eax
    2eb7:	74 08                	je     2ec1 <do_ecall+0x87>
                        (index == ECMD_ECALL_PTHREAD))))  /*Force do initial thread if this thread is created by SGX pthread_create() */
    2eb9:	8b 45 9c             	mov    -0x64(%rbp),%eax
                       (SGX_PTHREAD_EXIT == _pthread_tls_get_state()) ||    /*Force do initial thread if previous ECALL is exited by pthread_exit()*/
    2ebc:	83 f8 fa             	cmp    $0xfffffffa,%eax
    2ebf:	75 07                	jne    2ec8 <do_ecall+0x8e>
    if( (NULL == thread_data) || 
    2ec1:	b8 01 00 00 00       	mov    $0x1,%eax
    2ec6:	eb 05                	jmp    2ecd <do_ecall+0x93>
    2ec8:	b8 00 00 00 00       	mov    $0x0,%eax
    2ecd:	84 c0                	test   %al,%al
    2ecf:	74 22                	je     2ef3 <do_ecall+0xb9>
    {
        status = do_init_thread(tcs, false);
    2ed1:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    2ed5:	be 00 00 00 00       	mov    $0x0,%esi
    2eda:	48 89 c7             	mov    %rax,%rdi
    2edd:	e8 64 fc ff ff       	callq  2b46 <do_init_thread>
    2ee2:	89 45 a4             	mov    %eax,-0x5c(%rbp)
        if(0 != status)
    2ee5:	83 7d a4 00          	cmpl   $0x0,-0x5c(%rbp)
    2ee9:	74 08                	je     2ef3 <do_ecall+0xb9>
        {
            return status;
    2eeb:	8b 45 a4             	mov    -0x5c(%rbp),%eax
    2eee:	e9 13 01 00 00       	jmpq   3006 <do_ecall+0x1cc>
        }
    }
    thread_data = get_thread_data();
    2ef3:	e8 34 97 00 00       	callq  c62c <get_thread_data>
    2ef8:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    if(thread_data->stack_base_addr == thread_data->last_sp)
    2efc:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    2f00:	48 8b 50 10          	mov    0x10(%rax),%rdx
    2f04:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    2f08:	48 8b 40 08          	mov    0x8(%rax),%rax
    2f0c:	48 39 c2             	cmp    %rax,%rdx
    2f0f:	0f 85 da 00 00 00    	jne    2fef <do_ecall+0x1b5>
    {
        //root ecall
        if(_pthread_enabled())
    2f15:	e8 45 f7 ff ff       	callq  265f <_Z16_pthread_enabledv>
    2f1a:	84 c0                	test   %al,%al
    2f1c:	0f 84 b1 00 00 00    	je     2fd3 <do_ecall+0x199>
        {
            jmp_buf     buf = {0};
    2f22:	48 c7 45 b0 00 00 00 	movq   $0x0,-0x50(%rbp)
    2f29:	00 
    2f2a:	48 c7 45 b8 00 00 00 	movq   $0x0,-0x48(%rbp)
    2f31:	00 
    2f32:	48 c7 45 c0 00 00 00 	movq   $0x0,-0x40(%rbp)
    2f39:	00 
    2f3a:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    2f41:	00 
    2f42:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    2f49:	00 
    2f4a:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    2f51:	00 
    2f52:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    2f59:	00 
    2f5a:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    2f61:	00 
            if(0 == setjmp(buf))
    2f62:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    2f66:	48 89 c7             	mov    %rax,%rdi
    2f69:	e8 9e 84 00 00       	callq  b40c <_setjmp>
    2f6e:	85 c0                	test   %eax,%eax
    2f70:	0f 94 c0             	sete   %al
    2f73:	84 c0                	test   %al,%al
    2f75:	74 28                	je     2f9f <do_ecall+0x165>
            {
                _pthread_tls_store_context((void*)buf);
    2f77:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    2f7b:	48 89 c7             	mov    %rax,%rdi
    2f7e:	e8 fc f6 ff ff       	callq  267f <_Z26_pthread_tls_store_contextPv>
                status = random_stack_advance<0x800>(trts_ecall, index, ms);
    2f83:	48 8d 55 90          	lea    -0x70(%rbp),%rdx
    2f87:	48 8d 45 9c          	lea    -0x64(%rbp),%rax
    2f8b:	48 89 c6             	mov    %rax,%rsi
    2f8e:	48 8d 3d 5a fa ff ff 	lea    -0x5a6(%rip),%rdi        # 29ef <_ZL10trts_ecalljPv>
    2f95:	e8 78 04 00 00       	callq  3412 <_Z20random_stack_advanceILj2048E9_status_tJjPvEJRiRS1_EET0_PFS4_DpT1_EDpOT2_>
    2f9a:	89 45 a4             	mov    %eax,-0x5c(%rbp)
    2f9d:	eb 21                	jmp    2fc0 <do_ecall+0x186>
            }
            else
            {
                //Enter here if pthread_exit() is called inside ECALL functions.
                _pthread_tls_store_state(SGX_PTHREAD_EXIT);
    2f9f:	bf 09 00 00 00       	mov    $0x9,%edi
    2fa4:	e8 c1 f6 ff ff       	callq  266a <_Z24_pthread_tls_store_state9_status_t>
                //Important: manually reset the last_sp
                thread_data->last_sp = thread_data->stack_base_addr;
    2fa9:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    2fad:	48 8b 50 10          	mov    0x10(%rax),%rdx
    2fb1:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    2fb5:	48 89 50 08          	mov    %rdx,0x8(%rax)
                status = SGX_PTHREAD_EXIT;
    2fb9:	c7 45 a4 09 00 00 00 	movl   $0x9,-0x5c(%rbp)
            }
            //-- execute some resource recycle function here, such as tls resource recycle
            _pthread_tls_destructors();
    2fc0:	e8 d0 f6 ff ff       	callq  2695 <_Z24_pthread_tls_destructorsv>
            _pthread_wakeup_join(ms); 
    2fc5:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    2fc9:	48 89 c7             	mov    %rax,%rdi
    2fcc:	e8 b9 f6 ff ff       	callq  268a <_Z20_pthread_wakeup_joinPv>
    2fd1:	eb 30                	jmp    3003 <do_ecall+0x1c9>
        }
        else 
        {
            //sgx pthread lib isn't linked
            status = random_stack_advance<0x800>(trts_ecall, index, ms);
    2fd3:	48 8d 55 90          	lea    -0x70(%rbp),%rdx
    2fd7:	48 8d 45 9c          	lea    -0x64(%rbp),%rax
    2fdb:	48 89 c6             	mov    %rax,%rsi
    2fde:	48 8d 3d 0a fa ff ff 	lea    -0x5f6(%rip),%rdi        # 29ef <_ZL10trts_ecalljPv>
    2fe5:	e8 28 04 00 00       	callq  3412 <_Z20random_stack_advanceILj2048E9_status_tJjPvEJRiRS1_EET0_PFS4_DpT1_EDpOT2_>
    2fea:	89 45 a4             	mov    %eax,-0x5c(%rbp)
    2fed:	eb 14                	jmp    3003 <do_ecall+0x1c9>
        }
    }
    else
    {
        status = trts_ecall(index, ms);
    2fef:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    2ff3:	8b 55 9c             	mov    -0x64(%rbp),%edx
    2ff6:	48 89 c6             	mov    %rax,%rsi
    2ff9:	89 d7                	mov    %edx,%edi
    2ffb:	e8 ef f9 ff ff       	callq  29ef <_ZL10trts_ecalljPv>
    3000:	89 45 a4             	mov    %eax,-0x5c(%rbp)
    }
    return status;
    3003:	8b 45 a4             	mov    -0x5c(%rbp),%eax
}
    3006:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    300a:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    3011:	00 00 
    3013:	74 05                	je     301a <do_ecall+0x1e0>
    3015:	e8 4d 22 00 00       	callq  5267 <__stack_chk_fail>
    301a:	c9                   	leaveq 
    301b:	c3                   	retq   

000000000000301c <do_ecall_add_thread>:

sgx_status_t do_ecall_add_thread(void *ms)
{
    301c:	55                   	push   %rbp
    301d:	48 89 e5             	mov    %rsp,%rbp
    3020:	48 83 ec 30          	sub    $0x30,%rsp
    3024:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    3028:	c7 45 e4 01 00 00 00 	movl   $0x1,-0x1c(%rbp)

    if(!is_utility_thread())
    302f:	e8 20 0c 00 00       	callq  3c54 <is_utility_thread>
    3034:	83 f0 01             	xor    $0x1,%eax
    3037:	84 c0                	test   %al,%al
    3039:	74 08                	je     3043 <do_ecall_add_thread+0x27>
        return status;
    303b:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    303e:	e9 9b 00 00 00       	jmpq   30de <do_ecall_add_thread+0xc2>

    struct ms_tcs *tcs = (struct ms_tcs*)ms;
    3043:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3047:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    if (tcs == NULL)
    304b:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    3050:	75 08                	jne    305a <do_ecall_add_thread+0x3e>
    {
        return status;
    3052:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    3055:	e9 84 00 00 00       	jmpq   30de <do_ecall_add_thread+0xc2>
    }

    if (!sgx_is_outside_enclave(tcs, sizeof(struct ms_tcs)))
    305a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    305e:	be 08 00 00 00       	mov    $0x8,%esi
    3063:	48 89 c7             	mov    %rax,%rdi
    3066:	e8 b7 e2 ff ff       	callq  1322 <sgx_is_outside_enclave>
    306b:	85 c0                	test   %eax,%eax
    306d:	0f 94 c0             	sete   %al
    3070:	84 c0                	test   %al,%al
    3072:	74 05                	je     3079 <do_ecall_add_thread+0x5d>
    {
        return status;
    3074:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    3077:	eb 65                	jmp    30de <do_ecall_add_thread+0xc2>
    }

    const struct ms_tcs mtcs = *tcs;
    3079:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    307d:	48 8b 00             	mov    (%rax),%rax
    3080:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    void* ptcs = mtcs.ptcs;
    3084:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3088:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if (ptcs == NULL)
    308c:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    3091:	75 05                	jne    3098 <do_ecall_add_thread+0x7c>
    {
        return status;
    3093:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    3096:	eb 46                	jmp    30de <do_ecall_add_thread+0xc2>
    }

    sgx_lfence();
    3098:	0f ae e8             	lfence 

    status = do_save_tcs(ptcs);
    309b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    309f:	48 89 c7             	mov    %rax,%rdi
    30a2:	e8 71 f7 ff ff       	callq  2818 <_Z11do_save_tcsPv>
    30a7:	89 45 e4             	mov    %eax,-0x1c(%rbp)
    if(SGX_SUCCESS != status)
    30aa:	83 7d e4 00          	cmpl   $0x0,-0x1c(%rbp)
    30ae:	74 05                	je     30b5 <do_ecall_add_thread+0x99>
    {
        return status;
    30b0:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    30b3:	eb 29                	jmp    30de <do_ecall_add_thread+0xc2>
    }

    status = do_add_thread(ptcs);
    30b5:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    30b9:	48 89 c7             	mov    %rax,%rdi
    30bc:	e8 07 f3 ff ff       	callq  23c8 <do_add_thread>
    30c1:	89 45 e4             	mov    %eax,-0x1c(%rbp)
    if (SGX_SUCCESS != status)
    30c4:	83 7d e4 00          	cmpl   $0x0,-0x1c(%rbp)
    30c8:	74 11                	je     30db <do_ecall_add_thread+0xbf>
    {
    	do_del_tcs(ptcs);
    30ca:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    30ce:	48 89 c7             	mov    %rax,%rdi
    30d1:	e8 39 f8 ff ff       	callq  290f <_ZL10do_del_tcsPv>
        return status;
    30d6:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    30d9:	eb 03                	jmp    30de <do_ecall_add_thread+0xc2>
    }

    return status;
    30db:	8b 45 e4             	mov    -0x1c(%rbp),%eax
}
    30de:	c9                   	leaveq 
    30df:	c3                   	retq   

00000000000030e0 <do_uninit_enclave>:
// Return Value:
//     zero - success
//     non-zero - fail
//
sgx_status_t do_uninit_enclave(void *tcs)
{
    30e0:	55                   	push   %rbp
    30e1:	48 89 e5             	mov    %rsp,%rbp
    30e4:	48 83 ec 40          	sub    $0x40,%rsp
    30e8:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    // This function should only be called when
    //  1. EDMM is enabled
    //  2. on HW mode
    // urts would not call this ECALL either on simulation mode
    // or on non-EDMM supported platform.
    if (!EDMM_supported)
    30ec:	48 8d 05 0d dd 00 00 	lea    0xdd0d(%rip),%rax        # 10e00 <EDMM_supported>
    30f3:	8b 00                	mov    (%rax),%eax
    30f5:	85 c0                	test   %eax,%eax
    30f7:	75 14                	jne    310d <do_uninit_enclave+0x2d>
    {
        set_enclave_state(ENCLAVE_CRASHED);
    30f9:	bf 03 00 00 00       	mov    $0x3,%edi
    30fe:	e8 03 95 00 00       	callq  c606 <set_enclave_state>
        return SGX_ERROR_UNEXPECTED;
    3103:	b8 01 00 00 00       	mov    $0x1,%eax
    3108:	e9 4c 01 00 00       	jmpq   3259 <do_uninit_enclave+0x179>
    }

    if(!is_utility_thread() && is_dynamic_thread_exist())
    310d:	e8 42 0b 00 00       	callq  3c54 <is_utility_thread>
    3112:	83 f0 01             	xor    $0x1,%eax
    3115:	84 c0                	test   %al,%al
    3117:	74 10                	je     3129 <do_uninit_enclave+0x49>
    3119:	e8 aa ee ff ff       	callq  1fc8 <is_dynamic_thread_exist>
    311e:	85 c0                	test   %eax,%eax
    3120:	74 07                	je     3129 <do_uninit_enclave+0x49>
    3122:	b8 01 00 00 00       	mov    $0x1,%eax
    3127:	eb 05                	jmp    312e <do_uninit_enclave+0x4e>
    3129:	b8 00 00 00 00       	mov    $0x0,%eax
    312e:	84 c0                	test   %al,%al
    3130:	74 14                	je     3146 <do_uninit_enclave+0x66>
    {
        set_enclave_state(ENCLAVE_CRASHED);
    3132:	bf 03 00 00 00       	mov    $0x3,%edi
    3137:	e8 ca 94 00 00       	callq  c606 <set_enclave_state>
        return SGX_ERROR_UNEXPECTED;
    313c:	b8 01 00 00 00       	mov    $0x1,%eax
    3141:	e9 13 01 00 00       	jmpq   3259 <do_uninit_enclave+0x179>
    }

    // Set uninit_flag to indicate the do_uninit_enclave is called
    __sync_or_and_fetch(&g_uninit_flag, 1);
    3146:	f0 83 0d 86 df 00 00 	lock orl $0x1,0xdf86(%rip)        # 110d4 <g_uninit_flag>
    314d:	01 

    tcs_node_t *tcs_node = g_tcs_node;
    314e:	48 8b 05 6b df 00 00 	mov    0xdf6b(%rip),%rax        # 110c0 <_ZL10g_tcs_node>
    3155:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    g_tcs_node = NULL;
    3159:	48 c7 05 5c df 00 00 	movq   $0x0,0xdf5c(%rip)        # 110c0 <_ZL10g_tcs_node>
    3160:	00 00 00 00 
    while (tcs_node != NULL)
    3164:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    3169:	0f 84 b0 00 00 00    	je     321f <do_uninit_enclave+0x13f>
    {
        if (DEC_TCS_POINTER(tcs_node->tcs) == tcs)
    316f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3173:	48 8b 10             	mov    (%rax),%rdx
    3176:	48 8b 05 4b df 00 00 	mov    0xdf4b(%rip),%rax        # 110c8 <_ZL12g_tcs_cookie>
    317d:	48 31 d0             	xor    %rdx,%rax
    3180:	48 39 45 c8          	cmp    %rax,-0x38(%rbp)
    3184:	75 22                	jne    31a8 <do_uninit_enclave+0xc8>
        {
            tcs_node_t *tmp = tcs_node;
    3186:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    318a:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
            tcs_node = tcs_node->next;
    318e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3192:	48 8b 40 08          	mov    0x8(%rax),%rax
    3196:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
            free(tmp);
    319a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    319e:	48 89 c7             	mov    %rax,%rdi
    31a1:	e8 86 66 00 00       	callq  982c <dlfree>
            continue;
    31a6:	eb 72                	jmp    321a <do_uninit_enclave+0x13a>
        }

        size_t start = (size_t)DEC_TCS_POINTER(tcs_node->tcs);
    31a8:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    31ac:	48 8b 10             	mov    (%rax),%rdx
    31af:	48 8b 05 12 df 00 00 	mov    0xdf12(%rip),%rax        # 110c8 <_ZL12g_tcs_cookie>
    31b6:	48 31 d0             	xor    %rdx,%rax
    31b9:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
        size_t end = start + (1 << SE_PAGE_SHIFT);
    31bd:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    31c1:	48 05 00 10 00 00    	add    $0x1000,%rax
    31c7:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
        int rc = sgx_accept_forward(SI_FLAG_TRIM | SI_FLAG_MODIFIED, start, end);
    31cb:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    31cf:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    31d3:	48 89 c6             	mov    %rax,%rsi
    31d6:	bf 10 04 00 00       	mov    $0x410,%edi
    31db:	e8 54 ee ff ff       	callq  2034 <sgx_accept_forward>
    31e0:	89 45 d4             	mov    %eax,-0x2c(%rbp)
        if(rc != 0)
    31e3:	83 7d d4 00          	cmpl   $0x0,-0x2c(%rbp)
    31e7:	74 11                	je     31fa <do_uninit_enclave+0x11a>
        {
            set_enclave_state(ENCLAVE_CRASHED);
    31e9:	bf 03 00 00 00       	mov    $0x3,%edi
    31ee:	e8 13 94 00 00       	callq  c606 <set_enclave_state>
            return SGX_ERROR_UNEXPECTED;
    31f3:	b8 01 00 00 00       	mov    $0x1,%eax
    31f8:	eb 5f                	jmp    3259 <do_uninit_enclave+0x179>
        }

        tcs_node_t *tmp = tcs_node;
    31fa:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    31fe:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
        tcs_node = tcs_node->next;
    3202:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3206:	48 8b 40 08          	mov    0x8(%rax),%rax
    320a:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
        free(tmp);
    320e:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    3212:	48 89 c7             	mov    %rax,%rdi
    3215:	e8 12 66 00 00       	callq  982c <dlfree>
    while (tcs_node != NULL)
    321a:	e9 45 ff ff ff       	jmpq   3164 <do_uninit_enclave+0x84>
    }

    sgx_spin_lock(&g_ife_lock);
    321f:	48 8d 3d aa de 00 00 	lea    0xdeaa(%rip),%rdi        # 110d0 <_ZL10g_ife_lock>
    3226:	e8 61 81 00 00       	callq  b38c <sgx_spin_lock>
    if (!g_is_first_ecall)
    322b:	0f b6 05 ce dd 00 00 	movzbl 0xddce(%rip),%eax        # 11000 <_ZL16g_is_first_ecall>
    3232:	83 f0 01             	xor    $0x1,%eax
    3235:	84 c0                	test   %al,%al
    3237:	74 05                	je     323e <do_uninit_enclave+0x15e>
    {
        uninit_global_object();
    3239:	e8 18 20 00 00       	callq  5256 <uninit_global_object>
    }
    sgx_spin_unlock(&g_ife_lock);
    323e:	48 8d 3d 8b de 00 00 	lea    0xde8b(%rip),%rdi        # 110d0 <_ZL10g_ife_lock>
    3245:	e8 a9 81 00 00       	callq  b3f3 <sgx_spin_unlock>
#else
    UNUSED(tcs);
#endif    
    set_enclave_state(ENCLAVE_CRASHED);
    324a:	bf 03 00 00 00       	mov    $0x3,%edi
    324f:	e8 b2 93 00 00       	callq  c606 <set_enclave_state>

    return SGX_SUCCESS;
    3254:	b8 00 00 00 00       	mov    $0x0,%eax
}
    3259:	c9                   	leaveq 
    325a:	c3                   	retq   

000000000000325b <trts_mprotect>:

extern sdk_version_t g_sdk_version;

extern "C" sgx_status_t trts_mprotect(size_t start, size_t size, uint64_t perms)
{
    325b:	4c 8d 54 24 08       	lea    0x8(%rsp),%r10
    3260:	48 83 e4 c0          	and    $0xffffffffffffffc0,%rsp
    3264:	41 ff 72 f8          	pushq  -0x8(%r10)
    3268:	55                   	push   %rbp
    3269:	48 89 e5             	mov    %rsp,%rbp
    326c:	41 52                	push   %r10
    326e:	48 81 ec e8 00 00 00 	sub    $0xe8,%rsp
    3275:	48 89 bd 38 ff ff ff 	mov    %rdi,-0xc8(%rbp)
    327c:	48 89 b5 30 ff ff ff 	mov    %rsi,-0xd0(%rbp)
    3283:	48 89 95 28 ff ff ff 	mov    %rdx,-0xd8(%rbp)
    328a:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    3291:	00 00 
    3293:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    3297:	31 c0                	xor    %eax,%eax
    int rc = -1;
    3299:	c7 85 40 ff ff ff ff 	movl   $0xffffffff,-0xc0(%rbp)
    32a0:	ff ff ff 
    size_t page;
    sgx_status_t ret = SGX_SUCCESS;
    32a3:	c7 85 44 ff ff ff 00 	movl   $0x0,-0xbc(%rbp)
    32aa:	00 00 00 
    SE_DECLSPEC_ALIGN(sizeof(sec_info_t)) sec_info_t si;

    //Error return if start or size is not page-aligned or size is zero.
    if (!IS_PAGE_ALIGNED(start) || (size == 0) || !IS_PAGE_ALIGNED(size))
    32ad:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    32b4:	25 ff 0f 00 00       	and    $0xfff,%eax
    32b9:	48 85 c0             	test   %rax,%rax
    32bc:	75 1b                	jne    32d9 <trts_mprotect+0x7e>
    32be:	48 83 bd 30 ff ff ff 	cmpq   $0x0,-0xd0(%rbp)
    32c5:	00 
    32c6:	74 11                	je     32d9 <trts_mprotect+0x7e>
    32c8:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    32cf:	25 ff 0f 00 00       	and    $0xfff,%eax
    32d4:	48 85 c0             	test   %rax,%rax
    32d7:	74 0a                	je     32e3 <trts_mprotect+0x88>
        return SGX_ERROR_INVALID_PARAMETER;
    32d9:	b8 02 00 00 00       	mov    $0x2,%eax
    32de:	e9 0c 01 00 00       	jmpq   33ef <trts_mprotect+0x194>
    if (g_sdk_version == SDK_VERSION_2_0)
    32e3:	48 8d 05 1a db 00 00 	lea    0xdb1a(%rip),%rax        # 10e04 <g_sdk_version>
    32ea:	8b 00                	mov    (%rax),%eax
    32ec:	83 f8 01             	cmp    $0x1,%eax
    32ef:	75 3a                	jne    332b <trts_mprotect+0xd0>
    {
        ret = change_permissions_ocall(start, size, perms);
    32f1:	48 8b 95 28 ff ff ff 	mov    -0xd8(%rbp),%rdx
    32f8:	48 8b 8d 30 ff ff ff 	mov    -0xd0(%rbp),%rcx
    32ff:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    3306:	48 89 ce             	mov    %rcx,%rsi
    3309:	48 89 c7             	mov    %rax,%rdi
    330c:	e8 39 02 00 00       	callq  354a <change_permissions_ocall>
    3311:	89 85 44 ff ff ff    	mov    %eax,-0xbc(%rbp)
        if (ret != SGX_SUCCESS)
    3317:	83 bd 44 ff ff ff 00 	cmpl   $0x0,-0xbc(%rbp)
    331e:	74 0b                	je     332b <trts_mprotect+0xd0>
            return ret;
    3320:	8b 85 44 ff ff ff    	mov    -0xbc(%rbp),%eax
    3326:	e9 c4 00 00 00       	jmpq   33ef <trts_mprotect+0x194>
    }

    si.flags = perms|SI_FLAG_REG|SI_FLAG_PR;
    332b:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    3332:	48 0d 20 02 00 00    	or     $0x220,%rax
    3338:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    memset(&si.reserved, 0, sizeof(si.reserved));
    333f:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
    3346:	48 83 c0 08          	add    $0x8,%rax
    334a:	ba 38 00 00 00       	mov    $0x38,%edx
    334f:	be 00 00 00 00       	mov    $0x0,%esi
    3354:	48 89 c7             	mov    %rax,%rdi
    3357:	e8 d1 7b 00 00       	callq  af2d <memset>

    for(page = start; page < start + size; page += SE_PAGE_SIZE)
    335c:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    3363:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    336a:	48 8b 95 38 ff ff ff 	mov    -0xc8(%rbp),%rdx
    3371:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    3378:	48 01 d0             	add    %rdx,%rax
    337b:	48 39 85 48 ff ff ff 	cmp    %rax,-0xb8(%rbp)
    3382:	73 66                	jae    33ea <trts_mprotect+0x18f>
    {
        do_emodpe(&si, page);
    3384:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    338b:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
    3392:	48 89 d6             	mov    %rdx,%rsi
    3395:	48 89 c7             	mov    %rax,%rdi
    3398:	e8 8a 95 00 00       	callq  c927 <do_emodpe>
        // If the target permission to set is RWX, no EMODPR, hence no EACCEPT.
        if ((perms & (SI_FLAG_W|SI_FLAG_X)) != (SI_FLAG_W|SI_FLAG_X))
    339d:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    33a4:	83 e0 06             	and    $0x6,%eax
    33a7:	48 83 f8 06          	cmp    $0x6,%rax
    33ab:	74 30                	je     33dd <trts_mprotect+0x182>
        {
            rc = do_eaccept(&si, page);
    33ad:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    33b4:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
    33bb:	48 89 d6             	mov    %rdx,%rsi
    33be:	48 89 c7             	mov    %rax,%rdi
    33c1:	e8 47 95 00 00       	callq  c90d <do_eaccept>
    33c6:	89 85 40 ff ff ff    	mov    %eax,-0xc0(%rbp)
            if(rc != 0)
    33cc:	83 bd 40 ff ff ff 00 	cmpl   $0x0,-0xc0(%rbp)
    33d3:	74 08                	je     33dd <trts_mprotect+0x182>
                return (sgx_status_t)rc;
    33d5:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    33db:	eb 12                	jmp    33ef <trts_mprotect+0x194>
    for(page = start; page < start + size; page += SE_PAGE_SIZE)
    33dd:	48 81 85 48 ff ff ff 	addq   $0x1000,-0xb8(%rbp)
    33e4:	00 10 00 00 
    33e8:	eb 80                	jmp    336a <trts_mprotect+0x10f>
        }
    }

    return SGX_SUCCESS;
    33ea:	b8 00 00 00 00       	mov    $0x0,%eax
}
    33ef:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    33f3:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    33fa:	00 00 
    33fc:	74 05                	je     3403 <trts_mprotect+0x1a8>
    33fe:	e8 64 1e 00 00       	callq  5267 <__stack_chk_fail>
    3403:	48 81 c4 e8 00 00 00 	add    $0xe8,%rsp
    340a:	41 5a                	pop    %r10
    340c:	5d                   	pop    %rbp
    340d:	49 8d 62 f8          	lea    -0x8(%r10),%rsp
    3411:	c3                   	retq   

0000000000003412 <_Z20random_stack_advanceILj2048E9_status_tJjPvEJRiRS1_EET0_PFS4_DpT1_EDpOT2_>:
__attribute__((noinline)) static R _random_stack_noinline_wrapper(R(*f)(Ps...), Qs&&... args)
{
    return f(std::forward<Qs>(args)...);
}
template <unsigned M = 0x1000, class R, class... Ps, class... Qs>
R random_stack_advance(R(*f)(Ps...), Qs&&... args)
    3412:	55                   	push   %rbp
    3413:	48 89 e5             	mov    %rsp,%rbp
    3416:	41 57                	push   %r15
    3418:	41 56                	push   %r14
    341a:	41 55                	push   %r13
    341c:	41 54                	push   %r12
    341e:	53                   	push   %rbx
    341f:	48 83 ec 58          	sub    $0x58,%rsp
    3423:	48 89 7d 98          	mov    %rdi,-0x68(%rbp)
    3427:	48 89 75 90          	mov    %rsi,-0x70(%rbp)
    342b:	48 89 55 88          	mov    %rdx,-0x78(%rbp)
    342f:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    3436:	00 00 
    3438:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    343c:	31 c0                	xor    %eax,%eax
        memset((void *)dummy_vla, 0, size);
#else
    (void)(dummy_vla);
#endif

    return _random_stack_noinline_wrapper(f, std::forward<Qs>(args)...);
    343e:	48 89 e0             	mov    %rsp,%rax
    3441:	48 89 c3             	mov    %rax,%rbx
    unsigned size = rdrand() % M + 1;
    3444:	e8 b2 00 00 00       	callq  34fb <_Z6rdrandIjET_v>
    3449:	25 ff 07 00 00       	and    $0x7ff,%eax
    344e:	83 c0 01             	add    $0x1,%eax
    3451:	89 45 a4             	mov    %eax,-0x5c(%rbp)
    volatile char dummy_vla[size];
    3454:	8b 45 a4             	mov    -0x5c(%rbp),%eax
    3457:	48 83 e8 01          	sub    $0x1,%rax
    345b:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    345f:	48 89 c2             	mov    %rax,%rdx
    3462:	48 83 c2 01          	add    $0x1,%rdx
    3466:	49 89 d6             	mov    %rdx,%r14
    3469:	41 bf 00 00 00 00    	mov    $0x0,%r15d
    346f:	48 89 c2             	mov    %rax,%rdx
    3472:	48 83 c2 01          	add    $0x1,%rdx
    3476:	49 89 d4             	mov    %rdx,%r12
    3479:	41 bd 00 00 00 00    	mov    $0x0,%r13d
    347f:	48 8d 50 01          	lea    0x1(%rax),%rdx
    3483:	b8 10 00 00 00       	mov    $0x10,%eax
    3488:	48 83 e8 01          	sub    $0x1,%rax
    348c:	48 01 d0             	add    %rdx,%rax
    348f:	be 10 00 00 00       	mov    $0x10,%esi
    3494:	ba 00 00 00 00       	mov    $0x0,%edx
    3499:	48 f7 f6             	div    %rsi
    349c:	48 6b c0 10          	imul   $0x10,%rax,%rax
    34a0:	48 29 c4             	sub    %rax,%rsp
    34a3:	48 89 e0             	mov    %rsp,%rax
    34a6:	48 83 c0 00          	add    $0x0,%rax
    34aa:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    34ae:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    34b2:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
template <class _Tp>
inline _LIBCPP_INLINE_VISIBILITY _LIBCPP_CONSTEXPR_AFTER_CXX11
_Tp&&
forward(typename remove_reference<_Tp>::type& __t) _NOEXCEPT
{
    return static_cast<_Tp&&>(__t);
    34b6:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    34ba:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    34be:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    34c2:	48 8b 4d b8          	mov    -0x48(%rbp),%rcx
    return _random_stack_noinline_wrapper(f, std::forward<Qs>(args)...);
    34c6:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    34ca:	48 89 ce             	mov    %rcx,%rsi
    34cd:	48 89 c7             	mov    %rax,%rdi
    34d0:	e8 35 00 00 00       	callq  350a <_Z30_random_stack_noinline_wrapperI9_status_tJjPvEJRiRS1_EET_PFS4_DpT0_EDpOT1_>
    34d5:	48 89 dc             	mov    %rbx,%rsp
}
    34d8:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    34dc:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    34e3:	00 00 
    34e5:	74 05                	je     34ec <_Z20random_stack_advanceILj2048E9_status_tJjPvEJRiRS1_EET0_PFS4_DpT1_EDpOT2_+0xda>
    34e7:	e8 7b 1d 00 00       	callq  5267 <__stack_chk_fail>
    34ec:	48 8d 65 d8          	lea    -0x28(%rbp),%rsp
    34f0:	5b                   	pop    %rbx
    34f1:	41 5c                	pop    %r12
    34f3:	41 5d                	pop    %r13
    34f5:	41 5e                	pop    %r14
    34f7:	41 5f                	pop    %r15
    34f9:	5d                   	pop    %rbp
    34fa:	c3                   	retq   

00000000000034fb <_Z6rdrandIjET_v>:
inline R rdrand(void)
    34fb:	55                   	push   %rbp
    34fc:	48 89 e5             	mov    %rsp,%rbp
    __asm__ volatile ("rdrand %0" : "=r"(r));
    34ff:	0f c7 f0             	rdrand %eax
    3502:	89 45 fc             	mov    %eax,-0x4(%rbp)
    return r;
    3505:	8b 45 fc             	mov    -0x4(%rbp),%eax
}
    3508:	5d                   	pop    %rbp
    3509:	c3                   	retq   

000000000000350a <_Z30_random_stack_noinline_wrapperI9_status_tJjPvEJRiRS1_EET_PFS4_DpT0_EDpOT1_>:
__attribute__((noinline)) static R _random_stack_noinline_wrapper(R(*f)(Ps...), Qs&&... args)
    350a:	55                   	push   %rbp
    350b:	48 89 e5             	mov    %rsp,%rbp
    350e:	48 83 ec 30          	sub    $0x30,%rsp
    3512:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    3516:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    351a:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    351e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3522:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    3526:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    return f(std::forward<Qs>(args)...);
    352a:	48 8b 10             	mov    (%rax),%rdx
    352d:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3531:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    3535:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    3539:	8b 00                	mov    (%rax),%eax
    353b:	89 c1                	mov    %eax,%ecx
    353d:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3541:	48 89 d6             	mov    %rdx,%rsi
    3544:	89 cf                	mov    %ecx,%edi
    3546:	ff d0                	callq  *%rax
}
    3548:	c9                   	leaveq 
    3549:	c3                   	retq   

000000000000354a <change_permissions_ocall>:
    size_t ms_size;
    uint64_t ms_epcm_perms;
} ms_change_permissions_ocall_t;

sgx_status_t SGXAPI change_permissions_ocall(size_t addr, size_t size, uint64_t epcm_perms)
{
    354a:	55                   	push   %rbp
    354b:	48 89 e5             	mov    %rsp,%rbp
    354e:	48 83 ec 40          	sub    $0x40,%rsp
    3552:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    3556:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    355a:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
    (void)addr;
    (void)size;
    (void)epcm_perms;
    return SGX_SUCCESS;
#else
    sgx_status_t status = SGX_SUCCESS;
    355e:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%rbp)

    ms_change_permissions_ocall_t* ms;
    OCALLOC(ms, ms_change_permissions_ocall_t*, sizeof(*ms));
    3565:	bf 18 00 00 00       	mov    $0x18,%edi
    356a:	e8 43 de ff ff       	callq  13b2 <sgx_ocalloc>
    356f:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    3573:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    3578:	75 0c                	jne    3586 <change_permissions_ocall+0x3c>
    357a:	e8 44 df ff ff       	callq  14c3 <sgx_ocfree>
    357f:	b8 01 00 00 00       	mov    $0x1,%eax
    3584:	eb 47                	jmp    35cd <change_permissions_ocall+0x83>
    3586:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    358a:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

    ms->ms_addr = addr;
    358e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3592:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    3596:	48 89 10             	mov    %rdx,(%rax)
    ms->ms_size = size;
    3599:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    359d:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    35a1:	48 89 50 08          	mov    %rdx,0x8(%rax)
    ms->ms_epcm_perms = epcm_perms;
    35a5:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    35a9:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    35ad:	48 89 50 10          	mov    %rdx,0x10(%rax)
    status = sgx_ocall(EDMM_MODPR, ms);
    35b1:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    35b5:	48 89 c6             	mov    %rax,%rsi
    35b8:	bf fc ff ff ff       	mov    $0xfffffffc,%edi
    35bd:	e8 0d 00 00 00       	callq  35cf <sgx_ocall>
    35c2:	89 45 ec             	mov    %eax,-0x14(%rbp)


    sgx_ocfree();
    35c5:	e8 f9 de ff ff       	callq  14c3 <sgx_ocfree>
    return status;
    35ca:	8b 45 ec             	mov    -0x14(%rbp),%eax
#endif
}
    35cd:	c9                   	leaveq 
    35ce:	c3                   	retq   

00000000000035cf <sgx_ocall>:
//      ms - the mashalling structure
// Return Value:
//      OCALL status
//
sgx_status_t sgx_ocall(const unsigned int index, void *ms)
{
    35cf:	55                   	push   %rbp
    35d0:	48 89 e5             	mov    %rsp,%rbp
    35d3:	48 83 ec 20          	sub    $0x20,%rsp
    35d7:	89 7d ec             	mov    %edi,-0x14(%rbp)
    35da:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    // the OCALL index should be within the ocall table range
    // -2, -3 and -4 -5 should be allowed to test SDK 2.0 features
    if((index != 0) && !is_builtin_ocall((int)index) &&
    35de:	83 7d ec 00          	cmpl   $0x0,-0x14(%rbp)
    35e2:	74 29                	je     360d <sgx_ocall+0x3e>
    35e4:	8b 45 ec             	mov    -0x14(%rbp),%eax
    35e7:	83 f8 fc             	cmp    $0xfffffffc,%eax
    35ea:	7c 08                	jl     35f4 <sgx_ocall+0x25>
    35ec:	8b 45 ec             	mov    -0x14(%rbp),%eax
    35ef:	83 f8 ff             	cmp    $0xffffffff,%eax
    35f2:	7c 19                	jl     360d <sgx_ocall+0x3e>
            static_cast<size_t>(index) >= g_dyn_entry_table.nr_ocall)
    35f4:	8b 55 ec             	mov    -0x14(%rbp),%edx
    35f7:	48 8d 05 02 9a 00 00 	lea    0x9a02(%rip),%rax        # d000 <g_dyn_entry_table>
    35fe:	48 8b 00             	mov    (%rax),%rax
    if((index != 0) && !is_builtin_ocall((int)index) &&
    3601:	48 39 c2             	cmp    %rax,%rdx
    3604:	72 07                	jb     360d <sgx_ocall+0x3e>
    {
        return SGX_ERROR_INVALID_FUNCTION;
    3606:	b8 01 10 00 00       	mov    $0x1001,%eax
    360b:	eb 17                	jmp    3624 <sgx_ocall+0x55>
    }

    // do sgx_ocall
    sgx_status_t status = do_ocall(index, ms);
    360d:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    3611:	8b 45 ec             	mov    -0x14(%rbp),%eax
    3614:	48 89 d6             	mov    %rdx,%rsi
    3617:	89 c7                	mov    %eax,%edi
    3619:	e8 42 92 00 00       	callq  c860 <__morestack>
    361e:	89 45 fc             	mov    %eax,-0x4(%rbp)

    return status;
    3621:	8b 45 fc             	mov    -0x4(%rbp),%eax
}
    3624:	c9                   	leaveq 
    3625:	c3                   	retq   

0000000000003626 <update_ocall_lastsp>:


extern "C"
uintptr_t update_ocall_lastsp(ocall_context_t* context)
{
    3626:	55                   	push   %rbp
    3627:	48 89 e5             	mov    %rsp,%rbp
    362a:	48 83 ec 30          	sub    $0x30,%rsp
    362e:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    thread_data_t* thread_data = get_thread_data();
    3632:	e8 f5 8f 00 00       	callq  c62c <get_thread_data>
    3637:	48 89 45 e8          	mov    %rax,-0x18(%rbp)

    uintptr_t last_sp = 0;
    363b:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
    3642:	00 

    last_sp = thread_data->last_sp;
    3643:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3647:	48 8b 40 08          	mov    0x8(%rax),%rax
    364b:	48 89 45 f0          	mov    %rax,-0x10(%rbp)

    context->pre_last_sp = last_sp;
    364f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3653:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    3657:	48 89 50 30          	mov    %rdx,0x30(%rax)

    if (context->pre_last_sp == thread_data->stack_base_addr)
    365b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    365f:	48 8b 50 30          	mov    0x30(%rax),%rdx
    3663:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3667:	48 8b 40 10          	mov    0x10(%rax),%rax
    366b:	48 39 c2             	cmp    %rax,%rdx
    366e:	75 11                	jne    3681 <update_ocall_lastsp+0x5b>
    {
        context->ocall_depth = 1;
    3670:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3674:	48 c7 80 90 00 00 00 	movq   $0x1,0x90(%rax)
    367b:	01 00 00 00 
    367f:	eb 26                	jmp    36a7 <update_ocall_lastsp+0x81>
    } else {
        // thread_data->last_sp is only set when ocall or exception handling occurs
        // ocall is block during exception handling, so last_sp is always ocall frame here
        ocall_context_t* context_pre = reinterpret_cast<ocall_context_t*>(context->pre_last_sp);
    3681:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3685:	48 8b 40 30          	mov    0x30(%rax),%rax
    3689:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
        context->ocall_depth = context_pre->ocall_depth + 1;
    368d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3691:	48 8b 80 90 00 00 00 	mov    0x90(%rax),%rax
    3698:	48 8d 50 01          	lea    0x1(%rax),%rdx
    369c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    36a0:	48 89 90 90 00 00 00 	mov    %rdx,0x90(%rax)
    }

    thread_data->last_sp = reinterpret_cast<uintptr_t>(context);
    36a7:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    36ab:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    36af:	48 89 50 08          	mov    %rdx,0x8(%rax)

    return last_sp;
    36b3:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
}
    36b7:	c9                   	leaveq 
    36b8:	c3                   	retq   

00000000000036b9 <do_oret>:

sgx_status_t do_oret(void *ms)
{
    36b9:	55                   	push   %rbp
    36ba:	48 89 e5             	mov    %rsp,%rbp
    36bd:	48 83 ec 30          	sub    $0x30,%rsp
    36c1:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    36c5:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    36cc:	00 00 
    36ce:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    36d2:	31 c0                	xor    %eax,%eax
    thread_data_t *thread_data = get_thread_data();
    36d4:	e8 53 8f 00 00       	callq  c62c <get_thread_data>
    36d9:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    uintptr_t last_sp = thread_data->last_sp;
    36dd:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    36e1:	48 8b 40 08          	mov    0x8(%rax),%rax
    36e5:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    ocall_context_t *context = reinterpret_cast<ocall_context_t*>(thread_data->last_sp);
    36e9:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    36ed:	48 8b 40 08          	mov    0x8(%rax),%rax
    36f1:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    if(0 == last_sp || last_sp <= (uintptr_t)&context)
    36f5:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    36fa:	74 0a                	je     3706 <do_oret+0x4d>
    36fc:	48 8d 45 e0          	lea    -0x20(%rbp),%rax
    3700:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    3704:	77 0a                	ja     3710 <do_oret+0x57>
    {
        return SGX_ERROR_UNEXPECTED;
    3706:	b8 01 00 00 00       	mov    $0x1,%eax
    370b:	e9 87 00 00 00       	jmpq   3797 <do_oret+0xde>
    }
    // At least 1 ecall frame and 1 ocall frame are expected on stack. 
    // 30 is an estimated value: 8 for enclave_entry and 22 for do_ocall.
    if(last_sp > thread_data->stack_base_addr - 30 * sizeof(size_t))
    3710:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3714:	48 8b 40 10          	mov    0x10(%rax),%rax
    3718:	48 2d f0 00 00 00    	sub    $0xf0,%rax
    371e:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    3722:	76 07                	jbe    372b <do_oret+0x72>
    {
        return SGX_ERROR_UNEXPECTED;
    3724:	b8 01 00 00 00       	mov    $0x1,%eax
    3729:	eb 6c                	jmp    3797 <do_oret+0xde>
    }
    if(context->ocall_flag != OCALL_FLAG)
    372b:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    372f:	48 8b 40 20          	mov    0x20(%rax),%rax
    3733:	48 3d 44 49 43 4f    	cmp    $0x4f434944,%rax
    3739:	74 07                	je     3742 <do_oret+0x89>
    {
        return SGX_ERROR_UNEXPECTED;
    373b:	b8 01 00 00 00       	mov    $0x1,%eax
    3740:	eb 55                	jmp    3797 <do_oret+0xde>
    }
    if(context->pre_last_sp > thread_data->stack_base_addr
    3742:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3746:	48 8b 50 30          	mov    0x30(%rax),%rdx
    374a:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    374e:	48 8b 40 10          	mov    0x10(%rax),%rax
    3752:	48 39 c2             	cmp    %rax,%rdx
    3755:	77 11                	ja     3768 <do_oret+0xaf>
       || context->pre_last_sp <= (uintptr_t)context)
    3757:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    375b:	48 8b 40 30          	mov    0x30(%rax),%rax
    375f:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    3763:	48 39 d0             	cmp    %rdx,%rax
    3766:	77 07                	ja     376f <do_oret+0xb6>
    {
        return SGX_ERROR_UNEXPECTED;
    3768:	b8 01 00 00 00       	mov    $0x1,%eax
    376d:	eb 28                	jmp    3797 <do_oret+0xde>
    }

    thread_data->last_sp = context->pre_last_sp;
    376f:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3773:	48 8b 50 30          	mov    0x30(%rax),%rdx
    3777:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    377b:	48 89 50 08          	mov    %rdx,0x8(%rax)
    asm_oret(last_sp, ms);
    377f:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    3783:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    3787:	48 89 d6             	mov    %rdx,%rsi
    378a:	48 89 c7             	mov    %rax,%rdi
    378d:	e8 dd 90 00 00       	callq  c86f <asm_oret>
    
    // Should not come here
    return SGX_ERROR_UNEXPECTED;
    3792:	b8 01 00 00 00       	mov    $0x1,%eax
}
    3797:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    379b:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    37a2:	00 00 
    37a4:	74 05                	je     37ab <do_oret+0xf2>
    37a6:	e8 bc 1a 00 00       	callq  5267 <__stack_chk_fail>
    37ab:	c9                   	leaveq 
    37ac:	c3                   	retq   

00000000000037ad <trim_range_ocall>:
typedef struct ms_trim_range_commit_ocall_t {
    size_t ms_addr;
} ms_trim_range_commit_ocall_t;

sgx_status_t SGXAPI trim_range_ocall(size_t fromaddr, size_t toaddr)
{
    37ad:	55                   	push   %rbp
    37ae:	48 89 e5             	mov    %rsp,%rbp
    37b1:	48 83 ec 30          	sub    $0x30,%rsp
    37b5:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    37b9:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    sgx_status_t status = SGX_SUCCESS;
    37bd:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%rbp)

    ms_trim_range_ocall_t* ms;
    OCALLOC(ms, ms_trim_range_ocall_t*, sizeof(*ms));
    37c4:	bf 10 00 00 00       	mov    $0x10,%edi
    37c9:	e8 e4 db ff ff       	callq  13b2 <sgx_ocalloc>
    37ce:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    37d2:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    37d7:	75 0c                	jne    37e5 <trim_range_ocall+0x38>
    37d9:	e8 e5 dc ff ff       	callq  14c3 <sgx_ocfree>
    37de:	b8 01 00 00 00       	mov    $0x1,%eax
    37e3:	eb 3b                	jmp    3820 <trim_range_ocall+0x73>
    37e5:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    37e9:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

    ms->ms_fromaddr = fromaddr;
    37ed:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    37f1:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    37f5:	48 89 10             	mov    %rdx,(%rax)
    ms->ms_toaddr = toaddr;
    37f8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    37fc:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    3800:	48 89 50 08          	mov    %rdx,0x8(%rax)
    status = sgx_ocall(EDMM_TRIM, ms);
    3804:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3808:	48 89 c6             	mov    %rax,%rsi
    380b:	bf fe ff ff ff       	mov    $0xfffffffe,%edi
    3810:	e8 ba fd ff ff       	callq  35cf <sgx_ocall>
    3815:	89 45 ec             	mov    %eax,-0x14(%rbp)


    sgx_ocfree();
    3818:	e8 a6 dc ff ff       	callq  14c3 <sgx_ocfree>
    return status;
    381d:	8b 45 ec             	mov    -0x14(%rbp),%eax
}
    3820:	c9                   	leaveq 
    3821:	c3                   	retq   

0000000000003822 <trim_range_commit_ocall>:

sgx_status_t SGXAPI trim_range_commit_ocall(size_t addr)
{
    3822:	55                   	push   %rbp
    3823:	48 89 e5             	mov    %rsp,%rbp
    3826:	48 83 ec 30          	sub    $0x30,%rsp
    382a:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    sgx_status_t status = SGX_SUCCESS;
    382e:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%rbp)

    ms_trim_range_commit_ocall_t* ms;
    OCALLOC(ms, ms_trim_range_commit_ocall_t*, sizeof(*ms));
    3835:	bf 08 00 00 00       	mov    $0x8,%edi
    383a:	e8 73 db ff ff       	callq  13b2 <sgx_ocalloc>
    383f:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    3843:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    3848:	75 0c                	jne    3856 <trim_range_commit_ocall+0x34>
    384a:	e8 74 dc ff ff       	callq  14c3 <sgx_ocfree>
    384f:	b8 01 00 00 00       	mov    $0x1,%eax
    3854:	eb 2f                	jmp    3885 <trim_range_commit_ocall+0x63>
    3856:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    385a:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

    ms->ms_addr = addr;
    385e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3862:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    3866:	48 89 10             	mov    %rdx,(%rax)
    status = sgx_ocall(EDMM_TRIM_COMMIT, ms);
    3869:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    386d:	48 89 c6             	mov    %rax,%rsi
    3870:	bf fd ff ff ff       	mov    $0xfffffffd,%edi
    3875:	e8 55 fd ff ff       	callq  35cf <sgx_ocall>
    387a:	89 45 ec             	mov    %eax,-0x14(%rbp)


    sgx_ocfree();
    387d:	e8 41 dc ff ff       	callq  14c3 <sgx_ocfree>
    return status;
    3882:	8b 45 ec             	mov    -0x14(%rbp),%eax
}
    3885:	c9                   	leaveq 
    3886:	c3                   	retq   

0000000000003887 <get_heap_base>:
{
    return (size_t)get_enclave_base() + (size_t)g_global_data.enclave_size - 1;
}

void * get_heap_base(void)
{
    3887:	55                   	push   %rbp
    3888:	48 89 e5             	mov    %rsp,%rbp
    return GET_PTR(void, &__ImageBase, g_global_data.heap_offset);
    388b:	48 8d 05 ee 98 00 00 	lea    0x98ee(%rip),%rax        # d180 <g_global_data>
    3892:	48 8b 40 08          	mov    0x8(%rax),%rax
    3896:	48 8d 15 63 c7 ff ff 	lea    -0x389d(%rip),%rdx        # 0 <enclave.so>
    389d:	48 01 d0             	add    %rdx,%rax
}
    38a0:	5d                   	pop    %rbp
    38a1:	c3                   	retq   

00000000000038a2 <get_heap_size>:

size_t get_heap_size(void)
{
    38a2:	55                   	push   %rbp
    38a3:	48 89 e5             	mov    %rsp,%rbp
    size_t heap_size = g_global_data.heap_size;
    38a6:	48 8d 05 d3 98 00 00 	lea    0x98d3(%rip),%rax        # d180 <g_global_data>
    38ad:	48 8b 40 10          	mov    0x10(%rax),%rax
    38b1:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if (EDMM_supported)
    38b5:	48 8d 05 44 d5 00 00 	lea    0xd544(%rip),%rax        # 10e00 <EDMM_supported>
    38bc:	8b 00                	mov    (%rax),%eax
    38be:	85 c0                	test   %eax,%eax
    38c0:	74 6c                	je     392e <get_heap_size+0x8c>
    {
        for(uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    38c2:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    38c9:	48 8d 05 b0 98 00 00 	lea    0x98b0(%rip),%rax        # d180 <g_global_data>
    38d0:	8b 80 28 01 00 00    	mov    0x128(%rax),%eax
    38d6:	39 45 f4             	cmp    %eax,-0xc(%rbp)
    38d9:	0f 92 c0             	setb   %al
    38dc:	84 c0                	test   %al,%al
    38de:	74 4e                	je     392e <get_heap_size+0x8c>
        {
            if(g_global_data.layout_table[i].entry.id == LAYOUT_ID_HEAP_MAX)
    38e0:	48 8d 05 99 98 00 00 	lea    0x9899(%rip),%rax        # d180 <g_global_data>
    38e7:	8b 55 f4             	mov    -0xc(%rbp),%edx
    38ea:	48 c1 e2 05          	shl    $0x5,%rdx
    38ee:	48 01 d0             	add    %rdx,%rax
    38f1:	48 05 30 01 00 00    	add    $0x130,%rax
    38f7:	0f b7 00             	movzwl (%rax),%eax
    38fa:	66 83 f8 03          	cmp    $0x3,%ax
    38fe:	0f 94 c0             	sete   %al
    3901:	84 c0                	test   %al,%al
    3903:	74 23                	je     3928 <get_heap_size+0x86>
            {
                heap_size += ((size_t)g_global_data.layout_table[i].entry.page_count << SE_PAGE_SHIFT);
    3905:	48 8d 05 74 98 00 00 	lea    0x9874(%rip),%rax        # d180 <g_global_data>
    390c:	8b 55 f4             	mov    -0xc(%rbp),%edx
    390f:	48 c1 e2 05          	shl    $0x5,%rdx
    3913:	48 01 d0             	add    %rdx,%rax
    3916:	48 05 34 01 00 00    	add    $0x134,%rax
    391c:	8b 00                	mov    (%rax),%eax
    391e:	89 c0                	mov    %eax,%eax
    3920:	48 c1 e0 0c          	shl    $0xc,%rax
    3924:	48 01 45 f8          	add    %rax,-0x8(%rbp)
        for(uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    3928:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    392c:	eb 9b                	jmp    38c9 <get_heap_size+0x27>
            }
        }
    }
    return heap_size;
    392e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
}
    3932:	5d                   	pop    %rbp
    3933:	c3                   	retq   

0000000000003934 <get_heap_min_size>:

size_t get_heap_min_size(void)
{
    3934:	55                   	push   %rbp
    3935:	48 89 e5             	mov    %rsp,%rbp
    size_t heap_size = 0;
    3938:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    393f:	00 
    for(uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    3940:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    3947:	48 8d 05 32 98 00 00 	lea    0x9832(%rip),%rax        # d180 <g_global_data>
    394e:	8b 80 28 01 00 00    	mov    0x128(%rax),%eax
    3954:	39 45 f4             	cmp    %eax,-0xc(%rbp)
    3957:	0f 92 c0             	setb   %al
    395a:	84 c0                	test   %al,%al
    395c:	74 50                	je     39ae <get_heap_min_size+0x7a>
    {
        if(g_global_data.layout_table[i].entry.id == LAYOUT_ID_HEAP_MIN)
    395e:	48 8d 05 1b 98 00 00 	lea    0x981b(%rip),%rax        # d180 <g_global_data>
    3965:	8b 55 f4             	mov    -0xc(%rbp),%edx
    3968:	48 c1 e2 05          	shl    $0x5,%rdx
    396c:	48 01 d0             	add    %rdx,%rax
    396f:	48 05 30 01 00 00    	add    $0x130,%rax
    3975:	0f b7 00             	movzwl (%rax),%eax
    3978:	66 83 f8 01          	cmp    $0x1,%ax
    397c:	0f 94 c0             	sete   %al
    397f:	84 c0                	test   %al,%al
    3981:	74 25                	je     39a8 <get_heap_min_size+0x74>
        {
            heap_size = ((size_t)g_global_data.layout_table[i].entry.page_count << SE_PAGE_SHIFT);
    3983:	48 8d 05 f6 97 00 00 	lea    0x97f6(%rip),%rax        # d180 <g_global_data>
    398a:	8b 55 f4             	mov    -0xc(%rbp),%edx
    398d:	48 c1 e2 05          	shl    $0x5,%rdx
    3991:	48 01 d0             	add    %rdx,%rax
    3994:	48 05 34 01 00 00    	add    $0x134,%rax
    399a:	8b 00                	mov    (%rax),%eax
    399c:	89 c0                	mov    %eax,%eax
    399e:	48 c1 e0 0c          	shl    $0xc,%rax
    39a2:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
            break;
    39a6:	eb 06                	jmp    39ae <get_heap_min_size+0x7a>
    for(uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    39a8:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    39ac:	eb 99                	jmp    3947 <get_heap_min_size+0x13>
        }
    }
    return heap_size;
    39ae:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
}
    39b2:	5d                   	pop    %rbp
    39b3:	c3                   	retq   

00000000000039b4 <get_rsrv_base>:

void * get_rsrv_base(void)
{
    39b4:	55                   	push   %rbp
    39b5:	48 89 e5             	mov    %rsp,%rbp
    return GET_PTR(void, &__ImageBase, g_global_data.rsrv_offset);
    39b8:	48 8d 05 c1 97 00 00 	lea    0x97c1(%rip),%rax        # d180 <g_global_data>
    39bf:	48 8b 40 18          	mov    0x18(%rax),%rax
    39c3:	48 8d 15 36 c6 ff ff 	lea    -0x39ca(%rip),%rdx        # 0 <enclave.so>
    39ca:	48 01 d0             	add    %rdx,%rax
}
    39cd:	5d                   	pop    %rbp
    39ce:	c3                   	retq   

00000000000039cf <get_rsrv_size>:
{
    return (size_t)get_rsrv_base() + (size_t)get_rsrv_size() - 1;
}

size_t get_rsrv_size(void)
{
    39cf:	55                   	push   %rbp
    39d0:	48 89 e5             	mov    %rsp,%rbp
    size_t rsrv_size = g_global_data.rsrv_size;
    39d3:	48 8d 05 a6 97 00 00 	lea    0x97a6(%rip),%rax        # d180 <g_global_data>
    39da:	48 8b 40 20          	mov    0x20(%rax),%rax
    39de:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if (EDMM_supported)
    39e2:	48 8d 05 17 d4 00 00 	lea    0xd417(%rip),%rax        # 10e00 <EDMM_supported>
    39e9:	8b 00                	mov    (%rax),%eax
    39eb:	85 c0                	test   %eax,%eax
    39ed:	74 6c                	je     3a5b <get_rsrv_size+0x8c>
    {
        for (uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    39ef:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    39f6:	48 8d 05 83 97 00 00 	lea    0x9783(%rip),%rax        # d180 <g_global_data>
    39fd:	8b 80 28 01 00 00    	mov    0x128(%rax),%eax
    3a03:	39 45 f4             	cmp    %eax,-0xc(%rbp)
    3a06:	0f 92 c0             	setb   %al
    3a09:	84 c0                	test   %al,%al
    3a0b:	74 4e                	je     3a5b <get_rsrv_size+0x8c>
        {
            if (g_global_data.layout_table[i].entry.id == LAYOUT_ID_RSRV_MAX)
    3a0d:	48 8d 05 6c 97 00 00 	lea    0x976c(%rip),%rax        # d180 <g_global_data>
    3a14:	8b 55 f4             	mov    -0xc(%rbp),%edx
    3a17:	48 c1 e2 05          	shl    $0x5,%rdx
    3a1b:	48 01 d0             	add    %rdx,%rax
    3a1e:	48 05 30 01 00 00    	add    $0x130,%rax
    3a24:	0f b7 00             	movzwl (%rax),%eax
    3a27:	66 83 f8 16          	cmp    $0x16,%ax
    3a2b:	0f 94 c0             	sete   %al
    3a2e:	84 c0                	test   %al,%al
    3a30:	74 23                	je     3a55 <get_rsrv_size+0x86>
            {
                rsrv_size += ((size_t)g_global_data.layout_table[i].entry.page_count << SE_PAGE_SHIFT);
    3a32:	48 8d 05 47 97 00 00 	lea    0x9747(%rip),%rax        # d180 <g_global_data>
    3a39:	8b 55 f4             	mov    -0xc(%rbp),%edx
    3a3c:	48 c1 e2 05          	shl    $0x5,%rdx
    3a40:	48 01 d0             	add    %rdx,%rax
    3a43:	48 05 34 01 00 00    	add    $0x134,%rax
    3a49:	8b 00                	mov    (%rax),%eax
    3a4b:	89 c0                	mov    %eax,%eax
    3a4d:	48 c1 e0 0c          	shl    $0xc,%rax
    3a51:	48 01 45 f8          	add    %rax,-0x8(%rbp)
        for (uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    3a55:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    3a59:	eb 9b                	jmp    39f6 <get_rsrv_size+0x27>
            }
        }
    }
    return rsrv_size;
    3a5b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
}
    3a5f:	5d                   	pop    %rbp
    3a60:	c3                   	retq   

0000000000003a61 <get_rsrv_min_size>:

size_t get_rsrv_min_size(void)
{
    3a61:	55                   	push   %rbp
    3a62:	48 89 e5             	mov    %rsp,%rbp
    size_t rsrv_size = 0;
    3a65:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    3a6c:	00 
    for (uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    3a6d:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    3a74:	48 8d 05 05 97 00 00 	lea    0x9705(%rip),%rax        # d180 <g_global_data>
    3a7b:	8b 80 28 01 00 00    	mov    0x128(%rax),%eax
    3a81:	39 45 f4             	cmp    %eax,-0xc(%rbp)
    3a84:	0f 92 c0             	setb   %al
    3a87:	84 c0                	test   %al,%al
    3a89:	74 50                	je     3adb <get_rsrv_min_size+0x7a>
    {
        if (g_global_data.layout_table[i].entry.id == LAYOUT_ID_RSRV_MIN)
    3a8b:	48 8d 05 ee 96 00 00 	lea    0x96ee(%rip),%rax        # d180 <g_global_data>
    3a92:	8b 55 f4             	mov    -0xc(%rbp),%edx
    3a95:	48 c1 e2 05          	shl    $0x5,%rdx
    3a99:	48 01 d0             	add    %rdx,%rax
    3a9c:	48 05 30 01 00 00    	add    $0x130,%rax
    3aa2:	0f b7 00             	movzwl (%rax),%eax
    3aa5:	66 83 f8 14          	cmp    $0x14,%ax
    3aa9:	0f 94 c0             	sete   %al
    3aac:	84 c0                	test   %al,%al
    3aae:	74 25                	je     3ad5 <get_rsrv_min_size+0x74>
        {
            rsrv_size = ((size_t)g_global_data.layout_table[i].entry.page_count << SE_PAGE_SHIFT);
    3ab0:	48 8d 05 c9 96 00 00 	lea    0x96c9(%rip),%rax        # d180 <g_global_data>
    3ab7:	8b 55 f4             	mov    -0xc(%rbp),%edx
    3aba:	48 c1 e2 05          	shl    $0x5,%rdx
    3abe:	48 01 d0             	add    %rdx,%rax
    3ac1:	48 05 34 01 00 00    	add    $0x134,%rax
    3ac7:	8b 00                	mov    (%rax),%eax
    3ac9:	89 c0                	mov    %eax,%eax
    3acb:	48 c1 e0 0c          	shl    $0xc,%rax
    3acf:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
            break;
    3ad3:	eb 06                	jmp    3adb <get_rsrv_min_size+0x7a>
    for (uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    3ad5:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    3ad9:	eb 99                	jmp    3a74 <get_rsrv_min_size+0x13>
        }
    }
    return rsrv_size;
    3adb:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
}
    3adf:	5d                   	pop    %rbp
    3ae0:	c3                   	retq   

0000000000003ae1 <get_errno_addr>:

int * get_errno_addr(void)
{
    3ae1:	55                   	push   %rbp
    3ae2:	48 89 e5             	mov    %rsp,%rbp
    3ae5:	48 83 ec 10          	sub    $0x10,%rsp
    thread_data_t *thread_data = get_thread_data();
    3ae9:	e8 3e 8b 00 00       	callq  c62c <get_thread_data>
    3aee:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    return reinterpret_cast<int *>(&thread_data->last_error);
    3af2:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3af6:	48 83 c0 40          	add    $0x40,%rax
}
    3afa:	c9                   	leaveq 
    3afb:	c3                   	retq   

0000000000003afc <feature_supported>:
//Features listed in array[0], counting from right-most bit  to left-most bit,
//have feature shift values 0 ~ 62, while features listed in array[1], have feature
//shift values 64 ~ 126.

int feature_supported(const uint64_t *feature_set, uint32_t feature_shift)
{
    3afc:	55                   	push   %rbp
    3afd:	48 89 e5             	mov    %rsp,%rbp
    3b00:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    3b04:	89 75 e4             	mov    %esi,-0x1c(%rbp)
    const uint64_t *f_set = feature_set;
    3b07:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3b0b:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    uint32_t bit_position = 0, i = 0;
    3b0f:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    3b16:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%rbp)

    if (!f_set)
    3b1d:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    3b22:	75 07                	jne    3b2b <feature_supported+0x2f>
        return 0;
    3b24:	b8 00 00 00 00       	mov    $0x0,%eax
    3b29:	eb 79                	jmp    3ba4 <feature_supported+0xa8>

    while (((i+1) << 6) <= feature_shift)
    3b2b:	8b 45 f0             	mov    -0x10(%rbp),%eax
    3b2e:	83 c0 01             	add    $0x1,%eax
    3b31:	c1 e0 06             	shl    $0x6,%eax
    3b34:	39 45 e4             	cmp    %eax,-0x1c(%rbp)
    3b37:	72 27                	jb     3b60 <feature_supported+0x64>
    {
        if (f_set[i] & (0x1ULL << 63))
    3b39:	8b 45 f0             	mov    -0x10(%rbp),%eax
    3b3c:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3b43:	00 
    3b44:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3b48:	48 01 d0             	add    %rdx,%rax
    3b4b:	48 8b 00             	mov    (%rax),%rax
    3b4e:	48 85 c0             	test   %rax,%rax
    3b51:	79 07                	jns    3b5a <feature_supported+0x5e>
            return 0;
    3b53:	b8 00 00 00 00       	mov    $0x0,%eax
    3b58:	eb 4a                	jmp    3ba4 <feature_supported+0xa8>
        i++;
    3b5a:	83 45 f0 01          	addl   $0x1,-0x10(%rbp)
    while (((i+1) << 6) <= feature_shift)
    3b5e:	eb cb                	jmp    3b2b <feature_supported+0x2f>
    }
    bit_position = feature_shift - (i << 6);
    3b60:	8b 45 f0             	mov    -0x10(%rbp),%eax
    3b63:	c1 e0 06             	shl    $0x6,%eax
    3b66:	89 c2                	mov    %eax,%edx
    3b68:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    3b6b:	29 d0                	sub    %edx,%eax
    3b6d:	89 45 f4             	mov    %eax,-0xc(%rbp)
    if (f_set[i] & (0x1ULL << bit_position))
    3b70:	8b 45 f0             	mov    -0x10(%rbp),%eax
    3b73:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3b7a:	00 
    3b7b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3b7f:	48 01 d0             	add    %rdx,%rax
    3b82:	48 8b 10             	mov    (%rax),%rdx
    3b85:	8b 45 f4             	mov    -0xc(%rbp),%eax
    3b88:	89 c1                	mov    %eax,%ecx
    3b8a:	48 d3 ea             	shr    %cl,%rdx
    3b8d:	48 89 d0             	mov    %rdx,%rax
    3b90:	83 e0 01             	and    $0x1,%eax
    3b93:	48 85 c0             	test   %rax,%rax
    3b96:	74 07                	je     3b9f <feature_supported+0xa3>
        return 1;
    3b98:	b8 01 00 00 00       	mov    $0x1,%eax
    3b9d:	eb 05                	jmp    3ba4 <feature_supported+0xa8>
    else
        return 0;
    3b9f:	b8 00 00 00 00       	mov    $0x0,%eax
}
    3ba4:	5d                   	pop    %rbp
    3ba5:	c3                   	retq   

0000000000003ba6 <is_stack_addr>:

bool is_stack_addr(void *address, size_t size)
{
    3ba6:	55                   	push   %rbp
    3ba7:	48 89 e5             	mov    %rsp,%rbp
    3baa:	48 83 ec 30          	sub    $0x30,%rsp
    3bae:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    3bb2:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    thread_data_t *thread_data = get_thread_data();
    3bb6:	e8 71 8a 00 00       	callq  c62c <get_thread_data>
    3bbb:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    size_t stack_base = thread_data->stack_base_addr;
    3bbf:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3bc3:	48 8b 40 10          	mov    0x10(%rax),%rax
    3bc7:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    size_t stack_limit  = thread_data->stack_limit_addr;
    3bcb:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3bcf:	48 8b 40 18          	mov    0x18(%rax),%rax
    3bd3:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    size_t addr = (size_t) address;
    3bd7:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3bdb:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    return (addr <= (addr + size)) && (stack_base >= (addr + size)) && (stack_limit <= addr);
    3bdf:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    3be3:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    3be7:	48 01 d0             	add    %rdx,%rax
    3bea:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    3bee:	77 22                	ja     3c12 <is_stack_addr+0x6c>
    3bf0:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    3bf4:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    3bf8:	48 01 d0             	add    %rdx,%rax
    3bfb:	48 39 45 e8          	cmp    %rax,-0x18(%rbp)
    3bff:	72 11                	jb     3c12 <is_stack_addr+0x6c>
    3c01:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    3c05:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    3c09:	77 07                	ja     3c12 <is_stack_addr+0x6c>
    3c0b:	b8 01 00 00 00       	mov    $0x1,%eax
    3c10:	eb 05                	jmp    3c17 <is_stack_addr+0x71>
    3c12:	b8 00 00 00 00       	mov    $0x0,%eax
}
    3c17:	c9                   	leaveq 
    3c18:	c3                   	retq   

0000000000003c19 <is_valid_sp>:

bool is_valid_sp(uintptr_t sp)
{
    3c19:	55                   	push   %rbp
    3c1a:	48 89 e5             	mov    %rsp,%rbp
    3c1d:	48 83 ec 10          	sub    $0x10,%rsp
    3c21:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    return ( !(sp & (sizeof(uintptr_t) - 1))   // sp is expected to be 4/8 bytes aligned
    3c25:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3c29:	83 e0 07             	and    $0x7,%eax
           && is_stack_addr((void*)sp, 0) );   // sp points to the top/bottom of stack are accepted
    3c2c:	48 85 c0             	test   %rax,%rax
    3c2f:	75 1c                	jne    3c4d <is_valid_sp+0x34>
    3c31:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3c35:	be 00 00 00 00       	mov    $0x0,%esi
    3c3a:	48 89 c7             	mov    %rax,%rdi
    3c3d:	e8 64 ff ff ff       	callq  3ba6 <is_stack_addr>
    3c42:	84 c0                	test   %al,%al
    3c44:	74 07                	je     3c4d <is_valid_sp+0x34>
    3c46:	b8 01 00 00 00       	mov    $0x1,%eax
    3c4b:	eb 05                	jmp    3c52 <is_valid_sp+0x39>
    3c4d:	b8 00 00 00 00       	mov    $0x0,%eax
}
    3c52:	c9                   	leaveq 
    3c53:	c3                   	retq   

0000000000003c54 <is_utility_thread>:


bool is_utility_thread()
{
    3c54:	55                   	push   %rbp
    3c55:	48 89 e5             	mov    %rsp,%rbp
    3c58:	48 83 ec 10          	sub    $0x10,%rsp
    thread_data_t *thread_data = get_thread_data();
    3c5c:	e8 cb 89 00 00       	callq  c62c <get_thread_data>
    3c61:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if ((thread_data != NULL) && (thread_data->flags & SGX_UTILITY_THREAD))
    3c65:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    3c6a:	74 17                	je     3c83 <is_utility_thread+0x2f>
    3c6c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3c70:	48 8b 40 30          	mov    0x30(%rax),%rax
    3c74:	83 e0 01             	and    $0x1,%eax
    3c77:	48 85 c0             	test   %rax,%rax
    3c7a:	74 07                	je     3c83 <is_utility_thread+0x2f>
    {
        return true;
    3c7c:	b8 01 00 00 00       	mov    $0x1,%eax
    3c81:	eb 05                	jmp    3c88 <is_utility_thread+0x34>
    }
    return false;
    3c83:	b8 00 00 00 00       	mov    $0x0,%eax
}
    3c88:	c9                   	leaveq 
    3c89:	c3                   	retq   

0000000000003c8a <internal_handle_exception>:
// internal_handle_exception(sgx_exception_info_t *info):
//      the 2nd phrase exception handing, which traverse registered exception handlers.
//      if the exception can be handled, then continue execution
//      otherwise, throw abortion, go back to 1st phrase, and call the default handler.
extern "C" __attribute__((regparm(1))) void internal_handle_exception(sgx_exception_info_t *info)
{
    3c8a:	55                   	push   %rbp
    3c8b:	48 89 e5             	mov    %rsp,%rbp
    3c8e:	48 83 ec 50          	sub    $0x50,%rsp
    3c92:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    int status = EXCEPTION_CONTINUE_SEARCH;
    3c96:	c7 45 c4 00 00 00 00 	movl   $0x0,-0x3c(%rbp)
    handler_node_t *node = NULL;
    3c9d:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    3ca4:	00 
    thread_data_t *thread_data = get_thread_data();
    3ca5:	e8 82 89 00 00       	callq  c62c <get_thread_data>
    3caa:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    size_t size = 0;
    3cae:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    3cb5:	00 
    uintptr_t *nhead = NULL;
    3cb6:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    3cbd:	00 
    uintptr_t *ntmp = NULL;
    3cbe:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    3cc5:	00 
    uintptr_t xsp = 0;
    3cc6:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
    3ccd:	00 

    if (thread_data->exception_flag < 0)
    3cce:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3cd2:	48 8b 40 60          	mov    0x60(%rax),%rax
    3cd6:	48 85 c0             	test   %rax,%rax
    3cd9:	0f 88 8c 01 00 00    	js     3e6b <internal_handle_exception+0x1e1>
        goto failed_end;
    thread_data->exception_flag++;
    3cdf:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3ce3:	48 8b 40 60          	mov    0x60(%rax),%rax
    3ce7:	48 8d 50 01          	lea    0x1(%rax),%rdx
    3ceb:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3cef:	48 89 50 60          	mov    %rdx,0x60(%rax)

    // read lock
    sgx_spin_lock(&g_handler_lock);
    3cf3:	48 8d 3d e6 d3 00 00 	lea    0xd3e6(%rip),%rdi        # 110e0 <_ZL14g_handler_lock>
    3cfa:	e8 8d 76 00 00       	callq  b38c <sgx_spin_lock>

    node = g_first_node;
    3cff:	48 8b 05 d2 d3 00 00 	mov    0xd3d2(%rip),%rax        # 110d8 <_ZL12g_first_node>
    3d06:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    while(node != NULL)
    3d0a:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    3d0f:	74 13                	je     3d24 <internal_handle_exception+0x9a>
    {
        size += sizeof(uintptr_t);
    3d11:	48 83 45 d0 08       	addq   $0x8,-0x30(%rbp)
        node = node->next;
    3d16:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3d1a:	48 8b 40 08          	mov    0x8(%rax),%rax
    3d1e:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    while(node != NULL)
    3d22:	eb e6                	jmp    3d0a <internal_handle_exception+0x80>
    }

    // There's no exception handler registered
    if (size == 0)
    3d24:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    3d29:	75 24                	jne    3d4f <internal_handle_exception+0xc5>
    {
        sgx_spin_unlock(&g_handler_lock);
    3d2b:	48 8d 3d ae d3 00 00 	lea    0xd3ae(%rip),%rdi        # 110e0 <_ZL14g_handler_lock>
    3d32:	e8 bc 76 00 00       	callq  b3f3 <sgx_spin_unlock>

        //exception cannot be handled
        thread_data->exception_flag = -1;
    3d37:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3d3b:	48 c7 40 60 ff ff ff 	movq   $0xffffffffffffffff,0x60(%rax)
    3d42:	ff 

        //instruction triggering the exception will be executed again.
        continue_execution(info);
    3d43:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3d47:	48 89 c7             	mov    %rax,%rdi
    3d4a:	e8 1b 8c 00 00       	callq  c96a <continue_execution>
    }

    if ((nhead = (uintptr_t *)malloc(size)) == NULL)
    3d4f:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    3d53:	48 89 c7             	mov    %rax,%rdi
    3d56:	e8 da 4f 00 00       	callq  8d35 <dlmalloc>
    3d5b:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    3d5f:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    3d64:	0f 94 c0             	sete   %al
    3d67:	84 c0                	test   %al,%al
    3d69:	74 11                	je     3d7c <internal_handle_exception+0xf2>
    {
        sgx_spin_unlock(&g_handler_lock);
    3d6b:	48 8d 3d 6e d3 00 00 	lea    0xd36e(%rip),%rdi        # 110e0 <_ZL14g_handler_lock>
    3d72:	e8 7c 76 00 00       	callq  b3f3 <sgx_spin_unlock>
        goto failed_end;
    3d77:	e9 f3 00 00 00       	jmpq   3e6f <internal_handle_exception+0x1e5>
    }
    ntmp = nhead;
    3d7c:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3d80:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    node = g_first_node;
    3d84:	48 8b 05 4d d3 00 00 	mov    0xd34d(%rip),%rax        # 110d8 <_ZL12g_first_node>
    3d8b:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    while(node != NULL)
    3d8f:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    3d94:	74 21                	je     3db7 <internal_handle_exception+0x12d>
    {
        *ntmp = node->callback;
    3d96:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3d9a:	48 8b 10             	mov    (%rax),%rdx
    3d9d:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3da1:	48 89 10             	mov    %rdx,(%rax)
        ntmp++;
    3da4:	48 83 45 d8 08       	addq   $0x8,-0x28(%rbp)
        node = node->next;
    3da9:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3dad:	48 8b 40 08          	mov    0x8(%rax),%rax
    3db1:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    while(node != NULL)
    3db5:	eb d8                	jmp    3d8f <internal_handle_exception+0x105>
    }

    // read unlock
    sgx_spin_unlock(&g_handler_lock);
    3db7:	48 8d 3d 22 d3 00 00 	lea    0xd322(%rip),%rdi        # 110e0 <_ZL14g_handler_lock>
    3dbe:	e8 30 76 00 00       	callq  b3f3 <sgx_spin_unlock>

    // call exception handler until EXCEPTION_CONTINUE_EXECUTION is returned
    ntmp = nhead;
    3dc3:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3dc7:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    while(size > 0)
    3dcb:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    3dd0:	74 38                	je     3e0a <internal_handle_exception+0x180>
    {
        sgx_exception_handler_t handler = DEC_VEH_POINTER(*ntmp);
    3dd2:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3dd6:	48 8b 10             	mov    (%rax),%rdx
    3dd9:	48 8b 05 08 d3 00 00 	mov    0xd308(%rip),%rax        # 110e8 <_ZL12g_veh_cookie>
    3de0:	48 31 d0             	xor    %rdx,%rax
    3de3:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
        status = handler(info);
    3de7:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
    3deb:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3def:	48 89 d7             	mov    %rdx,%rdi
    3df2:	ff d0                	callq  *%rax
    3df4:	89 45 c4             	mov    %eax,-0x3c(%rbp)
        if(EXCEPTION_CONTINUE_EXECUTION == status)
    3df7:	83 7d c4 ff          	cmpl   $0xffffffff,-0x3c(%rbp)
    3dfb:	74 0c                	je     3e09 <internal_handle_exception+0x17f>
        {
            break;
        }
        ntmp++;
    3dfd:	48 83 45 d8 08       	addq   $0x8,-0x28(%rbp)
        size -= sizeof(sgx_exception_handler_t);
    3e02:	48 83 6d d0 08       	subq   $0x8,-0x30(%rbp)
    while(size > 0)
    3e07:	eb c2                	jmp    3dcb <internal_handle_exception+0x141>
            break;
    3e09:	90                   	nop
    }
    free(nhead);
    3e0a:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3e0e:	48 89 c7             	mov    %rax,%rdi
    3e11:	e8 16 5a 00 00       	callq  982c <dlfree>

    // call default handler
    // ignore invalid return value, treat to EXCEPTION_CONTINUE_SEARCH
    // check SP to be written on SSA is pointing to the trusted stack
    xsp = info->cpu_context.REG(sp);
    3e16:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3e1a:	48 8b 40 20          	mov    0x20(%rax),%rax
    3e1e:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    if (!is_valid_sp(xsp))
    3e22:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    3e26:	48 89 c7             	mov    %rax,%rdi
    3e29:	e8 eb fd ff ff       	callq  3c19 <is_valid_sp>
    3e2e:	83 f0 01             	xor    $0x1,%eax
    3e31:	84 c0                	test   %al,%al
    3e33:	75 39                	jne    3e6e <internal_handle_exception+0x1e4>
    {
        goto failed_end;
    }

    if(EXCEPTION_CONTINUE_EXECUTION == status)
    3e35:	83 7d c4 ff          	cmpl   $0xffffffff,-0x3c(%rbp)
    3e39:	75 16                	jne    3e51 <internal_handle_exception+0x1c7>
    {
        //exception is handled, decrease the nested exception count
        thread_data->exception_flag--;
    3e3b:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3e3f:	48 8b 40 60          	mov    0x60(%rax),%rax
    3e43:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    3e47:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3e4b:	48 89 50 60          	mov    %rdx,0x60(%rax)
    3e4f:	eb 0c                	jmp    3e5d <internal_handle_exception+0x1d3>
    }
    else
    {
        //exception cannot be handled
        thread_data->exception_flag = -1;
    3e51:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3e55:	48 c7 40 60 ff ff ff 	movq   $0xffffffffffffffff,0x60(%rax)
    3e5c:	ff 
    }

    //instruction triggering the exception will be executed again.
    continue_execution(info);
    3e5d:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3e61:	48 89 c7             	mov    %rax,%rdi
    3e64:	e8 01 8b 00 00       	callq  c96a <continue_execution>
    3e69:	eb 04                	jmp    3e6f <internal_handle_exception+0x1e5>
        goto failed_end;
    3e6b:	90                   	nop
    3e6c:	eb 01                	jmp    3e6f <internal_handle_exception+0x1e5>
        goto failed_end;
    3e6e:	90                   	nop

failed_end:
    thread_data->exception_flag = -1; // mark the current exception cannot be handled
    3e6f:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3e73:	48 c7 40 60 ff ff ff 	movq   $0xffffffffffffffff,0x60(%rax)
    3e7a:	ff 
    abort();    // throw abortion
    3e7b:	e8 db 8a 00 00       	callq  c95b <abort>

0000000000003e80 <_ZL21expand_stack_by_pagesPvm>:
}

static int expand_stack_by_pages(void *start_addr, size_t page_count)
{
    3e80:	55                   	push   %rbp
    3e81:	48 89 e5             	mov    %rsp,%rbp
    3e84:	48 83 ec 20          	sub    $0x20,%rsp
    3e88:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    3e8c:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    int ret = -1;
    3e90:	c7 45 fc ff ff ff ff 	movl   $0xffffffff,-0x4(%rbp)

    if ((start_addr == NULL) || (page_count == 0))
    3e97:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    3e9c:	74 07                	je     3ea5 <_ZL21expand_stack_by_pagesPvm+0x25>
    3e9e:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
    3ea3:	75 07                	jne    3eac <_ZL21expand_stack_by_pagesPvm+0x2c>
        return -1;
    3ea5:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    3eaa:	eb 19                	jmp    3ec5 <_ZL21expand_stack_by_pagesPvm+0x45>

    ret = apply_pages_within_exception(start_addr, page_count);
    3eac:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    3eb0:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3eb4:	48 89 d6             	mov    %rdx,%rsi
    3eb7:	48 89 c7             	mov    %rax,%rdi
    3eba:	e8 7c e2 ff ff       	callq  213b <apply_pages_within_exception>
    3ebf:	89 45 fc             	mov    %eax,-0x4(%rbp)
    return ret;
    3ec2:	8b 45 fc             	mov    -0x4(%rbp),%eax
}
    3ec5:	c9                   	leaveq 
    3ec6:	c3                   	retq   

0000000000003ec7 <trts_handle_exception>:
//      the pointer of TCS
// Return Value
//      none zero - success
//              0 - fail
extern "C" sgx_status_t trts_handle_exception(void *tcs)
{
    3ec7:	55                   	push   %rbp
    3ec8:	48 89 e5             	mov    %rsp,%rbp
    3ecb:	48 83 ec 50          	sub    $0x50,%rsp
    3ecf:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    thread_data_t *thread_data = get_thread_data();
    3ed3:	e8 54 87 00 00       	callq  c62c <get_thread_data>
    3ed8:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    ssa_gpr_t *ssa_gpr = NULL;
    3edc:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    3ee3:	00 
    sgx_exception_info_t *info = NULL;
    3ee4:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    3eeb:	00 
    uintptr_t sp, *new_sp = NULL;
    3eec:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    3ef3:	00 
    size_t size = 0;
    3ef4:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    3efb:	00 

    if ((thread_data == NULL) || (tcs == NULL)) goto default_handler;
    3efc:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    3f01:	0f 84 86 04 00 00    	je     438d <trts_handle_exception+0x4c6>
    3f07:	48 83 7d b8 00       	cmpq   $0x0,-0x48(%rbp)
    3f0c:	0f 84 7b 04 00 00    	je     438d <trts_handle_exception+0x4c6>
    if (check_static_stack_canary(tcs) != 0)
    3f12:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3f16:	48 89 c7             	mov    %rax,%rdi
    3f19:	e8 53 d7 ff ff       	callq  1671 <check_static_stack_canary>
    3f1e:	85 c0                	test   %eax,%eax
    3f20:	0f 95 c0             	setne  %al
    3f23:	84 c0                	test   %al,%al
    3f25:	0f 85 65 04 00 00    	jne    4390 <trts_handle_exception+0x4c9>
        goto default_handler;
 
    if(get_enclave_state() != ENCLAVE_INIT_DONE)
    3f2b:	e8 c9 86 00 00       	callq  c5f9 <get_enclave_state>
    3f30:	83 f8 02             	cmp    $0x2,%eax
    3f33:	0f 95 c0             	setne  %al
    3f36:	84 c0                	test   %al,%al
    3f38:	0f 85 55 04 00 00    	jne    4393 <trts_handle_exception+0x4cc>
    {
        goto default_handler;
    }
    
    // check if the exception is raised from 2nd phrase
    if(thread_data->exception_flag == -1) {
    3f3e:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3f42:	48 8b 40 60          	mov    0x60(%rax),%rax
    3f46:	48 83 f8 ff          	cmp    $0xffffffffffffffff,%rax
    3f4a:	0f 84 46 04 00 00    	je     4396 <trts_handle_exception+0x4cf>
        goto default_handler;
    }
 
    if ((TD2TCS(thread_data) != tcs) 
    3f50:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3f54:	48 8b 40 10          	mov    0x10(%rax),%rax
    3f58:	48 05 b0 02 01 00    	add    $0x102b0,%rax
    3f5e:	48 39 45 b8          	cmp    %rax,-0x48(%rbp)
    3f62:	0f 85 25 04 00 00    	jne    438d <trts_handle_exception+0x4c6>
            || (((thread_data->first_ssa_gpr)&(~0xfff)) - SE_PAGE_SIZE) != (uintptr_t)tcs) {
    3f68:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3f6c:	48 8b 40 20          	mov    0x20(%rax),%rax
    3f70:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    3f76:	48 8d 90 00 f0 ff ff 	lea    -0x1000(%rax),%rdx
    3f7d:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3f81:	48 39 c2             	cmp    %rax,%rdx
    3f84:	0f 85 03 04 00 00    	jne    438d <trts_handle_exception+0x4c6>
        goto default_handler;
    }

    // no need to check the result of ssa_gpr because thread_data is always trusted
    ssa_gpr = reinterpret_cast<ssa_gpr_t *>(thread_data->first_ssa_gpr);
    3f8a:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3f8e:	48 8b 40 20          	mov    0x20(%rax),%rax
    3f92:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    
    sp = ssa_gpr->REG(sp);
    3f96:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    3f9a:	48 8b 40 20          	mov    0x20(%rax),%rax
    3f9e:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    if(!is_stack_addr((void*)sp, 0))  // check stack overrun only, alignment will be checked after exception handled
    3fa2:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    3fa6:	be 00 00 00 00       	mov    $0x0,%esi
    3fab:	48 89 c7             	mov    %rax,%rdi
    3fae:	e8 f3 fb ff ff       	callq  3ba6 <is_stack_addr>
    3fb3:	83 f0 01             	xor    $0x1,%eax
    3fb6:	84 c0                	test   %al,%al
    3fb8:	74 17                	je     3fd1 <trts_handle_exception+0x10a>
    {
        g_enclave_state = ENCLAVE_CRASHED;
    3fba:	48 8d 05 df d0 00 00 	lea    0xd0df(%rip),%rax        # 110a0 <g_enclave_state>
    3fc1:	c7 00 03 00 00 00    	movl   $0x3,(%rax)
        return SGX_ERROR_STACK_OVERRUN;
    3fc7:	b8 09 10 00 00       	mov    $0x1009,%eax
    3fcc:	e9 db 03 00 00       	jmpq   43ac <trts_handle_exception+0x4e5>
    }

    size = 0;
    3fd1:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    3fd8:	00 
    // x86_64 requires a 128-bytes red zone, which begins directly
    // after the return addr and includes func's arguments
    size += RED_ZONE_SIZE;
    3fd9:	48 83 6d e8 80       	subq   $0xffffffffffffff80,-0x18(%rbp)

    // decrease the stack to give space for info
    size += sizeof(sgx_exception_info_t);
    3fde:	48 81 45 e8 98 00 00 	addq   $0x98,-0x18(%rbp)
    3fe5:	00 
    sp -= size;
    3fe6:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3fea:	48 29 45 f0          	sub    %rax,-0x10(%rbp)
    sp = sp & ~0xF;
    3fee:	48 83 65 f0 f0       	andq   $0xfffffffffffffff0,-0x10(%rbp)

    // check the decreased sp to make sure it is in the trusted stack range
    if(!is_stack_addr((void *)sp, size))
    3ff3:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    3ff7:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    3ffb:	48 89 d6             	mov    %rdx,%rsi
    3ffe:	48 89 c7             	mov    %rax,%rdi
    4001:	e8 a0 fb ff ff       	callq  3ba6 <is_stack_addr>
    4006:	83 f0 01             	xor    $0x1,%eax
    4009:	84 c0                	test   %al,%al
    400b:	74 17                	je     4024 <trts_handle_exception+0x15d>
    {
        g_enclave_state = ENCLAVE_CRASHED;
    400d:	48 8d 05 8c d0 00 00 	lea    0xd08c(%rip),%rax        # 110a0 <g_enclave_state>
    4014:	c7 00 03 00 00 00    	movl   $0x3,(%rax)
        return SGX_ERROR_STACK_OVERRUN;
    401a:	b8 09 10 00 00       	mov    $0x1009,%eax
    401f:	e9 88 03 00 00       	jmpq   43ac <trts_handle_exception+0x4e5>
    }

    info = (sgx_exception_info_t *)sp;
    4024:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4028:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    // decrease the stack to save the SSA[0]->ip
    size = sizeof(uintptr_t);
    402c:	48 c7 45 e8 08 00 00 	movq   $0x8,-0x18(%rbp)
    4033:	00 
    sp -= size;
    4034:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4038:	48 29 45 f0          	sub    %rax,-0x10(%rbp)
    if(!is_stack_addr((void *)sp, size))
    403c:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4040:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    4044:	48 89 d6             	mov    %rdx,%rsi
    4047:	48 89 c7             	mov    %rax,%rdi
    404a:	e8 57 fb ff ff       	callq  3ba6 <is_stack_addr>
    404f:	83 f0 01             	xor    $0x1,%eax
    4052:	84 c0                	test   %al,%al
    4054:	74 17                	je     406d <trts_handle_exception+0x1a6>
    {
        g_enclave_state = ENCLAVE_CRASHED;
    4056:	48 8d 05 43 d0 00 00 	lea    0xd043(%rip),%rax        # 110a0 <g_enclave_state>
    405d:	c7 00 03 00 00 00    	movl   $0x3,(%rax)
        return SGX_ERROR_STACK_OVERRUN;
    4063:	b8 09 10 00 00       	mov    $0x1009,%eax
    4068:	e9 3f 03 00 00       	jmpq   43ac <trts_handle_exception+0x4e5>
    }
    
    // sp is within limit_addr and commit_addr, currently only SGX 2.0 under hardware mode will enter this branch.^M
    if((size_t)sp < thread_data->stack_commit_addr)
    406d:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4071:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    4078:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    407c:	0f 83 ca 00 00 00    	jae    414c <trts_handle_exception+0x285>
    { 
        int ret = -1;
    4082:	c7 45 c4 ff ff ff ff 	movl   $0xffffffff,-0x3c(%rbp)
        size_t page_aligned_delta = 0;
    4089:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    4090:	00 
        /* try to allocate memory dynamically */
        page_aligned_delta = ROUND_TO(thread_data->stack_commit_addr - (size_t)sp, SE_PAGE_SIZE);
    4091:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4095:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    409c:	48 2b 45 f0          	sub    -0x10(%rbp),%rax
    40a0:	48 05 ff 0f 00 00    	add    $0xfff,%rax
    40a6:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    40ac:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
        if ((thread_data->stack_commit_addr > page_aligned_delta)
    40b0:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    40b4:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    40bb:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    40bf:	73 47                	jae    4108 <trts_handle_exception+0x241>
                && ((thread_data->stack_commit_addr - page_aligned_delta) >= thread_data->stack_limit_addr))
    40c1:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    40c5:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    40cc:	48 2b 45 f8          	sub    -0x8(%rbp),%rax
    40d0:	48 89 c2             	mov    %rax,%rdx
    40d3:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    40d7:	48 8b 40 18          	mov    0x18(%rax),%rax
    40db:	48 39 c2             	cmp    %rax,%rdx
    40de:	72 28                	jb     4108 <trts_handle_exception+0x241>
        {
            ret = expand_stack_by_pages((void *)(thread_data->stack_commit_addr - page_aligned_delta), (page_aligned_delta >> SE_PAGE_SHIFT));
    40e0:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    40e4:	48 c1 e8 0c          	shr    $0xc,%rax
    40e8:	48 89 c2             	mov    %rax,%rdx
    40eb:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    40ef:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    40f6:	48 2b 45 f8          	sub    -0x8(%rbp),%rax
    40fa:	48 89 d6             	mov    %rdx,%rsi
    40fd:	48 89 c7             	mov    %rax,%rdi
    4100:	e8 7b fd ff ff       	callq  3e80 <_ZL21expand_stack_by_pagesPvm>
    4105:	89 45 c4             	mov    %eax,-0x3c(%rbp)
        }
        if (ret == 0)
    4108:	83 7d c4 00          	cmpl   $0x0,-0x3c(%rbp)
    410c:	75 27                	jne    4135 <trts_handle_exception+0x26e>
        {
            thread_data->stack_commit_addr -= page_aligned_delta;
    410e:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4112:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    4119:	48 2b 45 f8          	sub    -0x8(%rbp),%rax
    411d:	48 89 c2             	mov    %rax,%rdx
    4120:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4124:	48 89 90 98 00 00 00 	mov    %rdx,0x98(%rax)
            return SGX_SUCCESS;
    412b:	b8 00 00 00 00       	mov    $0x0,%eax
    4130:	e9 77 02 00 00       	jmpq   43ac <trts_handle_exception+0x4e5>
        }
        else
        {
            g_enclave_state = ENCLAVE_CRASHED;
    4135:	48 8d 05 64 cf 00 00 	lea    0xcf64(%rip),%rax        # 110a0 <g_enclave_state>
    413c:	c7 00 03 00 00 00    	movl   $0x3,(%rax)
            return SGX_ERROR_STACK_OVERRUN;
    4142:	b8 09 10 00 00       	mov    $0x1009,%eax
    4147:	e9 60 02 00 00       	jmpq   43ac <trts_handle_exception+0x4e5>
        }
    }
    if (size_t(&Lereport_inst) == ssa_gpr->REG(ip) && SE_EREPORT == ssa_gpr->REG(ax))
    414c:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4150:	48 8b 80 88 00 00 00 	mov    0x88(%rax),%rax
    4157:	48 8d 15 a5 87 00 00 	lea    0x87a5(%rip),%rdx        # c903 <Lereport_inst>
    415e:	48 39 d0             	cmp    %rdx,%rax
    4161:	75 4d                	jne    41b0 <trts_handle_exception+0x2e9>
    4163:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4167:	48 8b 00             	mov    (%rax),%rax
    416a:	48 85 c0             	test   %rax,%rax
    416d:	75 41                	jne    41b0 <trts_handle_exception+0x2e9>
    {
        // Handle the exception raised by EREPORT instruction
        ssa_gpr->REG(ip) += 3;     // Skip ENCLU, which is always a 3-byte instruction
    416f:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4173:	48 8b 80 88 00 00 00 	mov    0x88(%rax),%rax
    417a:	48 8d 50 03          	lea    0x3(%rax),%rdx
    417e:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4182:	48 89 90 88 00 00 00 	mov    %rdx,0x88(%rax)
        ssa_gpr->REG(flags) |= 1;  // Set CF to indicate error condition, see implementation of do_report()
    4189:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    418d:	48 8b 80 80 00 00 00 	mov    0x80(%rax),%rax
    4194:	48 83 c8 01          	or     $0x1,%rax
    4198:	48 89 c2             	mov    %rax,%rdx
    419b:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    419f:	48 89 90 80 00 00 00 	mov    %rdx,0x80(%rax)
        return SGX_SUCCESS;
    41a6:	b8 00 00 00 00       	mov    $0x0,%eax
    41ab:	e9 fc 01 00 00       	jmpq   43ac <trts_handle_exception+0x4e5>
    }

    if(ssa_gpr->exit_info.valid != 1)
    41b0:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    41b4:	0f b6 80 a3 00 00 00 	movzbl 0xa3(%rax),%eax
    41bb:	83 e0 80             	and    $0xffffff80,%eax
    41be:	84 c0                	test   %al,%al
    41c0:	0f 84 d3 01 00 00    	je     4399 <trts_handle_exception+0x4d2>
    {   // exception handlers are not allowed to call in a non-exception state
        goto default_handler;
    }

    // initialize the info with SSA[0]
    info->exception_vector = (sgx_exception_vector_t)ssa_gpr->exit_info.vector;
    41c6:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    41ca:	0f b6 80 a0 00 00 00 	movzbl 0xa0(%rax),%eax
    41d1:	0f b6 d0             	movzbl %al,%edx
    41d4:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    41d8:	89 90 90 00 00 00    	mov    %edx,0x90(%rax)
    info->exception_type = (sgx_exception_type_t)ssa_gpr->exit_info.exit_type;
    41de:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    41e2:	0f b6 80 a1 00 00 00 	movzbl 0xa1(%rax),%eax
    41e9:	83 e0 07             	and    $0x7,%eax
    41ec:	0f b6 d0             	movzbl %al,%edx
    41ef:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    41f3:	89 90 94 00 00 00    	mov    %edx,0x94(%rax)

    info->cpu_context.REG(ax) = ssa_gpr->REG(ax);
    41f9:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    41fd:	48 8b 10             	mov    (%rax),%rdx
    4200:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4204:	48 89 10             	mov    %rdx,(%rax)
    info->cpu_context.REG(cx) = ssa_gpr->REG(cx);
    4207:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    420b:	48 8b 50 08          	mov    0x8(%rax),%rdx
    420f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4213:	48 89 50 08          	mov    %rdx,0x8(%rax)
    info->cpu_context.REG(dx) = ssa_gpr->REG(dx);
    4217:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    421b:	48 8b 50 10          	mov    0x10(%rax),%rdx
    421f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4223:	48 89 50 10          	mov    %rdx,0x10(%rax)
    info->cpu_context.REG(bx) = ssa_gpr->REG(bx);
    4227:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    422b:	48 8b 50 18          	mov    0x18(%rax),%rdx
    422f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4233:	48 89 50 18          	mov    %rdx,0x18(%rax)
    info->cpu_context.REG(sp) = ssa_gpr->REG(sp);
    4237:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    423b:	48 8b 50 20          	mov    0x20(%rax),%rdx
    423f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4243:	48 89 50 20          	mov    %rdx,0x20(%rax)
    info->cpu_context.REG(bp) = ssa_gpr->REG(bp);
    4247:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    424b:	48 8b 50 28          	mov    0x28(%rax),%rdx
    424f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4253:	48 89 50 28          	mov    %rdx,0x28(%rax)
    info->cpu_context.REG(si) = ssa_gpr->REG(si);
    4257:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    425b:	48 8b 50 30          	mov    0x30(%rax),%rdx
    425f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4263:	48 89 50 30          	mov    %rdx,0x30(%rax)
    info->cpu_context.REG(di) = ssa_gpr->REG(di);
    4267:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    426b:	48 8b 50 38          	mov    0x38(%rax),%rdx
    426f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4273:	48 89 50 38          	mov    %rdx,0x38(%rax)
    info->cpu_context.REG(flags) = ssa_gpr->REG(flags);
    4277:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    427b:	48 8b 90 80 00 00 00 	mov    0x80(%rax),%rdx
    4282:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4286:	48 89 90 80 00 00 00 	mov    %rdx,0x80(%rax)
    info->cpu_context.REG(ip) = ssa_gpr->REG(ip);
    428d:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4291:	48 8b 90 88 00 00 00 	mov    0x88(%rax),%rdx
    4298:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    429c:	48 89 90 88 00 00 00 	mov    %rdx,0x88(%rax)
#ifdef SE_64
    info->cpu_context.r8  = ssa_gpr->r8;
    42a3:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    42a7:	48 8b 50 40          	mov    0x40(%rax),%rdx
    42ab:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    42af:	48 89 50 40          	mov    %rdx,0x40(%rax)
    info->cpu_context.r9  = ssa_gpr->r9;
    42b3:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    42b7:	48 8b 50 48          	mov    0x48(%rax),%rdx
    42bb:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    42bf:	48 89 50 48          	mov    %rdx,0x48(%rax)
    info->cpu_context.r10 = ssa_gpr->r10;
    42c3:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    42c7:	48 8b 50 50          	mov    0x50(%rax),%rdx
    42cb:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    42cf:	48 89 50 50          	mov    %rdx,0x50(%rax)
    info->cpu_context.r11 = ssa_gpr->r11;
    42d3:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    42d7:	48 8b 50 58          	mov    0x58(%rax),%rdx
    42db:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    42df:	48 89 50 58          	mov    %rdx,0x58(%rax)
    info->cpu_context.r12 = ssa_gpr->r12;
    42e3:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    42e7:	48 8b 50 60          	mov    0x60(%rax),%rdx
    42eb:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    42ef:	48 89 50 60          	mov    %rdx,0x60(%rax)
    info->cpu_context.r13 = ssa_gpr->r13;
    42f3:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    42f7:	48 8b 50 68          	mov    0x68(%rax),%rdx
    42fb:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    42ff:	48 89 50 68          	mov    %rdx,0x68(%rax)
    info->cpu_context.r14 = ssa_gpr->r14;
    4303:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4307:	48 8b 50 70          	mov    0x70(%rax),%rdx
    430b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    430f:	48 89 50 70          	mov    %rdx,0x70(%rax)
    info->cpu_context.r15 = ssa_gpr->r15;
    4313:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4317:	48 8b 50 78          	mov    0x78(%rax),%rdx
    431b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    431f:	48 89 50 78          	mov    %rdx,0x78(%rax)
#endif

    new_sp = (uintptr_t *)sp;
    4323:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4327:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    ssa_gpr->REG(ip) = (size_t)internal_handle_exception; // prepare the ip for 2nd phrase handling
    432b:	48 8d 15 58 f9 ff ff 	lea    -0x6a8(%rip),%rdx        # 3c8a <internal_handle_exception>
    4332:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4336:	48 89 90 88 00 00 00 	mov    %rdx,0x88(%rax)
    ssa_gpr->REG(sp) = (size_t)new_sp;      // new stack for internal_handle_exception
    433d:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    4341:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4345:	48 89 50 20          	mov    %rdx,0x20(%rax)
    ssa_gpr->REG(ax) = (size_t)info;        // 1st parameter (info) for LINUX32
    4349:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    434d:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4351:	48 89 10             	mov    %rdx,(%rax)
    ssa_gpr->REG(di) = (size_t)info;        // 1st parameter (info) for LINUX64, LINUX32 also uses it while restoring the context
    4354:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    4358:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    435c:	48 89 50 38          	mov    %rdx,0x38(%rax)
    *new_sp = info->cpu_context.REG(ip);    // for debugger to get call trace
    4360:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4364:	48 8b 90 88 00 00 00 	mov    0x88(%rax),%rdx
    436b:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    436f:	48 89 10             	mov    %rdx,(%rax)
    
    //mark valid to 0 to prevent eenter again
    ssa_gpr->exit_info.valid = 0;
    4372:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4376:	0f b6 90 a3 00 00 00 	movzbl 0xa3(%rax),%edx
    437d:	83 e2 7f             	and    $0x7f,%edx
    4380:	88 90 a3 00 00 00    	mov    %dl,0xa3(%rax)

    return SGX_SUCCESS;
    4386:	b8 00 00 00 00       	mov    $0x0,%eax
    438b:	eb 1f                	jmp    43ac <trts_handle_exception+0x4e5>
 
default_handler:
    438d:	90                   	nop
    438e:	eb 0a                	jmp    439a <trts_handle_exception+0x4d3>
        goto default_handler;
    4390:	90                   	nop
    4391:	eb 07                	jmp    439a <trts_handle_exception+0x4d3>
        goto default_handler;
    4393:	90                   	nop
    4394:	eb 04                	jmp    439a <trts_handle_exception+0x4d3>
        goto default_handler;
    4396:	90                   	nop
    4397:	eb 01                	jmp    439a <trts_handle_exception+0x4d3>
        goto default_handler;
    4399:	90                   	nop
    g_enclave_state = ENCLAVE_CRASHED;
    439a:	48 8d 05 ff cc 00 00 	lea    0xccff(%rip),%rax        # 110a0 <g_enclave_state>
    43a1:	c7 00 03 00 00 00    	movl   $0x3,(%rax)
    return SGX_ERROR_ENCLAVE_CRASHED;
    43a7:	b8 06 10 00 00       	mov    $0x1006,%eax
}
    43ac:	c9                   	leaveq 
    43ad:	c3                   	retq   

00000000000043ae <get_xfeature_state>:
#define SE_OPTIMIZE_OFF
#endif

SE_OPTIMIZE_OFF
uint64_t get_xfeature_state()
{
    43ae:	55                   	push   %rbp
    43af:	48 89 e5             	mov    %rsp,%rbp
    43b2:	48 83 ec 10          	sub    $0x10,%rsp
    auto *report = sgx_self_report();
    43b6:	e8 83 77 00 00       	callq  bb3e <sgx_self_report>
    43bb:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    g_xsave_enabled = (report->body.attributes.xfrm == SGX_XFRM_LEGACY) ? 0 : 1;
    43bf:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    43c3:	48 8b 40 38          	mov    0x38(%rax),%rax
    43c7:	48 83 f8 03          	cmp    $0x3,%rax
    43cb:	0f 95 c0             	setne  %al
    43ce:	0f b6 c0             	movzbl %al,%eax
    43d1:	89 05 cd cc 00 00    	mov    %eax,0xcccd(%rip)        # 110a4 <g_xsave_enabled>
    uint64_t xfrm = report->body.attributes.xfrm;
    43d7:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    43db:	48 8b 40 38          	mov    0x38(%rax),%rax
    43df:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
#endif

    // no secrets in target_info, report_data, and report. no need to clear them before return
    // tlibc functions cannot be used before calling init_optimized_libs().

    return xfrm;
    43e3:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
}
    43e7:	c9                   	leaveq 
    43e8:	c3                   	retq   

00000000000043e9 <get_phdr>:

static int elf_tls_aligned_virtual_size(const void *enclave_base,
                            size_t *aligned_virtual_size);

static ElfW(Phdr)* get_phdr(const ElfW(Ehdr)* ehdr)
{
    43e9:	55                   	push   %rbp
    43ea:	48 89 e5             	mov    %rsp,%rbp
    43ed:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    if (ehdr == NULL)
    43f1:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    43f6:	75 07                	jne    43ff <get_phdr+0x16>
        return NULL;  /* Invalid image. */
    43f8:	b8 00 00 00 00       	mov    $0x0,%eax
    43fd:	eb 5a                	jmp    4459 <get_phdr+0x70>

    /* Check the ElfW Magic number. */
    if ((ehdr->e_ident[EI_MAG0] != ELFMAG0) ||
    43ff:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4403:	0f b6 00             	movzbl (%rax),%eax
    4406:	3c 7f                	cmp    $0x7f,%al
    4408:	75 24                	jne    442e <get_phdr+0x45>
        (ehdr->e_ident[EI_MAG1] != ELFMAG1) ||
    440a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    440e:	0f b6 40 01          	movzbl 0x1(%rax),%eax
    if ((ehdr->e_ident[EI_MAG0] != ELFMAG0) ||
    4412:	3c 45                	cmp    $0x45,%al
    4414:	75 18                	jne    442e <get_phdr+0x45>
        (ehdr->e_ident[EI_MAG2] != ELFMAG2) ||
    4416:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    441a:	0f b6 40 02          	movzbl 0x2(%rax),%eax
        (ehdr->e_ident[EI_MAG1] != ELFMAG1) ||
    441e:	3c 4c                	cmp    $0x4c,%al
    4420:	75 0c                	jne    442e <get_phdr+0x45>
        (ehdr->e_ident[EI_MAG3] != ELFMAG3))
    4422:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4426:	0f b6 40 03          	movzbl 0x3(%rax),%eax
        (ehdr->e_ident[EI_MAG2] != ELFMAG2) ||
    442a:	3c 46                	cmp    $0x46,%al
    442c:	74 07                	je     4435 <get_phdr+0x4c>
        return NULL;
    442e:	b8 00 00 00 00       	mov    $0x0,%eax
    4433:	eb 24                	jmp    4459 <get_phdr+0x70>

    /* Enclave image should be a shared object file. */
    if (ehdr->e_type != ET_DYN)
    4435:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4439:	0f b7 40 10          	movzwl 0x10(%rax),%eax
    443d:	66 83 f8 03          	cmp    $0x3,%ax
    4441:	74 07                	je     444a <get_phdr+0x61>
        return NULL;
    4443:	b8 00 00 00 00       	mov    $0x0,%eax
    4448:	eb 0f                	jmp    4459 <get_phdr+0x70>

    return GET_PTR(ElfW(Phdr), ehdr, ehdr->e_phoff);
    444a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    444e:	48 8b 50 20          	mov    0x20(%rax),%rdx
    4452:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4456:	48 01 d0             	add    %rdx,%rax
}
    4459:	5d                   	pop    %rbp
    445a:	c3                   	retq   

000000000000445b <get_sym>:

static ElfW(Sym)* get_sym(ElfW(Sym)* symtab, size_t idx)
{
    445b:	55                   	push   %rbp
    445c:	48 89 e5             	mov    %rsp,%rbp
    445f:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    4463:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    if(STB_WEAK == ELFW(ST_BIND)(symtab[idx].st_info)
    4467:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    446b:	48 89 d0             	mov    %rdx,%rax
    446e:	48 01 c0             	add    %rax,%rax
    4471:	48 01 d0             	add    %rdx,%rax
    4474:	48 c1 e0 03          	shl    $0x3,%rax
    4478:	48 89 c2             	mov    %rax,%rdx
    447b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    447f:	48 01 d0             	add    %rdx,%rax
    4482:	0f b6 40 04          	movzbl 0x4(%rax),%eax
    4486:	c0 e8 04             	shr    $0x4,%al
    4489:	3c 02                	cmp    $0x2,%al
    448b:	75 2b                	jne    44b8 <get_sym+0x5d>
            && 0 == symtab[idx].st_value)
    448d:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    4491:	48 89 d0             	mov    %rdx,%rax
    4494:	48 01 c0             	add    %rax,%rax
    4497:	48 01 d0             	add    %rdx,%rax
    449a:	48 c1 e0 03          	shl    $0x3,%rax
    449e:	48 89 c2             	mov    %rax,%rdx
    44a1:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    44a5:	48 01 d0             	add    %rdx,%rax
    44a8:	48 8b 40 08          	mov    0x8(%rax),%rax
    44ac:	48 85 c0             	test   %rax,%rax
    44af:	75 07                	jne    44b8 <get_sym+0x5d>
    {
        return NULL;
    44b1:	b8 00 00 00 00       	mov    $0x0,%eax
    44b6:	eb 1b                	jmp    44d3 <get_sym+0x78>
    }

    return &symtab[idx];
    44b8:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    44bc:	48 89 d0             	mov    %rdx,%rax
    44bf:	48 01 c0             	add    %rax,%rax
    44c2:	48 01 d0             	add    %rdx,%rax
    44c5:	48 c1 e0 03          	shl    $0x3,%rax
    44c9:	48 89 c2             	mov    %rax,%rdx
    44cc:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    44d0:	48 01 d0             	add    %rdx,%rax
}
    44d3:	5d                   	pop    %rbp
    44d4:	c3                   	retq   

00000000000044d5 <do_relocs>:
/* Relocation for x64 (with addend) */
static int do_relocs(const ElfW(Addr) enclave_base,
        ElfW(Addr) rela_offset,
        ElfW(Addr) sym_offset,
        size_t nr_relocs)
{
    44d5:	55                   	push   %rbp
    44d6:	48 89 e5             	mov    %rsp,%rbp
    44d9:	48 83 ec 60          	sub    $0x60,%rsp
    44dd:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    44e1:	48 89 75 b0          	mov    %rsi,-0x50(%rbp)
    44e5:	48 89 55 a8          	mov    %rdx,-0x58(%rbp)
    44e9:	48 89 4d a0          	mov    %rcx,-0x60(%rbp)
    44ed:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    44f4:	00 00 
    44f6:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    44fa:	31 c0                	xor    %eax,%eax
    ElfW(Rela)* rela = GET_PTR(ElfW(Rela), enclave_base, rela_offset);
    44fc:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
    4500:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    4504:	48 01 d0             	add    %rdx,%rax
    4507:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    ElfW(Sym)*  symtab = GET_PTR(ElfW(Sym), enclave_base, sym_offset);
    450b:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
    450f:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4513:	48 01 d0             	add    %rdx,%rax
    4516:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    ElfW(Sym)*  sym;
    size_t      i;
    size_t aligned_virtual_size = 0;
    451a:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    4521:	00 

    for (i = 0; i < nr_relocs; ++i, ++rela)
    4522:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    4529:	00 
    452a:	e9 a2 01 00 00       	jmpq   46d1 <do_relocs+0x1fc>
    {
        ElfW(Addr)* reloc_addr = GET_PTR(ElfW(Addr), enclave_base, rela->r_offset);
    452f:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4533:	48 8b 10             	mov    (%rax),%rdx
    4536:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    453a:	48 01 d0             	add    %rdx,%rax
    453d:	48 89 45 e8          	mov    %rax,-0x18(%rbp)

        switch (ELF64_R_TYPE(rela->r_info))
    4541:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4545:	48 8b 40 08          	mov    0x8(%rax),%rax
    4549:	89 c0                	mov    %eax,%eax
    454b:	48 83 f8 12          	cmp    $0x12,%rax
    454f:	0f 87 61 01 00 00    	ja     46b6 <do_relocs+0x1e1>
    4555:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
    455c:	00 
    455d:	48 8d 05 10 8b 00 00 	lea    0x8b10(%rip),%rax        # d074 <_ZZL16init_stack_guardPvE8__func__+0x14>
    4564:	8b 04 02             	mov    (%rdx,%rax,1),%eax
    4567:	48 63 d0             	movslq %eax,%rdx
    456a:	48 8d 05 03 8b 00 00 	lea    0x8b03(%rip),%rax        # d074 <_ZZL16init_stack_guardPvE8__func__+0x14>
    4571:	48 01 d0             	add    %rdx,%rax
    4574:	ff e0                	jmpq   *%rax
        {
            case R_X86_64_RELATIVE:
                *reloc_addr = enclave_base + (uintptr_t)rela->r_addend;
    4576:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    457a:	48 8b 40 10          	mov    0x10(%rax),%rax
    457e:	48 89 c2             	mov    %rax,%rdx
    4581:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    4585:	48 01 c2             	add    %rax,%rdx
    4588:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    458c:	48 89 10             	mov    %rdx,(%rax)
                break;
    458f:	e9 33 01 00 00       	jmpq   46c7 <do_relocs+0x1f2>

            case R_X86_64_GLOB_DAT:
            case R_X86_64_JUMP_SLOT:
            case R_X86_64_64:
                sym = get_sym(symtab, ELF64_R_SYM(rela->r_info));
    4594:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4598:	48 8b 40 08          	mov    0x8(%rax),%rax
    459c:	48 c1 e8 20          	shr    $0x20,%rax
    45a0:	48 89 c2             	mov    %rax,%rdx
    45a3:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    45a7:	48 89 d6             	mov    %rdx,%rsi
    45aa:	48 89 c7             	mov    %rax,%rdi
    45ad:	e8 a9 fe ff ff       	callq  445b <get_sym>
    45b2:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
                if(!sym)
    45b6:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    45bb:	0f 84 ff 00 00 00    	je     46c0 <do_relocs+0x1eb>
                    break;
                *reloc_addr = enclave_base + sym->st_value + (uintptr_t)rela->r_addend;
    45c1:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    45c5:	48 8b 50 08          	mov    0x8(%rax),%rdx
    45c9:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    45cd:	48 01 c2             	add    %rax,%rdx
    45d0:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    45d4:	48 8b 40 10          	mov    0x10(%rax),%rax
    45d8:	48 01 c2             	add    %rax,%rdx
    45db:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    45df:	48 89 10             	mov    %rdx,(%rax)
                break;
    45e2:	e9 e0 00 00 00       	jmpq   46c7 <do_relocs+0x1f2>

            case R_X86_64_DTPMOD64:
                *reloc_addr = 1;
    45e7:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    45eb:	48 c7 00 01 00 00 00 	movq   $0x1,(%rax)
                break;
    45f2:	e9 d0 00 00 00       	jmpq   46c7 <do_relocs+0x1f2>
 
            case R_X86_64_DTPOFF64:
                sym = get_sym(symtab, ELF64_R_SYM(rela->r_info));
    45f7:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    45fb:	48 8b 40 08          	mov    0x8(%rax),%rax
    45ff:	48 c1 e8 20          	shr    $0x20,%rax
    4603:	48 89 c2             	mov    %rax,%rdx
    4606:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    460a:	48 89 d6             	mov    %rdx,%rsi
    460d:	48 89 c7             	mov    %rax,%rdi
    4610:	e8 46 fe ff ff       	callq  445b <get_sym>
    4615:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
                if(!sym)
    4619:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    461e:	0f 84 9f 00 00 00    	je     46c3 <do_relocs+0x1ee>
                    break;
                *reloc_addr = sym->st_value + (uintptr_t)rela->r_addend;
    4624:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4628:	48 8b 50 08          	mov    0x8(%rax),%rdx
    462c:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4630:	48 8b 40 10          	mov    0x10(%rax),%rax
    4634:	48 01 c2             	add    %rax,%rdx
    4637:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    463b:	48 89 10             	mov    %rdx,(%rax)
                break;
    463e:	e9 84 00 00 00       	jmpq   46c7 <do_relocs+0x1f2>

            case R_X86_64_TPOFF64:
                sym = get_sym(symtab, ELF64_R_SYM(rela->r_info));
    4643:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4647:	48 8b 40 08          	mov    0x8(%rax),%rax
    464b:	48 c1 e8 20          	shr    $0x20,%rax
    464f:	48 89 c2             	mov    %rax,%rdx
    4652:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    4656:	48 89 d6             	mov    %rdx,%rsi
    4659:	48 89 c7             	mov    %rax,%rdi
    465c:	e8 fa fd ff ff       	callq  445b <get_sym>
    4661:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
                if(!sym)
    4665:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    466a:	74 5a                	je     46c6 <do_relocs+0x1f1>
                    break;

                if ((0 == elf_tls_aligned_virtual_size((void *)enclave_base, &aligned_virtual_size)) && (aligned_virtual_size))
    466c:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    4670:	48 8d 55 c8          	lea    -0x38(%rbp),%rdx
    4674:	48 89 d6             	mov    %rdx,%rsi
    4677:	48 89 c7             	mov    %rax,%rdi
    467a:	e8 4f 03 00 00       	callq  49ce <elf_tls_aligned_virtual_size>
    467f:	85 c0                	test   %eax,%eax
    4681:	75 2c                	jne    46af <do_relocs+0x1da>
    4683:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4687:	48 85 c0             	test   %rax,%rax
    468a:	74 23                	je     46af <do_relocs+0x1da>
                {
                    *reloc_addr = sym->st_value + (uintptr_t)rela->r_addend - aligned_virtual_size;
    468c:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4690:	48 8b 50 08          	mov    0x8(%rax),%rdx
    4694:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4698:	48 8b 40 10          	mov    0x10(%rax),%rax
    469c:	48 01 c2             	add    %rax,%rdx
    469f:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    46a3:	48 29 c2             	sub    %rax,%rdx
    46a6:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    46aa:	48 89 10             	mov    %rdx,(%rax)
                    break;
    46ad:	eb 18                	jmp    46c7 <do_relocs+0x1f2>
                }
                else
                    return -1;
    46af:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    46b4:	eb 2e                	jmp    46e4 <do_relocs+0x20f>

            case R_X86_64_NONE:
                break;

            default:    /* unsupported relocs */
                return -1;
    46b6:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    46bb:	eb 27                	jmp    46e4 <do_relocs+0x20f>
                break;
    46bd:	90                   	nop
    46be:	eb 07                	jmp    46c7 <do_relocs+0x1f2>
                    break;
    46c0:	90                   	nop
    46c1:	eb 04                	jmp    46c7 <do_relocs+0x1f2>
                    break;
    46c3:	90                   	nop
    46c4:	eb 01                	jmp    46c7 <do_relocs+0x1f2>
                    break;
    46c6:	90                   	nop
    for (i = 0; i < nr_relocs; ++i, ++rela)
    46c7:	48 83 45 d8 01       	addq   $0x1,-0x28(%rbp)
    46cc:	48 83 45 d0 18       	addq   $0x18,-0x30(%rbp)
    46d1:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    46d5:	48 3b 45 a0          	cmp    -0x60(%rbp),%rax
    46d9:	0f 82 50 fe ff ff    	jb     452f <do_relocs+0x5a>
        }
    }

    return 0;
    46df:	b8 00 00 00 00       	mov    $0x0,%eax
}
    46e4:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    46e8:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    46ef:	00 00 
    46f1:	74 05                	je     46f8 <do_relocs+0x223>
    46f3:	e8 6f 0b 00 00       	callq  5267 <__stack_chk_fail>
    46f8:	c9                   	leaveq 
    46f9:	c3                   	retq   

00000000000046fa <relocate_enclave>:
 * it local symbol, so the code is like "fce3:	e8 98 12 00 00    call   10f80 <relocate_enclave>"
 * 0x9812=0x10f80-0xfce8
 */
__attribute__ ((visibility ("hidden")))
int relocate_enclave(void* enclave_base)
{
    46fa:	55                   	push   %rbp
    46fb:	48 89 e5             	mov    %rsp,%rbp
    46fe:	48 83 c4 80          	add    $0xffffffffffffff80,%rsp
    4702:	48 89 7d 88          	mov    %rdi,-0x78(%rbp)
    ElfW(Half) phnum = 0;
    4706:	c7 45 94 00 00 00 00 	movl   $0x0,-0x6c(%rbp)
    ElfW(Ehdr) *ehdr = (ElfW(Ehdr)*)enclave_base;
    470d:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    4711:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    ElfW(Phdr) *phdr = get_phdr(ehdr);
    4715:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    4719:	48 89 c7             	mov    %rax,%rdi
    471c:	e8 c8 fc ff ff       	callq  43e9 <get_phdr>
    4721:	48 89 45 98          	mov    %rax,-0x68(%rbp)

    if (phdr == NULL)
    4725:	48 83 7d 98 00       	cmpq   $0x0,-0x68(%rbp)
    472a:	0f 85 c3 01 00 00    	jne    48f3 <relocate_enclave+0x1f9>
        return -1;  /* Invalid image. */
    4730:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4735:	e9 d2 01 00 00       	jmpq   490c <relocate_enclave+0x212>

    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    {
        /* Search for dynamic segment */
        if (phdr->p_type == PT_DYNAMIC)
    473a:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    473e:	8b 00                	mov    (%rax),%eax
    4740:	83 f8 02             	cmp    $0x2,%eax
    4743:	0f 85 a1 01 00 00    	jne    48ea <relocate_enclave+0x1f0>
        {
            size_t      count;
            size_t      n_dyn = phdr->p_filesz/sizeof(ElfW(Dyn));
    4749:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    474d:	48 8b 40 20          	mov    0x20(%rax),%rax
    4751:	48 c1 e8 04          	shr    $0x4,%rax
    4755:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
            ElfW(Dyn)   *dyn = GET_PTR(ElfW(Dyn), ehdr, phdr->p_paddr);
    4759:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    475d:	48 8b 50 18          	mov    0x18(%rax),%rdx
    4761:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    4765:	48 01 d0             	add    %rdx,%rax
    4768:	48 89 45 a8          	mov    %rax,-0x58(%rbp)

            ElfW(Addr)   sym_offset = 0;
    476c:	48 c7 45 b0 00 00 00 	movq   $0x0,-0x50(%rbp)
    4773:	00 
            ElfW(Addr)   rel_offset = 0;
    4774:	48 c7 45 b8 00 00 00 	movq   $0x0,-0x48(%rbp)
    477b:	00 
            ElfW(Addr)   plt_offset = 0;
    477c:	48 c7 45 c0 00 00 00 	movq   $0x0,-0x40(%rbp)
    4783:	00 

            size_t   rel_total_sz = 0;
    4784:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    478b:	00 
            size_t   rel_entry_sz = 0;
    478c:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    4793:	00 
            size_t   plt_total_sz = 0;
    4794:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    479b:	00 

            for (count = 0; count < n_dyn; count++, dyn++)
    479c:	48 c7 45 a0 00 00 00 	movq   $0x0,-0x60(%rbp)
    47a3:	00 
    47a4:	e9 9b 00 00 00       	jmpq   4844 <relocate_enclave+0x14a>
            {
                if (dyn->d_tag == DT_NULL)  /* End */
    47a9:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    47ad:	48 8b 00             	mov    (%rax),%rax
    47b0:	48 85 c0             	test   %rax,%rax
    47b3:	0f 84 9b 00 00 00    	je     4854 <relocate_enclave+0x15a>
                    break;

                switch (dyn->d_tag)
    47b9:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    47bd:	48 8b 00             	mov    (%rax),%rax
    47c0:	48 83 f8 17          	cmp    $0x17,%rax
    47c4:	77 74                	ja     483a <relocate_enclave+0x140>
    47c6:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
    47cd:	00 
    47ce:	48 8d 05 eb 88 00 00 	lea    0x88eb(%rip),%rax        # d0c0 <_ZZL16init_stack_guardPvE8__func__+0x60>
    47d5:	8b 04 02             	mov    (%rdx,%rax,1),%eax
    47d8:	48 63 d0             	movslq %eax,%rdx
    47db:	48 8d 05 de 88 00 00 	lea    0x88de(%rip),%rax        # d0c0 <_ZZL16init_stack_guardPvE8__func__+0x60>
    47e2:	48 01 d0             	add    %rdx,%rax
    47e5:	ff e0                	jmpq   *%rax
                {
                    case DT_SYMTAB: /* symbol table */
                        sym_offset = dyn->d_un.d_ptr;
    47e7:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    47eb:	48 8b 40 08          	mov    0x8(%rax),%rax
    47ef:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
                        break;
    47f3:	eb 45                	jmp    483a <relocate_enclave+0x140>

                    case RTS_DT_REL:/* Rel (x86) or Rela (x64) relocs */
                        rel_offset = dyn->d_un.d_ptr;
    47f5:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    47f9:	48 8b 40 08          	mov    0x8(%rax),%rax
    47fd:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
                        break;
    4801:	eb 37                	jmp    483a <relocate_enclave+0x140>

                    case RTS_DT_RELSZ:
                        rel_total_sz = dyn->d_un.d_val;
    4803:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4807:	48 8b 40 08          	mov    0x8(%rax),%rax
    480b:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
                        break;
    480f:	eb 29                	jmp    483a <relocate_enclave+0x140>

                    case RTS_DT_RELENT:
                        rel_entry_sz = dyn->d_un.d_val;
    4811:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4815:	48 8b 40 08          	mov    0x8(%rax),%rax
    4819:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
                        break;
    481d:	eb 1b                	jmp    483a <relocate_enclave+0x140>

                    case DT_JMPREL: /* PLT relocs */
                        plt_offset = dyn->d_un.d_ptr;
    481f:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4823:	48 8b 40 08          	mov    0x8(%rax),%rax
    4827:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
                        break;
    482b:	eb 0d                	jmp    483a <relocate_enclave+0x140>

                    case DT_PLTRELSZ:
                        plt_total_sz = dyn->d_un.d_val;
    482d:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4831:	48 8b 40 08          	mov    0x8(%rax),%rax
    4835:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
                        break;
    4839:	90                   	nop
            for (count = 0; count < n_dyn; count++, dyn++)
    483a:	48 83 45 a0 01       	addq   $0x1,-0x60(%rbp)
    483f:	48 83 45 a8 10       	addq   $0x10,-0x58(%rbp)
    4844:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    4848:	48 3b 45 e8          	cmp    -0x18(%rbp),%rax
    484c:	0f 82 57 ff ff ff    	jb     47a9 <relocate_enclave+0xaf>
    4852:	eb 01                	jmp    4855 <relocate_enclave+0x15b>
                    break;
    4854:	90                   	nop
                }
            }

            DO_REL(enclave_base, rel_offset, sym_offset, rel_total_sz, rel_entry_sz);
    4855:	48 83 7d b8 00       	cmpq   $0x0,-0x48(%rbp)
    485a:	74 45                	je     48a1 <relocate_enclave+0x1a7>
    485c:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    4861:	75 0a                	jne    486d <relocate_enclave+0x173>
    4863:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4868:	e9 9f 00 00 00       	jmpq   490c <relocate_enclave+0x212>
    486d:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4871:	ba 00 00 00 00       	mov    $0x0,%edx
    4876:	48 f7 75 d0          	divq   -0x30(%rbp)
    487a:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    487e:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    4882:	48 8b 4d f0          	mov    -0x10(%rbp),%rcx
    4886:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    488a:	48 8b 75 b8          	mov    -0x48(%rbp),%rsi
    488e:	48 89 c7             	mov    %rax,%rdi
    4891:	e8 3f fc ff ff       	callq  44d5 <do_relocs>
    4896:	85 c0                	test   %eax,%eax
    4898:	74 07                	je     48a1 <relocate_enclave+0x1a7>
    489a:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    489f:	eb 6b                	jmp    490c <relocate_enclave+0x212>
            DO_REL(enclave_base, plt_offset, sym_offset, plt_total_sz, rel_entry_sz);
    48a1:	48 83 7d c0 00       	cmpq   $0x0,-0x40(%rbp)
    48a6:	74 42                	je     48ea <relocate_enclave+0x1f0>
    48a8:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    48ad:	75 07                	jne    48b6 <relocate_enclave+0x1bc>
    48af:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    48b4:	eb 56                	jmp    490c <relocate_enclave+0x212>
    48b6:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    48ba:	ba 00 00 00 00       	mov    $0x0,%edx
    48bf:	48 f7 75 d0          	divq   -0x30(%rbp)
    48c3:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    48c7:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    48cb:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    48cf:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    48d3:	48 8b 75 c0          	mov    -0x40(%rbp),%rsi
    48d7:	48 89 c7             	mov    %rax,%rdi
    48da:	e8 f6 fb ff ff       	callq  44d5 <do_relocs>
    48df:	85 c0                	test   %eax,%eax
    48e1:	74 07                	je     48ea <relocate_enclave+0x1f0>
    48e3:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    48e8:	eb 22                	jmp    490c <relocate_enclave+0x212>
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    48ea:	83 45 94 01          	addl   $0x1,-0x6c(%rbp)
    48ee:	48 83 45 98 38       	addq   $0x38,-0x68(%rbp)
    48f3:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    48f7:	0f b7 40 38          	movzwl 0x38(%rax),%eax
    48fb:	0f b7 c0             	movzwl %ax,%eax
    48fe:	39 45 94             	cmp    %eax,-0x6c(%rbp)
    4901:	0f 82 33 fe ff ff    	jb     473a <relocate_enclave+0x40>
        }
    }

    return 0;
    4907:	b8 00 00 00 00       	mov    $0x0,%eax
}
    490c:	c9                   	leaveq 
    490d:	c3                   	retq   

000000000000490e <elf_tls_info>:

int elf_tls_info(const void* enclave_base,
        uintptr_t *tls_addr, size_t *tdata_size)
{
    490e:	55                   	push   %rbp
    490f:	48 89 e5             	mov    %rsp,%rbp
    4912:	48 83 ec 38          	sub    $0x38,%rsp
    4916:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    491a:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    491e:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
    ElfW(Half) phnum = 0;
    4922:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%rbp)
    const ElfW(Ehdr) *ehdr = (const ElfW(Ehdr)*)enclave_base;
    4929:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    492d:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    ElfW(Phdr) *phdr = get_phdr(ehdr);
    4931:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4935:	48 89 c7             	mov    %rax,%rdi
    4938:	e8 ac fa ff ff       	callq  43e9 <get_phdr>
    493d:	48 89 45 f0          	mov    %rax,-0x10(%rbp)

    if (!tls_addr || !tdata_size)
    4941:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    4946:	74 07                	je     494f <elf_tls_info+0x41>
    4948:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    494d:	75 07                	jne    4956 <elf_tls_info+0x48>
        return -1;
    494f:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4954:	eb 76                	jmp    49cc <elf_tls_info+0xbe>

    if (phdr == NULL)
    4956:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    495b:	75 07                	jne    4964 <elf_tls_info+0x56>
        return -1;  /* Invalid image. */
    495d:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4962:	eb 68                	jmp    49cc <elf_tls_info+0xbe>

    /* Search for TLS segment */
    *tls_addr = 0;
    4964:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4968:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    *tdata_size = 0;
    496f:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4973:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    497a:	eb 3b                	jmp    49b7 <elf_tls_info+0xa9>
    {
        if (phdr->p_type == PT_TLS)
    497c:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4980:	8b 00                	mov    (%rax),%eax
    4982:	83 f8 07             	cmp    $0x7,%eax
    4985:	75 27                	jne    49ae <elf_tls_info+0xa0>
        {
            /* tls_addr here is got from the program header, the address
             * need to be added by the enclave base.
             */
            *tls_addr = (size_t)enclave_base + phdr->p_vaddr;
    4987:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    498b:	48 8b 50 10          	mov    0x10(%rax),%rdx
    498f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4993:	48 01 c2             	add    %rax,%rdx
    4996:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    499a:	48 89 10             	mov    %rdx,(%rax)
            *tdata_size = phdr->p_filesz;
    499d:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    49a1:	48 8b 50 20          	mov    0x20(%rax),%rdx
    49a5:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    49a9:	48 89 10             	mov    %rdx,(%rax)
            break;
    49ac:	eb 19                	jmp    49c7 <elf_tls_info+0xb9>
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    49ae:	83 45 ec 01          	addl   $0x1,-0x14(%rbp)
    49b2:	48 83 45 f0 38       	addq   $0x38,-0x10(%rbp)
    49b7:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    49bb:	0f b7 40 38          	movzwl 0x38(%rax),%eax
    49bf:	0f b7 c0             	movzwl %ax,%eax
    49c2:	39 45 ec             	cmp    %eax,-0x14(%rbp)
    49c5:	72 b5                	jb     497c <elf_tls_info+0x6e>
        }
    }

    return 0;
    49c7:	b8 00 00 00 00       	mov    $0x0,%eax
}
    49cc:	c9                   	leaveq 
    49cd:	c3                   	retq   

00000000000049ce <elf_tls_aligned_virtual_size>:

static int elf_tls_aligned_virtual_size(const void *enclave_base,
                                        size_t *aligned_virtual_size)
{
    49ce:	55                   	push   %rbp
    49cf:	48 89 e5             	mov    %rsp,%rbp
    49d2:	48 83 ec 40          	sub    $0x40,%rsp
    49d6:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    49da:	48 89 75 c0          	mov    %rsi,-0x40(%rbp)
    ElfW(Half) phnum = 0;
    49de:	c7 45 dc 00 00 00 00 	movl   $0x0,-0x24(%rbp)
    const ElfW(Ehdr) *ehdr = (const ElfW(Ehdr)*)enclave_base;
    49e5:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    49e9:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    ElfW(Phdr) *phdr = get_phdr(ehdr);
    49ed:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    49f1:	48 89 c7             	mov    %rax,%rdi
    49f4:	e8 f0 f9 ff ff       	callq  43e9 <get_phdr>
    49f9:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    size_t virtual_size =0, align = 0;
    49fd:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
    4a04:	00 
    4a05:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    4a0c:	00 

    if (phdr == NULL)
    4a0d:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
    4a12:	75 0a                	jne    4a1e <elf_tls_aligned_virtual_size+0x50>
        return -1;
    4a14:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4a19:	e9 9c 00 00 00       	jmpq   4aba <elf_tls_aligned_virtual_size+0xec>

    if (!aligned_virtual_size)
    4a1e:	48 83 7d c0 00       	cmpq   $0x0,-0x40(%rbp)
    4a23:	75 0a                	jne    4a2f <elf_tls_aligned_virtual_size+0x61>
        return -1;
    4a25:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4a2a:	e9 8b 00 00 00       	jmpq   4aba <elf_tls_aligned_virtual_size+0xec>

    *aligned_virtual_size = 0;
    4a2f:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    4a33:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4a3a:	eb 69                	jmp    4aa5 <elf_tls_aligned_virtual_size+0xd7>
    {
        if (phdr->p_type == PT_TLS)
    4a3c:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    4a40:	8b 00                	mov    (%rax),%eax
    4a42:	83 f8 07             	cmp    $0x7,%eax
    4a45:	75 55                	jne    4a9c <elf_tls_aligned_virtual_size+0xce>
        {
            virtual_size = phdr->p_memsz;
    4a47:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    4a4b:	48 8b 40 28          	mov    0x28(%rax),%rax
    4a4f:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
            align = phdr->p_align;
    4a53:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    4a57:	48 8b 40 30          	mov    0x30(%rax),%rax
    4a5b:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

            /* p_align == 0 or p_align == 1 means no alignment is required */
            if (align == 0 || align == 1)
    4a5f:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    4a64:	74 07                	je     4a6d <elf_tls_aligned_virtual_size+0x9f>
    4a66:	48 83 7d f8 01       	cmpq   $0x1,-0x8(%rbp)
    4a6b:	75 0d                	jne    4a7a <elf_tls_aligned_virtual_size+0xac>
                *aligned_virtual_size = virtual_size;
    4a6d:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    4a71:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    4a75:	48 89 10             	mov    %rdx,(%rax)
            else
                *aligned_virtual_size = (virtual_size + align - 1) & (~(align - 1));

            break;
    4a78:	eb 3b                	jmp    4ab5 <elf_tls_aligned_virtual_size+0xe7>
                *aligned_virtual_size = (virtual_size + align - 1) & (~(align - 1));
    4a7a:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    4a7e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4a82:	48 01 d0             	add    %rdx,%rax
    4a85:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    4a89:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4a8d:	48 f7 d8             	neg    %rax
    4a90:	48 21 c2             	and    %rax,%rdx
    4a93:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    4a97:	48 89 10             	mov    %rdx,(%rax)
            break;
    4a9a:	eb 19                	jmp    4ab5 <elf_tls_aligned_virtual_size+0xe7>
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4a9c:	83 45 dc 01          	addl   $0x1,-0x24(%rbp)
    4aa0:	48 83 45 e0 38       	addq   $0x38,-0x20(%rbp)
    4aa5:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4aa9:	0f b7 40 38          	movzwl 0x38(%rax),%eax
    4aad:	0f b7 c0             	movzwl %ax,%eax
    4ab0:	39 45 dc             	cmp    %eax,-0x24(%rbp)
    4ab3:	72 87                	jb     4a3c <elf_tls_aligned_virtual_size+0x6e>
        }
    }

    return 0;
    4ab5:	b8 00 00 00 00       	mov    $0x0,%eax
}
    4aba:	c9                   	leaveq 
    4abb:	c3                   	retq   

0000000000004abc <elf_get_init_array>:

int elf_get_init_array(const void* enclave_base,
        uintptr_t *init_array_addr, size_t *init_array_size)
{
    4abc:	55                   	push   %rbp
    4abd:	48 89 e5             	mov    %rsp,%rbp
    4ac0:	48 83 ec 48          	sub    $0x48,%rsp
    4ac4:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    4ac8:	48 89 75 c0          	mov    %rsi,-0x40(%rbp)
    4acc:	48 89 55 b8          	mov    %rdx,-0x48(%rbp)
    ElfW(Half) phnum = 0;
    4ad0:	c7 45 d4 00 00 00 00 	movl   $0x0,-0x2c(%rbp)
    const ElfW(Ehdr) *ehdr = (const ElfW(Ehdr)*)enclave_base;
    4ad7:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4adb:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    ElfW(Phdr) *phdr = get_phdr(ehdr);
    4adf:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4ae3:	48 89 c7             	mov    %rax,%rdi
    4ae6:	e8 fe f8 ff ff       	callq  43e9 <get_phdr>
    4aeb:	48 89 45 d8          	mov    %rax,-0x28(%rbp)

    if (!init_array_addr || !init_array_size)
    4aef:	48 83 7d c0 00       	cmpq   $0x0,-0x40(%rbp)
    4af4:	74 07                	je     4afd <elf_get_init_array+0x41>
    4af6:	48 83 7d b8 00       	cmpq   $0x0,-0x48(%rbp)
    4afb:	75 0a                	jne    4b07 <elf_get_init_array+0x4b>
        return -1;
    4afd:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4b02:	e9 d0 00 00 00       	jmpq   4bd7 <elf_get_init_array+0x11b>

    if (phdr == NULL)
    4b07:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    4b0c:	75 0a                	jne    4b18 <elf_get_init_array+0x5c>
        return -1;  /* Invalid image. */
    4b0e:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4b13:	e9 bf 00 00 00       	jmpq   4bd7 <elf_get_init_array+0x11b>

    *init_array_addr = 0;
    4b18:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    4b1c:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    *init_array_size = 0;
    4b23:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    4b27:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)

    /* Search for Dynamic segment */
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4b2e:	e9 8b 00 00 00       	jmpq   4bbe <elf_get_init_array+0x102>
    {
        if (phdr->p_type == PT_DYNAMIC)
    4b33:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4b37:	8b 00                	mov    (%rax),%eax
    4b39:	83 f8 02             	cmp    $0x2,%eax
    4b3c:	75 77                	jne    4bb5 <elf_get_init_array+0xf9>
        {
            size_t      count;
            size_t      n_dyn = phdr->p_filesz/sizeof(ElfW(Dyn));
    4b3e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4b42:	48 8b 40 20          	mov    0x20(%rax),%rax
    4b46:	48 c1 e8 04          	shr    $0x4,%rax
    4b4a:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
            ElfW(Dyn)   *dyn = GET_PTR(ElfW(Dyn), ehdr, phdr->p_paddr);
    4b4e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4b52:	48 8b 50 18          	mov    0x18(%rax),%rdx
    4b56:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4b5a:	48 01 d0             	add    %rdx,%rax
    4b5d:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
            
            for (count = 0; count < n_dyn; count++, dyn++)
    4b61:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    4b68:	00 
    4b69:	eb 40                	jmp    4bab <elf_get_init_array+0xef>
            {
                switch (dyn->d_tag)
    4b6b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4b6f:	48 8b 00             	mov    (%rax),%rax
    4b72:	48 83 f8 19          	cmp    $0x19,%rax
    4b76:	74 08                	je     4b80 <elf_get_init_array+0xc4>
    4b78:	48 83 f8 1b          	cmp    $0x1b,%rax
    4b7c:	74 13                	je     4b91 <elf_get_init_array+0xd5>
    4b7e:	eb 21                	jmp    4ba1 <elf_get_init_array+0xe5>
                {
                    case DT_INIT_ARRAY:
                        *init_array_addr = dyn->d_un.d_ptr;
    4b80:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4b84:	48 8b 50 08          	mov    0x8(%rax),%rdx
    4b88:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    4b8c:	48 89 10             	mov    %rdx,(%rax)
                        break;
    4b8f:	eb 10                	jmp    4ba1 <elf_get_init_array+0xe5>
                    case DT_INIT_ARRAYSZ:
                        *init_array_size = dyn->d_un.d_val;
    4b91:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4b95:	48 8b 50 08          	mov    0x8(%rax),%rdx
    4b99:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    4b9d:	48 89 10             	mov    %rdx,(%rax)
                        break;
    4ba0:	90                   	nop
            for (count = 0; count < n_dyn; count++, dyn++)
    4ba1:	48 83 45 e0 01       	addq   $0x1,-0x20(%rbp)
    4ba6:	48 83 45 e8 10       	addq   $0x10,-0x18(%rbp)
    4bab:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    4baf:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    4bb3:	72 b6                	jb     4b6b <elf_get_init_array+0xaf>
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4bb5:	83 45 d4 01          	addl   $0x1,-0x2c(%rbp)
    4bb9:	48 83 45 d8 38       	addq   $0x38,-0x28(%rbp)
    4bbe:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4bc2:	0f b7 40 38          	movzwl 0x38(%rax),%eax
    4bc6:	0f b7 c0             	movzwl %ax,%eax
    4bc9:	39 45 d4             	cmp    %eax,-0x2c(%rbp)
    4bcc:	0f 82 61 ff ff ff    	jb     4b33 <elf_get_init_array+0x77>
                }
            }
        }
    }

    return 0;
    4bd2:	b8 00 00 00 00       	mov    $0x0,%eax
}
    4bd7:	c9                   	leaveq 
    4bd8:	c3                   	retq   

0000000000004bd9 <elf_get_uninit_array>:

int elf_get_uninit_array(const void* enclave_base,
        uintptr_t *uninit_array_addr, size_t *uninit_array_size)
{
    4bd9:	55                   	push   %rbp
    4bda:	48 89 e5             	mov    %rsp,%rbp
    4bdd:	48 83 ec 48          	sub    $0x48,%rsp
    4be1:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    4be5:	48 89 75 c0          	mov    %rsi,-0x40(%rbp)
    4be9:	48 89 55 b8          	mov    %rdx,-0x48(%rbp)
    ElfW(Half) phnum = 0;
    4bed:	c7 45 d4 00 00 00 00 	movl   $0x0,-0x2c(%rbp)
    const ElfW(Ehdr) *ehdr = (const ElfW(Ehdr)*)enclave_base;
    4bf4:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4bf8:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    ElfW(Phdr) *phdr = get_phdr(ehdr);
    4bfc:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4c00:	48 89 c7             	mov    %rax,%rdi
    4c03:	e8 e1 f7 ff ff       	callq  43e9 <get_phdr>
    4c08:	48 89 45 d8          	mov    %rax,-0x28(%rbp)

    if (!uninit_array_addr || !uninit_array_size)
    4c0c:	48 83 7d c0 00       	cmpq   $0x0,-0x40(%rbp)
    4c11:	74 07                	je     4c1a <elf_get_uninit_array+0x41>
    4c13:	48 83 7d b8 00       	cmpq   $0x0,-0x48(%rbp)
    4c18:	75 0a                	jne    4c24 <elf_get_uninit_array+0x4b>
        return -1;
    4c1a:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4c1f:	e9 d0 00 00 00       	jmpq   4cf4 <elf_get_uninit_array+0x11b>

    if (phdr == NULL)
    4c24:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    4c29:	75 0a                	jne    4c35 <elf_get_uninit_array+0x5c>
        return -1;  /* Invalid image. */
    4c2b:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4c30:	e9 bf 00 00 00       	jmpq   4cf4 <elf_get_uninit_array+0x11b>

    *uninit_array_addr = 0;
    4c35:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    4c39:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    *uninit_array_size = 0;
    4c40:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    4c44:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)

    /* Search for Dynamic segment */
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4c4b:	e9 8b 00 00 00       	jmpq   4cdb <elf_get_uninit_array+0x102>
    {
        if (phdr->p_type == PT_DYNAMIC)
    4c50:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4c54:	8b 00                	mov    (%rax),%eax
    4c56:	83 f8 02             	cmp    $0x2,%eax
    4c59:	75 77                	jne    4cd2 <elf_get_uninit_array+0xf9>
        {
            size_t      count;
            size_t      n_dyn = phdr->p_filesz/sizeof(ElfW(Dyn));
    4c5b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4c5f:	48 8b 40 20          	mov    0x20(%rax),%rax
    4c63:	48 c1 e8 04          	shr    $0x4,%rax
    4c67:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
            ElfW(Dyn)   *dyn = GET_PTR(ElfW(Dyn), ehdr, phdr->p_paddr);
    4c6b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4c6f:	48 8b 50 18          	mov    0x18(%rax),%rdx
    4c73:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4c77:	48 01 d0             	add    %rdx,%rax
    4c7a:	48 89 45 e8          	mov    %rax,-0x18(%rbp)

            for (count = 0; count < n_dyn; count++, dyn++)
    4c7e:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    4c85:	00 
    4c86:	eb 40                	jmp    4cc8 <elf_get_uninit_array+0xef>
            {
                switch (dyn->d_tag)
    4c88:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4c8c:	48 8b 00             	mov    (%rax),%rax
    4c8f:	48 83 f8 1a          	cmp    $0x1a,%rax
    4c93:	74 08                	je     4c9d <elf_get_uninit_array+0xc4>
    4c95:	48 83 f8 1c          	cmp    $0x1c,%rax
    4c99:	74 13                	je     4cae <elf_get_uninit_array+0xd5>
    4c9b:	eb 21                	jmp    4cbe <elf_get_uninit_array+0xe5>
                {
                    case DT_FINI_ARRAY:
                        *uninit_array_addr = dyn->d_un.d_ptr;
    4c9d:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4ca1:	48 8b 50 08          	mov    0x8(%rax),%rdx
    4ca5:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    4ca9:	48 89 10             	mov    %rdx,(%rax)
                        break;
    4cac:	eb 10                	jmp    4cbe <elf_get_uninit_array+0xe5>
                    case DT_FINI_ARRAYSZ:
                        *uninit_array_size = dyn->d_un.d_val;
    4cae:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4cb2:	48 8b 50 08          	mov    0x8(%rax),%rdx
    4cb6:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    4cba:	48 89 10             	mov    %rdx,(%rax)
                        break;
    4cbd:	90                   	nop
            for (count = 0; count < n_dyn; count++, dyn++)
    4cbe:	48 83 45 e0 01       	addq   $0x1,-0x20(%rbp)
    4cc3:	48 83 45 e8 10       	addq   $0x10,-0x18(%rbp)
    4cc8:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    4ccc:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    4cd0:	72 b6                	jb     4c88 <elf_get_uninit_array+0xaf>
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4cd2:	83 45 d4 01          	addl   $0x1,-0x2c(%rbp)
    4cd6:	48 83 45 d8 38       	addq   $0x38,-0x28(%rbp)
    4cdb:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4cdf:	0f b7 40 38          	movzwl 0x38(%rax),%eax
    4ce3:	0f b7 c0             	movzwl %ax,%eax
    4ce6:	39 45 d4             	cmp    %eax,-0x2c(%rbp)
    4ce9:	0f 82 61 ff ff ff    	jb     4c50 <elf_get_uninit_array+0x77>
                }
            }
        }
    }

    return 0;
    4cef:	b8 00 00 00 00       	mov    $0x0,%eax
}
    4cf4:	c9                   	leaveq 
    4cf5:	c3                   	retq   

0000000000004cf6 <has_text_relo>:

static int has_text_relo(const ElfW(Ehdr) *ehdr, const ElfW(Phdr) *phdr, ElfW(Half) phnum)
{
    4cf6:	55                   	push   %rbp
    4cf7:	48 89 e5             	mov    %rsp,%rbp
    4cfa:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    4cfe:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    4d02:	89 55 cc             	mov    %edx,-0x34(%rbp)
    ElfW(Half) phi = 0;
    4d05:	c7 45 e0 00 00 00 00 	movl   $0x0,-0x20(%rbp)
    int text_relo = 0;
    4d0c:	c7 45 e4 00 00 00 00 	movl   $0x0,-0x1c(%rbp)

    for (; phi < phnum; phi++, phdr++)
    4d13:	eb 7c                	jmp    4d91 <has_text_relo+0x9b>
    {
        if (phdr->p_type == PT_DYNAMIC)
    4d15:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4d19:	8b 00                	mov    (%rax),%eax
    4d1b:	83 f8 02             	cmp    $0x2,%eax
    4d1e:	75 68                	jne    4d88 <has_text_relo+0x92>
        {
            size_t count;
            size_t n_dyn = phdr->p_filesz/sizeof(ElfW(Dyn));
    4d20:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4d24:	48 8b 40 20          	mov    0x20(%rax),%rax
    4d28:	48 c1 e8 04          	shr    $0x4,%rax
    4d2c:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
            ElfW(Dyn) *dyn = GET_PTR(ElfW(Dyn), ehdr, phdr->p_paddr);
    4d30:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4d34:	48 8b 50 18          	mov    0x18(%rax),%rdx
    4d38:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4d3c:	48 01 d0             	add    %rdx,%rax
    4d3f:	48 89 45 f0          	mov    %rax,-0x10(%rbp)

            for (count = 0; count < n_dyn; count++, dyn++)
    4d43:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    4d4a:	00 
    4d4b:	eb 2c                	jmp    4d79 <has_text_relo+0x83>
            {
                if (dyn->d_tag == DT_NULL)
    4d4d:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4d51:	48 8b 00             	mov    (%rax),%rax
    4d54:	48 85 c0             	test   %rax,%rax
    4d57:	74 2c                	je     4d85 <has_text_relo+0x8f>
                    break;

                if (dyn->d_tag == DT_TEXTREL)
    4d59:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4d5d:	48 8b 00             	mov    (%rax),%rax
    4d60:	48 83 f8 16          	cmp    $0x16,%rax
    4d64:	75 09                	jne    4d6f <has_text_relo+0x79>
                {
                    text_relo = 1;
    4d66:	c7 45 e4 01 00 00 00 	movl   $0x1,-0x1c(%rbp)
                    break;
    4d6d:	eb 17                	jmp    4d86 <has_text_relo+0x90>
            for (count = 0; count < n_dyn; count++, dyn++)
    4d6f:	48 83 45 e8 01       	addq   $0x1,-0x18(%rbp)
    4d74:	48 83 45 f0 10       	addq   $0x10,-0x10(%rbp)
    4d79:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4d7d:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    4d81:	72 ca                	jb     4d4d <has_text_relo+0x57>
                }
            }
            break;
    4d83:	eb 18                	jmp    4d9d <has_text_relo+0xa7>
                    break;
    4d85:	90                   	nop
            break;
    4d86:	eb 15                	jmp    4d9d <has_text_relo+0xa7>
    for (; phi < phnum; phi++, phdr++)
    4d88:	83 45 e0 01          	addl   $0x1,-0x20(%rbp)
    4d8c:	48 83 45 d0 38       	addq   $0x38,-0x30(%rbp)
    4d91:	8b 45 e0             	mov    -0x20(%rbp),%eax
    4d94:	3b 45 cc             	cmp    -0x34(%rbp),%eax
    4d97:	0f 82 78 ff ff ff    	jb     4d15 <has_text_relo+0x1f>
        }
    }
    return text_relo;
    4d9d:	8b 45 e4             	mov    -0x1c(%rbp),%eax
}
    4da0:	5d                   	pop    %rbp
    4da1:	c3                   	retq   

0000000000004da2 <change_protection>:

sgx_status_t change_protection(void *enclave_base)
{
    4da2:	55                   	push   %rbp
    4da3:	48 89 e5             	mov    %rsp,%rbp
    4da6:	48 83 ec 60          	sub    $0x60,%rsp
    4daa:	48 89 7d a8          	mov    %rdi,-0x58(%rbp)
    ElfW(Half) phnum = 0;
    4dae:	c7 45 b8 00 00 00 00 	movl   $0x0,-0x48(%rbp)
    const ElfW(Ehdr) *ehdr = (const ElfW(Ehdr)*)enclave_base;
    4db5:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4db9:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    const ElfW(Phdr) *phdr = get_phdr(ehdr);
    4dbd:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4dc1:	48 89 c7             	mov    %rax,%rdi
    4dc4:	e8 20 f6 ff ff       	callq  43e9 <get_phdr>
    4dc9:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    uint64_t perms;
    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    4dcd:	c7 45 c0 01 00 00 00 	movl   $0x1,-0x40(%rbp)

    if (phdr == NULL)
    4dd4:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    4dd9:	75 08                	jne    4de3 <change_protection+0x41>
        return status;
    4ddb:	8b 45 c0             	mov    -0x40(%rbp),%eax
    4dde:	e9 65 02 00 00       	jmpq   5048 <change_protection+0x2a6>

    int text_relocation = has_text_relo(ehdr, phdr, ehdr->e_phnum);
    4de3:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4de7:	0f b7 40 38          	movzwl 0x38(%rax),%eax
    4deb:	0f b7 d0             	movzwl %ax,%edx
    4dee:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    4df2:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4df6:	48 89 ce             	mov    %rcx,%rsi
    4df9:	48 89 c7             	mov    %rax,%rdi
    4dfc:	e8 f5 fe ff ff       	callq  4cf6 <has_text_relo>
    4e01:	89 45 c4             	mov    %eax,-0x3c(%rbp)

    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4e04:	e9 6e 01 00 00       	jmpq   4f77 <change_protection+0x1d5>
    {
        if (text_relocation && (phdr->p_type == PT_LOAD) && ((phdr->p_flags & PF_W) == 0))
    4e09:	83 7d c4 00          	cmpl   $0x0,-0x3c(%rbp)
    4e0d:	0f 84 c7 00 00 00    	je     4eda <change_protection+0x138>
    4e13:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4e17:	8b 00                	mov    (%rax),%eax
    4e19:	83 f8 01             	cmp    $0x1,%eax
    4e1c:	0f 85 b8 00 00 00    	jne    4eda <change_protection+0x138>
    4e22:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4e26:	8b 40 04             	mov    0x4(%rax),%eax
    4e29:	83 e0 02             	and    $0x2,%eax
    4e2c:	85 c0                	test   %eax,%eax
    4e2e:	0f 85 a6 00 00 00    	jne    4eda <change_protection+0x138>
        {
            perms = 0;
    4e34:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    4e3b:	00 
            size_t start = (size_t)enclave_base + (phdr->p_vaddr & (size_t)(~(SE_PAGE_SIZE-1)));
    4e3c:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4e40:	48 8b 40 10          	mov    0x10(%rax),%rax
    4e44:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    4e4a:	48 89 c2             	mov    %rax,%rdx
    4e4d:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4e51:	48 01 d0             	add    %rdx,%rax
    4e54:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
            size_t end = (size_t)enclave_base + ((phdr->p_vaddr + phdr->p_memsz + SE_PAGE_SIZE - 1) & (size_t)(~(SE_PAGE_SIZE-1)));
    4e58:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4e5c:	48 8b 50 10          	mov    0x10(%rax),%rdx
    4e60:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4e64:	48 8b 40 28          	mov    0x28(%rax),%rax
    4e68:	48 01 d0             	add    %rdx,%rax
    4e6b:	48 05 ff 0f 00 00    	add    $0xfff,%rax
    4e71:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    4e77:	48 89 c2             	mov    %rax,%rdx
    4e7a:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4e7e:	48 01 d0             	add    %rdx,%rax
    4e81:	48 89 45 e8          	mov    %rax,-0x18(%rbp)

            if (phdr->p_flags & PF_R)
    4e85:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4e89:	8b 40 04             	mov    0x4(%rax),%eax
    4e8c:	83 e0 04             	and    $0x4,%eax
    4e8f:	85 c0                	test   %eax,%eax
    4e91:	74 05                	je     4e98 <change_protection+0xf6>
                perms |= SI_FLAG_R;
    4e93:	48 83 4d d0 01       	orq    $0x1,-0x30(%rbp)
            if (phdr->p_flags & PF_X)
    4e98:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4e9c:	8b 40 04             	mov    0x4(%rax),%eax
    4e9f:	83 e0 01             	and    $0x1,%eax
    4ea2:	85 c0                	test   %eax,%eax
    4ea4:	74 05                	je     4eab <change_protection+0x109>
                perms |= SI_FLAG_X;
    4ea6:	48 83 4d d0 04       	orq    $0x4,-0x30(%rbp)

            if((status = trts_mprotect(start, end - start, perms)) != SGX_SUCCESS)
    4eab:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4eaf:	48 2b 45 e0          	sub    -0x20(%rbp),%rax
    4eb3:	48 89 c1             	mov    %rax,%rcx
    4eb6:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    4eba:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    4ebe:	48 89 ce             	mov    %rcx,%rsi
    4ec1:	48 89 c7             	mov    %rax,%rdi
    4ec4:	e8 92 e3 ff ff       	callq  325b <trts_mprotect>
    4ec9:	89 45 c0             	mov    %eax,-0x40(%rbp)
    4ecc:	83 7d c0 00          	cmpl   $0x0,-0x40(%rbp)
    4ed0:	74 08                	je     4eda <change_protection+0x138>
                return status;
    4ed2:	8b 45 c0             	mov    -0x40(%rbp),%eax
    4ed5:	e9 6e 01 00 00       	jmpq   5048 <change_protection+0x2a6>
        }

        if (phdr->p_type == PT_GNU_RELRO)
    4eda:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4ede:	8b 00                	mov    (%rax),%eax
    4ee0:	3d 52 e5 74 64       	cmp    $0x6474e552,%eax
    4ee5:	0f 85 83 00 00 00    	jne    4f6e <change_protection+0x1cc>
        {
            size_t start = (size_t)enclave_base + (phdr->p_vaddr & (size_t)(~(SE_PAGE_SIZE-1)));
    4eeb:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4eef:	48 8b 40 10          	mov    0x10(%rax),%rax
    4ef3:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    4ef9:	48 89 c2             	mov    %rax,%rdx
    4efc:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4f00:	48 01 d0             	add    %rdx,%rax
    4f03:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
            size_t end = (size_t)enclave_base + ((phdr->p_vaddr + phdr->p_memsz + SE_PAGE_SIZE - 1) & (size_t)(~(SE_PAGE_SIZE-1)));
    4f07:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4f0b:	48 8b 50 10          	mov    0x10(%rax),%rdx
    4f0f:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4f13:	48 8b 40 28          	mov    0x28(%rax),%rax
    4f17:	48 01 d0             	add    %rdx,%rax
    4f1a:	48 05 ff 0f 00 00    	add    $0xfff,%rax
    4f20:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    4f26:	48 89 c2             	mov    %rax,%rdx
    4f29:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4f2d:	48 01 d0             	add    %rdx,%rax
    4f30:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
            if ((start != end) &&
    4f34:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4f38:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    4f3c:	74 30                	je     4f6e <change_protection+0x1cc>
                    (status = trts_mprotect(start, end - start, SI_FLAG_R)) != SGX_SUCCESS)
    4f3e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4f42:	48 2b 45 f0          	sub    -0x10(%rbp),%rax
    4f46:	48 89 c1             	mov    %rax,%rcx
            if ((start != end) &&
    4f49:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4f4d:	ba 01 00 00 00       	mov    $0x1,%edx
    4f52:	48 89 ce             	mov    %rcx,%rsi
    4f55:	48 89 c7             	mov    %rax,%rdi
    4f58:	e8 fe e2 ff ff       	callq  325b <trts_mprotect>
    4f5d:	89 45 c0             	mov    %eax,-0x40(%rbp)
    4f60:	83 7d c0 00          	cmpl   $0x0,-0x40(%rbp)
    4f64:	74 08                	je     4f6e <change_protection+0x1cc>
                return status;
    4f66:	8b 45 c0             	mov    -0x40(%rbp),%eax
    4f69:	e9 da 00 00 00       	jmpq   5048 <change_protection+0x2a6>
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4f6e:	83 45 b8 01          	addl   $0x1,-0x48(%rbp)
    4f72:	48 83 45 c8 38       	addq   $0x38,-0x38(%rbp)
    4f77:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4f7b:	0f b7 40 38          	movzwl 0x38(%rax),%eax
    4f7f:	0f b7 c0             	movzwl %ax,%eax
    4f82:	39 45 b8             	cmp    %eax,-0x48(%rbp)
    4f85:	0f 82 7e fe ff ff    	jb     4e09 <change_protection+0x67>
        }
    }

    //The <ReservedMemMinSize> memory region's attributes has been set to RW if EDMM is supported by URTS.
    //So do_eaccept() to accept these pages.
    uint32_t i = 0;
    4f8b:	c7 45 bc 00 00 00 00 	movl   $0x0,-0x44(%rbp)
    for (i = 0; i < g_global_data.layout_entry_num; i++)
    4f92:	c7 45 bc 00 00 00 00 	movl   $0x0,-0x44(%rbp)
    4f99:	e9 93 00 00 00       	jmpq   5031 <change_protection+0x28f>
    {
        if (g_global_data.layout_table[i].entry.id == LAYOUT_ID_RSRV_MIN && g_global_data.layout_table[i].entry.si_flags ==  SI_FLAGS_RWX)
    4f9e:	8b 45 bc             	mov    -0x44(%rbp),%eax
    4fa1:	48 c1 e0 05          	shl    $0x5,%rax
    4fa5:	48 89 c2             	mov    %rax,%rdx
    4fa8:	48 8d 05 01 83 00 00 	lea    0x8301(%rip),%rax        # d2b0 <g_global_data+0x130>
    4faf:	0f b7 04 02          	movzwl (%rdx,%rax,1),%eax
    4fb3:	66 83 f8 14          	cmp    $0x14,%ax
    4fb7:	75 74                	jne    502d <change_protection+0x28b>
    4fb9:	8b 45 bc             	mov    -0x44(%rbp),%eax
    4fbc:	48 83 c0 0a          	add    $0xa,%rax
    4fc0:	48 c1 e0 05          	shl    $0x5,%rax
    4fc4:	48 89 c2             	mov    %rax,%rdx
    4fc7:	48 8d 05 ba 81 00 00 	lea    0x81ba(%rip),%rax        # d188 <g_global_data+0x8>
    4fce:	48 8b 04 02          	mov    (%rdx,%rax,1),%rax
    4fd2:	48 3d 07 02 00 00    	cmp    $0x207,%rax
    4fd8:	75 53                	jne    502d <change_protection+0x28b>
        {
            if((status = trts_mprotect((size_t)((size_t)enclave_base + g_global_data.layout_table[i].entry.rva), 
                                                                     g_global_data.layout_table[i].entry.page_count << SE_PAGE_SHIFT, 
    4fda:	8b 45 bc             	mov    -0x44(%rbp),%eax
    4fdd:	48 c1 e0 05          	shl    $0x5,%rax
    4fe1:	48 89 c2             	mov    %rax,%rdx
    4fe4:	48 8d 05 c9 82 00 00 	lea    0x82c9(%rip),%rax        # d2b4 <g_global_data+0x134>
    4feb:	8b 04 02             	mov    (%rdx,%rax,1),%eax
    4fee:	c1 e0 0c             	shl    $0xc,%eax
            if((status = trts_mprotect((size_t)((size_t)enclave_base + g_global_data.layout_table[i].entry.rva), 
    4ff1:	89 c1                	mov    %eax,%ecx
    4ff3:	8b 45 bc             	mov    -0x44(%rbp),%eax
    4ff6:	48 c1 e0 05          	shl    $0x5,%rax
    4ffa:	48 89 c2             	mov    %rax,%rdx
    4ffd:	48 8d 05 b4 82 00 00 	lea    0x82b4(%rip),%rax        # d2b8 <g_global_data+0x138>
    5004:	48 8b 14 02          	mov    (%rdx,%rax,1),%rdx
    5008:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    500c:	48 01 d0             	add    %rdx,%rax
    500f:	ba 03 00 00 00       	mov    $0x3,%edx
    5014:	48 89 ce             	mov    %rcx,%rsi
    5017:	48 89 c7             	mov    %rax,%rdi
    501a:	e8 3c e2 ff ff       	callq  325b <trts_mprotect>
    501f:	89 45 c0             	mov    %eax,-0x40(%rbp)
    5022:	83 7d c0 00          	cmpl   $0x0,-0x40(%rbp)
    5026:	74 1a                	je     5042 <change_protection+0x2a0>
                                                                           SI_FLAG_R|SI_FLAG_W)) != SGX_SUCCESS)
                return status;
    5028:	8b 45 c0             	mov    -0x40(%rbp),%eax
    502b:	eb 1b                	jmp    5048 <change_protection+0x2a6>
    for (i = 0; i < g_global_data.layout_entry_num; i++)
    502d:	83 45 bc 01          	addl   $0x1,-0x44(%rbp)
    5031:	8b 05 71 82 00 00    	mov    0x8271(%rip),%eax        # d2a8 <g_global_data+0x128>
    5037:	39 45 bc             	cmp    %eax,-0x44(%rbp)
    503a:	0f 82 5e ff ff ff    	jb     4f9e <change_protection+0x1fc>
    5040:	eb 01                	jmp    5043 <change_protection+0x2a1>
            break;
    5042:	90                   	nop
        }
    }

    return SGX_SUCCESS;
    5043:	b8 00 00 00 00       	mov    $0x0,%eax
}
    5048:	c9                   	leaveq 
    5049:	c3                   	retq   

000000000000504a <do_atexit_aux>:
{
    return __cxa_atexit((void (*)(void *))fun, NULL, __dso_handle);
}

static void do_atexit_aux(void)
{
    504a:	55                   	push   %rbp
    504b:	48 89 e5             	mov    %rsp,%rbp
    504e:	48 83 ec 20          	sub    $0x20,%rsp
    exit_function_t *exit_function = g_exit_function;
    5052:	48 8b 05 97 c0 00 00 	mov    0xc097(%rip),%rax        # 110f0 <g_exit_function>
    5059:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    g_exit_function = NULL;
    505d:	48 c7 05 88 c0 00 00 	movq   $0x0,0xc088(%rip)        # 110f0 <g_exit_function>
    5064:	00 00 00 00 

    while (exit_function != NULL)
    5068:	eb 58                	jmp    50c2 <do_atexit_aux+0x78>
    {
        cxa_function_t cxa_func = DEC_CXA_FUNC_POINTER(exit_function->cxa.fun);
    506a:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    506e:	48 8b 10             	mov    (%rax),%rdx
    5071:	48 8b 05 80 c0 00 00 	mov    0xc080(%rip),%rax        # 110f8 <g_exit_function_cookie>
    5078:	48 31 d0             	xor    %rdx,%rax
    507b:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
        void *para = DEC_CXA_PARA_POINTER(exit_function->cxa.para);
    507f:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5083:	48 8b 50 08          	mov    0x8(%rax),%rdx
    5087:	48 8b 05 6a c0 00 00 	mov    0xc06a(%rip),%rax        # 110f8 <g_exit_function_cookie>
    508e:	48 31 d0             	xor    %rdx,%rax
    5091:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
        cxa_func(para);
    5095:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    5099:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    509d:	48 89 d7             	mov    %rdx,%rdi
    50a0:	ff d0                	callq  *%rax

        exit_function_t *tmp = exit_function;
    50a2:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    50a6:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
        exit_function = exit_function->next;
    50aa:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    50ae:	48 8b 40 18          	mov    0x18(%rax),%rax
    50b2:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
        free(tmp);
    50b6:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    50ba:	48 89 c7             	mov    %rax,%rdi
    50bd:	e8 6a 47 00 00       	callq  982c <dlfree>
    while (exit_function != NULL)
    50c2:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
    50c7:	75 a1                	jne    506a <do_atexit_aux+0x20>
    }
}
    50c9:	90                   	nop
    50ca:	c9                   	leaveq 
    50cb:	c3                   	retq   

00000000000050cc <do_ctors_aux>:

/* auxiliary routines */
static void do_ctors_aux(void)
{
    50cc:	55                   	push   %rbp
    50cd:	48 89 e5             	mov    %rsp,%rbp
    50d0:	48 83 ec 40          	sub    $0x40,%rsp
    50d4:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    50db:	00 00 
    50dd:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    50e1:	31 c0                	xor    %eax,%eax
    /* SGX RTS does not support .ctors currently */
   
    fp_t *p = NULL;
    50e3:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    50ea:	00 
    uintptr_t init_array_addr = 0;
    50eb:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    50f2:	00 
    size_t init_array_size = 0;
    50f3:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    50fa:	00 
    const void *enclave_start = (const void*)&__ImageBase;
    50fb:	48 8d 05 fe ae ff ff 	lea    -0x5102(%rip),%rax        # 0 <enclave.so>
    5102:	48 89 45 e0          	mov    %rax,-0x20(%rbp)

    if (0 != elf_get_init_array(enclave_start, &init_array_addr, &init_array_size)|| init_array_addr == 0 || init_array_size == 0)
    5106:	48 8d 55 d0          	lea    -0x30(%rbp),%rdx
    510a:	48 8d 4d c8          	lea    -0x38(%rbp),%rcx
    510e:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5112:	48 89 ce             	mov    %rcx,%rsi
    5115:	48 89 c7             	mov    %rax,%rdi
    5118:	e8 9f f9 ff ff       	callq  4abc <elf_get_init_array>
    511d:	85 c0                	test   %eax,%eax
    511f:	75 5b                	jne    517c <do_ctors_aux+0xb0>
    5121:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    5125:	48 85 c0             	test   %rax,%rax
    5128:	74 52                	je     517c <do_ctors_aux+0xb0>
    512a:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    512e:	48 85 c0             	test   %rax,%rax
    5131:	74 49                	je     517c <do_ctors_aux+0xb0>
        return;

    fp_t *fp_start = (fp_t*)(init_array_addr + (uintptr_t)(enclave_start));
    5133:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    5137:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    513b:	48 01 d0             	add    %rdx,%rax
    513e:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    fp_t *fp_end = fp_start + (init_array_size / sizeof(fp_t));
    5142:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    5146:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    514a:	48 89 c2             	mov    %rax,%rdx
    514d:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    5151:	48 01 d0             	add    %rdx,%rax
    5154:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    
    /* traverse .init_array in forward order */
    for (p = fp_start; p < fp_end; p++)
    5158:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    515c:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    5160:	eb 0e                	jmp    5170 <do_ctors_aux+0xa4>
    {
        (*p)();
    5162:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    5166:	48 8b 00             	mov    (%rax),%rax
    5169:	ff d0                	callq  *%rax
    for (p = fp_start; p < fp_end; p++)
    516b:	48 83 45 d8 08       	addq   $0x8,-0x28(%rbp)
    5170:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    5174:	48 3b 45 f0          	cmp    -0x10(%rbp),%rax
    5178:	72 e8                	jb     5162 <do_ctors_aux+0x96>
    517a:	eb 01                	jmp    517d <do_ctors_aux+0xb1>
        return;
    517c:	90                   	nop
    }
}
    517d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5181:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    5188:	00 00 
    518a:	74 05                	je     5191 <do_ctors_aux+0xc5>
    518c:	e8 d6 00 00 00       	callq  5267 <__stack_chk_fail>
    5191:	c9                   	leaveq 
    5192:	c3                   	retq   

0000000000005193 <do_dtors_aux>:

/* auxiliary routines */
static void do_dtors_aux(void)
{
    5193:	55                   	push   %rbp
    5194:	48 89 e5             	mov    %rsp,%rbp
    5197:	48 83 ec 40          	sub    $0x40,%rsp
    519b:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    51a2:	00 00 
    51a4:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    51a8:	31 c0                	xor    %eax,%eax
    fp_t *p = NULL;
    51aa:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    51b1:	00 
    uintptr_t uninit_array_addr;
    size_t uninit_array_size;
    const void *enclave_start = (const void*)&__ImageBase;
    51b2:	48 8d 05 47 ae ff ff 	lea    -0x51b9(%rip),%rax        # 0 <enclave.so>
    51b9:	48 89 45 e0          	mov    %rax,-0x20(%rbp)

    elf_get_uninit_array(enclave_start, &uninit_array_addr, &uninit_array_size);
    51bd:	48 8d 55 d0          	lea    -0x30(%rbp),%rdx
    51c1:	48 8d 4d c8          	lea    -0x38(%rbp),%rcx
    51c5:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    51c9:	48 89 ce             	mov    %rcx,%rsi
    51cc:	48 89 c7             	mov    %rax,%rdi
    51cf:	e8 05 fa ff ff       	callq  4bd9 <elf_get_uninit_array>

    if (uninit_array_addr == 0 || uninit_array_size == 0)
    51d4:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    51d8:	48 85 c0             	test   %rax,%rax
    51db:	74 56                	je     5233 <do_dtors_aux+0xa0>
    51dd:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    51e1:	48 85 c0             	test   %rax,%rax
    51e4:	74 4d                	je     5233 <do_dtors_aux+0xa0>
        return;

    fp_t *fp_start = (fp_t*)(uninit_array_addr + (uintptr_t)(enclave_start));
    51e6:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    51ea:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    51ee:	48 01 d0             	add    %rdx,%rax
    51f1:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    fp_t *fp_end = fp_start + (uninit_array_size / sizeof(fp_t));
    51f5:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    51f9:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    51fd:	48 89 c2             	mov    %rax,%rdx
    5200:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    5204:	48 01 d0             	add    %rdx,%rax
    5207:	48 89 45 f0          	mov    %rax,-0x10(%rbp)

    /* traverse .fini_array in reverse order */
    for (p = fp_end - 1; p >= fp_start; p--)
    520b:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    520f:	48 83 e8 08          	sub    $0x8,%rax
    5213:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    5217:	eb 0e                	jmp    5227 <do_dtors_aux+0x94>
    {
        (*p)();
    5219:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    521d:	48 8b 00             	mov    (%rax),%rax
    5220:	ff d0                	callq  *%rax
    for (p = fp_end - 1; p >= fp_start; p--)
    5222:	48 83 6d d8 08       	subq   $0x8,-0x28(%rbp)
    5227:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    522b:	48 3b 45 e8          	cmp    -0x18(%rbp),%rax
    522f:	73 e8                	jae    5219 <do_dtors_aux+0x86>
    5231:	eb 01                	jmp    5234 <do_dtors_aux+0xa1>
        return;
    5233:	90                   	nop
    }
}
    5234:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5238:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    523f:	00 00 
    5241:	74 05                	je     5248 <do_dtors_aux+0xb5>
    5243:	e8 1f 00 00 00       	callq  5267 <__stack_chk_fail>
    5248:	c9                   	leaveq 
    5249:	c3                   	retq   

000000000000524a <init_global_object>:

void init_global_object(void)
{
    524a:	55                   	push   %rbp
    524b:	48 89 e5             	mov    %rsp,%rbp
    do_ctors_aux();
    524e:	e8 79 fe ff ff       	callq  50cc <do_ctors_aux>
}
    5253:	90                   	nop
    5254:	5d                   	pop    %rbp
    5255:	c3                   	retq   

0000000000005256 <uninit_global_object>:

void uninit_global_object(void)
{
    5256:	55                   	push   %rbp
    5257:	48 89 e5             	mov    %rsp,%rbp
    do_atexit_aux();
    525a:	e8 eb fd ff ff       	callq  504a <do_atexit_aux>
    do_dtors_aux();
    525f:	e8 2f ff ff ff       	callq  5193 <do_dtors_aux>
}
    5264:	90                   	nop
    5265:	5d                   	pop    %rbp
    5266:	c3                   	retq   

0000000000005267 <__stack_chk_fail>:
#include "stdlib.h"

void
__attribute__((noreturn))
__stack_chk_fail(void)
{
    5267:	55                   	push   %rbp
    5268:	48 89 e5             	mov    %rsp,%rbp
    abort();
    526b:	e8 eb 76 00 00       	callq  c95b <abort>

0000000000005270 <__assert>:
#include <stdio.h>
#include <stdlib.h>

void
__assert(const char *file, int line, const char *func, const char *failedexpr)
{
    5270:	55                   	push   %rbp
    5271:	48 89 e5             	mov    %rsp,%rbp
    5274:	48 83 ec 20          	sub    $0x20,%rsp
    5278:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    527c:	89 75 f4             	mov    %esi,-0xc(%rbp)
    527f:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    5283:	48 89 4d e0          	mov    %rcx,-0x20(%rbp)
	(void)(line);
	(void)(func);
	(void)(failedexpr);
#endif

	abort();
    5287:	e8 cf 76 00 00       	callq  c95b <abort>

000000000000528c <spin_acquire_lock>:
#define SPIN_LOCK_YIELD
#endif /* ... yield ... */

#if !defined(USE_RECURSIVE_LOCKS) || USE_RECURSIVE_LOCKS == 0
/* Plain spin locks use single word (embedded in malloc_states) */
static int spin_acquire_lock(int *sl) {
    528c:	55                   	push   %rbp
    528d:	48 89 e5             	mov    %rsp,%rbp
    5290:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  int spins = 0;
    5294:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  while (*(volatile int *)sl != 0 || CAS_LOCK(sl)) {
    529b:	eb 04                	jmp    52a1 <spin_acquire_lock+0x15>
    if ((++spins & SPINS_PER_YIELD) == 0) {
    529d:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  while (*(volatile int *)sl != 0 || CAS_LOCK(sl)) {
    52a1:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    52a5:	8b 00                	mov    (%rax),%eax
    52a7:	85 c0                	test   %eax,%eax
    52a9:	75 f2                	jne    529d <spin_acquire_lock+0x11>
    52ab:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    52af:	b8 01 00 00 00       	mov    $0x1,%eax
    52b4:	87 02                	xchg   %eax,(%rdx)
    52b6:	85 c0                	test   %eax,%eax
    52b8:	75 e3                	jne    529d <spin_acquire_lock+0x11>
      SPIN_LOCK_YIELD;
    }
  }
  return 0;
    52ba:	b8 00 00 00 00       	mov    $0x0,%eax
}
    52bf:	5d                   	pop    %rbp
    52c0:	c3                   	retq   

00000000000052c1 <segment_holding>:
/*  True if segment S holds address A */
#define segment_holds(S, A)\
  ((char*)(A) >= S->base && (char*)(A) < S->base + S->size)

/* Return segment holding given address */
static msegmentptr segment_holding(mstate m, char* addr) {
    52c1:	55                   	push   %rbp
    52c2:	48 89 e5             	mov    %rsp,%rbp
    52c5:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    52c9:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  msegmentptr sp = &m->seg;
    52cd:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    52d1:	48 05 78 03 00 00    	add    $0x378,%rax
    52d7:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  for (;;) {
    if (addr >= sp->base && addr < sp->base + sp->size)
    52db:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    52df:	48 8b 00             	mov    (%rax),%rax
    52e2:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    52e6:	72 1e                	jb     5306 <segment_holding+0x45>
    52e8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    52ec:	48 8b 10             	mov    (%rax),%rdx
    52ef:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    52f3:	48 8b 40 08          	mov    0x8(%rax),%rax
    52f7:	48 01 d0             	add    %rdx,%rax
    52fa:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    52fe:	73 06                	jae    5306 <segment_holding+0x45>
      return sp;
    5300:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5304:	eb 18                	jmp    531e <segment_holding+0x5d>
    if ((sp = sp->next) == 0)
    5306:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    530a:	48 8b 40 10          	mov    0x10(%rax),%rax
    530e:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    5312:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    5317:	75 c2                	jne    52db <segment_holding+0x1a>
      return 0;
    5319:	b8 00 00 00 00       	mov    $0x0,%eax
  }
}
    531e:	5d                   	pop    %rbp
    531f:	c3                   	retq   

0000000000005320 <init_mparams>:
static void post_fork_parent(void) { RELEASE_LOCK(&(gm)->mutex); }
static void post_fork_child(void)  { INITIAL_LOCK(&(gm)->mutex); }
#endif /* LOCK_AT_FORK */

/* Initialize mparams */
static int init_mparams(void) {
    5320:	55                   	push   %rbp
    5321:	48 89 e5             	mov    %rsp,%rbp
    5324:	48 83 ec 20          	sub    $0x20,%rsp
    5328:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    532f:	00 00 
    5331:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    5335:	31 c0                	xor    %eax,%eax
#ifdef NEED_GLOBAL_LOCK_INIT
  if (malloc_global_mutex_status <= 0)
    init_malloc_global_mutex();
#endif

  ACQUIRE_MALLOC_GLOBAL_LOCK();
    5337:	b8 01 00 00 00       	mov    $0x1,%eax
    533c:	87 05 be bd 00 00    	xchg   %eax,0xbdbe(%rip)        # 11100 <malloc_global_mutex>
    5342:	85 c0                	test   %eax,%eax
    5344:	74 0c                	je     5352 <init_mparams+0x32>
    5346:	48 8d 3d b3 bd 00 00 	lea    0xbdb3(%rip),%rdi        # 11100 <malloc_global_mutex>
    534d:	e8 3a ff ff ff       	callq  528c <spin_acquire_lock>
  if (mparams.magic == 0) {
    5352:	48 8b 05 c7 bd 00 00 	mov    0xbdc7(%rip),%rax        # 11120 <mparams>
    5359:	48 85 c0             	test   %rax,%rax
    535c:	0f 85 d1 00 00 00    	jne    5433 <init_mparams+0x113>
    size_t magic;
    size_t psize;
    size_t gsize;

#if !defined(WIN32) || defined(_TLIBC_)
    psize = malloc_getpagesize;
    5362:	48 c7 45 e8 00 10 00 	movq   $0x1000,-0x18(%rbp)
    5369:	00 
    gsize = ((DEFAULT_GRANULARITY != 0)? DEFAULT_GRANULARITY : psize);
    536a:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    536e:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
        (MAX_SIZE_T < MIN_CHUNK_SIZE)  ||
        (sizeof(int) < 4)  ||
        (MALLOC_ALIGNMENT < (size_t)8U) ||
        ((MALLOC_ALIGNMENT & (MALLOC_ALIGNMENT-SIZE_T_ONE)) != 0) ||
        ((MCHUNK_SIZE      & (MCHUNK_SIZE-SIZE_T_ONE))      != 0) ||
        ((gsize            & (gsize-SIZE_T_ONE))            != 0) ||
    5372:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5376:	48 83 e8 01          	sub    $0x1,%rax
    537a:	48 23 45 f0          	and    -0x10(%rbp),%rax
    if ((sizeof(size_t) != sizeof(char*)) ||
    537e:	48 85 c0             	test   %rax,%rax
    5381:	75 11                	jne    5394 <init_mparams+0x74>
        ((psize            & (psize-SIZE_T_ONE))            != 0))
    5383:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    5387:	48 83 e8 01          	sub    $0x1,%rax
    538b:	48 23 45 e8          	and    -0x18(%rbp),%rax
        ((gsize            & (gsize-SIZE_T_ONE))            != 0) ||
    538f:	48 85 c0             	test   %rax,%rax
    5392:	74 05                	je     5399 <init_mparams+0x79>
      ABORT;
    5394:	e8 c2 75 00 00       	callq  c95b <abort>
    mparams.granularity = gsize;
    5399:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    539d:	48 89 05 8c bd 00 00 	mov    %rax,0xbd8c(%rip)        # 11130 <mparams+0x10>
    mparams.page_size = psize;
    53a4:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    53a8:	48 89 05 79 bd 00 00 	mov    %rax,0xbd79(%rip)        # 11128 <mparams+0x8>
    mparams.mmap_threshold = DEFAULT_MMAP_THRESHOLD;
    53af:	48 c7 05 7e bd 00 00 	movq   $0xffffffffffffffff,0xbd7e(%rip)        # 11138 <mparams+0x18>
    53b6:	ff ff ff ff 
    mparams.trim_threshold = DEFAULT_TRIM_THRESHOLD;
    53ba:	48 c7 05 7b bd 00 00 	movq   $0x200000,0xbd7b(%rip)        # 11140 <mparams+0x20>
    53c1:	00 00 20 00 
#if MORECORE_CONTIGUOUS
    mparams.default_mflags = USE_LOCK_BIT|USE_MMAP_BIT;
    53c5:	c7 05 79 bd 00 00 02 	movl   $0x2,0xbd79(%rip)        # 11148 <mparams+0x28>
    53cc:	00 00 00 
    mparams.default_mflags = USE_LOCK_BIT|USE_MMAP_BIT|USE_NONCONTIGUOUS_BIT;
#endif /* MORECORE_CONTIGUOUS */

#if !ONLY_MSPACES
    /* Set up lock for main malloc area */
    gm->mflags = mparams.default_mflags;
    53cf:	8b 05 73 bd 00 00    	mov    0xbd73(%rip),%eax        # 11148 <mparams+0x28>
    53d5:	89 05 f5 c0 00 00    	mov    %eax,0xc0f5(%rip)        # 114d0 <_gm_+0x370>
    (void)INITIAL_LOCK(&gm->mutex);
    53db:	c7 05 ef c0 00 00 00 	movl   $0x0,0xc0ef(%rip)        # 114d4 <_gm_+0x374>
    53e2:	00 00 00 
      else
#endif /* USE_DEV_RANDOM */
#if defined(WIN32) && !defined(_TLIBC_)
      magic = (size_t)(GetTickCount() ^ (size_t)0x55555555U);
#elif defined(LACKS_TIME_H)
      if (SGX_SUCCESS != sgx_read_rand((unsigned char *)&magic, sizeof(size_t)))
    53e5:	48 8d 45 e0          	lea    -0x20(%rbp),%rax
    53e9:	be 08 00 00 00       	mov    $0x8,%esi
    53ee:	48 89 c7             	mov    %rax,%rdi
    53f1:	e8 62 c1 ff ff       	callq  1558 <sgx_read_rand>
    53f6:	85 c0                	test   %eax,%eax
    53f8:	74 05                	je     53ff <init_mparams+0xdf>
          ABORT;
    53fa:	e8 5c 75 00 00       	callq  c95b <abort>
      magic = (size_t)(magic ^ (size_t)0x55555555U);
    53ff:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5403:	48 35 55 55 55 55    	xor    $0x55555555,%rax
    5409:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
#else
      magic = (size_t)(time(0) ^ (size_t)0x55555555U);
#endif
      magic |= (size_t)8U;    /* ensure nonzero */
    540d:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5411:	48 83 c8 08          	or     $0x8,%rax
    5415:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
      magic &= ~(size_t)7U;   /* improve chances of fault for bad values */
    5419:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    541d:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    5421:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
      /* Until memory modes commonly available, use volatile-write */
      (*(volatile size_t *)(&(mparams.magic))) = magic;
    5425:	48 8d 05 f4 bc 00 00 	lea    0xbcf4(%rip),%rax        # 11120 <mparams>
    542c:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    5430:	48 89 10             	mov    %rdx,(%rax)
    }
  }

  RELEASE_MALLOC_GLOBAL_LOCK();
    5433:	b8 00 00 00 00       	mov    $0x0,%eax
    5438:	89 05 c2 bc 00 00    	mov    %eax,0xbcc2(%rip)        # 11100 <malloc_global_mutex>
  return 1;
    543e:	b8 01 00 00 00       	mov    $0x1,%eax
}
    5443:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    5447:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    544e:	00 00 
    5450:	74 05                	je     5457 <init_mparams+0x137>
    5452:	e8 10 fe ff ff       	callq  5267 <__stack_chk_fail>
    5457:	c9                   	leaveq 
    5458:	c3                   	retq   

0000000000005459 <do_check_any_chunk>:

#if DEBUG
/* ------------------------- Debugging Support --------------------------- */

/* Check properties of any chunk, whether free, inuse, mmapped etc  */
static void do_check_any_chunk(mstate m, mchunkptr p) {
    5459:	55                   	push   %rbp
    545a:	48 89 e5             	mov    %rsp,%rbp
    545d:	48 83 ec 10          	sub    $0x10,%rsp
    5461:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    5465:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
  assert((is_aligned(chunk2mem(p))) || (p->head == FENCEPOST_HEAD));
    5469:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    546d:	48 83 c0 10          	add    $0x10,%rax
    5471:	83 e0 0f             	and    $0xf,%eax
    5474:	48 85 c0             	test   %rax,%rax
    5477:	74 13                	je     548c <do_check_any_chunk+0x33>
    5479:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    547d:	48 8b 40 08          	mov    0x8(%rax),%rax
    5481:	48 83 f8 0b          	cmp    $0xb,%rax
    5485:	74 05                	je     548c <do_check_any_chunk+0x33>
    5487:	e8 cf 74 00 00       	callq  c95b <abort>
  assert(ok_address(m, p));
    548c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5490:	48 8b 40 18          	mov    0x18(%rax),%rax
    5494:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    5498:	73 05                	jae    549f <do_check_any_chunk+0x46>
    549a:	e8 bc 74 00 00       	callq  c95b <abort>
}
    549f:	90                   	nop
    54a0:	c9                   	leaveq 
    54a1:	c3                   	retq   

00000000000054a2 <do_check_top_chunk>:

/* Check properties of top chunk */
static void do_check_top_chunk(mstate m, mchunkptr p) {
    54a2:	55                   	push   %rbp
    54a3:	48 89 e5             	mov    %rsp,%rbp
    54a6:	48 83 ec 20          	sub    $0x20,%rsp
    54aa:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    54ae:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  msegmentptr sp = segment_holding(m, (char*)p);
    54b2:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    54b6:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    54ba:	48 89 d6             	mov    %rdx,%rsi
    54bd:	48 89 c7             	mov    %rax,%rdi
    54c0:	e8 fc fd ff ff       	callq  52c1 <segment_holding>
    54c5:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
  size_t  sz = p->head & ~INUSE_BITS; /* third-lowest bit can be set! */
    54c9:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    54cd:	48 8b 40 08          	mov    0x8(%rax),%rax
    54d1:	48 83 e0 fc          	and    $0xfffffffffffffffc,%rax
    54d5:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  assert(sp != 0);
    54d9:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    54de:	75 05                	jne    54e5 <do_check_top_chunk+0x43>
    54e0:	e8 76 74 00 00       	callq  c95b <abort>
  assert((is_aligned(chunk2mem(p))) || (p->head == FENCEPOST_HEAD));
    54e5:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    54e9:	48 83 c0 10          	add    $0x10,%rax
    54ed:	83 e0 0f             	and    $0xf,%eax
    54f0:	48 85 c0             	test   %rax,%rax
    54f3:	74 13                	je     5508 <do_check_top_chunk+0x66>
    54f5:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    54f9:	48 8b 40 08          	mov    0x8(%rax),%rax
    54fd:	48 83 f8 0b          	cmp    $0xb,%rax
    5501:	74 05                	je     5508 <do_check_top_chunk+0x66>
    5503:	e8 53 74 00 00       	callq  c95b <abort>
  assert(ok_address(m, p));
    5508:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    550c:	48 8b 40 18          	mov    0x18(%rax),%rax
    5510:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    5514:	73 05                	jae    551b <do_check_top_chunk+0x79>
    5516:	e8 40 74 00 00       	callq  c95b <abort>
  assert(sz == m->topsize);
    551b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    551f:	48 8b 40 10          	mov    0x10(%rax),%rax
    5523:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    5527:	74 05                	je     552e <do_check_top_chunk+0x8c>
    5529:	e8 2d 74 00 00       	callq  c95b <abort>
  assert(sz > 0);
    552e:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    5533:	75 05                	jne    553a <do_check_top_chunk+0x98>
    5535:	e8 21 74 00 00       	callq  c95b <abort>
  assert(sz == ((sp->base + sp->size) - (char*)p) - TOP_FOOT_SIZE);
    553a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    553e:	48 8b 10             	mov    (%rax),%rdx
    5541:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5545:	48 8b 40 08          	mov    0x8(%rax),%rax
    5549:	48 01 d0             	add    %rdx,%rax
    554c:	48 89 c2             	mov    %rax,%rdx
    554f:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5553:	48 29 c2             	sub    %rax,%rdx
    5556:	48 89 d0             	mov    %rdx,%rax
    5559:	48 83 e8 50          	sub    $0x50,%rax
    555d:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    5561:	74 05                	je     5568 <do_check_top_chunk+0xc6>
    5563:	e8 f3 73 00 00       	callq  c95b <abort>
  assert(pinuse(p));
    5568:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    556c:	48 8b 40 08          	mov    0x8(%rax),%rax
    5570:	83 e0 01             	and    $0x1,%eax
    5573:	48 85 c0             	test   %rax,%rax
    5576:	75 05                	jne    557d <do_check_top_chunk+0xdb>
    5578:	e8 de 73 00 00       	callq  c95b <abort>
  assert(!pinuse(chunk_plus_offset(p, sz)));
    557d:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    5581:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5585:	48 01 d0             	add    %rdx,%rax
    5588:	48 8b 40 08          	mov    0x8(%rax),%rax
    558c:	83 e0 01             	and    $0x1,%eax
    558f:	48 85 c0             	test   %rax,%rax
    5592:	74 05                	je     5599 <do_check_top_chunk+0xf7>
    5594:	e8 c2 73 00 00       	callq  c95b <abort>
}
    5599:	90                   	nop
    559a:	c9                   	leaveq 
    559b:	c3                   	retq   

000000000000559c <do_check_mmapped_chunk>:

/* Check properties of (inuse) mmapped chunks */
static void do_check_mmapped_chunk(mstate m, mchunkptr p) {
    559c:	55                   	push   %rbp
    559d:	48 89 e5             	mov    %rsp,%rbp
    55a0:	48 83 ec 20          	sub    $0x20,%rsp
    55a4:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    55a8:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  size_t  sz = chunksize(p);
    55ac:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    55b0:	48 8b 40 08          	mov    0x8(%rax),%rax
    55b4:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    55b8:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
  size_t len = (sz + (p->prev_foot) + MMAP_FOOT_PAD);
    55bc:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    55c0:	48 8b 10             	mov    (%rax),%rdx
    55c3:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    55c7:	48 01 d0             	add    %rdx,%rax
    55ca:	48 83 c0 20          	add    $0x20,%rax
    55ce:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  assert(is_mmapped(p));
    55d2:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    55d6:	48 8b 40 08          	mov    0x8(%rax),%rax
    55da:	83 e0 03             	and    $0x3,%eax
    55dd:	48 85 c0             	test   %rax,%rax
    55e0:	74 05                	je     55e7 <do_check_mmapped_chunk+0x4b>
    55e2:	e8 74 73 00 00       	callq  c95b <abort>
  assert(use_mmap(m));
    55e7:	e8 6f 73 00 00       	callq  c95b <abort>

00000000000055ec <do_check_inuse_chunk>:
  assert(chunk_plus_offset(p, sz)->head == FENCEPOST_HEAD);
  assert(chunk_plus_offset(p, sz+SIZE_T_SIZE)->head == 0);
}

/* Check properties of inuse chunks */
static void do_check_inuse_chunk(mstate m, mchunkptr p) {
    55ec:	55                   	push   %rbp
    55ed:	48 89 e5             	mov    %rsp,%rbp
    55f0:	48 83 ec 10          	sub    $0x10,%rsp
    55f4:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    55f8:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
  do_check_any_chunk(m, p);
    55fc:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    5600:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5604:	48 89 d6             	mov    %rdx,%rsi
    5607:	48 89 c7             	mov    %rax,%rdi
    560a:	e8 4a fe ff ff       	callq  5459 <do_check_any_chunk>
  assert(is_inuse(p));
    560f:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5613:	48 8b 40 08          	mov    0x8(%rax),%rax
    5617:	83 e0 03             	and    $0x3,%eax
    561a:	48 83 f8 01          	cmp    $0x1,%rax
    561e:	75 05                	jne    5625 <do_check_inuse_chunk+0x39>
    5620:	e8 36 73 00 00       	callq  c95b <abort>
  assert(next_pinuse(p));
    5625:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5629:	48 8b 40 08          	mov    0x8(%rax),%rax
    562d:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    5631:	48 89 c2             	mov    %rax,%rdx
    5634:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5638:	48 01 d0             	add    %rdx,%rax
    563b:	48 8b 40 08          	mov    0x8(%rax),%rax
    563f:	83 e0 01             	and    $0x1,%eax
    5642:	48 85 c0             	test   %rax,%rax
    5645:	75 05                	jne    564c <do_check_inuse_chunk+0x60>
    5647:	e8 0f 73 00 00       	callq  c95b <abort>
  /* If not pinuse and not mmapped, previous chunk has OK offset */
  assert(is_mmapped(p) || pinuse(p) || next_chunk(prev_chunk(p)) == p);
    564c:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5650:	48 8b 40 08          	mov    0x8(%rax),%rax
    5654:	83 e0 03             	and    $0x3,%eax
    5657:	48 85 c0             	test   %rax,%rax
    565a:	74 40                	je     569c <do_check_inuse_chunk+0xb0>
    565c:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5660:	48 8b 40 08          	mov    0x8(%rax),%rax
    5664:	83 e0 01             	and    $0x1,%eax
    5667:	48 85 c0             	test   %rax,%rax
    566a:	75 30                	jne    569c <do_check_inuse_chunk+0xb0>
    566c:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5670:	48 8b 00             	mov    (%rax),%rax
    5673:	48 f7 d8             	neg    %rax
    5676:	48 89 c2             	mov    %rax,%rdx
    5679:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    567d:	48 01 d0             	add    %rdx,%rax
    5680:	48 8b 40 08          	mov    0x8(%rax),%rax
    5684:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    5688:	48 89 c2             	mov    %rax,%rdx
    568b:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    568f:	48 8b 00             	mov    (%rax),%rax
    5692:	48 39 c2             	cmp    %rax,%rdx
    5695:	74 05                	je     569c <do_check_inuse_chunk+0xb0>
    5697:	e8 bf 72 00 00       	callq  c95b <abort>
  if (is_mmapped(p))
    569c:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    56a0:	48 8b 40 08          	mov    0x8(%rax),%rax
    56a4:	83 e0 03             	and    $0x3,%eax
    56a7:	48 85 c0             	test   %rax,%rax
    56aa:	75 13                	jne    56bf <do_check_inuse_chunk+0xd3>
    do_check_mmapped_chunk(m, p);
    56ac:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    56b0:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    56b4:	48 89 d6             	mov    %rdx,%rsi
    56b7:	48 89 c7             	mov    %rax,%rdi
    56ba:	e8 dd fe ff ff       	callq  559c <do_check_mmapped_chunk>
}
    56bf:	90                   	nop
    56c0:	c9                   	leaveq 
    56c1:	c3                   	retq   

00000000000056c2 <do_check_free_chunk>:

/* Check properties of free chunks */
static void do_check_free_chunk(mstate m, mchunkptr p) {
    56c2:	55                   	push   %rbp
    56c3:	48 89 e5             	mov    %rsp,%rbp
    56c6:	48 83 ec 20          	sub    $0x20,%rsp
    56ca:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    56ce:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  size_t sz = chunksize(p);
    56d2:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    56d6:	48 8b 40 08          	mov    0x8(%rax),%rax
    56da:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    56de:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
  mchunkptr next = chunk_plus_offset(p, sz);
    56e2:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    56e6:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    56ea:	48 01 d0             	add    %rdx,%rax
    56ed:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  do_check_any_chunk(m, p);
    56f1:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    56f5:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    56f9:	48 89 d6             	mov    %rdx,%rsi
    56fc:	48 89 c7             	mov    %rax,%rdi
    56ff:	e8 55 fd ff ff       	callq  5459 <do_check_any_chunk>
  assert(!is_inuse(p));
    5704:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5708:	48 8b 40 08          	mov    0x8(%rax),%rax
    570c:	83 e0 03             	and    $0x3,%eax
    570f:	48 83 f8 01          	cmp    $0x1,%rax
    5713:	74 05                	je     571a <do_check_free_chunk+0x58>
    5715:	e8 41 72 00 00       	callq  c95b <abort>
  assert(!next_pinuse(p));
    571a:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    571e:	48 8b 40 08          	mov    0x8(%rax),%rax
    5722:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    5726:	48 89 c2             	mov    %rax,%rdx
    5729:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    572d:	48 01 d0             	add    %rdx,%rax
    5730:	48 8b 40 08          	mov    0x8(%rax),%rax
    5734:	83 e0 01             	and    $0x1,%eax
    5737:	48 85 c0             	test   %rax,%rax
    573a:	74 05                	je     5741 <do_check_free_chunk+0x7f>
    573c:	e8 1a 72 00 00       	callq  c95b <abort>
  assert (!is_mmapped(p));
    5741:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5745:	48 8b 40 08          	mov    0x8(%rax),%rax
    5749:	83 e0 03             	and    $0x3,%eax
    574c:	48 85 c0             	test   %rax,%rax
    574f:	75 05                	jne    5756 <do_check_free_chunk+0x94>
    5751:	e8 05 72 00 00       	callq  c95b <abort>
  if (p != m->dv && p != m->top) {
    5756:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    575a:	48 8b 40 20          	mov    0x20(%rax),%rax
    575e:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    5762:	0f 84 c8 00 00 00    	je     5830 <do_check_free_chunk+0x16e>
    5768:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    576c:	48 8b 40 28          	mov    0x28(%rax),%rax
    5770:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    5774:	0f 84 b6 00 00 00    	je     5830 <do_check_free_chunk+0x16e>
    if (sz >= MIN_CHUNK_SIZE) {
    577a:	48 83 7d f0 1f       	cmpq   $0x1f,-0x10(%rbp)
    577f:	0f 86 9f 00 00 00    	jbe    5824 <do_check_free_chunk+0x162>
      assert((sz & CHUNK_ALIGN_MASK) == 0);
    5785:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5789:	83 e0 0f             	and    $0xf,%eax
    578c:	48 85 c0             	test   %rax,%rax
    578f:	74 05                	je     5796 <do_check_free_chunk+0xd4>
    5791:	e8 c5 71 00 00       	callq  c95b <abort>
      assert(is_aligned(chunk2mem(p)));
    5796:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    579a:	48 83 c0 10          	add    $0x10,%rax
    579e:	83 e0 0f             	and    $0xf,%eax
    57a1:	48 85 c0             	test   %rax,%rax
    57a4:	74 05                	je     57ab <do_check_free_chunk+0xe9>
    57a6:	e8 b0 71 00 00       	callq  c95b <abort>
      assert(next->prev_foot == sz);
    57ab:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    57af:	48 8b 00             	mov    (%rax),%rax
    57b2:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    57b6:	74 05                	je     57bd <do_check_free_chunk+0xfb>
    57b8:	e8 9e 71 00 00       	callq  c95b <abort>
      assert(pinuse(p));
    57bd:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    57c1:	48 8b 40 08          	mov    0x8(%rax),%rax
    57c5:	83 e0 01             	and    $0x1,%eax
    57c8:	48 85 c0             	test   %rax,%rax
    57cb:	75 05                	jne    57d2 <do_check_free_chunk+0x110>
    57cd:	e8 89 71 00 00       	callq  c95b <abort>
      assert (next == m->top || is_inuse(next));
    57d2:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    57d6:	48 8b 40 28          	mov    0x28(%rax),%rax
    57da:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    57de:	74 16                	je     57f6 <do_check_free_chunk+0x134>
    57e0:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    57e4:	48 8b 40 08          	mov    0x8(%rax),%rax
    57e8:	83 e0 03             	and    $0x3,%eax
    57eb:	48 83 f8 01          	cmp    $0x1,%rax
    57ef:	75 05                	jne    57f6 <do_check_free_chunk+0x134>
    57f1:	e8 65 71 00 00       	callq  c95b <abort>
      assert(p->fd->bk == p);
    57f6:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    57fa:	48 8b 40 10          	mov    0x10(%rax),%rax
    57fe:	48 8b 40 18          	mov    0x18(%rax),%rax
    5802:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    5806:	74 05                	je     580d <do_check_free_chunk+0x14b>
    5808:	e8 4e 71 00 00       	callq  c95b <abort>
      assert(p->bk->fd == p);
    580d:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5811:	48 8b 40 18          	mov    0x18(%rax),%rax
    5815:	48 8b 40 10          	mov    0x10(%rax),%rax
    5819:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    581d:	74 11                	je     5830 <do_check_free_chunk+0x16e>
    581f:	e8 37 71 00 00       	callq  c95b <abort>
    }
    else  /* markers are always of size SIZE_T_SIZE */
      assert(sz == SIZE_T_SIZE);
    5824:	48 83 7d f0 08       	cmpq   $0x8,-0x10(%rbp)
    5829:	74 05                	je     5830 <do_check_free_chunk+0x16e>
    582b:	e8 2b 71 00 00       	callq  c95b <abort>
  }
}
    5830:	90                   	nop
    5831:	c9                   	leaveq 
    5832:	c3                   	retq   

0000000000005833 <do_check_malloced_chunk>:

/* Check properties of malloced chunks at the point they are malloced */
static void do_check_malloced_chunk(mstate m, void* mem, size_t s) {
    5833:	55                   	push   %rbp
    5834:	48 89 e5             	mov    %rsp,%rbp
    5837:	48 83 ec 30          	sub    $0x30,%rsp
    583b:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    583f:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    5843:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
  if (mem != 0) {
    5847:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
    584c:	74 7e                	je     58cc <do_check_malloced_chunk+0x99>
    mchunkptr p = mem2chunk(mem);
    584e:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5852:	48 83 e8 10          	sub    $0x10,%rax
    5856:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    size_t sz = p->head & ~INUSE_BITS;
    585a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    585e:	48 8b 40 08          	mov    0x8(%rax),%rax
    5862:	48 83 e0 fc          	and    $0xfffffffffffffffc,%rax
    5866:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    do_check_inuse_chunk(m, p);
    586a:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    586e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    5872:	48 89 d6             	mov    %rdx,%rsi
    5875:	48 89 c7             	mov    %rax,%rdi
    5878:	e8 6f fd ff ff       	callq  55ec <do_check_inuse_chunk>
    assert((sz & CHUNK_ALIGN_MASK) == 0);
    587d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5881:	83 e0 0f             	and    $0xf,%eax
    5884:	48 85 c0             	test   %rax,%rax
    5887:	74 05                	je     588e <do_check_malloced_chunk+0x5b>
    5889:	e8 cd 70 00 00       	callq  c95b <abort>
    assert(sz >= MIN_CHUNK_SIZE);
    588e:	48 83 7d f8 1f       	cmpq   $0x1f,-0x8(%rbp)
    5893:	77 05                	ja     589a <do_check_malloced_chunk+0x67>
    5895:	e8 c1 70 00 00       	callq  c95b <abort>
    assert(sz >= s);
    589a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    589e:	48 3b 45 d8          	cmp    -0x28(%rbp),%rax
    58a2:	73 05                	jae    58a9 <do_check_malloced_chunk+0x76>
    58a4:	e8 b2 70 00 00       	callq  c95b <abort>
    /* unless mmapped, size is less than MIN_CHUNK_SIZE more than request */
    assert(is_mmapped(p) || sz < (s + MIN_CHUNK_SIZE));
    58a9:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    58ad:	48 8b 40 08          	mov    0x8(%rax),%rax
    58b1:	83 e0 03             	and    $0x3,%eax
    58b4:	48 85 c0             	test   %rax,%rax
    58b7:	74 13                	je     58cc <do_check_malloced_chunk+0x99>
    58b9:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    58bd:	48 83 c0 20          	add    $0x20,%rax
    58c1:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    58c5:	72 05                	jb     58cc <do_check_malloced_chunk+0x99>
    58c7:	e8 8f 70 00 00       	callq  c95b <abort>
  }
}
    58cc:	90                   	nop
    58cd:	c9                   	leaveq 
    58ce:	c3                   	retq   

00000000000058cf <init_top>:


/* -------------------------- mspace management -------------------------- */

/* Initialize top chunk and its size */
static void init_top(mstate m, mchunkptr p, size_t psize) {
    58cf:	55                   	push   %rbp
    58d0:	48 89 e5             	mov    %rsp,%rbp
    58d3:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    58d7:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    58db:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
  /* Ensure alignment */
  size_t offset = align_offset(chunk2mem(p));
    58df:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    58e3:	48 83 c0 10          	add    $0x10,%rax
    58e7:	83 e0 0f             	and    $0xf,%eax
    58ea:	48 85 c0             	test   %rax,%rax
    58ed:	74 10                	je     58ff <init_top+0x30>
    58ef:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    58f3:	48 83 c0 10          	add    $0x10,%rax
    58f7:	48 f7 d8             	neg    %rax
    58fa:	83 e0 0f             	and    $0xf,%eax
    58fd:	eb 05                	jmp    5904 <init_top+0x35>
    58ff:	b8 00 00 00 00       	mov    $0x0,%eax
    5904:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  p = (mchunkptr)((char*)p + offset);
    5908:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    590c:	48 01 45 e0          	add    %rax,-0x20(%rbp)
  psize -= offset;
    5910:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5914:	48 29 45 d8          	sub    %rax,-0x28(%rbp)

  m->top = p;
    5918:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    591c:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    5920:	48 89 50 28          	mov    %rdx,0x28(%rax)
  m->topsize = psize;
    5924:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    5928:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    592c:	48 89 50 10          	mov    %rdx,0x10(%rax)
  p->head = psize | PINUSE_BIT;
    5930:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    5934:	48 83 c8 01          	or     $0x1,%rax
    5938:	48 89 c2             	mov    %rax,%rdx
    593b:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    593f:	48 89 50 08          	mov    %rdx,0x8(%rax)
  /* set size of fake trailing chunk holding overhead space only once */
  chunk_plus_offset(p, psize)->head = TOP_FOOT_SIZE;
    5943:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    5947:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    594b:	48 01 d0             	add    %rdx,%rax
    594e:	48 c7 40 08 50 00 00 	movq   $0x50,0x8(%rax)
    5955:	00 
  m->trim_check = mparams.trim_threshold; /* reset on each update */
    5956:	48 8b 15 e3 b7 00 00 	mov    0xb7e3(%rip),%rdx        # 11140 <mparams+0x20>
    595d:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    5961:	48 89 50 30          	mov    %rdx,0x30(%rax)
}
    5965:	90                   	nop
    5966:	5d                   	pop    %rbp
    5967:	c3                   	retq   

0000000000005968 <init_bins>:

/* Initialize bins for a new mstate that is otherwise zeroed out */
static void init_bins(mstate m) {
    5968:	55                   	push   %rbp
    5969:	48 89 e5             	mov    %rsp,%rbp
    596c:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  /* Establish circular links for smallbins */
  bindex_t i;
  for (i = 0; i < NSMALLBINS; ++i) {
    5970:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    5977:	eb 42                	jmp    59bb <init_bins+0x53>
    sbinptr bin = smallbin_at(m,i);
    5979:	8b 45 f4             	mov    -0xc(%rbp),%eax
    597c:	01 c0                	add    %eax,%eax
    597e:	89 c0                	mov    %eax,%eax
    5980:	48 83 c0 08          	add    $0x8,%rax
    5984:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    598b:	00 
    598c:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    5990:	48 01 d0             	add    %rdx,%rax
    5993:	48 83 c0 08          	add    $0x8,%rax
    5997:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    bin->fd = bin->bk = bin;
    599b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    599f:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    59a3:	48 89 50 18          	mov    %rdx,0x18(%rax)
    59a7:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    59ab:	48 8b 50 18          	mov    0x18(%rax),%rdx
    59af:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    59b3:	48 89 50 10          	mov    %rdx,0x10(%rax)
  for (i = 0; i < NSMALLBINS; ++i) {
    59b7:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    59bb:	83 7d f4 1f          	cmpl   $0x1f,-0xc(%rbp)
    59bf:	76 b8                	jbe    5979 <init_bins+0x11>
  }
}
    59c1:	90                   	nop
    59c2:	5d                   	pop    %rbp
    59c3:	c3                   	retq   

00000000000059c4 <prepend_alloc>:
}
#endif /* PROCEED_ON_ERROR */

/* Allocate chunk and prepend remainder with chunk in successor base. */
static void* prepend_alloc(mstate m, char* newbase, char* oldbase,
                           size_t nb) {
    59c4:	55                   	push   %rbp
    59c5:	48 89 e5             	mov    %rsp,%rbp
    59c8:	48 81 ec 10 01 00 00 	sub    $0x110,%rsp
    59cf:	48 89 bd 08 ff ff ff 	mov    %rdi,-0xf8(%rbp)
    59d6:	48 89 b5 00 ff ff ff 	mov    %rsi,-0x100(%rbp)
    59dd:	48 89 95 f8 fe ff ff 	mov    %rdx,-0x108(%rbp)
    59e4:	48 89 8d f0 fe ff ff 	mov    %rcx,-0x110(%rbp)
  mchunkptr p = align_as_chunk(newbase);
    59eb:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    59f2:	48 83 c0 10          	add    $0x10,%rax
    59f6:	83 e0 0f             	and    $0xf,%eax
    59f9:	48 85 c0             	test   %rax,%rax
    59fc:	74 16                	je     5a14 <prepend_alloc+0x50>
    59fe:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    5a05:	48 83 c0 10          	add    $0x10,%rax
    5a09:	48 f7 d8             	neg    %rax
    5a0c:	83 e0 0f             	and    $0xf,%eax
    5a0f:	48 89 c2             	mov    %rax,%rdx
    5a12:	eb 05                	jmp    5a19 <prepend_alloc+0x55>
    5a14:	ba 00 00 00 00       	mov    $0x0,%edx
    5a19:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    5a20:	48 01 d0             	add    %rdx,%rax
    5a23:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
  mchunkptr oldfirst = align_as_chunk(oldbase);
    5a2a:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    5a31:	48 83 c0 10          	add    $0x10,%rax
    5a35:	83 e0 0f             	and    $0xf,%eax
    5a38:	48 85 c0             	test   %rax,%rax
    5a3b:	74 16                	je     5a53 <prepend_alloc+0x8f>
    5a3d:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    5a44:	48 83 c0 10          	add    $0x10,%rax
    5a48:	48 f7 d8             	neg    %rax
    5a4b:	83 e0 0f             	and    $0xf,%eax
    5a4e:	48 89 c2             	mov    %rax,%rdx
    5a51:	eb 05                	jmp    5a58 <prepend_alloc+0x94>
    5a53:	ba 00 00 00 00       	mov    $0x0,%edx
    5a58:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    5a5f:	48 01 d0             	add    %rdx,%rax
    5a62:	48 89 85 28 ff ff ff 	mov    %rax,-0xd8(%rbp)
  size_t psize = (char*)oldfirst - (char*)p;
    5a69:	48 8b 95 28 ff ff ff 	mov    -0xd8(%rbp),%rdx
    5a70:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    5a77:	48 29 c2             	sub    %rax,%rdx
    5a7a:	48 89 d0             	mov    %rdx,%rax
    5a7d:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
  mchunkptr q = chunk_plus_offset(p, nb);
    5a84:	48 8b 95 68 ff ff ff 	mov    -0x98(%rbp),%rdx
    5a8b:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    5a92:	48 01 d0             	add    %rdx,%rax
    5a95:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
  size_t qsize = psize - nb;
    5a9c:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    5aa3:	48 2b 85 f0 fe ff ff 	sub    -0x110(%rbp),%rax
    5aaa:	48 89 85 30 ff ff ff 	mov    %rax,-0xd0(%rbp)
  set_size_and_pinuse_of_inuse_chunk(m, p, nb);
    5ab1:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    5ab8:	48 83 c8 03          	or     $0x3,%rax
    5abc:	48 89 c2             	mov    %rax,%rdx
    5abf:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    5ac6:	48 89 50 08          	mov    %rdx,0x8(%rax)
    5aca:	48 8b 0d 4f b6 00 00 	mov    0xb64f(%rip),%rcx        # 11120 <mparams>
    5ad1:	48 8b 95 08 ff ff ff 	mov    -0xf8(%rbp),%rdx
    5ad8:	48 8b b5 68 ff ff ff 	mov    -0x98(%rbp),%rsi
    5adf:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    5ae6:	48 01 f0             	add    %rsi,%rax
    5ae9:	48 31 ca             	xor    %rcx,%rdx
    5aec:	48 89 10             	mov    %rdx,(%rax)

  assert((char*)oldfirst > (char*)q);
    5aef:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5af6:	48 3b 85 78 ff ff ff 	cmp    -0x88(%rbp),%rax
    5afd:	77 05                	ja     5b04 <prepend_alloc+0x140>
    5aff:	e8 57 6e 00 00       	callq  c95b <abort>
  assert(pinuse(oldfirst));
    5b04:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5b0b:	48 8b 40 08          	mov    0x8(%rax),%rax
    5b0f:	83 e0 01             	and    $0x1,%eax
    5b12:	48 85 c0             	test   %rax,%rax
    5b15:	75 05                	jne    5b1c <prepend_alloc+0x158>
    5b17:	e8 3f 6e 00 00       	callq  c95b <abort>
  assert(qsize >= MIN_CHUNK_SIZE);
    5b1c:	48 83 bd 30 ff ff ff 	cmpq   $0x1f,-0xd0(%rbp)
    5b23:	1f 
    5b24:	77 05                	ja     5b2b <prepend_alloc+0x167>
    5b26:	e8 30 6e 00 00       	callq  c95b <abort>

  /* consolidate remainder with first chunk of old base */
  if (oldfirst == m->top) {
    5b2b:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5b32:	48 8b 40 28          	mov    0x28(%rax),%rax
    5b36:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    5b3d:	75 75                	jne    5bb4 <prepend_alloc+0x1f0>
    size_t tsize = m->topsize += qsize;
    5b3f:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5b46:	48 8b 50 10          	mov    0x10(%rax),%rdx
    5b4a:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    5b51:	48 01 c2             	add    %rax,%rdx
    5b54:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5b5b:	48 89 50 10          	mov    %rdx,0x10(%rax)
    5b5f:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5b66:	48 8b 40 10          	mov    0x10(%rax),%rax
    5b6a:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    m->top = q;
    5b6e:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5b75:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    5b7c:	48 89 50 28          	mov    %rdx,0x28(%rax)
    q->head = tsize | PINUSE_BIT;
    5b80:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5b84:	48 83 c8 01          	or     $0x1,%rax
    5b88:	48 89 c2             	mov    %rax,%rdx
    5b8b:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    5b92:	48 89 50 08          	mov    %rdx,0x8(%rax)
    check_top_chunk(m, q);
    5b96:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    5b9d:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5ba4:	48 89 d6             	mov    %rdx,%rsi
    5ba7:	48 89 c7             	mov    %rax,%rdi
    5baa:	e8 f3 f8 ff ff       	callq  54a2 <do_check_top_chunk>
    5baf:	e9 95 0a 00 00       	jmpq   6649 <prepend_alloc+0xc85>
  }
  else if (oldfirst == m->dv) {
    5bb4:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5bbb:	48 8b 40 20          	mov    0x20(%rax),%rax
    5bbf:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    5bc6:	75 71                	jne    5c39 <prepend_alloc+0x275>
    size_t dsize = m->dvsize += qsize;
    5bc8:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5bcf:	48 8b 50 08          	mov    0x8(%rax),%rdx
    5bd3:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    5bda:	48 01 c2             	add    %rax,%rdx
    5bdd:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5be4:	48 89 50 08          	mov    %rdx,0x8(%rax)
    5be8:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5bef:	48 8b 40 08          	mov    0x8(%rax),%rax
    5bf3:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    m->dv = q;
    5bf7:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5bfe:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    5c05:	48 89 50 20          	mov    %rdx,0x20(%rax)
    set_size_and_pinuse_of_free_chunk(q, dsize);
    5c09:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5c0d:	48 83 c8 01          	or     $0x1,%rax
    5c11:	48 89 c2             	mov    %rax,%rdx
    5c14:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    5c1b:	48 89 50 08          	mov    %rdx,0x8(%rax)
    5c1f:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    5c26:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5c2a:	48 01 c2             	add    %rax,%rdx
    5c2d:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5c31:	48 89 02             	mov    %rax,(%rdx)
    5c34:	e9 10 0a 00 00       	jmpq   6649 <prepend_alloc+0xc85>
  }
  else {
    if (!is_inuse(oldfirst)) {
    5c39:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5c40:	48 8b 40 08          	mov    0x8(%rax),%rax
    5c44:	83 e0 03             	and    $0x3,%eax
    5c47:	48 83 f8 01          	cmp    $0x1,%rax
    5c4b:	0f 85 70 05 00 00    	jne    61c1 <prepend_alloc+0x7fd>
      size_t nsize = chunksize(oldfirst);
    5c51:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5c58:	48 8b 40 08          	mov    0x8(%rax),%rax
    5c5c:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    5c60:	48 89 45 80          	mov    %rax,-0x80(%rbp)
      unlink_chunk(m, oldfirst, nsize);
    5c64:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    5c68:	48 c1 e8 03          	shr    $0x3,%rax
    5c6c:	48 83 f8 1f          	cmp    $0x1f,%rax
    5c70:	0f 87 c6 01 00 00    	ja     5e3c <prepend_alloc+0x478>
    5c76:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5c7d:	48 8b 40 10          	mov    0x10(%rax),%rax
    5c81:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    5c85:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5c8c:	48 8b 40 18          	mov    0x18(%rax),%rax
    5c90:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    5c94:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    5c98:	48 c1 e8 03          	shr    $0x3,%rax
    5c9c:	89 85 18 ff ff ff    	mov    %eax,-0xe8(%rbp)
    5ca2:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5ca9:	48 3b 45 c0          	cmp    -0x40(%rbp),%rax
    5cad:	75 05                	jne    5cb4 <prepend_alloc+0x2f0>
    5caf:	e8 a7 6c 00 00       	callq  c95b <abort>
    5cb4:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5cbb:	48 3b 45 b8          	cmp    -0x48(%rbp),%rax
    5cbf:	75 05                	jne    5cc6 <prepend_alloc+0x302>
    5cc1:	e8 95 6c 00 00       	callq  c95b <abort>
    5cc6:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5ccd:	48 8b 40 08          	mov    0x8(%rax),%rax
    5cd1:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    5cd5:	48 89 c2             	mov    %rax,%rdx
    5cd8:	8b 85 18 ff ff ff    	mov    -0xe8(%rbp),%eax
    5cde:	c1 e0 03             	shl    $0x3,%eax
    5ce1:	89 c0                	mov    %eax,%eax
    5ce3:	48 39 c2             	cmp    %rax,%rdx
    5ce6:	74 05                	je     5ced <prepend_alloc+0x329>
    5ce8:	e8 6e 6c 00 00       	callq  c95b <abort>
    5ced:	8b 85 18 ff ff ff    	mov    -0xe8(%rbp),%eax
    5cf3:	01 c0                	add    %eax,%eax
    5cf5:	89 c0                	mov    %eax,%eax
    5cf7:	48 83 c0 08          	add    $0x8,%rax
    5cfb:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    5d02:	00 
    5d03:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5d0a:	48 01 d0             	add    %rdx,%rax
    5d0d:	48 83 c0 08          	add    $0x8,%rax
    5d11:	48 39 45 b8          	cmp    %rax,-0x48(%rbp)
    5d15:	0f 94 c0             	sete   %al
    5d18:	0f b6 c0             	movzbl %al,%eax
    5d1b:	48 85 c0             	test   %rax,%rax
    5d1e:	75 48                	jne    5d68 <prepend_alloc+0x3a4>
    5d20:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5d27:	48 8b 40 18          	mov    0x18(%rax),%rax
    5d2b:	48 39 45 b8          	cmp    %rax,-0x48(%rbp)
    5d2f:	0f 93 c0             	setae  %al
    5d32:	0f b6 c0             	movzbl %al,%eax
    5d35:	48 85 c0             	test   %rax,%rax
    5d38:	74 21                	je     5d5b <prepend_alloc+0x397>
    5d3a:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    5d3e:	48 8b 40 18          	mov    0x18(%rax),%rax
    5d42:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    5d49:	0f 94 c0             	sete   %al
    5d4c:	0f b6 c0             	movzbl %al,%eax
    5d4f:	48 85 c0             	test   %rax,%rax
    5d52:	74 07                	je     5d5b <prepend_alloc+0x397>
    5d54:	b8 01 00 00 00       	mov    $0x1,%eax
    5d59:	eb 05                	jmp    5d60 <prepend_alloc+0x39c>
    5d5b:	b8 00 00 00 00       	mov    $0x0,%eax
    5d60:	85 c0                	test   %eax,%eax
    5d62:	0f 84 cf 00 00 00    	je     5e37 <prepend_alloc+0x473>
    5d68:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    5d6c:	48 3b 45 b8          	cmp    -0x48(%rbp),%rax
    5d70:	75 2c                	jne    5d9e <prepend_alloc+0x3da>
    5d72:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5d79:	8b 10                	mov    (%rax),%edx
    5d7b:	8b 85 18 ff ff ff    	mov    -0xe8(%rbp),%eax
    5d81:	be 01 00 00 00       	mov    $0x1,%esi
    5d86:	89 c1                	mov    %eax,%ecx
    5d88:	d3 e6                	shl    %cl,%esi
    5d8a:	89 f0                	mov    %esi,%eax
    5d8c:	f7 d0                	not    %eax
    5d8e:	21 c2                	and    %eax,%edx
    5d90:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5d97:	89 10                	mov    %edx,(%rax)
    5d99:	e9 0d 04 00 00       	jmpq   61ab <prepend_alloc+0x7e7>
    5d9e:	8b 85 18 ff ff ff    	mov    -0xe8(%rbp),%eax
    5da4:	01 c0                	add    %eax,%eax
    5da6:	89 c0                	mov    %eax,%eax
    5da8:	48 83 c0 08          	add    $0x8,%rax
    5dac:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    5db3:	00 
    5db4:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5dbb:	48 01 d0             	add    %rdx,%rax
    5dbe:	48 83 c0 08          	add    $0x8,%rax
    5dc2:	48 39 45 c0          	cmp    %rax,-0x40(%rbp)
    5dc6:	0f 94 c0             	sete   %al
    5dc9:	0f b6 c0             	movzbl %al,%eax
    5dcc:	48 85 c0             	test   %rax,%rax
    5dcf:	75 44                	jne    5e15 <prepend_alloc+0x451>
    5dd1:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5dd8:	48 8b 40 18          	mov    0x18(%rax),%rax
    5ddc:	48 39 45 c0          	cmp    %rax,-0x40(%rbp)
    5de0:	0f 93 c0             	setae  %al
    5de3:	0f b6 c0             	movzbl %al,%eax
    5de6:	48 85 c0             	test   %rax,%rax
    5de9:	74 21                	je     5e0c <prepend_alloc+0x448>
    5deb:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    5def:	48 8b 40 10          	mov    0x10(%rax),%rax
    5df3:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    5dfa:	0f 94 c0             	sete   %al
    5dfd:	0f b6 c0             	movzbl %al,%eax
    5e00:	48 85 c0             	test   %rax,%rax
    5e03:	74 07                	je     5e0c <prepend_alloc+0x448>
    5e05:	b8 01 00 00 00       	mov    $0x1,%eax
    5e0a:	eb 05                	jmp    5e11 <prepend_alloc+0x44d>
    5e0c:	b8 00 00 00 00       	mov    $0x0,%eax
    5e11:	85 c0                	test   %eax,%eax
    5e13:	74 1d                	je     5e32 <prepend_alloc+0x46e>
    5e15:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    5e19:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    5e1d:	48 89 50 18          	mov    %rdx,0x18(%rax)
    5e21:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    5e25:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
    5e29:	48 89 50 10          	mov    %rdx,0x10(%rax)
    5e2d:	e9 79 03 00 00       	jmpq   61ab <prepend_alloc+0x7e7>
    5e32:	e8 24 6b 00 00       	callq  c95b <abort>
    5e37:	e8 1f 6b 00 00       	callq  c95b <abort>
    5e3c:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5e43:	48 89 45 88          	mov    %rax,-0x78(%rbp)
    5e47:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    5e4b:	48 8b 40 30          	mov    0x30(%rax),%rax
    5e4f:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    5e53:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    5e57:	48 8b 40 18          	mov    0x18(%rax),%rax
    5e5b:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    5e5f:	0f 84 9e 00 00 00    	je     5f03 <prepend_alloc+0x53f>
    5e65:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    5e69:	48 8b 40 10          	mov    0x10(%rax),%rax
    5e6d:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    5e71:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    5e75:	48 8b 40 18          	mov    0x18(%rax),%rax
    5e79:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
    5e80:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5e87:	48 8b 40 18          	mov    0x18(%rax),%rax
    5e8b:	48 39 45 98          	cmp    %rax,-0x68(%rbp)
    5e8f:	0f 93 c0             	setae  %al
    5e92:	0f b6 c0             	movzbl %al,%eax
    5e95:	48 85 c0             	test   %rax,%rax
    5e98:	74 1e                	je     5eb8 <prepend_alloc+0x4f4>
    5e9a:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    5e9e:	48 8b 40 18          	mov    0x18(%rax),%rax
    5ea2:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    5ea6:	0f 94 c0             	sete   %al
    5ea9:	0f b6 c0             	movzbl %al,%eax
    5eac:	48 85 c0             	test   %rax,%rax
    5eaf:	74 07                	je     5eb8 <prepend_alloc+0x4f4>
    5eb1:	b8 01 00 00 00       	mov    $0x1,%eax
    5eb6:	eb 05                	jmp    5ebd <prepend_alloc+0x4f9>
    5eb8:	b8 00 00 00 00       	mov    $0x0,%eax
    5ebd:	85 c0                	test   %eax,%eax
    5ebf:	74 3d                	je     5efe <prepend_alloc+0x53a>
    5ec1:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    5ec8:	48 8b 40 10          	mov    0x10(%rax),%rax
    5ecc:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    5ed0:	0f 94 c0             	sete   %al
    5ed3:	0f b6 c0             	movzbl %al,%eax
    5ed6:	48 85 c0             	test   %rax,%rax
    5ed9:	74 23                	je     5efe <prepend_alloc+0x53a>
    5edb:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    5edf:	48 8b 95 38 ff ff ff 	mov    -0xc8(%rbp),%rdx
    5ee6:	48 89 50 18          	mov    %rdx,0x18(%rax)
    5eea:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    5ef1:	48 8b 55 98          	mov    -0x68(%rbp),%rdx
    5ef5:	48 89 50 10          	mov    %rdx,0x10(%rax)
    5ef9:	e9 f2 00 00 00       	jmpq   5ff0 <prepend_alloc+0x62c>
    5efe:	e8 58 6a 00 00       	callq  c95b <abort>
    5f03:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    5f07:	48 83 c0 28          	add    $0x28,%rax
    5f0b:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
    5f12:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    5f19:	48 8b 00             	mov    (%rax),%rax
    5f1c:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
    5f23:	48 83 bd 38 ff ff ff 	cmpq   $0x0,-0xc8(%rbp)
    5f2a:	00 
    5f2b:	75 4f                	jne    5f7c <prepend_alloc+0x5b8>
    5f2d:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    5f31:	48 83 c0 20          	add    $0x20,%rax
    5f35:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
    5f3c:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    5f43:	48 8b 00             	mov    (%rax),%rax
    5f46:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
    5f4d:	48 83 bd 38 ff ff ff 	cmpq   $0x0,-0xc8(%rbp)
    5f54:	00 
    5f55:	0f 84 95 00 00 00    	je     5ff0 <prepend_alloc+0x62c>
    5f5b:	eb 1f                	jmp    5f7c <prepend_alloc+0x5b8>
    5f5d:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    5f64:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
    5f6b:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    5f72:	48 8b 00             	mov    (%rax),%rax
    5f75:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
    5f7c:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    5f83:	48 83 c0 28          	add    $0x28,%rax
    5f87:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    5f8e:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    5f95:	48 8b 00             	mov    (%rax),%rax
    5f98:	48 85 c0             	test   %rax,%rax
    5f9b:	75 c0                	jne    5f5d <prepend_alloc+0x599>
    5f9d:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    5fa4:	48 83 c0 20          	add    $0x20,%rax
    5fa8:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    5faf:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    5fb6:	48 8b 00             	mov    (%rax),%rax
    5fb9:	48 85 c0             	test   %rax,%rax
    5fbc:	75 9f                	jne    5f5d <prepend_alloc+0x599>
    5fbe:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5fc5:	48 8b 40 18          	mov    0x18(%rax),%rax
    5fc9:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    5fd0:	0f 93 c0             	setae  %al
    5fd3:	0f b6 c0             	movzbl %al,%eax
    5fd6:	48 85 c0             	test   %rax,%rax
    5fd9:	74 10                	je     5feb <prepend_alloc+0x627>
    5fdb:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    5fe2:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    5fe9:	eb 05                	jmp    5ff0 <prepend_alloc+0x62c>
    5feb:	e8 6b 69 00 00       	callq  c95b <abort>
    5ff0:	48 83 7d 90 00       	cmpq   $0x0,-0x70(%rbp)
    5ff5:	0f 84 b0 01 00 00    	je     61ab <prepend_alloc+0x7e7>
    5ffb:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    5fff:	8b 40 38             	mov    0x38(%rax),%eax
    6002:	89 c0                	mov    %eax,%eax
    6004:	48 83 c0 4a          	add    $0x4a,%rax
    6008:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    600f:	00 
    6010:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6017:	48 01 d0             	add    %rdx,%rax
    601a:	48 83 c0 08          	add    $0x8,%rax
    601e:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
    6022:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    6026:	48 8b 00             	mov    (%rax),%rax
    6029:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    602d:	75 46                	jne    6075 <prepend_alloc+0x6b1>
    602f:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    6033:	48 8b 95 38 ff ff ff 	mov    -0xc8(%rbp),%rdx
    603a:	48 89 10             	mov    %rdx,(%rax)
    603d:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    6041:	48 8b 00             	mov    (%rax),%rax
    6044:	48 85 c0             	test   %rax,%rax
    6047:	75 7b                	jne    60c4 <prepend_alloc+0x700>
    6049:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6050:	8b 50 04             	mov    0x4(%rax),%edx
    6053:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    6057:	8b 40 38             	mov    0x38(%rax),%eax
    605a:	be 01 00 00 00       	mov    $0x1,%esi
    605f:	89 c1                	mov    %eax,%ecx
    6061:	d3 e6                	shl    %cl,%esi
    6063:	89 f0                	mov    %esi,%eax
    6065:	f7 d0                	not    %eax
    6067:	21 c2                	and    %eax,%edx
    6069:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6070:	89 50 04             	mov    %edx,0x4(%rax)
    6073:	eb 4f                	jmp    60c4 <prepend_alloc+0x700>
    6075:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    607c:	48 8b 40 18          	mov    0x18(%rax),%rax
    6080:	48 39 45 90          	cmp    %rax,-0x70(%rbp)
    6084:	0f 93 c0             	setae  %al
    6087:	0f b6 c0             	movzbl %al,%eax
    608a:	48 85 c0             	test   %rax,%rax
    608d:	74 30                	je     60bf <prepend_alloc+0x6fb>
    608f:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    6093:	48 8b 40 20          	mov    0x20(%rax),%rax
    6097:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    609b:	75 11                	jne    60ae <prepend_alloc+0x6ea>
    609d:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    60a1:	48 8b 95 38 ff ff ff 	mov    -0xc8(%rbp),%rdx
    60a8:	48 89 50 20          	mov    %rdx,0x20(%rax)
    60ac:	eb 16                	jmp    60c4 <prepend_alloc+0x700>
    60ae:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    60b2:	48 8b 95 38 ff ff ff 	mov    -0xc8(%rbp),%rdx
    60b9:	48 89 50 28          	mov    %rdx,0x28(%rax)
    60bd:	eb 05                	jmp    60c4 <prepend_alloc+0x700>
    60bf:	e8 97 68 00 00       	callq  c95b <abort>
    60c4:	48 83 bd 38 ff ff ff 	cmpq   $0x0,-0xc8(%rbp)
    60cb:	00 
    60cc:	0f 84 d9 00 00 00    	je     61ab <prepend_alloc+0x7e7>
    60d2:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    60d9:	48 8b 40 18          	mov    0x18(%rax),%rax
    60dd:	48 39 85 38 ff ff ff 	cmp    %rax,-0xc8(%rbp)
    60e4:	0f 93 c0             	setae  %al
    60e7:	0f b6 c0             	movzbl %al,%eax
    60ea:	48 85 c0             	test   %rax,%rax
    60ed:	0f 84 b3 00 00 00    	je     61a6 <prepend_alloc+0x7e2>
    60f3:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    60fa:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    60fe:	48 89 50 30          	mov    %rdx,0x30(%rax)
    6102:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    6106:	48 8b 40 20          	mov    0x20(%rax),%rax
    610a:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    610e:	48 83 7d a8 00       	cmpq   $0x0,-0x58(%rbp)
    6113:	74 3f                	je     6154 <prepend_alloc+0x790>
    6115:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    611c:	48 8b 40 18          	mov    0x18(%rax),%rax
    6120:	48 39 45 a8          	cmp    %rax,-0x58(%rbp)
    6124:	0f 93 c0             	setae  %al
    6127:	0f b6 c0             	movzbl %al,%eax
    612a:	48 85 c0             	test   %rax,%rax
    612d:	74 20                	je     614f <prepend_alloc+0x78b>
    612f:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    6136:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    613a:	48 89 50 20          	mov    %rdx,0x20(%rax)
    613e:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    6142:	48 8b 95 38 ff ff ff 	mov    -0xc8(%rbp),%rdx
    6149:	48 89 50 30          	mov    %rdx,0x30(%rax)
    614d:	eb 05                	jmp    6154 <prepend_alloc+0x790>
    614f:	e8 07 68 00 00       	callq  c95b <abort>
    6154:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    6158:	48 8b 40 28          	mov    0x28(%rax),%rax
    615c:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    6160:	48 83 7d b0 00       	cmpq   $0x0,-0x50(%rbp)
    6165:	74 44                	je     61ab <prepend_alloc+0x7e7>
    6167:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    616e:	48 8b 40 18          	mov    0x18(%rax),%rax
    6172:	48 39 45 b0          	cmp    %rax,-0x50(%rbp)
    6176:	0f 93 c0             	setae  %al
    6179:	0f b6 c0             	movzbl %al,%eax
    617c:	48 85 c0             	test   %rax,%rax
    617f:	74 20                	je     61a1 <prepend_alloc+0x7dd>
    6181:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    6188:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    618c:	48 89 50 28          	mov    %rdx,0x28(%rax)
    6190:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    6194:	48 8b 95 38 ff ff ff 	mov    -0xc8(%rbp),%rdx
    619b:	48 89 50 30          	mov    %rdx,0x30(%rax)
    619f:	eb 0a                	jmp    61ab <prepend_alloc+0x7e7>
    61a1:	e8 b5 67 00 00       	callq  c95b <abort>
    61a6:	e8 b0 67 00 00       	callq  c95b <abort>
      oldfirst = chunk_plus_offset(oldfirst, nsize);
    61ab:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    61af:	48 01 85 28 ff ff ff 	add    %rax,-0xd8(%rbp)
      qsize += nsize;
    61b6:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    61ba:	48 01 85 30 ff ff ff 	add    %rax,-0xd0(%rbp)
    }
    set_free_with_pinuse(q, qsize, oldfirst);
    61c1:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    61c8:	48 8b 40 08          	mov    0x8(%rax),%rax
    61cc:	48 83 e0 fe          	and    $0xfffffffffffffffe,%rax
    61d0:	48 89 c2             	mov    %rax,%rdx
    61d3:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    61da:	48 89 50 08          	mov    %rdx,0x8(%rax)
    61de:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    61e5:	48 83 c8 01          	or     $0x1,%rax
    61e9:	48 89 c2             	mov    %rax,%rdx
    61ec:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    61f3:	48 89 50 08          	mov    %rdx,0x8(%rax)
    61f7:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    61fe:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    6205:	48 01 c2             	add    %rax,%rdx
    6208:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    620f:	48 89 02             	mov    %rax,(%rdx)
    insert_chunk(m, q, qsize);
    6212:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    6219:	48 c1 e8 03          	shr    $0x3,%rax
    621d:	48 83 f8 1f          	cmp    $0x1f,%rax
    6221:	0f 87 18 01 00 00    	ja     633f <prepend_alloc+0x97b>
    6227:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    622e:	48 c1 e8 03          	shr    $0x3,%rax
    6232:	89 85 24 ff ff ff    	mov    %eax,-0xdc(%rbp)
    6238:	8b 85 24 ff ff ff    	mov    -0xdc(%rbp),%eax
    623e:	01 c0                	add    %eax,%eax
    6240:	89 c0                	mov    %eax,%eax
    6242:	48 83 c0 08          	add    $0x8,%rax
    6246:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    624d:	00 
    624e:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6255:	48 01 d0             	add    %rdx,%rax
    6258:	48 83 c0 08          	add    $0x8,%rax
    625c:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    6260:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    6264:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    626b:	48 83 bd 30 ff ff ff 	cmpq   $0x1f,-0xd0(%rbp)
    6272:	1f 
    6273:	77 05                	ja     627a <prepend_alloc+0x8b6>
    6275:	e8 e1 66 00 00       	callq  c95b <abort>
    627a:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6281:	8b 10                	mov    (%rax),%edx
    6283:	8b 85 24 ff ff ff    	mov    -0xdc(%rbp),%eax
    6289:	be 01 00 00 00       	mov    $0x1,%esi
    628e:	89 c1                	mov    %eax,%ecx
    6290:	d3 e6                	shl    %cl,%esi
    6292:	89 f0                	mov    %esi,%eax
    6294:	21 d0                	and    %edx,%eax
    6296:	85 c0                	test   %eax,%eax
    6298:	75 27                	jne    62c1 <prepend_alloc+0x8fd>
    629a:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    62a1:	8b 10                	mov    (%rax),%edx
    62a3:	8b 85 24 ff ff ff    	mov    -0xdc(%rbp),%eax
    62a9:	be 01 00 00 00       	mov    $0x1,%esi
    62ae:	89 c1                	mov    %eax,%ecx
    62b0:	d3 e6                	shl    %cl,%esi
    62b2:	89 f0                	mov    %esi,%eax
    62b4:	09 c2                	or     %eax,%edx
    62b6:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    62bd:	89 10                	mov    %edx,(%rax)
    62bf:	eb 37                	jmp    62f8 <prepend_alloc+0x934>
    62c1:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    62c5:	48 8b 50 10          	mov    0x10(%rax),%rdx
    62c9:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    62d0:	48 8b 40 18          	mov    0x18(%rax),%rax
    62d4:	48 39 c2             	cmp    %rax,%rdx
    62d7:	0f 93 c0             	setae  %al
    62da:	0f b6 c0             	movzbl %al,%eax
    62dd:	48 85 c0             	test   %rax,%rax
    62e0:	74 11                	je     62f3 <prepend_alloc+0x92f>
    62e2:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    62e6:	48 8b 40 10          	mov    0x10(%rax),%rax
    62ea:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    62f1:	eb 05                	jmp    62f8 <prepend_alloc+0x934>
    62f3:	e8 63 66 00 00       	callq  c95b <abort>
    62f8:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    62fc:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    6303:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6307:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    630e:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    6315:	48 89 50 18          	mov    %rdx,0x18(%rax)
    6319:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    6320:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    6327:	48 89 50 10          	mov    %rdx,0x10(%rax)
    632b:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    6332:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    6336:	48 89 50 18          	mov    %rdx,0x18(%rax)
    633a:	e9 f1 02 00 00       	jmpq   6630 <prepend_alloc+0xc6c>
    633f:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    6346:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    634a:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    6351:	48 c1 e8 08          	shr    $0x8,%rax
    6355:	89 85 1c ff ff ff    	mov    %eax,-0xe4(%rbp)
    635b:	83 bd 1c ff ff ff 00 	cmpl   $0x0,-0xe4(%rbp)
    6362:	75 0c                	jne    6370 <prepend_alloc+0x9ac>
    6364:	c7 85 14 ff ff ff 00 	movl   $0x0,-0xec(%rbp)
    636b:	00 00 00 
    636e:	eb 5d                	jmp    63cd <prepend_alloc+0xa09>
    6370:	81 bd 1c ff ff ff ff 	cmpl   $0xffff,-0xe4(%rbp)
    6377:	ff 00 00 
    637a:	76 0c                	jbe    6388 <prepend_alloc+0x9c4>
    637c:	c7 85 14 ff ff ff 1f 	movl   $0x1f,-0xec(%rbp)
    6383:	00 00 00 
    6386:	eb 45                	jmp    63cd <prepend_alloc+0xa09>
    6388:	0f bd 85 1c ff ff ff 	bsr    -0xe4(%rbp),%eax
    638f:	83 f0 1f             	xor    $0x1f,%eax
    6392:	ba 1f 00 00 00       	mov    $0x1f,%edx
    6397:	29 c2                	sub    %eax,%edx
    6399:	89 d0                	mov    %edx,%eax
    639b:	89 85 20 ff ff ff    	mov    %eax,-0xe0(%rbp)
    63a1:	8b 85 20 ff ff ff    	mov    -0xe0(%rbp),%eax
    63a7:	8d 34 00             	lea    (%rax,%rax,1),%esi
    63aa:	8b 85 20 ff ff ff    	mov    -0xe0(%rbp),%eax
    63b0:	83 c0 07             	add    $0x7,%eax
    63b3:	48 8b 95 30 ff ff ff 	mov    -0xd0(%rbp),%rdx
    63ba:	89 c1                	mov    %eax,%ecx
    63bc:	48 d3 ea             	shr    %cl,%rdx
    63bf:	48 89 d0             	mov    %rdx,%rax
    63c2:	83 e0 01             	and    $0x1,%eax
    63c5:	01 f0                	add    %esi,%eax
    63c7:	89 85 14 ff ff ff    	mov    %eax,-0xec(%rbp)
    63cd:	8b 85 14 ff ff ff    	mov    -0xec(%rbp),%eax
    63d3:	48 83 c0 4a          	add    $0x4a,%rax
    63d7:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    63de:	00 
    63df:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    63e6:	48 01 d0             	add    %rdx,%rax
    63e9:	48 83 c0 08          	add    $0x8,%rax
    63ed:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    63f1:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    63f5:	8b 95 14 ff ff ff    	mov    -0xec(%rbp),%edx
    63fb:	89 50 38             	mov    %edx,0x38(%rax)
    63fe:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6402:	48 c7 40 28 00 00 00 	movq   $0x0,0x28(%rax)
    6409:	00 
    640a:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    640e:	48 8b 50 28          	mov    0x28(%rax),%rdx
    6412:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6416:	48 89 50 20          	mov    %rdx,0x20(%rax)
    641a:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6421:	8b 50 04             	mov    0x4(%rax),%edx
    6424:	8b 85 14 ff ff ff    	mov    -0xec(%rbp),%eax
    642a:	be 01 00 00 00       	mov    $0x1,%esi
    642f:	89 c1                	mov    %eax,%ecx
    6431:	d3 e6                	shl    %cl,%esi
    6433:	89 f0                	mov    %esi,%eax
    6435:	21 d0                	and    %edx,%eax
    6437:	85 c0                	test   %eax,%eax
    6439:	75 5f                	jne    649a <prepend_alloc+0xad6>
    643b:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6442:	8b 50 04             	mov    0x4(%rax),%edx
    6445:	8b 85 14 ff ff ff    	mov    -0xec(%rbp),%eax
    644b:	be 01 00 00 00       	mov    $0x1,%esi
    6450:	89 c1                	mov    %eax,%ecx
    6452:	d3 e6                	shl    %cl,%esi
    6454:	89 f0                	mov    %esi,%eax
    6456:	09 c2                	or     %eax,%edx
    6458:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    645f:	89 50 04             	mov    %edx,0x4(%rax)
    6462:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    6466:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    646a:	48 89 10             	mov    %rdx,(%rax)
    646d:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6471:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    6475:	48 89 50 30          	mov    %rdx,0x30(%rax)
    6479:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    647d:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    6481:	48 89 50 18          	mov    %rdx,0x18(%rax)
    6485:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6489:	48 8b 50 18          	mov    0x18(%rax),%rdx
    648d:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6491:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6495:	e9 96 01 00 00       	jmpq   6630 <prepend_alloc+0xc6c>
    649a:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    649e:	48 8b 00             	mov    (%rax),%rax
    64a1:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
    64a8:	83 bd 14 ff ff ff 1f 	cmpl   $0x1f,-0xec(%rbp)
    64af:	74 13                	je     64c4 <prepend_alloc+0xb00>
    64b1:	8b 85 14 ff ff ff    	mov    -0xec(%rbp),%eax
    64b7:	d1 e8                	shr    %eax
    64b9:	ba 39 00 00 00       	mov    $0x39,%edx
    64be:	29 c2                	sub    %eax,%edx
    64c0:	89 d0                	mov    %edx,%eax
    64c2:	eb 05                	jmp    64c9 <prepend_alloc+0xb05>
    64c4:	b8 00 00 00 00       	mov    $0x0,%eax
    64c9:	48 8b 95 30 ff ff ff 	mov    -0xd0(%rbp),%rdx
    64d0:	89 c1                	mov    %eax,%ecx
    64d2:	48 d3 e2             	shl    %cl,%rdx
    64d5:	48 89 d0             	mov    %rdx,%rax
    64d8:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
    64df:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    64e6:	48 8b 40 08          	mov    0x8(%rax),%rax
    64ea:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    64ee:	48 39 85 30 ff ff ff 	cmp    %rax,-0xd0(%rbp)
    64f5:	0f 84 a2 00 00 00    	je     659d <prepend_alloc+0xbd9>
    64fb:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    6502:	48 c1 e8 3f          	shr    $0x3f,%rax
    6506:	48 83 c0 04          	add    $0x4,%rax
    650a:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    6511:	00 
    6512:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    6519:	48 01 d0             	add    %rdx,%rax
    651c:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    6520:	48 d1 a5 60 ff ff ff 	shlq   -0xa0(%rbp)
    6527:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    652b:	48 8b 00             	mov    (%rax),%rax
    652e:	48 85 c0             	test   %rax,%rax
    6531:	74 10                	je     6543 <prepend_alloc+0xb7f>
    6533:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    6537:	48 8b 00             	mov    (%rax),%rax
    653a:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
    6541:	eb 9c                	jmp    64df <prepend_alloc+0xb1b>
    6543:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    654a:	48 8b 40 18          	mov    0x18(%rax),%rax
    654e:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    6552:	0f 93 c0             	setae  %al
    6555:	0f b6 c0             	movzbl %al,%eax
    6558:	48 85 c0             	test   %rax,%rax
    655b:	74 3b                	je     6598 <prepend_alloc+0xbd4>
    655d:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    6561:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    6565:	48 89 10             	mov    %rdx,(%rax)
    6568:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    656c:	48 8b 95 58 ff ff ff 	mov    -0xa8(%rbp),%rdx
    6573:	48 89 50 30          	mov    %rdx,0x30(%rax)
    6577:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    657b:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    657f:	48 89 50 18          	mov    %rdx,0x18(%rax)
    6583:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6587:	48 8b 50 18          	mov    0x18(%rax),%rdx
    658b:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    658f:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6593:	e9 98 00 00 00       	jmpq   6630 <prepend_alloc+0xc6c>
    6598:	e8 be 63 00 00       	callq  c95b <abort>
    659d:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    65a4:	48 8b 40 10          	mov    0x10(%rax),%rax
    65a8:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    65ac:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    65b3:	48 8b 40 18          	mov    0x18(%rax),%rax
    65b7:	48 39 85 58 ff ff ff 	cmp    %rax,-0xa8(%rbp)
    65be:	0f 93 c0             	setae  %al
    65c1:	0f b6 c0             	movzbl %al,%eax
    65c4:	48 85 c0             	test   %rax,%rax
    65c7:	74 62                	je     662b <prepend_alloc+0xc67>
    65c9:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    65d0:	48 8b 40 18          	mov    0x18(%rax),%rax
    65d4:	48 39 45 d8          	cmp    %rax,-0x28(%rbp)
    65d8:	0f 93 c0             	setae  %al
    65db:	0f b6 c0             	movzbl %al,%eax
    65de:	48 85 c0             	test   %rax,%rax
    65e1:	74 48                	je     662b <prepend_alloc+0xc67>
    65e3:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    65e7:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    65eb:	48 89 50 18          	mov    %rdx,0x18(%rax)
    65ef:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    65f3:	48 8b 50 18          	mov    0x18(%rax),%rdx
    65f7:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    65fe:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6602:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6606:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    660a:	48 89 50 10          	mov    %rdx,0x10(%rax)
    660e:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6612:	48 8b 95 58 ff ff ff 	mov    -0xa8(%rbp),%rdx
    6619:	48 89 50 18          	mov    %rdx,0x18(%rax)
    661d:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6621:	48 c7 40 30 00 00 00 	movq   $0x0,0x30(%rax)
    6628:	00 
    6629:	eb 05                	jmp    6630 <prepend_alloc+0xc6c>
    662b:	e8 2b 63 00 00       	callq  c95b <abort>
    check_free_chunk(m, q);
    6630:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    6637:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    663e:	48 89 d6             	mov    %rdx,%rsi
    6641:	48 89 c7             	mov    %rax,%rdi
    6644:	e8 79 f0 ff ff       	callq  56c2 <do_check_free_chunk>
  }

  check_malloced_chunk(m, chunk2mem(p), nb);
    6649:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    6650:	48 8d 48 10          	lea    0x10(%rax),%rcx
    6654:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    665b:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6662:	48 89 ce             	mov    %rcx,%rsi
    6665:	48 89 c7             	mov    %rax,%rdi
    6668:	e8 c6 f1 ff ff       	callq  5833 <do_check_malloced_chunk>
  return chunk2mem(p);
    666d:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    6674:	48 83 c0 10          	add    $0x10,%rax
}
    6678:	c9                   	leaveq 
    6679:	c3                   	retq   

000000000000667a <add_segment>:

/* Add a segment to hold a new noncontiguous region */
static void add_segment(mstate m, char* tbase, size_t tsize, flag_t mmapped) {
    667a:	55                   	push   %rbp
    667b:	48 89 e5             	mov    %rsp,%rbp
    667e:	48 81 ec 00 01 00 00 	sub    $0x100,%rsp
    6685:	48 89 bd 18 ff ff ff 	mov    %rdi,-0xe8(%rbp)
    668c:	48 89 b5 10 ff ff ff 	mov    %rsi,-0xf0(%rbp)
    6693:	48 89 95 08 ff ff ff 	mov    %rdx,-0xf8(%rbp)
    669a:	89 8d 04 ff ff ff    	mov    %ecx,-0xfc(%rbp)
  /* Determine locations and sizes of segment, fenceposts, old top */
  char* old_top = (char*)m->top;
    66a0:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    66a7:	48 8b 40 28          	mov    0x28(%rax),%rax
    66ab:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
  msegmentptr oldsp = segment_holding(m, old_top);
    66b2:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    66b9:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    66c0:	48 89 d6             	mov    %rdx,%rsi
    66c3:	48 89 c7             	mov    %rax,%rdi
    66c6:	e8 f6 eb ff ff       	callq  52c1 <segment_holding>
    66cb:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
  char* old_end = oldsp->base + oldsp->size;
    66d2:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    66d9:	48 8b 10             	mov    (%rax),%rdx
    66dc:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    66e3:	48 8b 40 08          	mov    0x8(%rax),%rax
    66e7:	48 01 d0             	add    %rdx,%rax
    66ea:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
  size_t ssize = pad_request(sizeof(struct malloc_segment));
    66f1:	48 c7 85 78 ff ff ff 	movq   $0x30,-0x88(%rbp)
    66f8:	30 00 00 00 
  char* rawsp = old_end - (ssize + FOUR_SIZE_T_SIZES + CHUNK_ALIGN_MASK);
    66fc:	48 c7 c0 d1 ff ff ff 	mov    $0xffffffffffffffd1,%rax
    6703:	48 2b 85 78 ff ff ff 	sub    -0x88(%rbp),%rax
    670a:	48 89 c2             	mov    %rax,%rdx
    670d:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    6714:	48 01 d0             	add    %rdx,%rax
    6717:	48 89 45 80          	mov    %rax,-0x80(%rbp)
  size_t offset = align_offset(chunk2mem(rawsp));
    671b:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    671f:	48 83 c0 10          	add    $0x10,%rax
    6723:	83 e0 0f             	and    $0xf,%eax
    6726:	48 85 c0             	test   %rax,%rax
    6729:	74 10                	je     673b <add_segment+0xc1>
    672b:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    672f:	48 83 c0 10          	add    $0x10,%rax
    6733:	48 f7 d8             	neg    %rax
    6736:	83 e0 0f             	and    $0xf,%eax
    6739:	eb 05                	jmp    6740 <add_segment+0xc6>
    673b:	b8 00 00 00 00       	mov    $0x0,%eax
    6740:	48 89 45 88          	mov    %rax,-0x78(%rbp)
  char* asp = rawsp + offset;
    6744:	48 8b 55 80          	mov    -0x80(%rbp),%rdx
    6748:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    674c:	48 01 d0             	add    %rdx,%rax
    674f:	48 89 45 90          	mov    %rax,-0x70(%rbp)
  char* csp = (asp < (old_top + MIN_CHUNK_SIZE))? old_top : asp;
    6753:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    675a:	48 83 c0 20          	add    $0x20,%rax
    675e:	48 39 45 90          	cmp    %rax,-0x70(%rbp)
    6762:	73 09                	jae    676d <add_segment+0xf3>
    6764:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    676b:	eb 04                	jmp    6771 <add_segment+0xf7>
    676d:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    6771:	48 89 45 98          	mov    %rax,-0x68(%rbp)
  mchunkptr sp = (mchunkptr)csp;
    6775:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    6779:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
  msegmentptr ss = (msegmentptr)(chunk2mem(sp));
    677d:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    6781:	48 83 c0 10          	add    $0x10,%rax
    6785:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
  mchunkptr tnext = chunk_plus_offset(sp, ssize);
    6789:	48 8b 55 a0          	mov    -0x60(%rbp),%rdx
    678d:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    6794:	48 01 d0             	add    %rdx,%rax
    6797:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
  mchunkptr p = tnext;
    679b:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    679f:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
  int nfences = 0;
    67a6:	c7 85 2c ff ff ff 00 	movl   $0x0,-0xd4(%rbp)
    67ad:	00 00 00 

  /* reset top to new space */
  init_top(m, (mchunkptr)tbase, tsize - TOP_FOOT_SIZE);
    67b0:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    67b7:	48 8d 50 b0          	lea    -0x50(%rax),%rdx
    67bb:	48 8b 8d 10 ff ff ff 	mov    -0xf0(%rbp),%rcx
    67c2:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    67c9:	48 89 ce             	mov    %rcx,%rsi
    67cc:	48 89 c7             	mov    %rax,%rdi
    67cf:	e8 fb f0 ff ff       	callq  58cf <init_top>

  /* Set up segment record */
  assert(is_aligned(ss));
    67d4:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    67d8:	83 e0 0f             	and    $0xf,%eax
    67db:	48 85 c0             	test   %rax,%rax
    67de:	74 05                	je     67e5 <add_segment+0x16b>
    67e0:	e8 76 61 00 00       	callq  c95b <abort>
  set_size_and_pinuse_of_inuse_chunk(m, sp, ssize);
    67e5:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    67ec:	48 83 c8 03          	or     $0x3,%rax
    67f0:	48 89 c2             	mov    %rax,%rdx
    67f3:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    67f7:	48 89 50 08          	mov    %rdx,0x8(%rax)
    67fb:	48 8b 0d 1e a9 00 00 	mov    0xa91e(%rip),%rcx        # 11120 <mparams>
    6802:	48 8b 95 18 ff ff ff 	mov    -0xe8(%rbp),%rdx
    6809:	48 8b 75 a0          	mov    -0x60(%rbp),%rsi
    680d:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    6814:	48 01 f0             	add    %rsi,%rax
    6817:	48 31 ca             	xor    %rcx,%rdx
    681a:	48 89 10             	mov    %rdx,(%rax)
  *ss = m->seg; /* Push current record */
    681d:	48 8b 4d a8          	mov    -0x58(%rbp),%rcx
    6821:	48 8b b5 18 ff ff ff 	mov    -0xe8(%rbp),%rsi
    6828:	48 8b 86 78 03 00 00 	mov    0x378(%rsi),%rax
    682f:	48 8b 96 80 03 00 00 	mov    0x380(%rsi),%rdx
    6836:	48 89 01             	mov    %rax,(%rcx)
    6839:	48 89 51 08          	mov    %rdx,0x8(%rcx)
    683d:	48 8b 86 88 03 00 00 	mov    0x388(%rsi),%rax
    6844:	48 8b 96 90 03 00 00 	mov    0x390(%rsi),%rdx
    684b:	48 89 41 10          	mov    %rax,0x10(%rcx)
    684f:	48 89 51 18          	mov    %rdx,0x18(%rcx)
  m->seg.base = tbase;
    6853:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    685a:	48 8b 95 10 ff ff ff 	mov    -0xf0(%rbp),%rdx
    6861:	48 89 90 78 03 00 00 	mov    %rdx,0x378(%rax)
  m->seg.size = tsize;
    6868:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    686f:	48 8b 95 08 ff ff ff 	mov    -0xf8(%rbp),%rdx
    6876:	48 89 90 80 03 00 00 	mov    %rdx,0x380(%rax)
  m->seg.sflags = mmapped;
    687d:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6884:	8b 95 04 ff ff ff    	mov    -0xfc(%rbp),%edx
    688a:	89 90 90 03 00 00    	mov    %edx,0x390(%rax)
  m->seg.next = ss;
    6890:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6897:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    689b:	48 89 90 88 03 00 00 	mov    %rdx,0x388(%rax)

  /* Insert trailing fenceposts */
  for (;;) {
    mchunkptr nextp = chunk_plus_offset(p, SIZE_T_SIZE);
    68a2:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    68a9:	48 83 c0 08          	add    $0x8,%rax
    68ad:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    p->head = FENCEPOST_HEAD;
    68b1:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    68b8:	48 c7 40 08 0b 00 00 	movq   $0xb,0x8(%rax)
    68bf:	00 
    ++nfences;
    68c0:	83 85 2c ff ff ff 01 	addl   $0x1,-0xd4(%rbp)
    if ((char*)(&(nextp->head)) < old_end)
    68c7:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    68cb:	48 83 c0 08          	add    $0x8,%rax
    68cf:	48 39 85 70 ff ff ff 	cmp    %rax,-0x90(%rbp)
    68d6:	76 0d                	jbe    68e5 <add_segment+0x26b>
      p = nextp;
    68d8:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    68dc:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
  for (;;) {
    68e3:	eb bd                	jmp    68a2 <add_segment+0x228>
    else
      break;
    68e5:	90                   	nop
  }
  assert(nfences >= 2);
    68e6:	83 bd 2c ff ff ff 01 	cmpl   $0x1,-0xd4(%rbp)
    68ed:	7f 05                	jg     68f4 <add_segment+0x27a>
    68ef:	e8 67 60 00 00       	callq  c95b <abort>

  /* Insert the rest of old top into a bin as an ordinary free chunk */
  if (csp != old_top) {
    68f4:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    68f8:	48 3b 85 60 ff ff ff 	cmp    -0xa0(%rbp),%rax
    68ff:	0f 84 65 04 00 00    	je     6d6a <add_segment+0x6f0>
    mchunkptr q = (mchunkptr)old_top;
    6905:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    690c:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    size_t psize = csp - old_top;
    6910:	48 8b 55 98          	mov    -0x68(%rbp),%rdx
    6914:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    691b:	48 29 c2             	sub    %rax,%rdx
    691e:	48 89 d0             	mov    %rdx,%rax
    6921:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    mchunkptr tn = chunk_plus_offset(q, psize);
    6925:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    6929:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    692d:	48 01 d0             	add    %rdx,%rax
    6930:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    set_free_with_pinuse(q, psize, tn);
    6934:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    6938:	48 8b 40 08          	mov    0x8(%rax),%rax
    693c:	48 83 e0 fe          	and    $0xfffffffffffffffe,%rax
    6940:	48 89 c2             	mov    %rax,%rdx
    6943:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    6947:	48 89 50 08          	mov    %rdx,0x8(%rax)
    694b:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    694f:	48 83 c8 01          	or     $0x1,%rax
    6953:	48 89 c2             	mov    %rax,%rdx
    6956:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    695a:	48 89 50 08          	mov    %rdx,0x8(%rax)
    695e:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    6962:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6966:	48 01 c2             	add    %rax,%rdx
    6969:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    696d:	48 89 02             	mov    %rax,(%rdx)
    insert_chunk(m, q, psize);
    6970:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6974:	48 c1 e8 03          	shr    $0x3,%rax
    6978:	48 83 f8 1f          	cmp    $0x1f,%rax
    697c:	0f 87 06 01 00 00    	ja     6a88 <add_segment+0x40e>
    6982:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6986:	48 c1 e8 03          	shr    $0x3,%rax
    698a:	89 85 3c ff ff ff    	mov    %eax,-0xc4(%rbp)
    6990:	8b 85 3c ff ff ff    	mov    -0xc4(%rbp),%eax
    6996:	01 c0                	add    %eax,%eax
    6998:	89 c0                	mov    %eax,%eax
    699a:	48 83 c0 08          	add    $0x8,%rax
    699e:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    69a5:	00 
    69a6:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    69ad:	48 01 d0             	add    %rdx,%rax
    69b0:	48 83 c0 08          	add    $0x8,%rax
    69b4:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    69b8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    69bc:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    69c3:	48 83 7d c8 1f       	cmpq   $0x1f,-0x38(%rbp)
    69c8:	77 05                	ja     69cf <add_segment+0x355>
    69ca:	e8 8c 5f 00 00       	callq  c95b <abort>
    69cf:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    69d6:	8b 10                	mov    (%rax),%edx
    69d8:	8b 85 3c ff ff ff    	mov    -0xc4(%rbp),%eax
    69de:	be 01 00 00 00       	mov    $0x1,%esi
    69e3:	89 c1                	mov    %eax,%ecx
    69e5:	d3 e6                	shl    %cl,%esi
    69e7:	89 f0                	mov    %esi,%eax
    69e9:	21 d0                	and    %edx,%eax
    69eb:	85 c0                	test   %eax,%eax
    69ed:	75 27                	jne    6a16 <add_segment+0x39c>
    69ef:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    69f6:	8b 10                	mov    (%rax),%edx
    69f8:	8b 85 3c ff ff ff    	mov    -0xc4(%rbp),%eax
    69fe:	be 01 00 00 00       	mov    $0x1,%esi
    6a03:	89 c1                	mov    %eax,%ecx
    6a05:	d3 e6                	shl    %cl,%esi
    6a07:	89 f0                	mov    %esi,%eax
    6a09:	09 c2                	or     %eax,%edx
    6a0b:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6a12:	89 10                	mov    %edx,(%rax)
    6a14:	eb 37                	jmp    6a4d <add_segment+0x3d3>
    6a16:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    6a1a:	48 8b 50 10          	mov    0x10(%rax),%rdx
    6a1e:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6a25:	48 8b 40 18          	mov    0x18(%rax),%rax
    6a29:	48 39 c2             	cmp    %rax,%rdx
    6a2c:	0f 93 c0             	setae  %al
    6a2f:	0f b6 c0             	movzbl %al,%eax
    6a32:	48 85 c0             	test   %rax,%rax
    6a35:	74 11                	je     6a48 <add_segment+0x3ce>
    6a37:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    6a3b:	48 8b 40 10          	mov    0x10(%rax),%rax
    6a3f:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    6a46:	eb 05                	jmp    6a4d <add_segment+0x3d3>
    6a48:	e8 0e 5f 00 00       	callq  c95b <abort>
    6a4d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    6a51:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    6a55:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6a59:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6a60:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    6a64:	48 89 50 18          	mov    %rdx,0x18(%rax)
    6a68:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    6a6c:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    6a73:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6a77:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    6a7b:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    6a7f:	48 89 50 18          	mov    %rdx,0x18(%rax)
    6a83:	e9 e2 02 00 00       	jmpq   6d6a <add_segment+0x6f0>
    6a88:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    6a8c:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    6a90:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6a94:	48 c1 e8 08          	shr    $0x8,%rax
    6a98:	89 85 34 ff ff ff    	mov    %eax,-0xcc(%rbp)
    6a9e:	83 bd 34 ff ff ff 00 	cmpl   $0x0,-0xcc(%rbp)
    6aa5:	75 0c                	jne    6ab3 <add_segment+0x439>
    6aa7:	c7 85 30 ff ff ff 00 	movl   $0x0,-0xd0(%rbp)
    6aae:	00 00 00 
    6ab1:	eb 5a                	jmp    6b0d <add_segment+0x493>
    6ab3:	81 bd 34 ff ff ff ff 	cmpl   $0xffff,-0xcc(%rbp)
    6aba:	ff 00 00 
    6abd:	76 0c                	jbe    6acb <add_segment+0x451>
    6abf:	c7 85 30 ff ff ff 1f 	movl   $0x1f,-0xd0(%rbp)
    6ac6:	00 00 00 
    6ac9:	eb 42                	jmp    6b0d <add_segment+0x493>
    6acb:	0f bd 85 34 ff ff ff 	bsr    -0xcc(%rbp),%eax
    6ad2:	83 f0 1f             	xor    $0x1f,%eax
    6ad5:	ba 1f 00 00 00       	mov    $0x1f,%edx
    6ada:	29 c2                	sub    %eax,%edx
    6adc:	89 d0                	mov    %edx,%eax
    6ade:	89 85 38 ff ff ff    	mov    %eax,-0xc8(%rbp)
    6ae4:	8b 85 38 ff ff ff    	mov    -0xc8(%rbp),%eax
    6aea:	8d 34 00             	lea    (%rax,%rax,1),%esi
    6aed:	8b 85 38 ff ff ff    	mov    -0xc8(%rbp),%eax
    6af3:	83 c0 07             	add    $0x7,%eax
    6af6:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    6afa:	89 c1                	mov    %eax,%ecx
    6afc:	48 d3 ea             	shr    %cl,%rdx
    6aff:	48 89 d0             	mov    %rdx,%rax
    6b02:	83 e0 01             	and    $0x1,%eax
    6b05:	01 f0                	add    %esi,%eax
    6b07:	89 85 30 ff ff ff    	mov    %eax,-0xd0(%rbp)
    6b0d:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    6b13:	48 83 c0 4a          	add    $0x4a,%rax
    6b17:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    6b1e:	00 
    6b1f:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6b26:	48 01 d0             	add    %rdx,%rax
    6b29:	48 83 c0 08          	add    $0x8,%rax
    6b2d:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    6b31:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6b35:	8b 95 30 ff ff ff    	mov    -0xd0(%rbp),%edx
    6b3b:	89 50 38             	mov    %edx,0x38(%rax)
    6b3e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6b42:	48 c7 40 28 00 00 00 	movq   $0x0,0x28(%rax)
    6b49:	00 
    6b4a:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6b4e:	48 8b 50 28          	mov    0x28(%rax),%rdx
    6b52:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6b56:	48 89 50 20          	mov    %rdx,0x20(%rax)
    6b5a:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6b61:	8b 50 04             	mov    0x4(%rax),%edx
    6b64:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    6b6a:	be 01 00 00 00       	mov    $0x1,%esi
    6b6f:	89 c1                	mov    %eax,%ecx
    6b71:	d3 e6                	shl    %cl,%esi
    6b73:	89 f0                	mov    %esi,%eax
    6b75:	21 d0                	and    %edx,%eax
    6b77:	85 c0                	test   %eax,%eax
    6b79:	75 5f                	jne    6bda <add_segment+0x560>
    6b7b:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6b82:	8b 50 04             	mov    0x4(%rax),%edx
    6b85:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    6b8b:	be 01 00 00 00       	mov    $0x1,%esi
    6b90:	89 c1                	mov    %eax,%ecx
    6b92:	d3 e6                	shl    %cl,%esi
    6b94:	89 f0                	mov    %esi,%eax
    6b96:	09 c2                	or     %eax,%edx
    6b98:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6b9f:	89 50 04             	mov    %edx,0x4(%rax)
    6ba2:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    6ba6:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    6baa:	48 89 10             	mov    %rdx,(%rax)
    6bad:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6bb1:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    6bb5:	48 89 50 30          	mov    %rdx,0x30(%rax)
    6bb9:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6bbd:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    6bc1:	48 89 50 18          	mov    %rdx,0x18(%rax)
    6bc5:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6bc9:	48 8b 50 18          	mov    0x18(%rax),%rdx
    6bcd:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6bd1:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6bd5:	e9 90 01 00 00       	jmpq   6d6a <add_segment+0x6f0>
    6bda:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    6bde:	48 8b 00             	mov    (%rax),%rax
    6be1:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    6be8:	83 bd 30 ff ff ff 1f 	cmpl   $0x1f,-0xd0(%rbp)
    6bef:	74 13                	je     6c04 <add_segment+0x58a>
    6bf1:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    6bf7:	d1 e8                	shr    %eax
    6bf9:	ba 39 00 00 00       	mov    $0x39,%edx
    6bfe:	29 c2                	sub    %eax,%edx
    6c00:	89 d0                	mov    %edx,%eax
    6c02:	eb 05                	jmp    6c09 <add_segment+0x58f>
    6c04:	b8 00 00 00 00       	mov    $0x0,%eax
    6c09:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    6c0d:	89 c1                	mov    %eax,%ecx
    6c0f:	48 d3 e2             	shl    %cl,%rdx
    6c12:	48 89 d0             	mov    %rdx,%rax
    6c15:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
    6c1c:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    6c23:	48 8b 40 08          	mov    0x8(%rax),%rax
    6c27:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    6c2b:	48 39 45 c8          	cmp    %rax,-0x38(%rbp)
    6c2f:	0f 84 a2 00 00 00    	je     6cd7 <add_segment+0x65d>
    6c35:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    6c3c:	48 c1 e8 3f          	shr    $0x3f,%rax
    6c40:	48 83 c0 04          	add    $0x4,%rax
    6c44:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    6c4b:	00 
    6c4c:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    6c53:	48 01 d0             	add    %rdx,%rax
    6c56:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    6c5a:	48 d1 a5 58 ff ff ff 	shlq   -0xa8(%rbp)
    6c61:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    6c65:	48 8b 00             	mov    (%rax),%rax
    6c68:	48 85 c0             	test   %rax,%rax
    6c6b:	74 10                	je     6c7d <add_segment+0x603>
    6c6d:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    6c71:	48 8b 00             	mov    (%rax),%rax
    6c74:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    6c7b:	eb 9f                	jmp    6c1c <add_segment+0x5a2>
    6c7d:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6c84:	48 8b 40 18          	mov    0x18(%rax),%rax
    6c88:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    6c8c:	0f 93 c0             	setae  %al
    6c8f:	0f b6 c0             	movzbl %al,%eax
    6c92:	48 85 c0             	test   %rax,%rax
    6c95:	74 3b                	je     6cd2 <add_segment+0x658>
    6c97:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    6c9b:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    6c9f:	48 89 10             	mov    %rdx,(%rax)
    6ca2:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6ca6:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    6cad:	48 89 50 30          	mov    %rdx,0x30(%rax)
    6cb1:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6cb5:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    6cb9:	48 89 50 18          	mov    %rdx,0x18(%rax)
    6cbd:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6cc1:	48 8b 50 18          	mov    0x18(%rax),%rdx
    6cc5:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6cc9:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6ccd:	e9 98 00 00 00       	jmpq   6d6a <add_segment+0x6f0>
    6cd2:	e8 84 5c 00 00       	callq  c95b <abort>
    6cd7:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    6cde:	48 8b 40 10          	mov    0x10(%rax),%rax
    6ce2:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    6ce6:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6ced:	48 8b 40 18          	mov    0x18(%rax),%rax
    6cf1:	48 39 85 50 ff ff ff 	cmp    %rax,-0xb0(%rbp)
    6cf8:	0f 93 c0             	setae  %al
    6cfb:	0f b6 c0             	movzbl %al,%eax
    6cfe:	48 85 c0             	test   %rax,%rax
    6d01:	74 62                	je     6d65 <add_segment+0x6eb>
    6d03:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6d0a:	48 8b 40 18          	mov    0x18(%rax),%rax
    6d0e:	48 39 45 e8          	cmp    %rax,-0x18(%rbp)
    6d12:	0f 93 c0             	setae  %al
    6d15:	0f b6 c0             	movzbl %al,%eax
    6d18:	48 85 c0             	test   %rax,%rax
    6d1b:	74 48                	je     6d65 <add_segment+0x6eb>
    6d1d:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    6d21:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    6d25:	48 89 50 18          	mov    %rdx,0x18(%rax)
    6d29:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    6d2d:	48 8b 50 18          	mov    0x18(%rax),%rdx
    6d31:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    6d38:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6d3c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6d40:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    6d44:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6d48:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6d4c:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    6d53:	48 89 50 18          	mov    %rdx,0x18(%rax)
    6d57:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6d5b:	48 c7 40 30 00 00 00 	movq   $0x0,0x30(%rax)
    6d62:	00 
    6d63:	eb 05                	jmp    6d6a <add_segment+0x6f0>
    6d65:	e8 f1 5b 00 00       	callq  c95b <abort>
  }

  check_top_chunk(m, m->top);
    6d6a:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6d71:	48 8b 50 28          	mov    0x28(%rax),%rdx
    6d75:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6d7c:	48 89 d6             	mov    %rdx,%rsi
    6d7f:	48 89 c7             	mov    %rax,%rdi
    6d82:	e8 1b e7 ff ff       	callq  54a2 <do_check_top_chunk>
}
    6d87:	90                   	nop
    6d88:	c9                   	leaveq 
    6d89:	c3                   	retq   

0000000000006d8a <sys_alloc>:

/* -------------------------- System allocation -------------------------- */

/* Get memory from system using MORECORE or MMAP */
static void* sys_alloc(mstate m, size_t nb) {
    6d8a:	55                   	push   %rbp
    6d8b:	48 89 e5             	mov    %rsp,%rbp
    6d8e:	48 81 ec c0 00 00 00 	sub    $0xc0,%rsp
    6d95:	48 89 bd 48 ff ff ff 	mov    %rdi,-0xb8(%rbp)
    6d9c:	48 89 b5 40 ff ff ff 	mov    %rsi,-0xc0(%rbp)
  char* tbase = CMFAIL;
    6da3:	48 c7 85 60 ff ff ff 	movq   $0xffffffffffffffff,-0xa0(%rbp)
    6daa:	ff ff ff ff 
  size_t tsize = 0;
    6dae:	48 c7 85 68 ff ff ff 	movq   $0x0,-0x98(%rbp)
    6db5:	00 00 00 00 
  flag_t mmap_flag = 0;
    6db9:	c7 85 5c ff ff ff 00 	movl   $0x0,-0xa4(%rbp)
    6dc0:	00 00 00 
  size_t asize; /* allocation size */

  ensure_initialization();
    6dc3:	48 8b 05 56 a3 00 00 	mov    0xa356(%rip),%rax        # 11120 <mparams>
    6dca:	48 85 c0             	test   %rax,%rax
    6dcd:	75 07                	jne    6dd6 <sys_alloc+0x4c>
    6dcf:	e8 4c e5 ff ff       	callq  5320 <init_mparams>
    6dd4:	85 c0                	test   %eax,%eax
    6dd6:	90                   	nop
    void* mem = mmap_alloc(m, nb);
    if (mem != 0)
      return mem;
  }

  asize = granularity_align(nb + SYS_ALLOC_PADDING);
    6dd7:	48 8b 15 52 a3 00 00 	mov    0xa352(%rip),%rdx        # 11130 <mparams+0x10>
    6dde:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    6de5:	48 01 d0             	add    %rdx,%rax
    6de8:	48 8d 50 5f          	lea    0x5f(%rax),%rdx
    6dec:	48 8b 05 3d a3 00 00 	mov    0xa33d(%rip),%rax        # 11130 <mparams+0x10>
    6df3:	48 f7 d8             	neg    %rax
    6df6:	48 21 d0             	and    %rdx,%rax
    6df9:	48 89 45 88          	mov    %rax,-0x78(%rbp)
  if (asize <= nb)
    6dfd:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    6e01:	48 3b 85 40 ff ff ff 	cmp    -0xc0(%rbp),%rax
    6e08:	77 0a                	ja     6e14 <sys_alloc+0x8a>
    return 0; /* wraparound */
    6e0a:	b8 00 00 00 00       	mov    $0x0,%eax
    6e0f:	e9 50 09 00 00       	jmpq   7764 <sys_alloc+0x9da>
  if (m->footprint_limit != 0) {
    6e14:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6e1b:	48 8b 80 68 03 00 00 	mov    0x368(%rax),%rax
    6e22:	48 85 c0             	test   %rax,%rax
    6e25:	74 4b                	je     6e72 <sys_alloc+0xe8>
    size_t fp = m->footprint + asize;
    6e27:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6e2e:	48 8b 90 58 03 00 00 	mov    0x358(%rax),%rdx
    6e35:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    6e39:	48 01 d0             	add    %rdx,%rax
    6e3c:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    if (fp <= m->footprint || fp > m->footprint_limit)
    6e40:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6e47:	48 8b 80 58 03 00 00 	mov    0x358(%rax),%rax
    6e4e:	48 39 45 90          	cmp    %rax,-0x70(%rbp)
    6e52:	76 14                	jbe    6e68 <sys_alloc+0xde>
    6e54:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6e5b:	48 8b 80 68 03 00 00 	mov    0x368(%rax),%rax
    6e62:	48 39 45 90          	cmp    %rax,-0x70(%rbp)
    6e66:	76 0a                	jbe    6e72 <sys_alloc+0xe8>
      return 0;
    6e68:	b8 00 00 00 00       	mov    $0x0,%eax
    6e6d:	e9 f2 08 00 00       	jmpq   7764 <sys_alloc+0x9da>
   we can malloc nb bytes upon success, so pad with enough space for
   top_foot, plus alignment-pad to make sure we don't lose bytes if
   not on boundary, and round this up to a granularity unit.
  */

  if (MORECORE_CONTIGUOUS && !use_noncontiguous(m)) {
    6e72:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6e79:	8b 80 70 03 00 00    	mov    0x370(%rax),%eax
    6e7f:	83 e0 04             	and    $0x4,%eax
    6e82:	85 c0                	test   %eax,%eax
    6e84:	0f 85 37 03 00 00    	jne    71c1 <sys_alloc+0x437>
    char* br = CMFAIL;
    6e8a:	48 c7 85 70 ff ff ff 	movq   $0xffffffffffffffff,-0x90(%rbp)
    6e91:	ff ff ff ff 
    size_t ssize = asize; /* sbrk call size */
    6e95:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    6e99:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
    msegmentptr ss = (m->top == 0)? 0 : segment_holding(m, (char*)m->top);
    6ea0:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6ea7:	48 8b 40 28          	mov    0x28(%rax),%rax
    6eab:	48 85 c0             	test   %rax,%rax
    6eae:	74 1f                	je     6ecf <sys_alloc+0x145>
    6eb0:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6eb7:	48 8b 50 28          	mov    0x28(%rax),%rdx
    6ebb:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6ec2:	48 89 d6             	mov    %rdx,%rsi
    6ec5:	48 89 c7             	mov    %rax,%rdi
    6ec8:	e8 f4 e3 ff ff       	callq  52c1 <segment_holding>
    6ecd:	eb 05                	jmp    6ed4 <sys_alloc+0x14a>
    6ecf:	b8 00 00 00 00       	mov    $0x0,%eax
    6ed4:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    ACQUIRE_MALLOC_GLOBAL_LOCK();
    6ed8:	b8 01 00 00 00       	mov    $0x1,%eax
    6edd:	87 05 1d a2 00 00    	xchg   %eax,0xa21d(%rip)        # 11100 <malloc_global_mutex>
    6ee3:	85 c0                	test   %eax,%eax
    6ee5:	74 0c                	je     6ef3 <sys_alloc+0x169>
    6ee7:	48 8d 3d 12 a2 00 00 	lea    0xa212(%rip),%rdi        # 11100 <malloc_global_mutex>
    6eee:	e8 99 e3 ff ff       	callq  528c <spin_acquire_lock>

    if (ss == 0) {  /* First time through or recovery */
    6ef3:	48 83 7d 98 00       	cmpq   $0x0,-0x68(%rbp)
    6ef8:	0f 85 2f 01 00 00    	jne    702d <sys_alloc+0x2a3>
      char* base = (char*)CALL_MORECORE(0);
    6efe:	bf 00 00 00 00       	mov    $0x0,%edi
    6f03:	e8 83 41 00 00       	callq  b08b <sbrk>
    6f08:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
      if (base != CMFAIL) {
    6f0c:	48 83 7d a0 ff       	cmpq   $0xffffffffffffffff,-0x60(%rbp)
    6f11:	0f 84 ad 01 00 00    	je     70c4 <sys_alloc+0x33a>
        size_t fp;
        /* Adjust to end on a page boundary */
        if (!is_page_aligned(base))
    6f17:	48 8b 05 0a a2 00 00 	mov    0xa20a(%rip),%rax        # 11128 <mparams+0x8>
    6f1e:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    6f22:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    6f26:	48 21 d0             	and    %rdx,%rax
    6f29:	48 85 c0             	test   %rax,%rax
    6f2c:	74 30                	je     6f5e <sys_alloc+0x1d4>
          ssize += (page_align((size_t)base) - (size_t)base);
    6f2e:	48 8b 15 f3 a1 00 00 	mov    0xa1f3(%rip),%rdx        # 11128 <mparams+0x8>
    6f35:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    6f39:	48 01 d0             	add    %rdx,%rax
    6f3c:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    6f40:	48 8b 05 e1 a1 00 00 	mov    0xa1e1(%rip),%rax        # 11128 <mparams+0x8>
    6f47:	48 f7 d8             	neg    %rax
    6f4a:	48 21 c2             	and    %rax,%rdx
    6f4d:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    6f51:	48 29 c2             	sub    %rax,%rdx
    6f54:	48 89 d0             	mov    %rdx,%rax
    6f57:	48 01 85 78 ff ff ff 	add    %rax,-0x88(%rbp)
        fp = m->footprint + ssize; /* recheck limits */
    6f5e:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6f65:	48 8b 90 58 03 00 00 	mov    0x358(%rax),%rdx
    6f6c:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    6f73:	48 01 d0             	add    %rdx,%rax
    6f76:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
        if (ssize > nb && ssize < HALF_MAX_SIZE_T &&
    6f7a:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    6f81:	48 3b 85 40 ff ff ff 	cmp    -0xc0(%rbp),%rax
    6f88:	0f 86 36 01 00 00    	jbe    70c4 <sys_alloc+0x33a>
    6f8e:	48 b8 fe ff ff ff ff 	movabs $0x7ffffffffffffffe,%rax
    6f95:	ff ff 7f 
    6f98:	48 39 85 78 ff ff ff 	cmp    %rax,-0x88(%rbp)
    6f9f:	0f 87 1f 01 00 00    	ja     70c4 <sys_alloc+0x33a>
            (m->footprint_limit == 0 ||
    6fa5:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6fac:	48 8b 80 68 03 00 00 	mov    0x368(%rax),%rax
        if (ssize > nb && ssize < HALF_MAX_SIZE_T &&
    6fb3:	48 85 c0             	test   %rax,%rax
    6fb6:	74 30                	je     6fe8 <sys_alloc+0x25e>
             (fp > m->footprint && fp <= m->footprint_limit)) &&
    6fb8:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6fbf:	48 8b 80 58 03 00 00 	mov    0x358(%rax),%rax
            (m->footprint_limit == 0 ||
    6fc6:	48 39 45 a8          	cmp    %rax,-0x58(%rbp)
    6fca:	0f 86 f4 00 00 00    	jbe    70c4 <sys_alloc+0x33a>
             (fp > m->footprint && fp <= m->footprint_limit)) &&
    6fd0:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6fd7:	48 8b 80 68 03 00 00 	mov    0x368(%rax),%rax
    6fde:	48 39 45 a8          	cmp    %rax,-0x58(%rbp)
    6fe2:	0f 87 dc 00 00 00    	ja     70c4 <sys_alloc+0x33a>
            (br = (char*)(CALL_MORECORE(ssize))) == base) {
    6fe8:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
             (fp > m->footprint && fp <= m->footprint_limit)) &&
    6fef:	48 89 c7             	mov    %rax,%rdi
    6ff2:	e8 94 40 00 00       	callq  b08b <sbrk>
    6ff7:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
    6ffe:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    7005:	48 3b 45 a0          	cmp    -0x60(%rbp),%rax
    7009:	0f 85 b5 00 00 00    	jne    70c4 <sys_alloc+0x33a>
          tbase = base;
    700f:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    7013:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
          tsize = ssize;
    701a:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    7021:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
    7028:	e9 97 00 00 00       	jmpq   70c4 <sys_alloc+0x33a>
        }
      }
    }
    else {
      /* Subtract out existing available top space from MORECORE request. */
      ssize = granularity_align(nb - m->topsize + SYS_ALLOC_PADDING);
    702d:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7034:	48 8b 40 10          	mov    0x10(%rax),%rax
    7038:	48 8b 95 40 ff ff ff 	mov    -0xc0(%rbp),%rdx
    703f:	48 29 c2             	sub    %rax,%rdx
    7042:	48 8b 05 e7 a0 00 00 	mov    0xa0e7(%rip),%rax        # 11130 <mparams+0x10>
    7049:	48 01 d0             	add    %rdx,%rax
    704c:	48 8d 50 5f          	lea    0x5f(%rax),%rdx
    7050:	48 8b 05 d9 a0 00 00 	mov    0xa0d9(%rip),%rax        # 11130 <mparams+0x10>
    7057:	48 f7 d8             	neg    %rax
    705a:	48 21 d0             	and    %rdx,%rax
    705d:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
      /* Use mem here only if it did continuously extend old space */
      if (ssize < HALF_MAX_SIZE_T &&
    7064:	48 b8 fe ff ff ff ff 	movabs $0x7ffffffffffffffe,%rax
    706b:	ff ff 7f 
    706e:	48 39 85 78 ff ff ff 	cmp    %rax,-0x88(%rbp)
    7075:	77 4d                	ja     70c4 <sys_alloc+0x33a>
          (br = (char*)(CALL_MORECORE(ssize))) == ss->base+ss->size) {
    7077:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
      if (ssize < HALF_MAX_SIZE_T &&
    707e:	48 89 c7             	mov    %rax,%rdi
    7081:	e8 05 40 00 00       	callq  b08b <sbrk>
    7086:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
          (br = (char*)(CALL_MORECORE(ssize))) == ss->base+ss->size) {
    708d:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    7091:	48 8b 10             	mov    (%rax),%rdx
    7094:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    7098:	48 8b 40 08          	mov    0x8(%rax),%rax
    709c:	48 01 d0             	add    %rdx,%rax
      if (ssize < HALF_MAX_SIZE_T &&
    709f:	48 39 85 70 ff ff ff 	cmp    %rax,-0x90(%rbp)
    70a6:	75 1c                	jne    70c4 <sys_alloc+0x33a>
        tbase = br;
    70a8:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    70af:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
        tsize = ssize;
    70b6:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    70bd:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
      }
    }

    if (tbase == CMFAIL) {    /* Cope with partial failure */
    70c4:	48 83 bd 60 ff ff ff 	cmpq   $0xffffffffffffffff,-0xa0(%rbp)
    70cb:	ff 
    70cc:	0f 85 e4 00 00 00    	jne    71b6 <sys_alloc+0x42c>
      if (br != CMFAIL) {    /* Try to use/extend the space we did get */
    70d2:	48 83 bd 70 ff ff ff 	cmpq   $0xffffffffffffffff,-0x90(%rbp)
    70d9:	ff 
    70da:	0f 84 b0 00 00 00    	je     7190 <sys_alloc+0x406>
        if (ssize < HALF_MAX_SIZE_T &&
    70e0:	48 b8 fe ff ff ff ff 	movabs $0x7ffffffffffffffe,%rax
    70e7:	ff ff 7f 
    70ea:	48 39 85 78 ff ff ff 	cmp    %rax,-0x88(%rbp)
    70f1:	0f 87 99 00 00 00    	ja     7190 <sys_alloc+0x406>
            ssize < nb + SYS_ALLOC_PADDING) {
    70f7:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    70fe:	48 83 c0 60          	add    $0x60,%rax
        if (ssize < HALF_MAX_SIZE_T &&
    7102:	48 39 85 78 ff ff ff 	cmp    %rax,-0x88(%rbp)
    7109:	0f 83 81 00 00 00    	jae    7190 <sys_alloc+0x406>
          size_t esize = granularity_align(nb + SYS_ALLOC_PADDING - ssize);
    710f:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    7116:	48 2b 85 78 ff ff ff 	sub    -0x88(%rbp),%rax
    711d:	48 89 c2             	mov    %rax,%rdx
    7120:	48 8b 05 09 a0 00 00 	mov    0xa009(%rip),%rax        # 11130 <mparams+0x10>
    7127:	48 01 d0             	add    %rdx,%rax
    712a:	48 8d 50 5f          	lea    0x5f(%rax),%rdx
    712e:	48 8b 05 fb 9f 00 00 	mov    0x9ffb(%rip),%rax        # 11130 <mparams+0x10>
    7135:	48 f7 d8             	neg    %rax
    7138:	48 21 d0             	and    %rdx,%rax
    713b:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
          if (esize < HALF_MAX_SIZE_T) {
    713f:	48 b8 fe ff ff ff ff 	movabs $0x7ffffffffffffffe,%rax
    7146:	ff ff 7f 
    7149:	48 39 45 b0          	cmp    %rax,-0x50(%rbp)
    714d:	77 41                	ja     7190 <sys_alloc+0x406>
            char* end = (char*)CALL_MORECORE(esize);
    714f:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    7153:	48 89 c7             	mov    %rax,%rdi
    7156:	e8 30 3f 00 00       	callq  b08b <sbrk>
    715b:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
            if (end != CMFAIL)
    715f:	48 83 7d b8 ff       	cmpq   $0xffffffffffffffff,-0x48(%rbp)
    7164:	74 0d                	je     7173 <sys_alloc+0x3e9>
              ssize += esize;
    7166:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    716a:	48 01 85 78 ff ff ff 	add    %rax,-0x88(%rbp)
    7171:	eb 1d                	jmp    7190 <sys_alloc+0x406>
            else {            /* Can't use; try to release */
              (void) CALL_MORECORE(-ssize);
    7173:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    717a:	48 f7 d8             	neg    %rax
    717d:	48 89 c7             	mov    %rax,%rdi
    7180:	e8 06 3f 00 00       	callq  b08b <sbrk>
              br = CMFAIL;
    7185:	48 c7 85 70 ff ff ff 	movq   $0xffffffffffffffff,-0x90(%rbp)
    718c:	ff ff ff ff 
            }
          }
        }
      }
      if (br != CMFAIL) {    /* Use the space we did get */
    7190:	48 83 bd 70 ff ff ff 	cmpq   $0xffffffffffffffff,-0x90(%rbp)
    7197:	ff 
    7198:	74 1c                	je     71b6 <sys_alloc+0x42c>
        tbase = br;
    719a:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    71a1:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
        tsize = ssize;
    71a8:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    71af:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
      else
        disable_contiguous(m); /* Don't try contiguous path in the future */
#endif
    }

    RELEASE_MALLOC_GLOBAL_LOCK();
    71b6:	b8 00 00 00 00       	mov    $0x0,%eax
    71bb:	89 05 3f 9f 00 00    	mov    %eax,0x9f3f(%rip)        # 11100 <malloc_global_mutex>
      tsize = asize;
      mmap_flag = USE_MMAP_BIT;
    }
  }

  if (HAVE_MORECORE && tbase == CMFAIL) { /* Try noncontiguous MORECORE */
    71c1:	48 83 bd 60 ff ff ff 	cmpq   $0xffffffffffffffff,-0xa0(%rbp)
    71c8:	ff 
    71c9:	0f 85 b9 00 00 00    	jne    7288 <sys_alloc+0x4fe>
    if (asize < HALF_MAX_SIZE_T) {
    71cf:	48 b8 fe ff ff ff ff 	movabs $0x7ffffffffffffffe,%rax
    71d6:	ff ff 7f 
    71d9:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    71dd:	0f 87 a5 00 00 00    	ja     7288 <sys_alloc+0x4fe>
      char* br = CMFAIL;
    71e3:	48 c7 45 c0 ff ff ff 	movq   $0xffffffffffffffff,-0x40(%rbp)
    71ea:	ff 
      char* end = CMFAIL;
    71eb:	48 c7 45 c8 ff ff ff 	movq   $0xffffffffffffffff,-0x38(%rbp)
    71f2:	ff 
      ACQUIRE_MALLOC_GLOBAL_LOCK();
    71f3:	b8 01 00 00 00       	mov    $0x1,%eax
    71f8:	87 05 02 9f 00 00    	xchg   %eax,0x9f02(%rip)        # 11100 <malloc_global_mutex>
    71fe:	85 c0                	test   %eax,%eax
    7200:	74 0c                	je     720e <sys_alloc+0x484>
    7202:	48 8d 3d f7 9e 00 00 	lea    0x9ef7(%rip),%rdi        # 11100 <malloc_global_mutex>
    7209:	e8 7e e0 ff ff       	callq  528c <spin_acquire_lock>
      br = (char*)(CALL_MORECORE(asize));
    720e:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    7212:	48 89 c7             	mov    %rax,%rdi
    7215:	e8 71 3e 00 00       	callq  b08b <sbrk>
    721a:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
      end = (char*)(CALL_MORECORE(0));
    721e:	bf 00 00 00 00       	mov    $0x0,%edi
    7223:	e8 63 3e 00 00       	callq  b08b <sbrk>
    7228:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
      RELEASE_MALLOC_GLOBAL_LOCK();
    722c:	b8 00 00 00 00       	mov    $0x0,%eax
    7231:	89 05 c9 9e 00 00    	mov    %eax,0x9ec9(%rip)        # 11100 <malloc_global_mutex>
      if (br != CMFAIL && end != CMFAIL && br < end) {
    7237:	48 83 7d c0 ff       	cmpq   $0xffffffffffffffff,-0x40(%rbp)
    723c:	74 4a                	je     7288 <sys_alloc+0x4fe>
    723e:	48 83 7d c8 ff       	cmpq   $0xffffffffffffffff,-0x38(%rbp)
    7243:	74 43                	je     7288 <sys_alloc+0x4fe>
    7245:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    7249:	48 3b 45 c8          	cmp    -0x38(%rbp),%rax
    724d:	73 39                	jae    7288 <sys_alloc+0x4fe>
        size_t ssize = end - br;
    724f:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    7253:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    7257:	48 29 c2             	sub    %rax,%rdx
    725a:	48 89 d0             	mov    %rdx,%rax
    725d:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
        if (ssize > nb + TOP_FOOT_SIZE) {
    7261:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    7268:	48 83 c0 50          	add    $0x50,%rax
    726c:	48 39 45 d0          	cmp    %rax,-0x30(%rbp)
    7270:	76 16                	jbe    7288 <sys_alloc+0x4fe>
          tbase = br;
    7272:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    7276:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
          tsize = ssize;
    727d:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    7281:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
        }
      }
    }
  }

  if (tbase != CMFAIL) {
    7288:	48 83 bd 60 ff ff ff 	cmpq   $0xffffffffffffffff,-0xa0(%rbp)
    728f:	ff 
    7290:	0f 84 be 04 00 00    	je     7754 <sys_alloc+0x9ca>

    if ((m->footprint += tsize) > m->max_footprint)
    7296:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    729d:	48 8b 90 58 03 00 00 	mov    0x358(%rax),%rdx
    72a4:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    72ab:	48 01 c2             	add    %rax,%rdx
    72ae:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    72b5:	48 89 90 58 03 00 00 	mov    %rdx,0x358(%rax)
    72bc:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    72c3:	48 8b 90 58 03 00 00 	mov    0x358(%rax),%rdx
    72ca:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    72d1:	48 8b 80 60 03 00 00 	mov    0x360(%rax),%rax
    72d8:	48 39 c2             	cmp    %rax,%rdx
    72db:	76 1c                	jbe    72f9 <sys_alloc+0x56f>
      m->max_footprint = m->footprint;
    72dd:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    72e4:	48 8b 90 58 03 00 00 	mov    0x358(%rax),%rdx
    72eb:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    72f2:	48 89 90 60 03 00 00 	mov    %rdx,0x360(%rax)

    if (!is_initialized(m)) { /* first-time initialization */
    72f9:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7300:	48 8b 40 28          	mov    0x28(%rax),%rax
    7304:	48 85 c0             	test   %rax,%rax
    7307:	0f 85 3e 01 00 00    	jne    744b <sys_alloc+0x6c1>
      if (m->least_addr == 0 || tbase < m->least_addr)
    730d:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7314:	48 8b 40 18          	mov    0x18(%rax),%rax
    7318:	48 85 c0             	test   %rax,%rax
    731b:	74 14                	je     7331 <sys_alloc+0x5a7>
    731d:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7324:	48 8b 40 18          	mov    0x18(%rax),%rax
    7328:	48 39 85 60 ff ff ff 	cmp    %rax,-0xa0(%rbp)
    732f:	73 12                	jae    7343 <sys_alloc+0x5b9>
        m->least_addr = tbase;
    7331:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7338:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    733f:	48 89 50 18          	mov    %rdx,0x18(%rax)
      m->seg.base = tbase;
    7343:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    734a:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    7351:	48 89 90 78 03 00 00 	mov    %rdx,0x378(%rax)
      m->seg.size = tsize;
    7358:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    735f:	48 8b 95 68 ff ff ff 	mov    -0x98(%rbp),%rdx
    7366:	48 89 90 80 03 00 00 	mov    %rdx,0x380(%rax)
      m->seg.sflags = mmap_flag;
    736d:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7374:	8b 95 5c ff ff ff    	mov    -0xa4(%rbp),%edx
    737a:	89 90 90 03 00 00    	mov    %edx,0x390(%rax)
      m->magic = mparams.magic;
    7380:	48 8b 15 99 9d 00 00 	mov    0x9d99(%rip),%rdx        # 11120 <mparams>
    7387:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    738e:	48 89 50 40          	mov    %rdx,0x40(%rax)
      m->release_checks = MAX_RELEASE_CHECK_RATE;
    7392:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7399:	48 c7 40 38 ff ff ff 	movq   $0xffffffffffffffff,0x38(%rax)
    73a0:	ff 
      init_bins(m);
    73a1:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    73a8:	48 89 c7             	mov    %rax,%rdi
    73ab:	e8 b8 e5 ff ff       	callq  5968 <init_bins>
#if !ONLY_MSPACES
      if (is_global(m))
    73b0:	48 8d 05 a9 9d 00 00 	lea    0x9da9(%rip),%rax        # 11160 <_gm_>
    73b7:	48 39 85 48 ff ff ff 	cmp    %rax,-0xb8(%rbp)
    73be:	75 29                	jne    73e9 <sys_alloc+0x65f>
        init_top(m, (mchunkptr)tbase, tsize - TOP_FOOT_SIZE);
    73c0:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    73c7:	48 8d 50 b0          	lea    -0x50(%rax),%rdx
    73cb:	48 8b 8d 60 ff ff ff 	mov    -0xa0(%rbp),%rcx
    73d2:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    73d9:	48 89 ce             	mov    %rcx,%rsi
    73dc:	48 89 c7             	mov    %rax,%rdi
    73df:	e8 eb e4 ff ff       	callq  58cf <init_top>
    73e4:	e9 5a 02 00 00       	jmpq   7643 <sys_alloc+0x8b9>
      else
#endif
      {
        /* Offset top by embedded malloc_state */
        mchunkptr mn = next_chunk(mem2chunk(m));
    73e9:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    73f0:	48 83 e8 10          	sub    $0x10,%rax
    73f4:	48 8b 40 08          	mov    0x8(%rax),%rax
    73f8:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    73fc:	48 8d 50 f0          	lea    -0x10(%rax),%rdx
    7400:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7407:	48 01 d0             	add    %rdx,%rax
    740a:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
        init_top(m, mn, (size_t)((tbase + tsize) - (char*)mn) -TOP_FOOT_SIZE);
    740e:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    7415:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    741c:	48 01 d0             	add    %rdx,%rax
    741f:	48 89 c2             	mov    %rax,%rdx
    7422:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    7426:	48 29 c2             	sub    %rax,%rdx
    7429:	48 89 d0             	mov    %rdx,%rax
    742c:	48 8d 50 b0          	lea    -0x50(%rax),%rdx
    7430:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    7434:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    743b:	48 89 ce             	mov    %rcx,%rsi
    743e:	48 89 c7             	mov    %rax,%rdi
    7441:	e8 89 e4 ff ff       	callq  58cf <init_top>
    7446:	e9 f8 01 00 00       	jmpq   7643 <sys_alloc+0x8b9>
      }
    }

    else {
      /* Try to merge with an existing segment */
      msegmentptr sp = &m->seg;
    744b:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7452:	48 05 78 03 00 00    	add    $0x378,%rax
    7458:	48 89 45 80          	mov    %rax,-0x80(%rbp)
      /* Only consider most recent segment if traversal suppressed */
      while (sp != 0 && tbase != sp->base + sp->size)
    745c:	eb 0c                	jmp    746a <sys_alloc+0x6e0>
        sp = (NO_SEGMENT_TRAVERSAL) ? 0 : sp->next;
    745e:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    7462:	48 8b 40 10          	mov    0x10(%rax),%rax
    7466:	48 89 45 80          	mov    %rax,-0x80(%rbp)
      while (sp != 0 && tbase != sp->base + sp->size)
    746a:	48 83 7d 80 00       	cmpq   $0x0,-0x80(%rbp)
    746f:	74 1b                	je     748c <sys_alloc+0x702>
    7471:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    7475:	48 8b 10             	mov    (%rax),%rdx
    7478:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    747c:	48 8b 40 08          	mov    0x8(%rax),%rax
    7480:	48 01 d0             	add    %rdx,%rax
    7483:	48 39 85 60 ff ff ff 	cmp    %rax,-0xa0(%rbp)
    748a:	75 d2                	jne    745e <sys_alloc+0x6d4>
      if (sp != 0 &&
    748c:	48 83 7d 80 00       	cmpq   $0x0,-0x80(%rbp)
    7491:	0f 84 a9 00 00 00    	je     7540 <sys_alloc+0x7b6>
          !is_extern_segment(sp) &&
    7497:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    749b:	8b 40 18             	mov    0x18(%rax),%eax
    749e:	83 e0 08             	and    $0x8,%eax
      if (sp != 0 &&
    74a1:	85 c0                	test   %eax,%eax
    74a3:	0f 85 97 00 00 00    	jne    7540 <sys_alloc+0x7b6>
          !is_extern_segment(sp) &&
    74a9:	83 bd 5c ff ff ff 00 	cmpl   $0x0,-0xa4(%rbp)
    74b0:	0f 85 8a 00 00 00    	jne    7540 <sys_alloc+0x7b6>
          (sp->sflags & USE_MMAP_BIT) == mmap_flag &&
          segment_holds(sp, m->top)) { /* append */
    74b6:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    74bd:	48 8b 50 28          	mov    0x28(%rax),%rdx
    74c1:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    74c5:	48 8b 00             	mov    (%rax),%rax
          (sp->sflags & USE_MMAP_BIT) == mmap_flag &&
    74c8:	48 39 c2             	cmp    %rax,%rdx
    74cb:	72 73                	jb     7540 <sys_alloc+0x7b6>
          segment_holds(sp, m->top)) { /* append */
    74cd:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    74d4:	48 8b 50 28          	mov    0x28(%rax),%rdx
    74d8:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    74dc:	48 8b 08             	mov    (%rax),%rcx
    74df:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    74e3:	48 8b 40 08          	mov    0x8(%rax),%rax
    74e7:	48 01 c8             	add    %rcx,%rax
    74ea:	48 39 c2             	cmp    %rax,%rdx
    74ed:	73 51                	jae    7540 <sys_alloc+0x7b6>
        sp->size += tsize;
    74ef:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    74f3:	48 8b 50 08          	mov    0x8(%rax),%rdx
    74f7:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    74fe:	48 01 c2             	add    %rax,%rdx
    7501:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    7505:	48 89 50 08          	mov    %rdx,0x8(%rax)
        init_top(m, m->top, m->topsize + tsize);
    7509:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7510:	48 8b 50 10          	mov    0x10(%rax),%rdx
    7514:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    751b:	48 01 c2             	add    %rax,%rdx
    751e:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7525:	48 8b 48 28          	mov    0x28(%rax),%rcx
    7529:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7530:	48 89 ce             	mov    %rcx,%rsi
    7533:	48 89 c7             	mov    %rax,%rdi
    7536:	e8 94 e3 ff ff       	callq  58cf <init_top>
    753b:	e9 03 01 00 00       	jmpq   7643 <sys_alloc+0x8b9>
      }
      else {
        if (tbase < m->least_addr)
    7540:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7547:	48 8b 40 18          	mov    0x18(%rax),%rax
    754b:	48 39 85 60 ff ff ff 	cmp    %rax,-0xa0(%rbp)
    7552:	73 12                	jae    7566 <sys_alloc+0x7dc>
          m->least_addr = tbase;
    7554:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    755b:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    7562:	48 89 50 18          	mov    %rdx,0x18(%rax)
        sp = &m->seg;
    7566:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    756d:	48 05 78 03 00 00    	add    $0x378,%rax
    7573:	48 89 45 80          	mov    %rax,-0x80(%rbp)
        while (sp != 0 && sp->base != tbase + tsize)
    7577:	eb 0c                	jmp    7585 <sys_alloc+0x7fb>
          sp = (NO_SEGMENT_TRAVERSAL) ? 0 : sp->next;
    7579:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    757d:	48 8b 40 10          	mov    0x10(%rax),%rax
    7581:	48 89 45 80          	mov    %rax,-0x80(%rbp)
        while (sp != 0 && sp->base != tbase + tsize)
    7585:	48 83 7d 80 00       	cmpq   $0x0,-0x80(%rbp)
    758a:	74 1d                	je     75a9 <sys_alloc+0x81f>
    758c:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    7590:	48 8b 00             	mov    (%rax),%rax
    7593:	48 8b 8d 60 ff ff ff 	mov    -0xa0(%rbp),%rcx
    759a:	48 8b 95 68 ff ff ff 	mov    -0x98(%rbp),%rdx
    75a1:	48 01 ca             	add    %rcx,%rdx
    75a4:	48 39 d0             	cmp    %rdx,%rax
    75a7:	75 d0                	jne    7579 <sys_alloc+0x7ef>
        if (sp != 0 &&
    75a9:	48 83 7d 80 00       	cmpq   $0x0,-0x80(%rbp)
    75ae:	74 70                	je     7620 <sys_alloc+0x896>
            !is_extern_segment(sp) &&
    75b0:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    75b4:	8b 40 18             	mov    0x18(%rax),%eax
    75b7:	83 e0 08             	and    $0x8,%eax
        if (sp != 0 &&
    75ba:	85 c0                	test   %eax,%eax
    75bc:	75 62                	jne    7620 <sys_alloc+0x896>
            !is_extern_segment(sp) &&
    75be:	83 bd 5c ff ff ff 00 	cmpl   $0x0,-0xa4(%rbp)
    75c5:	75 59                	jne    7620 <sys_alloc+0x896>
            (sp->sflags & USE_MMAP_BIT) == mmap_flag) {
          char* oldbase = sp->base;
    75c7:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    75cb:	48 8b 00             	mov    (%rax),%rax
    75ce:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
          sp->base = tbase;
    75d2:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    75d6:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    75dd:	48 89 10             	mov    %rdx,(%rax)
          sp->size += tsize;
    75e0:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    75e4:	48 8b 50 08          	mov    0x8(%rax),%rdx
    75e8:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    75ef:	48 01 c2             	add    %rax,%rdx
    75f2:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    75f6:	48 89 50 08          	mov    %rdx,0x8(%rax)
          return prepend_alloc(m, tbase, oldbase, nb);
    75fa:	48 8b 8d 40 ff ff ff 	mov    -0xc0(%rbp),%rcx
    7601:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    7605:	48 8b b5 60 ff ff ff 	mov    -0xa0(%rbp),%rsi
    760c:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7613:	48 89 c7             	mov    %rax,%rdi
    7616:	e8 a9 e3 ff ff       	callq  59c4 <prepend_alloc>
    761b:	e9 44 01 00 00       	jmpq   7764 <sys_alloc+0x9da>
        }
        else
          add_segment(m, tbase, tsize, mmap_flag);
    7620:	8b 8d 5c ff ff ff    	mov    -0xa4(%rbp),%ecx
    7626:	48 8b 95 68 ff ff ff 	mov    -0x98(%rbp),%rdx
    762d:	48 8b b5 60 ff ff ff 	mov    -0xa0(%rbp),%rsi
    7634:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    763b:	48 89 c7             	mov    %rax,%rdi
    763e:	e8 37 f0 ff ff       	callq  667a <add_segment>
      }
    }

    if (nb < m->topsize) { /* Allocate from new or extended top space */
    7643:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    764a:	48 8b 40 10          	mov    0x10(%rax),%rax
    764e:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    7655:	0f 83 f9 00 00 00    	jae    7754 <sys_alloc+0x9ca>
      size_t rsize = m->topsize -= nb;
    765b:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7662:	48 8b 40 10          	mov    0x10(%rax),%rax
    7666:	48 2b 85 40 ff ff ff 	sub    -0xc0(%rbp),%rax
    766d:	48 89 c2             	mov    %rax,%rdx
    7670:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7677:	48 89 50 10          	mov    %rdx,0x10(%rax)
    767b:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7682:	48 8b 40 10          	mov    0x10(%rax),%rax
    7686:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
      mchunkptr p = m->top;
    768a:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7691:	48 8b 40 28          	mov    0x28(%rax),%rax
    7695:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
      mchunkptr r = m->top = chunk_plus_offset(p, nb);
    7699:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    769d:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    76a4:	48 01 c2             	add    %rax,%rdx
    76a7:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    76ae:	48 89 50 28          	mov    %rdx,0x28(%rax)
    76b2:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    76b9:	48 8b 40 28          	mov    0x28(%rax),%rax
    76bd:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
      r->head = rsize | PINUSE_BIT;
    76c1:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    76c5:	48 83 c8 01          	or     $0x1,%rax
    76c9:	48 89 c2             	mov    %rax,%rdx
    76cc:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    76d0:	48 89 50 08          	mov    %rdx,0x8(%rax)
      set_size_and_pinuse_of_inuse_chunk(m, p, nb);
    76d4:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    76db:	48 83 c8 03          	or     $0x3,%rax
    76df:	48 89 c2             	mov    %rax,%rdx
    76e2:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    76e6:	48 89 50 08          	mov    %rdx,0x8(%rax)
    76ea:	48 8b 0d 2f 9a 00 00 	mov    0x9a2f(%rip),%rcx        # 11120 <mparams>
    76f1:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    76f8:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi
    76fc:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    7703:	48 01 f0             	add    %rsi,%rax
    7706:	48 31 ca             	xor    %rcx,%rdx
    7709:	48 89 10             	mov    %rdx,(%rax)
      check_top_chunk(m, m->top);
    770c:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7713:	48 8b 50 28          	mov    0x28(%rax),%rdx
    7717:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    771e:	48 89 d6             	mov    %rdx,%rsi
    7721:	48 89 c7             	mov    %rax,%rdi
    7724:	e8 79 dd ff ff       	callq  54a2 <do_check_top_chunk>
      check_malloced_chunk(m, chunk2mem(p), nb);
    7729:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    772d:	48 8d 48 10          	lea    0x10(%rax),%rcx
    7731:	48 8b 95 40 ff ff ff 	mov    -0xc0(%rbp),%rdx
    7738:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    773f:	48 89 ce             	mov    %rcx,%rsi
    7742:	48 89 c7             	mov    %rax,%rdi
    7745:	e8 e9 e0 ff ff       	callq  5833 <do_check_malloced_chunk>
      return chunk2mem(p);
    774a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    774e:	48 83 c0 10          	add    $0x10,%rax
    7752:	eb 10                	jmp    7764 <sys_alloc+0x9da>
    }
  }

  MALLOC_FAILURE_ACTION;
    7754:	e8 78 3e 00 00       	callq  b5d1 <__errno>
    7759:	c7 00 0c 00 00 00    	movl   $0xc,(%rax)
  return 0;
    775f:	b8 00 00 00 00       	mov    $0x0,%eax
}
    7764:	c9                   	leaveq 
    7765:	c3                   	retq   

0000000000007766 <release_unused_segments>:

/* -----------------------  system deallocation -------------------------- */

/* Unmap and unlink any mmapped segments that don't contain used chunks */
static size_t release_unused_segments(mstate m) {
    7766:	55                   	push   %rbp
    7767:	48 89 e5             	mov    %rsp,%rbp
    776a:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
  size_t released = 0;
    776e:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    7775:	00 
  int nsegs = 0;
    7776:	c7 45 cc 00 00 00 00 	movl   $0x0,-0x34(%rbp)
  msegmentptr pred = &m->seg;
    777d:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    7781:	48 05 78 03 00 00    	add    $0x378,%rax
    7787:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
  msegmentptr sp = pred->next;
    778b:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    778f:	48 8b 40 10          	mov    0x10(%rax),%rax
    7793:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
  while (sp != 0) {
    7797:	eb 37                	jmp    77d0 <release_unused_segments+0x6a>
    char* base = sp->base;
    7799:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    779d:	48 8b 00             	mov    (%rax),%rax
    77a0:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    size_t size = sp->size;
    77a4:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    77a8:	48 8b 40 08          	mov    0x8(%rax),%rax
    77ac:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    msegmentptr next = sp->next;
    77b0:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    77b4:	48 8b 40 10          	mov    0x10(%rax),%rax
    77b8:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    ++nsegs;
    77bc:	83 45 cc 01          	addl   $0x1,-0x34(%rbp)
        }
      }
    }
    if (NO_SEGMENT_TRAVERSAL) /* scan only first segment */
      break;
    pred = sp;
    77c0:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    77c4:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    sp = next;
    77c8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    77cc:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
  while (sp != 0) {
    77d0:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    77d5:	75 c2                	jne    7799 <release_unused_segments+0x33>
  }
  /* Reset check counter */
  m->release_checks = (((size_t) nsegs > (size_t) MAX_RELEASE_CHECK_RATE)?
    77d7:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    77db:	48 c7 40 38 ff ff ff 	movq   $0xffffffffffffffff,0x38(%rax)
    77e2:	ff 
                       (size_t) nsegs : (size_t) MAX_RELEASE_CHECK_RATE);
  return released;
    77e3:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
}
    77e7:	5d                   	pop    %rbp
    77e8:	c3                   	retq   

00000000000077e9 <sys_trim>:

static int sys_trim(mstate m, size_t pad) {
    77e9:	55                   	push   %rbp
    77ea:	48 89 e5             	mov    %rsp,%rbp
    77ed:	48 83 ec 50          	sub    $0x50,%rsp
    77f1:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    77f5:	48 89 75 b0          	mov    %rsi,-0x50(%rbp)
  size_t released = 0;
    77f9:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    7800:	00 
  ensure_initialization();
    7801:	48 8b 05 18 99 00 00 	mov    0x9918(%rip),%rax        # 11120 <mparams>
    7808:	48 85 c0             	test   %rax,%rax
    780b:	75 07                	jne    7814 <sys_trim+0x2b>
    780d:	e8 0e db ff ff       	callq  5320 <init_mparams>
    7812:	85 c0                	test   %eax,%eax
    7814:	90                   	nop
  if (pad < MAX_REQUEST && is_initialized(m)) {
    7815:	48 81 7d b0 7f ff ff 	cmpq   $0xffffffffffffff7f,-0x50(%rbp)
    781c:	ff 
    781d:	0f 87 e5 01 00 00    	ja     7a08 <sys_trim+0x21f>
    7823:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    7827:	48 8b 40 28          	mov    0x28(%rax),%rax
    782b:	48 85 c0             	test   %rax,%rax
    782e:	0f 84 d4 01 00 00    	je     7a08 <sys_trim+0x21f>
    pad += TOP_FOOT_SIZE; /* ensure enough room for segment overhead */
    7834:	48 83 45 b0 50       	addq   $0x50,-0x50(%rbp)

    if (m->topsize > pad) {
    7839:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    783d:	48 8b 40 10          	mov    0x10(%rax),%rax
    7841:	48 39 45 b0          	cmp    %rax,-0x50(%rbp)
    7845:	0f 83 95 01 00 00    	jae    79e0 <sys_trim+0x1f7>
      /* Shrink top space in granularity-size units, keeping at least one */
      size_t unit = mparams.granularity;
    784b:	48 8b 05 de 98 00 00 	mov    0x98de(%rip),%rax        # 11130 <mparams+0x10>
    7852:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
      size_t extra = ((m->topsize - pad + (unit - SIZE_T_ONE)) / unit -
    7856:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    785a:	48 8b 40 10          	mov    0x10(%rax),%rax
    785e:	48 2b 45 b0          	sub    -0x50(%rbp),%rax
    7862:	48 89 c2             	mov    %rax,%rdx
    7865:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    7869:	48 01 d0             	add    %rdx,%rax
    786c:	48 83 e8 01          	sub    $0x1,%rax
    7870:	ba 00 00 00 00       	mov    $0x0,%edx
    7875:	48 f7 75 d8          	divq   -0x28(%rbp)
    7879:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    787d:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    7881:	48 0f af c2          	imul   %rdx,%rax
    7885:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
                      SIZE_T_ONE) * unit;
      msegmentptr sp = segment_holding(m, (char*)m->top);
    7889:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    788d:	48 8b 50 28          	mov    0x28(%rax),%rdx
    7891:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    7895:	48 89 d6             	mov    %rdx,%rsi
    7898:	48 89 c7             	mov    %rax,%rdi
    789b:	e8 21 da ff ff       	callq  52c1 <segment_holding>
    78a0:	48 89 45 e0          	mov    %rax,-0x20(%rbp)

      if (!is_extern_segment(sp)) {
    78a4:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    78a8:	8b 40 18             	mov    0x18(%rax),%eax
    78ab:	83 e0 08             	and    $0x8,%eax
    78ae:	85 c0                	test   %eax,%eax
    78b0:	0f 85 b2 00 00 00    	jne    7968 <sys_trim+0x17f>
              released = extra;
            }
          }
        }
        else if (HAVE_MORECORE) {
          if (extra >= HALF_MAX_SIZE_T) /* Avoid wrapping negative */
    78b6:	48 b8 fe ff ff ff ff 	movabs $0x7ffffffffffffffe,%rax
    78bd:	ff ff 7f 
    78c0:	48 39 45 d0          	cmp    %rax,-0x30(%rbp)
    78c4:	76 12                	jbe    78d8 <sys_trim+0xef>
            extra = (HALF_MAX_SIZE_T) + SIZE_T_ONE - unit;
    78c6:	48 b8 00 00 00 00 00 	movabs $0x8000000000000000,%rax
    78cd:	00 00 80 
    78d0:	48 2b 45 d8          	sub    -0x28(%rbp),%rax
    78d4:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
          ACQUIRE_MALLOC_GLOBAL_LOCK();
    78d8:	b8 01 00 00 00       	mov    $0x1,%eax
    78dd:	87 05 1d 98 00 00    	xchg   %eax,0x981d(%rip)        # 11100 <malloc_global_mutex>
    78e3:	85 c0                	test   %eax,%eax
    78e5:	74 0c                	je     78f3 <sys_trim+0x10a>
    78e7:	48 8d 3d 12 98 00 00 	lea    0x9812(%rip),%rdi        # 11100 <malloc_global_mutex>
    78ee:	e8 99 d9 ff ff       	callq  528c <spin_acquire_lock>
          {
            /* Make sure end of memory is where we last set it. */
            char* old_br = (char*)(CALL_MORECORE(0));
    78f3:	bf 00 00 00 00       	mov    $0x0,%edi
    78f8:	e8 8e 37 00 00       	callq  b08b <sbrk>
    78fd:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
            if (old_br == sp->base + sp->size) {
    7901:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    7905:	48 8b 10             	mov    (%rax),%rdx
    7908:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    790c:	48 8b 40 08          	mov    0x8(%rax),%rax
    7910:	48 01 d0             	add    %rdx,%rax
    7913:	48 39 45 e8          	cmp    %rax,-0x18(%rbp)
    7917:	75 44                	jne    795d <sys_trim+0x174>
              char* rel_br = (char*)(CALL_MORECORE(-extra));
    7919:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    791d:	48 f7 d8             	neg    %rax
    7920:	48 89 c7             	mov    %rax,%rdi
    7923:	e8 63 37 00 00       	callq  b08b <sbrk>
    7928:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
              char* new_br = (char*)(CALL_MORECORE(0));
    792c:	bf 00 00 00 00       	mov    $0x0,%edi
    7931:	e8 55 37 00 00       	callq  b08b <sbrk>
    7936:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
              if (rel_br != CMFAIL && new_br < old_br)
    793a:	48 83 7d f0 ff       	cmpq   $0xffffffffffffffff,-0x10(%rbp)
    793f:	74 1c                	je     795d <sys_trim+0x174>
    7941:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    7945:	48 3b 45 e8          	cmp    -0x18(%rbp),%rax
    7949:	73 12                	jae    795d <sys_trim+0x174>
                released = old_br - new_br;
    794b:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    794f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    7953:	48 29 c2             	sub    %rax,%rdx
    7956:	48 89 d0             	mov    %rdx,%rax
    7959:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
            }
          }
          RELEASE_MALLOC_GLOBAL_LOCK();
    795d:	b8 00 00 00 00       	mov    $0x0,%eax
    7962:	89 05 98 97 00 00    	mov    %eax,0x9798(%rip)        # 11100 <malloc_global_mutex>
        }
      }

      if (released != 0) {
    7968:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    796d:	74 71                	je     79e0 <sys_trim+0x1f7>
        sp->size -= released;
    796f:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    7973:	48 8b 40 08          	mov    0x8(%rax),%rax
    7977:	48 2b 45 c8          	sub    -0x38(%rbp),%rax
    797b:	48 89 c2             	mov    %rax,%rdx
    797e:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    7982:	48 89 50 08          	mov    %rdx,0x8(%rax)
        m->footprint -= released;
    7986:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    798a:	48 8b 80 58 03 00 00 	mov    0x358(%rax),%rax
    7991:	48 2b 45 c8          	sub    -0x38(%rbp),%rax
    7995:	48 89 c2             	mov    %rax,%rdx
    7998:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    799c:	48 89 90 58 03 00 00 	mov    %rdx,0x358(%rax)
        init_top(m, m->top, m->topsize - released);
    79a3:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    79a7:	48 8b 40 10          	mov    0x10(%rax),%rax
    79ab:	48 2b 45 c8          	sub    -0x38(%rbp),%rax
    79af:	48 89 c2             	mov    %rax,%rdx
    79b2:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    79b6:	48 8b 48 28          	mov    0x28(%rax),%rcx
    79ba:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    79be:	48 89 ce             	mov    %rcx,%rsi
    79c1:	48 89 c7             	mov    %rax,%rdi
    79c4:	e8 06 df ff ff       	callq  58cf <init_top>
        check_top_chunk(m, m->top);
    79c9:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    79cd:	48 8b 50 28          	mov    0x28(%rax),%rdx
    79d1:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    79d5:	48 89 d6             	mov    %rdx,%rsi
    79d8:	48 89 c7             	mov    %rax,%rdi
    79db:	e8 c2 da ff ff       	callq  54a2 <do_check_top_chunk>
    /* Unmap any unused mmapped segments */
    if (HAVE_MMAP)
      released += release_unused_segments(m);

    /* On failure, disable autotrim to avoid repeated failed future calls */
    if (released == 0 && m->topsize > m->trim_check)
    79e0:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    79e5:	75 21                	jne    7a08 <sys_trim+0x21f>
    79e7:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    79eb:	48 8b 50 10          	mov    0x10(%rax),%rdx
    79ef:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    79f3:	48 8b 40 30          	mov    0x30(%rax),%rax
    79f7:	48 39 c2             	cmp    %rax,%rdx
    79fa:	76 0c                	jbe    7a08 <sys_trim+0x21f>
      m->trim_check = MAX_SIZE_T;
    79fc:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    7a00:	48 c7 40 30 ff ff ff 	movq   $0xffffffffffffffff,0x30(%rax)
    7a07:	ff 
  }

  return (released != 0)? 1 : 0;
    7a08:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    7a0d:	0f 95 c0             	setne  %al
    7a10:	0f b6 c0             	movzbl %al,%eax
}
    7a13:	c9                   	leaveq 
    7a14:	c3                   	retq   

0000000000007a15 <tmalloc_large>:
}

/* ---------------------------- malloc --------------------------- */

/* allocate a large request from the best fitting chunk in a treebin */
static void* tmalloc_large(mstate m, size_t nb) {
    7a15:	55                   	push   %rbp
    7a16:	48 89 e5             	mov    %rsp,%rbp
    7a19:	48 81 ec 10 01 00 00 	sub    $0x110,%rsp
    7a20:	48 89 bd f8 fe ff ff 	mov    %rdi,-0x108(%rbp)
    7a27:	48 89 b5 f0 fe ff ff 	mov    %rsi,-0x110(%rbp)
  tchunkptr v = 0;
    7a2e:	48 c7 85 38 ff ff ff 	movq   $0x0,-0xc8(%rbp)
    7a35:	00 00 00 00 
  size_t rsize = -nb; /* Unsigned negation */
    7a39:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    7a40:	48 f7 d8             	neg    %rax
    7a43:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
  tchunkptr t;
  bindex_t idx;
  compute_tree_index(nb, idx);
    7a4a:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    7a51:	48 c1 e8 08          	shr    $0x8,%rax
    7a55:	89 85 14 ff ff ff    	mov    %eax,-0xec(%rbp)
    7a5b:	83 bd 14 ff ff ff 00 	cmpl   $0x0,-0xec(%rbp)
    7a62:	75 0c                	jne    7a70 <tmalloc_large+0x5b>
    7a64:	c7 85 0c ff ff ff 00 	movl   $0x0,-0xf4(%rbp)
    7a6b:	00 00 00 
    7a6e:	eb 5d                	jmp    7acd <tmalloc_large+0xb8>
    7a70:	81 bd 14 ff ff ff ff 	cmpl   $0xffff,-0xec(%rbp)
    7a77:	ff 00 00 
    7a7a:	76 0c                	jbe    7a88 <tmalloc_large+0x73>
    7a7c:	c7 85 0c ff ff ff 1f 	movl   $0x1f,-0xf4(%rbp)
    7a83:	00 00 00 
    7a86:	eb 45                	jmp    7acd <tmalloc_large+0xb8>
    7a88:	0f bd 85 14 ff ff ff 	bsr    -0xec(%rbp),%eax
    7a8f:	83 f0 1f             	xor    $0x1f,%eax
    7a92:	ba 1f 00 00 00       	mov    $0x1f,%edx
    7a97:	29 c2                	sub    %eax,%edx
    7a99:	89 d0                	mov    %edx,%eax
    7a9b:	89 85 18 ff ff ff    	mov    %eax,-0xe8(%rbp)
    7aa1:	8b 85 18 ff ff ff    	mov    -0xe8(%rbp),%eax
    7aa7:	8d 34 00             	lea    (%rax,%rax,1),%esi
    7aaa:	8b 85 18 ff ff ff    	mov    -0xe8(%rbp),%eax
    7ab0:	83 c0 07             	add    $0x7,%eax
    7ab3:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    7aba:	89 c1                	mov    %eax,%ecx
    7abc:	48 d3 ea             	shr    %cl,%rdx
    7abf:	48 89 d0             	mov    %rdx,%rax
    7ac2:	83 e0 01             	and    $0x1,%eax
    7ac5:	01 f0                	add    %esi,%eax
    7ac7:	89 85 0c ff ff ff    	mov    %eax,-0xf4(%rbp)
  if ((t = *treebin_at(m, idx)) != 0) {
    7acd:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    7ad4:	8b 95 0c ff ff ff    	mov    -0xf4(%rbp),%edx
    7ada:	48 83 c2 4a          	add    $0x4a,%rdx
    7ade:	48 8b 44 d0 08       	mov    0x8(%rax,%rdx,8),%rax
    7ae3:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    7aea:	48 83 bd 48 ff ff ff 	cmpq   $0x0,-0xb8(%rbp)
    7af1:	00 
    7af2:	0f 84 05 01 00 00    	je     7bfd <tmalloc_large+0x1e8>
    /* Traverse tree for this bin looking for node with size == nb */
    size_t sizebits = nb << leftshift_for_tree_index(idx);
    7af8:	83 bd 0c ff ff ff 1f 	cmpl   $0x1f,-0xf4(%rbp)
    7aff:	74 13                	je     7b14 <tmalloc_large+0xff>
    7b01:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    7b07:	d1 e8                	shr    %eax
    7b09:	ba 39 00 00 00       	mov    $0x39,%edx
    7b0e:	29 c2                	sub    %eax,%edx
    7b10:	89 d0                	mov    %edx,%eax
    7b12:	eb 05                	jmp    7b19 <tmalloc_large+0x104>
    7b14:	b8 00 00 00 00       	mov    $0x0,%eax
    7b19:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    7b20:	89 c1                	mov    %eax,%ecx
    7b22:	48 d3 e2             	shl    %cl,%rdx
    7b25:	48 89 d0             	mov    %rdx,%rax
    7b28:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    tchunkptr rst = 0;  /* The deepest untaken right subtree */
    7b2f:	48 c7 85 58 ff ff ff 	movq   $0x0,-0xa8(%rbp)
    7b36:	00 00 00 00 
    for (;;) {
      tchunkptr rt;
      size_t trem = chunksize(t) - nb;
    7b3a:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7b41:	48 8b 40 08          	mov    0x8(%rax),%rax
    7b45:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    7b49:	48 2b 85 f0 fe ff ff 	sub    -0x110(%rbp),%rax
    7b50:	48 89 45 90          	mov    %rax,-0x70(%rbp)
      if (trem < rsize) {
    7b54:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    7b58:	48 3b 85 40 ff ff ff 	cmp    -0xc0(%rbp),%rax
    7b5f:	73 23                	jae    7b84 <tmalloc_large+0x16f>
        v = t;
    7b61:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7b68:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
        if ((rsize = trem) == 0)
    7b6f:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    7b73:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
    7b7a:	48 83 bd 40 ff ff ff 	cmpq   $0x0,-0xc0(%rbp)
    7b81:	00 
    7b82:	74 78                	je     7bfc <tmalloc_large+0x1e7>
          break;
      }
      rt = t->child[1];
    7b84:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7b8b:	48 8b 40 28          	mov    0x28(%rax),%rax
    7b8f:	48 89 45 98          	mov    %rax,-0x68(%rbp)
      t = t->child[(sizebits >> (SIZE_T_BITSIZE-SIZE_T_ONE)) & 1];
    7b93:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    7b9a:	48 c1 e8 3f          	shr    $0x3f,%rax
    7b9e:	48 89 c2             	mov    %rax,%rdx
    7ba1:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7ba8:	48 83 c2 04          	add    $0x4,%rdx
    7bac:	48 8b 04 d0          	mov    (%rax,%rdx,8),%rax
    7bb0:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
      if (rt != 0 && rt != t)
    7bb7:	48 83 7d 98 00       	cmpq   $0x0,-0x68(%rbp)
    7bbc:	74 18                	je     7bd6 <tmalloc_large+0x1c1>
    7bbe:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    7bc2:	48 3b 85 48 ff ff ff 	cmp    -0xb8(%rbp),%rax
    7bc9:	74 0b                	je     7bd6 <tmalloc_large+0x1c1>
        rst = rt;
    7bcb:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    7bcf:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
      if (t == 0) {
    7bd6:	48 83 bd 48 ff ff ff 	cmpq   $0x0,-0xb8(%rbp)
    7bdd:	00 
    7bde:	75 10                	jne    7bf0 <tmalloc_large+0x1db>
        t = rst; /* set t to least subtree holding sizes > nb */
    7be0:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    7be7:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
        break;
    7bee:	eb 0d                	jmp    7bfd <tmalloc_large+0x1e8>
      }
      sizebits <<= 1;
    7bf0:	48 d1 a5 50 ff ff ff 	shlq   -0xb0(%rbp)
    for (;;) {
    7bf7:	e9 3e ff ff ff       	jmpq   7b3a <tmalloc_large+0x125>
          break;
    7bfc:	90                   	nop
    }
  }
  if (t == 0 && v == 0) { /* set t to root of next non-empty treebin */
    7bfd:	48 83 bd 48 ff ff ff 	cmpq   $0x0,-0xb8(%rbp)
    7c04:	00 
    7c05:	0f 85 14 01 00 00    	jne    7d1f <tmalloc_large+0x30a>
    7c0b:	48 83 bd 38 ff ff ff 	cmpq   $0x0,-0xc8(%rbp)
    7c12:	00 
    7c13:	0f 85 06 01 00 00    	jne    7d1f <tmalloc_large+0x30a>
    binmap_t leftbits = left_bits(idx2bit(idx)) & m->treemap;
    7c19:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    7c1f:	ba 01 00 00 00       	mov    $0x1,%edx
    7c24:	89 c1                	mov    %eax,%ecx
    7c26:	d3 e2                	shl    %cl,%edx
    7c28:	89 d0                	mov    %edx,%eax
    7c2a:	8d 14 00             	lea    (%rax,%rax,1),%edx
    7c2d:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    7c33:	be 01 00 00 00       	mov    $0x1,%esi
    7c38:	89 c1                	mov    %eax,%ecx
    7c3a:	d3 e6                	shl    %cl,%esi
    7c3c:	89 f0                	mov    %esi,%eax
    7c3e:	01 c0                	add    %eax,%eax
    7c40:	f7 d8                	neg    %eax
    7c42:	09 c2                	or     %eax,%edx
    7c44:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    7c4b:	8b 40 04             	mov    0x4(%rax),%eax
    7c4e:	21 d0                	and    %edx,%eax
    7c50:	89 85 1c ff ff ff    	mov    %eax,-0xe4(%rbp)
    if (leftbits != 0) {
    7c56:	83 bd 1c ff ff ff 00 	cmpl   $0x0,-0xe4(%rbp)
    7c5d:	0f 84 bc 00 00 00    	je     7d1f <tmalloc_large+0x30a>
      bindex_t i;
      binmap_t leastbit = least_bit(leftbits);
    7c63:	8b 85 1c ff ff ff    	mov    -0xe4(%rbp),%eax
    7c69:	f7 d8                	neg    %eax
    7c6b:	23 85 1c ff ff ff    	and    -0xe4(%rbp),%eax
    7c71:	89 85 20 ff ff ff    	mov    %eax,-0xe0(%rbp)
      compute_bit2idx(leastbit, i);
    7c77:	f3 0f bc 85 20 ff ff 	tzcnt  -0xe0(%rbp),%eax
    7c7e:	ff 
    7c7f:	89 85 24 ff ff ff    	mov    %eax,-0xdc(%rbp)
    7c85:	8b 85 24 ff ff ff    	mov    -0xdc(%rbp),%eax
    7c8b:	89 85 28 ff ff ff    	mov    %eax,-0xd8(%rbp)
      t = *treebin_at(m, i);
    7c91:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    7c98:	8b 95 28 ff ff ff    	mov    -0xd8(%rbp),%edx
    7c9e:	48 83 c2 4a          	add    $0x4a,%rdx
    7ca2:	48 8b 44 d0 08       	mov    0x8(%rax,%rdx,8),%rax
    7ca7:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    }
  }

  while (t != 0) { /* find smallest of tree or subtree */
    7cae:	eb 6f                	jmp    7d1f <tmalloc_large+0x30a>
    size_t trem = chunksize(t) - nb;
    7cb0:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7cb7:	48 8b 40 08          	mov    0x8(%rax),%rax
    7cbb:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    7cbf:	48 2b 85 f0 fe ff ff 	sub    -0x110(%rbp),%rax
    7cc6:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if (trem < rsize) {
    7cca:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    7cce:	48 3b 85 40 ff ff ff 	cmp    -0xc0(%rbp),%rax
    7cd5:	73 19                	jae    7cf0 <tmalloc_large+0x2db>
      rsize = trem;
    7cd7:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    7cdb:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
      v = t;
    7ce2:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7ce9:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
    }
    t = leftmost_child(t);
    7cf0:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7cf7:	48 8b 40 20          	mov    0x20(%rax),%rax
    7cfb:	48 85 c0             	test   %rax,%rax
    7cfe:	74 0d                	je     7d0d <tmalloc_large+0x2f8>
    7d00:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7d07:	48 8b 40 20          	mov    0x20(%rax),%rax
    7d0b:	eb 0b                	jmp    7d18 <tmalloc_large+0x303>
    7d0d:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7d14:	48 8b 40 28          	mov    0x28(%rax),%rax
    7d18:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
  while (t != 0) { /* find smallest of tree or subtree */
    7d1f:	48 83 bd 48 ff ff ff 	cmpq   $0x0,-0xb8(%rbp)
    7d26:	00 
    7d27:	75 87                	jne    7cb0 <tmalloc_large+0x29b>
  }

  /*  If dv is a better fit, return 0 so malloc will use it */
  if (v != 0 && rsize < (size_t)(m->dvsize - nb)) {
    7d29:	48 83 bd 38 ff ff ff 	cmpq   $0x0,-0xc8(%rbp)
    7d30:	00 
    7d31:	0f 84 41 09 00 00    	je     8678 <tmalloc_large+0xc63>
    7d37:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    7d3e:	48 8b 40 08          	mov    0x8(%rax),%rax
    7d42:	48 2b 85 f0 fe ff ff 	sub    -0x110(%rbp),%rax
    7d49:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    7d50:	0f 83 22 09 00 00    	jae    8678 <tmalloc_large+0xc63>
    if (RTCHECK(ok_address(m, v))) { /* split */
    7d56:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    7d5d:	48 8b 40 18          	mov    0x18(%rax),%rax
    7d61:	48 39 85 38 ff ff ff 	cmp    %rax,-0xc8(%rbp)
    7d68:	0f 93 c0             	setae  %al
    7d6b:	0f b6 c0             	movzbl %al,%eax
    7d6e:	48 85 c0             	test   %rax,%rax
    7d71:	0f 84 fc 08 00 00    	je     8673 <tmalloc_large+0xc5e>
      mchunkptr r = chunk_plus_offset(v, nb);
    7d77:	48 8b 95 38 ff ff ff 	mov    -0xc8(%rbp),%rdx
    7d7e:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    7d85:	48 01 d0             	add    %rdx,%rax
    7d88:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
      assert(chunksize(v) == rsize + nb);
    7d8c:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7d93:	48 8b 40 08          	mov    0x8(%rax),%rax
    7d97:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    7d9b:	48 89 c1             	mov    %rax,%rcx
    7d9e:	48 8b 95 40 ff ff ff 	mov    -0xc0(%rbp),%rdx
    7da5:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    7dac:	48 01 d0             	add    %rdx,%rax
    7daf:	48 39 c1             	cmp    %rax,%rcx
    7db2:	74 05                	je     7db9 <tmalloc_large+0x3a4>
    7db4:	e8 a2 4b 00 00       	callq  c95b <abort>
      if (RTCHECK(ok_next(v, r))) {
    7db9:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7dc0:	48 3b 45 a0          	cmp    -0x60(%rbp),%rax
    7dc4:	0f 92 c0             	setb   %al
    7dc7:	0f b6 c0             	movzbl %al,%eax
    7dca:	48 85 c0             	test   %rax,%rax
    7dcd:	0f 84 a0 08 00 00    	je     8673 <tmalloc_large+0xc5e>
        unlink_large_chunk(m, v);
    7dd3:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7dda:	48 8b 40 30          	mov    0x30(%rax),%rax
    7dde:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    7de2:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7de9:	48 8b 40 18          	mov    0x18(%rax),%rax
    7ded:	48 39 85 38 ff ff ff 	cmp    %rax,-0xc8(%rbp)
    7df4:	0f 84 aa 00 00 00    	je     7ea4 <tmalloc_large+0x48f>
    7dfa:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7e01:	48 8b 40 10          	mov    0x10(%rax),%rax
    7e05:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    7e09:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7e10:	48 8b 40 18          	mov    0x18(%rax),%rax
    7e14:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
    7e1b:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    7e22:	48 8b 40 18          	mov    0x18(%rax),%rax
    7e26:	48 39 45 b0          	cmp    %rax,-0x50(%rbp)
    7e2a:	0f 93 c0             	setae  %al
    7e2d:	0f b6 c0             	movzbl %al,%eax
    7e30:	48 85 c0             	test   %rax,%rax
    7e33:	74 21                	je     7e56 <tmalloc_large+0x441>
    7e35:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    7e39:	48 8b 40 18          	mov    0x18(%rax),%rax
    7e3d:	48 39 85 38 ff ff ff 	cmp    %rax,-0xc8(%rbp)
    7e44:	0f 94 c0             	sete   %al
    7e47:	0f b6 c0             	movzbl %al,%eax
    7e4a:	48 85 c0             	test   %rax,%rax
    7e4d:	74 07                	je     7e56 <tmalloc_large+0x441>
    7e4f:	b8 01 00 00 00       	mov    $0x1,%eax
    7e54:	eb 05                	jmp    7e5b <tmalloc_large+0x446>
    7e56:	b8 00 00 00 00       	mov    $0x0,%eax
    7e5b:	85 c0                	test   %eax,%eax
    7e5d:	74 40                	je     7e9f <tmalloc_large+0x48a>
    7e5f:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    7e66:	48 8b 40 10          	mov    0x10(%rax),%rax
    7e6a:	48 39 85 38 ff ff ff 	cmp    %rax,-0xc8(%rbp)
    7e71:	0f 94 c0             	sete   %al
    7e74:	0f b6 c0             	movzbl %al,%eax
    7e77:	48 85 c0             	test   %rax,%rax
    7e7a:	74 23                	je     7e9f <tmalloc_large+0x48a>
    7e7c:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    7e80:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    7e87:	48 89 50 18          	mov    %rdx,0x18(%rax)
    7e8b:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    7e92:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    7e96:	48 89 50 10          	mov    %rdx,0x10(%rax)
    7e9a:	e9 f8 00 00 00       	jmpq   7f97 <tmalloc_large+0x582>
    7e9f:	e8 b7 4a 00 00       	callq  c95b <abort>
    7ea4:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7eab:	48 83 c0 28          	add    $0x28,%rax
    7eaf:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
    7eb6:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    7ebd:	48 8b 00             	mov    (%rax),%rax
    7ec0:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
    7ec7:	48 83 bd 60 ff ff ff 	cmpq   $0x0,-0xa0(%rbp)
    7ece:	00 
    7ecf:	75 52                	jne    7f23 <tmalloc_large+0x50e>
    7ed1:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7ed8:	48 83 c0 20          	add    $0x20,%rax
    7edc:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
    7ee3:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    7eea:	48 8b 00             	mov    (%rax),%rax
    7eed:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
    7ef4:	48 83 bd 60 ff ff ff 	cmpq   $0x0,-0xa0(%rbp)
    7efb:	00 
    7efc:	0f 84 95 00 00 00    	je     7f97 <tmalloc_large+0x582>
    7f02:	eb 1f                	jmp    7f23 <tmalloc_large+0x50e>
    7f04:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    7f0b:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
    7f12:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    7f19:	48 8b 00             	mov    (%rax),%rax
    7f1c:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
    7f23:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    7f2a:	48 83 c0 28          	add    $0x28,%rax
    7f2e:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
    7f35:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    7f3c:	48 8b 00             	mov    (%rax),%rax
    7f3f:	48 85 c0             	test   %rax,%rax
    7f42:	75 c0                	jne    7f04 <tmalloc_large+0x4ef>
    7f44:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    7f4b:	48 83 c0 20          	add    $0x20,%rax
    7f4f:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
    7f56:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    7f5d:	48 8b 00             	mov    (%rax),%rax
    7f60:	48 85 c0             	test   %rax,%rax
    7f63:	75 9f                	jne    7f04 <tmalloc_large+0x4ef>
    7f65:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    7f6c:	48 8b 40 18          	mov    0x18(%rax),%rax
    7f70:	48 39 85 68 ff ff ff 	cmp    %rax,-0x98(%rbp)
    7f77:	0f 93 c0             	setae  %al
    7f7a:	0f b6 c0             	movzbl %al,%eax
    7f7d:	48 85 c0             	test   %rax,%rax
    7f80:	74 10                	je     7f92 <tmalloc_large+0x57d>
    7f82:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    7f89:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    7f90:	eb 05                	jmp    7f97 <tmalloc_large+0x582>
    7f92:	e8 c4 49 00 00       	callq  c95b <abort>
    7f97:	48 83 7d a8 00       	cmpq   $0x0,-0x58(%rbp)
    7f9c:	0f 84 c6 01 00 00    	je     8168 <tmalloc_large+0x753>
    7fa2:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7fa9:	8b 40 38             	mov    0x38(%rax),%eax
    7fac:	89 c0                	mov    %eax,%eax
    7fae:	48 83 c0 4a          	add    $0x4a,%rax
    7fb2:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    7fb9:	00 
    7fba:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    7fc1:	48 01 d0             	add    %rdx,%rax
    7fc4:	48 83 c0 08          	add    $0x8,%rax
    7fc8:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    7fcc:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    7fd0:	48 8b 00             	mov    (%rax),%rax
    7fd3:	48 39 85 38 ff ff ff 	cmp    %rax,-0xc8(%rbp)
    7fda:	75 4d                	jne    8029 <tmalloc_large+0x614>
    7fdc:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    7fe0:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    7fe7:	48 89 10             	mov    %rdx,(%rax)
    7fea:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    7fee:	48 8b 00             	mov    (%rax),%rax
    7ff1:	48 85 c0             	test   %rax,%rax
    7ff4:	0f 85 81 00 00 00    	jne    807b <tmalloc_large+0x666>
    7ffa:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    8001:	8b 50 04             	mov    0x4(%rax),%edx
    8004:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    800b:	8b 40 38             	mov    0x38(%rax),%eax
    800e:	be 01 00 00 00       	mov    $0x1,%esi
    8013:	89 c1                	mov    %eax,%ecx
    8015:	d3 e6                	shl    %cl,%esi
    8017:	89 f0                	mov    %esi,%eax
    8019:	f7 d0                	not    %eax
    801b:	21 c2                	and    %eax,%edx
    801d:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    8024:	89 50 04             	mov    %edx,0x4(%rax)
    8027:	eb 52                	jmp    807b <tmalloc_large+0x666>
    8029:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    8030:	48 8b 40 18          	mov    0x18(%rax),%rax
    8034:	48 39 45 a8          	cmp    %rax,-0x58(%rbp)
    8038:	0f 93 c0             	setae  %al
    803b:	0f b6 c0             	movzbl %al,%eax
    803e:	48 85 c0             	test   %rax,%rax
    8041:	74 33                	je     8076 <tmalloc_large+0x661>
    8043:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8047:	48 8b 40 20          	mov    0x20(%rax),%rax
    804b:	48 39 85 38 ff ff ff 	cmp    %rax,-0xc8(%rbp)
    8052:	75 11                	jne    8065 <tmalloc_large+0x650>
    8054:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8058:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    805f:	48 89 50 20          	mov    %rdx,0x20(%rax)
    8063:	eb 16                	jmp    807b <tmalloc_large+0x666>
    8065:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8069:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    8070:	48 89 50 28          	mov    %rdx,0x28(%rax)
    8074:	eb 05                	jmp    807b <tmalloc_large+0x666>
    8076:	e8 e0 48 00 00       	callq  c95b <abort>
    807b:	48 83 bd 60 ff ff ff 	cmpq   $0x0,-0xa0(%rbp)
    8082:	00 
    8083:	0f 84 df 00 00 00    	je     8168 <tmalloc_large+0x753>
    8089:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    8090:	48 8b 40 18          	mov    0x18(%rax),%rax
    8094:	48 39 85 60 ff ff ff 	cmp    %rax,-0xa0(%rbp)
    809b:	0f 93 c0             	setae  %al
    809e:	0f b6 c0             	movzbl %al,%eax
    80a1:	48 85 c0             	test   %rax,%rax
    80a4:	0f 84 b9 00 00 00    	je     8163 <tmalloc_large+0x74e>
    80aa:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    80b1:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    80b5:	48 89 50 30          	mov    %rdx,0x30(%rax)
    80b9:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    80c0:	48 8b 40 20          	mov    0x20(%rax),%rax
    80c4:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    80c8:	48 83 7d c0 00       	cmpq   $0x0,-0x40(%rbp)
    80cd:	74 3f                	je     810e <tmalloc_large+0x6f9>
    80cf:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    80d6:	48 8b 40 18          	mov    0x18(%rax),%rax
    80da:	48 39 45 c0          	cmp    %rax,-0x40(%rbp)
    80de:	0f 93 c0             	setae  %al
    80e1:	0f b6 c0             	movzbl %al,%eax
    80e4:	48 85 c0             	test   %rax,%rax
    80e7:	74 20                	je     8109 <tmalloc_large+0x6f4>
    80e9:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    80f0:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    80f4:	48 89 50 20          	mov    %rdx,0x20(%rax)
    80f8:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    80fc:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    8103:	48 89 50 30          	mov    %rdx,0x30(%rax)
    8107:	eb 05                	jmp    810e <tmalloc_large+0x6f9>
    8109:	e8 4d 48 00 00       	callq  c95b <abort>
    810e:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    8115:	48 8b 40 28          	mov    0x28(%rax),%rax
    8119:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    811d:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    8122:	74 44                	je     8168 <tmalloc_large+0x753>
    8124:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    812b:	48 8b 40 18          	mov    0x18(%rax),%rax
    812f:	48 39 45 c8          	cmp    %rax,-0x38(%rbp)
    8133:	0f 93 c0             	setae  %al
    8136:	0f b6 c0             	movzbl %al,%eax
    8139:	48 85 c0             	test   %rax,%rax
    813c:	74 20                	je     815e <tmalloc_large+0x749>
    813e:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    8145:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    8149:	48 89 50 28          	mov    %rdx,0x28(%rax)
    814d:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    8151:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    8158:	48 89 50 30          	mov    %rdx,0x30(%rax)
    815c:	eb 0a                	jmp    8168 <tmalloc_large+0x753>
    815e:	e8 f8 47 00 00       	callq  c95b <abort>
    8163:	e8 f3 47 00 00       	callq  c95b <abort>
        if (rsize < MIN_CHUNK_SIZE)
    8168:	48 83 bd 40 ff ff ff 	cmpq   $0x1f,-0xc0(%rbp)
    816f:	1f 
    8170:	0f 87 99 00 00 00    	ja     820f <tmalloc_large+0x7fa>
          set_inuse_and_pinuse(m, v, (rsize + nb));
    8176:	48 8b 95 40 ff ff ff 	mov    -0xc0(%rbp),%rdx
    817d:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    8184:	48 01 d0             	add    %rdx,%rax
    8187:	48 83 c8 03          	or     $0x3,%rax
    818b:	48 89 c2             	mov    %rax,%rdx
    818e:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    8195:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8199:	48 8b 95 40 ff ff ff 	mov    -0xc0(%rbp),%rdx
    81a0:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    81a7:	48 01 c2             	add    %rax,%rdx
    81aa:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    81b1:	48 01 d0             	add    %rdx,%rax
    81b4:	48 8b 50 08          	mov    0x8(%rax),%rdx
    81b8:	48 8b 8d 40 ff ff ff 	mov    -0xc0(%rbp),%rcx
    81bf:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    81c6:	48 01 c1             	add    %rax,%rcx
    81c9:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    81d0:	48 01 c8             	add    %rcx,%rax
    81d3:	48 83 ca 01          	or     $0x1,%rdx
    81d7:	48 89 50 08          	mov    %rdx,0x8(%rax)
    81db:	48 8b 0d 3e 8f 00 00 	mov    0x8f3e(%rip),%rcx        # 11120 <mparams>
    81e2:	48 8b 95 f8 fe ff ff 	mov    -0x108(%rbp),%rdx
    81e9:	48 8b b5 40 ff ff ff 	mov    -0xc0(%rbp),%rsi
    81f0:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    81f7:	48 01 c6             	add    %rax,%rsi
    81fa:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    8201:	48 01 f0             	add    %rsi,%rax
    8204:	48 31 ca             	xor    %rcx,%rdx
    8207:	48 89 10             	mov    %rdx,(%rax)
    820a:	e9 57 04 00 00       	jmpq   8666 <tmalloc_large+0xc51>
        else {
          set_size_and_pinuse_of_inuse_chunk(m, v, nb);
    820f:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    8216:	48 83 c8 03          	or     $0x3,%rax
    821a:	48 89 c2             	mov    %rax,%rdx
    821d:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    8224:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8228:	48 8b 0d f1 8e 00 00 	mov    0x8ef1(%rip),%rcx        # 11120 <mparams>
    822f:	48 8b 95 f8 fe ff ff 	mov    -0x108(%rbp),%rdx
    8236:	48 8b b5 38 ff ff ff 	mov    -0xc8(%rbp),%rsi
    823d:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    8244:	48 01 f0             	add    %rsi,%rax
    8247:	48 31 ca             	xor    %rcx,%rdx
    824a:	48 89 10             	mov    %rdx,(%rax)
          set_size_and_pinuse_of_free_chunk(r, rsize);
    824d:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    8254:	48 83 c8 01          	or     $0x1,%rax
    8258:	48 89 c2             	mov    %rax,%rdx
    825b:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    825f:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8263:	48 8b 55 a0          	mov    -0x60(%rbp),%rdx
    8267:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    826e:	48 01 c2             	add    %rax,%rdx
    8271:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    8278:	48 89 02             	mov    %rax,(%rdx)
          insert_chunk(m, r, rsize);
    827b:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    8282:	48 c1 e8 03          	shr    $0x3,%rax
    8286:	48 83 f8 1f          	cmp    $0x1f,%rax
    828a:	0f 87 0c 01 00 00    	ja     839c <tmalloc_large+0x987>
    8290:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    8297:	48 c1 e8 03          	shr    $0x3,%rax
    829b:	89 85 34 ff ff ff    	mov    %eax,-0xcc(%rbp)
    82a1:	8b 85 34 ff ff ff    	mov    -0xcc(%rbp),%eax
    82a7:	01 c0                	add    %eax,%eax
    82a9:	89 c0                	mov    %eax,%eax
    82ab:	48 83 c0 08          	add    $0x8,%rax
    82af:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    82b6:	00 
    82b7:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    82be:	48 01 d0             	add    %rdx,%rax
    82c1:	48 83 c0 08          	add    $0x8,%rax
    82c5:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    82c9:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    82cd:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
    82d4:	48 83 bd 40 ff ff ff 	cmpq   $0x1f,-0xc0(%rbp)
    82db:	1f 
    82dc:	77 05                	ja     82e3 <tmalloc_large+0x8ce>
    82de:	e8 78 46 00 00       	callq  c95b <abort>
    82e3:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    82ea:	8b 10                	mov    (%rax),%edx
    82ec:	8b 85 34 ff ff ff    	mov    -0xcc(%rbp),%eax
    82f2:	be 01 00 00 00       	mov    $0x1,%esi
    82f7:	89 c1                	mov    %eax,%ecx
    82f9:	d3 e6                	shl    %cl,%esi
    82fb:	89 f0                	mov    %esi,%eax
    82fd:	21 d0                	and    %edx,%eax
    82ff:	85 c0                	test   %eax,%eax
    8301:	75 27                	jne    832a <tmalloc_large+0x915>
    8303:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    830a:	8b 10                	mov    (%rax),%edx
    830c:	8b 85 34 ff ff ff    	mov    -0xcc(%rbp),%eax
    8312:	be 01 00 00 00       	mov    $0x1,%esi
    8317:	89 c1                	mov    %eax,%ecx
    8319:	d3 e6                	shl    %cl,%esi
    831b:	89 f0                	mov    %esi,%eax
    831d:	09 c2                	or     %eax,%edx
    831f:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    8326:	89 10                	mov    %edx,(%rax)
    8328:	eb 37                	jmp    8361 <tmalloc_large+0x94c>
    832a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    832e:	48 8b 50 10          	mov    0x10(%rax),%rdx
    8332:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    8339:	48 8b 40 18          	mov    0x18(%rax),%rax
    833d:	48 39 c2             	cmp    %rax,%rdx
    8340:	0f 93 c0             	setae  %al
    8343:	0f b6 c0             	movzbl %al,%eax
    8346:	48 85 c0             	test   %rax,%rax
    8349:	74 11                	je     835c <tmalloc_large+0x947>
    834b:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    834f:	48 8b 40 10          	mov    0x10(%rax),%rax
    8353:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
    835a:	eb 05                	jmp    8361 <tmalloc_large+0x94c>
    835c:	e8 fa 45 00 00       	callq  c95b <abort>
    8361:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    8365:	48 8b 55 a0          	mov    -0x60(%rbp),%rdx
    8369:	48 89 50 10          	mov    %rdx,0x10(%rax)
    836d:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    8374:	48 8b 55 a0          	mov    -0x60(%rbp),%rdx
    8378:	48 89 50 18          	mov    %rdx,0x18(%rax)
    837c:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    8380:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    8387:	48 89 50 10          	mov    %rdx,0x10(%rax)
    838b:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    838f:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    8393:	48 89 50 18          	mov    %rdx,0x18(%rax)
    8397:	e9 ca 02 00 00       	jmpq   8666 <tmalloc_large+0xc51>
    839c:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    83a0:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    83a4:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    83ab:	48 c1 e8 08          	shr    $0x8,%rax
    83af:	89 85 2c ff ff ff    	mov    %eax,-0xd4(%rbp)
    83b5:	83 bd 2c ff ff ff 00 	cmpl   $0x0,-0xd4(%rbp)
    83bc:	75 0c                	jne    83ca <tmalloc_large+0x9b5>
    83be:	c7 85 10 ff ff ff 00 	movl   $0x0,-0xf0(%rbp)
    83c5:	00 00 00 
    83c8:	eb 5d                	jmp    8427 <tmalloc_large+0xa12>
    83ca:	81 bd 2c ff ff ff ff 	cmpl   $0xffff,-0xd4(%rbp)
    83d1:	ff 00 00 
    83d4:	76 0c                	jbe    83e2 <tmalloc_large+0x9cd>
    83d6:	c7 85 10 ff ff ff 1f 	movl   $0x1f,-0xf0(%rbp)
    83dd:	00 00 00 
    83e0:	eb 45                	jmp    8427 <tmalloc_large+0xa12>
    83e2:	0f bd 85 2c ff ff ff 	bsr    -0xd4(%rbp),%eax
    83e9:	83 f0 1f             	xor    $0x1f,%eax
    83ec:	ba 1f 00 00 00       	mov    $0x1f,%edx
    83f1:	29 c2                	sub    %eax,%edx
    83f3:	89 d0                	mov    %edx,%eax
    83f5:	89 85 30 ff ff ff    	mov    %eax,-0xd0(%rbp)
    83fb:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    8401:	8d 34 00             	lea    (%rax,%rax,1),%esi
    8404:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    840a:	83 c0 07             	add    $0x7,%eax
    840d:	48 8b 95 40 ff ff ff 	mov    -0xc0(%rbp),%rdx
    8414:	89 c1                	mov    %eax,%ecx
    8416:	48 d3 ea             	shr    %cl,%rdx
    8419:	48 89 d0             	mov    %rdx,%rax
    841c:	83 e0 01             	and    $0x1,%eax
    841f:	01 f0                	add    %esi,%eax
    8421:	89 85 10 ff ff ff    	mov    %eax,-0xf0(%rbp)
    8427:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    842d:	48 83 c0 4a          	add    $0x4a,%rax
    8431:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    8438:	00 
    8439:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    8440:	48 01 d0             	add    %rdx,%rax
    8443:	48 83 c0 08          	add    $0x8,%rax
    8447:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    844b:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    844f:	8b 95 10 ff ff ff    	mov    -0xf0(%rbp),%edx
    8455:	89 50 38             	mov    %edx,0x38(%rax)
    8458:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    845c:	48 c7 40 28 00 00 00 	movq   $0x0,0x28(%rax)
    8463:	00 
    8464:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    8468:	48 8b 50 28          	mov    0x28(%rax),%rdx
    846c:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    8470:	48 89 50 20          	mov    %rdx,0x20(%rax)
    8474:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    847b:	8b 50 04             	mov    0x4(%rax),%edx
    847e:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    8484:	be 01 00 00 00       	mov    $0x1,%esi
    8489:	89 c1                	mov    %eax,%ecx
    848b:	d3 e6                	shl    %cl,%esi
    848d:	89 f0                	mov    %esi,%eax
    848f:	21 d0                	and    %edx,%eax
    8491:	85 c0                	test   %eax,%eax
    8493:	75 5f                	jne    84f4 <tmalloc_large+0xadf>
    8495:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    849c:	8b 50 04             	mov    0x4(%rax),%edx
    849f:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    84a5:	be 01 00 00 00       	mov    $0x1,%esi
    84aa:	89 c1                	mov    %eax,%ecx
    84ac:	d3 e6                	shl    %cl,%esi
    84ae:	89 f0                	mov    %esi,%eax
    84b0:	09 c2                	or     %eax,%edx
    84b2:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    84b9:	89 50 04             	mov    %edx,0x4(%rax)
    84bc:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    84c0:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    84c4:	48 89 10             	mov    %rdx,(%rax)
    84c7:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    84cb:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    84cf:	48 89 50 30          	mov    %rdx,0x30(%rax)
    84d3:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    84d7:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    84db:	48 89 50 18          	mov    %rdx,0x18(%rax)
    84df:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    84e3:	48 8b 50 18          	mov    0x18(%rax),%rdx
    84e7:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    84eb:	48 89 50 10          	mov    %rdx,0x10(%rax)
    84ef:	e9 72 01 00 00       	jmpq   8666 <tmalloc_large+0xc51>
    84f4:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    84f8:	48 8b 00             	mov    (%rax),%rax
    84fb:	48 89 45 80          	mov    %rax,-0x80(%rbp)
    84ff:	83 bd 10 ff ff ff 1f 	cmpl   $0x1f,-0xf0(%rbp)
    8506:	74 13                	je     851b <tmalloc_large+0xb06>
    8508:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    850e:	d1 e8                	shr    %eax
    8510:	ba 39 00 00 00       	mov    $0x39,%edx
    8515:	29 c2                	sub    %eax,%edx
    8517:	89 d0                	mov    %edx,%eax
    8519:	eb 05                	jmp    8520 <tmalloc_large+0xb0b>
    851b:	b8 00 00 00 00       	mov    $0x0,%eax
    8520:	48 8b 95 40 ff ff ff 	mov    -0xc0(%rbp),%rdx
    8527:	89 c1                	mov    %eax,%ecx
    8529:	48 d3 e2             	shl    %cl,%rdx
    852c:	48 89 d0             	mov    %rdx,%rax
    852f:	48 89 45 88          	mov    %rax,-0x78(%rbp)
    8533:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8537:	48 8b 40 08          	mov    0x8(%rax),%rax
    853b:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    853f:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    8546:	0f 84 93 00 00 00    	je     85df <tmalloc_large+0xbca>
    854c:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    8550:	48 c1 e8 3f          	shr    $0x3f,%rax
    8554:	48 83 c0 04          	add    $0x4,%rax
    8558:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    855f:	00 
    8560:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8564:	48 01 d0             	add    %rdx,%rax
    8567:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    856b:	48 d1 65 88          	shlq   -0x78(%rbp)
    856f:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    8573:	48 8b 00             	mov    (%rax),%rax
    8576:	48 85 c0             	test   %rax,%rax
    8579:	74 0d                	je     8588 <tmalloc_large+0xb73>
    857b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    857f:	48 8b 00             	mov    (%rax),%rax
    8582:	48 89 45 80          	mov    %rax,-0x80(%rbp)
    8586:	eb ab                	jmp    8533 <tmalloc_large+0xb1e>
    8588:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    858f:	48 8b 40 18          	mov    0x18(%rax),%rax
    8593:	48 39 45 e8          	cmp    %rax,-0x18(%rbp)
    8597:	0f 93 c0             	setae  %al
    859a:	0f b6 c0             	movzbl %al,%eax
    859d:	48 85 c0             	test   %rax,%rax
    85a0:	74 38                	je     85da <tmalloc_large+0xbc5>
    85a2:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    85a6:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    85aa:	48 89 10             	mov    %rdx,(%rax)
    85ad:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    85b1:	48 8b 55 80          	mov    -0x80(%rbp),%rdx
    85b5:	48 89 50 30          	mov    %rdx,0x30(%rax)
    85b9:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    85bd:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    85c1:	48 89 50 18          	mov    %rdx,0x18(%rax)
    85c5:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    85c9:	48 8b 50 18          	mov    0x18(%rax),%rdx
    85cd:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    85d1:	48 89 50 10          	mov    %rdx,0x10(%rax)
    85d5:	e9 8c 00 00 00       	jmpq   8666 <tmalloc_large+0xc51>
    85da:	e8 7c 43 00 00       	callq  c95b <abort>
    85df:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    85e3:	48 8b 40 10          	mov    0x10(%rax),%rax
    85e7:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    85eb:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    85f2:	48 8b 40 18          	mov    0x18(%rax),%rax
    85f6:	48 39 45 80          	cmp    %rax,-0x80(%rbp)
    85fa:	0f 93 c0             	setae  %al
    85fd:	0f b6 c0             	movzbl %al,%eax
    8600:	48 85 c0             	test   %rax,%rax
    8603:	74 5c                	je     8661 <tmalloc_large+0xc4c>
    8605:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    860c:	48 8b 40 18          	mov    0x18(%rax),%rax
    8610:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    8614:	0f 93 c0             	setae  %al
    8617:	0f b6 c0             	movzbl %al,%eax
    861a:	48 85 c0             	test   %rax,%rax
    861d:	74 42                	je     8661 <tmalloc_large+0xc4c>
    861f:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    8623:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    8627:	48 89 50 18          	mov    %rdx,0x18(%rax)
    862b:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    862f:	48 8b 50 18          	mov    0x18(%rax),%rdx
    8633:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8637:	48 89 50 10          	mov    %rdx,0x10(%rax)
    863b:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    863f:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    8643:	48 89 50 10          	mov    %rdx,0x10(%rax)
    8647:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    864b:	48 8b 55 80          	mov    -0x80(%rbp),%rdx
    864f:	48 89 50 18          	mov    %rdx,0x18(%rax)
    8653:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    8657:	48 c7 40 30 00 00 00 	movq   $0x0,0x30(%rax)
    865e:	00 
    865f:	eb 05                	jmp    8666 <tmalloc_large+0xc51>
    8661:	e8 f5 42 00 00       	callq  c95b <abort>
        }
        return chunk2mem(v);
    8666:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    866d:	48 83 c0 10          	add    $0x10,%rax
    8671:	eb 0a                	jmp    867d <tmalloc_large+0xc68>
      }
    }
    CORRUPTION_ERROR_ACTION(m);
    8673:	e8 e3 42 00 00       	callq  c95b <abort>
  }
  return 0;
    8678:	b8 00 00 00 00       	mov    $0x0,%eax
}
    867d:	c9                   	leaveq 
    867e:	c3                   	retq   

000000000000867f <tmalloc_small>:

/* allocate a small request from the best fitting chunk in a treebin */
static void* tmalloc_small(mstate m, size_t nb) {
    867f:	55                   	push   %rbp
    8680:	48 89 e5             	mov    %rsp,%rbp
    8683:	48 81 ec b0 00 00 00 	sub    $0xb0,%rsp
    868a:	48 89 bd 58 ff ff ff 	mov    %rdi,-0xa8(%rbp)
    8691:	48 89 b5 50 ff ff ff 	mov    %rsi,-0xb0(%rbp)
  tchunkptr t, v;
  size_t rsize;
  bindex_t i;
  binmap_t leastbit = least_bit(m->treemap);
    8698:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    869f:	8b 50 04             	mov    0x4(%rax),%edx
    86a2:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    86a9:	8b 40 04             	mov    0x4(%rax),%eax
    86ac:	f7 d8                	neg    %eax
    86ae:	21 d0                	and    %edx,%eax
    86b0:	89 85 68 ff ff ff    	mov    %eax,-0x98(%rbp)
  compute_bit2idx(leastbit, i);
    86b6:	f3 0f bc 85 68 ff ff 	tzcnt  -0x98(%rbp),%eax
    86bd:	ff 
    86be:	89 85 6c ff ff ff    	mov    %eax,-0x94(%rbp)
    86c4:	8b 85 6c ff ff ff    	mov    -0x94(%rbp),%eax
    86ca:	89 85 70 ff ff ff    	mov    %eax,-0x90(%rbp)
  v = t = *treebin_at(m, i);
    86d0:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    86d7:	8b 95 70 ff ff ff    	mov    -0x90(%rbp),%edx
    86dd:	48 83 c2 4a          	add    $0x4a,%rdx
    86e1:	48 8b 44 d0 08       	mov    0x8(%rax,%rdx,8),%rax
    86e6:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
    86ed:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    86f4:	48 89 45 80          	mov    %rax,-0x80(%rbp)
  rsize = chunksize(t) - nb;
    86f8:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    86ff:	48 8b 40 08          	mov    0x8(%rax),%rax
    8703:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    8707:	48 2b 85 50 ff ff ff 	sub    -0xb0(%rbp),%rax
    870e:	48 89 45 88          	mov    %rax,-0x78(%rbp)

  while ((t = leftmost_child(t)) != 0) {
    8712:	eb 37                	jmp    874b <tmalloc_small+0xcc>
    size_t trem = chunksize(t) - nb;
    8714:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    871b:	48 8b 40 08          	mov    0x8(%rax),%rax
    871f:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    8723:	48 2b 85 50 ff ff ff 	sub    -0xb0(%rbp),%rax
    872a:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if (trem < rsize) {
    872e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    8732:	48 3b 45 88          	cmp    -0x78(%rbp),%rax
    8736:	73 13                	jae    874b <tmalloc_small+0xcc>
      rsize = trem;
    8738:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    873c:	48 89 45 88          	mov    %rax,-0x78(%rbp)
      v = t;
    8740:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    8747:	48 89 45 80          	mov    %rax,-0x80(%rbp)
  while ((t = leftmost_child(t)) != 0) {
    874b:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    8752:	48 8b 40 20          	mov    0x20(%rax),%rax
    8756:	48 85 c0             	test   %rax,%rax
    8759:	74 0d                	je     8768 <tmalloc_small+0xe9>
    875b:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    8762:	48 8b 40 20          	mov    0x20(%rax),%rax
    8766:	eb 0b                	jmp    8773 <tmalloc_small+0xf4>
    8768:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    876f:	48 8b 40 28          	mov    0x28(%rax),%rax
    8773:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
    877a:	48 83 bd 78 ff ff ff 	cmpq   $0x0,-0x88(%rbp)
    8781:	00 
    8782:	75 90                	jne    8714 <tmalloc_small+0x95>
    }
  }

  if (RTCHECK(ok_address(m, v))) {
    8784:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    878b:	48 8b 40 18          	mov    0x18(%rax),%rax
    878f:	48 39 45 80          	cmp    %rax,-0x80(%rbp)
    8793:	0f 93 c0             	setae  %al
    8796:	0f b6 c0             	movzbl %al,%eax
    8799:	48 85 c0             	test   %rax,%rax
    879c:	0f 84 8c 05 00 00    	je     8d2e <tmalloc_small+0x6af>
    mchunkptr r = chunk_plus_offset(v, nb);
    87a2:	48 8b 55 80          	mov    -0x80(%rbp),%rdx
    87a6:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    87ad:	48 01 d0             	add    %rdx,%rax
    87b0:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    assert(chunksize(v) == rsize + nb);
    87b4:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    87b8:	48 8b 40 08          	mov    0x8(%rax),%rax
    87bc:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    87c0:	48 89 c1             	mov    %rax,%rcx
    87c3:	48 8b 55 88          	mov    -0x78(%rbp),%rdx
    87c7:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    87ce:	48 01 d0             	add    %rdx,%rax
    87d1:	48 39 c1             	cmp    %rax,%rcx
    87d4:	74 05                	je     87db <tmalloc_small+0x15c>
    87d6:	e8 80 41 00 00       	callq  c95b <abort>
    if (RTCHECK(ok_next(v, r))) {
    87db:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    87df:	48 3b 45 b0          	cmp    -0x50(%rbp),%rax
    87e3:	0f 92 c0             	setb   %al
    87e6:	0f b6 c0             	movzbl %al,%eax
    87e9:	48 85 c0             	test   %rax,%rax
    87ec:	0f 84 3c 05 00 00    	je     8d2e <tmalloc_small+0x6af>
      unlink_large_chunk(m, v);
    87f2:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    87f6:	48 8b 40 30          	mov    0x30(%rax),%rax
    87fa:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    87fe:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8802:	48 8b 40 18          	mov    0x18(%rax),%rax
    8806:	48 39 45 80          	cmp    %rax,-0x80(%rbp)
    880a:	0f 84 92 00 00 00    	je     88a2 <tmalloc_small+0x223>
    8810:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8814:	48 8b 40 10          	mov    0x10(%rax),%rax
    8818:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    881c:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8820:	48 8b 40 18          	mov    0x18(%rax),%rax
    8824:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    8828:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    882f:	48 8b 40 18          	mov    0x18(%rax),%rax
    8833:	48 39 45 c0          	cmp    %rax,-0x40(%rbp)
    8837:	0f 93 c0             	setae  %al
    883a:	0f b6 c0             	movzbl %al,%eax
    883d:	48 85 c0             	test   %rax,%rax
    8840:	74 1e                	je     8860 <tmalloc_small+0x1e1>
    8842:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    8846:	48 8b 40 18          	mov    0x18(%rax),%rax
    884a:	48 39 45 80          	cmp    %rax,-0x80(%rbp)
    884e:	0f 94 c0             	sete   %al
    8851:	0f b6 c0             	movzbl %al,%eax
    8854:	48 85 c0             	test   %rax,%rax
    8857:	74 07                	je     8860 <tmalloc_small+0x1e1>
    8859:	b8 01 00 00 00       	mov    $0x1,%eax
    885e:	eb 05                	jmp    8865 <tmalloc_small+0x1e6>
    8860:	b8 00 00 00 00       	mov    $0x0,%eax
    8865:	85 c0                	test   %eax,%eax
    8867:	74 34                	je     889d <tmalloc_small+0x21e>
    8869:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    886d:	48 8b 40 10          	mov    0x10(%rax),%rax
    8871:	48 39 45 80          	cmp    %rax,-0x80(%rbp)
    8875:	0f 94 c0             	sete   %al
    8878:	0f b6 c0             	movzbl %al,%eax
    887b:	48 85 c0             	test   %rax,%rax
    887e:	74 1d                	je     889d <tmalloc_small+0x21e>
    8880:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    8884:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    8888:	48 89 50 18          	mov    %rdx,0x18(%rax)
    888c:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    8890:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    8894:	48 89 50 10          	mov    %rdx,0x10(%rax)
    8898:	e9 b2 00 00 00       	jmpq   894f <tmalloc_small+0x2d0>
    889d:	e8 b9 40 00 00       	callq  c95b <abort>
    88a2:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    88a6:	48 83 c0 28          	add    $0x28,%rax
    88aa:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    88ae:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    88b2:	48 8b 00             	mov    (%rax),%rax
    88b5:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    88b9:	48 83 7d 90 00       	cmpq   $0x0,-0x70(%rbp)
    88be:	75 33                	jne    88f3 <tmalloc_small+0x274>
    88c0:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    88c4:	48 83 c0 20          	add    $0x20,%rax
    88c8:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    88cc:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    88d0:	48 8b 00             	mov    (%rax),%rax
    88d3:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    88d7:	48 83 7d 90 00       	cmpq   $0x0,-0x70(%rbp)
    88dc:	74 71                	je     894f <tmalloc_small+0x2d0>
    88de:	eb 13                	jmp    88f3 <tmalloc_small+0x274>
    88e0:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    88e4:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    88e8:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    88ec:	48 8b 00             	mov    (%rax),%rax
    88ef:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    88f3:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    88f7:	48 83 c0 28          	add    $0x28,%rax
    88fb:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
    88ff:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    8903:	48 8b 00             	mov    (%rax),%rax
    8906:	48 85 c0             	test   %rax,%rax
    8909:	75 d5                	jne    88e0 <tmalloc_small+0x261>
    890b:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    890f:	48 83 c0 20          	add    $0x20,%rax
    8913:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
    8917:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    891b:	48 8b 00             	mov    (%rax),%rax
    891e:	48 85 c0             	test   %rax,%rax
    8921:	75 bd                	jne    88e0 <tmalloc_small+0x261>
    8923:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    892a:	48 8b 40 18          	mov    0x18(%rax),%rax
    892e:	48 39 45 98          	cmp    %rax,-0x68(%rbp)
    8932:	0f 93 c0             	setae  %al
    8935:	0f b6 c0             	movzbl %al,%eax
    8938:	48 85 c0             	test   %rax,%rax
    893b:	74 0d                	je     894a <tmalloc_small+0x2cb>
    893d:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    8941:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    8948:	eb 05                	jmp    894f <tmalloc_small+0x2d0>
    894a:	e8 0c 40 00 00       	callq  c95b <abort>
    894f:	48 83 7d b8 00       	cmpq   $0x0,-0x48(%rbp)
    8954:	0f 84 92 01 00 00    	je     8aec <tmalloc_small+0x46d>
    895a:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    895e:	8b 40 38             	mov    0x38(%rax),%eax
    8961:	89 c0                	mov    %eax,%eax
    8963:	48 83 c0 4a          	add    $0x4a,%rax
    8967:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    896e:	00 
    896f:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8976:	48 01 d0             	add    %rdx,%rax
    8979:	48 83 c0 08          	add    $0x8,%rax
    897d:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    8981:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    8985:	48 8b 00             	mov    (%rax),%rax
    8988:	48 39 45 80          	cmp    %rax,-0x80(%rbp)
    898c:	75 43                	jne    89d1 <tmalloc_small+0x352>
    898e:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    8992:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    8996:	48 89 10             	mov    %rdx,(%rax)
    8999:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    899d:	48 8b 00             	mov    (%rax),%rax
    89a0:	48 85 c0             	test   %rax,%rax
    89a3:	75 75                	jne    8a1a <tmalloc_small+0x39b>
    89a5:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    89ac:	8b 50 04             	mov    0x4(%rax),%edx
    89af:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    89b3:	8b 40 38             	mov    0x38(%rax),%eax
    89b6:	be 01 00 00 00       	mov    $0x1,%esi
    89bb:	89 c1                	mov    %eax,%ecx
    89bd:	d3 e6                	shl    %cl,%esi
    89bf:	89 f0                	mov    %esi,%eax
    89c1:	f7 d0                	not    %eax
    89c3:	21 c2                	and    %eax,%edx
    89c5:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    89cc:	89 50 04             	mov    %edx,0x4(%rax)
    89cf:	eb 49                	jmp    8a1a <tmalloc_small+0x39b>
    89d1:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    89d8:	48 8b 40 18          	mov    0x18(%rax),%rax
    89dc:	48 39 45 b8          	cmp    %rax,-0x48(%rbp)
    89e0:	0f 93 c0             	setae  %al
    89e3:	0f b6 c0             	movzbl %al,%eax
    89e6:	48 85 c0             	test   %rax,%rax
    89e9:	74 2a                	je     8a15 <tmalloc_small+0x396>
    89eb:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    89ef:	48 8b 40 20          	mov    0x20(%rax),%rax
    89f3:	48 39 45 80          	cmp    %rax,-0x80(%rbp)
    89f7:	75 0e                	jne    8a07 <tmalloc_small+0x388>
    89f9:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    89fd:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    8a01:	48 89 50 20          	mov    %rdx,0x20(%rax)
    8a05:	eb 13                	jmp    8a1a <tmalloc_small+0x39b>
    8a07:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    8a0b:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    8a0f:	48 89 50 28          	mov    %rdx,0x28(%rax)
    8a13:	eb 05                	jmp    8a1a <tmalloc_small+0x39b>
    8a15:	e8 41 3f 00 00       	callq  c95b <abort>
    8a1a:	48 83 7d 90 00       	cmpq   $0x0,-0x70(%rbp)
    8a1f:	0f 84 c7 00 00 00    	je     8aec <tmalloc_small+0x46d>
    8a25:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8a2c:	48 8b 40 18          	mov    0x18(%rax),%rax
    8a30:	48 39 45 90          	cmp    %rax,-0x70(%rbp)
    8a34:	0f 93 c0             	setae  %al
    8a37:	0f b6 c0             	movzbl %al,%eax
    8a3a:	48 85 c0             	test   %rax,%rax
    8a3d:	0f 84 a4 00 00 00    	je     8ae7 <tmalloc_small+0x468>
    8a43:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    8a47:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
    8a4b:	48 89 50 30          	mov    %rdx,0x30(%rax)
    8a4f:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8a53:	48 8b 40 20          	mov    0x20(%rax),%rax
    8a57:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    8a5b:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    8a60:	74 39                	je     8a9b <tmalloc_small+0x41c>
    8a62:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8a69:	48 8b 40 18          	mov    0x18(%rax),%rax
    8a6d:	48 39 45 d0          	cmp    %rax,-0x30(%rbp)
    8a71:	0f 93 c0             	setae  %al
    8a74:	0f b6 c0             	movzbl %al,%eax
    8a77:	48 85 c0             	test   %rax,%rax
    8a7a:	74 1a                	je     8a96 <tmalloc_small+0x417>
    8a7c:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    8a80:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    8a84:	48 89 50 20          	mov    %rdx,0x20(%rax)
    8a88:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    8a8c:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    8a90:	48 89 50 30          	mov    %rdx,0x30(%rax)
    8a94:	eb 05                	jmp    8a9b <tmalloc_small+0x41c>
    8a96:	e8 c0 3e 00 00       	callq  c95b <abort>
    8a9b:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8a9f:	48 8b 40 28          	mov    0x28(%rax),%rax
    8aa3:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    8aa7:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    8aac:	74 3e                	je     8aec <tmalloc_small+0x46d>
    8aae:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8ab5:	48 8b 40 18          	mov    0x18(%rax),%rax
    8ab9:	48 39 45 d8          	cmp    %rax,-0x28(%rbp)
    8abd:	0f 93 c0             	setae  %al
    8ac0:	0f b6 c0             	movzbl %al,%eax
    8ac3:	48 85 c0             	test   %rax,%rax
    8ac6:	74 1a                	je     8ae2 <tmalloc_small+0x463>
    8ac8:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    8acc:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    8ad0:	48 89 50 28          	mov    %rdx,0x28(%rax)
    8ad4:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    8ad8:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    8adc:	48 89 50 30          	mov    %rdx,0x30(%rax)
    8ae0:	eb 0a                	jmp    8aec <tmalloc_small+0x46d>
    8ae2:	e8 74 3e 00 00       	callq  c95b <abort>
    8ae7:	e8 6f 3e 00 00       	callq  c95b <abort>
      if (rsize < MIN_CHUNK_SIZE)
    8aec:	48 83 7d 88 1f       	cmpq   $0x1f,-0x78(%rbp)
    8af1:	0f 87 81 00 00 00    	ja     8b78 <tmalloc_small+0x4f9>
        set_inuse_and_pinuse(m, v, (rsize + nb));
    8af7:	48 8b 55 88          	mov    -0x78(%rbp),%rdx
    8afb:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    8b02:	48 01 d0             	add    %rdx,%rax
    8b05:	48 83 c8 03          	or     $0x3,%rax
    8b09:	48 89 c2             	mov    %rax,%rdx
    8b0c:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8b10:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8b14:	48 8b 55 88          	mov    -0x78(%rbp),%rdx
    8b18:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    8b1f:	48 01 c2             	add    %rax,%rdx
    8b22:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8b26:	48 01 d0             	add    %rdx,%rax
    8b29:	48 8b 50 08          	mov    0x8(%rax),%rdx
    8b2d:	48 8b 4d 88          	mov    -0x78(%rbp),%rcx
    8b31:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    8b38:	48 01 c1             	add    %rax,%rcx
    8b3b:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8b3f:	48 01 c8             	add    %rcx,%rax
    8b42:	48 83 ca 01          	or     $0x1,%rdx
    8b46:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8b4a:	48 8b 0d cf 85 00 00 	mov    0x85cf(%rip),%rcx        # 11120 <mparams>
    8b51:	48 8b 95 58 ff ff ff 	mov    -0xa8(%rbp),%rdx
    8b58:	48 8b 75 88          	mov    -0x78(%rbp),%rsi
    8b5c:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    8b63:	48 01 c6             	add    %rax,%rsi
    8b66:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8b6a:	48 01 f0             	add    %rsi,%rax
    8b6d:	48 31 ca             	xor    %rcx,%rdx
    8b70:	48 89 10             	mov    %rdx,(%rax)
    8b73:	e9 ac 01 00 00       	jmpq   8d24 <tmalloc_small+0x6a5>
      else {
        set_size_and_pinuse_of_inuse_chunk(m, v, nb);
    8b78:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    8b7f:	48 83 c8 03          	or     $0x3,%rax
    8b83:	48 89 c2             	mov    %rax,%rdx
    8b86:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8b8a:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8b8e:	48 8b 0d 8b 85 00 00 	mov    0x858b(%rip),%rcx        # 11120 <mparams>
    8b95:	48 8b 95 58 ff ff ff 	mov    -0xa8(%rbp),%rdx
    8b9c:	48 8b 75 80          	mov    -0x80(%rbp),%rsi
    8ba0:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    8ba7:	48 01 f0             	add    %rsi,%rax
    8baa:	48 31 ca             	xor    %rcx,%rdx
    8bad:	48 89 10             	mov    %rdx,(%rax)
        set_size_and_pinuse_of_free_chunk(r, rsize);
    8bb0:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    8bb4:	48 83 c8 01          	or     $0x1,%rax
    8bb8:	48 89 c2             	mov    %rax,%rdx
    8bbb:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    8bbf:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8bc3:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    8bc7:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    8bcb:	48 01 c2             	add    %rax,%rdx
    8bce:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    8bd2:	48 89 02             	mov    %rax,(%rdx)
        replace_dv(m, r, rsize);
    8bd5:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8bdc:	48 8b 40 08          	mov    0x8(%rax),%rax
    8be0:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    8be4:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    8be8:	48 c1 e8 03          	shr    $0x3,%rax
    8bec:	48 83 f8 1f          	cmp    $0x1f,%rax
    8bf0:	76 05                	jbe    8bf7 <tmalloc_small+0x578>
    8bf2:	e8 64 3d 00 00       	callq  c95b <abort>
    8bf7:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
    8bfc:	0f 84 04 01 00 00    	je     8d06 <tmalloc_small+0x687>
    8c02:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8c09:	48 8b 40 20          	mov    0x20(%rax),%rax
    8c0d:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    8c11:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    8c15:	48 c1 e8 03          	shr    $0x3,%rax
    8c19:	89 85 74 ff ff ff    	mov    %eax,-0x8c(%rbp)
    8c1f:	8b 85 74 ff ff ff    	mov    -0x8c(%rbp),%eax
    8c25:	01 c0                	add    %eax,%eax
    8c27:	89 c0                	mov    %eax,%eax
    8c29:	48 83 c0 08          	add    $0x8,%rax
    8c2d:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    8c34:	00 
    8c35:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8c3c:	48 01 d0             	add    %rdx,%rax
    8c3f:	48 83 c0 08          	add    $0x8,%rax
    8c43:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    8c47:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    8c4b:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    8c4f:	48 83 7d e0 1f       	cmpq   $0x1f,-0x20(%rbp)
    8c54:	77 05                	ja     8c5b <tmalloc_small+0x5dc>
    8c56:	e8 00 3d 00 00       	callq  c95b <abort>
    8c5b:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8c62:	8b 10                	mov    (%rax),%edx
    8c64:	8b 85 74 ff ff ff    	mov    -0x8c(%rbp),%eax
    8c6a:	be 01 00 00 00       	mov    $0x1,%esi
    8c6f:	89 c1                	mov    %eax,%ecx
    8c71:	d3 e6                	shl    %cl,%esi
    8c73:	89 f0                	mov    %esi,%eax
    8c75:	21 d0                	and    %edx,%eax
    8c77:	85 c0                	test   %eax,%eax
    8c79:	75 27                	jne    8ca2 <tmalloc_small+0x623>
    8c7b:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8c82:	8b 10                	mov    (%rax),%edx
    8c84:	8b 85 74 ff ff ff    	mov    -0x8c(%rbp),%eax
    8c8a:	be 01 00 00 00       	mov    $0x1,%esi
    8c8f:	89 c1                	mov    %eax,%ecx
    8c91:	d3 e6                	shl    %cl,%esi
    8c93:	89 f0                	mov    %esi,%eax
    8c95:	09 c2                	or     %eax,%edx
    8c97:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8c9e:	89 10                	mov    %edx,(%rax)
    8ca0:	eb 34                	jmp    8cd6 <tmalloc_small+0x657>
    8ca2:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    8ca6:	48 8b 50 10          	mov    0x10(%rax),%rdx
    8caa:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8cb1:	48 8b 40 18          	mov    0x18(%rax),%rax
    8cb5:	48 39 c2             	cmp    %rax,%rdx
    8cb8:	0f 93 c0             	setae  %al
    8cbb:	0f b6 c0             	movzbl %al,%eax
    8cbe:	48 85 c0             	test   %rax,%rax
    8cc1:	74 0e                	je     8cd1 <tmalloc_small+0x652>
    8cc3:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    8cc7:	48 8b 40 10          	mov    0x10(%rax),%rax
    8ccb:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    8ccf:	eb 05                	jmp    8cd6 <tmalloc_small+0x657>
    8cd1:	e8 85 3c 00 00       	callq  c95b <abort>
    8cd6:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    8cda:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    8cde:	48 89 50 10          	mov    %rdx,0x10(%rax)
    8ce2:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8ce6:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    8cea:	48 89 50 18          	mov    %rdx,0x18(%rax)
    8cee:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    8cf2:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    8cf6:	48 89 50 10          	mov    %rdx,0x10(%rax)
    8cfa:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    8cfe:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    8d02:	48 89 50 18          	mov    %rdx,0x18(%rax)
    8d06:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8d0d:	48 8b 55 88          	mov    -0x78(%rbp),%rdx
    8d11:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8d15:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8d1c:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    8d20:	48 89 50 20          	mov    %rdx,0x20(%rax)
      }
      return chunk2mem(v);
    8d24:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8d28:	48 83 c0 10          	add    $0x10,%rax
    8d2c:	eb 05                	jmp    8d33 <tmalloc_small+0x6b4>
    }
  }

  CORRUPTION_ERROR_ACTION(m);
    8d2e:	e8 28 3c 00 00       	callq  c95b <abort>
  return 0;
}
    8d33:	c9                   	leaveq 
    8d34:	c3                   	retq   

0000000000008d35 <dlmalloc>:

#if !ONLY_MSPACES

void* dlmalloc(size_t bytes) {
    8d35:	55                   	push   %rbp
    8d36:	48 89 e5             	mov    %rsp,%rbp
    8d39:	53                   	push   %rbx
    8d3a:	48 81 ec e8 00 00 00 	sub    $0xe8,%rsp
    8d41:	48 89 bd 18 ff ff ff 	mov    %rdi,-0xe8(%rbp)

     The ugly goto's here ensure that postaction occurs along all paths.
  */

#if USE_LOCKS
  ensure_initialization(); /* initialize in sys_alloc if not using locks */
    8d48:	48 8b 05 d1 83 00 00 	mov    0x83d1(%rip),%rax        # 11120 <mparams>
    8d4f:	48 85 c0             	test   %rax,%rax
    8d52:	75 07                	jne    8d5b <dlmalloc+0x26>
    8d54:	e8 c7 c5 ff ff       	callq  5320 <init_mparams>
    8d59:	85 c0                	test   %eax,%eax
    8d5b:	90                   	nop
#endif

  if (!PREACTION(gm)) {
    8d5c:	8b 05 6e 87 00 00    	mov    0x876e(%rip),%eax        # 114d0 <_gm_+0x370>
    8d62:	83 e0 02             	and    $0x2,%eax
    8d65:	85 c0                	test   %eax,%eax
    8d67:	74 23                	je     8d8c <dlmalloc+0x57>
    8d69:	b8 01 00 00 00       	mov    $0x1,%eax
    8d6e:	87 05 60 87 00 00    	xchg   %eax,0x8760(%rip)        # 114d4 <_gm_+0x374>
    8d74:	85 c0                	test   %eax,%eax
    8d76:	74 14                	je     8d8c <dlmalloc+0x57>
    8d78:	48 8d 3d 55 87 00 00 	lea    0x8755(%rip),%rdi        # 114d4 <_gm_+0x374>
    8d7f:	e8 08 c5 ff ff       	callq  528c <spin_acquire_lock>
    8d84:	85 c0                	test   %eax,%eax
    8d86:	0f 85 91 0a 00 00    	jne    981d <dlmalloc+0xae8>
    void* mem;
    size_t nb;
    if (bytes <= MAX_SMALL_REQUEST) {
    8d8c:	48 81 bd 18 ff ff ff 	cmpq   $0xe0,-0xe8(%rbp)
    8d93:	e0 00 00 00 
    8d97:	0f 87 12 07 00 00    	ja     94af <dlmalloc+0x77a>
      bindex_t idx;
      binmap_t smallbits;
      nb = (bytes < MIN_REQUEST)? MIN_CHUNK_SIZE : pad_request(bytes);
    8d9d:	48 83 bd 18 ff ff ff 	cmpq   $0xe,-0xe8(%rbp)
    8da4:	0e 
    8da5:	76 11                	jbe    8db8 <dlmalloc+0x83>
    8da7:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    8dae:	48 83 c0 1f          	add    $0x1f,%rax
    8db2:	48 83 e0 f0          	and    $0xfffffffffffffff0,%rax
    8db6:	eb 05                	jmp    8dbd <dlmalloc+0x88>
    8db8:	b8 20 00 00 00       	mov    $0x20,%eax
    8dbd:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
      idx = small_index(nb);
    8dc4:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    8dcb:	48 c1 e8 03          	shr    $0x3,%rax
    8dcf:	89 85 2c ff ff ff    	mov    %eax,-0xd4(%rbp)
      smallbits = gm->smallmap >> idx;
    8dd5:	8b 15 85 83 00 00    	mov    0x8385(%rip),%edx        # 11160 <_gm_>
    8ddb:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8de1:	89 c1                	mov    %eax,%ecx
    8de3:	d3 ea                	shr    %cl,%edx
    8de5:	89 d0                	mov    %edx,%eax
    8de7:	89 85 30 ff ff ff    	mov    %eax,-0xd0(%rbp)

      if ((smallbits & 0x3U) != 0) { /* Remainderless fit to a smallbin. */
    8ded:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    8df3:	83 e0 03             	and    $0x3,%eax
    8df6:	85 c0                	test   %eax,%eax
    8df8:	0f 84 d3 01 00 00    	je     8fd1 <dlmalloc+0x29c>
        mchunkptr b, p;
        idx += ~smallbits & 1;       /* Uses next bin if idx empty */
    8dfe:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    8e04:	83 e0 01             	and    $0x1,%eax
    8e07:	85 c0                	test   %eax,%eax
    8e09:	0f 94 c0             	sete   %al
    8e0c:	0f b6 c0             	movzbl %al,%eax
    8e0f:	01 85 2c ff ff ff    	add    %eax,-0xd4(%rbp)
        b = smallbin_at(gm, idx);
    8e15:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8e1b:	01 c0                	add    %eax,%eax
    8e1d:	89 c0                	mov    %eax,%eax
    8e1f:	48 83 c0 08          	add    $0x8,%rax
    8e23:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    8e2a:	00 
    8e2b:	48 8d 05 2e 83 00 00 	lea    0x832e(%rip),%rax        # 11160 <_gm_>
    8e32:	48 01 d0             	add    %rdx,%rax
    8e35:	48 83 c0 08          	add    $0x8,%rax
    8e39:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
        p = b->fd;
    8e3d:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    8e41:	48 8b 40 10          	mov    0x10(%rax),%rax
    8e45:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
        assert(chunksize(p) == small_index2size(idx));
    8e49:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8e4d:	48 8b 40 08          	mov    0x8(%rax),%rax
    8e51:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    8e55:	48 89 c2             	mov    %rax,%rdx
    8e58:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8e5e:	c1 e0 03             	shl    $0x3,%eax
    8e61:	89 c0                	mov    %eax,%eax
    8e63:	48 39 c2             	cmp    %rax,%rdx
    8e66:	74 05                	je     8e6d <dlmalloc+0x138>
    8e68:	e8 ee 3a 00 00       	callq  c95b <abort>
        unlink_first_small_chunk(gm, b, p, idx);
    8e6d:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8e71:	48 8b 40 10          	mov    0x10(%rax),%rax
    8e75:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    8e79:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8e7d:	48 3b 45 a0          	cmp    -0x60(%rbp),%rax
    8e81:	75 05                	jne    8e88 <dlmalloc+0x153>
    8e83:	e8 d3 3a 00 00       	callq  c95b <abort>
    8e88:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8e8c:	48 3b 45 b0          	cmp    -0x50(%rbp),%rax
    8e90:	75 05                	jne    8e97 <dlmalloc+0x162>
    8e92:	e8 c4 3a 00 00       	callq  c95b <abort>
    8e97:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8e9b:	48 8b 40 08          	mov    0x8(%rax),%rax
    8e9f:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    8ea3:	48 89 c2             	mov    %rax,%rdx
    8ea6:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8eac:	c1 e0 03             	shl    $0x3,%eax
    8eaf:	89 c0                	mov    %eax,%eax
    8eb1:	48 39 c2             	cmp    %rax,%rdx
    8eb4:	74 05                	je     8ebb <dlmalloc+0x186>
    8eb6:	e8 a0 3a 00 00       	callq  c95b <abort>
    8ebb:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    8ebf:	48 3b 45 b0          	cmp    -0x50(%rbp),%rax
    8ec3:	75 23                	jne    8ee8 <dlmalloc+0x1b3>
    8ec5:	8b 15 95 82 00 00    	mov    0x8295(%rip),%edx        # 11160 <_gm_>
    8ecb:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8ed1:	be 01 00 00 00       	mov    $0x1,%esi
    8ed6:	89 c1                	mov    %eax,%ecx
    8ed8:	d3 e6                	shl    %cl,%esi
    8eda:	89 f0                	mov    %esi,%eax
    8edc:	f7 d0                	not    %eax
    8ede:	21 d0                	and    %edx,%eax
    8ee0:	89 05 7a 82 00 00    	mov    %eax,0x827a(%rip)        # 11160 <_gm_>
    8ee6:	eb 4c                	jmp    8f34 <dlmalloc+0x1ff>
    8ee8:	48 8b 05 89 82 00 00 	mov    0x8289(%rip),%rax        # 11178 <_gm_+0x18>
    8eef:	48 39 45 b0          	cmp    %rax,-0x50(%rbp)
    8ef3:	0f 93 c0             	setae  %al
    8ef6:	0f b6 c0             	movzbl %al,%eax
    8ef9:	48 85 c0             	test   %rax,%rax
    8efc:	74 31                	je     8f2f <dlmalloc+0x1fa>
    8efe:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    8f02:	48 8b 40 18          	mov    0x18(%rax),%rax
    8f06:	48 39 45 a8          	cmp    %rax,-0x58(%rbp)
    8f0a:	0f 94 c0             	sete   %al
    8f0d:	0f b6 c0             	movzbl %al,%eax
    8f10:	48 85 c0             	test   %rax,%rax
    8f13:	74 1a                	je     8f2f <dlmalloc+0x1fa>
    8f15:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    8f19:	48 8b 55 a0          	mov    -0x60(%rbp),%rdx
    8f1d:	48 89 50 18          	mov    %rdx,0x18(%rax)
    8f21:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    8f25:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    8f29:	48 89 50 10          	mov    %rdx,0x10(%rax)
    8f2d:	eb 05                	jmp    8f34 <dlmalloc+0x1ff>
    8f2f:	e8 27 3a 00 00       	callq  c95b <abort>
        set_inuse_and_pinuse(gm, p, small_index2size(idx));
    8f34:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8f3a:	c1 e0 03             	shl    $0x3,%eax
    8f3d:	83 c8 03             	or     $0x3,%eax
    8f40:	89 c2                	mov    %eax,%edx
    8f42:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8f46:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8f4a:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8f50:	c1 e0 03             	shl    $0x3,%eax
    8f53:	89 c2                	mov    %eax,%edx
    8f55:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8f59:	48 01 d0             	add    %rdx,%rax
    8f5c:	48 8b 50 08          	mov    0x8(%rax),%rdx
    8f60:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8f66:	c1 e0 03             	shl    $0x3,%eax
    8f69:	89 c1                	mov    %eax,%ecx
    8f6b:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8f6f:	48 01 c8             	add    %rcx,%rax
    8f72:	48 83 ca 01          	or     $0x1,%rdx
    8f76:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8f7a:	48 8b 0d 9f 81 00 00 	mov    0x819f(%rip),%rcx        # 11120 <mparams>
    8f81:	48 8d 15 d8 81 00 00 	lea    0x81d8(%rip),%rdx        # 11160 <_gm_>
    8f88:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8f8e:	c1 e0 03             	shl    $0x3,%eax
    8f91:	89 c6                	mov    %eax,%esi
    8f93:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8f97:	48 01 f0             	add    %rsi,%rax
    8f9a:	48 31 ca             	xor    %rcx,%rdx
    8f9d:	48 89 10             	mov    %rdx,(%rax)
        mem = chunk2mem(p);
    8fa0:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8fa4:	48 83 c0 10          	add    $0x10,%rax
    8fa8:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
        check_malloced_chunk(gm, mem, nb);
    8faf:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    8fb6:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    8fbd:	48 89 c6             	mov    %rax,%rsi
    8fc0:	48 8d 3d 99 81 00 00 	lea    0x8199(%rip),%rdi        # 11160 <_gm_>
    8fc7:	e8 67 c8 ff ff       	callq  5833 <do_check_malloced_chunk>
        goto postaction;
    8fcc:	e9 d8 07 00 00       	jmpq   97a9 <dlmalloc+0xa74>
      }

      else if (nb > gm->dvsize) {
    8fd1:	48 8b 05 90 81 00 00 	mov    0x8190(%rip),%rax        # 11168 <_gm_+0x8>
    8fd8:	48 39 85 50 ff ff ff 	cmp    %rax,-0xb0(%rbp)
    8fdf:	0f 86 4d 05 00 00    	jbe    9532 <dlmalloc+0x7fd>
        if (smallbits != 0) { /* Use chunk in next nonempty smallbin */
    8fe5:	83 bd 30 ff ff ff 00 	cmpl   $0x0,-0xd0(%rbp)
    8fec:	0f 84 62 04 00 00    	je     9454 <dlmalloc+0x71f>
          mchunkptr b, p, r;
          size_t rsize;
          bindex_t i;
          binmap_t leftbits = (smallbits << idx) & left_bits(idx2bit(idx));
    8ff2:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8ff8:	8b 95 30 ff ff ff    	mov    -0xd0(%rbp),%edx
    8ffe:	89 c1                	mov    %eax,%ecx
    9000:	d3 e2                	shl    %cl,%edx
    9002:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    9008:	be 01 00 00 00       	mov    $0x1,%esi
    900d:	89 c1                	mov    %eax,%ecx
    900f:	d3 e6                	shl    %cl,%esi
    9011:	89 f0                	mov    %esi,%eax
    9013:	8d 34 00             	lea    (%rax,%rax,1),%esi
    9016:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    901c:	bf 01 00 00 00       	mov    $0x1,%edi
    9021:	89 c1                	mov    %eax,%ecx
    9023:	d3 e7                	shl    %cl,%edi
    9025:	89 f8                	mov    %edi,%eax
    9027:	01 c0                	add    %eax,%eax
    9029:	f7 d8                	neg    %eax
    902b:	09 f0                	or     %esi,%eax
    902d:	21 d0                	and    %edx,%eax
    902f:	89 85 34 ff ff ff    	mov    %eax,-0xcc(%rbp)
          binmap_t leastbit = least_bit(leftbits);
    9035:	8b 85 34 ff ff ff    	mov    -0xcc(%rbp),%eax
    903b:	f7 d8                	neg    %eax
    903d:	23 85 34 ff ff ff    	and    -0xcc(%rbp),%eax
    9043:	89 85 38 ff ff ff    	mov    %eax,-0xc8(%rbp)
          compute_bit2idx(leastbit, i);
    9049:	f3 0f bc 85 38 ff ff 	tzcnt  -0xc8(%rbp),%eax
    9050:	ff 
    9051:	89 85 3c ff ff ff    	mov    %eax,-0xc4(%rbp)
    9057:	8b 85 3c ff ff ff    	mov    -0xc4(%rbp),%eax
    905d:	89 85 40 ff ff ff    	mov    %eax,-0xc0(%rbp)
          b = smallbin_at(gm, i);
    9063:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    9069:	01 c0                	add    %eax,%eax
    906b:	89 c0                	mov    %eax,%eax
    906d:	48 83 c0 08          	add    $0x8,%rax
    9071:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    9078:	00 
    9079:	48 8d 05 e0 80 00 00 	lea    0x80e0(%rip),%rax        # 11160 <_gm_>
    9080:	48 01 d0             	add    %rdx,%rax
    9083:	48 83 c0 08          	add    $0x8,%rax
    9087:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
          p = b->fd;
    908e:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    9095:	48 8b 40 10          	mov    0x10(%rax),%rax
    9099:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
          assert(chunksize(p) == small_index2size(i));
    90a0:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    90a7:	48 8b 40 08          	mov    0x8(%rax),%rax
    90ab:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    90af:	48 89 c2             	mov    %rax,%rdx
    90b2:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    90b8:	c1 e0 03             	shl    $0x3,%eax
    90bb:	89 c0                	mov    %eax,%eax
    90bd:	48 39 c2             	cmp    %rax,%rdx
    90c0:	74 05                	je     90c7 <dlmalloc+0x392>
    90c2:	e8 94 38 00 00       	callq  c95b <abort>
          unlink_first_small_chunk(gm, b, p, i);
    90c7:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    90ce:	48 8b 40 10          	mov    0x10(%rax),%rax
    90d2:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
    90d9:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    90e0:	48 3b 85 60 ff ff ff 	cmp    -0xa0(%rbp),%rax
    90e7:	75 05                	jne    90ee <dlmalloc+0x3b9>
    90e9:	e8 6d 38 00 00       	callq  c95b <abort>
    90ee:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    90f5:	48 3b 85 70 ff ff ff 	cmp    -0x90(%rbp),%rax
    90fc:	75 05                	jne    9103 <dlmalloc+0x3ce>
    90fe:	e8 58 38 00 00       	callq  c95b <abort>
    9103:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    910a:	48 8b 40 08          	mov    0x8(%rax),%rax
    910e:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    9112:	48 89 c2             	mov    %rax,%rdx
    9115:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    911b:	c1 e0 03             	shl    $0x3,%eax
    911e:	89 c0                	mov    %eax,%eax
    9120:	48 39 c2             	cmp    %rax,%rdx
    9123:	74 05                	je     912a <dlmalloc+0x3f5>
    9125:	e8 31 38 00 00       	callq  c95b <abort>
    912a:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    9131:	48 3b 85 70 ff ff ff 	cmp    -0x90(%rbp),%rax
    9138:	75 23                	jne    915d <dlmalloc+0x428>
    913a:	8b 15 20 80 00 00    	mov    0x8020(%rip),%edx        # 11160 <_gm_>
    9140:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    9146:	be 01 00 00 00       	mov    $0x1,%esi
    914b:	89 c1                	mov    %eax,%ecx
    914d:	d3 e6                	shl    %cl,%esi
    914f:	89 f0                	mov    %esi,%eax
    9151:	f7 d0                	not    %eax
    9153:	21 d0                	and    %edx,%eax
    9155:	89 05 05 80 00 00    	mov    %eax,0x8005(%rip)        # 11160 <_gm_>
    915b:	eb 61                	jmp    91be <dlmalloc+0x489>
    915d:	48 8b 05 14 80 00 00 	mov    0x8014(%rip),%rax        # 11178 <_gm_+0x18>
    9164:	48 39 85 70 ff ff ff 	cmp    %rax,-0x90(%rbp)
    916b:	0f 93 c0             	setae  %al
    916e:	0f b6 c0             	movzbl %al,%eax
    9171:	48 85 c0             	test   %rax,%rax
    9174:	74 43                	je     91b9 <dlmalloc+0x484>
    9176:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    917d:	48 8b 40 18          	mov    0x18(%rax),%rax
    9181:	48 39 85 68 ff ff ff 	cmp    %rax,-0x98(%rbp)
    9188:	0f 94 c0             	sete   %al
    918b:	0f b6 c0             	movzbl %al,%eax
    918e:	48 85 c0             	test   %rax,%rax
    9191:	74 26                	je     91b9 <dlmalloc+0x484>
    9193:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    919a:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    91a1:	48 89 50 18          	mov    %rdx,0x18(%rax)
    91a5:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    91ac:	48 8b 95 70 ff ff ff 	mov    -0x90(%rbp),%rdx
    91b3:	48 89 50 10          	mov    %rdx,0x10(%rax)
    91b7:	eb 05                	jmp    91be <dlmalloc+0x489>
    91b9:	e8 9d 37 00 00       	callq  c95b <abort>
          rsize = small_index2size(i) - nb;
    91be:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    91c4:	c1 e0 03             	shl    $0x3,%eax
    91c7:	89 c0                	mov    %eax,%eax
    91c9:	48 2b 85 50 ff ff ff 	sub    -0xb0(%rbp),%rax
    91d0:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
          /* Fit here cannot be remainderless if 4byte sizes */
          if (SIZE_T_SIZE != 4 && rsize < MIN_CHUNK_SIZE)
    91d7:	48 83 bd 78 ff ff ff 	cmpq   $0x1f,-0x88(%rbp)
    91de:	1f 
    91df:	77 7d                	ja     925e <dlmalloc+0x529>
            set_inuse_and_pinuse(gm, p, small_index2size(i));
    91e1:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    91e7:	c1 e0 03             	shl    $0x3,%eax
    91ea:	83 c8 03             	or     $0x3,%eax
    91ed:	89 c2                	mov    %eax,%edx
    91ef:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    91f6:	48 89 50 08          	mov    %rdx,0x8(%rax)
    91fa:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    9200:	c1 e0 03             	shl    $0x3,%eax
    9203:	89 c2                	mov    %eax,%edx
    9205:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    920c:	48 01 d0             	add    %rdx,%rax
    920f:	48 8b 50 08          	mov    0x8(%rax),%rdx
    9213:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    9219:	c1 e0 03             	shl    $0x3,%eax
    921c:	89 c1                	mov    %eax,%ecx
    921e:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    9225:	48 01 c8             	add    %rcx,%rax
    9228:	48 83 ca 01          	or     $0x1,%rdx
    922c:	48 89 50 08          	mov    %rdx,0x8(%rax)
    9230:	48 8b 0d e9 7e 00 00 	mov    0x7ee9(%rip),%rcx        # 11120 <mparams>
    9237:	48 8d 15 22 7f 00 00 	lea    0x7f22(%rip),%rdx        # 11160 <_gm_>
    923e:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    9244:	c1 e0 03             	shl    $0x3,%eax
    9247:	89 c6                	mov    %eax,%esi
    9249:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    9250:	48 01 f0             	add    %rsi,%rax
    9253:	48 31 ca             	xor    %rcx,%rdx
    9256:	48 89 10             	mov    %rdx,(%rax)
    9259:	e9 c2 01 00 00       	jmpq   9420 <dlmalloc+0x6eb>
          else {
            set_size_and_pinuse_of_inuse_chunk(gm, p, nb);
    925e:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    9265:	48 83 c8 03          	or     $0x3,%rax
    9269:	48 89 c2             	mov    %rax,%rdx
    926c:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    9273:	48 89 50 08          	mov    %rdx,0x8(%rax)
    9277:	48 8b 0d a2 7e 00 00 	mov    0x7ea2(%rip),%rcx        # 11120 <mparams>
    927e:	48 8d 15 db 7e 00 00 	lea    0x7edb(%rip),%rdx        # 11160 <_gm_>
    9285:	48 8b b5 68 ff ff ff 	mov    -0x98(%rbp),%rsi
    928c:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    9293:	48 01 f0             	add    %rsi,%rax
    9296:	48 31 ca             	xor    %rcx,%rdx
    9299:	48 89 10             	mov    %rdx,(%rax)
            r = chunk_plus_offset(p, nb);
    929c:	48 8b 95 68 ff ff ff 	mov    -0x98(%rbp),%rdx
    92a3:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    92aa:	48 01 d0             	add    %rdx,%rax
    92ad:	48 89 45 80          	mov    %rax,-0x80(%rbp)
            set_size_and_pinuse_of_free_chunk(r, rsize);
    92b1:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    92b8:	48 83 c8 01          	or     $0x1,%rax
    92bc:	48 89 c2             	mov    %rax,%rdx
    92bf:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    92c3:	48 89 50 08          	mov    %rdx,0x8(%rax)
    92c7:	48 8b 55 80          	mov    -0x80(%rbp),%rdx
    92cb:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    92d2:	48 01 c2             	add    %rax,%rdx
    92d5:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    92dc:	48 89 02             	mov    %rax,(%rdx)
            replace_dv(gm, r, rsize);
    92df:	48 8b 05 82 7e 00 00 	mov    0x7e82(%rip),%rax        # 11168 <_gm_+0x8>
    92e6:	48 89 45 88          	mov    %rax,-0x78(%rbp)
    92ea:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    92ee:	48 c1 e8 03          	shr    $0x3,%rax
    92f2:	48 83 f8 1f          	cmp    $0x1f,%rax
    92f6:	76 05                	jbe    92fd <dlmalloc+0x5c8>
    92f8:	e8 5e 36 00 00       	callq  c95b <abort>
    92fd:	48 83 7d 88 00       	cmpq   $0x0,-0x78(%rbp)
    9302:	0f 84 ff 00 00 00    	je     9407 <dlmalloc+0x6d2>
    9308:	48 8b 05 71 7e 00 00 	mov    0x7e71(%rip),%rax        # 11180 <_gm_+0x20>
    930f:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    9313:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    9317:	48 c1 e8 03          	shr    $0x3,%rax
    931b:	89 85 44 ff ff ff    	mov    %eax,-0xbc(%rbp)
    9321:	8b 85 44 ff ff ff    	mov    -0xbc(%rbp),%eax
    9327:	01 c0                	add    %eax,%eax
    9329:	89 c0                	mov    %eax,%eax
    932b:	48 83 c0 08          	add    $0x8,%rax
    932f:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    9336:	00 
    9337:	48 8d 05 22 7e 00 00 	lea    0x7e22(%rip),%rax        # 11160 <_gm_>
    933e:	48 01 d0             	add    %rdx,%rax
    9341:	48 83 c0 08          	add    $0x8,%rax
    9345:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    9349:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    934d:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
    9354:	48 83 7d 88 1f       	cmpq   $0x1f,-0x78(%rbp)
    9359:	77 05                	ja     9360 <dlmalloc+0x62b>
    935b:	e8 fb 35 00 00       	callq  c95b <abort>
    9360:	8b 15 fa 7d 00 00    	mov    0x7dfa(%rip),%edx        # 11160 <_gm_>
    9366:	8b 85 44 ff ff ff    	mov    -0xbc(%rbp),%eax
    936c:	be 01 00 00 00       	mov    $0x1,%esi
    9371:	89 c1                	mov    %eax,%ecx
    9373:	d3 e6                	shl    %cl,%esi
    9375:	89 f0                	mov    %esi,%eax
    9377:	21 d0                	and    %edx,%eax
    9379:	85 c0                	test   %eax,%eax
    937b:	75 21                	jne    939e <dlmalloc+0x669>
    937d:	8b 15 dd 7d 00 00    	mov    0x7ddd(%rip),%edx        # 11160 <_gm_>
    9383:	8b 85 44 ff ff ff    	mov    -0xbc(%rbp),%eax
    9389:	be 01 00 00 00       	mov    $0x1,%esi
    938e:	89 c1                	mov    %eax,%ecx
    9390:	d3 e6                	shl    %cl,%esi
    9392:	89 f0                	mov    %esi,%eax
    9394:	09 d0                	or     %edx,%eax
    9396:	89 05 c4 7d 00 00    	mov    %eax,0x7dc4(%rip)        # 11160 <_gm_>
    939c:	eb 33                	jmp    93d1 <dlmalloc+0x69c>
    939e:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    93a2:	48 8b 50 10          	mov    0x10(%rax),%rdx
    93a6:	48 8b 05 cb 7d 00 00 	mov    0x7dcb(%rip),%rax        # 11178 <_gm_+0x18>
    93ad:	48 39 c2             	cmp    %rax,%rdx
    93b0:	0f 93 c0             	setae  %al
    93b3:	0f b6 c0             	movzbl %al,%eax
    93b6:	48 85 c0             	test   %rax,%rax
    93b9:	74 11                	je     93cc <dlmalloc+0x697>
    93bb:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    93bf:	48 8b 40 10          	mov    0x10(%rax),%rax
    93c3:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
    93ca:	eb 05                	jmp    93d1 <dlmalloc+0x69c>
    93cc:	e8 8a 35 00 00       	callq  c95b <abort>
    93d1:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    93d5:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    93d9:	48 89 50 10          	mov    %rdx,0x10(%rax)
    93dd:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    93e4:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    93e8:	48 89 50 18          	mov    %rdx,0x18(%rax)
    93ec:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    93f0:	48 8b 95 58 ff ff ff 	mov    -0xa8(%rbp),%rdx
    93f7:	48 89 50 10          	mov    %rdx,0x10(%rax)
    93fb:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    93ff:	48 8b 55 98          	mov    -0x68(%rbp),%rdx
    9403:	48 89 50 18          	mov    %rdx,0x18(%rax)
    9407:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    940e:	48 89 05 53 7d 00 00 	mov    %rax,0x7d53(%rip)        # 11168 <_gm_+0x8>
    9415:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    9419:	48 89 05 60 7d 00 00 	mov    %rax,0x7d60(%rip)        # 11180 <_gm_+0x20>
          }
          mem = chunk2mem(p);
    9420:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    9427:	48 83 c0 10          	add    $0x10,%rax
    942b:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
          check_malloced_chunk(gm, mem, nb);
    9432:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    9439:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    9440:	48 89 c6             	mov    %rax,%rsi
    9443:	48 8d 3d 16 7d 00 00 	lea    0x7d16(%rip),%rdi        # 11160 <_gm_>
    944a:	e8 e4 c3 ff ff       	callq  5833 <do_check_malloced_chunk>
          goto postaction;
    944f:	e9 55 03 00 00       	jmpq   97a9 <dlmalloc+0xa74>
        }

        else if (gm->treemap != 0 && (mem = tmalloc_small(gm, nb)) != 0) {
    9454:	8b 05 0a 7d 00 00    	mov    0x7d0a(%rip),%eax        # 11164 <_gm_+0x4>
    945a:	85 c0                	test   %eax,%eax
    945c:	0f 84 d0 00 00 00    	je     9532 <dlmalloc+0x7fd>
    9462:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    9469:	48 89 c6             	mov    %rax,%rsi
    946c:	48 8d 3d ed 7c 00 00 	lea    0x7ced(%rip),%rdi        # 11160 <_gm_>
    9473:	e8 07 f2 ff ff       	callq  867f <tmalloc_small>
    9478:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    947f:	48 83 bd 48 ff ff ff 	cmpq   $0x0,-0xb8(%rbp)
    9486:	00 
    9487:	0f 84 a5 00 00 00    	je     9532 <dlmalloc+0x7fd>
          check_malloced_chunk(gm, mem, nb);
    948d:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    9494:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    949b:	48 89 c6             	mov    %rax,%rsi
    949e:	48 8d 3d bb 7c 00 00 	lea    0x7cbb(%rip),%rdi        # 11160 <_gm_>
    94a5:	e8 89 c3 ff ff       	callq  5833 <do_check_malloced_chunk>
          goto postaction;
    94aa:	e9 fa 02 00 00       	jmpq   97a9 <dlmalloc+0xa74>
        }
      }
    }
    else if (bytes >= MAX_REQUEST)
    94af:	48 81 bd 18 ff ff ff 	cmpq   $0xffffffffffffff7f,-0xe8(%rbp)
    94b6:	7f ff ff ff 
    94ba:	76 0d                	jbe    94c9 <dlmalloc+0x794>
      nb = MAX_SIZE_T; /* Too big to allocate. Force failure (in sys alloc) */
    94bc:	48 c7 85 50 ff ff ff 	movq   $0xffffffffffffffff,-0xb0(%rbp)
    94c3:	ff ff ff ff 
    94c7:	eb 69                	jmp    9532 <dlmalloc+0x7fd>
    else {
      nb = pad_request(bytes);
    94c9:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    94d0:	48 83 c0 1f          	add    $0x1f,%rax
    94d4:	48 83 e0 f0          	and    $0xfffffffffffffff0,%rax
    94d8:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
      if (gm->treemap != 0 && (mem = tmalloc_large(gm, nb)) != 0) {
    94df:	8b 05 7f 7c 00 00    	mov    0x7c7f(%rip),%eax        # 11164 <_gm_+0x4>
    94e5:	85 c0                	test   %eax,%eax
    94e7:	74 49                	je     9532 <dlmalloc+0x7fd>
    94e9:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    94f0:	48 89 c6             	mov    %rax,%rsi
    94f3:	48 8d 3d 66 7c 00 00 	lea    0x7c66(%rip),%rdi        # 11160 <_gm_>
    94fa:	e8 16 e5 ff ff       	callq  7a15 <tmalloc_large>
    94ff:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    9506:	48 83 bd 48 ff ff ff 	cmpq   $0x0,-0xb8(%rbp)
    950d:	00 
    950e:	74 22                	je     9532 <dlmalloc+0x7fd>
        check_malloced_chunk(gm, mem, nb);
    9510:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    9517:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    951e:	48 89 c6             	mov    %rax,%rsi
    9521:	48 8d 3d 38 7c 00 00 	lea    0x7c38(%rip),%rdi        # 11160 <_gm_>
    9528:	e8 06 c3 ff ff       	callq  5833 <do_check_malloced_chunk>
        goto postaction;
    952d:	e9 77 02 00 00       	jmpq   97a9 <dlmalloc+0xa74>
      }
    }

    if (nb <= gm->dvsize) {
    9532:	48 8b 05 2f 7c 00 00 	mov    0x7c2f(%rip),%rax        # 11168 <_gm_+0x8>
    9539:	48 39 85 50 ff ff ff 	cmp    %rax,-0xb0(%rbp)
    9540:	0f 87 58 01 00 00    	ja     969e <dlmalloc+0x969>
      size_t rsize = gm->dvsize - nb;
    9546:	48 8b 05 1b 7c 00 00 	mov    0x7c1b(%rip),%rax        # 11168 <_gm_+0x8>
    954d:	48 2b 85 50 ff ff ff 	sub    -0xb0(%rbp),%rax
    9554:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
      mchunkptr p = gm->dv;
    9558:	48 8b 05 21 7c 00 00 	mov    0x7c21(%rip),%rax        # 11180 <_gm_+0x20>
    955f:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
      if (rsize >= MIN_CHUNK_SIZE) { /* split dv */
    9563:	48 83 7d d0 1f       	cmpq   $0x1f,-0x30(%rbp)
    9568:	0f 86 8a 00 00 00    	jbe    95f8 <dlmalloc+0x8c3>
        mchunkptr r = gm->dv = chunk_plus_offset(p, nb);
    956e:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    9572:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    9579:	48 01 d0             	add    %rdx,%rax
    957c:	48 89 05 fd 7b 00 00 	mov    %rax,0x7bfd(%rip)        # 11180 <_gm_+0x20>
    9583:	48 8b 05 f6 7b 00 00 	mov    0x7bf6(%rip),%rax        # 11180 <_gm_+0x20>
    958a:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
        gm->dvsize = rsize;
    958e:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    9592:	48 89 05 cf 7b 00 00 	mov    %rax,0x7bcf(%rip)        # 11168 <_gm_+0x8>
        set_size_and_pinuse_of_free_chunk(r, rsize);
    9599:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    959d:	48 83 c8 01          	or     $0x1,%rax
    95a1:	48 89 c2             	mov    %rax,%rdx
    95a4:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    95a8:	48 89 50 08          	mov    %rdx,0x8(%rax)
    95ac:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    95b0:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    95b4:	48 01 c2             	add    %rax,%rdx
    95b7:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    95bb:	48 89 02             	mov    %rax,(%rdx)
        set_size_and_pinuse_of_inuse_chunk(gm, p, nb);
    95be:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    95c5:	48 83 c8 03          	or     $0x3,%rax
    95c9:	48 89 c2             	mov    %rax,%rdx
    95cc:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    95d0:	48 89 50 08          	mov    %rdx,0x8(%rax)
    95d4:	48 8b 0d 45 7b 00 00 	mov    0x7b45(%rip),%rcx        # 11120 <mparams>
    95db:	48 8d 15 7e 7b 00 00 	lea    0x7b7e(%rip),%rdx        # 11160 <_gm_>
    95e2:	48 8b 75 d8          	mov    -0x28(%rbp),%rsi
    95e6:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    95ed:	48 01 f0             	add    %rsi,%rax
    95f0:	48 31 ca             	xor    %rcx,%rdx
    95f3:	48 89 10             	mov    %rdx,(%rax)
    95f6:	eb 75                	jmp    966d <dlmalloc+0x938>
      }
      else { /* exhaust dv */
        size_t dvs = gm->dvsize;
    95f8:	48 8b 05 69 7b 00 00 	mov    0x7b69(%rip),%rax        # 11168 <_gm_+0x8>
    95ff:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
        gm->dvsize = 0;
    9603:	48 c7 05 5a 7b 00 00 	movq   $0x0,0x7b5a(%rip)        # 11168 <_gm_+0x8>
    960a:	00 00 00 00 
        gm->dv = 0;
    960e:	48 c7 05 67 7b 00 00 	movq   $0x0,0x7b67(%rip)        # 11180 <_gm_+0x20>
    9615:	00 00 00 00 
        set_inuse_and_pinuse(gm, p, dvs);
    9619:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    961d:	48 83 c8 03          	or     $0x3,%rax
    9621:	48 89 c2             	mov    %rax,%rdx
    9624:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    9628:	48 89 50 08          	mov    %rdx,0x8(%rax)
    962c:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    9630:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    9634:	48 01 d0             	add    %rdx,%rax
    9637:	48 8b 50 08          	mov    0x8(%rax),%rdx
    963b:	48 8b 4d d8          	mov    -0x28(%rbp),%rcx
    963f:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    9643:	48 01 c8             	add    %rcx,%rax
    9646:	48 83 ca 01          	or     $0x1,%rdx
    964a:	48 89 50 08          	mov    %rdx,0x8(%rax)
    964e:	48 8b 0d cb 7a 00 00 	mov    0x7acb(%rip),%rcx        # 11120 <mparams>
    9655:	48 8d 15 04 7b 00 00 	lea    0x7b04(%rip),%rdx        # 11160 <_gm_>
    965c:	48 8b 75 d8          	mov    -0x28(%rbp),%rsi
    9660:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    9664:	48 01 f0             	add    %rsi,%rax
    9667:	48 31 ca             	xor    %rcx,%rdx
    966a:	48 89 10             	mov    %rdx,(%rax)
      }
      mem = chunk2mem(p);
    966d:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    9671:	48 83 c0 10          	add    $0x10,%rax
    9675:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
      check_malloced_chunk(gm, mem, nb);
    967c:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    9683:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    968a:	48 89 c6             	mov    %rax,%rsi
    968d:	48 8d 3d cc 7a 00 00 	lea    0x7acc(%rip),%rdi        # 11160 <_gm_>
    9694:	e8 9a c1 ff ff       	callq  5833 <do_check_malloced_chunk>
      goto postaction;
    9699:	e9 0b 01 00 00       	jmpq   97a9 <dlmalloc+0xa74>
    }

    else if (nb < gm->topsize) { /* Split top */
    969e:	48 8b 05 cb 7a 00 00 	mov    0x7acb(%rip),%rax        # 11170 <_gm_+0x10>
    96a5:	48 39 85 50 ff ff ff 	cmp    %rax,-0xb0(%rbp)
    96ac:	0f 83 da 00 00 00    	jae    978c <dlmalloc+0xa57>
      size_t rsize = gm->topsize -= nb;
    96b2:	48 8b 05 b7 7a 00 00 	mov    0x7ab7(%rip),%rax        # 11170 <_gm_+0x10>
    96b9:	48 2b 85 50 ff ff ff 	sub    -0xb0(%rbp),%rax
    96c0:	48 89 05 a9 7a 00 00 	mov    %rax,0x7aa9(%rip)        # 11170 <_gm_+0x10>
    96c7:	48 8b 05 a2 7a 00 00 	mov    0x7aa2(%rip),%rax        # 11170 <_gm_+0x10>
    96ce:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
      mchunkptr p = gm->top;
    96d2:	48 8b 05 af 7a 00 00 	mov    0x7aaf(%rip),%rax        # 11188 <_gm_+0x28>
    96d9:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
      mchunkptr r = gm->top = chunk_plus_offset(p, nb);
    96dd:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    96e1:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    96e8:	48 01 d0             	add    %rdx,%rax
    96eb:	48 89 05 96 7a 00 00 	mov    %rax,0x7a96(%rip)        # 11188 <_gm_+0x28>
    96f2:	48 8b 05 8f 7a 00 00 	mov    0x7a8f(%rip),%rax        # 11188 <_gm_+0x28>
    96f9:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
      r->head = rsize | PINUSE_BIT;
    96fd:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    9701:	48 83 c8 01          	or     $0x1,%rax
    9705:	48 89 c2             	mov    %rax,%rdx
    9708:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    970c:	48 89 50 08          	mov    %rdx,0x8(%rax)
      set_size_and_pinuse_of_inuse_chunk(gm, p, nb);
    9710:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    9717:	48 83 c8 03          	or     $0x3,%rax
    971b:	48 89 c2             	mov    %rax,%rdx
    971e:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    9722:	48 89 50 08          	mov    %rdx,0x8(%rax)
    9726:	48 8b 0d f3 79 00 00 	mov    0x79f3(%rip),%rcx        # 11120 <mparams>
    972d:	48 8d 15 2c 7a 00 00 	lea    0x7a2c(%rip),%rdx        # 11160 <_gm_>
    9734:	48 8b 75 c0          	mov    -0x40(%rbp),%rsi
    9738:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    973f:	48 01 f0             	add    %rsi,%rax
    9742:	48 31 ca             	xor    %rcx,%rdx
    9745:	48 89 10             	mov    %rdx,(%rax)
      mem = chunk2mem(p);
    9748:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    974c:	48 83 c0 10          	add    $0x10,%rax
    9750:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
      check_top_chunk(gm, gm->top);
    9757:	48 8b 05 2a 7a 00 00 	mov    0x7a2a(%rip),%rax        # 11188 <_gm_+0x28>
    975e:	48 89 c6             	mov    %rax,%rsi
    9761:	48 8d 3d f8 79 00 00 	lea    0x79f8(%rip),%rdi        # 11160 <_gm_>
    9768:	e8 35 bd ff ff       	callq  54a2 <do_check_top_chunk>
      check_malloced_chunk(gm, mem, nb);
    976d:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    9774:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    977b:	48 89 c6             	mov    %rax,%rsi
    977e:	48 8d 3d db 79 00 00 	lea    0x79db(%rip),%rdi        # 11160 <_gm_>
    9785:	e8 a9 c0 ff ff       	callq  5833 <do_check_malloced_chunk>
      goto postaction;
    978a:	eb 1d                	jmp    97a9 <dlmalloc+0xa74>
    }

    mem = sys_alloc(gm, nb);
    978c:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    9793:	48 89 c6             	mov    %rax,%rsi
    9796:	48 8d 3d c3 79 00 00 	lea    0x79c3(%rip),%rdi        # 11160 <_gm_>
    979d:	e8 e8 d5 ff ff       	callq  6d8a <sys_alloc>
    97a2:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)

  postaction:
    if (mem != 0 && !ok_heap_range(mem, bytes)) ABORT;
    97a9:	48 83 bd 48 ff ff ff 	cmpq   $0x0,-0xb8(%rbp)
    97b0:	00 
    97b1:	74 49                	je     97fc <dlmalloc+0xac7>
    97b3:	e8 cf a0 ff ff       	callq  3887 <get_heap_base>
    97b8:	48 39 85 48 ff ff ff 	cmp    %rax,-0xb8(%rbp)
    97bf:	72 36                	jb     97f7 <dlmalloc+0xac2>
    97c1:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    97c8:	48 f7 d0             	not    %rax
    97cb:	48 39 85 18 ff ff ff 	cmp    %rax,-0xe8(%rbp)
    97d2:	77 23                	ja     97f7 <dlmalloc+0xac2>
    97d4:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    97db:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    97e2:	48 01 d0             	add    %rdx,%rax
    97e5:	48 89 c3             	mov    %rax,%rbx
    97e8:	bf 00 00 00 00       	mov    $0x0,%edi
    97ed:	e8 99 18 00 00       	callq  b08b <sbrk>
    97f2:	48 39 c3             	cmp    %rax,%rbx
    97f5:	76 05                	jbe    97fc <dlmalloc+0xac7>
    97f7:	e8 5f 31 00 00       	callq  c95b <abort>
    POSTACTION(gm);
    97fc:	8b 05 ce 7c 00 00    	mov    0x7cce(%rip),%eax        # 114d0 <_gm_+0x370>
    9802:	83 e0 02             	and    $0x2,%eax
    9805:	85 c0                	test   %eax,%eax
    9807:	74 0b                	je     9814 <dlmalloc+0xadf>
    9809:	b8 00 00 00 00       	mov    $0x0,%eax
    980e:	89 05 c0 7c 00 00    	mov    %eax,0x7cc0(%rip)        # 114d4 <_gm_+0x374>
    return mem;
    9814:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    981b:	eb 05                	jmp    9822 <dlmalloc+0xaed>
  }

  return 0;
    981d:	b8 00 00 00 00       	mov    $0x0,%eax
}
    9822:	48 81 c4 e8 00 00 00 	add    $0xe8,%rsp
    9829:	5b                   	pop    %rbx
    982a:	5d                   	pop    %rbp
    982b:	c3                   	retq   

000000000000982c <dlfree>:

/* ---------------------------- free --------------------------- */

void dlfree(void* mem) {
    982c:	55                   	push   %rbp
    982d:	48 89 e5             	mov    %rsp,%rbp
    9830:	48 81 ec 60 01 00 00 	sub    $0x160,%rsp
    9837:	48 89 bd a8 fe ff ff 	mov    %rdi,-0x158(%rbp)
     Consolidate freed chunks with preceeding or succeeding bordering
     free chunks, if they exist, and then place in a bin.  Intermixed
     with special cases for top, dv, mmapped chunks, and usage errors.
  */

  if (mem != 0) {
    983e:	48 83 bd a8 fe ff ff 	cmpq   $0x0,-0x158(%rbp)
    9845:	00 
    9846:	0f 84 ff 14 00 00    	je     ad4b <dlfree+0x151f>
    mchunkptr p  = mem2chunk(mem);
    984c:	48 8b 85 a8 fe ff ff 	mov    -0x158(%rbp),%rax
    9853:	48 83 e8 10          	sub    $0x10,%rax
    9857:	48 89 85 c8 fe ff ff 	mov    %rax,-0x138(%rbp)
#if FOOTERS
    mstate fm = get_mstate_for(p);
    985e:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9865:	48 8b 40 08          	mov    0x8(%rax),%rax
    9869:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    986d:	48 89 c2             	mov    %rax,%rdx
    9870:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9877:	48 01 d0             	add    %rdx,%rax
    987a:	48 8b 10             	mov    (%rax),%rdx
    987d:	48 8b 05 9c 78 00 00 	mov    0x789c(%rip),%rax        # 11120 <mparams>
    9884:	48 31 d0             	xor    %rdx,%rax
    9887:	48 89 85 20 ff ff ff 	mov    %rax,-0xe0(%rbp)
    if (!ok_magic(fm)) {
    988e:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9895:	48 8b 50 40          	mov    0x40(%rax),%rdx
    9899:	48 8b 05 80 78 00 00 	mov    0x7880(%rip),%rax        # 11120 <mparams>
    98a0:	48 39 c2             	cmp    %rax,%rdx
    98a3:	74 05                	je     98aa <dlfree+0x7e>
      USAGE_ERROR_ACTION(fm, p);
    98a5:	e8 b1 30 00 00       	callq  c95b <abort>
      return;
    }
#else /* FOOTERS */
#define fm gm
#endif /* FOOTERS */
    if (!PREACTION(fm)) {
    98aa:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    98b1:	8b 80 70 03 00 00    	mov    0x370(%rax),%eax
    98b7:	83 e0 02             	and    $0x2,%eax
    98ba:	85 c0                	test   %eax,%eax
    98bc:	74 36                	je     98f4 <dlfree+0xc8>
    98be:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    98c5:	48 8d 90 74 03 00 00 	lea    0x374(%rax),%rdx
    98cc:	b8 01 00 00 00       	mov    $0x1,%eax
    98d1:	87 02                	xchg   %eax,(%rdx)
    98d3:	85 c0                	test   %eax,%eax
    98d5:	74 1d                	je     98f4 <dlfree+0xc8>
    98d7:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    98de:	48 05 74 03 00 00    	add    $0x374,%rax
    98e4:	48 89 c7             	mov    %rax,%rdi
    98e7:	e8 a0 b9 ff ff       	callq  528c <spin_acquire_lock>
    98ec:	85 c0                	test   %eax,%eax
    98ee:	0f 85 57 14 00 00    	jne    ad4b <dlfree+0x151f>
      check_inuse_chunk(fm, p);
    98f4:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    98fb:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9902:	48 89 d6             	mov    %rdx,%rsi
    9905:	48 89 c7             	mov    %rax,%rdi
    9908:	e8 df bc ff ff       	callq  55ec <do_check_inuse_chunk>
      if (RTCHECK(ok_address(fm, p) && ok_inuse(p))) {
    990d:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9914:	48 8b 40 18          	mov    0x18(%rax),%rax
    9918:	48 39 85 c8 fe ff ff 	cmp    %rax,-0x138(%rbp)
    991f:	0f 93 c0             	setae  %al
    9922:	0f b6 c0             	movzbl %al,%eax
    9925:	48 85 c0             	test   %rax,%rax
    9928:	0f 84 e8 13 00 00    	je     ad16 <dlfree+0x14ea>
    992e:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9935:	48 8b 40 08          	mov    0x8(%rax),%rax
    9939:	83 e0 03             	and    $0x3,%eax
    993c:	48 83 f8 01          	cmp    $0x1,%rax
    9940:	0f 95 c0             	setne  %al
    9943:	0f b6 c0             	movzbl %al,%eax
    9946:	48 85 c0             	test   %rax,%rax
    9949:	0f 84 c7 13 00 00    	je     ad16 <dlfree+0x14ea>
        size_t psize = chunksize(p);
    994f:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9956:	48 8b 40 08          	mov    0x8(%rax),%rax
    995a:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    995e:	48 89 85 d0 fe ff ff 	mov    %rax,-0x130(%rbp)
        mchunkptr next = chunk_plus_offset(p, psize);
    9965:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    996c:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    9973:	48 01 d0             	add    %rdx,%rax
    9976:	48 89 85 28 ff ff ff 	mov    %rax,-0xd8(%rbp)
        if (!pinuse(p)) {
    997d:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9984:	48 8b 40 08          	mov    0x8(%rax),%rax
    9988:	83 e0 01             	and    $0x1,%eax
    998b:	48 85 c0             	test   %rax,%rax
    998e:	0f 85 3a 07 00 00    	jne    a0ce <dlfree+0x8a2>
          size_t prevsize = p->prev_foot;
    9994:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    999b:	48 8b 00             	mov    (%rax),%rax
    999e:	48 89 85 30 ff ff ff 	mov    %rax,-0xd0(%rbp)
          if (is_mmapped(p)) {
    99a5:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    99ac:	48 8b 40 08          	mov    0x8(%rax),%rax
    99b0:	83 e0 03             	and    $0x3,%eax
    99b3:	48 85 c0             	test   %rax,%rax
    99b6:	75 21                	jne    99d9 <dlfree+0x1ad>
            psize += prevsize + MMAP_FOOT_PAD;
    99b8:	48 8b 95 30 ff ff ff 	mov    -0xd0(%rbp),%rdx
    99bf:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    99c6:	48 01 d0             	add    %rdx,%rax
    99c9:	48 83 c0 20          	add    $0x20,%rax
    99cd:	48 89 85 d0 fe ff ff 	mov    %rax,-0x130(%rbp)
            if (CALL_MUNMAP((char*)p - prevsize, psize) == 0)
              fm->footprint -= psize;
            goto postaction;
    99d4:	e9 4a 13 00 00       	jmpq   ad23 <dlfree+0x14f7>
          }
          else {
            mchunkptr prev = chunk_minus_offset(p, prevsize);
    99d9:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    99e0:	48 f7 d8             	neg    %rax
    99e3:	48 89 c2             	mov    %rax,%rdx
    99e6:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    99ed:	48 01 d0             	add    %rdx,%rax
    99f0:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
            psize += prevsize;
    99f7:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    99fe:	48 01 85 d0 fe ff ff 	add    %rax,-0x130(%rbp)
            p = prev;
    9a05:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9a0c:	48 89 85 c8 fe ff ff 	mov    %rax,-0x138(%rbp)
            if (RTCHECK(ok_address(fm, prev))) { /* consolidate backward */
    9a13:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9a1a:	48 8b 40 18          	mov    0x18(%rax),%rax
    9a1e:	48 39 85 38 ff ff ff 	cmp    %rax,-0xc8(%rbp)
    9a25:	0f 93 c0             	setae  %al
    9a28:	0f b6 c0             	movzbl %al,%eax
    9a2b:	48 85 c0             	test   %rax,%rax
    9a2e:	0f 84 e5 12 00 00    	je     ad19 <dlfree+0x14ed>
              if (p != fm->dv) {
    9a34:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9a3b:	48 8b 40 20          	mov    0x20(%rax),%rax
    9a3f:	48 39 85 c8 fe ff ff 	cmp    %rax,-0x138(%rbp)
    9a46:	0f 84 06 06 00 00    	je     a052 <dlfree+0x826>
                unlink_chunk(fm, p, prevsize);
    9a4c:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    9a53:	48 c1 e8 03          	shr    $0x3,%rax
    9a57:	48 83 f8 1f          	cmp    $0x1f,%rax
    9a5b:	0f 87 f9 01 00 00    	ja     9c5a <dlfree+0x42e>
    9a61:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9a68:	48 8b 40 10          	mov    0x10(%rax),%rax
    9a6c:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
    9a73:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9a7a:	48 8b 40 18          	mov    0x18(%rax),%rax
    9a7e:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
    9a85:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    9a8c:	48 c1 e8 03          	shr    $0x3,%rax
    9a90:	89 85 b4 fe ff ff    	mov    %eax,-0x14c(%rbp)
    9a96:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9a9d:	48 3b 85 78 ff ff ff 	cmp    -0x88(%rbp),%rax
    9aa4:	75 05                	jne    9aab <dlfree+0x27f>
    9aa6:	e8 b0 2e 00 00       	callq  c95b <abort>
    9aab:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9ab2:	48 3b 85 70 ff ff ff 	cmp    -0x90(%rbp),%rax
    9ab9:	75 05                	jne    9ac0 <dlfree+0x294>
    9abb:	e8 9b 2e 00 00       	callq  c95b <abort>
    9ac0:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9ac7:	48 8b 40 08          	mov    0x8(%rax),%rax
    9acb:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    9acf:	48 89 c2             	mov    %rax,%rdx
    9ad2:	8b 85 b4 fe ff ff    	mov    -0x14c(%rbp),%eax
    9ad8:	c1 e0 03             	shl    $0x3,%eax
    9adb:	89 c0                	mov    %eax,%eax
    9add:	48 39 c2             	cmp    %rax,%rdx
    9ae0:	74 05                	je     9ae7 <dlfree+0x2bb>
    9ae2:	e8 74 2e 00 00       	callq  c95b <abort>
    9ae7:	8b 85 b4 fe ff ff    	mov    -0x14c(%rbp),%eax
    9aed:	01 c0                	add    %eax,%eax
    9aef:	89 c0                	mov    %eax,%eax
    9af1:	48 83 c0 08          	add    $0x8,%rax
    9af5:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    9afc:	00 
    9afd:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9b04:	48 01 d0             	add    %rdx,%rax
    9b07:	48 83 c0 08          	add    $0x8,%rax
    9b0b:	48 39 85 70 ff ff ff 	cmp    %rax,-0x90(%rbp)
    9b12:	0f 94 c0             	sete   %al
    9b15:	0f b6 c0             	movzbl %al,%eax
    9b18:	48 85 c0             	test   %rax,%rax
    9b1b:	75 4e                	jne    9b6b <dlfree+0x33f>
    9b1d:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9b24:	48 8b 40 18          	mov    0x18(%rax),%rax
    9b28:	48 39 85 70 ff ff ff 	cmp    %rax,-0x90(%rbp)
    9b2f:	0f 93 c0             	setae  %al
    9b32:	0f b6 c0             	movzbl %al,%eax
    9b35:	48 85 c0             	test   %rax,%rax
    9b38:	74 24                	je     9b5e <dlfree+0x332>
    9b3a:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    9b41:	48 8b 40 18          	mov    0x18(%rax),%rax
    9b45:	48 39 85 c8 fe ff ff 	cmp    %rax,-0x138(%rbp)
    9b4c:	0f 94 c0             	sete   %al
    9b4f:	0f b6 c0             	movzbl %al,%eax
    9b52:	48 85 c0             	test   %rax,%rax
    9b55:	74 07                	je     9b5e <dlfree+0x332>
    9b57:	b8 01 00 00 00       	mov    $0x1,%eax
    9b5c:	eb 05                	jmp    9b63 <dlfree+0x337>
    9b5e:	b8 00 00 00 00       	mov    $0x0,%eax
    9b63:	85 c0                	test   %eax,%eax
    9b65:	0f 84 ea 00 00 00    	je     9c55 <dlfree+0x429>
    9b6b:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    9b72:	48 3b 85 70 ff ff ff 	cmp    -0x90(%rbp),%rax
    9b79:	75 2c                	jne    9ba7 <dlfree+0x37b>
    9b7b:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9b82:	8b 10                	mov    (%rax),%edx
    9b84:	8b 85 b4 fe ff ff    	mov    -0x14c(%rbp),%eax
    9b8a:	be 01 00 00 00       	mov    $0x1,%esi
    9b8f:	89 c1                	mov    %eax,%ecx
    9b91:	d3 e6                	shl    %cl,%esi
    9b93:	89 f0                	mov    %esi,%eax
    9b95:	f7 d0                	not    %eax
    9b97:	21 c2                	and    %eax,%edx
    9b99:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9ba0:	89 10                	mov    %edx,(%rax)
    9ba2:	e9 27 05 00 00       	jmpq   a0ce <dlfree+0x8a2>
    9ba7:	8b 85 b4 fe ff ff    	mov    -0x14c(%rbp),%eax
    9bad:	01 c0                	add    %eax,%eax
    9baf:	89 c0                	mov    %eax,%eax
    9bb1:	48 83 c0 08          	add    $0x8,%rax
    9bb5:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    9bbc:	00 
    9bbd:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9bc4:	48 01 d0             	add    %rdx,%rax
    9bc7:	48 83 c0 08          	add    $0x8,%rax
    9bcb:	48 39 85 78 ff ff ff 	cmp    %rax,-0x88(%rbp)
    9bd2:	0f 94 c0             	sete   %al
    9bd5:	0f b6 c0             	movzbl %al,%eax
    9bd8:	48 85 c0             	test   %rax,%rax
    9bdb:	75 4a                	jne    9c27 <dlfree+0x3fb>
    9bdd:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9be4:	48 8b 40 18          	mov    0x18(%rax),%rax
    9be8:	48 39 85 78 ff ff ff 	cmp    %rax,-0x88(%rbp)
    9bef:	0f 93 c0             	setae  %al
    9bf2:	0f b6 c0             	movzbl %al,%eax
    9bf5:	48 85 c0             	test   %rax,%rax
    9bf8:	74 24                	je     9c1e <dlfree+0x3f2>
    9bfa:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    9c01:	48 8b 40 10          	mov    0x10(%rax),%rax
    9c05:	48 39 85 c8 fe ff ff 	cmp    %rax,-0x138(%rbp)
    9c0c:	0f 94 c0             	sete   %al
    9c0f:	0f b6 c0             	movzbl %al,%eax
    9c12:	48 85 c0             	test   %rax,%rax
    9c15:	74 07                	je     9c1e <dlfree+0x3f2>
    9c17:	b8 01 00 00 00       	mov    $0x1,%eax
    9c1c:	eb 05                	jmp    9c23 <dlfree+0x3f7>
    9c1e:	b8 00 00 00 00       	mov    $0x0,%eax
    9c23:	85 c0                	test   %eax,%eax
    9c25:	74 29                	je     9c50 <dlfree+0x424>
    9c27:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    9c2e:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    9c35:	48 89 50 18          	mov    %rdx,0x18(%rax)
    9c39:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    9c40:	48 8b 95 70 ff ff ff 	mov    -0x90(%rbp),%rdx
    9c47:	48 89 50 10          	mov    %rdx,0x10(%rax)
    9c4b:	e9 7e 04 00 00       	jmpq   a0ce <dlfree+0x8a2>
    9c50:	e8 06 2d 00 00       	callq  c95b <abort>
    9c55:	e8 01 2d 00 00       	callq  c95b <abort>
    9c5a:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9c61:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
    9c68:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9c6f:	48 8b 40 30          	mov    0x30(%rax),%rax
    9c73:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    9c7a:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9c81:	48 8b 40 18          	mov    0x18(%rax),%rax
    9c85:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    9c8c:	0f 84 b9 00 00 00    	je     9d4b <dlfree+0x51f>
    9c92:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9c99:	48 8b 40 10          	mov    0x10(%rax),%rax
    9c9d:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    9ca4:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9cab:	48 8b 40 18          	mov    0x18(%rax),%rax
    9caf:	48 89 85 d8 fe ff ff 	mov    %rax,-0x128(%rbp)
    9cb6:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9cbd:	48 8b 40 18          	mov    0x18(%rax),%rax
    9cc1:	48 39 85 50 ff ff ff 	cmp    %rax,-0xb0(%rbp)
    9cc8:	0f 93 c0             	setae  %al
    9ccb:	0f b6 c0             	movzbl %al,%eax
    9cce:	48 85 c0             	test   %rax,%rax
    9cd1:	74 24                	je     9cf7 <dlfree+0x4cb>
    9cd3:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    9cda:	48 8b 40 18          	mov    0x18(%rax),%rax
    9cde:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    9ce5:	0f 94 c0             	sete   %al
    9ce8:	0f b6 c0             	movzbl %al,%eax
    9ceb:	48 85 c0             	test   %rax,%rax
    9cee:	74 07                	je     9cf7 <dlfree+0x4cb>
    9cf0:	b8 01 00 00 00       	mov    $0x1,%eax
    9cf5:	eb 05                	jmp    9cfc <dlfree+0x4d0>
    9cf7:	b8 00 00 00 00       	mov    $0x0,%eax
    9cfc:	85 c0                	test   %eax,%eax
    9cfe:	74 46                	je     9d46 <dlfree+0x51a>
    9d00:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    9d07:	48 8b 40 10          	mov    0x10(%rax),%rax
    9d0b:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    9d12:	0f 94 c0             	sete   %al
    9d15:	0f b6 c0             	movzbl %al,%eax
    9d18:	48 85 c0             	test   %rax,%rax
    9d1b:	74 29                	je     9d46 <dlfree+0x51a>
    9d1d:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    9d24:	48 8b 95 d8 fe ff ff 	mov    -0x128(%rbp),%rdx
    9d2b:	48 89 50 18          	mov    %rdx,0x18(%rax)
    9d2f:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    9d36:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    9d3d:	48 89 50 10          	mov    %rdx,0x10(%rax)
    9d41:	e9 f8 00 00 00       	jmpq   9e3e <dlfree+0x612>
    9d46:	e8 10 2c 00 00       	callq  c95b <abort>
    9d4b:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9d52:	48 83 c0 28          	add    $0x28,%rax
    9d56:	48 89 85 e0 fe ff ff 	mov    %rax,-0x120(%rbp)
    9d5d:	48 8b 85 e0 fe ff ff 	mov    -0x120(%rbp),%rax
    9d64:	48 8b 00             	mov    (%rax),%rax
    9d67:	48 89 85 d8 fe ff ff 	mov    %rax,-0x128(%rbp)
    9d6e:	48 83 bd d8 fe ff ff 	cmpq   $0x0,-0x128(%rbp)
    9d75:	00 
    9d76:	75 52                	jne    9dca <dlfree+0x59e>
    9d78:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9d7f:	48 83 c0 20          	add    $0x20,%rax
    9d83:	48 89 85 e0 fe ff ff 	mov    %rax,-0x120(%rbp)
    9d8a:	48 8b 85 e0 fe ff ff 	mov    -0x120(%rbp),%rax
    9d91:	48 8b 00             	mov    (%rax),%rax
    9d94:	48 89 85 d8 fe ff ff 	mov    %rax,-0x128(%rbp)
    9d9b:	48 83 bd d8 fe ff ff 	cmpq   $0x0,-0x128(%rbp)
    9da2:	00 
    9da3:	0f 84 95 00 00 00    	je     9e3e <dlfree+0x612>
    9da9:	eb 1f                	jmp    9dca <dlfree+0x59e>
    9dab:	48 8b 85 e8 fe ff ff 	mov    -0x118(%rbp),%rax
    9db2:	48 89 85 e0 fe ff ff 	mov    %rax,-0x120(%rbp)
    9db9:	48 8b 85 e0 fe ff ff 	mov    -0x120(%rbp),%rax
    9dc0:	48 8b 00             	mov    (%rax),%rax
    9dc3:	48 89 85 d8 fe ff ff 	mov    %rax,-0x128(%rbp)
    9dca:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    9dd1:	48 83 c0 28          	add    $0x28,%rax
    9dd5:	48 89 85 e8 fe ff ff 	mov    %rax,-0x118(%rbp)
    9ddc:	48 8b 85 e8 fe ff ff 	mov    -0x118(%rbp),%rax
    9de3:	48 8b 00             	mov    (%rax),%rax
    9de6:	48 85 c0             	test   %rax,%rax
    9de9:	75 c0                	jne    9dab <dlfree+0x57f>
    9deb:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    9df2:	48 83 c0 20          	add    $0x20,%rax
    9df6:	48 89 85 e8 fe ff ff 	mov    %rax,-0x118(%rbp)
    9dfd:	48 8b 85 e8 fe ff ff 	mov    -0x118(%rbp),%rax
    9e04:	48 8b 00             	mov    (%rax),%rax
    9e07:	48 85 c0             	test   %rax,%rax
    9e0a:	75 9f                	jne    9dab <dlfree+0x57f>
    9e0c:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9e13:	48 8b 40 18          	mov    0x18(%rax),%rax
    9e17:	48 39 85 e0 fe ff ff 	cmp    %rax,-0x120(%rbp)
    9e1e:	0f 93 c0             	setae  %al
    9e21:	0f b6 c0             	movzbl %al,%eax
    9e24:	48 85 c0             	test   %rax,%rax
    9e27:	74 10                	je     9e39 <dlfree+0x60d>
    9e29:	48 8b 85 e0 fe ff ff 	mov    -0x120(%rbp),%rax
    9e30:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    9e37:	eb 05                	jmp    9e3e <dlfree+0x612>
    9e39:	e8 1d 2b 00 00       	callq  c95b <abort>
    9e3e:	48 83 bd 48 ff ff ff 	cmpq   $0x0,-0xb8(%rbp)
    9e45:	00 
    9e46:	0f 84 82 02 00 00    	je     a0ce <dlfree+0x8a2>
    9e4c:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9e53:	8b 40 38             	mov    0x38(%rax),%eax
    9e56:	89 c0                	mov    %eax,%eax
    9e58:	48 83 c0 4a          	add    $0x4a,%rax
    9e5c:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    9e63:	00 
    9e64:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9e6b:	48 01 d0             	add    %rdx,%rax
    9e6e:	48 83 c0 08          	add    $0x8,%rax
    9e72:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
    9e79:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    9e80:	48 8b 00             	mov    (%rax),%rax
    9e83:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    9e8a:	75 53                	jne    9edf <dlfree+0x6b3>
    9e8c:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    9e93:	48 8b 95 d8 fe ff ff 	mov    -0x128(%rbp),%rdx
    9e9a:	48 89 10             	mov    %rdx,(%rax)
    9e9d:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    9ea4:	48 8b 00             	mov    (%rax),%rax
    9ea7:	48 85 c0             	test   %rax,%rax
    9eaa:	0f 85 8d 00 00 00    	jne    9f3d <dlfree+0x711>
    9eb0:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9eb7:	8b 50 04             	mov    0x4(%rax),%edx
    9eba:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9ec1:	8b 40 38             	mov    0x38(%rax),%eax
    9ec4:	be 01 00 00 00       	mov    $0x1,%esi
    9ec9:	89 c1                	mov    %eax,%ecx
    9ecb:	d3 e6                	shl    %cl,%esi
    9ecd:	89 f0                	mov    %esi,%eax
    9ecf:	f7 d0                	not    %eax
    9ed1:	21 c2                	and    %eax,%edx
    9ed3:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9eda:	89 50 04             	mov    %edx,0x4(%rax)
    9edd:	eb 5e                	jmp    9f3d <dlfree+0x711>
    9edf:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9ee6:	48 8b 40 18          	mov    0x18(%rax),%rax
    9eea:	48 39 85 48 ff ff ff 	cmp    %rax,-0xb8(%rbp)
    9ef1:	0f 93 c0             	setae  %al
    9ef4:	0f b6 c0             	movzbl %al,%eax
    9ef7:	48 85 c0             	test   %rax,%rax
    9efa:	74 3c                	je     9f38 <dlfree+0x70c>
    9efc:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    9f03:	48 8b 40 20          	mov    0x20(%rax),%rax
    9f07:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    9f0e:	75 14                	jne    9f24 <dlfree+0x6f8>
    9f10:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    9f17:	48 8b 95 d8 fe ff ff 	mov    -0x128(%rbp),%rdx
    9f1e:	48 89 50 20          	mov    %rdx,0x20(%rax)
    9f22:	eb 19                	jmp    9f3d <dlfree+0x711>
    9f24:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    9f2b:	48 8b 95 d8 fe ff ff 	mov    -0x128(%rbp),%rdx
    9f32:	48 89 50 28          	mov    %rdx,0x28(%rax)
    9f36:	eb 05                	jmp    9f3d <dlfree+0x711>
    9f38:	e8 1e 2a 00 00       	callq  c95b <abort>
    9f3d:	48 83 bd d8 fe ff ff 	cmpq   $0x0,-0x128(%rbp)
    9f44:	00 
    9f45:	0f 84 83 01 00 00    	je     a0ce <dlfree+0x8a2>
    9f4b:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9f52:	48 8b 40 18          	mov    0x18(%rax),%rax
    9f56:	48 39 85 d8 fe ff ff 	cmp    %rax,-0x128(%rbp)
    9f5d:	0f 93 c0             	setae  %al
    9f60:	0f b6 c0             	movzbl %al,%eax
    9f63:	48 85 c0             	test   %rax,%rax
    9f66:	0f 84 e1 00 00 00    	je     a04d <dlfree+0x821>
    9f6c:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    9f73:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    9f7a:	48 89 50 30          	mov    %rdx,0x30(%rax)
    9f7e:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9f85:	48 8b 40 20          	mov    0x20(%rax),%rax
    9f89:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
    9f90:	48 83 bd 60 ff ff ff 	cmpq   $0x0,-0xa0(%rbp)
    9f97:	00 
    9f98:	74 48                	je     9fe2 <dlfree+0x7b6>
    9f9a:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9fa1:	48 8b 40 18          	mov    0x18(%rax),%rax
    9fa5:	48 39 85 60 ff ff ff 	cmp    %rax,-0xa0(%rbp)
    9fac:	0f 93 c0             	setae  %al
    9faf:	0f b6 c0             	movzbl %al,%eax
    9fb2:	48 85 c0             	test   %rax,%rax
    9fb5:	74 26                	je     9fdd <dlfree+0x7b1>
    9fb7:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    9fbe:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    9fc5:	48 89 50 20          	mov    %rdx,0x20(%rax)
    9fc9:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    9fd0:	48 8b 95 d8 fe ff ff 	mov    -0x128(%rbp),%rdx
    9fd7:	48 89 50 30          	mov    %rdx,0x30(%rax)
    9fdb:	eb 05                	jmp    9fe2 <dlfree+0x7b6>
    9fdd:	e8 79 29 00 00       	callq  c95b <abort>
    9fe2:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9fe9:	48 8b 40 28          	mov    0x28(%rax),%rax
    9fed:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
    9ff4:	48 83 bd 68 ff ff ff 	cmpq   $0x0,-0x98(%rbp)
    9ffb:	00 
    9ffc:	0f 84 cc 00 00 00    	je     a0ce <dlfree+0x8a2>
    a002:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a009:	48 8b 40 18          	mov    0x18(%rax),%rax
    a00d:	48 39 85 68 ff ff ff 	cmp    %rax,-0x98(%rbp)
    a014:	0f 93 c0             	setae  %al
    a017:	0f b6 c0             	movzbl %al,%eax
    a01a:	48 85 c0             	test   %rax,%rax
    a01d:	74 29                	je     a048 <dlfree+0x81c>
    a01f:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    a026:	48 8b 95 68 ff ff ff 	mov    -0x98(%rbp),%rdx
    a02d:	48 89 50 28          	mov    %rdx,0x28(%rax)
    a031:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    a038:	48 8b 95 d8 fe ff ff 	mov    -0x128(%rbp),%rdx
    a03f:	48 89 50 30          	mov    %rdx,0x30(%rax)
    a043:	e9 86 00 00 00       	jmpq   a0ce <dlfree+0x8a2>
    a048:	e8 0e 29 00 00       	callq  c95b <abort>
    a04d:	e8 09 29 00 00       	callq  c95b <abort>
              }
              else if ((next->head & INUSE_BITS) == INUSE_BITS) {
    a052:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a059:	48 8b 40 08          	mov    0x8(%rax),%rax
    a05d:	83 e0 03             	and    $0x3,%eax
    a060:	48 83 f8 03          	cmp    $0x3,%rax
    a064:	75 68                	jne    a0ce <dlfree+0x8a2>
                fm->dvsize = psize;
    a066:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a06d:	48 8b 95 d0 fe ff ff 	mov    -0x130(%rbp),%rdx
    a074:	48 89 50 08          	mov    %rdx,0x8(%rax)
                set_free_with_pinuse(p, psize, next);
    a078:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a07f:	48 8b 40 08          	mov    0x8(%rax),%rax
    a083:	48 83 e0 fe          	and    $0xfffffffffffffffe,%rax
    a087:	48 89 c2             	mov    %rax,%rdx
    a08a:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a091:	48 89 50 08          	mov    %rdx,0x8(%rax)
    a095:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a09c:	48 83 c8 01          	or     $0x1,%rax
    a0a0:	48 89 c2             	mov    %rax,%rdx
    a0a3:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    a0aa:	48 89 50 08          	mov    %rdx,0x8(%rax)
    a0ae:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a0b5:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a0bc:	48 01 c2             	add    %rax,%rdx
    a0bf:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a0c6:	48 89 02             	mov    %rax,(%rdx)
                goto postaction;
    a0c9:	e9 55 0c 00 00       	jmpq   ad23 <dlfree+0x14f7>
            else
              goto erroraction;
          }
        }

        if (RTCHECK(ok_next(p, next) && ok_pinuse(next))) {
    a0ce:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    a0d5:	48 3b 85 28 ff ff ff 	cmp    -0xd8(%rbp),%rax
    a0dc:	0f 92 c0             	setb   %al
    a0df:	0f b6 c0             	movzbl %al,%eax
    a0e2:	48 85 c0             	test   %rax,%rax
    a0e5:	0f 84 2b 0c 00 00    	je     ad16 <dlfree+0x14ea>
    a0eb:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a0f2:	48 8b 40 08          	mov    0x8(%rax),%rax
    a0f6:	83 e0 01             	and    $0x1,%eax
    a0f9:	48 85 c0             	test   %rax,%rax
    a0fc:	0f 95 c0             	setne  %al
    a0ff:	0f b6 c0             	movzbl %al,%eax
    a102:	48 85 c0             	test   %rax,%rax
    a105:	0f 84 0b 0c 00 00    	je     ad16 <dlfree+0x14ea>
          if (!cinuse(next)) {  /* consolidate forward */
    a10b:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a112:	48 8b 40 08          	mov    0x8(%rax),%rax
    a116:	83 e0 02             	and    $0x2,%eax
    a119:	48 85 c0             	test   %rax,%rax
    a11c:	0f 85 18 07 00 00    	jne    a83a <dlfree+0x100e>
            if (next == fm->top) {
    a122:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a129:	48 8b 40 28          	mov    0x28(%rax),%rax
    a12d:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    a134:	0f 85 b7 00 00 00    	jne    a1f1 <dlfree+0x9c5>
              size_t tsize = fm->topsize += psize;
    a13a:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a141:	48 8b 50 10          	mov    0x10(%rax),%rdx
    a145:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a14c:	48 01 c2             	add    %rax,%rdx
    a14f:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a156:	48 89 50 10          	mov    %rdx,0x10(%rax)
    a15a:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a161:	48 8b 40 10          	mov    0x10(%rax),%rax
    a165:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
              fm->top = p;
    a169:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a170:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a177:	48 89 50 28          	mov    %rdx,0x28(%rax)
              p->head = tsize | PINUSE_BIT;
    a17b:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    a17f:	48 83 c8 01          	or     $0x1,%rax
    a183:	48 89 c2             	mov    %rax,%rdx
    a186:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    a18d:	48 89 50 08          	mov    %rdx,0x8(%rax)
              if (p == fm->dv) {
    a191:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a198:	48 8b 40 20          	mov    0x20(%rax),%rax
    a19c:	48 39 85 c8 fe ff ff 	cmp    %rax,-0x138(%rbp)
    a1a3:	75 1e                	jne    a1c3 <dlfree+0x997>
                fm->dv = 0;
    a1a5:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a1ac:	48 c7 40 20 00 00 00 	movq   $0x0,0x20(%rax)
    a1b3:	00 
                fm->dvsize = 0;
    a1b4:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a1bb:	48 c7 40 08 00 00 00 	movq   $0x0,0x8(%rax)
    a1c2:	00 
              }
              if (should_trim(fm, tsize))
    a1c3:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a1ca:	48 8b 40 30          	mov    0x30(%rax),%rax
    a1ce:	48 39 45 d0          	cmp    %rax,-0x30(%rbp)
    a1d2:	0f 86 47 0b 00 00    	jbe    ad1f <dlfree+0x14f3>
                sys_trim(fm, 0);
    a1d8:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a1df:	be 00 00 00 00       	mov    $0x0,%esi
    a1e4:	48 89 c7             	mov    %rax,%rdi
    a1e7:	e8 fd d5 ff ff       	callq  77e9 <sys_trim>
              goto postaction;
    a1ec:	e9 2e 0b 00 00       	jmpq   ad1f <dlfree+0x14f3>
            }
            else if (next == fm->dv) {
    a1f1:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a1f8:	48 8b 40 20          	mov    0x20(%rax),%rax
    a1fc:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    a203:	75 71                	jne    a276 <dlfree+0xa4a>
              size_t dsize = fm->dvsize += psize;
    a205:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a20c:	48 8b 50 08          	mov    0x8(%rax),%rdx
    a210:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a217:	48 01 c2             	add    %rax,%rdx
    a21a:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a221:	48 89 50 08          	mov    %rdx,0x8(%rax)
    a225:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a22c:	48 8b 40 08          	mov    0x8(%rax),%rax
    a230:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
              fm->dv = p;
    a234:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a23b:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a242:	48 89 50 20          	mov    %rdx,0x20(%rax)
              set_size_and_pinuse_of_free_chunk(p, dsize);
    a246:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    a24a:	48 83 c8 01          	or     $0x1,%rax
    a24e:	48 89 c2             	mov    %rax,%rdx
    a251:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    a258:	48 89 50 08          	mov    %rdx,0x8(%rax)
    a25c:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a263:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    a267:	48 01 c2             	add    %rax,%rdx
    a26a:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    a26e:	48 89 02             	mov    %rax,(%rdx)
              goto postaction;
    a271:	e9 ad 0a 00 00       	jmpq   ad23 <dlfree+0x14f7>
            }
            else {
              size_t nsize = chunksize(next);
    a276:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a27d:	48 8b 40 08          	mov    0x8(%rax),%rax
    a281:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    a285:	48 89 45 80          	mov    %rax,-0x80(%rbp)
              psize += nsize;
    a289:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    a28d:	48 01 85 d0 fe ff ff 	add    %rax,-0x130(%rbp)
              unlink_chunk(fm, next, nsize);
    a294:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    a298:	48 c1 e8 03          	shr    $0x3,%rax
    a29c:	48 83 f8 1f          	cmp    $0x1f,%rax
    a2a0:	0f 87 c6 01 00 00    	ja     a46c <dlfree+0xc40>
    a2a6:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a2ad:	48 8b 40 10          	mov    0x10(%rax),%rax
    a2b1:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    a2b5:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a2bc:	48 8b 40 18          	mov    0x18(%rax),%rax
    a2c0:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    a2c4:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    a2c8:	48 c1 e8 03          	shr    $0x3,%rax
    a2cc:	89 85 b8 fe ff ff    	mov    %eax,-0x148(%rbp)
    a2d2:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a2d9:	48 3b 45 c0          	cmp    -0x40(%rbp),%rax
    a2dd:	75 05                	jne    a2e4 <dlfree+0xab8>
    a2df:	e8 77 26 00 00       	callq  c95b <abort>
    a2e4:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a2eb:	48 3b 45 b8          	cmp    -0x48(%rbp),%rax
    a2ef:	75 05                	jne    a2f6 <dlfree+0xaca>
    a2f1:	e8 65 26 00 00       	callq  c95b <abort>
    a2f6:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a2fd:	48 8b 40 08          	mov    0x8(%rax),%rax
    a301:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    a305:	48 89 c2             	mov    %rax,%rdx
    a308:	8b 85 b8 fe ff ff    	mov    -0x148(%rbp),%eax
    a30e:	c1 e0 03             	shl    $0x3,%eax
    a311:	89 c0                	mov    %eax,%eax
    a313:	48 39 c2             	cmp    %rax,%rdx
    a316:	74 05                	je     a31d <dlfree+0xaf1>
    a318:	e8 3e 26 00 00       	callq  c95b <abort>
    a31d:	8b 85 b8 fe ff ff    	mov    -0x148(%rbp),%eax
    a323:	01 c0                	add    %eax,%eax
    a325:	89 c0                	mov    %eax,%eax
    a327:	48 83 c0 08          	add    $0x8,%rax
    a32b:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    a332:	00 
    a333:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a33a:	48 01 d0             	add    %rdx,%rax
    a33d:	48 83 c0 08          	add    $0x8,%rax
    a341:	48 39 45 b8          	cmp    %rax,-0x48(%rbp)
    a345:	0f 94 c0             	sete   %al
    a348:	0f b6 c0             	movzbl %al,%eax
    a34b:	48 85 c0             	test   %rax,%rax
    a34e:	75 48                	jne    a398 <dlfree+0xb6c>
    a350:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a357:	48 8b 40 18          	mov    0x18(%rax),%rax
    a35b:	48 39 45 b8          	cmp    %rax,-0x48(%rbp)
    a35f:	0f 93 c0             	setae  %al
    a362:	0f b6 c0             	movzbl %al,%eax
    a365:	48 85 c0             	test   %rax,%rax
    a368:	74 21                	je     a38b <dlfree+0xb5f>
    a36a:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    a36e:	48 8b 40 18          	mov    0x18(%rax),%rax
    a372:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    a379:	0f 94 c0             	sete   %al
    a37c:	0f b6 c0             	movzbl %al,%eax
    a37f:	48 85 c0             	test   %rax,%rax
    a382:	74 07                	je     a38b <dlfree+0xb5f>
    a384:	b8 01 00 00 00       	mov    $0x1,%eax
    a389:	eb 05                	jmp    a390 <dlfree+0xb64>
    a38b:	b8 00 00 00 00       	mov    $0x0,%eax
    a390:	85 c0                	test   %eax,%eax
    a392:	0f 84 cf 00 00 00    	je     a467 <dlfree+0xc3b>
    a398:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    a39c:	48 3b 45 b8          	cmp    -0x48(%rbp),%rax
    a3a0:	75 2c                	jne    a3ce <dlfree+0xba2>
    a3a2:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a3a9:	8b 10                	mov    (%rax),%edx
    a3ab:	8b 85 b8 fe ff ff    	mov    -0x148(%rbp),%eax
    a3b1:	be 01 00 00 00       	mov    $0x1,%esi
    a3b6:	89 c1                	mov    %eax,%ecx
    a3b8:	d3 e6                	shl    %cl,%esi
    a3ba:	89 f0                	mov    %esi,%eax
    a3bc:	f7 d0                	not    %eax
    a3be:	21 c2                	and    %eax,%edx
    a3c0:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a3c7:	89 10                	mov    %edx,(%rax)
    a3c9:	e9 0d 04 00 00       	jmpq   a7db <dlfree+0xfaf>
    a3ce:	8b 85 b8 fe ff ff    	mov    -0x148(%rbp),%eax
    a3d4:	01 c0                	add    %eax,%eax
    a3d6:	89 c0                	mov    %eax,%eax
    a3d8:	48 83 c0 08          	add    $0x8,%rax
    a3dc:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    a3e3:	00 
    a3e4:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a3eb:	48 01 d0             	add    %rdx,%rax
    a3ee:	48 83 c0 08          	add    $0x8,%rax
    a3f2:	48 39 45 c0          	cmp    %rax,-0x40(%rbp)
    a3f6:	0f 94 c0             	sete   %al
    a3f9:	0f b6 c0             	movzbl %al,%eax
    a3fc:	48 85 c0             	test   %rax,%rax
    a3ff:	75 44                	jne    a445 <dlfree+0xc19>
    a401:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a408:	48 8b 40 18          	mov    0x18(%rax),%rax
    a40c:	48 39 45 c0          	cmp    %rax,-0x40(%rbp)
    a410:	0f 93 c0             	setae  %al
    a413:	0f b6 c0             	movzbl %al,%eax
    a416:	48 85 c0             	test   %rax,%rax
    a419:	74 21                	je     a43c <dlfree+0xc10>
    a41b:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    a41f:	48 8b 40 10          	mov    0x10(%rax),%rax
    a423:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    a42a:	0f 94 c0             	sete   %al
    a42d:	0f b6 c0             	movzbl %al,%eax
    a430:	48 85 c0             	test   %rax,%rax
    a433:	74 07                	je     a43c <dlfree+0xc10>
    a435:	b8 01 00 00 00       	mov    $0x1,%eax
    a43a:	eb 05                	jmp    a441 <dlfree+0xc15>
    a43c:	b8 00 00 00 00       	mov    $0x0,%eax
    a441:	85 c0                	test   %eax,%eax
    a443:	74 1d                	je     a462 <dlfree+0xc36>
    a445:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    a449:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    a44d:	48 89 50 18          	mov    %rdx,0x18(%rax)
    a451:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    a455:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
    a459:	48 89 50 10          	mov    %rdx,0x10(%rax)
    a45d:	e9 79 03 00 00       	jmpq   a7db <dlfree+0xfaf>
    a462:	e8 f4 24 00 00       	callq  c95b <abort>
    a467:	e8 ef 24 00 00       	callq  c95b <abort>
    a46c:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a473:	48 89 45 88          	mov    %rax,-0x78(%rbp)
    a477:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a47b:	48 8b 40 30          	mov    0x30(%rax),%rax
    a47f:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    a483:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a487:	48 8b 40 18          	mov    0x18(%rax),%rax
    a48b:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    a48f:	0f 84 9e 00 00 00    	je     a533 <dlfree+0xd07>
    a495:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a499:	48 8b 40 10          	mov    0x10(%rax),%rax
    a49d:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    a4a1:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a4a5:	48 8b 40 18          	mov    0x18(%rax),%rax
    a4a9:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    a4b0:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a4b7:	48 8b 40 18          	mov    0x18(%rax),%rax
    a4bb:	48 39 45 98          	cmp    %rax,-0x68(%rbp)
    a4bf:	0f 93 c0             	setae  %al
    a4c2:	0f b6 c0             	movzbl %al,%eax
    a4c5:	48 85 c0             	test   %rax,%rax
    a4c8:	74 1e                	je     a4e8 <dlfree+0xcbc>
    a4ca:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    a4ce:	48 8b 40 18          	mov    0x18(%rax),%rax
    a4d2:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    a4d6:	0f 94 c0             	sete   %al
    a4d9:	0f b6 c0             	movzbl %al,%eax
    a4dc:	48 85 c0             	test   %rax,%rax
    a4df:	74 07                	je     a4e8 <dlfree+0xcbc>
    a4e1:	b8 01 00 00 00       	mov    $0x1,%eax
    a4e6:	eb 05                	jmp    a4ed <dlfree+0xcc1>
    a4e8:	b8 00 00 00 00       	mov    $0x0,%eax
    a4ed:	85 c0                	test   %eax,%eax
    a4ef:	74 3d                	je     a52e <dlfree+0xd02>
    a4f1:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    a4f8:	48 8b 40 10          	mov    0x10(%rax),%rax
    a4fc:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    a500:	0f 94 c0             	sete   %al
    a503:	0f b6 c0             	movzbl %al,%eax
    a506:	48 85 c0             	test   %rax,%rax
    a509:	74 23                	je     a52e <dlfree+0xd02>
    a50b:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    a50f:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    a516:	48 89 50 18          	mov    %rdx,0x18(%rax)
    a51a:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    a521:	48 8b 55 98          	mov    -0x68(%rbp),%rdx
    a525:	48 89 50 10          	mov    %rdx,0x10(%rax)
    a529:	e9 f2 00 00 00       	jmpq   a620 <dlfree+0xdf4>
    a52e:	e8 28 24 00 00       	callq  c95b <abort>
    a533:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a537:	48 83 c0 28          	add    $0x28,%rax
    a53b:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
    a542:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    a549:	48 8b 00             	mov    (%rax),%rax
    a54c:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    a553:	48 83 bd f0 fe ff ff 	cmpq   $0x0,-0x110(%rbp)
    a55a:	00 
    a55b:	75 4f                	jne    a5ac <dlfree+0xd80>
    a55d:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a561:	48 83 c0 20          	add    $0x20,%rax
    a565:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
    a56c:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    a573:	48 8b 00             	mov    (%rax),%rax
    a576:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    a57d:	48 83 bd f0 fe ff ff 	cmpq   $0x0,-0x110(%rbp)
    a584:	00 
    a585:	0f 84 95 00 00 00    	je     a620 <dlfree+0xdf4>
    a58b:	eb 1f                	jmp    a5ac <dlfree+0xd80>
    a58d:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    a594:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
    a59b:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    a5a2:	48 8b 00             	mov    (%rax),%rax
    a5a5:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    a5ac:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    a5b3:	48 83 c0 28          	add    $0x28,%rax
    a5b7:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
    a5be:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    a5c5:	48 8b 00             	mov    (%rax),%rax
    a5c8:	48 85 c0             	test   %rax,%rax
    a5cb:	75 c0                	jne    a58d <dlfree+0xd61>
    a5cd:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    a5d4:	48 83 c0 20          	add    $0x20,%rax
    a5d8:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
    a5df:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    a5e6:	48 8b 00             	mov    (%rax),%rax
    a5e9:	48 85 c0             	test   %rax,%rax
    a5ec:	75 9f                	jne    a58d <dlfree+0xd61>
    a5ee:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a5f5:	48 8b 40 18          	mov    0x18(%rax),%rax
    a5f9:	48 39 85 f8 fe ff ff 	cmp    %rax,-0x108(%rbp)
    a600:	0f 93 c0             	setae  %al
    a603:	0f b6 c0             	movzbl %al,%eax
    a606:	48 85 c0             	test   %rax,%rax
    a609:	74 10                	je     a61b <dlfree+0xdef>
    a60b:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    a612:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    a619:	eb 05                	jmp    a620 <dlfree+0xdf4>
    a61b:	e8 3b 23 00 00       	callq  c95b <abort>
    a620:	48 83 7d 90 00       	cmpq   $0x0,-0x70(%rbp)
    a625:	0f 84 b0 01 00 00    	je     a7db <dlfree+0xfaf>
    a62b:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a62f:	8b 40 38             	mov    0x38(%rax),%eax
    a632:	89 c0                	mov    %eax,%eax
    a634:	48 83 c0 4a          	add    $0x4a,%rax
    a638:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    a63f:	00 
    a640:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a647:	48 01 d0             	add    %rdx,%rax
    a64a:	48 83 c0 08          	add    $0x8,%rax
    a64e:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
    a652:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    a656:	48 8b 00             	mov    (%rax),%rax
    a659:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    a65d:	75 46                	jne    a6a5 <dlfree+0xe79>
    a65f:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    a663:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    a66a:	48 89 10             	mov    %rdx,(%rax)
    a66d:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    a671:	48 8b 00             	mov    (%rax),%rax
    a674:	48 85 c0             	test   %rax,%rax
    a677:	75 7b                	jne    a6f4 <dlfree+0xec8>
    a679:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a680:	8b 50 04             	mov    0x4(%rax),%edx
    a683:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a687:	8b 40 38             	mov    0x38(%rax),%eax
    a68a:	be 01 00 00 00       	mov    $0x1,%esi
    a68f:	89 c1                	mov    %eax,%ecx
    a691:	d3 e6                	shl    %cl,%esi
    a693:	89 f0                	mov    %esi,%eax
    a695:	f7 d0                	not    %eax
    a697:	21 c2                	and    %eax,%edx
    a699:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a6a0:	89 50 04             	mov    %edx,0x4(%rax)
    a6a3:	eb 4f                	jmp    a6f4 <dlfree+0xec8>
    a6a5:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a6ac:	48 8b 40 18          	mov    0x18(%rax),%rax
    a6b0:	48 39 45 90          	cmp    %rax,-0x70(%rbp)
    a6b4:	0f 93 c0             	setae  %al
    a6b7:	0f b6 c0             	movzbl %al,%eax
    a6ba:	48 85 c0             	test   %rax,%rax
    a6bd:	74 30                	je     a6ef <dlfree+0xec3>
    a6bf:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    a6c3:	48 8b 40 20          	mov    0x20(%rax),%rax
    a6c7:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    a6cb:	75 11                	jne    a6de <dlfree+0xeb2>
    a6cd:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    a6d1:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    a6d8:	48 89 50 20          	mov    %rdx,0x20(%rax)
    a6dc:	eb 16                	jmp    a6f4 <dlfree+0xec8>
    a6de:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    a6e2:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    a6e9:	48 89 50 28          	mov    %rdx,0x28(%rax)
    a6ed:	eb 05                	jmp    a6f4 <dlfree+0xec8>
    a6ef:	e8 67 22 00 00       	callq  c95b <abort>
    a6f4:	48 83 bd f0 fe ff ff 	cmpq   $0x0,-0x110(%rbp)
    a6fb:	00 
    a6fc:	0f 84 d9 00 00 00    	je     a7db <dlfree+0xfaf>
    a702:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a709:	48 8b 40 18          	mov    0x18(%rax),%rax
    a70d:	48 39 85 f0 fe ff ff 	cmp    %rax,-0x110(%rbp)
    a714:	0f 93 c0             	setae  %al
    a717:	0f b6 c0             	movzbl %al,%eax
    a71a:	48 85 c0             	test   %rax,%rax
    a71d:	0f 84 b3 00 00 00    	je     a7d6 <dlfree+0xfaa>
    a723:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    a72a:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    a72e:	48 89 50 30          	mov    %rdx,0x30(%rax)
    a732:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a736:	48 8b 40 20          	mov    0x20(%rax),%rax
    a73a:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    a73e:	48 83 7d a8 00       	cmpq   $0x0,-0x58(%rbp)
    a743:	74 3f                	je     a784 <dlfree+0xf58>
    a745:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a74c:	48 8b 40 18          	mov    0x18(%rax),%rax
    a750:	48 39 45 a8          	cmp    %rax,-0x58(%rbp)
    a754:	0f 93 c0             	setae  %al
    a757:	0f b6 c0             	movzbl %al,%eax
    a75a:	48 85 c0             	test   %rax,%rax
    a75d:	74 20                	je     a77f <dlfree+0xf53>
    a75f:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    a766:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    a76a:	48 89 50 20          	mov    %rdx,0x20(%rax)
    a76e:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    a772:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    a779:	48 89 50 30          	mov    %rdx,0x30(%rax)
    a77d:	eb 05                	jmp    a784 <dlfree+0xf58>
    a77f:	e8 d7 21 00 00       	callq  c95b <abort>
    a784:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a788:	48 8b 40 28          	mov    0x28(%rax),%rax
    a78c:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    a790:	48 83 7d b0 00       	cmpq   $0x0,-0x50(%rbp)
    a795:	74 44                	je     a7db <dlfree+0xfaf>
    a797:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a79e:	48 8b 40 18          	mov    0x18(%rax),%rax
    a7a2:	48 39 45 b0          	cmp    %rax,-0x50(%rbp)
    a7a6:	0f 93 c0             	setae  %al
    a7a9:	0f b6 c0             	movzbl %al,%eax
    a7ac:	48 85 c0             	test   %rax,%rax
    a7af:	74 20                	je     a7d1 <dlfree+0xfa5>
    a7b1:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    a7b8:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    a7bc:	48 89 50 28          	mov    %rdx,0x28(%rax)
    a7c0:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    a7c4:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    a7cb:	48 89 50 30          	mov    %rdx,0x30(%rax)
    a7cf:	eb 0a                	jmp    a7db <dlfree+0xfaf>
    a7d1:	e8 85 21 00 00       	callq  c95b <abort>
    a7d6:	e8 80 21 00 00       	callq  c95b <abort>
              set_size_and_pinuse_of_free_chunk(p, psize);
    a7db:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a7e2:	48 83 c8 01          	or     $0x1,%rax
    a7e6:	48 89 c2             	mov    %rax,%rdx
    a7e9:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    a7f0:	48 89 50 08          	mov    %rdx,0x8(%rax)
    a7f4:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a7fb:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a802:	48 01 c2             	add    %rax,%rdx
    a805:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a80c:	48 89 02             	mov    %rax,(%rdx)
              if (p == fm->dv) {
    a80f:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a816:	48 8b 40 20          	mov    0x20(%rax),%rax
    a81a:	48 39 85 c8 fe ff ff 	cmp    %rax,-0x138(%rbp)
    a821:	75 68                	jne    a88b <dlfree+0x105f>
                fm->dvsize = psize;
    a823:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a82a:	48 8b 95 d0 fe ff ff 	mov    -0x130(%rbp),%rdx
    a831:	48 89 50 08          	mov    %rdx,0x8(%rax)
                goto postaction;
    a835:	e9 e9 04 00 00       	jmpq   ad23 <dlfree+0x14f7>
              }
            }
          }
          else
            set_free_with_pinuse(p, psize, next);
    a83a:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a841:	48 8b 40 08          	mov    0x8(%rax),%rax
    a845:	48 83 e0 fe          	and    $0xfffffffffffffffe,%rax
    a849:	48 89 c2             	mov    %rax,%rdx
    a84c:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a853:	48 89 50 08          	mov    %rdx,0x8(%rax)
    a857:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a85e:	48 83 c8 01          	or     $0x1,%rax
    a862:	48 89 c2             	mov    %rax,%rdx
    a865:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    a86c:	48 89 50 08          	mov    %rdx,0x8(%rax)
    a870:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a877:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a87e:	48 01 c2             	add    %rax,%rdx
    a881:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a888:	48 89 02             	mov    %rax,(%rdx)

          if (is_small(psize)) {
    a88b:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a892:	48 c1 e8 03          	shr    $0x3,%rax
    a896:	48 83 f8 1f          	cmp    $0x1f,%rax
    a89a:	0f 87 31 01 00 00    	ja     a9d1 <dlfree+0x11a5>
            insert_small_chunk(fm, p, psize);
    a8a0:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a8a7:	48 c1 e8 03          	shr    $0x3,%rax
    a8ab:	89 85 c4 fe ff ff    	mov    %eax,-0x13c(%rbp)
    a8b1:	8b 85 c4 fe ff ff    	mov    -0x13c(%rbp),%eax
    a8b7:	01 c0                	add    %eax,%eax
    a8b9:	89 c0                	mov    %eax,%eax
    a8bb:	48 83 c0 08          	add    $0x8,%rax
    a8bf:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    a8c6:	00 
    a8c7:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a8ce:	48 01 d0             	add    %rdx,%rax
    a8d1:	48 83 c0 08          	add    $0x8,%rax
    a8d5:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    a8d9:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a8dd:	48 89 85 08 ff ff ff 	mov    %rax,-0xf8(%rbp)
    a8e4:	48 83 bd d0 fe ff ff 	cmpq   $0x1f,-0x130(%rbp)
    a8eb:	1f 
    a8ec:	77 05                	ja     a8f3 <dlfree+0x10c7>
    a8ee:	e8 68 20 00 00       	callq  c95b <abort>
    a8f3:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a8fa:	8b 10                	mov    (%rax),%edx
    a8fc:	8b 85 c4 fe ff ff    	mov    -0x13c(%rbp),%eax
    a902:	be 01 00 00 00       	mov    $0x1,%esi
    a907:	89 c1                	mov    %eax,%ecx
    a909:	d3 e6                	shl    %cl,%esi
    a90b:	89 f0                	mov    %esi,%eax
    a90d:	21 d0                	and    %edx,%eax
    a90f:	85 c0                	test   %eax,%eax
    a911:	75 27                	jne    a93a <dlfree+0x110e>
    a913:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a91a:	8b 10                	mov    (%rax),%edx
    a91c:	8b 85 c4 fe ff ff    	mov    -0x13c(%rbp),%eax
    a922:	be 01 00 00 00       	mov    $0x1,%esi
    a927:	89 c1                	mov    %eax,%ecx
    a929:	d3 e6                	shl    %cl,%esi
    a92b:	89 f0                	mov    %esi,%eax
    a92d:	09 c2                	or     %eax,%edx
    a92f:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a936:	89 10                	mov    %edx,(%rax)
    a938:	eb 37                	jmp    a971 <dlfree+0x1145>
    a93a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a93e:	48 8b 50 10          	mov    0x10(%rax),%rdx
    a942:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a949:	48 8b 40 18          	mov    0x18(%rax),%rax
    a94d:	48 39 c2             	cmp    %rax,%rdx
    a950:	0f 93 c0             	setae  %al
    a953:	0f b6 c0             	movzbl %al,%eax
    a956:	48 85 c0             	test   %rax,%rax
    a959:	74 11                	je     a96c <dlfree+0x1140>
    a95b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a95f:	48 8b 40 10          	mov    0x10(%rax),%rax
    a963:	48 89 85 08 ff ff ff 	mov    %rax,-0xf8(%rbp)
    a96a:	eb 05                	jmp    a971 <dlfree+0x1145>
    a96c:	e8 ea 1f 00 00       	callq  c95b <abort>
    a971:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a975:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a97c:	48 89 50 10          	mov    %rdx,0x10(%rax)
    a980:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    a987:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a98e:	48 89 50 18          	mov    %rdx,0x18(%rax)
    a992:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    a999:	48 8b 95 08 ff ff ff 	mov    -0xf8(%rbp),%rdx
    a9a0:	48 89 50 10          	mov    %rdx,0x10(%rax)
    a9a4:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    a9ab:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    a9af:	48 89 50 18          	mov    %rdx,0x18(%rax)
            check_free_chunk(fm, p);
    a9b3:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a9ba:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a9c1:	48 89 d6             	mov    %rdx,%rsi
    a9c4:	48 89 c7             	mov    %rax,%rdi
    a9c7:	e8 f6 ac ff ff       	callq  56c2 <do_check_free_chunk>
            insert_large_chunk(fm, tp, psize);
            check_free_chunk(fm, p);
            if (--fm->release_checks == 0)
              release_unused_segments(fm);
          }
          goto postaction;
    a9cc:	e9 51 03 00 00       	jmpq   ad22 <dlfree+0x14f6>
            tchunkptr tp = (tchunkptr)p;
    a9d1:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    a9d8:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
            insert_large_chunk(fm, tp, psize);
    a9dc:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a9e3:	48 c1 e8 08          	shr    $0x8,%rax
    a9e7:	89 85 bc fe ff ff    	mov    %eax,-0x144(%rbp)
    a9ed:	83 bd bc fe ff ff 00 	cmpl   $0x0,-0x144(%rbp)
    a9f4:	75 0c                	jne    aa02 <dlfree+0x11d6>
    a9f6:	c7 85 b0 fe ff ff 00 	movl   $0x0,-0x150(%rbp)
    a9fd:	00 00 00 
    aa00:	eb 5d                	jmp    aa5f <dlfree+0x1233>
    aa02:	81 bd bc fe ff ff ff 	cmpl   $0xffff,-0x144(%rbp)
    aa09:	ff 00 00 
    aa0c:	76 0c                	jbe    aa1a <dlfree+0x11ee>
    aa0e:	c7 85 b0 fe ff ff 1f 	movl   $0x1f,-0x150(%rbp)
    aa15:	00 00 00 
    aa18:	eb 45                	jmp    aa5f <dlfree+0x1233>
    aa1a:	0f bd 85 bc fe ff ff 	bsr    -0x144(%rbp),%eax
    aa21:	83 f0 1f             	xor    $0x1f,%eax
    aa24:	ba 1f 00 00 00       	mov    $0x1f,%edx
    aa29:	29 c2                	sub    %eax,%edx
    aa2b:	89 d0                	mov    %edx,%eax
    aa2d:	89 85 c0 fe ff ff    	mov    %eax,-0x140(%rbp)
    aa33:	8b 85 c0 fe ff ff    	mov    -0x140(%rbp),%eax
    aa39:	8d 34 00             	lea    (%rax,%rax,1),%esi
    aa3c:	8b 85 c0 fe ff ff    	mov    -0x140(%rbp),%eax
    aa42:	83 c0 07             	add    $0x7,%eax
    aa45:	48 8b 95 d0 fe ff ff 	mov    -0x130(%rbp),%rdx
    aa4c:	89 c1                	mov    %eax,%ecx
    aa4e:	48 d3 ea             	shr    %cl,%rdx
    aa51:	48 89 d0             	mov    %rdx,%rax
    aa54:	83 e0 01             	and    $0x1,%eax
    aa57:	01 f0                	add    %esi,%eax
    aa59:	89 85 b0 fe ff ff    	mov    %eax,-0x150(%rbp)
    aa5f:	8b 85 b0 fe ff ff    	mov    -0x150(%rbp),%eax
    aa65:	48 83 c0 4a          	add    $0x4a,%rax
    aa69:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    aa70:	00 
    aa71:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    aa78:	48 01 d0             	add    %rdx,%rax
    aa7b:	48 83 c0 08          	add    $0x8,%rax
    aa7f:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    aa83:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    aa87:	8b 95 b0 fe ff ff    	mov    -0x150(%rbp),%edx
    aa8d:	89 50 38             	mov    %edx,0x38(%rax)
    aa90:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    aa94:	48 c7 40 28 00 00 00 	movq   $0x0,0x28(%rax)
    aa9b:	00 
    aa9c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    aaa0:	48 8b 50 28          	mov    0x28(%rax),%rdx
    aaa4:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    aaa8:	48 89 50 20          	mov    %rdx,0x20(%rax)
    aaac:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    aab3:	8b 50 04             	mov    0x4(%rax),%edx
    aab6:	8b 85 b0 fe ff ff    	mov    -0x150(%rbp),%eax
    aabc:	be 01 00 00 00       	mov    $0x1,%esi
    aac1:	89 c1                	mov    %eax,%ecx
    aac3:	d3 e6                	shl    %cl,%esi
    aac5:	89 f0                	mov    %esi,%eax
    aac7:	21 d0                	and    %edx,%eax
    aac9:	85 c0                	test   %eax,%eax
    aacb:	75 5f                	jne    ab2c <dlfree+0x1300>
    aacd:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    aad4:	8b 50 04             	mov    0x4(%rax),%edx
    aad7:	8b 85 b0 fe ff ff    	mov    -0x150(%rbp),%eax
    aadd:	be 01 00 00 00       	mov    $0x1,%esi
    aae2:	89 c1                	mov    %eax,%ecx
    aae4:	d3 e6                	shl    %cl,%esi
    aae6:	89 f0                	mov    %esi,%eax
    aae8:	09 c2                	or     %eax,%edx
    aaea:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    aaf1:	89 50 04             	mov    %edx,0x4(%rax)
    aaf4:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    aaf8:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    aafc:	48 89 10             	mov    %rdx,(%rax)
    aaff:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ab03:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    ab07:	48 89 50 30          	mov    %rdx,0x30(%rax)
    ab0b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ab0f:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    ab13:	48 89 50 18          	mov    %rdx,0x18(%rax)
    ab17:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ab1b:	48 8b 50 18          	mov    0x18(%rax),%rdx
    ab1f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ab23:	48 89 50 10          	mov    %rdx,0x10(%rax)
    ab27:	e9 96 01 00 00       	jmpq   acc2 <dlfree+0x1496>
    ab2c:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    ab30:	48 8b 00             	mov    (%rax),%rax
    ab33:	48 89 85 10 ff ff ff 	mov    %rax,-0xf0(%rbp)
    ab3a:	83 bd b0 fe ff ff 1f 	cmpl   $0x1f,-0x150(%rbp)
    ab41:	74 13                	je     ab56 <dlfree+0x132a>
    ab43:	8b 85 b0 fe ff ff    	mov    -0x150(%rbp),%eax
    ab49:	d1 e8                	shr    %eax
    ab4b:	ba 39 00 00 00       	mov    $0x39,%edx
    ab50:	29 c2                	sub    %eax,%edx
    ab52:	89 d0                	mov    %edx,%eax
    ab54:	eb 05                	jmp    ab5b <dlfree+0x132f>
    ab56:	b8 00 00 00 00       	mov    $0x0,%eax
    ab5b:	48 8b 95 d0 fe ff ff 	mov    -0x130(%rbp),%rdx
    ab62:	89 c1                	mov    %eax,%ecx
    ab64:	48 d3 e2             	shl    %cl,%rdx
    ab67:	48 89 d0             	mov    %rdx,%rax
    ab6a:	48 89 85 18 ff ff ff 	mov    %rax,-0xe8(%rbp)
    ab71:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    ab78:	48 8b 40 08          	mov    0x8(%rax),%rax
    ab7c:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    ab80:	48 39 85 d0 fe ff ff 	cmp    %rax,-0x130(%rbp)
    ab87:	0f 84 a2 00 00 00    	je     ac2f <dlfree+0x1403>
    ab8d:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    ab94:	48 c1 e8 3f          	shr    $0x3f,%rax
    ab98:	48 83 c0 04          	add    $0x4,%rax
    ab9c:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    aba3:	00 
    aba4:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    abab:	48 01 d0             	add    %rdx,%rax
    abae:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    abb2:	48 d1 a5 18 ff ff ff 	shlq   -0xe8(%rbp)
    abb9:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    abbd:	48 8b 00             	mov    (%rax),%rax
    abc0:	48 85 c0             	test   %rax,%rax
    abc3:	74 10                	je     abd5 <dlfree+0x13a9>
    abc5:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    abc9:	48 8b 00             	mov    (%rax),%rax
    abcc:	48 89 85 10 ff ff ff 	mov    %rax,-0xf0(%rbp)
    abd3:	eb 9c                	jmp    ab71 <dlfree+0x1345>
    abd5:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    abdc:	48 8b 40 18          	mov    0x18(%rax),%rax
    abe0:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    abe4:	0f 93 c0             	setae  %al
    abe7:	0f b6 c0             	movzbl %al,%eax
    abea:	48 85 c0             	test   %rax,%rax
    abed:	74 3b                	je     ac2a <dlfree+0x13fe>
    abef:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    abf3:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    abf7:	48 89 10             	mov    %rdx,(%rax)
    abfa:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    abfe:	48 8b 95 10 ff ff ff 	mov    -0xf0(%rbp),%rdx
    ac05:	48 89 50 30          	mov    %rdx,0x30(%rax)
    ac09:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ac0d:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    ac11:	48 89 50 18          	mov    %rdx,0x18(%rax)
    ac15:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ac19:	48 8b 50 18          	mov    0x18(%rax),%rdx
    ac1d:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ac21:	48 89 50 10          	mov    %rdx,0x10(%rax)
    ac25:	e9 98 00 00 00       	jmpq   acc2 <dlfree+0x1496>
    ac2a:	e8 2c 1d 00 00       	callq  c95b <abort>
    ac2f:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    ac36:	48 8b 40 10          	mov    0x10(%rax),%rax
    ac3a:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    ac3e:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ac45:	48 8b 40 18          	mov    0x18(%rax),%rax
    ac49:	48 39 85 10 ff ff ff 	cmp    %rax,-0xf0(%rbp)
    ac50:	0f 93 c0             	setae  %al
    ac53:	0f b6 c0             	movzbl %al,%eax
    ac56:	48 85 c0             	test   %rax,%rax
    ac59:	74 62                	je     acbd <dlfree+0x1491>
    ac5b:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ac62:	48 8b 40 18          	mov    0x18(%rax),%rax
    ac66:	48 39 45 e8          	cmp    %rax,-0x18(%rbp)
    ac6a:	0f 93 c0             	setae  %al
    ac6d:	0f b6 c0             	movzbl %al,%eax
    ac70:	48 85 c0             	test   %rax,%rax
    ac73:	74 48                	je     acbd <dlfree+0x1491>
    ac75:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    ac79:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    ac7d:	48 89 50 18          	mov    %rdx,0x18(%rax)
    ac81:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    ac85:	48 8b 50 18          	mov    0x18(%rax),%rdx
    ac89:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    ac90:	48 89 50 10          	mov    %rdx,0x10(%rax)
    ac94:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ac98:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    ac9c:	48 89 50 10          	mov    %rdx,0x10(%rax)
    aca0:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    aca4:	48 8b 95 10 ff ff ff 	mov    -0xf0(%rbp),%rdx
    acab:	48 89 50 18          	mov    %rdx,0x18(%rax)
    acaf:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    acb3:	48 c7 40 30 00 00 00 	movq   $0x0,0x30(%rax)
    acba:	00 
    acbb:	eb 05                	jmp    acc2 <dlfree+0x1496>
    acbd:	e8 99 1c 00 00       	callq  c95b <abort>
            check_free_chunk(fm, p);
    acc2:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    acc9:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    acd0:	48 89 d6             	mov    %rdx,%rsi
    acd3:	48 89 c7             	mov    %rax,%rdi
    acd6:	e8 e7 a9 ff ff       	callq  56c2 <do_check_free_chunk>
            if (--fm->release_checks == 0)
    acdb:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ace2:	48 8b 40 38          	mov    0x38(%rax),%rax
    ace6:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    acea:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    acf1:	48 89 50 38          	mov    %rdx,0x38(%rax)
    acf5:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    acfc:	48 8b 40 38          	mov    0x38(%rax),%rax
    ad00:	48 85 c0             	test   %rax,%rax
    ad03:	75 1d                	jne    ad22 <dlfree+0x14f6>
              release_unused_segments(fm);
    ad05:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ad0c:	48 89 c7             	mov    %rax,%rdi
    ad0f:	e8 52 ca ff ff       	callq  7766 <release_unused_segments>
          goto postaction;
    ad14:	eb 0c                	jmp    ad22 <dlfree+0x14f6>
        }
      }
    erroraction:
    ad16:	90                   	nop
    ad17:	eb 01                	jmp    ad1a <dlfree+0x14ee>
              goto erroraction;
    ad19:	90                   	nop
      USAGE_ERROR_ACTION(fm, p);
    ad1a:	e8 3c 1c 00 00       	callq  c95b <abort>
              goto postaction;
    ad1f:	90                   	nop
    ad20:	eb 01                	jmp    ad23 <dlfree+0x14f7>
          goto postaction;
    ad22:	90                   	nop
    postaction:
      POSTACTION(fm);
    ad23:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ad2a:	8b 80 70 03 00 00    	mov    0x370(%rax),%eax
    ad30:	83 e0 02             	and    $0x2,%eax
    ad33:	85 c0                	test   %eax,%eax
    ad35:	74 14                	je     ad4b <dlfree+0x151f>
    ad37:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ad3e:	48 05 74 03 00 00    	add    $0x374,%rax
    ad44:	ba 00 00 00 00       	mov    $0x0,%edx
    ad49:	89 10                	mov    %edx,(%rax)
    }
  }
#if !FOOTERS
#undef fm
#endif /* FOOTERS */
}
    ad4b:	90                   	nop
    ad4c:	c9                   	leaveq 
    ad4d:	c3                   	retq   

000000000000ad4e <__memcpy>:
/*
 * Copy a block of memory, not handling overlap.
 */
void *
__memcpy(void *dst0, const void *src0, size_t length)
{
    ad4e:	55                   	push   %rbp
    ad4f:	48 89 e5             	mov    %rsp,%rbp
    ad52:	48 83 ec 40          	sub    $0x40,%rsp
    ad56:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    ad5a:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    ad5e:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
	char *dst = (char *)dst0;
    ad62:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ad66:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
	const char *src = (const char *)src0;
    ad6a:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    ad6e:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
	size_t t;

	if (length == 0 || dst == src)		/* nothing to do */
    ad72:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    ad77:	0f 84 3b 01 00 00    	je     aeb8 <__memcpy+0x16a>
    ad7d:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    ad81:	48 3b 45 f0          	cmp    -0x10(%rbp),%rax
    ad85:	0f 84 2d 01 00 00    	je     aeb8 <__memcpy+0x16a>
		goto done;

	if ((dst < src && dst + length > src) ||
    ad8b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    ad8f:	48 3b 45 f0          	cmp    -0x10(%rbp),%rax
    ad93:	73 11                	jae    ada6 <__memcpy+0x58>
    ad95:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    ad99:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    ad9d:	48 01 d0             	add    %rdx,%rax
    ada0:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    ada4:	72 1b                	jb     adc1 <__memcpy+0x73>
    ada6:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    adaa:	48 3b 45 e8          	cmp    -0x18(%rbp),%rax
    adae:	73 16                	jae    adc6 <__memcpy+0x78>
	    (src < dst && src + length > dst)) {
    adb0:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    adb4:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    adb8:	48 01 d0             	add    %rdx,%rax
    adbb:	48 39 45 e8          	cmp    %rax,-0x18(%rbp)
    adbf:	73 05                	jae    adc6 <__memcpy+0x78>
        /* backwards memcpy */
		abort();
    adc1:	e8 95 1b 00 00       	callq  c95b <abort>
#define	TLOOP1(s) do { s; } while (--t)

	/*
	 * Copy forward.
	 */
	t = (long)src;	/* only need low bits */
    adc6:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    adca:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
	if ((t | (long)dst) & wmask) {
    adce:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    add2:	48 0b 45 f8          	or     -0x8(%rbp),%rax
    add6:	83 e0 07             	and    $0x7,%eax
    add9:	48 85 c0             	test   %rax,%rax
    addc:	74 68                	je     ae46 <__memcpy+0xf8>
		/*
		 * Try to align operands.  This cannot be done
		 * unless the low bits match.
		 */
		if ((t ^ (long)dst) & wmask || length < wsize)
    adde:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    ade2:	48 33 45 f8          	xor    -0x8(%rbp),%rax
    ade6:	83 e0 07             	and    $0x7,%eax
    ade9:	48 85 c0             	test   %rax,%rax
    adec:	75 07                	jne    adf5 <__memcpy+0xa7>
    adee:	48 83 7d c8 07       	cmpq   $0x7,-0x38(%rbp)
    adf3:	77 0a                	ja     adff <__memcpy+0xb1>
			t = length;
    adf5:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    adf9:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    adfd:	eb 16                	jmp    ae15 <__memcpy+0xc7>
		else
			t = wsize - (t & wmask);
    adff:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ae03:	83 e0 07             	and    $0x7,%eax
    ae06:	ba 08 00 00 00       	mov    $0x8,%edx
    ae0b:	48 29 c2             	sub    %rax,%rdx
    ae0e:	48 89 d0             	mov    %rdx,%rax
    ae11:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
		length -= t;
    ae15:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ae19:	48 29 45 c8          	sub    %rax,-0x38(%rbp)
		TLOOP1(*dst++ = *src++);
    ae1d:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    ae21:	48 8d 42 01          	lea    0x1(%rdx),%rax
    ae25:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    ae29:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    ae2d:	48 8d 48 01          	lea    0x1(%rax),%rcx
    ae31:	48 89 4d e8          	mov    %rcx,-0x18(%rbp)
    ae35:	0f b6 12             	movzbl (%rdx),%edx
    ae38:	88 10                	mov    %dl,(%rax)
    ae3a:	48 83 6d f8 01       	subq   $0x1,-0x8(%rbp)
    ae3f:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    ae44:	75 d7                	jne    ae1d <__memcpy+0xcf>
	}
	/*
	 * Copy whole words, then mop up any trailing bytes.
	 */
	t = length / wsize;
    ae46:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    ae4a:	48 c1 e8 03          	shr    $0x3,%rax
    ae4e:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
	TLOOP(*(word *)dst = *(word *)src; src += wsize; dst += wsize);
    ae52:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    ae57:	74 24                	je     ae7d <__memcpy+0x12f>
    ae59:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    ae5d:	48 8b 10             	mov    (%rax),%rdx
    ae60:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    ae64:	48 89 10             	mov    %rdx,(%rax)
    ae67:	48 83 45 f0 08       	addq   $0x8,-0x10(%rbp)
    ae6c:	48 83 45 e8 08       	addq   $0x8,-0x18(%rbp)
    ae71:	48 83 6d f8 01       	subq   $0x1,-0x8(%rbp)
    ae76:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    ae7b:	75 dc                	jne    ae59 <__memcpy+0x10b>
	t = length & wmask;
    ae7d:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    ae81:	83 e0 07             	and    $0x7,%eax
    ae84:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
	TLOOP(*dst++ = *src++);
    ae88:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    ae8d:	74 29                	je     aeb8 <__memcpy+0x16a>
    ae8f:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    ae93:	48 8d 42 01          	lea    0x1(%rdx),%rax
    ae97:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    ae9b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    ae9f:	48 8d 48 01          	lea    0x1(%rax),%rcx
    aea3:	48 89 4d e8          	mov    %rcx,-0x18(%rbp)
    aea7:	0f b6 12             	movzbl (%rdx),%edx
    aeaa:	88 10                	mov    %dl,(%rax)
    aeac:	48 83 6d f8 01       	subq   $0x1,-0x8(%rbp)
    aeb1:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    aeb6:	75 d7                	jne    ae8f <__memcpy+0x141>
done:
    aeb8:	90                   	nop
	return (dst0);
    aeb9:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
}
    aebd:	c9                   	leaveq 
    aebe:	c3                   	retq   

000000000000aebf <memcpy>:


void *
memcpy(void *dst0, const void *src0, size_t length)
{
    aebf:	55                   	push   %rbp
    aec0:	48 89 e5             	mov    %rsp,%rbp
    aec3:	48 83 ec 20          	sub    $0x20,%rsp
    aec7:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    aecb:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    aecf:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
#ifdef _TLIBC_USE_INTEL_FAST_STRING_
 	return _intel_fast_memcpy(dst0, (void*)src0, length);
#else
	return __memcpy(dst0, src0, length);
    aed3:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    aed7:	48 8b 4d f0          	mov    -0x10(%rbp),%rcx
    aedb:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    aedf:	48 89 ce             	mov    %rcx,%rsi
    aee2:	48 89 c7             	mov    %rax,%rdi
    aee5:	e8 64 fe ff ff       	callq  ad4e <__memcpy>
#endif
}
    aeea:	c9                   	leaveq 
    aeeb:	c3                   	retq   

000000000000aeec <__memset>:
extern void *_intel_fast_memset(void *, void *, size_t);
#endif

void * __attribute__((optimize("O0")))
__memset(void *dst, int c, size_t n)
{
    aeec:	55                   	push   %rbp
    aeed:	48 89 e5             	mov    %rsp,%rbp
    aef0:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    aef4:	89 75 e4             	mov    %esi,-0x1c(%rbp)
    aef7:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
	if (n != 0) {
    aefb:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    af00:	74 25                	je     af27 <__memset+0x3b>
                unsigned char *d = dst;
    af02:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    af06:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

                do
                        *d++ = (unsigned char)c;
    af0a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    af0e:	48 8d 50 01          	lea    0x1(%rax),%rdx
    af12:	48 89 55 f8          	mov    %rdx,-0x8(%rbp)
    af16:	8b 55 e4             	mov    -0x1c(%rbp),%edx
    af19:	88 10                	mov    %dl,(%rax)
                while (--n != 0);
    af1b:	48 83 6d d8 01       	subq   $0x1,-0x28(%rbp)
    af20:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    af25:	75 e3                	jne    af0a <__memset+0x1e>
        }
        return (dst);
    af27:	48 8b 45 e8          	mov    -0x18(%rbp),%rax


}
    af2b:	5d                   	pop    %rbp
    af2c:	c3                   	retq   

000000000000af2d <memset>:

void *
memset(void *dst, int c, size_t n)
{
    af2d:	55                   	push   %rbp
    af2e:	48 89 e5             	mov    %rsp,%rbp
    af31:	48 83 ec 18          	sub    $0x18,%rsp
    af35:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    af39:	89 75 f4             	mov    %esi,-0xc(%rbp)
    af3c:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
#ifdef _TLIBC_USE_INTEL_FAST_STRING_
	return _intel_fast_memset(dst, (void*)c, n);
#else
	return __memset(dst, c, n);
    af40:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    af44:	8b 4d f4             	mov    -0xc(%rbp),%ecx
    af47:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    af4b:	89 ce                	mov    %ecx,%esi
    af4d:	48 89 c7             	mov    %rax,%rdi
    af50:	e8 97 ff ff ff       	callq  aeec <__memset>
#endif /* !_TLIBC_USE_INTEL_FAST_STRING_ */	
}
    af55:	c9                   	leaveq 
    af56:	c3                   	retq   

000000000000af57 <memset_s>:

#undef memset_s /* in case it was defined as a macro */

errno_t
memset_s(void *s, size_t smax, int c, size_t n)
{
    af57:	55                   	push   %rbp
    af58:	48 89 e5             	mov    %rsp,%rbp
    af5b:	48 83 ec 30          	sub    $0x30,%rsp
    af5f:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    af63:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    af67:	89 55 dc             	mov    %edx,-0x24(%rbp)
    af6a:	48 89 4d d0          	mov    %rcx,-0x30(%rbp)
    errno_t err = 0;
    af6e:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)

    if (s == NULL) {
    af75:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    af7a:	75 09                	jne    af85 <memset_s+0x2e>
        err = EINVAL;
    af7c:	c7 45 fc 16 00 00 00 	movl   $0x16,-0x4(%rbp)
        goto out;
    af83:	eb 30                	jmp    afb5 <memset_s+0x5e>
    }
    if (n > SIZE_MAX) {
        err = E2BIG;
        n = smax;
    }
    if (n > smax) {
    af85:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    af89:	48 3b 45 e0          	cmp    -0x20(%rbp),%rax
    af8d:	76 0f                	jbe    af9e <memset_s+0x47>
        err = EOVERFLOW;
    af8f:	c7 45 fc 4b 00 00 00 	movl   $0x4b,-0x4(%rbp)
        n = smax;
    af96:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    af9a:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    }

    /* Calling through a volatile pointer should never be optimised away. */
    (*__memset_vp)(s, c, n);
    af9e:	48 8b 05 8b 60 00 00 	mov    0x608b(%rip),%rax        # 11030 <__memset_vp>
    afa5:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    afa9:	8b 75 dc             	mov    -0x24(%rbp),%esi
    afac:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
    afb0:	48 89 cf             	mov    %rcx,%rdi
    afb3:	ff d0                	callq  *%rax

    out:
    if (err == 0)
    afb5:	83 7d fc 00          	cmpl   $0x0,-0x4(%rbp)
    afb9:	75 07                	jne    afc2 <memset_s+0x6b>
        return 0;
    afbb:	b8 00 00 00 00       	mov    $0x0,%eax
    afc0:	eb 10                	jmp    afd2 <memset_s+0x7b>
    else {
        errno = err;
    afc2:	e8 0a 06 00 00       	callq  b5d1 <__errno>
    afc7:	48 89 c2             	mov    %rax,%rdx
    afca:	8b 45 fc             	mov    -0x4(%rbp),%eax
    afcd:	89 02                	mov    %eax,(%rdx)
        /* XXX call runtime-constraint handler */
        return err;
    afcf:	8b 45 fc             	mov    -0x4(%rbp),%eax
    }
}
    afd2:	c9                   	leaveq 
    afd3:	c3                   	retq   

000000000000afd4 <heap_init>:
static size_t heap_size __attribute__((section(RELRO_SECTION_NAME))) = 0;
static int is_edmm_supported __attribute__((section(RELRO_SECTION_NAME))) = 0;
static size_t heap_min_size __attribute__((section(RELRO_SECTION_NAME))) = 0;

int heap_init(void *_heap_base, size_t _heap_size, size_t _heap_min_size, int _is_edmm_supported)
{
    afd4:	55                   	push   %rbp
    afd5:	48 89 e5             	mov    %rsp,%rbp
    afd8:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    afdc:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    afe0:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    afe4:	89 4d e4             	mov    %ecx,-0x1c(%rbp)
    if (heap_base != NULL)
    afe7:	48 8b 05 2a 5e 00 00 	mov    0x5e2a(%rip),%rax        # 10e18 <heap_base>
    afee:	48 85 c0             	test   %rax,%rax
    aff1:	74 0a                	je     affd <heap_init+0x29>
        return SGX_ERROR_UNEXPECTED;
    aff3:	b8 01 00 00 00       	mov    $0x1,%eax
    aff8:	e9 8c 00 00 00       	jmpq   b089 <heap_init+0xb5>

    if ((_heap_base == NULL) || (((size_t) _heap_base) & (SE_PAGE_SIZE - 1)))
    affd:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    b002:	74 0e                	je     b012 <heap_init+0x3e>
    b004:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b008:	25 ff 0f 00 00       	and    $0xfff,%eax
    b00d:	48 85 c0             	test   %rax,%rax
    b010:	74 07                	je     b019 <heap_init+0x45>
        return SGX_ERROR_UNEXPECTED;
    b012:	b8 01 00 00 00       	mov    $0x1,%eax
    b017:	eb 70                	jmp    b089 <heap_init+0xb5>

    if (_heap_size & (SE_PAGE_SIZE - 1))
    b019:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b01d:	25 ff 0f 00 00       	and    $0xfff,%eax
    b022:	48 85 c0             	test   %rax,%rax
    b025:	74 07                	je     b02e <heap_init+0x5a>
        return SGX_ERROR_UNEXPECTED;
    b027:	b8 01 00 00 00       	mov    $0x1,%eax
    b02c:	eb 5b                	jmp    b089 <heap_init+0xb5>

    if (_heap_min_size & (SE_PAGE_SIZE - 1))
    b02e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b032:	25 ff 0f 00 00       	and    $0xfff,%eax
    b037:	48 85 c0             	test   %rax,%rax
    b03a:	74 07                	je     b043 <heap_init+0x6f>
        return SGX_ERROR_UNEXPECTED;
    b03c:	b8 01 00 00 00       	mov    $0x1,%eax
    b041:	eb 46                	jmp    b089 <heap_init+0xb5>

    if (_heap_size > SIZE_MAX - (size_t)heap_base)
    b043:	48 8b 05 ce 5d 00 00 	mov    0x5dce(%rip),%rax        # 10e18 <heap_base>
    b04a:	48 f7 d0             	not    %rax
    b04d:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    b051:	76 07                	jbe    b05a <heap_init+0x86>
        return SGX_ERROR_UNEXPECTED;
    b053:	b8 01 00 00 00       	mov    $0x1,%eax
    b058:	eb 2f                	jmp    b089 <heap_init+0xb5>

    heap_base = _heap_base;
    b05a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b05e:	48 89 05 b3 5d 00 00 	mov    %rax,0x5db3(%rip)        # 10e18 <heap_base>
    heap_size = _heap_size;
    b065:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b069:	48 89 05 b0 5d 00 00 	mov    %rax,0x5db0(%rip)        # 10e20 <heap_size>
    heap_min_size = _heap_min_size;
    b070:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b074:	48 89 05 b5 5d 00 00 	mov    %rax,0x5db5(%rip)        # 10e30 <heap_min_size>
    is_edmm_supported = _is_edmm_supported;
    b07b:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    b07e:	89 05 a4 5d 00 00    	mov    %eax,0x5da4(%rip)        # 10e28 <is_edmm_supported>

    return SGX_SUCCESS;
    b084:	b8 00 00 00 00       	mov    $0x0,%eax
}
    b089:	5d                   	pop    %rbp
    b08a:	c3                   	retq   

000000000000b08b <sbrk>:

void* sbrk(intptr_t n)
{
    b08b:	55                   	push   %rbp
    b08c:	48 89 e5             	mov    %rsp,%rbp
    b08f:	48 83 ec 40          	sub    $0x40,%rsp
    b093:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    static size_t heap_used;
    void *heap_ptr = NULL;
    b097:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
    b09e:	00 
    size_t prev_heap_used = heap_used;
    b09f:	48 8b 05 6a 64 00 00 	mov    0x646a(%rip),%rax        # 11510 <heap_used.2393>
    b0a6:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    void * start_addr;
    size_t size = 0;
    b0aa:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    b0b1:	00 

    if (!heap_base)
    b0b2:	48 8b 05 5f 5d 00 00 	mov    0x5d5f(%rip),%rax        # 10e18 <heap_base>
    b0b9:	48 85 c0             	test   %rax,%rax
    b0bc:	75 0c                	jne    b0ca <sbrk+0x3f>
        return (void *)(~(size_t)0);
    b0be:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
    b0c5:	e9 9d 02 00 00       	jmpq   b367 <sbrk+0x2dc>

    /* shrink the heap */
    if (n < 0) {
    b0ca:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    b0cf:	0f 89 31 01 00 00    	jns    b206 <sbrk+0x17b>

        n *= -1;
    b0d5:	48 f7 5d c8          	negq   -0x38(%rbp)
        if (heap_used < n)
    b0d9:	48 8b 15 30 64 00 00 	mov    0x6430(%rip),%rdx        # 11510 <heap_used.2393>
    b0e0:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b0e4:	48 39 c2             	cmp    %rax,%rdx
    b0e7:	73 0c                	jae    b0f5 <sbrk+0x6a>
            return (void *)(~(size_t)0);
    b0e9:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
    b0f0:	e9 72 02 00 00       	jmpq   b367 <sbrk+0x2dc>

        heap_used -= n;
    b0f5:	48 8b 15 14 64 00 00 	mov    0x6414(%rip),%rdx        # 11510 <heap_used.2393>
    b0fc:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b100:	48 29 c2             	sub    %rax,%rdx
    b103:	48 89 d0             	mov    %rdx,%rax
    b106:	48 89 05 03 64 00 00 	mov    %rax,0x6403(%rip)        # 11510 <heap_used.2393>

        /* heap_used is never larger than heap_size, and since heap_size <= SIZE_MAX - (size_t)heap_base,
           there's no integer overflow here.
         */  
        heap_ptr = (void *)((size_t)heap_base + (size_t)heap_used);
    b10d:	48 8b 05 04 5d 00 00 	mov    0x5d04(%rip),%rax        # 10e18 <heap_base>
    b114:	48 89 c2             	mov    %rax,%rdx
    b117:	48 8b 05 f2 63 00 00 	mov    0x63f2(%rip),%rax        # 11510 <heap_used.2393>
    b11e:	48 01 d0             	add    %rdx,%rax
    b121:	48 89 45 f0          	mov    %rax,-0x10(%rbp)

        if (is_edmm_supported && (prev_heap_used > heap_min_size)) 
    b125:	8b 05 fd 5c 00 00    	mov    0x5cfd(%rip),%eax        # 10e28 <is_edmm_supported>
    b12b:	85 c0                	test   %eax,%eax
    b12d:	0f 84 ca 00 00 00    	je     b1fd <sbrk+0x172>
    b133:	48 8b 05 f6 5c 00 00 	mov    0x5cf6(%rip),%rax        # 10e30 <heap_min_size>
    b13a:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    b13e:	0f 86 b9 00 00 00    	jbe    b1fd <sbrk+0x172>
        {
            assert((n & (SE_PAGE_SIZE - 1)) == 0);
    b144:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b148:	25 ff 0f 00 00       	and    $0xfff,%eax
    b14d:	48 85 c0             	test   %rax,%rax
    b150:	74 1f                	je     b171 <sbrk+0xe6>
    b152:	48 8d 0d c7 1f 00 00 	lea    0x1fc7(%rip),%rcx        # d120 <_ZZL16init_stack_guardPvE8__func__+0xc0>
    b159:	48 8d 15 e9 1f 00 00 	lea    0x1fe9(%rip),%rdx        # d149 <__func__.2398>
    b160:	be 65 00 00 00       	mov    $0x65,%esi
    b165:	48 8d 3d d2 1f 00 00 	lea    0x1fd2(%rip),%rdi        # d13e <_ZZL16init_stack_guardPvE8__func__+0xde>
    b16c:	e8 ff a0 ff ff       	callq  5270 <__assert>

            if (heap_used > heap_min_size)
    b171:	48 8b 15 98 63 00 00 	mov    0x6398(%rip),%rdx        # 11510 <heap_used.2393>
    b178:	48 8b 05 b1 5c 00 00 	mov    0x5cb1(%rip),%rax        # 10e30 <heap_min_size>
    b17f:	48 39 c2             	cmp    %rax,%rdx
    b182:	76 12                	jbe    b196 <sbrk+0x10b>
            {
                start_addr = heap_ptr;
    b184:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b188:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
                size = n;
    b18c:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b190:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    b194:	eb 2d                	jmp    b1c3 <sbrk+0x138>
            else
            {
                /* heap_min_size is never larger than heap_size, and since heap_size <= SIZE_MAX - (size_t)heap_base,
                   there's no integer overflow here.
                 */  
                start_addr = (void *)((size_t)(heap_base) + heap_min_size);
    b196:	48 8b 05 7b 5c 00 00 	mov    0x5c7b(%rip),%rax        # 10e18 <heap_base>
    b19d:	48 89 c2             	mov    %rax,%rdx
    b1a0:	48 8b 05 89 5c 00 00 	mov    0x5c89(%rip),%rax        # 10e30 <heap_min_size>
    b1a7:	48 01 d0             	add    %rdx,%rax
    b1aa:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
                size = prev_heap_used - heap_min_size;
    b1ae:	48 8b 05 7b 5c 00 00 	mov    0x5c7b(%rip),%rax        # 10e30 <heap_min_size>
    b1b5:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    b1b9:	48 29 c2             	sub    %rax,%rdx
    b1bc:	48 89 d0             	mov    %rdx,%rax
    b1bf:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
            }
            int ret = trim_EPC_pages(start_addr, size >> SE_PAGE_SHIFT);
    b1c3:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b1c7:	48 c1 e8 0c          	shr    $0xc,%rax
    b1cb:	48 89 c2             	mov    %rax,%rdx
    b1ce:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    b1d2:	48 89 d6             	mov    %rdx,%rsi
    b1d5:	48 89 c7             	mov    %rax,%rdi
    b1d8:	e8 b2 70 ff ff       	callq  228f <trim_EPC_pages>
    b1dd:	89 45 dc             	mov    %eax,-0x24(%rbp)
            if (ret != 0)
    b1e0:	83 7d dc 00          	cmpl   $0x0,-0x24(%rbp)
    b1e4:	74 17                	je     b1fd <sbrk+0x172>
            {
                heap_used = prev_heap_used;
    b1e6:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b1ea:	48 89 05 1f 63 00 00 	mov    %rax,0x631f(%rip)        # 11510 <heap_used.2393>
                return (void *)(~(size_t)0);
    b1f1:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
    b1f8:	e9 6a 01 00 00       	jmpq   b367 <sbrk+0x2dc>
            }
        }
        return heap_ptr;
    b1fd:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b201:	e9 61 01 00 00       	jmpq   b367 <sbrk+0x2dc>
    }

    /* extend the heap */
    if((heap_used > (SIZE_MAX - n)) || ((heap_used + n) > heap_size))
    b206:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b20a:	48 f7 d0             	not    %rax
    b20d:	48 89 c2             	mov    %rax,%rdx
    b210:	48 8b 05 f9 62 00 00 	mov    0x62f9(%rip),%rax        # 11510 <heap_used.2393>
    b217:	48 39 c2             	cmp    %rax,%rdx
    b21a:	72 1a                	jb     b236 <sbrk+0x1ab>
    b21c:	48 8b 15 ed 62 00 00 	mov    0x62ed(%rip),%rdx        # 11510 <heap_used.2393>
    b223:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b227:	48 01 c2             	add    %rax,%rdx
    b22a:	48 8b 05 ef 5b 00 00 	mov    0x5bef(%rip),%rax        # 10e20 <heap_size>
    b231:	48 39 c2             	cmp    %rax,%rdx
    b234:	76 0c                	jbe    b242 <sbrk+0x1b7>
        return (void *)(~(size_t)0);
    b236:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
    b23d:	e9 25 01 00 00       	jmpq   b367 <sbrk+0x2dc>

    /* heap_used is never larger than heap_size, and since heap_size <= SIZE_MAX - (size_t)heap_base,
       there's no integer overflow here.
     */  
    heap_ptr = (void *)((size_t)heap_base + (size_t)heap_used);
    b242:	48 8b 05 cf 5b 00 00 	mov    0x5bcf(%rip),%rax        # 10e18 <heap_base>
    b249:	48 89 c2             	mov    %rax,%rdx
    b24c:	48 8b 05 bd 62 00 00 	mov    0x62bd(%rip),%rax        # 11510 <heap_used.2393>
    b253:	48 01 d0             	add    %rdx,%rax
    b256:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    heap_used += n;
    b25a:	48 8b 15 af 62 00 00 	mov    0x62af(%rip),%rdx        # 11510 <heap_used.2393>
    b261:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b265:	48 01 d0             	add    %rdx,%rax
    b268:	48 89 05 a1 62 00 00 	mov    %rax,0x62a1(%rip)        # 11510 <heap_used.2393>

    /* update g_peak_heap_used */
    g_peak_heap_used = (g_peak_heap_used < heap_used) ? heap_used : g_peak_heap_used;
    b26f:	48 8b 15 92 62 00 00 	mov    0x6292(%rip),%rdx        # 11508 <g_peak_heap_used>
    b276:	48 8b 05 93 62 00 00 	mov    0x6293(%rip),%rax        # 11510 <heap_used.2393>
    b27d:	48 39 c2             	cmp    %rax,%rdx
    b280:	48 0f 43 c2          	cmovae %rdx,%rax
    b284:	48 89 05 7d 62 00 00 	mov    %rax,0x627d(%rip)        # 11508 <g_peak_heap_used>

    if (is_edmm_supported && heap_used > heap_min_size)
    b28b:	8b 05 97 5b 00 00    	mov    0x5b97(%rip),%eax        # 10e28 <is_edmm_supported>
    b291:	85 c0                	test   %eax,%eax
    b293:	0f 84 ca 00 00 00    	je     b363 <sbrk+0x2d8>
    b299:	48 8b 15 70 62 00 00 	mov    0x6270(%rip),%rdx        # 11510 <heap_used.2393>
    b2a0:	48 8b 05 89 5b 00 00 	mov    0x5b89(%rip),%rax        # 10e30 <heap_min_size>
    b2a7:	48 39 c2             	cmp    %rax,%rdx
    b2aa:	0f 86 b3 00 00 00    	jbe    b363 <sbrk+0x2d8>
    {
        assert((n & (SE_PAGE_SIZE - 1)) == 0);
    b2b0:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b2b4:	25 ff 0f 00 00       	and    $0xfff,%eax
    b2b9:	48 85 c0             	test   %rax,%rax
    b2bc:	74 1f                	je     b2dd <sbrk+0x252>
    b2be:	48 8d 0d 5b 1e 00 00 	lea    0x1e5b(%rip),%rcx        # d120 <_ZZL16init_stack_guardPvE8__func__+0xc0>
    b2c5:	48 8d 15 7d 1e 00 00 	lea    0x1e7d(%rip),%rdx        # d149 <__func__.2398>
    b2cc:	be 8d 00 00 00       	mov    $0x8d,%esi
    b2d1:	48 8d 3d 66 1e 00 00 	lea    0x1e66(%rip),%rdi        # d13e <_ZZL16init_stack_guardPvE8__func__+0xde>
    b2d8:	e8 93 9f ff ff       	callq  5270 <__assert>

        if (prev_heap_used > heap_min_size)
    b2dd:	48 8b 05 4c 5b 00 00 	mov    0x5b4c(%rip),%rax        # 10e30 <heap_min_size>
    b2e4:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    b2e8:	76 12                	jbe    b2fc <sbrk+0x271>
        {
            start_addr = heap_ptr;
    b2ea:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b2ee:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
            size = n;
    b2f2:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b2f6:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    b2fa:	eb 30                	jmp    b32c <sbrk+0x2a1>
        {

            /* heap_min_size is never larger than heap_size, and since heap_size <= SIZE_MAX - (size_t)heap_base,
               there's no integer overflow here.
             */  
            start_addr = (void *)((size_t)(heap_base) + heap_min_size);
    b2fc:	48 8b 05 15 5b 00 00 	mov    0x5b15(%rip),%rax        # 10e18 <heap_base>
    b303:	48 89 c2             	mov    %rax,%rdx
    b306:	48 8b 05 23 5b 00 00 	mov    0x5b23(%rip),%rax        # 10e30 <heap_min_size>
    b30d:	48 01 d0             	add    %rdx,%rax
    b310:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
            size = heap_used - heap_min_size;
    b314:	48 8b 15 f5 61 00 00 	mov    0x61f5(%rip),%rdx        # 11510 <heap_used.2393>
    b31b:	48 8b 05 0e 5b 00 00 	mov    0x5b0e(%rip),%rax        # 10e30 <heap_min_size>
    b322:	48 29 c2             	sub    %rax,%rdx
    b325:	48 89 d0             	mov    %rdx,%rax
    b328:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
        }
        int ret = apply_EPC_pages(start_addr, size >> SE_PAGE_SHIFT);
    b32c:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b330:	48 c1 e8 0c          	shr    $0xc,%rax
    b334:	48 89 c2             	mov    %rax,%rdx
    b337:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    b33b:	48 89 d6             	mov    %rdx,%rsi
    b33e:	48 89 c7             	mov    %rax,%rdi
    b341:	e8 76 6e ff ff       	callq  21bc <apply_EPC_pages>
    b346:	89 45 d8             	mov    %eax,-0x28(%rbp)
        if (ret != 0)
    b349:	83 7d d8 00          	cmpl   $0x0,-0x28(%rbp)
    b34d:	74 14                	je     b363 <sbrk+0x2d8>
        {
            heap_used = prev_heap_used;
    b34f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b353:	48 89 05 b6 61 00 00 	mov    %rax,0x61b6(%rip)        # 11510 <heap_used.2393>
            return (void *)(~(size_t)0);
    b35a:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
    b361:	eb 04                	jmp    b367 <sbrk+0x2dc>
        }
    }
    return heap_ptr;
    b363:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
}
    b367:	c9                   	leaveq 
    b368:	c3                   	retq   

000000000000b369 <tstdc_access_version_dummy1>:
#include "stdint.h"
#include "se_cpu_feature.h"
#include "se_cdefs.h"

// add a version to tlibc.
SGX_ACCESS_VERSION(tstdc, 1)
    b369:	55                   	push   %rbp
    b36a:	48 89 e5             	mov    %rsp,%rbp
    b36d:	c6 05 cc 5c 00 00 73 	movb   $0x73,0x5ccc(%rip)        # 11040 <sgx_tstdc_version>
    b374:	48 8d 05 c5 5c 00 00 	lea    0x5cc5(%rip),%rax        # 11040 <sgx_tstdc_version>
    b37b:	5d                   	pop    %rbp
    b37c:	c3                   	retq   

000000000000b37d <sgx_init_string_lib>:
    return _intel_cpu_indicator_init(cpu_feature_indicator);
}

#else
int sgx_init_string_lib(uint64_t cpu_feature_indicator)
{
    b37d:	55                   	push   %rbp
    b37e:	48 89 e5             	mov    %rsp,%rbp
    b381:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    (void)cpu_feature_indicator; 
    return 0;
    b385:	b8 00 00 00 00       	mov    $0x0,%eax
}
    b38a:	5d                   	pop    %rbp
    b38b:	c3                   	retq   

000000000000b38c <sgx_spin_lock>:
    return (res);
   
}

uint32_t sgx_spin_lock(sgx_spinlock_t *lock)
{
    b38c:	55                   	push   %rbp
    b38d:	48 89 e5             	mov    %rsp,%rbp
    b390:	48 83 ec 30          	sub    $0x30,%rsp
    b394:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    b398:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    b39f:	00 00 
    b3a1:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    b3a5:	31 c0                	xor    %eax,%eax
    while(_InterlockedExchange((volatile int *)lock, 1) != 0) {
    b3a7:	eb 0c                	jmp    b3b5 <sgx_spin_lock+0x29>
    __asm __volatile(
    b3a9:	f3 90                	pause  
        while (*lock) {
    b3ab:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    b3af:	8b 00                	mov    (%rax),%eax
    b3b1:	85 c0                	test   %eax,%eax
    b3b3:	75 f4                	jne    b3a9 <sgx_spin_lock+0x1d>
    b3b5:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    b3b9:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    b3bd:	c7 45 ec 01 00 00 00 	movl   $0x1,-0x14(%rbp)
    __asm __volatile(
    b3c4:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b3c8:	8b 55 ec             	mov    -0x14(%rbp),%edx
    b3cb:	f0 87 10             	lock xchg %edx,(%rax)
    b3ce:	89 55 e8             	mov    %edx,-0x18(%rbp)
    return (res);
    b3d1:	8b 45 e8             	mov    -0x18(%rbp),%eax
    while(_InterlockedExchange((volatile int *)lock, 1) != 0) {
    b3d4:	85 c0                	test   %eax,%eax
    b3d6:	75 d3                	jne    b3ab <sgx_spin_lock+0x1f>
            /* tell cpu we are spinning */
            _mm_pause();
        } 
    }

    return (0);
    b3d8:	b8 00 00 00 00       	mov    $0x0,%eax
}
    b3dd:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    b3e1:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    b3e8:	00 00 
    b3ea:	74 05                	je     b3f1 <sgx_spin_lock+0x65>
    b3ec:	e8 76 9e ff ff       	callq  5267 <__stack_chk_fail>
    b3f1:	c9                   	leaveq 
    b3f2:	c3                   	retq   

000000000000b3f3 <sgx_spin_unlock>:

uint32_t sgx_spin_unlock(sgx_spinlock_t *lock)
{
    b3f3:	55                   	push   %rbp
    b3f4:	48 89 e5             	mov    %rsp,%rbp
    b3f7:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    *lock = 0;
    b3fb:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b3ff:	c7 00 00 00 00 00    	movl   $0x0,(%rax)

    return (0);
    b405:	b8 00 00 00 00       	mov    $0x0,%eax
}
    b40a:	5d                   	pop    %rbp
    b40b:	c3                   	retq   

000000000000b40c <_setjmp>:
    xorl    %edx, (_JB_EBP * SE_WORDSIZE)(%eax)
    xorl    %edx, (_JB_ESI * SE_WORDSIZE)(%eax)
    xorl    %edx, (_JB_EDI * SE_WORDSIZE)(%eax)
#endif
#ifdef LINUX64
    PUSHAQ
    b40c:	50                   	push   %rax
    b40d:	53                   	push   %rbx
    b40e:	51                   	push   %rcx
    b40f:	52                   	push   %rdx
    b410:	56                   	push   %rsi
    b411:	57                   	push   %rdi
    b412:	41 50                	push   %r8
    b414:	41 51                	push   %r9
    b416:	41 52                	push   %r10
    b418:	41 53                	push   %r11
    b41a:	41 54                	push   %r12
    b41c:	41 55                	push   %r13
    b41e:	41 56                	push   %r14
    b420:	41 57                	push   %r15
    /* check the buf is within the enclave */
    movq    $SE_WORDSIZE, %rsi
    b422:	48 c7 c6 08 00 00 00 	mov    $0x8,%rsi
    call    sgx_is_within_enclave
    b429:	e8 64 5e ff ff       	callq  1292 <sgx_is_within_enclave>
    cmpl    $0, %eax
    b42e:	83 f8 00             	cmp    $0x0,%eax
    jz      .crash
    b431:	74 60                	je     b493 <.crash>
    POPAQ
    b433:	41 5f                	pop    %r15
    b435:	41 5e                	pop    %r14
    b437:	41 5d                	pop    %r13
    b439:	41 5c                	pop    %r12
    b43b:	41 5b                	pop    %r11
    b43d:	41 5a                	pop    %r10
    b43f:	41 59                	pop    %r9
    b441:	41 58                	pop    %r8
    b443:	5f                   	pop    %rdi
    b444:	5e                   	pop    %rsi
    b445:	5a                   	pop    %rdx
    b446:	59                   	pop    %rcx
    b447:	5b                   	pop    %rbx
    b448:	58                   	pop    %rax
    /* store the registers */
    movq    (%rsp),%r11
    b449:	4c 8b 1c 24          	mov    (%rsp),%r11
    movq    %rbx, (_JB_RBX * SE_WORDSIZE)(%rdi)
    b44d:	48 89 1f             	mov    %rbx,(%rdi)
    movq    %rbp, (_JB_RBP * SE_WORDSIZE)(%rdi)
    b450:	48 89 6f 08          	mov    %rbp,0x8(%rdi)
    movq    %r12, (_JB_R12 * SE_WORDSIZE)(%rdi)
    b454:	4c 89 67 10          	mov    %r12,0x10(%rdi)
    movq    %r13, (_JB_R13 * SE_WORDSIZE)(%rdi)
    b458:	4c 89 6f 18          	mov    %r13,0x18(%rdi)
    movq    %r14, (_JB_R14 * SE_WORDSIZE)(%rdi)
    b45c:	4c 89 77 20          	mov    %r14,0x20(%rdi)
    movq    %r15, (_JB_R15 * SE_WORDSIZE)(%rdi)
    b460:	4c 89 7f 28          	mov    %r15,0x28(%rdi)
    movq    %rsp, (_JB_RSP * SE_WORDSIZE)(%rdi)
    b464:	48 89 67 30          	mov    %rsp,0x30(%rdi)
    movq    %r11, (_JB_PC  * SE_WORDSIZE)(%rdi)
    b468:	4c 89 5f 38          	mov    %r11,0x38(%rdi)
    /* use statck_guard as cookie*/
    call    get_stack_guard
    b46c:	e8 c5 11 00 00       	callq  c636 <get_stack_guard>
    xorq    %rax, (_JB_RBX * SE_WORDSIZE)(%rdi)
    b471:	48 31 07             	xor    %rax,(%rdi)
    xorq    %rax, (_JB_RBP * SE_WORDSIZE)(%rdi)
    b474:	48 31 47 08          	xor    %rax,0x8(%rdi)
    xorq    %rax, (_JB_R12 * SE_WORDSIZE)(%rdi)
    b478:	48 31 47 10          	xor    %rax,0x10(%rdi)
    xorq    %rax, (_JB_R13 * SE_WORDSIZE)(%rdi)
    b47c:	48 31 47 18          	xor    %rax,0x18(%rdi)
    xorq    %rax, (_JB_R14 * SE_WORDSIZE)(%rdi)
    b480:	48 31 47 20          	xor    %rax,0x20(%rdi)
    xorq    %rax, (_JB_R15 * SE_WORDSIZE)(%rdi)
    b484:	48 31 47 28          	xor    %rax,0x28(%rdi)
    xorq    %rax, (_JB_RSP * SE_WORDSIZE)(%rdi)
    b488:	48 31 47 30          	xor    %rax,0x30(%rdi)
    xorq    %rax, (_JB_PC  * SE_WORDSIZE)(%rdi)
    b48c:	48 31 47 38          	xor    %rax,0x38(%rdi)
#endif	
    xorl    %eax,%eax
    b490:	31 c0                	xor    %eax,%eax
    ret
    b492:	c3                   	retq   

000000000000b493 <.crash>:
.crash:
    ud2
    b493:	0f 0b                	ud2    

000000000000b495 <_longjmp>:
    movl    %ecx, (0)(%edx)
    popl    %eax   
    movl    %edx, %esp
#endif
#ifdef LINUX64
    PUSHAQ
    b495:	50                   	push   %rax
    b496:	53                   	push   %rbx
    b497:	51                   	push   %rcx
    b498:	52                   	push   %rdx
    b499:	56                   	push   %rsi
    b49a:	57                   	push   %rdi
    b49b:	41 50                	push   %r8
    b49d:	41 51                	push   %r9
    b49f:	41 52                	push   %r10
    b4a1:	41 53                	push   %r11
    b4a3:	41 54                	push   %r12
    b4a5:	41 55                	push   %r13
    b4a7:	41 56                	push   %r14
    b4a9:	41 57                	push   %r15
    pushq   %rdi
    b4ab:	57                   	push   %rdi
    /* check the buf is within the enclave */
    movq    $SE_WORDSIZE, %rsi
    b4ac:	48 c7 c6 08 00 00 00 	mov    $0x8,%rsi
    call    sgx_is_within_enclave
    b4b3:	e8 da 5d ff ff       	callq  1292 <sgx_is_within_enclave>
    cmpl    $0, %eax
    b4b8:	83 f8 00             	cmp    $0x0,%eax
    jz      .crash
    b4bb:	74 d6                	je     b493 <.crash>
    popq     %rdi
    b4bd:	5f                   	pop    %rdi
    /* restore xsp*/
    movq    (_JB_RSP * SE_WORDSIZE)(%rdi),%rdx
    b4be:	48 8b 57 30          	mov    0x30(%rdi),%rdx
    call    get_stack_guard
    b4c2:	e8 6f 11 00 00       	callq  c636 <get_stack_guard>
    xorq    %rax, %rdx
    b4c7:	48 31 c2             	xor    %rax,%rdx
    pushq   %rdx
    b4ca:	52                   	push   %rdx
    /* check restored rsp is on current statck */
    popq    %rdi
    b4cb:	5f                   	pop    %rdi
    call    is_valid_sp
    b4cc:	e8 48 87 ff ff       	callq  3c19 <is_valid_sp>
    cmpl    $0, %eax
    b4d1:	83 f8 00             	cmp    $0x0,%eax
    jz      .crash
    b4d4:	74 bd                	je     b493 <.crash>
    POPAQ
    b4d6:	41 5f                	pop    %r15
    b4d8:	41 5e                	pop    %r14
    b4da:	41 5d                	pop    %r13
    b4dc:	41 5c                	pop    %r12
    b4de:	41 5b                	pop    %r11
    b4e0:	41 5a                	pop    %r10
    b4e2:	41 59                	pop    %r9
    b4e4:	41 58                	pop    %r8
    b4e6:	5f                   	pop    %rdi
    b4e7:	5e                   	pop    %rsi
    b4e8:	5a                   	pop    %rdx
    b4e9:	59                   	pop    %rcx
    b4ea:	5b                   	pop    %rbx
    b4eb:	58                   	pop    %rax
    /* restore the registers */
    movl    %esi,%eax
    b4ec:	89 f0                	mov    %esi,%eax
    movq    (_JB_RBX * SE_WORDSIZE)(%rdi),%rbx
    b4ee:	48 8b 1f             	mov    (%rdi),%rbx
    movq    (_JB_RBP * SE_WORDSIZE)(%rdi),%rsi
    b4f1:	48 8b 77 08          	mov    0x8(%rdi),%rsi
    movq    (_JB_R12 * SE_WORDSIZE)(%rdi),%r12
    b4f5:	4c 8b 67 10          	mov    0x10(%rdi),%r12
    movq    (_JB_R13 * SE_WORDSIZE)(%rdi),%r13
    b4f9:	4c 8b 6f 18          	mov    0x18(%rdi),%r13
    movq    (_JB_R14 * SE_WORDSIZE)(%rdi),%r14
    b4fd:	4c 8b 77 20          	mov    0x20(%rdi),%r14
    movq    (_JB_R15 * SE_WORDSIZE)(%rdi),%r15
    b501:	4c 8b 7f 28          	mov    0x28(%rdi),%r15
    movq    (_JB_RSP * SE_WORDSIZE)(%rdi),%rdx
    b505:	48 8b 57 30          	mov    0x30(%rdi),%rdx
    movq    (_JB_PC  * SE_WORDSIZE)(%rdi),%rcx
    b509:	48 8b 4f 38          	mov    0x38(%rdi),%rcx
    pushq   %rax
    b50d:	50                   	push   %rax
    call    get_stack_guard
    b50e:	e8 23 11 00 00       	callq  c636 <get_stack_guard>
    xorq    %rax, %rbx
    b513:	48 31 c3             	xor    %rax,%rbx
    xorq    %rax, %rsi
    b516:	48 31 c6             	xor    %rax,%rsi
    xorq    %rax, %r12
    b519:	49 31 c4             	xor    %rax,%r12
    xorq    %rax, %r13
    b51c:	49 31 c5             	xor    %rax,%r13
    xorq    %rax, %r14
    b51f:	49 31 c6             	xor    %rax,%r14
    xorq    %rax, %r15
    b522:	49 31 c7             	xor    %rax,%r15
    xorq    %rax, %rdx
    b525:	48 31 c2             	xor    %rax,%rdx
    xorq    %rax, %rcx
    b528:	48 31 c1             	xor    %rax,%rcx
    popq    %rax
    b52b:	58                   	pop    %rax
    movq    %rsi, %rbp
    b52c:	48 89 f5             	mov    %rsi,%rbp
    movq    %rcx, 0(%rdx)
    b52f:	48 89 0a             	mov    %rcx,(%rdx)
    movq    %rdx, %rsp
    b532:	48 89 d4             	mov    %rdx,%rsp
#endif
    testl   %eax,%eax
    b535:	85 c0                	test   %eax,%eax
    jnz     1f
    b537:	75 02                	jne    b53b <_longjmp+0xa6>
    incl    %eax
    b539:	ff c0                	inc    %eax
1:  ret
    b53b:	c3                   	retq   

000000000000b53c <rsrv_mem_init>:

SE_DECLSPEC_EXPORT size_t g_peak_rsrv_mem_committed = 0;


extern "C" int rsrv_mem_init(void *_rsrv_mem_base, size_t _rsrv_mem_size, size_t _rsrv_mem_min_size)
{
    b53c:	55                   	push   %rbp
    b53d:	48 89 e5             	mov    %rsp,%rbp
    b540:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    b544:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    b548:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    if ((_rsrv_mem_base == NULL) || (((size_t) _rsrv_mem_base) & (SE_PAGE_SIZE - 1)))
    b54c:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    b551:	74 0e                	je     b561 <rsrv_mem_init+0x25>
    b553:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b557:	25 ff 0f 00 00       	and    $0xfff,%eax
    b55c:	48 85 c0             	test   %rax,%rax
    b55f:	74 07                	je     b568 <rsrv_mem_init+0x2c>
        return SGX_ERROR_UNEXPECTED;
    b561:	b8 01 00 00 00       	mov    $0x1,%eax
    b566:	eb 67                	jmp    b5cf <rsrv_mem_init+0x93>

    if (_rsrv_mem_size & (SE_PAGE_SIZE - 1))
    b568:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b56c:	25 ff 0f 00 00       	and    $0xfff,%eax
    b571:	48 85 c0             	test   %rax,%rax
    b574:	74 07                	je     b57d <rsrv_mem_init+0x41>
        return SGX_ERROR_UNEXPECTED;
    b576:	b8 01 00 00 00       	mov    $0x1,%eax
    b57b:	eb 52                	jmp    b5cf <rsrv_mem_init+0x93>

    if (_rsrv_mem_min_size & (SE_PAGE_SIZE - 1))
    b57d:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b581:	25 ff 0f 00 00       	and    $0xfff,%eax
    b586:	48 85 c0             	test   %rax,%rax
    b589:	74 07                	je     b592 <rsrv_mem_init+0x56>
        return SGX_ERROR_UNEXPECTED;
    b58b:	b8 01 00 00 00       	mov    $0x1,%eax
    b590:	eb 3d                	jmp    b5cf <rsrv_mem_init+0x93>

    if (_rsrv_mem_size > SIZE_MAX - (size_t)rsrv_mem_base)
    b592:	48 8b 05 9f 58 00 00 	mov    0x589f(%rip),%rax        # 10e38 <rsrv_mem_base>
    b599:	48 f7 d0             	not    %rax
    b59c:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    b5a0:	76 07                	jbe    b5a9 <rsrv_mem_init+0x6d>
        return SGX_ERROR_UNEXPECTED;
    b5a2:	b8 01 00 00 00       	mov    $0x1,%eax
    b5a7:	eb 26                	jmp    b5cf <rsrv_mem_init+0x93>

    rsrv_mem_base = _rsrv_mem_base;
    b5a9:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b5ad:	48 89 05 84 58 00 00 	mov    %rax,0x5884(%rip)        # 10e38 <rsrv_mem_base>
    rsrv_mem_size = _rsrv_mem_size;
    b5b4:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b5b8:	48 89 05 81 58 00 00 	mov    %rax,0x5881(%rip)        # 10e40 <rsrv_mem_size>
    rsrv_mem_min_size = _rsrv_mem_min_size;
    b5bf:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b5c3:	48 89 05 7e 58 00 00 	mov    %rax,0x587e(%rip)        # 10e48 <rsrv_mem_min_size>

    return SGX_SUCCESS;
    b5ca:	b8 00 00 00 00       	mov    $0x0,%eax
}
    b5cf:	5d                   	pop    %rbp
    b5d0:	c3                   	retq   

000000000000b5d1 <__errno>:
#include <errno.h>

extern int *get_errno_addr(void);

int *__errno(void)
{
    b5d1:	55                   	push   %rbp
    b5d2:	48 89 e5             	mov    %rsp,%rbp
/*
 * get errno's address from TD section.
 */
    return get_errno_addr();
    b5d5:	e8 07 85 ff ff       	callq  3ae1 <get_errno_addr>
}
    b5da:	5d                   	pop    %rbp
    b5db:	c3                   	retq   

000000000000b5dc <tcrypto_access_version_dummy1>:
#include "ippcp.h"
#include "se_cpu_feature.h"
#include "se_cdefs.h"

// add a version to tcrypto.
SGX_ACCESS_VERSION(tcrypto, 1)
    b5dc:	55                   	push   %rbp
    b5dd:	48 89 e5             	mov    %rsp,%rbp
    b5e0:	c6 05 79 5a 00 00 73 	movb   $0x73,0x5a79(%rip)        # 11060 <sgx_tcrypto_version>
    b5e7:	48 8d 05 72 5a 00 00 	lea    0x5a72(%rip),%rax        # 11060 <sgx_tcrypto_version>
    b5ee:	5d                   	pop    %rbp
    b5ef:	c3                   	retq   

000000000000b5f0 <sgx_init_crypto_lib>:
/* Crypto Library Initialization
* Parameters:
* 	Return: sgx_status_t  - SGX_SUCCESS or failure as defined sgx_error.h
*	Inputs: uint64_t cpu_feature_indicator - Bit array of host CPU feature bits */
extern "C" sgx_status_t sgx_init_crypto_lib(uint64_t cpu_feature_indicator, uint32_t *cpuid_table)
{
    b5f0:	55                   	push   %rbp
    b5f1:	48 89 e5             	mov    %rsp,%rbp
    b5f4:	48 83 ec 10          	sub    $0x10,%rsp
    b5f8:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    b5fc:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    (void)(cpuid_table);

    return init_ipp_cpuid(cpu_feature_indicator);
    b600:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b604:	48 89 c7             	mov    %rax,%rdi
    b607:	e8 02 00 00 00       	callq  b60e <init_ipp_cpuid>
}
    b60c:	c9                   	leaveq 
    b60d:	c3                   	retq   

000000000000b60e <init_ipp_cpuid>:
/* IPP library Initialization
* Parameters:
* 	Return: sgx_status_t  - SGX_SUCCESS or failure as defined sgx_error.h
*	Inputs: uint64_t cpu_feature_indicator - Bit array of host CPU feature bits */
extern "C" sgx_status_t init_ipp_cpuid(uint64_t cpu_feature_indicator)
{
    b60e:	55                   	push   %rbp
    b60f:	48 89 e5             	mov    %rsp,%rbp
    b612:	48 83 ec 20          	sub    $0x20,%rsp
    b616:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    IppStatus error_code = ippStsNoOperation;
    b61a:	c7 45 f4 01 00 00 00 	movl   $0x1,-0xc(%rbp)
    if (ippcpSetCpuFeatures == NULL) {
    b621:	48 8b 05 c8 59 00 00 	mov    0x59c8(%rip),%rax        # 10ff0 <ippcpSetCpuFeatures>
    b628:	48 85 c0             	test   %rax,%rax
    b62b:	75 0a                	jne    b637 <init_ipp_cpuid+0x29>
        return SGX_SUCCESS;
    b62d:	b8 00 00 00 00       	mov    $0x0,%eax
    b632:	e9 81 02 00 00       	jmpq   b8b8 <init_ipp_cpuid+0x2aa>
    //       1. AVX2
    //       2. SSE4.1
    //  We set SSE4.1 as the baseline.
    // Set the IPP feature bits based on host attributes that have been collected
    // NOTE: Some sanity check
    Ipp64u ippCpuFeatures = 0;
    b637:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    b63e:	00 
    if ((cpu_feature_indicator & CPU_FEATURE_SSE4_1) == CPU_FEATURE_SSE4_1)
    b63f:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b643:	25 00 02 00 00       	and    $0x200,%eax
    b648:	48 85 c0             	test   %rax,%rax
    b64b:	0f 84 31 02 00 00    	je     b882 <init_ipp_cpuid+0x274>
    {
        // Some sanity checking has been performed when setting the feature mask
        // If SSE4.1 is set, then all earlier SSE/MMX ISA enhancements are available
        ippCpuFeatures |= (ippCPUID_SSE41 | ippCPUID_MMX | ippCPUID_SSE |
    b651:	48 83 4d f8 5f       	orq    $0x5f,-0x8(%rbp)
            ippCPUID_SSE2 | ippCPUID_SSE3 | ippCPUID_SSSE3);
        if ((cpu_feature_indicator & CPU_FEATURE_MOVBE) == CPU_FEATURE_MOVBE)
    b656:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b65a:	25 00 08 00 00       	and    $0x800,%eax
    b65f:	48 85 c0             	test   %rax,%rax
    b662:	74 05                	je     b669 <init_ipp_cpuid+0x5b>
        {
            ippCpuFeatures |= ippCPUID_MOVBE;
    b664:	48 83 4d f8 20       	orq    $0x20,-0x8(%rbp)
        }
        if ((cpu_feature_indicator & CPU_FEATURE_SSE4_2) == CPU_FEATURE_SSE4_2)
    b669:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b66d:	25 00 04 00 00       	and    $0x400,%eax
    b672:	48 85 c0             	test   %rax,%rax
    b675:	74 08                	je     b67f <init_ipp_cpuid+0x71>
        {
            ippCpuFeatures |= ippCPUID_SSE42;
    b677:	48 81 4d f8 80 00 00 	orq    $0x80,-0x8(%rbp)
    b67e:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX) == CPU_FEATURE_AVX)
    b67f:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b683:	25 00 00 01 00       	and    $0x10000,%eax
    b688:	48 85 c0             	test   %rax,%rax
    b68b:	74 10                	je     b69d <init_ipp_cpuid+0x8f>
        {
            ippCpuFeatures |= ippCPUID_AVX;
    b68d:	48 81 4d f8 00 01 00 	orq    $0x100,-0x8(%rbp)
    b694:	00 
            ippCpuFeatures |= ippAVX_ENABLEDBYOS;
    b695:	48 81 4d f8 00 02 00 	orq    $0x200,-0x8(%rbp)
    b69c:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AES) == CPU_FEATURE_AES)
    b69d:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b6a1:	25 00 40 00 00       	and    $0x4000,%eax
    b6a6:	48 85 c0             	test   %rax,%rax
    b6a9:	74 08                	je     b6b3 <init_ipp_cpuid+0xa5>
        {
            ippCpuFeatures |= ippCPUID_AES;
    b6ab:	48 81 4d f8 00 04 00 	orq    $0x400,-0x8(%rbp)
    b6b2:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_PCLMULQDQ) == CPU_FEATURE_PCLMULQDQ)
    b6b3:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b6b7:	25 00 20 00 00       	and    $0x2000,%eax
    b6bc:	48 85 c0             	test   %rax,%rax
    b6bf:	74 08                	je     b6c9 <init_ipp_cpuid+0xbb>
        {
            ippCpuFeatures |= ippCPUID_CLMUL;
    b6c1:	48 81 4d f8 00 08 00 	orq    $0x800,-0x8(%rbp)
    b6c8:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_RDRND) == CPU_FEATURE_RDRND)
    b6c9:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b6cd:	25 00 00 02 00       	and    $0x20000,%eax
    b6d2:	48 85 c0             	test   %rax,%rax
    b6d5:	74 08                	je     b6df <init_ipp_cpuid+0xd1>
        {
            ippCpuFeatures |= ippCPUID_RDRAND;
    b6d7:	48 81 4d f8 00 20 00 	orq    $0x2000,-0x8(%rbp)
    b6de:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_F16C) == CPU_FEATURE_F16C)
    b6df:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b6e3:	25 00 80 00 00       	and    $0x8000,%eax
    b6e8:	48 85 c0             	test   %rax,%rax
    b6eb:	74 08                	je     b6f5 <init_ipp_cpuid+0xe7>
        {
            ippCpuFeatures |= ippCPUID_F16C;
    b6ed:	48 81 4d f8 00 40 00 	orq    $0x4000,-0x8(%rbp)
    b6f4:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX2) == CPU_FEATURE_AVX2)
    b6f5:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b6f9:	25 00 00 80 00       	and    $0x800000,%eax
    b6fe:	48 85 c0             	test   %rax,%rax
    b701:	74 08                	je     b70b <init_ipp_cpuid+0xfd>
        {
            ippCpuFeatures |= ippCPUID_AVX2;
    b703:	48 81 4d f8 00 80 00 	orq    $0x8000,-0x8(%rbp)
    b70a:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_ADX) == CPU_FEATURE_ADX)
    b70b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b70f:	25 00 00 00 10       	and    $0x10000000,%eax
    b714:	48 85 c0             	test   %rax,%rax
    b717:	74 08                	je     b721 <init_ipp_cpuid+0x113>
        {
            ippCpuFeatures |= ippCPUID_ADCOX;
    b719:	48 81 4d f8 00 00 01 	orq    $0x10000,-0x8(%rbp)
    b720:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_RDSEED) == CPU_FEATURE_RDSEED)
    b721:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b725:	25 00 00 00 20       	and    $0x20000000,%eax
    b72a:	48 85 c0             	test   %rax,%rax
    b72d:	74 08                	je     b737 <init_ipp_cpuid+0x129>
        {
            ippCpuFeatures |= ippCPUID_RDSEED;
    b72f:	48 81 4d f8 00 00 02 	orq    $0x20000,-0x8(%rbp)
    b736:	00 
        }
	if ((cpu_feature_indicator & CPU_FEATURE_SHA) == CPU_FEATURE_SHA)
    b737:	48 b8 00 00 00 00 08 	movabs $0x800000000,%rax
    b73e:	00 00 00 
    b741:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b745:	48 85 c0             	test   %rax,%rax
    b748:	74 08                	je     b752 <init_ipp_cpuid+0x144>
        {
            ippCpuFeatures |= ippCPUID_SHA;
    b74a:	48 81 4d f8 00 00 08 	orq    $0x80000,-0x8(%rbp)
    b751:	00 
        }
        
	// AVX512
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512F) == CPU_FEATURE_AVX512F)
    b752:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b756:	25 00 00 00 08       	and    $0x8000000,%eax
    b75b:	48 85 c0             	test   %rax,%rax
    b75e:	74 16                	je     b776 <init_ipp_cpuid+0x168>
        {
            ippCpuFeatures |= ippCPUID_AVX512F;
    b760:	48 81 4d f8 00 00 10 	orq    $0x100000,-0x8(%rbp)
    b767:	00 
            ippCpuFeatures |= ippAVX512_ENABLEDBYOS;
    b768:	48 b8 00 00 00 00 02 	movabs $0x200000000,%rax
    b76f:	00 00 00 
    b772:	48 09 45 f8          	or     %rax,-0x8(%rbp)
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512PF) == CPU_FEATURE_AVX512PF)
    b776:	48 b8 00 00 00 00 02 	movabs $0x200000000,%rax
    b77d:	00 00 00 
    b780:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b784:	48 85 c0             	test   %rax,%rax
    b787:	74 08                	je     b791 <init_ipp_cpuid+0x183>
        {
            ippCpuFeatures |= ippCPUID_AVX512PF;
    b789:	48 81 4d f8 00 00 80 	orq    $0x800000,-0x8(%rbp)
    b790:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512ER) == CPU_FEATURE_AVX512ER)
    b791:	48 b8 00 00 00 00 01 	movabs $0x100000000,%rax
    b798:	00 00 00 
    b79b:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b79f:	48 85 c0             	test   %rax,%rax
    b7a2:	74 08                	je     b7ac <init_ipp_cpuid+0x19e>
        {
            ippCpuFeatures |= ippCPUID_AVX512ER;
    b7a4:	48 81 4d f8 00 00 40 	orq    $0x400000,-0x8(%rbp)
    b7ab:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512CD) == CPU_FEATURE_AVX512CD)
    b7ac:	48 b8 00 00 00 00 04 	movabs $0x400000000,%rax
    b7b3:	00 00 00 
    b7b6:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b7ba:	48 85 c0             	test   %rax,%rax
    b7bd:	74 08                	je     b7c7 <init_ipp_cpuid+0x1b9>
        {
            ippCpuFeatures |= ippCPUID_AVX512CD;
    b7bf:	48 81 4d f8 00 00 20 	orq    $0x200000,-0x8(%rbp)
    b7c6:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512DQ) == CPU_FEATURE_AVX512DQ)
    b7c7:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b7cb:	25 00 00 00 01       	and    $0x1000000,%eax
    b7d0:	48 85 c0             	test   %rax,%rax
    b7d3:	74 08                	je     b7dd <init_ipp_cpuid+0x1cf>
        {
            ippCpuFeatures |= ippCPUID_AVX512DQ;
    b7d5:	48 81 4d f8 00 00 00 	orq    $0x2000000,-0x8(%rbp)
    b7dc:	02 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512BW) == CPU_FEATURE_AVX512BW)
    b7dd:	48 b8 00 00 00 00 20 	movabs $0x2000000000,%rax
    b7e4:	00 00 00 
    b7e7:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b7eb:	48 85 c0             	test   %rax,%rax
    b7ee:	74 08                	je     b7f8 <init_ipp_cpuid+0x1ea>
        {
            ippCpuFeatures |= ippCPUID_AVX512BW;
    b7f0:	48 81 4d f8 00 00 00 	orq    $0x1000000,-0x8(%rbp)
    b7f7:	01 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512VL) == CPU_FEATURE_AVX512VL)
    b7f8:	48 b8 00 00 00 00 40 	movabs $0x4000000000,%rax
    b7ff:	00 00 00 
    b802:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b806:	48 85 c0             	test   %rax,%rax
    b809:	74 08                	je     b813 <init_ipp_cpuid+0x205>
        {
            ippCpuFeatures |= ippCPUID_AVX512VL;
    b80b:	48 81 4d f8 00 00 00 	orq    $0x4000000,-0x8(%rbp)
    b812:	04 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512VBMI) == CPU_FEATURE_AVX512VBMI)
    b813:	48 b8 00 00 00 00 80 	movabs $0x8000000000,%rax
    b81a:	00 00 00 
    b81d:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b821:	48 85 c0             	test   %rax,%rax
    b824:	74 08                	je     b82e <init_ipp_cpuid+0x220>
        {
            ippCpuFeatures |= ippCPUID_AVX512VBMI;
    b826:	48 81 4d f8 00 00 00 	orq    $0x8000000,-0x8(%rbp)
    b82d:	08 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512_4VNNIW) == CPU_FEATURE_AVX512_4VNNIW)
    b82e:	48 b8 00 00 00 00 00 	movabs $0x20000000000,%rax
    b835:	02 00 00 
    b838:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b83c:	48 85 c0             	test   %rax,%rax
    b83f:	74 08                	je     b849 <init_ipp_cpuid+0x23b>
        {
            ippCpuFeatures |= ippCPUID_AVX512_4VNNIW;
    b841:	48 81 4d f8 00 00 00 	orq    $0x40000000,-0x8(%rbp)
    b848:	40 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512_4FMAPS) == CPU_FEATURE_AVX512_4FMAPS)
    b849:	48 b8 00 00 00 00 00 	movabs $0x10000000000,%rax
    b850:	01 00 00 
    b853:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b857:	48 85 c0             	test   %rax,%rax
    b85a:	74 08                	je     b864 <init_ipp_cpuid+0x256>
        {
            ippCpuFeatures |= ippCPUID_AVX512_4FMADDPS;
    b85c:	48 81 4d f8 00 00 00 	orq    $0x20000000,-0x8(%rbp)
    b863:	20 
        }

        if ((cpu_feature_indicator & CPU_FEATURE_AVX512IFMA52) == CPU_FEATURE_AVX512IFMA52)
    b864:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b868:	25 00 00 00 40       	and    $0x40000000,%eax
    b86d:	48 85 c0             	test   %rax,%rax
    b870:	74 17                	je     b889 <init_ipp_cpuid+0x27b>
        {
            ippCpuFeatures |= ippCPUID_AVX512IFMA;
    b872:	48 b8 00 00 00 00 01 	movabs $0x100000000,%rax
    b879:	00 00 00 
    b87c:	48 09 45 f8          	or     %rax,-0x8(%rbp)
    b880:	eb 07                	jmp    b889 <init_ipp_cpuid+0x27b>
        }
    }
    else
    {
        // Return error if the old platoform has no SSE4.1
        return SGX_ERROR_INVALID_PARAMETER;
    b882:	b8 02 00 00 00       	mov    $0x2,%eax
    b887:	eb 2f                	jmp    b8b8 <init_ipp_cpuid+0x2aa>

    }

    // Call SetCpuFeatures() to set the IPP library with the collected CPU features
    ippCpuFeatures |= ippCPUID_NOCHECK; /* Force ippcpSetCpuFeatures to set CPU features without check */
    b889:	48 b8 00 00 00 00 00 	movabs $0x8000000000000000,%rax
    b890:	00 00 80 
    b893:	48 09 45 f8          	or     %rax,-0x8(%rbp)
    error_code = ippcpSetCpuFeatures(ippCpuFeatures);
    b897:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b89b:	48 89 c7             	mov    %rax,%rdi
    b89e:	e8 75 57 ff ff       	callq  1018 <ippcpSetCpuFeatures@plt>
    b8a3:	89 45 f4             	mov    %eax,-0xc(%rbp)

    if (error_code != ippStsNoErr)
    b8a6:	83 7d f4 00          	cmpl   $0x0,-0xc(%rbp)
    b8aa:	74 07                	je     b8b3 <init_ipp_cpuid+0x2a5>
    {
        return SGX_ERROR_INVALID_PARAMETER;
    b8ac:	b8 02 00 00 00       	mov    $0x2,%eax
    b8b1:	eb 05                	jmp    b8b8 <init_ipp_cpuid+0x2aa>
    }
    return SGX_SUCCESS;
    b8b3:	b8 00 00 00 00       	mov    $0x0,%eax
}
    b8b8:	c9                   	leaveq 
    b8b9:	c3                   	retq   

000000000000b8ba <tservice_access_version_dummy1>:
#include "sgx_trts.h"
#include "trts_inst.h"
#include "se_cdefs.h"

// add a version to tservice.
SGX_ACCESS_VERSION(tservice, 1)
    b8ba:	55                   	push   %rbp
    b8bb:	48 89 e5             	mov    %rsp,%rbp
    b8be:	c6 05 bb 57 00 00 73 	movb   $0x73,0x57bb(%rip)        # 11080 <sgx_tservice_version>
    b8c5:	48 8d 05 b4 57 00 00 	lea    0x57b4(%rip),%rax        # 11080 <sgx_tservice_version>
    b8cc:	5d                   	pop    %rbp
    b8cd:	c3                   	retq   

000000000000b8ce <sgx_create_report>:

extern "C" void * __memset(void *dst, int c, size_t n);

sgx_status_t sgx_create_report(const sgx_target_info_t *target_info, const sgx_report_data_t *report_data, sgx_report_t *report)
{
    b8ce:	4c 8d 54 24 08       	lea    0x8(%rsp),%r10
    b8d3:	48 81 e4 00 fe ff ff 	and    $0xfffffffffffffe00,%rsp
    b8da:	41 ff 72 f8          	pushq  -0x8(%r10)
    b8de:	55                   	push   %rbp
    b8df:	48 89 e5             	mov    %rsp,%rbp
    b8e2:	41 52                	push   %r10
    b8e4:	48 81 ec e8 09 00 00 	sub    $0x9e8,%rsp
    b8eb:	48 89 bd 78 f7 ff ff 	mov    %rdi,-0x888(%rbp)
    b8f2:	48 89 b5 70 f7 ff ff 	mov    %rsi,-0x890(%rbp)
    b8f9:	48 89 95 68 f7 ff ff 	mov    %rdx,-0x898(%rbp)
    b900:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    b907:	00 00 
    b909:	48 89 85 08 fe ff ff 	mov    %rax,-0x1f8(%rbp)
    b910:	31 c0                	xor    %eax,%eax
    static_assert(sizeof(*target_info) == 512, "sgx_target_info_t");
    static_assert(sizeof(*report_data) == 64, "sgx_report_data_t");
    static_assert(sizeof(*report) == 432, "sgx_report_t");

    alignas(REPORT_DATA_ALIGN_SIZE) sgx_report_data_t tmp_report_data;
    __memset((void *)&tmp_report_data, 0, sizeof(sgx_report_data_t));
    b912:	48 8d 85 90 f7 ff ff 	lea    -0x870(%rbp),%rax
    b919:	ba 40 00 00 00       	mov    $0x40,%edx
    b91e:	be 00 00 00 00       	mov    $0x0,%esi
    b923:	48 89 c7             	mov    %rax,%rdi
    b926:	e8 c1 f5 ff ff       	callq  aeec <__memset>
    alignas(TARGET_INFO_ALIGN_SIZE) sgx_target_info_t tmp_target_info;
    __memset((void *)&tmp_target_info, 0, sizeof(sgx_target_info_t));    
    b92b:	48 8d 85 10 fa ff ff 	lea    -0x5f0(%rbp),%rax
    b932:	ba 00 02 00 00       	mov    $0x200,%edx
    b937:	be 00 00 00 00       	mov    $0x0,%esi
    b93c:	48 89 c7             	mov    %rax,%rdi
    b93f:	e8 a8 f5 ff ff       	callq  aeec <__memset>
    alignas(REPORT_ALIGN_SIZE)sgx_report_t tmp_report;
    __memset((void *)&tmp_report, 0, sizeof(sgx_report_t));
    b944:	48 8d 85 10 f8 ff ff 	lea    -0x7f0(%rbp),%rax
    b94b:	ba b0 01 00 00       	mov    $0x1b0,%edx
    b950:	be 00 00 00 00       	mov    $0x0,%esi
    b955:	48 89 c7             	mov    %rax,%rdi
    b958:	e8 8f f5 ff ff       	callq  aeec <__memset>

    // check parameters
    //
    // target_info is allowed to be NULL, but if it is not NULL, it must be within the enclave
    if(target_info)
    b95d:	48 83 bd 78 f7 ff ff 	cmpq   $0x0,-0x888(%rbp)
    b964:	00 
    b965:	74 46                	je     b9ad <sgx_create_report+0xdf>
    {
        if (!sgx_is_within_enclave(target_info, sizeof(*target_info)))
    b967:	48 8b 85 78 f7 ff ff 	mov    -0x888(%rbp),%rax
    b96e:	be 00 02 00 00       	mov    $0x200,%esi
    b973:	48 89 c7             	mov    %rax,%rdi
    b976:	e8 17 59 ff ff       	callq  1292 <sgx_is_within_enclave>
    b97b:	85 c0                	test   %eax,%eax
    b97d:	0f 94 c0             	sete   %al
    b980:	84 c0                	test   %al,%al
    b982:	74 0a                	je     b98e <sgx_create_report+0xc0>
            return SGX_ERROR_INVALID_PARAMETER;
    b984:	b8 02 00 00 00       	mov    $0x2,%eax
    b989:	e9 8a 01 00 00       	jmpq   bb18 <sgx_create_report+0x24a>
        tmp_target_info = *target_info;
    b98e:	48 8b 95 78 f7 ff ff 	mov    -0x888(%rbp),%rdx
    b995:	48 8d 85 10 fa ff ff 	lea    -0x5f0(%rbp),%rax
    b99c:	48 89 d6             	mov    %rdx,%rsi
    b99f:	ba 40 00 00 00       	mov    $0x40,%edx
    b9a4:	48 89 c7             	mov    %rax,%rdi
    b9a7:	48 89 d1             	mov    %rdx,%rcx
    b9aa:	f3 48 a5             	rep movsq %ds:(%rsi),%es:(%rdi)
    }
    // report_data is allowed to be NULL, but if it is not NULL, it must be within the enclave
    if(report_data)
    b9ad:	48 83 bd 70 f7 ff ff 	cmpq   $0x0,-0x890(%rbp)
    b9b4:	00 
    b9b5:	0f 84 85 00 00 00    	je     ba40 <sgx_create_report+0x172>
    {
        if(!sgx_is_within_enclave(report_data, sizeof(*report_data)))
    b9bb:	48 8b 85 70 f7 ff ff 	mov    -0x890(%rbp),%rax
    b9c2:	be 40 00 00 00       	mov    $0x40,%esi
    b9c7:	48 89 c7             	mov    %rax,%rdi
    b9ca:	e8 c3 58 ff ff       	callq  1292 <sgx_is_within_enclave>
    b9cf:	85 c0                	test   %eax,%eax
    b9d1:	0f 94 c0             	sete   %al
    b9d4:	84 c0                	test   %al,%al
    b9d6:	74 0a                	je     b9e2 <sgx_create_report+0x114>
            return SGX_ERROR_INVALID_PARAMETER;
    b9d8:	b8 02 00 00 00       	mov    $0x2,%eax
    b9dd:	e9 36 01 00 00       	jmpq   bb18 <sgx_create_report+0x24a>
        tmp_report_data = *report_data;
    b9e2:	48 8b 8d 70 f7 ff ff 	mov    -0x890(%rbp),%rcx
    b9e9:	48 8b 01             	mov    (%rcx),%rax
    b9ec:	48 8b 51 08          	mov    0x8(%rcx),%rdx
    b9f0:	48 89 85 90 f7 ff ff 	mov    %rax,-0x870(%rbp)
    b9f7:	48 89 95 98 f7 ff ff 	mov    %rdx,-0x868(%rbp)
    b9fe:	48 8b 41 10          	mov    0x10(%rcx),%rax
    ba02:	48 8b 51 18          	mov    0x18(%rcx),%rdx
    ba06:	48 89 85 a0 f7 ff ff 	mov    %rax,-0x860(%rbp)
    ba0d:	48 89 95 a8 f7 ff ff 	mov    %rdx,-0x858(%rbp)
    ba14:	48 8b 41 20          	mov    0x20(%rcx),%rax
    ba18:	48 8b 51 28          	mov    0x28(%rcx),%rdx
    ba1c:	48 89 85 b0 f7 ff ff 	mov    %rax,-0x850(%rbp)
    ba23:	48 89 95 b8 f7 ff ff 	mov    %rdx,-0x848(%rbp)
    ba2a:	48 8b 41 30          	mov    0x30(%rcx),%rax
    ba2e:	48 8b 51 38          	mov    0x38(%rcx),%rdx
    ba32:	48 89 85 c0 f7 ff ff 	mov    %rax,-0x840(%rbp)
    ba39:	48 89 95 c8 f7 ff ff 	mov    %rdx,-0x838(%rbp)
    }
    // report must be within the enclave
    if(!report || !sgx_is_within_enclave(report, sizeof(*report)))
    ba40:	48 83 bd 68 f7 ff ff 	cmpq   $0x0,-0x898(%rbp)
    ba47:	00 
    ba48:	74 18                	je     ba62 <sgx_create_report+0x194>
    ba4a:	48 8b 85 68 f7 ff ff 	mov    -0x898(%rbp),%rax
    ba51:	be b0 01 00 00       	mov    $0x1b0,%esi
    ba56:	48 89 c7             	mov    %rax,%rdi
    ba59:	e8 34 58 ff ff       	callq  1292 <sgx_is_within_enclave>
    ba5e:	85 c0                	test   %eax,%eax
    ba60:	75 07                	jne    ba69 <sgx_create_report+0x19b>
    ba62:	b8 01 00 00 00       	mov    $0x1,%eax
    ba67:	eb 05                	jmp    ba6e <sgx_create_report+0x1a0>
    ba69:	b8 00 00 00 00       	mov    $0x0,%eax
    ba6e:	84 c0                	test   %al,%al
    ba70:	74 0a                	je     ba7c <sgx_create_report+0x1ae>
    {
        return SGX_ERROR_INVALID_PARAMETER;
    ba72:	b8 02 00 00 00       	mov    $0x2,%eax
    ba77:	e9 9c 00 00 00       	jmpq   bb18 <sgx_create_report+0x24a>
    }


    // Do EREPORT
    auto failed = do_ereport(&tmp_target_info, &tmp_report_data, &tmp_report);
    ba7c:	48 8d 95 10 f8 ff ff 	lea    -0x7f0(%rbp),%rdx
    ba83:	48 8d 8d 90 f7 ff ff 	lea    -0x870(%rbp),%rcx
    ba8a:	48 8d 85 10 fa ff ff 	lea    -0x5f0(%rbp),%rax
    ba91:	48 89 ce             	mov    %rcx,%rsi
    ba94:	48 89 c7             	mov    %rax,%rdi
    ba97:	e8 56 0e 00 00       	callq  c8f2 <do_ereport>
    ba9c:	89 85 84 f7 ff ff    	mov    %eax,-0x87c(%rbp)
    
    // Copy data to the user buffer: *report = tmp_report; 
    // Use a loop to avoid compiler to call memcpy, 
    // which cannot be used during enclave initialization.
    // No need to cleanup the tmp_report as it is not secret.
    if (!failed)
    baa2:	83 bd 84 f7 ff ff 00 	cmpl   $0x0,-0x87c(%rbp)
    baa9:	75 57                	jne    bb02 <sgx_create_report+0x234>
    {
        static_assert(sizeof(*report) % sizeof(uint64_t) == 0, "sizeof(sgx_report_t) should be multiple of 8");
        for(size_t i = 0; i < sizeof(*report)/sizeof(uint64_t); i++)
    baab:	48 c7 85 88 f7 ff ff 	movq   $0x0,-0x878(%rbp)
    bab2:	00 00 00 00 
    bab6:	48 83 bd 88 f7 ff ff 	cmpq   $0x35,-0x878(%rbp)
    babd:	35 
    babe:	77 42                	ja     bb02 <sgx_create_report+0x234>
        {
            ((uint64_t*)report)[i] = ((uint64_t*)&tmp_report)[i];
    bac0:	48 8b 85 88 f7 ff ff 	mov    -0x878(%rbp),%rax
    bac7:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    bace:	00 
    bacf:	48 8d 85 10 f8 ff ff 	lea    -0x7f0(%rbp),%rax
    bad6:	48 01 d0             	add    %rdx,%rax
    bad9:	48 8b 95 88 f7 ff ff 	mov    -0x878(%rbp),%rdx
    bae0:	48 8d 0c d5 00 00 00 	lea    0x0(,%rdx,8),%rcx
    bae7:	00 
    bae8:	48 8b 95 68 f7 ff ff 	mov    -0x898(%rbp),%rdx
    baef:	48 01 ca             	add    %rcx,%rdx
    baf2:	48 8b 00             	mov    (%rax),%rax
    baf5:	48 89 02             	mov    %rax,(%rdx)
        for(size_t i = 0; i < sizeof(*report)/sizeof(uint64_t); i++)
    baf8:	48 83 85 88 f7 ff ff 	addq   $0x1,-0x878(%rbp)
    baff:	01 
    bb00:	eb b4                	jmp    bab6 <sgx_create_report+0x1e8>
        }
    }


    return failed ? SGX_ERROR_UNEXPECTED : SGX_SUCCESS;
    bb02:	83 bd 84 f7 ff ff 00 	cmpl   $0x0,-0x87c(%rbp)
    bb09:	74 07                	je     bb12 <sgx_create_report+0x244>
    bb0b:	b8 01 00 00 00       	mov    $0x1,%eax
    bb10:	eb 06                	jmp    bb18 <sgx_create_report+0x24a>
    bb12:	b8 00 00 00 00       	mov    $0x0,%eax
    bb17:	90                   	nop
}
    bb18:	48 8b b5 08 fe ff ff 	mov    -0x1f8(%rbp),%rsi
    bb1f:	64 48 33 34 25 28 00 	xor    %fs:0x28,%rsi
    bb26:	00 00 
    bb28:	74 05                	je     bb2f <sgx_create_report+0x261>
    bb2a:	e8 38 97 ff ff       	callq  5267 <__stack_chk_fail>
    bb2f:	48 81 c4 e8 09 00 00 	add    $0x9e8,%rsp
    bb36:	41 5a                	pop    %r10
    bb38:	5d                   	pop    %rbp
    bb39:	49 8d 62 f8          	lea    -0x8(%r10),%rsp
    bb3d:	c3                   	retq   

000000000000bb3e <sgx_self_report>:

const sgx_report_t *sgx_self_report(void)
{
    bb3e:	55                   	push   %rbp
    bb3f:	48 89 e5             	mov    %rsp,%rbp
        .mac = {0}
    };

    // Below sgx_create_report() will be called only once during the enclave initialization,
    // so there is no potential race conditional.
    if (0 == _report.body.attributes.flags)
    bb42:	48 8b 05 07 5a 00 00 	mov    0x5a07(%rip),%rax        # 11550 <_ZZ15sgx_self_reportE7_report+0x30>
    bb49:	48 85 c0             	test   %rax,%rax
    bb4c:	75 16                	jne    bb64 <sgx_self_report+0x26>
        sgx_create_report(nullptr, nullptr, &_report);
    bb4e:	48 8d 15 cb 59 00 00 	lea    0x59cb(%rip),%rdx        # 11520 <_ZZ15sgx_self_reportE7_report>
    bb55:	be 00 00 00 00       	mov    $0x0,%esi
    bb5a:	bf 00 00 00 00       	mov    $0x0,%edi
    bb5f:	e8 6a fd ff ff       	callq  b8ce <sgx_create_report>

    return &_report;
    bb64:	48 8d 05 b5 59 00 00 	lea    0x59b5(%rip),%rax        # 11520 <_ZZ15sgx_self_reportE7_report>
}
    bb6b:	5d                   	pop    %rbp
    bb6c:	c3                   	retq   

Disassembly of section .nipx:

000000000000bb6d <do_init_enclave>:
#endif

extern size_t rsrv_mem_min_size;

sgx_status_t do_init_enclave(void *ms, void *tcs)
{
    bb6d:	55                   	push   %rbp
    bb6e:	48 89 e5             	mov    %rsp,%rbp
    bb71:	48 83 ec 20          	sub    $0x20,%rsp
    bb75:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    bb79:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
#ifdef SE_SIM
    UNUSED(tcs);
#endif
    void *enclave_base = get_enclave_base();
    bb7d:	e8 6f 0a 00 00       	callq  c5f1 <get_enclave_base>
    bb82:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    if(ENCLAVE_INIT_NOT_STARTED != lock_enclave())
    bb86:	e8 85 0a 00 00       	callq  c610 <lock_enclave>
    bb8b:	85 c0                	test   %eax,%eax
    bb8d:	0f 95 c0             	setne  %al
    bb90:	84 c0                	test   %al,%al
    bb92:	74 0a                	je     bb9e <do_init_enclave+0x31>
    {
        return SGX_ERROR_UNEXPECTED;
    bb94:	b8 01 00 00 00       	mov    $0x1,%eax
    bb99:	e9 fa 01 00 00       	jmpq   bd98 <do_init_enclave+0x22b>
    }
    if(0 != init_enclave(enclave_base, ms))
    bb9e:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    bba2:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    bba6:	48 89 d6             	mov    %rdx,%rsi
    bba9:	48 89 c7             	mov    %rax,%rdi
    bbac:	e8 e9 01 00 00       	callq  bd9a <init_enclave>
    bbb1:	85 c0                	test   %eax,%eax
    bbb3:	0f 95 c0             	setne  %al
    bbb6:	84 c0                	test   %al,%al
    bbb8:	74 0a                	je     bbc4 <do_init_enclave+0x57>
    {
        return SGX_ERROR_UNEXPECTED;
    bbba:	b8 01 00 00 00       	mov    $0x1,%eax
    bbbf:	e9 d4 01 00 00       	jmpq   bd98 <do_init_enclave+0x22b>
    }

#ifndef SE_SIM
    if (SGX_SUCCESS != do_init_thread(tcs, true))
    bbc4:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    bbc8:	be 01 00 00 00       	mov    $0x1,%esi
    bbcd:	48 89 c7             	mov    %rax,%rdi
    bbd0:	e8 71 6f ff ff       	callq  2b46 <do_init_thread>
    bbd5:	85 c0                	test   %eax,%eax
    bbd7:	0f 95 c0             	setne  %al
    bbda:	84 c0                	test   %al,%al
    bbdc:	74 0a                	je     bbe8 <do_init_enclave+0x7b>
    {
        return SGX_ERROR_UNEXPECTED;
    bbde:	b8 01 00 00 00       	mov    $0x1,%eax
    bbe3:	e9 b0 01 00 00       	jmpq   bd98 <do_init_enclave+0x22b>
    }

    /* for EDMM, we need to accept the trimming of the POST_REMOVE pages. */
    if (EDMM_supported)
    bbe8:	8b 05 12 52 00 00    	mov    0x5212(%rip),%eax        # 10e00 <EDMM_supported>
    bbee:	85 c0                	test   %eax,%eax
    bbf0:	0f 84 1d 01 00 00    	je     bd13 <do_init_enclave+0x1a6>
    {
        if (0 != accept_post_remove(&g_global_data.layout_table[0], &g_global_data.layout_table[0] + g_global_data.layout_entry_num, 0))
    bbf6:	48 8d 05 83 15 00 00 	lea    0x1583(%rip),%rax        # d180 <g_global_data>
    bbfd:	8b 80 28 01 00 00    	mov    0x128(%rax),%eax
    bc03:	89 c0                	mov    %eax,%eax
    bc05:	48 c1 e0 05          	shl    $0x5,%rax
    bc09:	48 89 c2             	mov    %rax,%rdx
    bc0c:	48 8d 05 6d 15 00 00 	lea    0x156d(%rip),%rax        # d180 <g_global_data>
    bc13:	48 8d 80 30 01 00 00 	lea    0x130(%rax),%rax
    bc1a:	48 01 d0             	add    %rdx,%rax
    bc1d:	ba 00 00 00 00       	mov    $0x0,%edx
    bc22:	48 89 c6             	mov    %rax,%rsi
    bc25:	48 8d 05 54 15 00 00 	lea    0x1554(%rip),%rax        # d180 <g_global_data>
    bc2c:	48 8d b8 30 01 00 00 	lea    0x130(%rax),%rdi
    bc33:	e8 5e 5d ff ff       	callq  1996 <_Z18accept_post_removePVK9_layout_tS1_m>
    bc38:	85 c0                	test   %eax,%eax
    bc3a:	0f 95 c0             	setne  %al
    bc3d:	84 c0                	test   %al,%al
    bc3f:	74 0a                	je     bc4b <do_init_enclave+0xde>
            return SGX_ERROR_UNEXPECTED;
    bc41:	b8 01 00 00 00       	mov    $0x1,%eax
    bc46:	e9 4d 01 00 00       	jmpq   bd98 <do_init_enclave+0x22b>

        size_t heap_min_size = get_heap_min_size();
    bc4b:	e8 e4 7c ff ff       	callq  3934 <get_heap_min_size>
    bc50:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
        memset_s(GET_PTR(void, enclave_base, g_global_data.heap_offset), heap_min_size, 0, heap_min_size);
    bc54:	48 8d 05 25 15 00 00 	lea    0x1525(%rip),%rax        # d180 <g_global_data>
    bc5b:	48 8b 50 08          	mov    0x8(%rax),%rdx
    bc5f:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    bc63:	48 01 d0             	add    %rdx,%rax
    bc66:	48 89 c7             	mov    %rax,%rdi
    bc69:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    bc6d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    bc71:	48 89 d1             	mov    %rdx,%rcx
    bc74:	ba 00 00 00 00       	mov    $0x0,%edx
    bc79:	48 89 c6             	mov    %rax,%rsi
    bc7c:	e8 d6 f2 ff ff       	callq  af57 <memset_s>

        memset_s(GET_PTR(void, enclave_base, g_global_data.rsrv_offset), rsrv_mem_min_size, 0, rsrv_mem_min_size);
    bc81:	48 8d 05 c0 51 00 00 	lea    0x51c0(%rip),%rax        # 10e48 <rsrv_mem_min_size>
    bc88:	48 8b 10             	mov    (%rax),%rdx
    bc8b:	48 8d 05 b6 51 00 00 	lea    0x51b6(%rip),%rax        # 10e48 <rsrv_mem_min_size>
    bc92:	48 8b 00             	mov    (%rax),%rax
    bc95:	48 8d 0d e4 14 00 00 	lea    0x14e4(%rip),%rcx        # d180 <g_global_data>
    bc9c:	48 8b 71 18          	mov    0x18(%rcx),%rsi
    bca0:	48 8b 4d f0          	mov    -0x10(%rbp),%rcx
    bca4:	48 01 f1             	add    %rsi,%rcx
    bca7:	48 89 cf             	mov    %rcx,%rdi
    bcaa:	48 89 d1             	mov    %rdx,%rcx
    bcad:	ba 00 00 00 00       	mov    $0x0,%edx
    bcb2:	48 89 c6             	mov    %rax,%rsi
    bcb5:	e8 9d f2 ff ff       	callq  af57 <memset_s>
        // save all the static threads into the thread table. These TCS would be trimmed in the uninit flow
        if (add_static_threads(
            &g_global_data.layout_table[0],
            &g_global_data.layout_table[0] + g_global_data.layout_entry_num,
    bcba:	48 8d 05 bf 14 00 00 	lea    0x14bf(%rip),%rax        # d180 <g_global_data>
    bcc1:	8b 80 28 01 00 00    	mov    0x128(%rax),%eax
    bcc7:	89 c0                	mov    %eax,%eax
    bcc9:	48 c1 e0 05          	shl    $0x5,%rax
    bccd:	48 89 c2             	mov    %rax,%rdx
        if (add_static_threads(
    bcd0:	48 8d 05 a9 14 00 00 	lea    0x14a9(%rip),%rax        # d180 <g_global_data>
    bcd7:	48 8d 80 30 01 00 00 	lea    0x130(%rax),%rax
    bcde:	48 01 d0             	add    %rdx,%rax
    bce1:	ba 00 00 00 00       	mov    $0x0,%edx
    bce6:	48 89 c6             	mov    %rax,%rsi
    bce9:	48 8d 05 90 14 00 00 	lea    0x1490(%rip),%rax        # d180 <g_global_data>
    bcf0:	48 8d b8 30 01 00 00 	lea    0x130(%rax),%rdi
    bcf7:	e8 16 05 00 00       	callq  c212 <_ZL18add_static_threadsPVK9_layout_tS1_m>
            0) != 0)
    bcfc:	85 c0                	test   %eax,%eax
    bcfe:	0f 95 c0             	setne  %al
        if (add_static_threads(
    bd01:	84 c0                	test   %al,%al
    bd03:	0f 84 80 00 00 00    	je     bd89 <do_init_enclave+0x21c>
        {
            return SGX_ERROR_UNEXPECTED;
    bd09:	b8 01 00 00 00       	mov    $0x1,%eax
    bd0e:	e9 85 00 00 00       	jmpq   bd98 <do_init_enclave+0x22b>
        }
    }
    else
    {
        memset_s(GET_PTR(void, enclave_base, g_global_data.heap_offset), g_global_data.heap_size, 0, g_global_data.heap_size);
    bd13:	48 8d 05 66 14 00 00 	lea    0x1466(%rip),%rax        # d180 <g_global_data>
    bd1a:	48 8b 50 10          	mov    0x10(%rax),%rdx
    bd1e:	48 8d 05 5b 14 00 00 	lea    0x145b(%rip),%rax        # d180 <g_global_data>
    bd25:	48 8b 40 10          	mov    0x10(%rax),%rax
    bd29:	48 8d 0d 50 14 00 00 	lea    0x1450(%rip),%rcx        # d180 <g_global_data>
    bd30:	48 8b 71 08          	mov    0x8(%rcx),%rsi
    bd34:	48 8b 4d f0          	mov    -0x10(%rbp),%rcx
    bd38:	48 01 f1             	add    %rsi,%rcx
    bd3b:	48 89 cf             	mov    %rcx,%rdi
    bd3e:	48 89 d1             	mov    %rdx,%rcx
    bd41:	ba 00 00 00 00       	mov    $0x0,%edx
    bd46:	48 89 c6             	mov    %rax,%rsi
    bd49:	e8 09 f2 ff ff       	callq  af57 <memset_s>
        memset_s(GET_PTR(void, enclave_base, g_global_data.rsrv_offset), g_global_data.rsrv_size, 0, g_global_data.rsrv_size);
    bd4e:	48 8d 05 2b 14 00 00 	lea    0x142b(%rip),%rax        # d180 <g_global_data>
    bd55:	48 8b 50 20          	mov    0x20(%rax),%rdx
    bd59:	48 8d 05 20 14 00 00 	lea    0x1420(%rip),%rax        # d180 <g_global_data>
    bd60:	48 8b 40 20          	mov    0x20(%rax),%rax
    bd64:	48 8d 0d 15 14 00 00 	lea    0x1415(%rip),%rcx        # d180 <g_global_data>
    bd6b:	48 8b 71 18          	mov    0x18(%rcx),%rsi
    bd6f:	48 8b 4d f0          	mov    -0x10(%rbp),%rcx
    bd73:	48 01 f1             	add    %rsi,%rcx
    bd76:	48 89 cf             	mov    %rcx,%rdi
    bd79:	48 89 d1             	mov    %rdx,%rcx
    bd7c:	ba 00 00 00 00       	mov    $0x0,%edx
    bd81:	48 89 c6             	mov    %rax,%rsi
    bd84:	e8 ce f1 ff ff       	callq  af57 <memset_s>
    }
#endif

    g_enclave_state = ENCLAVE_INIT_DONE;
    bd89:	c7 05 0d 53 00 00 02 	movl   $0x2,0x530d(%rip)        # 110a0 <g_enclave_state>
    bd90:	00 00 00 
    return SGX_SUCCESS;
    bd93:	b8 00 00 00 00       	mov    $0x0,%eax
}
    bd98:	c9                   	leaveq 
    bd99:	c3                   	retq   

000000000000bd9a <init_enclave>:
{
    bd9a:	55                   	push   %rbp
    bd9b:	48 89 e5             	mov    %rsp,%rbp
    bd9e:	41 55                	push   %r13
    bda0:	41 54                	push   %r12
    bda2:	53                   	push   %rbx
    bda3:	48 81 ec 18 01 00 00 	sub    $0x118,%rsp
    bdaa:	48 89 bd d8 fe ff ff 	mov    %rdi,-0x128(%rbp)
    bdb1:	48 89 b5 d0 fe ff ff 	mov    %rsi,-0x130(%rbp)
    bdb8:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    bdbf:	00 00 
    bdc1:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    bdc5:	31 c0                	xor    %eax,%eax
    if(enclave_base == NULL || ms == NULL)
    bdc7:	48 83 bd d8 fe ff ff 	cmpq   $0x0,-0x128(%rbp)
    bdce:	00 
    bdcf:	74 0a                	je     bddb <init_enclave+0x41>
    bdd1:	48 83 bd d0 fe ff ff 	cmpq   $0x0,-0x130(%rbp)
    bdd8:	00 
    bdd9:	75 0a                	jne    bde5 <init_enclave+0x4b>
        return -1;
    bddb:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    bde0:	e9 0b 04 00 00       	jmpq   c1f0 <init_enclave+0x456>
    if(NULL != pcl_entry)
    bde5:	48 8b 05 fc 51 00 00 	mov    0x51fc(%rip),%rax        # 10fe8 <_Z9pcl_entryPvS_>
    bdec:	48 85 c0             	test   %rax,%rax
    bdef:	74 67                	je     be58 <init_enclave+0xbe>
        sgx_lfence();
    bdf1:	0f ae e8             	lfence 
        system_features_t * csi = (system_features_t *)ms;
    bdf4:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    bdfb:	48 89 85 08 ff ff ff 	mov    %rax,-0xf8(%rbp)
        if(NULL == csi->sealed_key)
    be02:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    be09:	48 8b 80 94 00 00 00 	mov    0x94(%rax),%rax
    be10:	48 85 c0             	test   %rax,%rax
    be13:	75 0a                	jne    be1f <init_enclave+0x85>
            return -1;
    be15:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    be1a:	e9 d1 03 00 00       	jmpq   c1f0 <init_enclave+0x456>
        sgx_status_t ret = pcl_entry(enclave_base, csi->sealed_key);
    be1f:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    be26:	48 8b 90 94 00 00 00 	mov    0x94(%rax),%rdx
    be2d:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    be34:	48 89 d6             	mov    %rdx,%rsi
    be37:	48 89 c7             	mov    %rax,%rdi
    be3a:	e8 d1 51 ff ff       	callq  1010 <_Z9pcl_entryPvS_@plt>
    be3f:	89 85 ec fe ff ff    	mov    %eax,-0x114(%rbp)
        if(SGX_SUCCESS != ret)
    be45:	83 bd ec fe ff ff 00 	cmpl   $0x0,-0x114(%rbp)
    be4c:	74 0a                	je     be58 <init_enclave+0xbe>
            return -1;
    be4e:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    be53:	e9 98 03 00 00       	jmpq   c1f0 <init_enclave+0x456>
    if(0 != relocate_enclave(enclave_base))
    be58:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    be5f:	48 89 c7             	mov    %rax,%rdi
    be62:	e8 93 88 ff ff       	callq  46fa <relocate_enclave>
    be67:	85 c0                	test   %eax,%eax
    be69:	0f 95 c0             	setne  %al
    be6c:	84 c0                	test   %al,%al
    be6e:	74 0a                	je     be7a <init_enclave+0xe0>
        return -1;
    be70:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    be75:	e9 76 03 00 00       	jmpq   c1f0 <init_enclave+0x456>
    system_features_t *info = (system_features_t *)ms;
    be7a:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    be81:	48 89 85 10 ff ff ff 	mov    %rax,-0xf0(%rbp)
    if(!sgx_is_outside_enclave(info, sizeof(system_features_t)))
    be88:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    be8f:	be b0 00 00 00       	mov    $0xb0,%esi
    be94:	48 89 c7             	mov    %rax,%rdi
    be97:	e8 86 54 ff ff       	callq  1322 <sgx_is_outside_enclave>
    be9c:	85 c0                	test   %eax,%eax
    be9e:	0f 94 c0             	sete   %al
    bea1:	84 c0                	test   %al,%al
    bea3:	74 0a                	je     beaf <init_enclave+0x115>
        return -1;
    bea5:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    beaa:	e9 41 03 00 00       	jmpq   c1f0 <init_enclave+0x456>
    sgx_lfence();
    beaf:	0f ae e8             	lfence 
    system_features_t sys_features = *info;
    beb2:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    beb9:	48 8b 10             	mov    (%rax),%rdx
    bebc:	48 8b 48 08          	mov    0x8(%rax),%rcx
    bec0:	48 89 95 20 ff ff ff 	mov    %rdx,-0xe0(%rbp)
    bec7:	48 89 8d 28 ff ff ff 	mov    %rcx,-0xd8(%rbp)
    bece:	48 8b 50 10          	mov    0x10(%rax),%rdx
    bed2:	48 8b 48 18          	mov    0x18(%rax),%rcx
    bed6:	48 89 95 30 ff ff ff 	mov    %rdx,-0xd0(%rbp)
    bedd:	48 89 8d 38 ff ff ff 	mov    %rcx,-0xc8(%rbp)
    bee4:	48 8b 50 20          	mov    0x20(%rax),%rdx
    bee8:	48 8b 48 28          	mov    0x28(%rax),%rcx
    beec:	48 89 95 40 ff ff ff 	mov    %rdx,-0xc0(%rbp)
    bef3:	48 89 8d 48 ff ff ff 	mov    %rcx,-0xb8(%rbp)
    befa:	48 8b 50 30          	mov    0x30(%rax),%rdx
    befe:	48 8b 48 38          	mov    0x38(%rax),%rcx
    bf02:	48 89 95 50 ff ff ff 	mov    %rdx,-0xb0(%rbp)
    bf09:	48 89 8d 58 ff ff ff 	mov    %rcx,-0xa8(%rbp)
    bf10:	48 8b 50 40          	mov    0x40(%rax),%rdx
    bf14:	48 8b 48 48          	mov    0x48(%rax),%rcx
    bf18:	48 89 95 60 ff ff ff 	mov    %rdx,-0xa0(%rbp)
    bf1f:	48 89 8d 68 ff ff ff 	mov    %rcx,-0x98(%rbp)
    bf26:	48 8b 50 50          	mov    0x50(%rax),%rdx
    bf2a:	48 8b 48 58          	mov    0x58(%rax),%rcx
    bf2e:	48 89 95 70 ff ff ff 	mov    %rdx,-0x90(%rbp)
    bf35:	48 89 8d 78 ff ff ff 	mov    %rcx,-0x88(%rbp)
    bf3c:	48 8b 50 60          	mov    0x60(%rax),%rdx
    bf40:	48 8b 48 68          	mov    0x68(%rax),%rcx
    bf44:	48 89 55 80          	mov    %rdx,-0x80(%rbp)
    bf48:	48 89 4d 88          	mov    %rcx,-0x78(%rbp)
    bf4c:	48 8b 50 70          	mov    0x70(%rax),%rdx
    bf50:	48 8b 48 78          	mov    0x78(%rax),%rcx
    bf54:	48 89 55 90          	mov    %rdx,-0x70(%rbp)
    bf58:	48 89 4d 98          	mov    %rcx,-0x68(%rbp)
    bf5c:	48 8b 90 80 00 00 00 	mov    0x80(%rax),%rdx
    bf63:	48 8b 88 88 00 00 00 	mov    0x88(%rax),%rcx
    bf6a:	48 89 55 a0          	mov    %rdx,-0x60(%rbp)
    bf6e:	48 89 4d a8          	mov    %rcx,-0x58(%rbp)
    bf72:	48 8b 90 90 00 00 00 	mov    0x90(%rax),%rdx
    bf79:	48 8b 88 98 00 00 00 	mov    0x98(%rax),%rcx
    bf80:	48 89 55 b0          	mov    %rdx,-0x50(%rbp)
    bf84:	48 89 4d b8          	mov    %rcx,-0x48(%rbp)
    bf88:	48 8b 90 a8 00 00 00 	mov    0xa8(%rax),%rdx
    bf8f:	48 8b 80 a0 00 00 00 	mov    0xa0(%rax),%rax
    bf96:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    bf9a:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
    size_t offset = 0;
    bf9e:	48 c7 85 f0 fe ff ff 	movq   $0x0,-0x110(%rbp)
    bfa5:	00 00 00 00 
    if(sys_features.system_feature_set[0] & (1ULL<< SYS_FEATURE_EXTEND))
    bfa9:	48 8b 95 2c ff ff ff 	mov    -0xd4(%rbp),%rdx
    bfb0:	48 b8 00 00 00 00 00 	movabs $0x4000000000000000,%rax
    bfb7:	00 00 40 
    bfba:	48 21 d0             	and    %rdx,%rax
    bfbd:	48 85 c0             	test   %rax,%rax
    bfc0:	74 1c                	je     bfde <init_enclave+0x244>
        offset = (sys_features.size < sizeof(sys_features)) ? sys_features.size : sizeof(sys_features);
    bfc2:	48 8b 45 bc          	mov    -0x44(%rbp),%rax
    bfc6:	ba b0 00 00 00       	mov    $0xb0,%edx
    bfcb:	48 3d b0 00 00 00    	cmp    $0xb0,%rax
    bfd1:	48 0f 47 c2          	cmova  %rdx,%rax
    bfd5:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    bfdc:	eb 0b                	jmp    bfe9 <init_enclave+0x24f>
        offset = offsetof(system_features_t, size);
    bfde:	48 c7 85 f0 fe ff ff 	movq   $0x9c,-0x110(%rbp)
    bfe5:	9c 00 00 00 
    for(size_t i = 0; i < sizeof(sys_features) - offset; i++)
    bfe9:	48 c7 85 f8 fe ff ff 	movq   $0x0,-0x108(%rbp)
    bff0:	00 00 00 00 
    bff4:	b8 b0 00 00 00       	mov    $0xb0,%eax
    bff9:	48 2b 85 f0 fe ff ff 	sub    -0x110(%rbp),%rax
    c000:	48 39 85 f8 fe ff ff 	cmp    %rax,-0x108(%rbp)
    c007:	73 28                	jae    c031 <init_enclave+0x297>
        *((uint8_t *)&sys_features + offset + i) = 0;
    c009:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    c010:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    c017:	48 01 c2             	add    %rax,%rdx
    c01a:	48 8d 85 20 ff ff ff 	lea    -0xe0(%rbp),%rax
    c021:	48 01 d0             	add    %rdx,%rax
    c024:	c6 00 00             	movb   $0x0,(%rax)
    for(size_t i = 0; i < sizeof(sys_features) - offset; i++)
    c027:	48 83 85 f8 fe ff ff 	addq   $0x1,-0x108(%rbp)
    c02e:	01 
    c02f:	eb c3                	jmp    bff4 <init_enclave+0x25a>
    g_cpu_core_num = sys_features.cpu_core_num;
    c031:	8b 45 cc             	mov    -0x34(%rbp),%eax
    c034:	89 05 ce 4d 00 00    	mov    %eax,0x4dce(%rip)        # 10e08 <g_cpu_core_num>
    g_sdk_version = sys_features.version;
    c03a:	8b 85 28 ff ff ff    	mov    -0xd8(%rbp),%eax
    c040:	89 05 be 4d 00 00    	mov    %eax,0x4dbe(%rip)        # 10e04 <g_sdk_version>
    if (g_sdk_version == SDK_VERSION_1_5)
    c046:	8b 05 b8 4d 00 00    	mov    0x4db8(%rip),%eax        # 10e04 <g_sdk_version>
    c04c:	85 c0                	test   %eax,%eax
    c04e:	75 0c                	jne    c05c <init_enclave+0x2c2>
        EDMM_supported = 0;
    c050:	c7 05 a6 4d 00 00 00 	movl   $0x0,0x4da6(%rip)        # 10e00 <EDMM_supported>
    c057:	00 00 00 
    c05a:	eb 34                	jmp    c090 <init_enclave+0x2f6>
    else if (g_sdk_version >= SDK_VERSION_2_0)
    c05c:	8b 05 a2 4d 00 00    	mov    0x4da2(%rip),%eax        # 10e04 <g_sdk_version>
    c062:	85 c0                	test   %eax,%eax
    c064:	7e 20                	jle    c086 <init_enclave+0x2ec>
        EDMM_supported = feature_supported((const uint64_t *)sys_features.system_feature_set, 0);
    c066:	48 8d 85 20 ff ff ff 	lea    -0xe0(%rbp),%rax
    c06d:	48 83 c0 0c          	add    $0xc,%rax
    c071:	be 00 00 00 00       	mov    $0x0,%esi
    c076:	48 89 c7             	mov    %rax,%rdi
    c079:	e8 7e 7a ff ff       	callq  3afc <feature_supported>
    c07e:	89 05 7c 4d 00 00    	mov    %eax,0x4d7c(%rip)        # 10e00 <EDMM_supported>
    c084:	eb 0a                	jmp    c090 <init_enclave+0x2f6>
        return -1;
    c086:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c08b:	e9 60 01 00 00       	jmpq   c1f0 <init_enclave+0x456>
    if (heap_init(get_heap_base(), get_heap_size(), get_heap_min_size(), EDMM_supported) != SGX_SUCCESS)
    c090:	8b 1d 6a 4d 00 00    	mov    0x4d6a(%rip),%ebx        # 10e00 <EDMM_supported>
    c096:	e8 99 78 ff ff       	callq  3934 <get_heap_min_size>
    c09b:	49 89 c5             	mov    %rax,%r13
    c09e:	e8 ff 77 ff ff       	callq  38a2 <get_heap_size>
    c0a3:	49 89 c4             	mov    %rax,%r12
    c0a6:	e8 dc 77 ff ff       	callq  3887 <get_heap_base>
    c0ab:	89 d9                	mov    %ebx,%ecx
    c0ad:	4c 89 ea             	mov    %r13,%rdx
    c0b0:	4c 89 e6             	mov    %r12,%rsi
    c0b3:	48 89 c7             	mov    %rax,%rdi
    c0b6:	e8 19 ef ff ff       	callq  afd4 <heap_init>
    c0bb:	85 c0                	test   %eax,%eax
    c0bd:	0f 95 c0             	setne  %al
    c0c0:	84 c0                	test   %al,%al
    c0c2:	74 0a                	je     c0ce <init_enclave+0x334>
        return -1;
    c0c4:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c0c9:	e9 22 01 00 00       	jmpq   c1f0 <init_enclave+0x456>
    uint64_t xfrm = get_xfeature_state();
    c0ce:	e8 db 82 ff ff       	callq  43ae <get_xfeature_state>
    c0d3:	48 89 85 18 ff ff ff 	mov    %rax,-0xe8(%rbp)
    uint64_t cpu_features = (sys_features.cpu_features | INCOMPAT_FEATURE_BIT);
    c0da:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    c0e1:	48 0d 00 18 00 1e    	or     $0x1e001800,%rax
    c0e7:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
    if (sys_features.system_feature_set[0] & ((uint64_t)(1ULL << SYS_FEATURE_EXTEND)))
    c0ee:	48 8b 95 2c ff ff ff 	mov    -0xd4(%rbp),%rdx
    c0f5:	48 b8 00 00 00 00 00 	movabs $0x4000000000000000,%rax
    c0fc:	00 00 40 
    c0ff:	48 21 d0             	and    %rdx,%rax
    c102:	48 85 c0             	test   %rax,%rax
    c105:	74 0b                	je     c112 <init_enclave+0x378>
        cpu_features = sys_features.cpu_features_ext;
    c107:	48 8b 45 c4          	mov    -0x3c(%rbp),%rax
    c10b:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
    if (SDK_VERSION_2_0 < g_sdk_version || sys_features.size != 0)
    c112:	8b 05 ec 4c 00 00    	mov    0x4cec(%rip),%eax        # 10e04 <g_sdk_version>
    c118:	83 f8 01             	cmp    $0x1,%eax
    c11b:	7f 09                	jg     c126 <init_enclave+0x38c>
    c11d:	48 8b 45 bc          	mov    -0x44(%rbp),%rax
    c121:	48 85 c0             	test   %rax,%rax
    c124:	74 37                	je     c15d <init_enclave+0x3c3>
        if (0 != init_optimized_libs(cpu_features, (uint32_t*)sys_features.cpuinfo_table, xfrm))
    c126:	48 8b 95 18 ff ff ff 	mov    -0xe8(%rbp),%rdx
    c12d:	48 8d 85 20 ff ff ff 	lea    -0xe0(%rbp),%rax
    c134:	48 8d 48 14          	lea    0x14(%rax),%rcx
    c138:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    c13f:	48 89 ce             	mov    %rcx,%rsi
    c142:	48 89 c7             	mov    %rax,%rdi
    c145:	e8 93 50 ff ff       	callq  11dd <init_optimized_libs>
    c14a:	85 c0                	test   %eax,%eax
    c14c:	0f 95 c0             	setne  %al
    c14f:	84 c0                	test   %al,%al
    c151:	74 35                	je     c188 <init_enclave+0x3ee>
            return -1;
    c153:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c158:	e9 93 00 00 00       	jmpq   c1f0 <init_enclave+0x456>
        if (0 != init_optimized_libs(cpu_features, NULL, xfrm))
    c15d:	48 8b 95 18 ff ff ff 	mov    -0xe8(%rbp),%rdx
    c164:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    c16b:	be 00 00 00 00       	mov    $0x0,%esi
    c170:	48 89 c7             	mov    %rax,%rdi
    c173:	e8 65 50 ff ff       	callq  11dd <init_optimized_libs>
    c178:	85 c0                	test   %eax,%eax
    c17a:	0f 95 c0             	setne  %al
    c17d:	84 c0                	test   %al,%al
    c17f:	74 07                	je     c188 <init_enclave+0x3ee>
            return -1;
    c181:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c186:	eb 68                	jmp    c1f0 <init_enclave+0x456>
    if ( get_rsrv_size() != 0)
    c188:	e8 42 78 ff ff       	callq  39cf <get_rsrv_size>
    c18d:	48 85 c0             	test   %rax,%rax
    c190:	0f 95 c0             	setne  %al
    c193:	84 c0                	test   %al,%al
    c195:	74 33                	je     c1ca <init_enclave+0x430>
        if(rsrv_mem_init(get_rsrv_base(), get_rsrv_size(), get_rsrv_min_size()) != SGX_SUCCESS)
    c197:	e8 c5 78 ff ff       	callq  3a61 <get_rsrv_min_size>
    c19c:	49 89 c4             	mov    %rax,%r12
    c19f:	e8 2b 78 ff ff       	callq  39cf <get_rsrv_size>
    c1a4:	48 89 c3             	mov    %rax,%rbx
    c1a7:	e8 08 78 ff ff       	callq  39b4 <get_rsrv_base>
    c1ac:	4c 89 e2             	mov    %r12,%rdx
    c1af:	48 89 de             	mov    %rbx,%rsi
    c1b2:	48 89 c7             	mov    %rax,%rdi
    c1b5:	e8 82 f3 ff ff       	callq  b53c <rsrv_mem_init>
    c1ba:	85 c0                	test   %eax,%eax
    c1bc:	0f 95 c0             	setne  %al
    c1bf:	84 c0                	test   %al,%al
    c1c1:	74 07                	je     c1ca <init_enclave+0x430>
            return -1;
    c1c3:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c1c8:	eb 26                	jmp    c1f0 <init_enclave+0x456>
    if(SGX_SUCCESS != sgx_read_rand((unsigned char*)&__stack_chk_guard,
    c1ca:	be 08 00 00 00       	mov    $0x8,%esi
    c1cf:	48 8d 3d 3a 4c 00 00 	lea    0x4c3a(%rip),%rdi        # 10e10 <__intel_security_cookie>
    c1d6:	e8 7d 53 ff ff       	callq  1558 <sgx_read_rand>
    c1db:	85 c0                	test   %eax,%eax
    c1dd:	0f 95 c0             	setne  %al
    c1e0:	84 c0                	test   %al,%al
    c1e2:	74 07                	je     c1eb <init_enclave+0x451>
        return -1;
    c1e4:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c1e9:	eb 05                	jmp    c1f0 <init_enclave+0x456>
    return 0;
    c1eb:	b8 00 00 00 00       	mov    $0x0,%eax
}
    c1f0:	48 8b 4d d8          	mov    -0x28(%rbp),%rcx
    c1f4:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    c1fb:	00 00 
    c1fd:	74 05                	je     c204 <init_enclave+0x46a>
    c1ff:	e8 63 90 ff ff       	callq  5267 <__stack_chk_fail>
    c204:	48 81 c4 18 01 00 00 	add    $0x118,%rsp
    c20b:	5b                   	pop    %rbx
    c20c:	41 5c                	pop    %r12
    c20e:	41 5d                	pop    %r13
    c210:	5d                   	pop    %rbp
    c211:	c3                   	retq   

000000000000c212 <_ZL18add_static_threadsPVK9_layout_tS1_m>:
{
    c212:	55                   	push   %rbp
    c213:	48 89 e5             	mov    %rsp,%rbp
    c216:	53                   	push   %rbx
    c217:	48 83 ec 48          	sub    $0x48,%rsp
    c21b:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    c21f:	48 89 75 c0          	mov    %rsi,-0x40(%rbp)
    c223:	48 89 55 b8          	mov    %rdx,-0x48(%rbp)
    int ret = -1;
    c227:	c7 45 d4 ff ff ff ff 	movl   $0xffffffff,-0x2c(%rbp)
    for (const volatile layout_t *layout = layout_start; layout < layout_end; layout++)
    c22e:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    c232:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    c236:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c23a:	48 3b 45 c0          	cmp    -0x40(%rbp),%rax
    c23e:	0f 83 1a 01 00 00    	jae    c35e <_ZL18add_static_threadsPVK9_layout_tS1_m+0x14c>
        if (!IS_GROUP_ID(layout->group.id) && (layout->entry.si_flags & SI_FLAGS_TCS) && layout->entry.attributes == (PAGE_ATTR_EADD | PAGE_ATTR_EEXTEND))
    c244:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c248:	0f b7 00             	movzwl (%rax),%eax
    c24b:	0f b7 c0             	movzwl %ax,%eax
    c24e:	25 00 10 00 00       	and    $0x1000,%eax
    c253:	85 c0                	test   %eax,%eax
    c255:	75 27                	jne    c27e <_ZL18add_static_threadsPVK9_layout_tS1_m+0x6c>
    c257:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c25b:	48 8b 40 18          	mov    0x18(%rax),%rax
    c25f:	25 00 01 00 00       	and    $0x100,%eax
    c264:	48 85 c0             	test   %rax,%rax
    c267:	74 15                	je     c27e <_ZL18add_static_threadsPVK9_layout_tS1_m+0x6c>
    c269:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c26d:	0f b7 40 02          	movzwl 0x2(%rax),%eax
    c271:	66 83 f8 03          	cmp    $0x3,%ax
    c275:	75 07                	jne    c27e <_ZL18add_static_threadsPVK9_layout_tS1_m+0x6c>
    c277:	b8 01 00 00 00       	mov    $0x1,%eax
    c27c:	eb 05                	jmp    c283 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x71>
    c27e:	b8 00 00 00 00       	mov    $0x0,%eax
    c283:	84 c0                	test   %al,%al
    c285:	74 3f                	je     c2c6 <_ZL18add_static_threadsPVK9_layout_tS1_m+0xb4>
            uintptr_t tcs_addr = (uintptr_t)layout->entry.rva + offset + (uintptr_t)get_enclave_base();
    c287:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c28b:	48 8b 50 08          	mov    0x8(%rax),%rdx
    c28f:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    c293:	48 8d 1c 02          	lea    (%rdx,%rax,1),%rbx
    c297:	e8 55 03 00 00       	callq  c5f1 <get_enclave_base>
    c29c:	48 01 d8             	add    %rbx,%rax
    c29f:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
            if (do_save_tcs(reinterpret_cast<void *>(tcs_addr)) != SGX_SUCCESS)
    c2a3:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    c2a7:	48 89 c7             	mov    %rax,%rdi
    c2aa:	e8 69 65 ff ff       	callq  2818 <_Z11do_save_tcsPv>
    c2af:	85 c0                	test   %eax,%eax
    c2b1:	0f 95 c0             	setne  %al
    c2b4:	84 c0                	test   %al,%al
    c2b6:	0f 84 98 00 00 00    	je     c354 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x142>
		    return (-1);
    c2bc:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c2c1:	e9 9d 00 00 00       	jmpq   c363 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x151>
        else if (IS_GROUP_ID(layout->group.id)){
    c2c6:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c2ca:	0f b7 00             	movzwl (%rax),%eax
    c2cd:	0f b7 c0             	movzwl %ax,%eax
    c2d0:	25 00 10 00 00       	and    $0x1000,%eax
    c2d5:	85 c0                	test   %eax,%eax
    c2d7:	0f 95 c0             	setne  %al
    c2da:	84 c0                	test   %al,%al
    c2dc:	74 76                	je     c354 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x142>
            size_t step = 0;
    c2de:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    c2e5:	00 
            for(uint32_t j = 0; j < layout->group.load_times; j++)
    c2e6:	c7 45 d0 00 00 00 00 	movl   $0x0,-0x30(%rbp)
    c2ed:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c2f1:	8b 40 04             	mov    0x4(%rax),%eax
    c2f4:	39 45 d0             	cmp    %eax,-0x30(%rbp)
    c2f7:	0f 92 c0             	setb   %al
    c2fa:	84 c0                	test   %al,%al
    c2fc:	74 56                	je     c354 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x142>
                step += (size_t)layout->group.load_step;
    c2fe:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c302:	48 8b 40 08          	mov    0x8(%rax),%rax
    c306:	48 01 45 e0          	add    %rax,-0x20(%rbp)
                if(0 != (ret = add_static_threads(&layout[-layout->group.entry_count], layout, step)))
    c30a:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c30e:	0f b7 40 02          	movzwl 0x2(%rax),%eax
    c312:	0f b7 c0             	movzwl %ax,%eax
    c315:	f7 d8                	neg    %eax
    c317:	48 98                	cltq   
    c319:	48 c1 e0 05          	shl    $0x5,%rax
    c31d:	48 89 c2             	mov    %rax,%rdx
    c320:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c324:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
    c328:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    c32c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c330:	48 89 c6             	mov    %rax,%rsi
    c333:	48 89 cf             	mov    %rcx,%rdi
    c336:	e8 d7 fe ff ff       	callq  c212 <_ZL18add_static_threadsPVK9_layout_tS1_m>
    c33b:	89 45 d4             	mov    %eax,-0x2c(%rbp)
    c33e:	83 7d d4 00          	cmpl   $0x0,-0x2c(%rbp)
    c342:	0f 95 c0             	setne  %al
    c345:	84 c0                	test   %al,%al
    c347:	74 05                	je     c34e <_ZL18add_static_threadsPVK9_layout_tS1_m+0x13c>
                    return ret;
    c349:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    c34c:	eb 15                	jmp    c363 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x151>
            for(uint32_t j = 0; j < layout->group.load_times; j++)
    c34e:	83 45 d0 01          	addl   $0x1,-0x30(%rbp)
    c352:	eb 99                	jmp    c2ed <_ZL18add_static_threadsPVK9_layout_tS1_m+0xdb>
    for (const volatile layout_t *layout = layout_start; layout < layout_end; layout++)
    c354:	48 83 45 d8 20       	addq   $0x20,-0x28(%rbp)
    c359:	e9 d8 fe ff ff       	jmpq   c236 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x24>
    return 0;
    c35e:	b8 00 00 00 00       	mov    $0x0,%eax
}
    c363:	48 83 c4 48          	add    $0x48,%rsp
    c367:	5b                   	pop    %rbx
    c368:	5d                   	pop    %rbp
    c369:	c3                   	retq   

000000000000c36a <sgx_is_enclave_crashed>:
{
    c36a:	55                   	push   %rbp
    c36b:	48 89 e5             	mov    %rsp,%rbp
    return get_enclave_state() == ENCLAVE_CRASHED;
    c36e:	e8 86 02 00 00       	callq  c5f9 <get_enclave_state>
    c373:	83 f8 03             	cmp    $0x3,%eax
    c376:	0f 94 c0             	sete   %al
    c379:	0f b6 c0             	movzbl %al,%eax
}
    c37c:	5d                   	pop    %rbp
    c37d:	c3                   	retq   

000000000000c37e <_ZL16init_stack_guardPv>:
#include "global_data.h"
#include "trts_internal.h"
#include "internal/rts.h"

static void __attribute__((section(".nipx"))) init_stack_guard(void *tcs)
{
    c37e:	55                   	push   %rbp
    c37f:	48 89 e5             	mov    %rsp,%rbp
    c382:	48 83 ec 20          	sub    $0x20,%rsp
    c386:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    thread_data_t *thread_data = get_thread_data();
    c38a:	e8 9d 02 00 00       	callq  c62c <get_thread_data>
    c38f:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if( (NULL == thread_data) || ((thread_data->stack_base_addr == thread_data->last_sp) && (0 != g_global_data.thread_policy)))
    c393:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    c398:	74 25                	je     c3bf <_ZL16init_stack_guardPv+0x41>
    c39a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    c39e:	48 8b 50 10          	mov    0x10(%rax),%rdx
    c3a2:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    c3a6:	48 8b 40 08          	mov    0x8(%rax),%rax
    c3aa:	48 39 c2             	cmp    %rax,%rdx
    c3ad:	75 17                	jne    c3c6 <_ZL16init_stack_guardPv+0x48>
    c3af:	48 8d 05 ca 0d 00 00 	lea    0xdca(%rip),%rax        # d180 <g_global_data>
    c3b6:	48 8b 40 30          	mov    0x30(%rax),%rax
    c3ba:	48 85 c0             	test   %rax,%rax
    c3bd:	74 07                	je     c3c6 <_ZL16init_stack_guardPv+0x48>
    c3bf:	b8 01 00 00 00       	mov    $0x1,%eax
    c3c4:	eb 05                	jmp    c3cb <_ZL16init_stack_guardPv+0x4d>
    c3c6:	b8 00 00 00 00       	mov    $0x0,%eax
    c3cb:	84 c0                	test   %al,%al
    c3cd:	74 71                	je     c440 <_ZL16init_stack_guardPv+0xc2>
    {
         thread_data = GET_PTR(thread_data_t, tcs, g_global_data.td_template.self_addr);
    c3cf:	48 8d 05 aa 0d 00 00 	lea    0xdaa(%rip),%rax        # d180 <g_global_data>
    c3d6:	48 8b 50 40          	mov    0x40(%rax),%rdx
    c3da:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    c3de:	48 01 d0             	add    %rdx,%rax
    c3e1:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    else
    {
        return;
    }

    assert(thread_data != NULL);
    c3e5:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    c3ea:	75 1f                	jne    c40b <_ZL16init_stack_guardPv+0x8d>
    c3ec:	48 8d 0d 44 0c 00 00 	lea    0xc44(%rip),%rcx        # d037 <_ZZ14trim_EPC_pagesE8__func__+0xf>
    c3f3:	48 8d 15 66 0c 00 00 	lea    0xc66(%rip),%rdx        # d060 <_ZZL16init_stack_guardPvE8__func__>
    c3fa:	be 3f 00 00 00       	mov    $0x3f,%esi
    c3ff:	48 8d 3d 45 0c 00 00 	lea    0xc45(%rip),%rdi        # d04b <_ZZ14trim_EPC_pagesE8__func__+0x23>
    c406:	e8 65 8e ff ff       	callq  5270 <__assert>

    size_t tmp_stack_guard = 0;
    c40b:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
    c412:	00 
    if (SGX_SUCCESS != sgx_read_rand(
    c413:	48 8d 45 f0          	lea    -0x10(%rbp),%rax
    c417:	be 08 00 00 00       	mov    $0x8,%esi
    c41c:	48 89 c7             	mov    %rax,%rdi
    c41f:	e8 34 51 ff ff       	callq  1558 <sgx_read_rand>
    c424:	85 c0                	test   %eax,%eax
    c426:	0f 95 c0             	setne  %al
    c429:	84 c0                	test   %al,%al
    c42b:	74 05                	je     c432 <_ZL16init_stack_guardPv+0xb4>
                (unsigned char*)&tmp_stack_guard,
                sizeof(tmp_stack_guard)))
        abort();
    c42d:	e8 29 05 00 00       	callq  c95b <abort>

    thread_data->stack_guard = tmp_stack_guard;
    c432:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    c436:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    c43a:	48 89 50 28          	mov    %rdx,0x28(%rax)
    c43e:	eb 01                	jmp    c441 <_ZL16init_stack_guardPv+0xc3>
        return;
    c440:	90                   	nop
}
    c441:	c9                   	leaveq 
    c442:	c3                   	retq   

000000000000c443 <enter_enclave>:

extern "C" int enter_enclave(int index, void *ms, void *tcs, int cssa) __attribute__((section(".nipx")));

extern "C" int enter_enclave(int index, void *ms, void *tcs, int cssa)
{
    c443:	55                   	push   %rbp
    c444:	48 89 e5             	mov    %rsp,%rbp
    c447:	48 83 ec 30          	sub    $0x30,%rsp
    c44b:	89 7d ec             	mov    %edi,-0x14(%rbp)
    c44e:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    c452:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    c456:	89 4d e8             	mov    %ecx,-0x18(%rbp)
    sgx_status_t error = SGX_ERROR_UNEXPECTED;
    c459:	c7 45 fc 01 00 00 00 	movl   $0x1,-0x4(%rbp)

    if(sgx_is_enclave_crashed())
    c460:	e8 05 ff ff ff       	callq  c36a <sgx_is_enclave_crashed>
    c465:	85 c0                	test   %eax,%eax
    c467:	0f 95 c0             	setne  %al
    c46a:	84 c0                	test   %al,%al
    c46c:	74 0a                	je     c478 <enter_enclave+0x35>
    {
        return SGX_ERROR_ENCLAVE_CRASHED;
    c46e:	b8 06 10 00 00       	mov    $0x1006,%eax
    c473:	e9 1e 01 00 00       	jmpq   c596 <enter_enclave+0x153>
    }
    if((ECMD_INIT_ENCLAVE != index) && (ENCLAVE_INIT_DONE != get_enclave_state()))
    c478:	83 7d ec ff          	cmpl   $0xffffffff,-0x14(%rbp)
    c47c:	74 11                	je     c48f <enter_enclave+0x4c>
    c47e:	e8 76 01 00 00       	callq  c5f9 <get_enclave_state>
    c483:	83 f8 02             	cmp    $0x2,%eax
    c486:	74 07                	je     c48f <enter_enclave+0x4c>
    c488:	b8 01 00 00 00       	mov    $0x1,%eax
    c48d:	eb 05                	jmp    c494 <enter_enclave+0x51>
    c48f:	b8 00 00 00 00       	mov    $0x0,%eax
    c494:	84 c0                	test   %al,%al
    c496:	74 12                	je     c4aa <enter_enclave+0x67>
    {
        set_enclave_state(ENCLAVE_CRASHED);
    c498:	bf 03 00 00 00       	mov    $0x3,%edi
    c49d:	e8 64 01 00 00       	callq  c606 <set_enclave_state>
        return error;
    c4a2:	8b 45 fc             	mov    -0x4(%rbp),%eax
    c4a5:	e9 ec 00 00 00       	jmpq   c596 <enter_enclave+0x153>
    }

    if(cssa == 0)
    c4aa:	83 7d e8 00          	cmpl   $0x0,-0x18(%rbp)
    c4ae:	0f 85 98 00 00 00    	jne    c54c <enter_enclave+0x109>
    {
        if((index >= 0) || (index == ECMD_ECALL_PTHREAD))
    c4b4:	83 7d ec 00          	cmpl   $0x0,-0x14(%rbp)
    c4b8:	79 06                	jns    c4c0 <enter_enclave+0x7d>
    c4ba:	83 7d ec fa          	cmpl   $0xfffffffa,-0x14(%rbp)
    c4be:	75 29                	jne    c4e9 <enter_enclave+0xa6>
        {
            // Initialize stack guard if necessary
            init_stack_guard(tcs);
    c4c0:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c4c4:	48 89 c7             	mov    %rax,%rdi
    c4c7:	e8 b2 fe ff ff       	callq  c37e <_ZL16init_stack_guardPv>
            error = do_ecall(index, ms, tcs);
    c4cc:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    c4d0:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    c4d4:	8b 45 ec             	mov    -0x14(%rbp),%eax
    c4d7:	48 89 ce             	mov    %rcx,%rsi
    c4da:	89 c7                	mov    %eax,%edi
    c4dc:	e8 59 69 ff ff       	callq  2e3a <do_ecall>
    c4e1:	89 45 fc             	mov    %eax,-0x4(%rbp)
    c4e4:	e9 9a 00 00 00       	jmpq   c583 <enter_enclave+0x140>
        }
        else if(index == ECMD_INIT_ENCLAVE)
    c4e9:	83 7d ec ff          	cmpl   $0xffffffff,-0x14(%rbp)
    c4ed:	75 18                	jne    c507 <enter_enclave+0xc4>
        {
            error = do_init_enclave(ms, tcs);
    c4ef:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    c4f3:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    c4f7:	48 89 d6             	mov    %rdx,%rsi
    c4fa:	48 89 c7             	mov    %rax,%rdi
    c4fd:	e8 6b f6 ff ff       	callq  bb6d <do_init_enclave>
    c502:	89 45 fc             	mov    %eax,-0x4(%rbp)
    c505:	eb 7c                	jmp    c583 <enter_enclave+0x140>
        }
        else if(index == ECMD_ORET)
    c507:	83 7d ec fe          	cmpl   $0xfffffffe,-0x14(%rbp)
    c50b:	75 11                	jne    c51e <enter_enclave+0xdb>
        {
            error = do_oret(ms);
    c50d:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    c511:	48 89 c7             	mov    %rax,%rdi
    c514:	e8 a0 71 ff ff       	callq  36b9 <do_oret>
    c519:	89 45 fc             	mov    %eax,-0x4(%rbp)
    c51c:	eb 65                	jmp    c583 <enter_enclave+0x140>
        }
        else if(index == ECMD_MKTCS)
    c51e:	83 7d ec fc          	cmpl   $0xfffffffc,-0x14(%rbp)
    c522:	75 11                	jne    c535 <enter_enclave+0xf2>
        {
            error = do_ecall_add_thread(ms);
    c524:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    c528:	48 89 c7             	mov    %rax,%rdi
    c52b:	e8 ec 6a ff ff       	callq  301c <do_ecall_add_thread>
    c530:	89 45 fc             	mov    %eax,-0x4(%rbp)
    c533:	eb 4e                	jmp    c583 <enter_enclave+0x140>
        }
        else if(index == ECMD_UNINIT_ENCLAVE)
    c535:	83 7d ec fb          	cmpl   $0xfffffffb,-0x14(%rbp)
    c539:	75 48                	jne    c583 <enter_enclave+0x140>
        {
            error = do_uninit_enclave(tcs);
    c53b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c53f:	48 89 c7             	mov    %rax,%rdi
    c542:	e8 99 6b ff ff       	callq  30e0 <do_uninit_enclave>
    c547:	89 45 fc             	mov    %eax,-0x4(%rbp)
    c54a:	eb 37                	jmp    c583 <enter_enclave+0x140>
        }
    }
    else if((cssa == 1) && (index == ECMD_EXCEPT))
    c54c:	83 7d e8 01          	cmpl   $0x1,-0x18(%rbp)
    c550:	75 31                	jne    c583 <enter_enclave+0x140>
    c552:	83 7d ec fd          	cmpl   $0xfffffffd,-0x14(%rbp)
    c556:	75 2b                	jne    c583 <enter_enclave+0x140>
    {
        error = trts_handle_exception(tcs);
    c558:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c55c:	48 89 c7             	mov    %rax,%rdi
    c55f:	e8 63 79 ff ff       	callq  3ec7 <trts_handle_exception>
    c564:	89 45 fc             	mov    %eax,-0x4(%rbp)
        if (check_static_stack_canary(tcs) != 0)
    c567:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c56b:	48 89 c7             	mov    %rax,%rdi
    c56e:	e8 fe 50 ff ff       	callq  1671 <check_static_stack_canary>
    c573:	85 c0                	test   %eax,%eax
    c575:	0f 95 c0             	setne  %al
    c578:	84 c0                	test   %al,%al
    c57a:	74 07                	je     c583 <enter_enclave+0x140>
        {
            error = SGX_ERROR_STACK_OVERRUN;
    c57c:	c7 45 fc 09 10 00 00 	movl   $0x1009,-0x4(%rbp)
        }
    }
    if(error == SGX_ERROR_UNEXPECTED)
    c583:	83 7d fc 01          	cmpl   $0x1,-0x4(%rbp)
    c587:	75 0a                	jne    c593 <enter_enclave+0x150>
    {
        set_enclave_state(ENCLAVE_CRASHED);
    c589:	bf 03 00 00 00       	mov    $0x3,%edi
    c58e:	e8 73 00 00 00       	callq  c606 <set_enclave_state>
    }
    return error;
    c593:	8b 45 fc             	mov    -0x4(%rbp),%eax
}
    c596:	c9                   	leaveq 
    c597:	c3                   	retq   

000000000000c598 <restore_xregs>:
DECLARE_LOCAL_FUNC restore_xregs
#if defined(LINUX32)
    mov     SE_WORDSIZE(%esp), %ecx
    lea     g_xsave_enabled, %eax
#else
    mov     %rdi, %rcx
    c598:	48 89 f9             	mov    %rdi,%rcx
    lea_pic g_xsave_enabled, %rax
    c59b:	48 8d 05 02 4b 00 00 	lea    0x4b02(%rip),%rax        # 110a4 <g_xsave_enabled>
#endif
    movl    (%xax), %eax
    c5a2:	8b 00                	mov    (%rax),%eax
    cmpl    $0, %eax
    c5a4:	83 f8 00             	cmp    $0x0,%eax
    jz      1f
    c5a7:	74 16                	je     c5bf <restore_xregs+0x27>
    SET_XSAVE_MASK
    c5a9:	48 31 c0             	xor    %rax,%rax
    c5ac:	48 31 d2             	xor    %rdx,%rdx
    c5af:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c5b4:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    c5b9:	48 0f ae 29          	xrstor64 (%rcx)
    DO_XRSTOR
    jmp     2f
    c5bd:	eb 04                	jmp    c5c3 <restore_xregs+0x2b>
    c5bf:	48 0f ae 09          	fxrstor64 (%rcx)
1:
    DO_FXRSTOR
2:
    ret
    c5c3:	c3                   	retq   

000000000000c5c4 <save_xregs>:
DECLARE_LOCAL_FUNC save_xregs
#if defined(LINUX32)
    mov     SE_WORDSIZE(%esp), %ecx
    lea     g_xsave_enabled, %eax
#else
    mov     %rdi, %rcx
    c5c4:	48 89 f9             	mov    %rdi,%rcx
    lea_pic g_xsave_enabled, %rax
    c5c7:	48 8d 05 d6 4a 00 00 	lea    0x4ad6(%rip),%rax        # 110a4 <g_xsave_enabled>
#endif
    fwait
    c5ce:	9b                   	fwait
    movl    (%xax), %eax
    c5cf:	8b 00                	mov    (%rax),%eax
    cmpl    $0, %eax
    c5d1:	83 f8 00             	cmp    $0x0,%eax
    jz      1f
    c5d4:	74 16                	je     c5ec <save_xregs+0x28>
    SET_XSAVE_MASK
    c5d6:	48 31 c0             	xor    %rax,%rax
    c5d9:	48 31 d2             	xor    %rdx,%rdx
    c5dc:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c5e1:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    c5e6:	48 0f c7 21          	xsavec64 (%rcx)
    DO_XSAVEC
    jmp     2f
    c5ea:	eb 04                	jmp    c5f0 <save_xregs+0x2c>
    c5ec:	48 0f ae 01          	fxsave64 (%rcx)
1:
    DO_FXSAVE
2:
    ret
    c5f0:	c3                   	retq   

000000000000c5f1 <get_enclave_base>:

    /* .text */
    .section .nipx,"ax",@progbits

DECLARE_LOCAL_FUNC get_enclave_base
    lea_pic __ImageBase, %xax
    c5f1:	48 8d 05 08 3a ff ff 	lea    -0xc5f8(%rip),%rax        # 0 <enclave.so>
    ret
    c5f8:	c3                   	retq   

000000000000c5f9 <get_enclave_state>:
DECLARE_LOCAL_FUNC get_enclave_state
    lea_pic g_enclave_state, %xcx
    c5f9:	48 8d 0d a0 4a 00 00 	lea    0x4aa0(%rip),%rcx        # 110a0 <g_enclave_state>
    xor     %xax, %xax
    c600:	48 31 c0             	xor    %rax,%rax
    movl    (%xcx), %eax
    c603:	8b 01                	mov    (%rcx),%eax
    ret
    c605:	c3                   	retq   

000000000000c606 <set_enclave_state>:
DECLARE_LOCAL_FUNC set_enclave_state
    lea_pic g_enclave_state, %xax
    c606:	48 8d 05 93 4a 00 00 	lea    0x4a93(%rip),%rax        # 110a0 <g_enclave_state>
#ifdef LINUX32
    mov     SE_WORDSIZE(%esp), %edi
#endif
    movl    %edi, (%xax)
    c60d:	89 38                	mov    %edi,(%rax)
    ret
    c60f:	c3                   	retq   

000000000000c610 <lock_enclave>:

DECLARE_LOCAL_FUNC lock_enclave
    lea_pic g_enclave_state, %xdx
    c610:	48 8d 15 89 4a 00 00 	lea    0x4a89(%rip),%rdx        # 110a0 <g_enclave_state>
    xor     %xax, %xax
    c617:	48 31 c0             	xor    %rax,%rax
    mov     $ENCLAVE_INIT_NOT_STARTED, %eax
    c61a:	b8 00 00 00 00       	mov    $0x0,%eax
    xor     %xcx, %xcx
    c61f:	48 31 c9             	xor    %rcx,%rcx
    mov     $ENCLAVE_INIT_IN_PROGRESS, %ecx     /* if (g_global_data.enclave_state == ENCLAVE_INIT_NOT_STARTED) */
    c622:	b9 01 00 00 00       	mov    $0x1,%ecx
    lock cmpxchgl %ecx, (%xdx)                  /*   g_global_data.enclave_state == ENCLAVE_INIT_IN_PROGRESS */
    c627:	f0 0f b1 0a          	lock cmpxchg %ecx,(%rdx)
    ret                                         /* xax: the initial value of enclave state */
    c62b:	c3                   	retq   

000000000000c62c <get_thread_data>:
 *
 *     Get the address of thread_data
 * ---------------------------------------------------------------------
 */
DECLARE_LOCAL_FUNC get_thread_data
    READ_TD_DATA self_addr 
    c62c:	65 48 8b 04 25 00 00 	mov    %gs:0x0,%rax
    c633:	00 00 
    ret
    c635:	c3                   	retq   

000000000000c636 <get_stack_guard>:
 *
 *     Get the value of stack_guard
 * ---------------------------------------------------------------------
 */
DECLARE_LOCAL_FUNC get_stack_guard 
    READ_TD_DATA stack_guard 
    c636:	65 48 8b 04 25 28 00 	mov    %gs:0x28,%rax
    c63d:	00 00 
    ret
    c63f:	c3                   	retq   

000000000000c640 <enclave_entry>:
 * ----------------------------------------------------------------------
 */
    .cfi_startproc

    /* Clear unused general registers */
    xor     %xdx, %xdx
    c640:	48 31 d2             	xor    %rdx,%rdx
    add     %xdx, %xdx          /* OF = SF = AF = CF = 0; ZF = PF = 1 */
    c643:	48 01 d2             	add    %rdx,%rdx
    cld                         /* DF = 0 */
    c646:	fc                   	cld    
#if defined(LINUX64)
    xor     %r8, %r8
    c647:	4d 31 c0             	xor    %r8,%r8
    xor     %r9, %r9
    c64a:	4d 31 c9             	xor    %r9,%r9
    xor     %r10, %r10
    c64d:	4d 31 d2             	xor    %r10,%r10
    xor     %r11, %r11
    c650:	4d 31 db             	xor    %r11,%r11
    xor     %r12, %r12
    c653:	4d 31 e4             	xor    %r12,%r12
    xor     %r13, %r13
    c656:	4d 31 ed             	xor    %r13,%r13
    xor     %r14, %r14
    c659:	4d 31 f6             	xor    %r14,%r14
    xor     %r15, %r15
    c65c:	4d 31 ff             	xor    %r15,%r15
#endif

    /* switch to trusted stack */
    cmp     $0, %xax
    c65f:	48 83 f8 00          	cmp    $0x0,%rax
    jne     .Ldo_handler                /* handle exception state */
    c663:	0f 85 cb 00 00 00    	jne    c734 <enclave_entry+0xf4>
    /* xor     %xdx, %xdx                  xdx is cssa, make sure it is 0 */
    READ_TD_DATA last_sp
    c669:	65 48 8b 04 25 08 00 	mov    %gs:0x8,%rax
    c670:	00 00 
    cmp     $0, %xax
    c672:	48 83 f8 00          	cmp    $0x0,%rax
    jne .Lswitch_stack
    c676:	75 0f                	jne    c687 <enclave_entry+0x47>
    GET_STACK_BASE  %xbx                /* if last_sp == 0, set sp to stack base */
    c678:	48 89 d8             	mov    %rbx,%rax
    c67b:	48 2d 00 00 01 00    	sub    $0x10000,%rax
    sub     $STATIC_STACK_SIZE, %xax    /* give space for static stack */
    c681:	48 2d b0 02 00 00    	sub    $0x2b0,%rax
.Lswitch_stack:
    xchg    %xsp, %xax
    c687:	48 94                	xchg   %rax,%rsp
    push    %xcx
    c689:	51                   	push   %rcx
    push    %xbp
    c68a:	55                   	push   %rbp

    .cfi_def_cfa_offset   2 * SE_WORDSIZE
    .cfi_offset           xbp, -2 * SE_WORDSIZE
    mov     %xsp, %xbp
    c68b:	48 89 e5             	mov    %rsp,%rbp
    .cfi_def_cfa_register xbp

    CLEAN_XFLAGS
    c68e:	9c                   	pushfq 
    c68f:	48 f7 14 24          	notq   (%rsp)
    c693:	48 81 0c 24 00 00 04 	orq    $0x40000,(%rsp)
    c69a:	00 
    c69b:	48 f7 14 24          	notq   (%rsp)
    c69f:	9d                   	popfq  


    /* Save the registers */
    sub     $(6*SE_WORDSIZE), %xsp
    c6a0:	48 83 ec 30          	sub    $0x30,%rsp
    mov     %xax, -1*SE_WORDSIZE(%xbp)  /* xsp_u */
    c6a4:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    mov     %xdx, -3*SE_WORDSIZE(%xbp)  /* cssa */
    c6a8:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    mov     %xbx, -4*SE_WORDSIZE(%xbp)  /* TCS */
    c6ac:	48 89 5d e0          	mov    %rbx,-0x20(%rbp)
    mov     %xsi, -5*SE_WORDSIZE(%xbp)  /* XSI */
    c6b0:	48 89 75 d8          	mov    %rsi,-0x28(%rbp)
    mov     %xdi, -6*SE_WORDSIZE(%xbp)  /* XDI */
    c6b4:	48 89 7d d0          	mov    %rdi,-0x30(%rbp)

    /* clean extended feature registers */
    sub     $(4*SE_WORDSIZE), %xsp
    c6b8:	48 83 ec 20          	sub    $0x20,%rsp

    lea_pic SYNTHETIC_STATE, %xdi
    c6bc:	48 8d 3d 3d 11 00 00 	lea    0x113d(%rip),%rdi        # d800 <SYNTHETIC_STATE>
#ifdef LINUX32
    mov     %xdi, (%xsp)
#endif
    call    restore_xregs
    c6c3:	e8 d0 fe ff ff       	callq  c598 <restore_xregs>
    add     $(4*SE_WORDSIZE), %xsp
    c6c8:	48 83 c4 20          	add    $0x20,%rsp

    /* switch to C code */
#ifdef LINUX64
    mov     -6*SE_WORDSIZE(%xbp), %xdi  /* index */
    c6cc:	48 8b 7d d0          	mov    -0x30(%rbp),%rdi
    mov     -5*SE_WORDSIZE(%xbp), %xsi  /* ms */
    c6d0:	48 8b 75 d8          	mov    -0x28(%rbp),%rsi
    mov     -4*SE_WORDSIZE(%xbp), %xdx  /* TCS */
    c6d4:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    mov     -3*SE_WORDSIZE(%xbp), %xcx  /* cssa */
    c6d8:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
#endif
    call    enter_enclave
    c6dc:	e8 62 fd ff ff       	callq  c443 <enter_enclave>
    mov     %xax, %xbx
    c6e1:	48 89 c3             	mov    %rax,%rbx

.Lexit_enclave:
/* clean extended feature registers */
    lea_pic SYNTHETIC_STATE, %xdi
    c6e4:	48 8d 3d 15 11 00 00 	lea    0x1115(%rip),%rdi        # d800 <SYNTHETIC_STATE>
#ifdef LINUX32
    mov     %xdi, (%xsp)
#endif
    call    restore_xregs
    c6eb:	e8 a8 fe ff ff       	callq  c598 <restore_xregs>

/* set xdi and xsi */
    mov     $OCMD_ERET, %xdi
    c6f0:	48 c7 c7 ff ff ff ff 	mov    $0xffffffffffffffff,%rdi
    mov     %xbx, %xsi
    c6f7:	48 89 de             	mov    %rbx,%rsi

/* restore stack */
    mov     -1*SE_WORDSIZE(%xbp), %xdx  /* xdx: xsp_u  */
    c6fa:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    mov     %xbp, %xsp
    c6fe:	48 89 ec             	mov    %rbp,%rsp
    pop     %xbp                        /* xbp_u */
    c701:	5d                   	pop    %rbp
    pop     %xbx                        /* ret_u */
    c702:	5b                   	pop    %rbx
    mov     %xdx, %xsp                  /* xsp_u */
    c703:	48 89 d4             	mov    %rdx,%rsp

.Lclear_and_exit_enclave:
    /* Clear all GPRs, except xax, xbx, xdi and xsi */
    xor     %xcx, %xcx
    c706:	48 31 c9             	xor    %rcx,%rcx
    xor     %xdx, %xdx
    c709:	48 31 d2             	xor    %rdx,%rdx
#if defined(LINUX64)
    xor     %r8, %r8
    c70c:	4d 31 c0             	xor    %r8,%r8
    xor     %r9, %r9
    c70f:	4d 31 c9             	xor    %r9,%r9
    xor     %r10, %r10
    c712:	4d 31 d2             	xor    %r10,%r10
    xor     %r11, %r11
    c715:	4d 31 db             	xor    %r11,%r11
    xor     %r12, %r12
    c718:	4d 31 e4             	xor    %r12,%r12
    xor     %r13, %r13
    c71b:	4d 31 ed             	xor    %r13,%r13
    xor     %r14, %r14
    c71e:	4d 31 f6             	xor    %r14,%r14
    xor     %r15, %r15
    c721:	4d 31 ff             	xor    %r15,%r15
#endif

    /* Set status flags to pre-defined values */
    add     %xdx, %xdx          /* OF = SF = AF = CF = 0; ZF = PF = 1 */
    c724:	48 01 d2             	add    %rdx,%rdx
    cld                         /* DF = 0 */
    c727:	fc                   	cld    

    /* EEXIT */
    mov     $SE_EEXIT, %xax     /* EEXIT leaf */
    c728:	48 c7 c0 04 00 00 00 	mov    $0x4,%rax
    c72f:	0f 01 d7             	enclu  
    ENCLU

    /* Should not come here */
    ud2
    c732:	0f 0b                	ud2    

.Ldo_handler:
    mov     %xax, %xdx          /* XDX: cssa */
    c734:	48 89 c2             	mov    %rax,%rdx
    GET_STACK_BASE %xbx         /* XAX: static stack, set sp to stack base */
    c737:	48 89 d8             	mov    %rbx,%rax
    c73a:	48 2d 00 00 01 00    	sub    $0x10000,%rax
    jmp     .Lswitch_stack   
    c740:	e9 42 ff ff ff       	jmpq   c687 <enclave_entry+0x47>
 
    /* Should not come here */
    ud2
    c745:	0f 0b                	ud2    

000000000000c747 <do_ocall>:
/* 
 * 8 for GPR, 1 for TD.last_sp, 1 for ocall_index
 * 1 for OCALL_FLAG, 4 for shadow space.
 * Stack Pointer is 16-byte aligned under x86_64.
 */
    push    %xbp
    c747:	55                   	push   %rbp
    mov     %xsp, %xbp
    c748:	48 89 e5             	mov    %rsp,%rbp

/* save parameters in stack */
#ifdef LINUX64
    mov     %xdi, 2*SE_WORDSIZE(%xbp)
    c74b:	48 89 7d 10          	mov    %rdi,0x10(%rbp)
    mov     %xsi, 3*SE_WORDSIZE(%xbp)
    c74f:	48 89 75 18          	mov    %rsi,0x18(%rbp)
#endif

/* save and clean extended feature registers */
    READ_TD_DATA xsave_size
    c753:	65 48 8b 04 25 38 00 	mov    %gs:0x38,%rax
    c75a:	00 00 
    sub     %xax, %xsp                 /* allocate buffer to save xregs */
    c75c:	48 29 c4             	sub    %rax,%rsp
    mov     $0x3f, %xax
    c75f:	48 c7 c0 3f 00 00 00 	mov    $0x3f,%rax
    not     %xax
    c766:	48 f7 d0             	not    %rax
    and     %xax, %xsp                 /* xsave requires 64 byte aligned */
    c769:	48 21 c4             	and    %rax,%rsp
    mov     %xsp, %xcx                 # xsave pointer
    c76c:	48 89 e1             	mov    %rsp,%rcx

    sub     $(20*SE_WORDSIZE), %xsp    /* 20 slots for GPRs and other info */
    c76f:	48 81 ec a0 00 00 00 	sub    $0xa0,%rsp
    mov     %xcx, SE_WORDSIZE*19(%xsp) /* addr for xsave */
    c776:	48 89 8c 24 98 00 00 	mov    %rcx,0x98(%rsp)
    c77d:	00 
/* save non-volatile registers, except xsp */
    mov     %xbx, SE_WORDSIZE*14(%xsp)
    c77e:	48 89 5c 24 70       	mov    %rbx,0x70(%rsp)
    mov     %xsi, SE_WORDSIZE*13(%xsp)
    c783:	48 89 74 24 68       	mov    %rsi,0x68(%rsp)
    mov     %xdi, SE_WORDSIZE*12(%xsp)
    c788:	48 89 7c 24 60       	mov    %rdi,0x60(%rsp)
    mov     %xbp, SE_WORDSIZE*11(%xsp)
    c78d:	48 89 6c 24 58       	mov    %rbp,0x58(%rsp)

#ifdef LINUX64
    mov     %r12, SE_WORDSIZE*10(%rsp)
    c792:	4c 89 64 24 50       	mov    %r12,0x50(%rsp)
    mov     %r13, SE_WORDSIZE* 9(%rsp)
    c797:	4c 89 6c 24 48       	mov    %r13,0x48(%rsp)
    mov     %r14, SE_WORDSIZE* 8(%rsp)
    c79c:	4c 89 74 24 40       	mov    %r14,0x40(%rsp)
    mov     %r15, SE_WORDSIZE* 7(%rsp)
    c7a1:	4c 89 7c 24 38       	mov    %r15,0x38(%rsp)
#endif

/* save and clean extended feature registers */
    mov     SE_WORDSIZE*19(%xsp), %xdi /* xsave pointer */
    c7a6:	48 8b bc 24 98 00 00 	mov    0x98(%rsp),%rdi
    c7ad:	00 
    READ_TD_DATA xsave_size
    c7ae:	65 48 8b 04 25 38 00 	mov    %gs:0x38,%rax
    c7b5:	00 00 
    mov     %xax, %xcx
    c7b7:	48 89 c1             	mov    %rax,%rcx
    shr     $2, %xcx                   /* xsave size in dword */
    c7ba:	48 c1 e9 02          	shr    $0x2,%rcx
    xor     %xax, %xax
    c7be:	48 31 c0             	xor    %rax,%rax
    cld
    c7c1:	fc                   	cld    
    rep stos %eax, %es:(%xdi)
    c7c2:	f3 ab                	rep stos %eax,%es:(%rdi)

    mov     SE_WORDSIZE*19(%xsp), %xdi # xsave pointer
    c7c4:	48 8b bc 24 98 00 00 	mov    0x98(%rsp),%rdi
    c7cb:	00 
    mov     %xdi, (%xsp)
    c7cc:	48 89 3c 24          	mov    %rdi,(%rsp)
    call    save_xregs
    c7d0:	e8 ef fd ff ff       	callq  c5c4 <save_xregs>
    lea_pic SYNTHETIC_STATE, %xdi
    c7d5:	48 8d 3d 24 10 00 00 	lea    0x1024(%rip),%rdi        # d800 <SYNTHETIC_STATE>
    mov     %xdi, (%xsp)
    c7dc:	48 89 3c 24          	mov    %rdi,(%rsp)
    call    restore_xregs
    c7e0:	e8 b3 fd ff ff       	callq  c598 <restore_xregs>

    /* set xdi and xsi using the input parameters */
#ifdef LINUX64
    mov     SE_WORDSIZE*12(%xsp), %xdi
    c7e5:	48 8b 7c 24 60       	mov    0x60(%rsp),%rdi
    mov     SE_WORDSIZE*13(%xsp), %xsi
    c7ea:	48 8b 74 24 68       	mov    0x68(%rsp),%rsi
    mov     SE_WORDSIZE*2(%ebp), %edi
    mov     SE_WORDSIZE*3(%ebp), %esi
#endif

    /* save ocall index to the stack */
    mov     $OCALL_FLAG, %xax
    c7ef:	48 c7 c0 44 49 43 4f 	mov    $0x4f434944,%rax
    mov     %xax, SE_WORDSIZE*4(%xsp)   /* save OCALL_FLAG */
    c7f6:	48 89 44 24 20       	mov    %rax,0x20(%rsp)
    mov     %xdi, SE_WORDSIZE*5(%xsp)   /* save ocall_index */
    c7fb:	48 89 7c 24 28       	mov    %rdi,0x28(%rsp)
    /*
     * save the inside stack context
     *     push TD.last_sp
     *     set TD.last_sp = xsp
     */
    READ_TD_DATA self_addr
    c800:	65 48 8b 04 25 00 00 	mov    %gs:0x0,%rax
    c807:	00 00 
    mov     %xax, %xbx 
    c809:	48 89 c3             	mov    %rax,%rbx

    /* call update_ocall_lastsp */
#ifdef LINUX32
    mov     %xsp, (%xsp)
#else
    mov     %xsp, %xdi
    c80c:	48 89 e7             	mov    %rsp,%rdi
#endif
    
    call    update_ocall_lastsp         /* xax: td.last_sp */
    c80f:	e8 12 6e ff ff       	callq  3626 <update_ocall_lastsp>

#ifdef LINUX64
    mov     SE_WORDSIZE*12(%xsp), %xdi   /* restore xdi */
    c814:	48 8b 7c 24 60       	mov    0x60(%rsp),%rdi
    mov     SE_WORDSIZE*13(%xsp), %xsi   /* restore xdi */
    c819:	48 8b 74 24 68       	mov    0x68(%rsp),%rsi
#endif

    /* restore outside stack context */
    mov     first_ssa_gpr(%xbx), %xdx
    c81e:	48 8b 53 20          	mov    0x20(%rbx),%rdx
    mov     ssa_bp_u(%xdx), %xbp
    c822:	48 8b aa 98 00 00 00 	mov    0x98(%rdx),%rbp
    mov     ssa_sp_u(%xdx), %xsp
    c829:	48 8b a2 90 00 00 00 	mov    0x90(%rdx),%rsp
     *                    | ret_addr    |
     *                    | xbp_u       |
     *                    | xsp_u       |
     *                    | ...         |
     */
    mov     -1*SE_WORDSIZE(%xax), %xbx  /* return address */
    c830:	48 8b 58 f8          	mov    -0x8(%rax),%rbx
    mov     $SE_EEXIT, %xax             /* EEXIT leaf */
    c834:	48 c7 c0 04 00 00 00 	mov    $0x4,%rax

    /* Clear all GPRs, except xax, xbx, xdi, and xsi*/
    xor     %xcx, %xcx
    c83b:	48 31 c9             	xor    %rcx,%rcx
    xor     %xdx, %xdx
    c83e:	48 31 d2             	xor    %rdx,%rdx
#ifdef LINUX64
    xor     %r8,  %r8
    c841:	4d 31 c0             	xor    %r8,%r8
    xor     %r9,  %r9
    c844:	4d 31 c9             	xor    %r9,%r9
    xor     %r10, %r10
    c847:	4d 31 d2             	xor    %r10,%r10
    xor     %r11, %r11
    c84a:	4d 31 db             	xor    %r11,%r11
    xor     %r12, %r12
    c84d:	4d 31 e4             	xor    %r12,%r12
    xor     %r13, %r13
    c850:	4d 31 ed             	xor    %r13,%r13
    xor     %r14, %r14
    c853:	4d 31 f6             	xor    %r14,%r14
    xor     %r15, %r15
    c856:	4d 31 ff             	xor    %r15,%r15
#endif

    /* Set status flags to pre-defined values */
    add     %xdx, %xdx          /* OF = SF = AF = CF = 0; ZF = PF = 1 */
    c859:	48 01 d2             	add    %rdx,%rdx
    cld                         /* DF = 0 */
    c85c:	fc                   	cld    
    c85d:	0f 01 d7             	enclu  

000000000000c860 <__morestack>:
 * stick ocall bridge and proxy frame together
 * ------------------------------------------------------------------
 */
DECLARE_LOCAL_FUNC __morestack
    .cfi_startproc
    push %xbp
    c860:	55                   	push   %rbp
    .cfi_def_cfa_offset     2*SE_WORDSIZE
    .cfi_offset             xbp,-2*SE_WORDSIZE
    mov %xsp, %xbp
    c861:	48 89 e5             	mov    %rsp,%rbp
    .cfi_def_cfa_register   xbp
    sub $(4*SE_WORDSIZE), %xsp
    c864:	48 83 ec 20          	sub    $0x20,%rsp
    mov (2*SE_WORDSIZE)(%xbp), %xax
    mov %xax, (0*SE_WORDSIZE)(%xsp)
    mov (3*SE_WORDSIZE)(%xbp), %xax
    mov %xax, (1*SE_WORDSIZE)(%xsp)
#endif
    call        do_ocall
    c868:	e8 da fe ff ff       	callq  c747 <do_ocall>
    leave
    c86d:	c9                   	leaveq 
    ret
    c86e:	c3                   	retq   

000000000000c86f <asm_oret>:
    .cfi_endproc

DECLARE_GLOBAL_FUNC asm_oret
    mov     %xsp, %xbx
    c86f:	48 89 e3             	mov    %rsp,%rbx
#ifdef LINUX64
    mov     %xdi, SE_WORDSIZE(%xsp)
    c872:	48 89 7c 24 08       	mov    %rdi,0x8(%rsp)
    mov     %xsi, 2*SE_WORDSIZE(%xsp)
    c877:	48 89 74 24 10       	mov    %rsi,0x10(%rsp)
#endif
    mov     SE_WORDSIZE(%xbx), %xsp    /* restore thread_data.last_sp */
    c87c:	48 8b 63 08          	mov    0x8(%rbx),%rsp

/* restore extended feature registers */
    mov     19*SE_WORDSIZE(%xsp), %xdi
    c880:	48 8b bc 24 98 00 00 	mov    0x98(%rsp),%rdi
    c887:	00 
#ifdef LINUX32
    mov     %xdi, (%xsp)
#endif
    call    restore_xregs
    c888:	e8 0b fd ff ff       	callq  c598 <restore_xregs>

/* memset_s */
    xor     %xax, %xax
    c88d:	48 31 c0             	xor    %rax,%rax
    mov     11*SE_WORDSIZE(%xsp), %xcx
    c890:	48 8b 4c 24 58       	mov    0x58(%rsp),%rcx
    sub     %xdi, %xcx
    c895:	48 29 f9             	sub    %rdi,%rcx
    sub     $SE_WORDSIZE, %xcx
    c898:	48 83 e9 08          	sub    $0x8,%rcx
    shr     $2, %xcx
    c89c:	48 c1 e9 02          	shr    $0x2,%rcx
    cld
    c8a0:	fc                   	cld    
    rep stos %eax,%es:(%xdi)
    c8a1:	f3 ab                	rep stos %eax,%es:(%rdi)

    mov     2*SE_WORDSIZE(%xbx), %xax  /* ocall return value */
    c8a3:	48 8b 43 10          	mov    0x10(%rbx),%rax

#ifdef LINUX64
    mov     7*SE_WORDSIZE(%xsp), %r15
    c8a7:	4c 8b 7c 24 38       	mov    0x38(%rsp),%r15
    mov     8*SE_WORDSIZE(%xsp), %r14
    c8ac:	4c 8b 74 24 40       	mov    0x40(%rsp),%r14
    mov     9*SE_WORDSIZE(%xsp), %r13
    c8b1:	4c 8b 6c 24 48       	mov    0x48(%rsp),%r13
    mov    10*SE_WORDSIZE(%xsp), %r12
    c8b6:	4c 8b 64 24 50       	mov    0x50(%rsp),%r12
#endif

    mov    11*SE_WORDSIZE(%xsp), %xbp
    c8bb:	48 8b 6c 24 58       	mov    0x58(%rsp),%rbp
    mov    12*SE_WORDSIZE(%xsp), %xdi
    c8c0:	48 8b 7c 24 60       	mov    0x60(%rsp),%rdi
    mov    13*SE_WORDSIZE(%xsp), %xsi
    c8c5:	48 8b 74 24 68       	mov    0x68(%rsp),%rsi
    mov    14*SE_WORDSIZE(%xsp), %xbx
    c8ca:	48 8b 5c 24 70       	mov    0x70(%rsp),%rbx

    mov     %xbp, %xsp
    c8cf:	48 89 ec             	mov    %rbp,%rsp
    pop     %xbp
    c8d2:	5d                   	pop    %rbp

    ret
    c8d3:	c3                   	retq   
    /* should not come here */
    ud2
    c8d4:	0f 0b                	ud2    

000000000000c8d6 <do_egetkey>:
 * EGETKEY: rbx - the address of KEYREQUEST structure
 *	   rcx - the address where the key is outputted
 * ------------------------------------------------------------------------
 */
DECLARE_LOCAL_FUNC do_egetkey
    SE_PROLOG
    c8d6:	53                   	push   %rbx
    c8d7:	51                   	push   %rcx
    c8d8:	52                   	push   %rdx
    c8d9:	48 89 fb             	mov    %rdi,%rbx
    c8dc:	48 89 f1             	mov    %rsi,%rcx
    mov  $SE_EGETKEY, %xax      /* EGETKEY leaf */
    c8df:	48 c7 c0 01 00 00 00 	mov    $0x1,%rax
    c8e6:	0f 01 d7             	enclu  
    ENCLU
#ifdef SE_SIM
    cmp  $SGX_SUCCESS, %xax     /* In simulation mode, ZF flag will not be set */
    jnz	 .Legetkey_done         /* because the stack clean operation will always clean ZF flag */
#else
    jz   .Legetkey_done         /* if EGETKEY error, ZF flag is set and error code is set to xax */
    c8e9:	74 03                	je     c8ee <do_egetkey+0x18>
#endif
    xor  %xax, %xax
    c8eb:	48 31 c0             	xor    %rax,%rax
.Legetkey_done:
    SE_EPILOG
    c8ee:	5a                   	pop    %rdx
    c8ef:	59                   	pop    %rcx
    c8f0:	5b                   	pop    %rbx
    c8f1:	c3                   	retq   

000000000000c8f2 <do_ereport>:
 *          non-zero: failure
 * -------------------------------------------------------------------------
 */
.global Lereport_inst
DECLARE_LOCAL_FUNC do_ereport
    SE_PROLOG
    c8f2:	53                   	push   %rbx
    c8f3:	51                   	push   %rcx
    c8f4:	52                   	push   %rdx
    c8f5:	48 89 fb             	mov    %rdi,%rbx
    c8f8:	48 89 f1             	mov    %rsi,%rcx
    mov       $SE_EREPORT, %xax  /* EREPORT leaf */
    c8fb:	48 c7 c0 00 00 00 00 	mov    $0x0,%rax
    clc
    c902:	f8                   	clc    

000000000000c903 <Lereport_inst>:
    c903:	0f 01 d7             	enclu  
Lereport_inst:
    ENCLU
    setc      %al
    c906:	0f 92 c0             	setb   %al
    SE_EPILOG
    c909:	5a                   	pop    %rdx
    c90a:	59                   	pop    %rcx
    c90b:	5b                   	pop    %rbx
    c90c:	c3                   	retq   

000000000000c90d <do_eaccept>:
    
DECLARE_GLOBAL_FUNC do_eaccept
    SE_PROLOG
    c90d:	53                   	push   %rbx
    c90e:	51                   	push   %rcx
    c90f:	52                   	push   %rdx
    c910:	48 89 fb             	mov    %rdi,%rbx
    c913:	48 89 f1             	mov    %rsi,%rcx
    mov     $SE_EACCEPT, %eax
    c916:	b8 05 00 00 00       	mov    $0x5,%eax
    c91b:	0f 01 d7             	enclu  
    ENCLU
    cmp  $SGX_SUCCESS, %eax 
    c91e:	83 f8 00             	cmp    $0x0,%eax
    jnz	 abort 
    c921:	75 38                	jne    c95b <abort>
    SE_EPILOG
    c923:	5a                   	pop    %rdx
    c924:	59                   	pop    %rcx
    c925:	5b                   	pop    %rbx
    c926:	c3                   	retq   

000000000000c927 <do_emodpe>:

DECLARE_GLOBAL_FUNC do_emodpe
    SE_PROLOG
    c927:	53                   	push   %rbx
    c928:	51                   	push   %rcx
    c929:	52                   	push   %rdx
    c92a:	48 89 fb             	mov    %rdi,%rbx
    c92d:	48 89 f1             	mov    %rsi,%rcx
    mov     $SE_EMODPE, %eax 
    c930:	b8 06 00 00 00       	mov    $0x6,%eax
    c935:	0f 01 d7             	enclu  
    ENCLU
    SE_EPILOG
    c938:	5a                   	pop    %rdx
    c939:	59                   	pop    %rcx
    c93a:	5b                   	pop    %rbx
    c93b:	c3                   	retq   

000000000000c93c <do_rdrand>:
 *	non-zero: rdrand succeeded
 *	zero: rdrand failed
 * -------------------------------------
 */
DECLARE_LOCAL_FUNC do_rdrand
    mov $_RDRAND_RETRY_TIMES, %ecx
    c93c:	b9 0a 00 00 00       	mov    $0xa,%ecx
    c941:	0f c7 f0             	rdrand %eax
.Lrdrand_retry:
    .byte 0x0F, 0xC7, 0xF0	    /* rdrand %eax */
    jc	.Lrdrand_return
    c944:	72 08                	jb     c94e <do_rdrand+0x12>
    dec	%ecx
    c946:	ff c9                	dec    %ecx
    jnz 	.Lrdrand_retry
    c948:	75 f7                	jne    c941 <do_rdrand+0x5>
    xor 	%xax, %xax
    c94a:	48 31 c0             	xor    %rax,%rax
    ret
    c94d:	c3                   	retq   
.Lrdrand_return:
#ifdef LINUX32
    mov     SE_WORDSIZE(%esp), %ecx
#else
    mov     %rdi, %rcx
    c94e:	48 89 f9             	mov    %rdi,%rcx
#endif
    movl    %eax, (%xcx)
    c951:	89 01                	mov    %eax,(%rcx)
    mov     $1, %xax
    c953:	48 c7 c0 01 00 00 00 	mov    $0x1,%rax
    ret
    c95a:	c3                   	retq   

000000000000c95b <abort>:
 * -------------------------------------------------------------------------
 * extern "C" void abort(void) __attribute__(__noreturn__);
 * -------------------------------------------------------------------------
 */
DECLARE_LOCAL_FUNC abort
    lea_pic g_enclave_state, %xax
    c95b:	48 8d 05 3e 47 00 00 	lea    0x473e(%rip),%rax        # 110a0 <g_enclave_state>
    movl    $ENCLAVE_CRASHED, (%xax)
    c962:	c7 00 03 00 00 00    	movl   $0x3,(%rax)
    ud2
    c968:	0f 0b                	ud2    

000000000000c96a <continue_execution>:
 */
DECLARE_LOCAL_FUNC continue_execution
#ifdef LINUX32
    mov     %xax, %xcx
#else
    mov     %xdi, %xcx
    c96a:	48 89 f9             	mov    %rdi,%rcx
#endif
    mov     SE_WORDSIZE*0(%xcx), %xax
    c96d:	48 8b 01             	mov    (%rcx),%rax
    push    %xax                       /* push xax */
    c970:	50                   	push   %rax
    mov     SE_WORDSIZE*1(%xcx), %xax
    c971:	48 8b 41 08          	mov    0x8(%rcx),%rax
    push    %xax                       /* push xcx */
    c975:	50                   	push   %rax
    mov     SE_WORDSIZE*4(%xcx), %xax  /* xax: xsp */
    c976:	48 8b 41 20          	mov    0x20(%rcx),%rax
/* x86_64 requires a 128-bytes red zone. We need to allocate buffer to avoid touching the red zone. */
    sub     $(SE_WORDSIZE + RED_ZONE_SIZE), %xax   /* allocate buffer to skip red zone and save xip */
    c97a:	48 2d 88 00 00 00    	sub    $0x88,%rax

/* restore registers except xax, xcx, xsp */
    mov     SE_WORDSIZE*2(%xcx), %xdx
    c980:	48 8b 51 10          	mov    0x10(%rcx),%rdx
    mov     SE_WORDSIZE*3(%xcx), %xbx
    c984:	48 8b 59 18          	mov    0x18(%rcx),%rbx
    mov     SE_WORDSIZE*5(%xcx), %xbp
    c988:	48 8b 69 28          	mov    0x28(%rcx),%rbp
    mov     SE_WORDSIZE*6(%xcx), %xsi
    c98c:	48 8b 71 30          	mov    0x30(%rcx),%rsi
    mov     SE_WORDSIZE*7(%xcx), %xdi
    c990:	48 8b 79 38          	mov    0x38(%rcx),%rdi
#ifdef LINUX64
    mov     SE_WORDSIZE*8(%xcx), %r8
    c994:	4c 8b 41 40          	mov    0x40(%rcx),%r8
    mov     SE_WORDSIZE*9(%xcx), %r9
    c998:	4c 8b 49 48          	mov    0x48(%rcx),%r9
    mov     SE_WORDSIZE*10(%xcx), %r10
    c99c:	4c 8b 51 50          	mov    0x50(%rcx),%r10
    mov     SE_WORDSIZE*11(%xcx), %r11
    c9a0:	4c 8b 59 58          	mov    0x58(%rcx),%r11
    mov     SE_WORDSIZE*12(%xcx), %r12
    c9a4:	4c 8b 61 60          	mov    0x60(%rcx),%r12
    mov     SE_WORDSIZE*13(%xcx), %r13
    c9a8:	4c 8b 69 68          	mov    0x68(%rcx),%r13
    mov     SE_WORDSIZE*14(%xcx), %r14
    c9ac:	4c 8b 71 70          	mov    0x70(%rcx),%r14
    mov     SE_WORDSIZE*15(%xcx), %r15
    c9b0:	4c 8b 79 78          	mov    0x78(%rcx),%r15
    push    SE_WORDSIZE*16(%xcx)
    c9b4:	ff b1 80 00 00 00    	pushq  0x80(%rcx)
    popf    /* make sure the following instructions do not affect flags */
    c9ba:	9d                   	popfq  
    push    SE_WORDSIZE*8(%xcx)
    popf
#endif

#ifdef LINUX64
    mov     SE_WORDSIZE*17(%xcx), %xcx
    c9bb:	48 8b 89 88 00 00 00 	mov    0x88(%rcx),%rcx
#endif

/* do not setup the new stack until info is not needed any more
 * otherwise, info will be overwritten
 */
    mov     %xcx, (%xax)               /* save xip to the new stack */
    c9c2:	48 89 08             	mov    %rcx,(%rax)
    pop     %xcx                       /* restore xcx */
    c9c5:	59                   	pop    %rcx
    pop     %xsp                       /* xsp: xax */
    c9c6:	5c                   	pop    %rsp
    xchg    %xax, %xsp
    c9c7:	48 94                	xchg   %rax,%rsp
    ret     $(RED_ZONE_SIZE)           /* pop xip and red zone (if any) */
    c9c9:	c2 80 00             	retq   $0x80
