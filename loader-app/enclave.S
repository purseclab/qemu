
./enclave.signed.so:     file format elf64-x86-64


Disassembly of section .plt:

0000000000001000 <.plt>:
    1000:	ff 35 c2 ff 00 00    	pushq  0xffc2(%rip)        # 10fc8 <_GLOBAL_OFFSET_TABLE_+0x8>
    1006:	ff 25 c4 ff 00 00    	jmpq   *0xffc4(%rip)        # 10fd0 <_GLOBAL_OFFSET_TABLE_+0x10>
    100c:	0f 1f 40 00          	nopl   0x0(%rax)

Disassembly of section .plt.got:

0000000000001010 <_Z9pcl_entryPvS_@plt>:
    1010:	ff 25 c2 ff 00 00    	jmpq   *0xffc2(%rip)        # 10fd8 <_Z9pcl_entryPvS_>
    1016:	66 90                	xchg   %ax,%ax

0000000000001018 <ippcpSetCpuFeatures@plt>:
    1018:	ff 25 c2 ff 00 00    	jmpq   *0xffc2(%rip)        # 10fe0 <ippcpSetCpuFeatures>
    101e:	66 90                	xchg   %ax,%ax

Disassembly of section .text:

0000000000001020 <sgx_test>:
typedef struct ms_test2_t {
	int ms_retval;
} ms_test2_t;

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
    103f:	e8 51 03 00 00       	callq  1395 <sgx_is_outside_enclave>
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
    1061:	e8 60 00 00 00       	callq  10c6 <test>
    1066:	89 c2                	mov    %eax,%edx
    1068:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    106c:	89 10                	mov    %edx,(%rax)


	return status;
    106e:	8b 45 f4             	mov    -0xc(%rbp),%eax
}
    1071:	c9                   	leaveq 
    1072:	c3                   	retq   

0000000000001073 <sgx_test2>:

static sgx_status_t SGX_CDECL sgx_test2(void* pms)
{
    1073:	55                   	push   %rbp
    1074:	48 89 e5             	mov    %rsp,%rbp
    1077:	48 83 ec 20          	sub    $0x20,%rsp
    107b:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
	CHECK_REF_POINTER(pms, sizeof(ms_test2_t));
    107f:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    1084:	74 15                	je     109b <sgx_test2+0x28>
    1086:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    108a:	be 04 00 00 00       	mov    $0x4,%esi
    108f:	48 89 c7             	mov    %rax,%rdi
    1092:	e8 fe 02 00 00       	callq  1395 <sgx_is_outside_enclave>
    1097:	85 c0                	test   %eax,%eax
    1099:	75 07                	jne    10a2 <sgx_test2+0x2f>
    109b:	b8 02 00 00 00       	mov    $0x2,%eax
    10a0:	eb 22                	jmp    10c4 <sgx_test2+0x51>
	//
	// fence after pointer checks
	//
	sgx_lfence();
    10a2:	0f ae e8             	lfence 
	ms_test2_t* ms = SGX_CAST(ms_test2_t*, pms);
    10a5:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    10a9:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
	sgx_status_t status = SGX_SUCCESS;
    10ad:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)



	ms->ms_retval = test2();
    10b4:	e8 2d 00 00 00       	callq  10e6 <test2>
    10b9:	89 c2                	mov    %eax,%edx
    10bb:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    10bf:	89 10                	mov    %edx,(%rax)


	return status;
    10c1:	8b 45 f4             	mov    -0xc(%rbp),%eax
}
    10c4:	c9                   	leaveq 
    10c5:	c3                   	retq   

00000000000010c6 <test>:
	return;
}
#pragma GCC pop_options
extern int relocate_enclave(void * base);
extern "C" int enter_enclave(int index, void *ms, void *tcs, int cssa);
int test() {
    10c6:	55                   	push   %rbp
    10c7:	48 89 e5             	mov    %rsp,%rbp
	volatile int i =0;
    10ca:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
	i=43;
    10d1:	c7 45 fc 2b 00 00 00 	movl   $0x2b,-0x4(%rbp)
	i++;
    10d8:	8b 45 fc             	mov    -0x4(%rbp),%eax
    10db:	83 c0 01             	add    $0x1,%eax
    10de:	89 45 fc             	mov    %eax,-0x4(%rbp)
	return (int)i;
    10e1:	8b 45 fc             	mov    -0x4(%rbp),%eax
}
    10e4:	5d                   	pop    %rbp
    10e5:	c3                   	retq   

00000000000010e6 <test2>:

int test2() {
    10e6:	55                   	push   %rbp
    10e7:	48 89 e5             	mov    %rsp,%rbp
	volatile int i =0;
    10ea:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
        i=43;
    10f1:	c7 45 fc 2b 00 00 00 	movl   $0x2b,-0x4(%rbp)
        i++;
    10f8:	8b 45 fc             	mov    -0x4(%rbp),%eax
    10fb:	83 c0 01             	add    $0x1,%eax
    10fe:	89 45 fc             	mov    %eax,-0x4(%rbp)
        return (int)i;
    1101:	8b 45 fc             	mov    -0x4(%rbp),%eax
}
    1104:	5d                   	pop    %rbp
    1105:	c3                   	retq   

0000000000001106 <_ZL28set_global_feature_indicatormm>:
extern "C" int sgx_init_string_lib(uint64_t cpu_feature_indicator);
extern "C" sgx_status_t sgx_init_crypto_lib(uint64_t cpu_feature_indicator, uint32_t *cpuinfo_table);


static int set_global_feature_indicator(uint64_t feature_bit_array, uint64_t xfrm)
{
    1106:	55                   	push   %rbp
    1107:	48 89 e5             	mov    %rsp,%rbp
    110a:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    110e:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    // Confirm the reserved bits and the unset bits by uRTS must be 0.
    
    
    if(feature_bit_array & (RESERVED_CPU_FEATURE_BIT))
    1112:	48 b8 00 00 00 00 00 	movabs $0xff00000000000000,%rax
    1119:	00 00 ff 
    111c:	48 23 45 f8          	and    -0x8(%rbp),%rax
    1120:	48 85 c0             	test   %rax,%rax
    1123:	74 0e                	je     1133 <_ZL28set_global_feature_indicatormm+0x2d>
    {
        // clear the reserved bits
        feature_bit_array = feature_bit_array & (~(RESERVED_CPU_FEATURE_BIT));
    1125:	48 b8 ff ff ff ff ff 	movabs $0xffffffffffffff,%rax
    112c:	ff ff 00 
    112f:	48 21 45 f8          	and    %rax,-0x8(%rbp)
    }

    // Requires SSE4.1. Take SSE4.1 as the baseline.
    if(!(feature_bit_array & ~(CPU_FEATURE_SSE4_1 - 1)))
    1133:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1137:	48 25 00 fe ff ff    	and    $0xfffffffffffffe00,%rax
    113d:	48 85 c0             	test   %rax,%rax
    1140:	75 0a                	jne    114c <_ZL28set_global_feature_indicatormm+0x46>
    {
        return -1;
    1142:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    1147:	e9 02 01 00 00       	jmpq   124e <_ZL28set_global_feature_indicatormm+0x148>
    }

    // Check for inconsistencies in the CPUID feature mask.
    if ( (((feature_bit_array & CPU_FEATURE_SSE) == CPU_FEATURE_SSE) &&((feature_bit_array & (CPU_FEATURE_SSE - 1)) != (CPU_FEATURE_SSE - 1))) || 
    114c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1150:	83 e0 20             	and    $0x20,%eax
    1153:	48 85 c0             	test   %rax,%rax
    1156:	74 11                	je     1169 <_ZL28set_global_feature_indicatormm+0x63>
    1158:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    115c:	83 e0 1f             	and    $0x1f,%eax
    115f:	48 83 f8 1f          	cmp    $0x1f,%rax
    1163:	0f 85 8f 00 00 00    	jne    11f8 <_ZL28set_global_feature_indicatormm+0xf2>
        (((feature_bit_array & CPU_FEATURE_SSE2) == CPU_FEATURE_SSE2) &&((feature_bit_array & (CPU_FEATURE_SSE2 - 1)) != (CPU_FEATURE_SSE2 - 1))) ||
    1169:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    116d:	83 e0 40             	and    $0x40,%eax
    if ( (((feature_bit_array & CPU_FEATURE_SSE) == CPU_FEATURE_SSE) &&((feature_bit_array & (CPU_FEATURE_SSE - 1)) != (CPU_FEATURE_SSE - 1))) || 
    1170:	48 85 c0             	test   %rax,%rax
    1173:	74 0d                	je     1182 <_ZL28set_global_feature_indicatormm+0x7c>
        (((feature_bit_array & CPU_FEATURE_SSE2) == CPU_FEATURE_SSE2) &&((feature_bit_array & (CPU_FEATURE_SSE2 - 1)) != (CPU_FEATURE_SSE2 - 1))) ||
    1175:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1179:	83 e0 3f             	and    $0x3f,%eax
    117c:	48 83 f8 3f          	cmp    $0x3f,%rax
    1180:	75 76                	jne    11f8 <_ZL28set_global_feature_indicatormm+0xf2>
        (((feature_bit_array & CPU_FEATURE_SSE3) == CPU_FEATURE_SSE3) &&((feature_bit_array & (CPU_FEATURE_SSE3 - 1)) != (CPU_FEATURE_SSE3 - 1))) ||
    1182:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1186:	25 80 00 00 00       	and    $0x80,%eax
        (((feature_bit_array & CPU_FEATURE_SSE2) == CPU_FEATURE_SSE2) &&((feature_bit_array & (CPU_FEATURE_SSE2 - 1)) != (CPU_FEATURE_SSE2 - 1))) ||
    118b:	48 85 c0             	test   %rax,%rax
    118e:	74 0d                	je     119d <_ZL28set_global_feature_indicatormm+0x97>
        (((feature_bit_array & CPU_FEATURE_SSE3) == CPU_FEATURE_SSE3) &&((feature_bit_array & (CPU_FEATURE_SSE3 - 1)) != (CPU_FEATURE_SSE3 - 1))) ||
    1190:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1194:	83 e0 7f             	and    $0x7f,%eax
    1197:	48 83 f8 7f          	cmp    $0x7f,%rax
    119b:	75 5b                	jne    11f8 <_ZL28set_global_feature_indicatormm+0xf2>
        (((feature_bit_array & CPU_FEATURE_SSSE3) == CPU_FEATURE_SSSE3) && ((feature_bit_array & (CPU_FEATURE_SSSE3 - 1)) != (CPU_FEATURE_SSSE3 - 1))) ||
    119d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    11a1:	25 00 01 00 00       	and    $0x100,%eax
        (((feature_bit_array & CPU_FEATURE_SSE3) == CPU_FEATURE_SSE3) &&((feature_bit_array & (CPU_FEATURE_SSE3 - 1)) != (CPU_FEATURE_SSE3 - 1))) ||
    11a6:	48 85 c0             	test   %rax,%rax
    11a9:	74 0f                	je     11ba <_ZL28set_global_feature_indicatormm+0xb4>
        (((feature_bit_array & CPU_FEATURE_SSSE3) == CPU_FEATURE_SSSE3) && ((feature_bit_array & (CPU_FEATURE_SSSE3 - 1)) != (CPU_FEATURE_SSSE3 - 1))) ||
    11ab:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    11af:	0f b6 c0             	movzbl %al,%eax
    11b2:	48 3d ff 00 00 00    	cmp    $0xff,%rax
    11b8:	75 3e                	jne    11f8 <_ZL28set_global_feature_indicatormm+0xf2>
        (((feature_bit_array & CPU_FEATURE_SSE4_1) == CPU_FEATURE_SSE4_1) && ((feature_bit_array & (CPU_FEATURE_SSE4_1 - 1)) != (CPU_FEATURE_SSE4_1 - 1))) ||
    11ba:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    11be:	25 00 02 00 00       	and    $0x200,%eax
        (((feature_bit_array & CPU_FEATURE_SSSE3) == CPU_FEATURE_SSSE3) && ((feature_bit_array & (CPU_FEATURE_SSSE3 - 1)) != (CPU_FEATURE_SSSE3 - 1))) ||
    11c3:	48 85 c0             	test   %rax,%rax
    11c6:	74 11                	je     11d9 <_ZL28set_global_feature_indicatormm+0xd3>
        (((feature_bit_array & CPU_FEATURE_SSE4_1) == CPU_FEATURE_SSE4_1) && ((feature_bit_array & (CPU_FEATURE_SSE4_1 - 1)) != (CPU_FEATURE_SSE4_1 - 1))) ||
    11c8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    11cc:	25 ff 01 00 00       	and    $0x1ff,%eax
    11d1:	48 3d ff 01 00 00    	cmp    $0x1ff,%rax
    11d7:	75 1f                	jne    11f8 <_ZL28set_global_feature_indicatormm+0xf2>
        (((feature_bit_array & CPU_FEATURE_SSE4_2) == CPU_FEATURE_SSE4_2) && ((feature_bit_array & (CPU_FEATURE_SSE4_2 - 1)) != (CPU_FEATURE_SSE4_2 - 1))) )
    11d9:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    11dd:	25 00 04 00 00       	and    $0x400,%eax
        (((feature_bit_array & CPU_FEATURE_SSE4_1) == CPU_FEATURE_SSE4_1) && ((feature_bit_array & (CPU_FEATURE_SSE4_1 - 1)) != (CPU_FEATURE_SSE4_1 - 1))) ||
    11e2:	48 85 c0             	test   %rax,%rax
    11e5:	74 18                	je     11ff <_ZL28set_global_feature_indicatormm+0xf9>
        (((feature_bit_array & CPU_FEATURE_SSE4_2) == CPU_FEATURE_SSE4_2) && ((feature_bit_array & (CPU_FEATURE_SSE4_2 - 1)) != (CPU_FEATURE_SSE4_2 - 1))) )
    11e7:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    11eb:	25 ff 03 00 00       	and    $0x3ff,%eax
    11f0:	48 3d ff 03 00 00    	cmp    $0x3ff,%rax
    11f6:	74 07                	je     11ff <_ZL28set_global_feature_indicatormm+0xf9>
    {
        return -1;
    11f8:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    11fd:	eb 4f                	jmp    124e <_ZL28set_global_feature_indicatormm+0x148>
    }

    // Determine whether the OS & ENCLAVE support SAVE/RESTORE of the AVX register set
    // IF NOT, clear the advanced feature set bits corresponding to AVX and beyond
    if(!XFEATURE_ENABLED_AVX(xfrm))
    11ff:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1203:	83 e0 06             	and    $0x6,%eax
    1206:	48 83 f8 06          	cmp    $0x6,%rax
    120a:	74 10                	je     121c <_ZL28set_global_feature_indicatormm+0x116>
    {
        // AVX is disabled by OS, so clear the AVX related feature bits
	feature_bit_array &= (~(CPU_FEATURE_AVX | CPU_FEATURE_VAES | CPU_FEATURE_VPCLMULQDQ | CPU_FEATURE_F16C | CPU_FEATURE_AVX2 |
    120c:	48 b8 ff 7f 12 86 08 	movabs $0xfffe200886127fff,%rax
    1213:	20 fe ff 
    1216:	48 21 45 f8          	and    %rax,-0x8(%rbp)
    121a:	eb 1f                	jmp    123b <_ZL28set_global_feature_indicatormm+0x135>
            CPU_FEATURE_AVX512F | CPU_FEATURE_AVX512CD | CPU_FEATURE_AVX512ER | CPU_FEATURE_AVX512PF | CPU_FEATURE_AVX512DQ | CPU_FEATURE_AVX512BW |
            CPU_FEATURE_AVX512VL | CPU_FEATURE_AVX512IFMA52 | CPU_FEATURE_AVX512VBMI | CPU_FEATURE_AVX512_VPOPCNTDQ | CPU_FEATURE_AVX512_4VNNIW |
            CPU_FEATURE_AVX512_4FMAPS | CPU_FEATURE_AVX512_BITALG | CPU_FEATURE_AVX512_VBMI2 | CPU_FEATURE_AVX512_VNNI));
    }

    else if (!XFEATURE_ENABLED_AVX3(xfrm))
    121c:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1220:	25 e0 00 00 00       	and    $0xe0,%eax
    1225:	48 3d e0 00 00 00    	cmp    $0xe0,%rax
    122b:	74 0e                	je     123b <_ZL28set_global_feature_indicatormm+0x135>
    {
        feature_bit_array &= (~(CPU_FEATURE_AVX512F | CPU_FEATURE_AVX512CD | CPU_FEATURE_AVX512ER | CPU_FEATURE_AVX512PF | CPU_FEATURE_AVX512DQ |
    122d:	48 b8 ff ff ff b6 18 	movabs $0xfffee018b6ffffff,%rax
    1234:	e0 fe ff 
    1237:	48 21 45 f8          	and    %rax,-0x8(%rbp)
            CPU_FEATURE_AVX512BW | CPU_FEATURE_AVX512VL | CPU_FEATURE_AVX512IFMA52 | CPU_FEATURE_AVX512VBMI | CPU_FEATURE_AVX512_VPOPCNTDQ |
            CPU_FEATURE_AVX512_4VNNIW | CPU_FEATURE_AVX512_4FMAPS | CPU_FEATURE_AVX512_BITALG | CPU_FEATURE_AVX512_VBMI2 | CPU_FEATURE_AVX512_VNNI));
    }

    g_cpu_feature_indicator = feature_bit_array;
    123b:	48 8d 05 a6 fb 00 00 	lea    0xfba6(%rip),%rax        # 10de8 <g_cpu_feature_indicator>
    1242:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    1246:	48 89 10             	mov    %rdx,(%rax)
    return 0;
    1249:	b8 00 00 00 00       	mov    $0x0,%eax
}
    124e:	5d                   	pop    %rbp
    124f:	c3                   	retq   

0000000000001250 <init_optimized_libs>:

extern "C" int init_optimized_libs(const uint64_t feature_bit_array, uint32_t *cpuinfo_table, uint64_t xfrm)
{
    1250:	55                   	push   %rbp
    1251:	48 89 e5             	mov    %rsp,%rbp
    1254:	48 83 ec 20          	sub    $0x20,%rsp
    1258:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    125c:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    1260:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    if (g_enclave_state != ENCLAVE_INIT_IN_PROGRESS)
    1264:	48 8d 05 35 fe 00 00 	lea    0xfe35(%rip),%rax        # 110a0 <g_enclave_state>
    126b:	8b 00                	mov    (%rax),%eax
    126d:	83 f8 01             	cmp    $0x1,%eax
    1270:	74 07                	je     1279 <init_optimized_libs+0x29>
    {
        return -1;
    1272:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    1277:	eb 73                	jmp    12ec <init_optimized_libs+0x9c>
    }
    // set the global feature indicator
    if(set_global_feature_indicator(feature_bit_array, xfrm))
    1279:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    127d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1281:	48 89 d6             	mov    %rdx,%rsi
    1284:	48 89 c7             	mov    %rax,%rdi
    1287:	e8 7a fe ff ff       	callq  1106 <_ZL28set_global_feature_indicatormm>
    128c:	85 c0                	test   %eax,%eax
    128e:	0f 95 c0             	setne  %al
    1291:	84 c0                	test   %al,%al
    1293:	74 07                	je     129c <init_optimized_libs+0x4c>
    {
        return -1;
    1295:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    129a:	eb 50                	jmp    12ec <init_optimized_libs+0x9c>
    }

    // Init string library with the global feature indicator
    if(sgx_init_string_lib(g_cpu_feature_indicator) != 0)
    129c:	48 8d 05 45 fb 00 00 	lea    0xfb45(%rip),%rax        # 10de8 <g_cpu_feature_indicator>
    12a3:	48 8b 00             	mov    (%rax),%rax
    12a6:	48 89 c7             	mov    %rax,%rdi
    12a9:	e8 42 a1 00 00       	callq  b3f0 <sgx_init_string_lib>
    12ae:	85 c0                	test   %eax,%eax
    12b0:	0f 95 c0             	setne  %al
    12b3:	84 c0                	test   %al,%al
    12b5:	74 07                	je     12be <init_optimized_libs+0x6e>
    {
        return -1;
    12b7:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    12bc:	eb 2e                	jmp    12ec <init_optimized_libs+0x9c>
    }

    // Init IPP crypto library with the global feature indicator	
    if(sgx_init_crypto_lib(g_cpu_feature_indicator, cpuinfo_table) != 0)
    12be:	48 8d 05 23 fb 00 00 	lea    0xfb23(%rip),%rax        # 10de8 <g_cpu_feature_indicator>
    12c5:	48 8b 00             	mov    (%rax),%rax
    12c8:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    12cc:	48 89 d6             	mov    %rdx,%rsi
    12cf:	48 89 c7             	mov    %rax,%rdi
    12d2:	e8 8c a3 00 00       	callq  b663 <sgx_init_crypto_lib>
    12d7:	85 c0                	test   %eax,%eax
    12d9:	0f 95 c0             	setne  %al
    12dc:	84 c0                	test   %al,%al
    12de:	74 07                	je     12e7 <init_optimized_libs+0x97>
    {
        return -1;
    12e0:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    12e5:	eb 05                	jmp    12ec <init_optimized_libs+0x9c>
    }

    return 0;
    12e7:	b8 00 00 00 00       	mov    $0x0,%eax
}
    12ec:	c9                   	leaveq 
    12ed:	c3                   	retq   

00000000000012ee <trts_access_version_dummy1>:

#ifndef SE_SIM

#include "se_cdefs.h"
// add a version to trts
SGX_ACCESS_VERSION(trts, 1);
    12ee:	55                   	push   %rbp
    12ef:	48 89 e5             	mov    %rsp,%rbp
    12f2:	48 8d 05 17 fd 00 00 	lea    0xfd17(%rip),%rax        # 11010 <sgx_trts_version>
    12f9:	c6 00 73             	movb   $0x73,(%rax)
    12fc:	48 8d 05 0d fd 00 00 	lea    0xfd0d(%rip),%rax        # 11010 <sgx_trts_version>
    1303:	5d                   	pop    %rbp
    1304:	c3                   	retq   

0000000000001305 <sgx_is_within_enclave>:
//      1 - the buffer is strictly within the enclave
//      0 - the whole buffer or part of the buffer is not within the enclave,
//          or the buffer is wrap around
//
int sgx_is_within_enclave(const void *addr, size_t size)
{
    1305:	55                   	push   %rbp
    1306:	48 89 e5             	mov    %rsp,%rbp
    1309:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    130d:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    size_t start = reinterpret_cast<size_t>(addr);
    1311:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1315:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    size_t end = 0;
    1319:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    1320:	00 
    size_t enclave_start = (size_t)&__ImageBase;
    1321:	48 8d 05 d8 ec ff ff 	lea    -0x1328(%rip),%rax        # 0 <enclave.so>
    1328:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    size_t enclave_end = enclave_start + g_global_data.enclave_size - 1;
    132c:	48 8d 05 4d be 00 00 	lea    0xbe4d(%rip),%rax        # d180 <g_global_data>
    1333:	48 8b 10             	mov    (%rax),%rdx
    1336:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    133a:	48 01 d0             	add    %rdx,%rax
    133d:	48 83 e8 01          	sub    $0x1,%rax
    1341:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    // g_global_data.enclave_end = enclave_base + enclave_size - 1;
    // so the enclave range is [enclave_start, enclave_end] inclusively

    if(size > 0)
    1345:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    134a:	74 15                	je     1361 <sgx_is_within_enclave+0x5c>
    {
        end = start + size - 1;
    134c:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    1350:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    1354:	48 01 d0             	add    %rdx,%rax
    1357:	48 83 e8 01          	sub    $0x1,%rax
    135b:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    135f:	eb 08                	jmp    1369 <sgx_is_within_enclave+0x64>
    }
    else
    {
        end = start;
    1361:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1365:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    }
    if( (start <= end) && (start >= enclave_start) && (end <= enclave_end) )
    1369:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    136d:	48 3b 45 e0          	cmp    -0x20(%rbp),%rax
    1371:	77 1b                	ja     138e <sgx_is_within_enclave+0x89>
    1373:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1377:	48 3b 45 f0          	cmp    -0x10(%rbp),%rax
    137b:	72 11                	jb     138e <sgx_is_within_enclave+0x89>
    137d:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1381:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    1385:	77 07                	ja     138e <sgx_is_within_enclave+0x89>
    {
        return 1;
    1387:	b8 01 00 00 00       	mov    $0x1,%eax
    138c:	eb 05                	jmp    1393 <sgx_is_within_enclave+0x8e>
    }
    return 0;
    138e:	b8 00 00 00 00       	mov    $0x0,%eax
}
    1393:	5d                   	pop    %rbp
    1394:	c3                   	retq   

0000000000001395 <sgx_is_outside_enclave>:
//      1 - the buffer is strictly outside the enclave
//      0 - the whole buffer or part of the buffer is not outside the enclave,
//          or the buffer is wrap around
//
int sgx_is_outside_enclave(const void *addr, size_t size)
{
    1395:	55                   	push   %rbp
    1396:	48 89 e5             	mov    %rsp,%rbp
    1399:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    139d:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    size_t start = reinterpret_cast<size_t>(addr);
    13a1:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    13a5:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    size_t end = 0;
    13a9:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    13b0:	00 
    size_t enclave_start = (size_t)&__ImageBase;
    13b1:	48 8d 05 48 ec ff ff 	lea    -0x13b8(%rip),%rax        # 0 <enclave.so>
    13b8:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    size_t enclave_end = enclave_start + g_global_data.enclave_size - 1;
    13bc:	48 8d 05 bd bd 00 00 	lea    0xbdbd(%rip),%rax        # d180 <g_global_data>
    13c3:	48 8b 10             	mov    (%rax),%rdx
    13c6:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    13ca:	48 01 d0             	add    %rdx,%rax
    13cd:	48 83 e8 01          	sub    $0x1,%rax
    13d1:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    // g_global_data.enclave_end = enclave_base + enclave_size - 1;
    // so the enclave range is [enclave_start, enclave_end] inclusively

    if(size > 0)
    13d5:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    13da:	74 15                	je     13f1 <sgx_is_outside_enclave+0x5c>
    {
        end = start + size - 1;
    13dc:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    13e0:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    13e4:	48 01 d0             	add    %rdx,%rax
    13e7:	48 83 e8 01          	sub    $0x1,%rax
    13eb:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    13ef:	eb 08                	jmp    13f9 <sgx_is_outside_enclave+0x64>
    }
    else
    {
        end = start;
    13f1:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    13f5:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    }
    if( (start <= end) && ((end < enclave_start) || (start > enclave_end)) )
    13f9:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    13fd:	48 3b 45 e0          	cmp    -0x20(%rbp),%rax
    1401:	77 1b                	ja     141e <sgx_is_outside_enclave+0x89>
    1403:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1407:	48 3b 45 f0          	cmp    -0x10(%rbp),%rax
    140b:	72 0a                	jb     1417 <sgx_is_outside_enclave+0x82>
    140d:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1411:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    1415:	76 07                	jbe    141e <sgx_is_outside_enclave+0x89>
    {
        return 1;
    1417:	b8 01 00 00 00       	mov    $0x1,%eax
    141c:	eb 05                	jmp    1423 <sgx_is_outside_enclave+0x8e>
    }
    return 0;
    141e:	b8 00 00 00 00       	mov    $0x0,%eax
}
    1423:	5d                   	pop    %rbp
    1424:	c3                   	retq   

0000000000001425 <sgx_ocalloc>:
// When ECALL or exception handling returns, the stack pointer is set as the value in the ECALL stack frame and then EEXIT,
// so the outside stack is automatically unwind.
// In addition, sgx_ocalloc needs perform outside stack probe to make sure it is not allocating beyond the end of the stack.
#define OC_ROUND 16
void * sgx_ocalloc(size_t size)
{
    1425:	55                   	push   %rbp
    1426:	48 89 e5             	mov    %rsp,%rbp
    1429:	48 83 ec 40          	sub    $0x40,%rsp
    142d:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    // read the outside stack address from current SSA
    thread_data_t *thread_data = get_thread_data();
    1431:	e8 69 b2 00 00       	callq  c69f <get_thread_data>
    1436:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    ssa_gpr_t *ssa_gpr = reinterpret_cast<ssa_gpr_t *>(thread_data->first_ssa_gpr);
    143a:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    143e:	48 8b 40 20          	mov    0x20(%rax),%rax
    1442:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    size_t addr = ssa_gpr->REG(sp_u);
    1446:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    144a:	48 8b 80 90 00 00 00 	mov    0x90(%rax),%rax
    1451:	48 89 45 e8          	mov    %rax,-0x18(%rbp)

    // check u_rsp points to the untrusted address.
    // if the check fails, it should be hacked. call abort directly
    if(!sgx_is_outside_enclave(reinterpret_cast<void *>(addr), sizeof(size_t)))
    1455:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1459:	be 08 00 00 00       	mov    $0x8,%esi
    145e:	48 89 c7             	mov    %rax,%rdi
    1461:	e8 2f ff ff ff       	callq  1395 <sgx_is_outside_enclave>
    1466:	85 c0                	test   %eax,%eax
    1468:	0f 94 c0             	sete   %al
    146b:	84 c0                	test   %al,%al
    146d:	74 05                	je     1474 <sgx_ocalloc+0x4f>
    {
        abort();
    146f:	e8 5a b5 00 00       	callq  c9ce <abort>
    }

    // size is too large to allocate. call abort() directly.
    if(addr < size)
    1474:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1478:	48 3b 45 c8          	cmp    -0x38(%rbp),%rax
    147c:	73 05                	jae    1483 <sgx_ocalloc+0x5e>
    {
        abort();
    147e:	e8 4b b5 00 00       	callq  c9ce <abort>
    }

    // calculate the start address for the allocated memory
    addr -= size;
    1483:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    1487:	48 29 45 e8          	sub    %rax,-0x18(%rbp)
    addr &= ~(static_cast<size_t>(OC_ROUND - 1));  // for stack alignment
    148b:	48 83 65 e8 f0       	andq   $0xfffffffffffffff0,-0x18(%rbp)

    // the allocated memory has overlap with enclave, abort the enclave
    if(!sgx_is_outside_enclave(reinterpret_cast<void *>(addr), size))
    1490:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1494:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    1498:	48 89 d6             	mov    %rdx,%rsi
    149b:	48 89 c7             	mov    %rax,%rdi
    149e:	e8 f2 fe ff ff       	callq  1395 <sgx_is_outside_enclave>
    14a3:	85 c0                	test   %eax,%eax
    14a5:	0f 94 c0             	sete   %al
    14a8:	84 c0                	test   %al,%al
    14aa:	74 05                	je     14b1 <sgx_ocalloc+0x8c>
    {
        abort();
    14ac:	e8 1d b5 00 00       	callq  c9ce <abort>

    // probe the outside stack to ensure that we do not skip over the stack3 guard page
    // we need to probe all the pages including the first page and the last page
    // the first page need to be probed in case uRTS didnot touch that page before EENTER enclave
    // the last page need to be probed in case the enclave didnot touch that page before another OCALLOC
    size_t first_page = TRIM_TO_PAGE(ssa_gpr->REG(sp_u) - 1);
    14b1:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    14b5:	48 8b 80 90 00 00 00 	mov    0x90(%rax),%rax
    14bc:	48 83 e8 01          	sub    $0x1,%rax
    14c0:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    14c6:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    size_t last_page = TRIM_TO_PAGE(addr);
    14ca:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    14ce:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    14d4:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

    // To avoid the dead-loop in the following for(...) loop.
    // Attacker might fake a stack address that is within address 0x4095.
    if (last_page == 0)
    14d8:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    14dd:	75 05                	jne    14e4 <sgx_ocalloc+0xbf>
    {
        abort();
    14df:	e8 ea b4 00 00       	callq  c9ce <abort>
    }

    // the compiler may optimize the following code to probe the pages in any order
    // while we only expect the probe order should be from higher addr to lower addr
    // so use volatile to avoid optimization by the compiler
    for(volatile size_t page = first_page; page >= last_page; page -= SE_PAGE_SIZE)
    14e4:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    14e8:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    14ec:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    14f0:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    14f4:	0f 96 c0             	setbe  %al
    14f7:	84 c0                	test   %al,%al
    14f9:	74 26                	je     1521 <sgx_ocalloc+0xfc>
    {
        // OS may refuse to commit a physical page if the page fault address is smaller than RSP
        // So update the outside stack address before probe the page
        ssa_gpr->REG(sp_u) = page;
    14fb:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    14ff:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1503:	48 89 90 90 00 00 00 	mov    %rdx,0x90(%rax)

        *reinterpret_cast<uint8_t *>(page) = 0;
    150a:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    150e:	c6 00 00             	movb   $0x0,(%rax)
    for(volatile size_t page = first_page; page >= last_page; page -= SE_PAGE_SIZE)
    1511:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    1515:	48 2d 00 10 00 00    	sub    $0x1000,%rax
    151b:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    151f:	eb cb                	jmp    14ec <sgx_ocalloc+0xc7>
    }

    // update the outside stack address in the SSA to the allocated address
    ssa_gpr->REG(sp_u) = addr;
    1521:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1525:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    1529:	48 89 90 90 00 00 00 	mov    %rdx,0x90(%rax)

    return reinterpret_cast<void *>(addr);
    1530:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
}
    1534:	c9                   	leaveq 
    1535:	c3                   	retq   

0000000000001536 <sgx_ocfree>:
// Return Value:
//      N/A
// sgx_ocfree restores the original outside stack pointer in the SSA.
// Do not call this function if you still need the buffer allocated by sgx_ocalloc within the ECALL.
void sgx_ocfree()
{
    1536:	55                   	push   %rbp
    1537:	48 89 e5             	mov    %rsp,%rbp
    153a:	48 83 ec 20          	sub    $0x20,%rsp
    //                       -------------
    //                      | ret_addr    |
    //                      | xbp_u       |
    //                      | xsp_u       |

    thread_data_t *thread_data = get_thread_data();
    153e:	e8 5c b1 00 00       	callq  c69f <get_thread_data>
    1543:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    ssa_gpr_t *ssa_gpr = reinterpret_cast<ssa_gpr_t *>(thread_data->first_ssa_gpr);
    1547:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    154b:	48 8b 40 20          	mov    0x20(%rax),%rax
    154f:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    uintptr_t *addr = reinterpret_cast<uintptr_t *>(thread_data->last_sp);
    1553:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1557:	48 8b 40 08          	mov    0x8(%rax),%rax
    155b:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    uintptr_t usp = *(addr - 3);
    155f:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1563:	48 8b 40 e8          	mov    -0x18(%rax),%rax
    1567:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if(!sgx_is_outside_enclave(reinterpret_cast<void *>(usp), sizeof(uintptr_t)))
    156b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    156f:	be 08 00 00 00       	mov    $0x8,%esi
    1574:	48 89 c7             	mov    %rax,%rdi
    1577:	e8 19 fe ff ff       	callq  1395 <sgx_is_outside_enclave>
    157c:	85 c0                	test   %eax,%eax
    157e:	0f 94 c0             	sete   %al
    1581:	84 c0                	test   %al,%al
    1583:	74 05                	je     158a <sgx_ocfree+0x54>
    {
        abort();
    1585:	e8 44 b4 00 00       	callq  c9ce <abort>
    }
    ssa_gpr->REG(sp_u) = usp;
    158a:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    158e:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    1592:	48 89 90 90 00 00 00 	mov    %rdx,0x90(%rax)
}
    1599:	90                   	nop
    159a:	c9                   	leaveq 
    159b:	c3                   	retq   

000000000000159c <_ZL15__do_get_rand32Pj>:
    return n;
}
#endif

static sgx_status_t  __do_get_rand32(uint32_t* rand_num)
{
    159c:	55                   	push   %rbp
    159d:	48 89 e5             	mov    %rsp,%rbp
    15a0:	48 83 ec 10          	sub    $0x10,%rsp
    15a4:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
#ifndef SE_SIM
    /* We expect the CPU has RDRAND support for HW mode. Otherwise, an exception will be thrown
    * do_rdrand() will try to call RDRAND for 10 times
    */
    if(0 == do_rdrand(rand_num))
    15a8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    15ac:	48 89 c7             	mov    %rax,%rdi
    15af:	e8 fb b3 00 00       	callq  c9af <do_rdrand>
    15b4:	85 c0                	test   %eax,%eax
    15b6:	0f 94 c0             	sete   %al
    15b9:	84 c0                	test   %al,%al
    15bb:	74 07                	je     15c4 <_ZL15__do_get_rand32Pj+0x28>
        return SGX_ERROR_UNEXPECTED;
    15bd:	b8 01 00 00 00       	mov    $0x1,%eax
    15c2:	eb 05                	jmp    15c9 <_ZL15__do_get_rand32Pj+0x2d>
    {
        /*  use LCG in simulation mode */
        *rand_num = get_rand_lcg();
    }
#endif
    return SGX_SUCCESS;
    15c4:	b8 00 00 00 00       	mov    $0x0,%eax
}
    15c9:	c9                   	leaveq 
    15ca:	c3                   	retq   

00000000000015cb <sgx_read_rand>:

sgx_status_t sgx_read_rand(unsigned char *rand, size_t length_in_bytes)
{
    15cb:	55                   	push   %rbp
    15cc:	48 89 e5             	mov    %rsp,%rbp
    15cf:	48 83 ec 30          	sub    $0x30,%rsp
    15d3:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    15d7:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    15db:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    15e2:	00 00 
    15e4:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    15e8:	31 c0                	xor    %eax,%eax
    // check parameters
    //
    // rand can be within or outside the enclave
    if(!rand || !length_in_bytes)
    15ea:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    15ef:	74 07                	je     15f8 <sgx_read_rand+0x2d>
    15f1:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    15f6:	75 0a                	jne    1602 <sgx_read_rand+0x37>
    {
        return SGX_ERROR_INVALID_PARAMETER;
    15f8:	b8 02 00 00 00       	mov    $0x2,%eax
    15fd:	e9 cc 00 00 00       	jmpq   16ce <sgx_read_rand+0x103>
    }
    if(!sgx_is_within_enclave(rand, length_in_bytes) && !sgx_is_outside_enclave(rand, length_in_bytes))
    1602:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    1606:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    160a:	48 89 d6             	mov    %rdx,%rsi
    160d:	48 89 c7             	mov    %rax,%rdi
    1610:	e8 f0 fc ff ff       	callq  1305 <sgx_is_within_enclave>
    1615:	85 c0                	test   %eax,%eax
    1617:	75 1e                	jne    1637 <sgx_read_rand+0x6c>
    1619:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    161d:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1621:	48 89 d6             	mov    %rdx,%rsi
    1624:	48 89 c7             	mov    %rax,%rdi
    1627:	e8 69 fd ff ff       	callq  1395 <sgx_is_outside_enclave>
    162c:	85 c0                	test   %eax,%eax
    162e:	75 07                	jne    1637 <sgx_read_rand+0x6c>
    1630:	b8 01 00 00 00       	mov    $0x1,%eax
    1635:	eb 05                	jmp    163c <sgx_read_rand+0x71>
    1637:	b8 00 00 00 00       	mov    $0x0,%eax
    163c:	84 c0                	test   %al,%al
    163e:	74 0a                	je     164a <sgx_read_rand+0x7f>
    {
        return SGX_ERROR_INVALID_PARAMETER;
    1640:	b8 02 00 00 00       	mov    $0x2,%eax
    1645:	e9 84 00 00 00       	jmpq   16ce <sgx_read_rand+0x103>
    }
    // loop to rdrand
    uint32_t rand_num = 0;
    164a:	c7 45 e8 00 00 00 00 	movl   $0x0,-0x18(%rbp)
    while(length_in_bytes > 0)
    1651:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    1656:	74 56                	je     16ae <sgx_read_rand+0xe3>
    {
        sgx_status_t status = __do_get_rand32(&rand_num);
    1658:	48 8d 45 e8          	lea    -0x18(%rbp),%rax
    165c:	48 89 c7             	mov    %rax,%rdi
    165f:	e8 38 ff ff ff       	callq  159c <_ZL15__do_get_rand32Pj>
    1664:	89 45 ec             	mov    %eax,-0x14(%rbp)
        if(status != SGX_SUCCESS)
    1667:	83 7d ec 00          	cmpl   $0x0,-0x14(%rbp)
    166b:	74 05                	je     1672 <sgx_read_rand+0xa7>
        {
            return status;
    166d:	8b 45 ec             	mov    -0x14(%rbp),%eax
    1670:	eb 5c                	jmp    16ce <sgx_read_rand+0x103>
        }

        size_t size = (length_in_bytes < sizeof(rand_num)) ? length_in_bytes : sizeof(rand_num);
    1672:	b8 04 00 00 00       	mov    $0x4,%eax
    1677:	48 83 7d d0 04       	cmpq   $0x4,-0x30(%rbp)
    167c:	48 0f 46 45 d0       	cmovbe -0x30(%rbp),%rax
    1681:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
        memcpy(rand, &rand_num, size);
    1685:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    1689:	48 8d 4d e8          	lea    -0x18(%rbp),%rcx
    168d:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1691:	48 89 ce             	mov    %rcx,%rsi
    1694:	48 89 c7             	mov    %rax,%rdi
    1697:	e8 96 98 00 00       	callq  af32 <memcpy>

        rand += size;
    169c:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    16a0:	48 01 45 d8          	add    %rax,-0x28(%rbp)
        length_in_bytes -= size;
    16a4:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    16a8:	48 29 45 d0          	sub    %rax,-0x30(%rbp)
    while(length_in_bytes > 0)
    16ac:	eb a3                	jmp    1651 <sgx_read_rand+0x86>
    }
    memset_s(&rand_num, sizeof(rand_num), 0, sizeof(rand_num));
    16ae:	48 8d 45 e8          	lea    -0x18(%rbp),%rax
    16b2:	b9 04 00 00 00       	mov    $0x4,%ecx
    16b7:	ba 00 00 00 00       	mov    $0x0,%edx
    16bc:	be 04 00 00 00       	mov    $0x4,%esi
    16c1:	48 89 c7             	mov    %rax,%rdi
    16c4:	e8 01 99 00 00       	callq  afca <memset_s>
    return SGX_SUCCESS;
    16c9:	b8 00 00 00 00       	mov    $0x0,%eax
}
    16ce:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    16d2:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    16d9:	00 00 
    16db:	74 05                	je     16e2 <sgx_read_rand+0x117>
    16dd:	e8 f8 3b 00 00       	callq  52da <__stack_chk_fail>
    16e2:	c9                   	leaveq 
    16e3:	c3                   	retq   

00000000000016e4 <check_static_stack_canary>:
    return get_enclave_state() == ENCLAVE_CRASHED;
}

extern uintptr_t __stack_chk_guard;
int check_static_stack_canary(void *tcs)
{
    16e4:	55                   	push   %rbp
    16e5:	48 89 e5             	mov    %rsp,%rbp
    16e8:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    size_t *canary = TCS2CANARY(tcs);
    16ec:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    16f0:	48 2d a8 02 01 00    	sub    $0x102a8,%rax
    16f6:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if ( *canary != (size_t)__stack_chk_guard)
    16fa:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    16fe:	48 8b 10             	mov    (%rax),%rdx
    1701:	48 8d 05 f8 f6 00 00 	lea    0xf6f8(%rip),%rax        # 10e00 <__intel_security_cookie>
    1708:	48 8b 00             	mov    (%rax),%rax
    170b:	48 39 c2             	cmp    %rax,%rdx
    170e:	74 07                	je     1717 <check_static_stack_canary+0x33>
    {
        return -1;
    1710:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    1715:	eb 05                	jmp    171c <check_static_stack_canary+0x38>
    }
    return 0;
    1717:	b8 00 00 00 00       	mov    $0x0,%eax
}
    171c:	5d                   	pop    %rbp
    171d:	c3                   	retq   

000000000000171e <memcpy_s>:
#ifdef __cplusplus
    extern "C" {
#endif

static inline errno_t memcpy_s(void *dest, size_t numberOfElements, const void *src, size_t count)
{
    171e:	55                   	push   %rbp
    171f:	48 89 e5             	mov    %rsp,%rbp
    1722:	48 83 ec 20          	sub    $0x20,%rsp
    1726:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    172a:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    172e:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    1732:	48 89 4d e0          	mov    %rcx,-0x20(%rbp)
    if(numberOfElements<count)
    1736:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    173a:	48 3b 45 e0          	cmp    -0x20(%rbp),%rax
    173e:	73 07                	jae    1747 <memcpy_s+0x29>
        return -1;
    1740:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    1745:	eb 1c                	jmp    1763 <memcpy_s+0x45>
    memcpy(dest, src, count);
    1747:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    174b:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
    174f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1753:	48 89 ce             	mov    %rcx,%rsi
    1756:	48 89 c7             	mov    %rax,%rdi
    1759:	e8 d4 97 00 00       	callq  af32 <memcpy>
    return 0;
    175e:	b8 00 00 00 00       	mov    $0x0,%eax
}
    1763:	c9                   	leaveq 
    1764:	c3                   	retq   

0000000000001765 <_ZL19sgx_accept_backwardmmm>:
    uint16_t    attributes;
};

// Low level API to EACCEPT pages on grow-up region.
static int sgx_accept_backward(si_flags_t sfl, size_t lo, size_t hi)
{
    1765:	4c 8d 54 24 08       	lea    0x8(%rsp),%r10
    176a:	48 83 e4 c0          	and    $0xffffffffffffffc0,%rsp
    176e:	41 ff 72 f8          	pushq  -0x8(%r10)
    1772:	55                   	push   %rbp
    1773:	48 89 e5             	mov    %rsp,%rbp
    1776:	41 52                	push   %r10
    1778:	48 81 ec e8 00 00 00 	sub    $0xe8,%rsp
    177f:	48 89 bd 38 ff ff ff 	mov    %rdi,-0xc8(%rbp)
    1786:	48 89 b5 30 ff ff ff 	mov    %rsi,-0xd0(%rbp)
    178d:	48 89 95 28 ff ff ff 	mov    %rdx,-0xd8(%rbp)
    1794:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    179b:	00 00 
    179d:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    17a1:	31 c0                	xor    %eax,%eax
    size_t addr = hi;
    17a3:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    17aa:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    SE_DECLSPEC_ALIGN(sizeof(sec_info_t)) sec_info_t si;
    si.flags = sfl;
    17b1:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    17b8:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    for (uint16_t i = 0; i < (sizeof(si.reserved)/sizeof(si.reserved[0])); i++)
    17bf:	66 c7 85 42 ff ff ff 	movw   $0x0,-0xbe(%rbp)
    17c6:	00 00 
    17c8:	66 83 bd 42 ff ff ff 	cmpw   $0x6,-0xbe(%rbp)
    17cf:	06 
    17d0:	77 28                	ja     17fa <_ZL19sgx_accept_backwardmmm+0x95>
        si.reserved[i] = 0;
    17d2:	0f b7 85 42 ff ff ff 	movzwl -0xbe(%rbp),%eax
    17d9:	48 98                	cltq   
    17db:	48 c7 84 c5 58 ff ff 	movq   $0x0,-0xa8(%rbp,%rax,8)
    17e2:	ff 00 00 00 00 
    for (uint16_t i = 0; i < (sizeof(si.reserved)/sizeof(si.reserved[0])); i++)
    17e7:	0f b7 85 42 ff ff ff 	movzwl -0xbe(%rbp),%eax
    17ee:	83 c0 01             	add    $0x1,%eax
    17f1:	66 89 85 42 ff ff ff 	mov    %ax,-0xbe(%rbp)
    17f8:	eb ce                	jmp    17c8 <_ZL19sgx_accept_backwardmmm+0x63>

    while (lo < addr)
    17fa:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    1801:	48 3b 85 48 ff ff ff 	cmp    -0xb8(%rbp),%rax
    1808:	73 38                	jae    1842 <_ZL19sgx_accept_backwardmmm+0xdd>
    {
        int rc = do_eaccept(&si, addr -= SE_PAGE_SIZE);
    180a:	48 81 ad 48 ff ff ff 	subq   $0x1000,-0xb8(%rbp)
    1811:	00 10 00 00 
    1815:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    181c:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
    1823:	48 89 d6             	mov    %rdx,%rsi
    1826:	48 89 c7             	mov    %rax,%rdi
    1829:	e8 52 b1 00 00       	callq  c980 <do_eaccept>
    182e:	89 85 44 ff ff ff    	mov    %eax,-0xbc(%rbp)
        if (rc != 0)
    1834:	83 bd 44 ff ff ff 00 	cmpl   $0x0,-0xbc(%rbp)
    183b:	74 bd                	je     17fa <_ZL19sgx_accept_backwardmmm+0x95>
            abort();
    183d:	e8 8c b1 00 00       	callq  c9ce <abort>
    }
    return 0;
    1842:	b8 00 00 00 00       	mov    $0x0,%eax
}
    1847:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    184b:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    1852:	00 00 
    1854:	74 05                	je     185b <_ZL19sgx_accept_backwardmmm+0xf6>
    1856:	e8 7f 3a 00 00       	callq  52da <__stack_chk_fail>
    185b:	48 81 c4 e8 00 00 00 	add    $0xe8,%rsp
    1862:	41 5a                	pop    %r10
    1864:	5d                   	pop    %rbp
    1865:	49 8d 62 f8          	lea    -0x8(%r10),%rsp
    1869:	c3                   	retq   

000000000000186a <_ZL35sgx_accept_forward_within_exceptionmm>:

// Low level API to EACCEPT pages on grow-up region during exception handling.
static int sgx_accept_forward_within_exception(size_t lo, size_t hi)
{
    186a:	4c 8d 54 24 08       	lea    0x8(%rsp),%r10
    186f:	48 83 e4 c0          	and    $0xffffffffffffffc0,%rsp
    1873:	41 ff 72 f8          	pushq  -0x8(%r10)
    1877:	55                   	push   %rbp
    1878:	48 89 e5             	mov    %rsp,%rbp
    187b:	41 52                	push   %r10
    187d:	48 81 ec e8 00 00 00 	sub    $0xe8,%rsp
    1884:	48 89 bd 28 ff ff ff 	mov    %rdi,-0xd8(%rbp)
    188b:	48 89 b5 20 ff ff ff 	mov    %rsi,-0xe0(%rbp)
    1892:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    1899:	00 00 
    189b:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    189f:	31 c0                	xor    %eax,%eax
    size_t addr = lo;
    18a1:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    18a8:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    SE_DECLSPEC_ALIGN(sizeof(sec_info_t)) sec_info_t si;

#ifdef DEBUG
    unsigned int sp_value = 0;
    18af:	c7 85 40 ff ff ff 00 	movl   $0x0,-0xc0(%rbp)
    18b6:	00 00 00 
    asm("mov %%esp, %0;" : "=r" (sp_value) :);
    18b9:	89 e0                	mov    %esp,%eax
    18bb:	89 85 40 ff ff ff    	mov    %eax,-0xc0(%rbp)
    if ((sp_value & (SE_PAGE_SIZE -1)) <= (SE_PAGE_SIZE - (STATIC_STACK_SIZE % SE_PAGE_SIZE)))
    18c1:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    18c7:	25 ff 0f 00 00       	and    $0xfff,%eax
    18cc:	3d 50 0d 00 00       	cmp    $0xd50,%eax
    18d1:	77 0a                	ja     18dd <_ZL35sgx_accept_forward_within_exceptionmm+0x73>
        return SGX_ERROR_UNEXPECTED;
    18d3:	b8 01 00 00 00       	mov    $0x1,%eax
    18d8:	e9 95 00 00 00       	jmpq   1972 <_ZL35sgx_accept_forward_within_exceptionmm+0x108>
#endif

    si.flags = SI_FLAGS_RW | SI_FLAG_PENDING;
    18dd:	48 c7 85 50 ff ff ff 	movq   $0x20b,-0xb0(%rbp)
    18e4:	0b 02 00 00 
    for (uint16_t i = 0; i < (sizeof(si.reserved)/sizeof(si.reserved[0])); i++)
    18e8:	66 c7 85 3e ff ff ff 	movw   $0x0,-0xc2(%rbp)
    18ef:	00 00 
    18f1:	66 83 bd 3e ff ff ff 	cmpw   $0x6,-0xc2(%rbp)
    18f8:	06 
    18f9:	77 28                	ja     1923 <_ZL35sgx_accept_forward_within_exceptionmm+0xb9>
        si.reserved[i] = 0;
    18fb:	0f b7 85 3e ff ff ff 	movzwl -0xc2(%rbp),%eax
    1902:	48 98                	cltq   
    1904:	48 c7 84 c5 58 ff ff 	movq   $0x0,-0xa8(%rbp,%rax,8)
    190b:	ff 00 00 00 00 
    for (uint16_t i = 0; i < (sizeof(si.reserved)/sizeof(si.reserved[0])); i++)
    1910:	0f b7 85 3e ff ff ff 	movzwl -0xc2(%rbp),%eax
    1917:	83 c0 01             	add    $0x1,%eax
    191a:	66 89 85 3e ff ff ff 	mov    %ax,-0xc2(%rbp)
    1921:	eb ce                	jmp    18f1 <_ZL35sgx_accept_forward_within_exceptionmm+0x87>

    while (addr < hi)
    1923:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    192a:	48 3b 85 20 ff ff ff 	cmp    -0xe0(%rbp),%rax
    1931:	73 3a                	jae    196d <_ZL35sgx_accept_forward_within_exceptionmm+0x103>
    {
        int rc = do_eaccept(&si, addr);
    1933:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    193a:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
    1941:	48 89 d6             	mov    %rdx,%rsi
    1944:	48 89 c7             	mov    %rax,%rdi
    1947:	e8 34 b0 00 00       	callq  c980 <do_eaccept>
    194c:	89 85 44 ff ff ff    	mov    %eax,-0xbc(%rbp)
        if (rc != 0)
    1952:	83 bd 44 ff ff ff 00 	cmpl   $0x0,-0xbc(%rbp)
    1959:	74 05                	je     1960 <_ZL35sgx_accept_forward_within_exceptionmm+0xf6>
            abort();
    195b:	e8 6e b0 00 00       	callq  c9ce <abort>
        addr += SE_PAGE_SIZE;
    1960:	48 81 85 48 ff ff ff 	addq   $0x1000,-0xb8(%rbp)
    1967:	00 10 00 00 
    while (addr < hi)
    196b:	eb b6                	jmp    1923 <_ZL35sgx_accept_forward_within_exceptionmm+0xb9>
    }

    return 0;
    196d:	b8 00 00 00 00       	mov    $0x0,%eax
}
    1972:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    1976:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    197d:	00 00 
    197f:	74 05                	je     1986 <_ZL35sgx_accept_forward_within_exceptionmm+0x11c>
    1981:	e8 54 39 00 00       	callq  52da <__stack_chk_fail>
    1986:	48 81 c4 e8 00 00 00 	add    $0xe8,%rsp
    198d:	41 5a                	pop    %r10
    198f:	5d                   	pop    %rbp
    1990:	49 8d 62 f8          	lea    -0x8(%r10),%rsp
    1994:	c3                   	retq   

0000000000001995 <_Z24get_dynamic_layout_by_idt>:

const volatile layout_t *get_dynamic_layout_by_id(uint16_t id)
{
    1995:	55                   	push   %rbp
    1996:	48 89 e5             	mov    %rsp,%rbp
    1999:	89 f8                	mov    %edi,%eax
    199b:	66 89 45 ec          	mov    %ax,-0x14(%rbp)
    for(uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    199f:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    19a6:	48 8d 05 d3 b7 00 00 	lea    0xb7d3(%rip),%rax        # d180 <g_global_data>
    19ad:	8b 80 28 01 00 00    	mov    0x128(%rax),%eax
    19b3:	39 45 fc             	cmp    %eax,-0x4(%rbp)
    19b6:	0f 92 c0             	setb   %al
    19b9:	84 c0                	test   %al,%al
    19bb:	74 45                	je     1a02 <_Z24get_dynamic_layout_by_idt+0x6d>
    {
        if(g_global_data.layout_table[i].entry.id == id)
    19bd:	48 8d 05 bc b7 00 00 	lea    0xb7bc(%rip),%rax        # d180 <g_global_data>
    19c4:	8b 55 fc             	mov    -0x4(%rbp),%edx
    19c7:	48 c1 e2 05          	shl    $0x5,%rdx
    19cb:	48 01 d0             	add    %rdx,%rax
    19ce:	48 05 30 01 00 00    	add    $0x130,%rax
    19d4:	0f b7 00             	movzwl (%rax),%eax
    19d7:	66 39 45 ec          	cmp    %ax,-0x14(%rbp)
    19db:	0f 94 c0             	sete   %al
    19de:	84 c0                	test   %al,%al
    19e0:	74 1a                	je     19fc <_Z24get_dynamic_layout_by_idt+0x67>
        {
            return &(g_global_data.layout_table[i]);
    19e2:	8b 45 fc             	mov    -0x4(%rbp),%eax
    19e5:	48 c1 e0 05          	shl    $0x5,%rax
    19e9:	48 8d 90 30 01 00 00 	lea    0x130(%rax),%rdx
    19f0:	48 8d 05 89 b7 00 00 	lea    0xb789(%rip),%rax        # d180 <g_global_data>
    19f7:	48 01 d0             	add    %rdx,%rax
    19fa:	eb 0b                	jmp    1a07 <_Z24get_dynamic_layout_by_idt+0x72>
    for(uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    19fc:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    1a00:	eb a4                	jmp    19a6 <_Z24get_dynamic_layout_by_idt+0x11>
        }
    }
    return NULL;
    1a02:	b8 00 00 00 00       	mov    $0x0,%eax
}
    1a07:	5d                   	pop    %rbp
    1a08:	c3                   	retq   

0000000000001a09 <_Z18accept_post_removePVK9_layout_tS1_m>:

// EACCEPT trim requests when the enclave completes initialization.
int accept_post_remove(const volatile layout_t *layout_start, const volatile layout_t *layout_end, size_t offset)
{
    1a09:	55                   	push   %rbp
    1a0a:	48 89 e5             	mov    %rsp,%rbp
    1a0d:	53                   	push   %rbx
    1a0e:	48 83 ec 58          	sub    $0x58,%rsp
    1a12:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    1a16:	48 89 75 b0          	mov    %rsi,-0x50(%rbp)
    1a1a:	48 89 55 a8          	mov    %rdx,-0x58(%rbp)
    int ret = -1;
    1a1e:	c7 45 d0 ff ff ff ff 	movl   $0xffffffff,-0x30(%rbp)
    for (const volatile layout_t *layout = layout_start; layout < layout_end; layout++)
    1a25:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    1a29:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    1a2d:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1a31:	48 3b 45 b0          	cmp    -0x50(%rbp),%rax
    1a35:	0f 83 2f 01 00 00    	jae    1b6a <_Z18accept_post_removePVK9_layout_tS1_m+0x161>
    {
        if (!IS_GROUP_ID(layout->group.id) && (layout->entry.attributes & PAGE_ATTR_POST_REMOVE))
    1a3b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1a3f:	0f b7 00             	movzwl (%rax),%eax
    1a42:	0f b7 c0             	movzwl %ax,%eax
    1a45:	25 00 10 00 00       	and    $0x1000,%eax
    1a4a:	85 c0                	test   %eax,%eax
    1a4c:	75 19                	jne    1a67 <_Z18accept_post_removePVK9_layout_tS1_m+0x5e>
    1a4e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1a52:	0f b7 40 02          	movzwl 0x2(%rax),%eax
    1a56:	0f b7 c0             	movzwl %ax,%eax
    1a59:	83 e0 10             	and    $0x10,%eax
    1a5c:	85 c0                	test   %eax,%eax
    1a5e:	74 07                	je     1a67 <_Z18accept_post_removePVK9_layout_tS1_m+0x5e>
    1a60:	b8 01 00 00 00       	mov    $0x1,%eax
    1a65:	eb 05                	jmp    1a6c <_Z18accept_post_removePVK9_layout_tS1_m+0x63>
    1a67:	b8 00 00 00 00       	mov    $0x0,%eax
    1a6c:	84 c0                	test   %al,%al
    1a6e:	74 62                	je     1ad2 <_Z18accept_post_removePVK9_layout_tS1_m+0xc9>
        {
            size_t start_addr = (size_t)layout->entry.rva + offset + (size_t)get_enclave_base();
    1a70:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1a74:	48 8b 50 08          	mov    0x8(%rax),%rdx
    1a78:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    1a7c:	48 8d 1c 02          	lea    (%rdx,%rax,1),%rbx
    1a80:	e8 df ab 00 00       	callq  c664 <get_enclave_base>
    1a85:	48 01 d8             	add    %rbx,%rax
    1a88:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
            uint32_t page_count = layout->entry.page_count;
    1a8c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1a90:	8b 40 04             	mov    0x4(%rax),%eax
    1a93:	89 45 d4             	mov    %eax,-0x2c(%rbp)

            if (0 != (ret = sgx_accept_forward(SI_FLAG_TRIM | SI_FLAG_MODIFIED, start_addr, start_addr + ((size_t)page_count << SE_PAGE_SHIFT))))
    1a96:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    1a99:	48 c1 e0 0c          	shl    $0xc,%rax
    1a9d:	48 89 c2             	mov    %rax,%rdx
    1aa0:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1aa4:	48 01 c2             	add    %rax,%rdx
    1aa7:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1aab:	48 89 c6             	mov    %rax,%rsi
    1aae:	bf 10 04 00 00       	mov    $0x410,%edi
    1ab3:	e8 ef 05 00 00       	callq  20a7 <sgx_accept_forward>
    1ab8:	89 45 d0             	mov    %eax,-0x30(%rbp)
    1abb:	83 7d d0 00          	cmpl   $0x0,-0x30(%rbp)
    1abf:	0f 95 c0             	setne  %al
    1ac2:	84 c0                	test   %al,%al
    1ac4:	0f 84 96 00 00 00    	je     1b60 <_Z18accept_post_removePVK9_layout_tS1_m+0x157>
                return ret;
    1aca:	8b 45 d0             	mov    -0x30(%rbp),%eax
    1acd:	e9 9d 00 00 00       	jmpq   1b6f <_Z18accept_post_removePVK9_layout_tS1_m+0x166>
        }
        else if (IS_GROUP_ID(layout->group.id))
    1ad2:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1ad6:	0f b7 00             	movzwl (%rax),%eax
    1ad9:	0f b7 c0             	movzwl %ax,%eax
    1adc:	25 00 10 00 00       	and    $0x1000,%eax
    1ae1:	85 c0                	test   %eax,%eax
    1ae3:	0f 95 c0             	setne  %al
    1ae6:	84 c0                	test   %al,%al
    1ae8:	74 76                	je     1b60 <_Z18accept_post_removePVK9_layout_tS1_m+0x157>
        {
            size_t step = 0;
    1aea:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    1af1:	00 
            for(uint32_t j = 0; j < layout->group.load_times; j++)
    1af2:	c7 45 cc 00 00 00 00 	movl   $0x0,-0x34(%rbp)
    1af9:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1afd:	8b 40 04             	mov    0x4(%rax),%eax
    1b00:	39 45 cc             	cmp    %eax,-0x34(%rbp)
    1b03:	0f 92 c0             	setb   %al
    1b06:	84 c0                	test   %al,%al
    1b08:	74 56                	je     1b60 <_Z18accept_post_removePVK9_layout_tS1_m+0x157>
            {
                step += (size_t)layout->group.load_step;
    1b0a:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1b0e:	48 8b 40 08          	mov    0x8(%rax),%rax
    1b12:	48 01 45 e0          	add    %rax,-0x20(%rbp)
                if(0 != (ret = accept_post_remove(&layout[-layout->group.entry_count], layout, step)))
    1b16:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1b1a:	0f b7 40 02          	movzwl 0x2(%rax),%eax
    1b1e:	0f b7 c0             	movzwl %ax,%eax
    1b21:	f7 d8                	neg    %eax
    1b23:	48 98                	cltq   
    1b25:	48 c1 e0 05          	shl    $0x5,%rax
    1b29:	48 89 c2             	mov    %rax,%rdx
    1b2c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1b30:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
    1b34:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    1b38:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1b3c:	48 89 c6             	mov    %rax,%rsi
    1b3f:	48 89 cf             	mov    %rcx,%rdi
    1b42:	e8 c2 fe ff ff       	callq  1a09 <_Z18accept_post_removePVK9_layout_tS1_m>
    1b47:	89 45 d0             	mov    %eax,-0x30(%rbp)
    1b4a:	83 7d d0 00          	cmpl   $0x0,-0x30(%rbp)
    1b4e:	0f 95 c0             	setne  %al
    1b51:	84 c0                	test   %al,%al
    1b53:	74 05                	je     1b5a <_Z18accept_post_removePVK9_layout_tS1_m+0x151>
                    return ret;
    1b55:	8b 45 d0             	mov    -0x30(%rbp),%eax
    1b58:	eb 15                	jmp    1b6f <_Z18accept_post_removePVK9_layout_tS1_m+0x166>
            for(uint32_t j = 0; j < layout->group.load_times; j++)
    1b5a:	83 45 cc 01          	addl   $0x1,-0x34(%rbp)
    1b5e:	eb 99                	jmp    1af9 <_Z18accept_post_removePVK9_layout_tS1_m+0xf0>
    for (const volatile layout_t *layout = layout_start; layout < layout_end; layout++)
    1b60:	48 83 45 d8 20       	addq   $0x20,-0x28(%rbp)
    1b65:	e9 c3 fe ff ff       	jmpq   1a2d <_Z18accept_post_removePVK9_layout_tS1_m+0x24>
            }
        }
    }
    return 0;
    1b6a:	b8 00 00 00 00       	mov    $0x0,%eax
}
    1b6f:	48 83 c4 58          	add    $0x58,%rsp
    1b73:	5b                   	pop    %rbx
    1b74:	5d                   	pop    %rbp
    1b75:	c3                   	retq   

0000000000001b76 <_ZL20check_heap_dyn_rangePvmP24dynamic_flags_attributes>:

static int check_heap_dyn_range(void *addr, size_t page_count, struct dynamic_flags_attributes *fa)
{
    1b76:	55                   	push   %rbp
    1b77:	48 89 e5             	mov    %rsp,%rbp
    1b7a:	53                   	push   %rbx
    1b7b:	48 83 ec 38          	sub    $0x38,%rsp
    1b7f:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    1b83:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    1b87:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
    size_t heap_dyn_start, heap_dyn_size;

    heap_dyn_start = (size_t)get_heap_base() + get_heap_min_size();
    1b8b:	e8 6a 1d 00 00       	callq  38fa <get_heap_base>
    1b90:	48 89 c3             	mov    %rax,%rbx
    1b93:	e8 0f 1e 00 00       	callq  39a7 <get_heap_min_size>
    1b98:	48 01 d8             	add    %rbx,%rax
    1b9b:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    heap_dyn_size = get_heap_size() - get_heap_min_size();
    1b9f:	e8 71 1d 00 00       	callq  3915 <get_heap_size>
    1ba4:	48 89 c3             	mov    %rax,%rbx
    1ba7:	e8 fb 1d 00 00       	callq  39a7 <get_heap_min_size>
    1bac:	48 29 c3             	sub    %rax,%rbx
    1baf:	48 89 d8             	mov    %rbx,%rax
    1bb2:	48 89 45 e8          	mov    %rax,-0x18(%rbp)

    if ((size_t)addr >= heap_dyn_start
    1bb6:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1bba:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    1bbe:	77 46                	ja     1c06 <_ZL20check_heap_dyn_rangePvmP24dynamic_flags_attributes+0x90>
            && (size_t)addr + (page_count << SE_PAGE_SHIFT) <= heap_dyn_start + heap_dyn_size)
    1bc0:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    1bc4:	48 c1 e0 0c          	shl    $0xc,%rax
    1bc8:	48 89 c2             	mov    %rax,%rdx
    1bcb:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1bcf:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
    1bd3:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    1bd7:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1bdb:	48 01 d0             	add    %rdx,%rax
    1bde:	48 39 c1             	cmp    %rax,%rcx
    1be1:	77 23                	ja     1c06 <_ZL20check_heap_dyn_rangePvmP24dynamic_flags_attributes+0x90>
    {
        if (fa != NULL)
    1be3:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    1be8:	74 15                	je     1bff <_ZL20check_heap_dyn_rangePvmP24dynamic_flags_attributes+0x89>
        {
            fa->si_flags = SI_FLAGS_RW;
    1bea:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    1bee:	48 c7 00 03 02 00 00 	movq   $0x203,(%rax)
            fa->attributes = PAGE_ATTR_POST_ADD;
    1bf5:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    1bf9:	66 c7 40 08 08 00    	movw   $0x8,0x8(%rax)
        }
        return 0;
    1bff:	b8 00 00 00 00       	mov    $0x0,%eax
    1c04:	eb 05                	jmp    1c0b <_ZL20check_heap_dyn_rangePvmP24dynamic_flags_attributes+0x95>
    }
    else
    {
        return -1;
    1c06:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    }
}
    1c0b:	48 83 c4 38          	add    $0x38,%rsp
    1c0f:	5b                   	pop    %rbx
    1c10:	5d                   	pop    %rbp
    1c11:	c3                   	retq   

0000000000001c12 <_ZL20check_rsrv_dyn_rangePvmP24dynamic_flags_attributes>:
extern void *rsrv_mem_base;
extern size_t rsrv_mem_size;
extern size_t rsrv_mem_min_size;

static int check_rsrv_dyn_range(void *addr, size_t page_count, struct dynamic_flags_attributes *fa)
{
    1c12:	55                   	push   %rbp
    1c13:	48 89 e5             	mov    %rsp,%rbp
    1c16:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    1c1a:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    1c1e:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    size_t rsrv_mem_dyn_start, rsrv_mem_dyn_size;

    rsrv_mem_dyn_start = (size_t)rsrv_mem_base + rsrv_mem_min_size;
    1c22:	48 8d 05 ff f1 00 00 	lea    0xf1ff(%rip),%rax        # 10e28 <rsrv_mem_base>
    1c29:	48 8b 00             	mov    (%rax),%rax
    1c2c:	48 89 c2             	mov    %rax,%rdx
    1c2f:	48 8d 05 02 f2 00 00 	lea    0xf202(%rip),%rax        # 10e38 <rsrv_mem_min_size>
    1c36:	48 8b 00             	mov    (%rax),%rax
    1c39:	48 01 d0             	add    %rdx,%rax
    1c3c:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    rsrv_mem_dyn_size = rsrv_mem_size - rsrv_mem_min_size;
    1c40:	48 8d 05 e9 f1 00 00 	lea    0xf1e9(%rip),%rax        # 10e30 <rsrv_mem_size>
    1c47:	48 8b 10             	mov    (%rax),%rdx
    1c4a:	48 8d 05 e7 f1 00 00 	lea    0xf1e7(%rip),%rax        # 10e38 <rsrv_mem_min_size>
    1c51:	48 8b 00             	mov    (%rax),%rax
    1c54:	48 29 c2             	sub    %rax,%rdx
    1c57:	48 89 d0             	mov    %rdx,%rax
    1c5a:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

    if ((size_t)addr >= rsrv_mem_dyn_start
    1c5e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1c62:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    1c66:	77 46                	ja     1cae <_ZL20check_rsrv_dyn_rangePvmP24dynamic_flags_attributes+0x9c>
            && (size_t)addr + (page_count << SE_PAGE_SHIFT) <= rsrv_mem_dyn_start + rsrv_mem_dyn_size)
    1c68:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1c6c:	48 c1 e0 0c          	shl    $0xc,%rax
    1c70:	48 89 c2             	mov    %rax,%rdx
    1c73:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1c77:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
    1c7b:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    1c7f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1c83:	48 01 d0             	add    %rdx,%rax
    1c86:	48 39 c1             	cmp    %rax,%rcx
    1c89:	77 23                	ja     1cae <_ZL20check_rsrv_dyn_rangePvmP24dynamic_flags_attributes+0x9c>
    {
        if (fa != NULL)
    1c8b:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    1c90:	74 15                	je     1ca7 <_ZL20check_rsrv_dyn_rangePvmP24dynamic_flags_attributes+0x95>
        {
            fa->si_flags = SI_FLAGS_RW;
    1c92:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1c96:	48 c7 00 03 02 00 00 	movq   $0x203,(%rax)
            fa->attributes = PAGE_ATTR_POST_ADD;
    1c9d:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1ca1:	66 c7 40 08 08 00    	movw   $0x8,0x8(%rax)
        }
        return 0;
    1ca7:	b8 00 00 00 00       	mov    $0x0,%eax
    1cac:	eb 05                	jmp    1cb3 <_ZL20check_rsrv_dyn_rangePvmP24dynamic_flags_attributes+0xa1>
    }
    else
    {
        return -1;
    1cae:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    }
}
    1cb3:	5d                   	pop    %rbp
    1cb4:	c3                   	retq   

0000000000001cb5 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes>:


static int check_dynamic_entry_range(void *addr, size_t page_count, uint16_t entry_id, size_t entry_offset, struct dynamic_flags_attributes *fa)
{
    1cb5:	55                   	push   %rbp
    1cb6:	48 89 e5             	mov    %rsp,%rbp
    1cb9:	48 83 ec 50          	sub    $0x50,%rsp
    1cbd:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    1cc1:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    1cc5:	89 d0                	mov    %edx,%eax
    1cc7:	48 89 4d c0          	mov    %rcx,-0x40(%rbp)
    1ccb:	4c 89 45 b8          	mov    %r8,-0x48(%rbp)
    1ccf:	66 89 45 cc          	mov    %ax,-0x34(%rbp)
    const volatile layout_t *layout = NULL;
    1cd3:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
    1cda:	00 
    size_t entry_start_addr;
    uint32_t entry_page_count;

    if (entry_id < LAYOUT_ID_HEAP_MIN
            || entry_id > LAYOUT_ID_STACK_DYN_MIN
            || (NULL == (layout = get_dynamic_layout_by_id(entry_id))))
    1cdb:	66 83 7d cc 00       	cmpw   $0x0,-0x34(%rbp)
    1ce0:	74 1d                	je     1cff <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0x4a>
            || entry_id > LAYOUT_ID_STACK_DYN_MIN
    1ce2:	66 83 7d cc 12       	cmpw   $0x12,-0x34(%rbp)
    1ce7:	77 16                	ja     1cff <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0x4a>
            || (NULL == (layout = get_dynamic_layout_by_id(entry_id))))
    1ce9:	0f b7 45 cc          	movzwl -0x34(%rbp),%eax
    1ced:	89 c7                	mov    %eax,%edi
    1cef:	e8 a1 fc ff ff       	callq  1995 <_Z24get_dynamic_layout_by_idt>
    1cf4:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    1cf8:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    1cfd:	75 07                	jne    1d06 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0x51>
    1cff:	b8 01 00 00 00       	mov    $0x1,%eax
    1d04:	eb 05                	jmp    1d0b <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0x56>
    1d06:	b8 00 00 00 00       	mov    $0x0,%eax
    if (entry_id < LAYOUT_ID_HEAP_MIN
    1d0b:	84 c0                	test   %al,%al
    1d0d:	74 0a                	je     1d19 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0x64>
    {
        return -1;
    1d0f:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    1d14:	e9 8c 00 00 00       	jmpq   1da5 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0xf0>
    }

    entry_start_addr = (size_t)get_enclave_base() + (size_t)layout->entry.rva + entry_offset;
    1d19:	e8 46 a9 00 00       	callq  c664 <get_enclave_base>
    1d1e:	48 89 c2             	mov    %rax,%rdx
    1d21:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1d25:	48 8b 40 08          	mov    0x8(%rax),%rax
    1d29:	48 01 c2             	add    %rax,%rdx
    1d2c:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    1d30:	48 01 d0             	add    %rdx,%rax
    1d33:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    entry_page_count = layout->entry.page_count;
    1d37:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1d3b:	8b 40 04             	mov    0x4(%rax),%eax
    1d3e:	89 45 ec             	mov    %eax,-0x14(%rbp)
    if ((size_t)addr >= entry_start_addr
    1d41:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1d45:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    1d49:	77 55                	ja     1da0 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0xeb>
            && (size_t)addr + (page_count << SE_PAGE_SHIFT) <= entry_start_addr + ((size_t)entry_page_count << SE_PAGE_SHIFT))
    1d4b:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    1d4f:	48 c1 e0 0c          	shl    $0xc,%rax
    1d53:	48 89 c2             	mov    %rax,%rdx
    1d56:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1d5a:	48 01 c2             	add    %rax,%rdx
    1d5d:	8b 45 ec             	mov    -0x14(%rbp),%eax
    1d60:	48 c1 e0 0c          	shl    $0xc,%rax
    1d64:	48 89 c1             	mov    %rax,%rcx
    1d67:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1d6b:	48 01 c8             	add    %rcx,%rax
    1d6e:	48 39 c2             	cmp    %rax,%rdx
    1d71:	77 2d                	ja     1da0 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0xeb>
    {
        if (fa != NULL)
    1d73:	48 83 7d b8 00       	cmpq   $0x0,-0x48(%rbp)
    1d78:	74 1f                	je     1d99 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0xe4>
        {
            fa->si_flags = layout->entry.si_flags;
    1d7a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1d7e:	48 8b 50 18          	mov    0x18(%rax),%rdx
    1d82:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    1d86:	48 89 10             	mov    %rdx,(%rax)
            fa->attributes = layout->entry.attributes;
    1d89:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1d8d:	0f b7 50 02          	movzwl 0x2(%rax),%edx
    1d91:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    1d95:	66 89 50 08          	mov    %dx,0x8(%rax)
        }
        return 0;
    1d99:	b8 00 00 00 00       	mov    $0x0,%eax
    1d9e:	eb 05                	jmp    1da5 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes+0xf0>
    }
    else
    {
        return -1;
    1da0:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    }
}
    1da5:	c9                   	leaveq 
    1da6:	c3                   	retq   

0000000000001da7 <_ZL34check_utility_thread_dynamic_stackPvmP24dynamic_flags_attributes>:

static int check_utility_thread_dynamic_stack(void *addr, size_t page_count, struct dynamic_flags_attributes *fa)
{
    1da7:	55                   	push   %rbp
    1da8:	48 89 e5             	mov    %rsp,%rbp
    1dab:	48 83 ec 20          	sub    $0x20,%rsp
    1daf:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    1db3:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    1db7:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    return check_dynamic_entry_range(addr, page_count, LAYOUT_ID_STACK_MAX, 0, fa);
    1dbb:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    1dbf:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi
    1dc3:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1dc7:	49 89 d0             	mov    %rdx,%r8
    1dca:	b9 00 00 00 00       	mov    $0x0,%ecx
    1dcf:	ba 07 00 00 00       	mov    $0x7,%edx
    1dd4:	48 89 c7             	mov    %rax,%rdi
    1dd7:	e8 d9 fe ff ff       	callq  1cb5 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes>
}
    1ddc:	c9                   	leaveq 
    1ddd:	c3                   	retq   

0000000000001dde <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes>:

// Verify if the range specified belongs to a dynamic range recorded in metadata.
static int check_dynamic_range(void *addr, size_t page_count, size_t *offset, struct dynamic_flags_attributes *fa)
{
    1dde:	55                   	push   %rbp
    1ddf:	48 89 e5             	mov    %rsp,%rbp
    1de2:	48 83 ec 30          	sub    $0x30,%rsp
    1de6:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    1dea:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    1dee:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    1df2:	48 89 4d d0          	mov    %rcx,-0x30(%rbp)
    const volatile layout_t *dt_layout = NULL;
    1df6:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    1dfd:	00 

    // check for integer overflow
    if ((size_t)addr > SIZE_MAX - (page_count << SE_PAGE_SHIFT))
    1dfe:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1e02:	48 c1 e0 0c          	shl    $0xc,%rax
    1e06:	48 f7 d0             	not    %rax
    1e09:	48 89 c2             	mov    %rax,%rdx
    1e0c:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1e10:	48 39 c2             	cmp    %rax,%rdx
    1e13:	73 0a                	jae    1e1f <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x41>
        return -1;
    1e15:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    1e1a:	e9 99 01 00 00       	jmpq   1fb8 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1da>

    // check heap dynamic range
    if (0 == check_heap_dyn_range(addr, page_count, fa))
    1e1f:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    1e23:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    1e27:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1e2b:	48 89 ce             	mov    %rcx,%rsi
    1e2e:	48 89 c7             	mov    %rax,%rdi
    1e31:	e8 40 fd ff ff       	callq  1b76 <_ZL20check_heap_dyn_rangePvmP24dynamic_flags_attributes>
    1e36:	85 c0                	test   %eax,%eax
    1e38:	0f 94 c0             	sete   %al
    1e3b:	84 c0                	test   %al,%al
    1e3d:	74 0a                	je     1e49 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x6b>
        return 0;
    1e3f:	b8 00 00 00 00       	mov    $0x0,%eax
    1e44:	e9 6f 01 00 00       	jmpq   1fb8 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1da>

    // check dynamic stack within utility thread
    if (0 == check_utility_thread_dynamic_stack(addr, page_count, fa))
    1e49:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    1e4d:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    1e51:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1e55:	48 89 ce             	mov    %rcx,%rsi
    1e58:	48 89 c7             	mov    %rax,%rdi
    1e5b:	e8 47 ff ff ff       	callq  1da7 <_ZL34check_utility_thread_dynamic_stackPvmP24dynamic_flags_attributes>
    1e60:	85 c0                	test   %eax,%eax
    1e62:	0f 94 c0             	sete   %al
    1e65:	84 c0                	test   %al,%al
    1e67:	74 0a                	je     1e73 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x95>
        return 0;
    1e69:	b8 00 00 00 00       	mov    $0x0,%eax
    1e6e:	e9 45 01 00 00       	jmpq   1fb8 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1da>

    if (0 == check_rsrv_dyn_range(addr, page_count, fa))
    1e73:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    1e77:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    1e7b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1e7f:	48 89 ce             	mov    %rcx,%rsi
    1e82:	48 89 c7             	mov    %rax,%rdi
    1e85:	e8 88 fd ff ff       	callq  1c12 <_ZL20check_rsrv_dyn_rangePvmP24dynamic_flags_attributes>
    1e8a:	85 c0                	test   %eax,%eax
    1e8c:	0f 94 c0             	sete   %al
    1e8f:	84 c0                	test   %al,%al
    1e91:	74 0a                	je     1e9d <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0xbf>
        return 0;
    1e93:	b8 00 00 00 00       	mov    $0x0,%eax
    1e98:	e9 1b 01 00 00       	jmpq   1fb8 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1da>

    // check dynamic thread entries range
    if (NULL != (dt_layout = get_dynamic_layout_by_id(LAYOUT_ID_THREAD_GROUP_DYN)))
    1e9d:	bf 13 10 00 00       	mov    $0x1013,%edi
    1ea2:	e8 ee fa ff ff       	callq  1995 <_Z24get_dynamic_layout_by_idt>
    1ea7:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1eab:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    1eb0:	0f 95 c0             	setne  %al
    1eb3:	84 c0                	test   %al,%al
    1eb5:	0f 84 9c 00 00 00    	je     1f57 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x179>
    {
        for (uint16_t id = LAYOUT_ID_TCS_DYN; id <= LAYOUT_ID_STACK_DYN_MIN; id++)
    1ebb:	66 c7 45 f0 0e 00    	movw   $0xe,-0x10(%rbp)
    1ec1:	66 83 7d f0 12       	cmpw   $0x12,-0x10(%rbp)
    1ec6:	0f 87 e7 00 00 00    	ja     1fb3 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1d5>
            for (uint32_t i = 0; i < dt_layout->group.load_times + 1; i++)
    1ecc:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    1ed3:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1ed7:	8b 40 04             	mov    0x4(%rax),%eax
    1eda:	83 c0 01             	add    $0x1,%eax
    1edd:	39 45 f4             	cmp    %eax,-0xc(%rbp)
    1ee0:	0f 92 c0             	setb   %al
    1ee3:	84 c0                	test   %al,%al
    1ee5:	74 60                	je     1f47 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x169>
            {
                if (0 == check_dynamic_entry_range(addr, page_count, id, i * ((size_t)dt_layout->group.load_step), fa))
    1ee7:	8b 55 f4             	mov    -0xc(%rbp),%edx
    1eea:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1eee:	48 8b 40 08          	mov    0x8(%rax),%rax
    1ef2:	48 89 d1             	mov    %rdx,%rcx
    1ef5:	48 0f af c8          	imul   %rax,%rcx
    1ef9:	0f b7 55 f0          	movzwl -0x10(%rbp),%edx
    1efd:	48 8b 7d d0          	mov    -0x30(%rbp),%rdi
    1f01:	48 8b 75 e0          	mov    -0x20(%rbp),%rsi
    1f05:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1f09:	49 89 f8             	mov    %rdi,%r8
    1f0c:	48 89 c7             	mov    %rax,%rdi
    1f0f:	e8 a1 fd ff ff       	callq  1cb5 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes>
    1f14:	85 c0                	test   %eax,%eax
    1f16:	0f 94 c0             	sete   %al
    1f19:	84 c0                	test   %al,%al
    1f1b:	74 24                	je     1f41 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x163>
                {
                    if (offset != NULL) *offset = i * ((size_t)dt_layout->group.load_step);
    1f1d:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    1f22:	74 16                	je     1f3a <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x15c>
    1f24:	8b 55 f4             	mov    -0xc(%rbp),%edx
    1f27:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1f2b:	48 8b 40 08          	mov    0x8(%rax),%rax
    1f2f:	48 0f af d0          	imul   %rax,%rdx
    1f33:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1f37:	48 89 10             	mov    %rdx,(%rax)
                    return 0;
    1f3a:	b8 00 00 00 00       	mov    $0x0,%eax
    1f3f:	eb 77                	jmp    1fb8 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1da>
            for (uint32_t i = 0; i < dt_layout->group.load_times + 1; i++)
    1f41:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    1f45:	eb 8c                	jmp    1ed3 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0xf5>
        for (uint16_t id = LAYOUT_ID_TCS_DYN; id <= LAYOUT_ID_STACK_DYN_MIN; id++)
    1f47:	0f b7 45 f0          	movzwl -0x10(%rbp),%eax
    1f4b:	83 c0 01             	add    $0x1,%eax
    1f4e:	66 89 45 f0          	mov    %ax,-0x10(%rbp)
    1f52:	e9 6a ff ff ff       	jmpq   1ec1 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0xe3>
            }
    }
    else
    {
        // LAYOUT_ID_THREAD_GROUP_DYN does not exist, but possibly there is one single dynamic thead
        for (uint16_t id = LAYOUT_ID_TCS_DYN; id <= LAYOUT_ID_STACK_DYN_MIN; id++)
    1f57:	66 c7 45 f2 0e 00    	movw   $0xe,-0xe(%rbp)
    1f5d:	66 83 7d f2 12       	cmpw   $0x12,-0xe(%rbp)
    1f62:	77 4f                	ja     1fb3 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1d5>
            if (0 == check_dynamic_entry_range(addr, page_count, id, 0, fa))
    1f64:	0f b7 55 f2          	movzwl -0xe(%rbp),%edx
    1f68:	48 8b 4d d0          	mov    -0x30(%rbp),%rcx
    1f6c:	48 8b 75 e0          	mov    -0x20(%rbp),%rsi
    1f70:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    1f74:	49 89 c8             	mov    %rcx,%r8
    1f77:	b9 00 00 00 00       	mov    $0x0,%ecx
    1f7c:	48 89 c7             	mov    %rax,%rdi
    1f7f:	e8 31 fd ff ff       	callq  1cb5 <_ZL25check_dynamic_entry_rangePvmtmP24dynamic_flags_attributes>
    1f84:	85 c0                	test   %eax,%eax
    1f86:	0f 94 c0             	sete   %al
    1f89:	84 c0                	test   %al,%al
    1f8b:	74 19                	je     1fa6 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1c8>
            {
                if (offset != NULL) *offset = 0;
    1f8d:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    1f92:	74 0b                	je     1f9f <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1c1>
    1f94:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1f98:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
                return 0;
    1f9f:	b8 00 00 00 00       	mov    $0x0,%eax
    1fa4:	eb 12                	jmp    1fb8 <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x1da>
        for (uint16_t id = LAYOUT_ID_TCS_DYN; id <= LAYOUT_ID_STACK_DYN_MIN; id++)
    1fa6:	0f b7 45 f2          	movzwl -0xe(%rbp),%eax
    1faa:	83 c0 01             	add    $0x1,%eax
    1fad:	66 89 45 f2          	mov    %ax,-0xe(%rbp)
    1fb1:	eb aa                	jmp    1f5d <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes+0x17f>
            }
    }
    return -1;
    1fb3:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
}
    1fb8:	c9                   	leaveq 
    1fb9:	c3                   	retq   

0000000000001fba <is_dynamic_thread>:

int is_dynamic_thread(void *tcs)
{
    1fba:	55                   	push   %rbp
    1fbb:	48 89 e5             	mov    %rsp,%rbp
    1fbe:	48 83 ec 30          	sub    $0x30,%rsp
    1fc2:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    1fc6:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    1fcd:	00 00 
    1fcf:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1fd3:	31 c0                	xor    %eax,%eax
    struct dynamic_flags_attributes fa;

    if ((tcs != NULL) && (check_dynamic_range(tcs, 1, NULL, &fa) == 0) &&
    1fd5:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    1fda:	74 34                	je     2010 <is_dynamic_thread+0x56>
    1fdc:	48 8d 55 e0          	lea    -0x20(%rbp),%rdx
    1fe0:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1fe4:	48 89 d1             	mov    %rdx,%rcx
    1fe7:	ba 00 00 00 00       	mov    $0x0,%edx
    1fec:	be 01 00 00 00       	mov    $0x1,%esi
    1ff1:	48 89 c7             	mov    %rax,%rdi
    1ff4:	e8 e5 fd ff ff       	callq  1dde <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes>
    1ff9:	85 c0                	test   %eax,%eax
    1ffb:	75 13                	jne    2010 <is_dynamic_thread+0x56>
            (fa.si_flags == SI_FLAGS_TCS))
    1ffd:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    if ((tcs != NULL) && (check_dynamic_range(tcs, 1, NULL, &fa) == 0) &&
    2001:	48 3d 00 01 00 00    	cmp    $0x100,%rax
    2007:	75 07                	jne    2010 <is_dynamic_thread+0x56>
    2009:	b8 01 00 00 00       	mov    $0x1,%eax
    200e:	eb 05                	jmp    2015 <is_dynamic_thread+0x5b>
    2010:	b8 00 00 00 00       	mov    $0x0,%eax
    2015:	84 c0                	test   %al,%al
    2017:	74 07                	je     2020 <is_dynamic_thread+0x66>
    {
        return true;
    2019:	b8 01 00 00 00       	mov    $0x1,%eax
    201e:	eb 05                	jmp    2025 <is_dynamic_thread+0x6b>
    }

    return false;
    2020:	b8 00 00 00 00       	mov    $0x0,%eax
}
    2025:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    2029:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    2030:	00 00 
    2032:	74 05                	je     2039 <is_dynamic_thread+0x7f>
    2034:	e8 a1 32 00 00       	callq  52da <__stack_chk_fail>
    2039:	c9                   	leaveq 
    203a:	c3                   	retq   

000000000000203b <is_dynamic_thread_exist>:

int is_dynamic_thread_exist()
{
    203b:	55                   	push   %rbp
    203c:	48 89 e5             	mov    %rsp,%rbp
    203f:	48 83 ec 10          	sub    $0x10,%rsp
    if(!EDMM_supported)
    2043:	48 8d 05 a6 ed 00 00 	lea    0xeda6(%rip),%rax        # 10df0 <EDMM_supported>
    204a:	8b 00                	mov    (%rax),%eax
    204c:	85 c0                	test   %eax,%eax
    204e:	75 07                	jne    2057 <is_dynamic_thread_exist+0x1c>
        return false;
    2050:	b8 00 00 00 00       	mov    $0x0,%eax
    2055:	eb 21                	jmp    2078 <is_dynamic_thread_exist+0x3d>
    const volatile layout_t * layout = get_dynamic_layout_by_id(LAYOUT_ID_STACK_DYN_MIN);
    2057:	bf 12 00 00 00       	mov    $0x12,%edi
    205c:	e8 34 f9 ff ff       	callq  1995 <_Z24get_dynamic_layout_by_idt>
    2061:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if (!layout)
    2065:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    206a:	75 07                	jne    2073 <is_dynamic_thread_exist+0x38>
        return false;
    206c:	b8 00 00 00 00       	mov    $0x0,%eax
    2071:	eb 05                	jmp    2078 <is_dynamic_thread_exist+0x3d>
    else
        return true;
    2073:	b8 01 00 00 00       	mov    $0x1,%eax
}
    2078:	c9                   	leaveq 
    2079:	c3                   	retq   

000000000000207a <get_dynamic_stack_max_page>:


uint32_t get_dynamic_stack_max_page()
{
    207a:	55                   	push   %rbp
    207b:	48 89 e5             	mov    %rsp,%rbp
    207e:	48 83 ec 10          	sub    $0x10,%rsp
    const volatile layout_t * layout = get_dynamic_layout_by_id(LAYOUT_ID_STACK_MAX);
    2082:	bf 07 00 00 00       	mov    $0x7,%edi
    2087:	e8 09 f9 ff ff       	callq  1995 <_Z24get_dynamic_layout_by_idt>
    208c:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if (!layout)
    2090:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    2095:	75 07                	jne    209e <get_dynamic_stack_max_page+0x24>
        return 0;
    2097:	b8 00 00 00 00       	mov    $0x0,%eax
    209c:	eb 07                	jmp    20a5 <get_dynamic_stack_max_page+0x2b>
    else
        return layout->entry.page_count;
    209e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    20a2:	8b 40 04             	mov    0x4(%rax),%eax
}
    20a5:	c9                   	leaveq 
    20a6:	c3                   	retq   

00000000000020a7 <sgx_accept_forward>:
#endif

int sgx_accept_forward(si_flags_t sfl, size_t lo, size_t hi)
{
    20a7:	4c 8d 54 24 08       	lea    0x8(%rsp),%r10
    20ac:	48 83 e4 c0          	and    $0xffffffffffffffc0,%rsp
    20b0:	41 ff 72 f8          	pushq  -0x8(%r10)
    20b4:	55                   	push   %rbp
    20b5:	48 89 e5             	mov    %rsp,%rbp
    20b8:	41 52                	push   %r10
    20ba:	48 81 ec e8 00 00 00 	sub    $0xe8,%rsp
    20c1:	48 89 bd 38 ff ff ff 	mov    %rdi,-0xc8(%rbp)
    20c8:	48 89 b5 30 ff ff ff 	mov    %rsi,-0xd0(%rbp)
    20cf:	48 89 95 28 ff ff ff 	mov    %rdx,-0xd8(%rbp)
    20d6:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    20dd:	00 00 
    20df:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    20e3:	31 c0                	xor    %eax,%eax
    (void)sfl;
    (void)lo;
    (void)hi;
    return 0;
#else
    size_t addr = lo;
    20e5:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    20ec:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    SE_DECLSPEC_ALIGN(sizeof(sec_info_t)) sec_info_t si;
    si.flags = sfl;
    20f3:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    20fa:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    for (uint16_t i = 0; i < (sizeof(si.reserved)/sizeof(si.reserved[0])); i++)
    2101:	66 c7 85 42 ff ff ff 	movw   $0x0,-0xbe(%rbp)
    2108:	00 00 
    210a:	66 83 bd 42 ff ff ff 	cmpw   $0x6,-0xbe(%rbp)
    2111:	06 
    2112:	77 28                	ja     213c <sgx_accept_forward+0x95>
        si.reserved[i] = 0;
    2114:	0f b7 85 42 ff ff ff 	movzwl -0xbe(%rbp),%eax
    211b:	48 98                	cltq   
    211d:	48 c7 84 c5 58 ff ff 	movq   $0x0,-0xa8(%rbp,%rax,8)
    2124:	ff 00 00 00 00 
    for (uint16_t i = 0; i < (sizeof(si.reserved)/sizeof(si.reserved[0])); i++)
    2129:	0f b7 85 42 ff ff ff 	movzwl -0xbe(%rbp),%eax
    2130:	83 c0 01             	add    $0x1,%eax
    2133:	66 89 85 42 ff ff ff 	mov    %ax,-0xbe(%rbp)
    213a:	eb ce                	jmp    210a <sgx_accept_forward+0x63>

    while (addr < hi)
    213c:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    2143:	48 3b 85 28 ff ff ff 	cmp    -0xd8(%rbp),%rax
    214a:	73 3a                	jae    2186 <sgx_accept_forward+0xdf>
    {
        int rc = do_eaccept(&si, addr);
    214c:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    2153:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
    215a:	48 89 d6             	mov    %rdx,%rsi
    215d:	48 89 c7             	mov    %rax,%rdi
    2160:	e8 1b a8 00 00       	callq  c980 <do_eaccept>
    2165:	89 85 44 ff ff ff    	mov    %eax,-0xbc(%rbp)
        if (rc != 0)
    216b:	83 bd 44 ff ff ff 00 	cmpl   $0x0,-0xbc(%rbp)
    2172:	74 05                	je     2179 <sgx_accept_forward+0xd2>
            abort();
    2174:	e8 55 a8 00 00       	callq  c9ce <abort>
        addr += SE_PAGE_SIZE;
    2179:	48 81 85 48 ff ff ff 	addq   $0x1000,-0xb8(%rbp)
    2180:	00 10 00 00 
    while (addr < hi)
    2184:	eb b6                	jmp    213c <sgx_accept_forward+0x95>
    }

    return 0;
    2186:	b8 00 00 00 00       	mov    $0x0,%eax
#endif
}
    218b:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    218f:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    2196:	00 00 
    2198:	74 05                	je     219f <sgx_accept_forward+0xf8>
    219a:	e8 3b 31 00 00       	callq  52da <__stack_chk_fail>
    219f:	48 81 c4 e8 00 00 00 	add    $0xe8,%rsp
    21a6:	41 5a                	pop    %r10
    21a8:	5d                   	pop    %rbp
    21a9:	49 8d 62 f8          	lea    -0x8(%r10),%rsp
    21ad:	c3                   	retq   

00000000000021ae <apply_pages_within_exception>:

// High level API to EACCEPT pages, mainly used in exception handling
// to deal with stack expansion. 
int apply_pages_within_exception(void *start_address, size_t page_count)
{
    21ae:	55                   	push   %rbp
    21af:	48 89 e5             	mov    %rsp,%rbp
    21b2:	48 83 ec 30          	sub    $0x30,%rsp
    21b6:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    21ba:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    (void)page_count;
    return 0;
#else
    int rc;

    if (start_address == NULL)
    21be:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    21c3:	75 07                	jne    21cc <apply_pages_within_exception+0x1e>
        return -1;
    21c5:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    21ca:	eb 61                	jmp    222d <apply_pages_within_exception+0x7f>
    
    if (check_dynamic_range(start_address, page_count, NULL, NULL) != 0)
    21cc:	48 8b 75 d0          	mov    -0x30(%rbp),%rsi
    21d0:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    21d4:	b9 00 00 00 00       	mov    $0x0,%ecx
    21d9:	ba 00 00 00 00       	mov    $0x0,%edx
    21de:	48 89 c7             	mov    %rax,%rdi
    21e1:	e8 f8 fb ff ff       	callq  1dde <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes>
    21e6:	85 c0                	test   %eax,%eax
    21e8:	0f 95 c0             	setne  %al
    21eb:	84 c0                	test   %al,%al
    21ed:	74 07                	je     21f6 <apply_pages_within_exception+0x48>
        return -1;
    21ef:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    21f4:	eb 37                	jmp    222d <apply_pages_within_exception+0x7f>

    size_t start = (size_t)start_address;
    21f6:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    21fa:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    size_t end = start + (page_count << SE_PAGE_SHIFT);
    21fe:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2202:	48 c1 e0 0c          	shl    $0xc,%rax
    2206:	48 89 c2             	mov    %rax,%rdx
    2209:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    220d:	48 01 d0             	add    %rdx,%rax
    2210:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

    rc = sgx_accept_forward_within_exception(start, end);
    2214:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    2218:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    221c:	48 89 d6             	mov    %rdx,%rsi
    221f:	48 89 c7             	mov    %rax,%rdi
    2222:	e8 43 f6 ff ff       	callq  186a <_ZL35sgx_accept_forward_within_exceptionmm>
    2227:	89 45 ec             	mov    %eax,-0x14(%rbp)

    return rc;
    222a:	8b 45 ec             	mov    -0x14(%rbp),%eax
#endif

}
    222d:	c9                   	leaveq 
    222e:	c3                   	retq   

000000000000222f <apply_EPC_pages>:

// High level API to EACCEPT pages
int apply_EPC_pages(void *start_address, size_t page_count)
{
    222f:	55                   	push   %rbp
    2230:	48 89 e5             	mov    %rsp,%rbp
    2233:	48 83 ec 50          	sub    $0x50,%rsp
    2237:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    223b:	48 89 75 b0          	mov    %rsi,-0x50(%rbp)
    223f:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    2246:	00 00 
    2248:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    224c:	31 c0                	xor    %eax,%eax
    return 0;
#else
    int rc;
    struct dynamic_flags_attributes fa;

    if (start_address == NULL)
    224e:	48 83 7d b8 00       	cmpq   $0x0,-0x48(%rbp)
    2253:	75 0a                	jne    225f <apply_EPC_pages+0x30>
        return -1;
    2255:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    225a:	e9 8d 00 00 00       	jmpq   22ec <apply_EPC_pages+0xbd>
    
    if (check_dynamic_range(start_address, page_count, NULL, &fa) != 0)
    225f:	48 8d 55 e0          	lea    -0x20(%rbp),%rdx
    2263:	48 8b 75 b0          	mov    -0x50(%rbp),%rsi
    2267:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    226b:	48 89 d1             	mov    %rdx,%rcx
    226e:	ba 00 00 00 00       	mov    $0x0,%edx
    2273:	48 89 c7             	mov    %rax,%rdi
    2276:	e8 63 fb ff ff       	callq  1dde <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes>
    227b:	85 c0                	test   %eax,%eax
    227d:	0f 95 c0             	setne  %al
    2280:	84 c0                	test   %al,%al
    2282:	74 07                	je     228b <apply_EPC_pages+0x5c>
        return -1;
    2284:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    2289:	eb 61                	jmp    22ec <apply_EPC_pages+0xbd>

    size_t start = (size_t)start_address;
    228b:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    228f:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    size_t end = start + (page_count << SE_PAGE_SHIFT);
    2293:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    2297:	48 c1 e0 0c          	shl    $0xc,%rax
    229b:	48 89 c2             	mov    %rax,%rdx
    229e:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    22a2:	48 01 d0             	add    %rdx,%rax
    22a5:	48 89 45 d8          	mov    %rax,-0x28(%rbp)

    if (fa.attributes & PAGE_DIR_GROW_DOWN)
    22a9:	0f b7 45 e8          	movzwl -0x18(%rbp),%eax
    22ad:	0f b7 c0             	movzwl %ax,%eax
    22b0:	83 e0 40             	and    $0x40,%eax
    22b3:	85 c0                	test   %eax,%eax
    22b5:	74 1a                	je     22d1 <apply_EPC_pages+0xa2>
    {
        rc = sgx_accept_forward(SI_FLAGS_RW | SI_FLAG_PENDING, start, end);
    22b7:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    22bb:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    22bf:	48 89 c6             	mov    %rax,%rsi
    22c2:	bf 0b 02 00 00       	mov    $0x20b,%edi
    22c7:	e8 db fd ff ff       	callq  20a7 <sgx_accept_forward>
    22cc:	89 45 cc             	mov    %eax,-0x34(%rbp)
    22cf:	eb 18                	jmp    22e9 <apply_EPC_pages+0xba>
    }
    else
    {
        rc = sgx_accept_backward(SI_FLAGS_RW | SI_FLAG_PENDING, start, end);
    22d1:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    22d5:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    22d9:	48 89 c6             	mov    %rax,%rsi
    22dc:	bf 0b 02 00 00       	mov    $0x20b,%edi
    22e1:	e8 7f f4 ff ff       	callq  1765 <_ZL19sgx_accept_backwardmmm>
    22e6:	89 45 cc             	mov    %eax,-0x34(%rbp)
    }

    return rc;
    22e9:	8b 45 cc             	mov    -0x34(%rbp),%eax
#endif
}
    22ec:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    22f0:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    22f7:	00 00 
    22f9:	74 05                	je     2300 <apply_EPC_pages+0xd1>
    22fb:	e8 da 2f 00 00       	callq  52da <__stack_chk_fail>
    2300:	c9                   	leaveq 
    2301:	c3                   	retq   

0000000000002302 <trim_EPC_pages>:

// High level API to trim previously EAUG-ed pages.
int trim_EPC_pages(void *start_address, size_t page_count)
{
    2302:	55                   	push   %rbp
    2303:	48 89 e5             	mov    %rsp,%rbp
    2306:	48 83 ec 30          	sub    $0x30,%rsp
    230a:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    230e:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    (void)page_count;
    return 0;
#else
    int rc;

    if (start_address == NULL)
    2312:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    2317:	75 0a                	jne    2323 <trim_EPC_pages+0x21>
        return -1;
    2319:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    231e:	e9 16 01 00 00       	jmpq   2439 <trim_EPC_pages+0x137>

    // check range
    if (check_dynamic_range(start_address, page_count, NULL, NULL) != 0)
    2323:	48 8b 75 d0          	mov    -0x30(%rbp),%rsi
    2327:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    232b:	b9 00 00 00 00       	mov    $0x0,%ecx
    2330:	ba 00 00 00 00       	mov    $0x0,%edx
    2335:	48 89 c7             	mov    %rax,%rdi
    2338:	e8 a1 fa ff ff       	callq  1dde <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes>
    233d:	85 c0                	test   %eax,%eax
    233f:	0f 95 c0             	setne  %al
    2342:	84 c0                	test   %al,%al
    2344:	74 0a                	je     2350 <trim_EPC_pages+0x4e>
        return -1;
    2346:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    234b:	e9 e9 00 00 00       	jmpq   2439 <trim_EPC_pages+0x137>

    size_t start = (size_t)start_address;
    2350:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2354:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    size_t end = start + (page_count << SE_PAGE_SHIFT);
    2358:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    235c:	48 c1 e0 0c          	shl    $0xc,%rax
    2360:	48 89 c2             	mov    %rax,%rdx
    2363:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2367:	48 01 d0             	add    %rdx,%rax
    236a:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

    // trim ocall
    rc = trim_range_ocall(start, end);
    236e:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    2372:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2376:	48 89 d6             	mov    %rdx,%rsi
    2379:	48 89 c7             	mov    %rax,%rdi
    237c:	e8 9f 14 00 00       	callq  3820 <trim_range_ocall>
    2381:	89 45 e4             	mov    %eax,-0x1c(%rbp)
    assert(rc == 0);
    2384:	83 7d e4 00          	cmpl   $0x0,-0x1c(%rbp)
    2388:	74 1f                	je     23a9 <trim_EPC_pages+0xa7>
    238a:	48 8d 0d 77 ac 00 00 	lea    0xac77(%rip),%rcx        # d008 <g_dyn_entry_table+0x8>
    2391:	48 8d 15 90 ac 00 00 	lea    0xac90(%rip),%rdx        # d028 <_ZZ14trim_EPC_pagesE8__func__>
    2398:	be 9e 01 00 00       	mov    $0x19e,%esi
    239d:	48 8d 3d 6c ac 00 00 	lea    0xac6c(%rip),%rdi        # d010 <g_dyn_entry_table+0x10>
    23a4:	e8 3a 2f 00 00       	callq  52e3 <__assert>

    rc = sgx_accept_forward(SI_FLAG_TRIM | SI_FLAG_MODIFIED, start, end);
    23a9:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    23ad:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    23b1:	48 89 c6             	mov    %rax,%rsi
    23b4:	bf 10 04 00 00       	mov    $0x410,%edi
    23b9:	e8 e9 fc ff ff       	callq  20a7 <sgx_accept_forward>
    23be:	89 45 e4             	mov    %eax,-0x1c(%rbp)
    assert(rc == 0);
    23c1:	83 7d e4 00          	cmpl   $0x0,-0x1c(%rbp)
    23c5:	74 1f                	je     23e6 <trim_EPC_pages+0xe4>
    23c7:	48 8d 0d 3a ac 00 00 	lea    0xac3a(%rip),%rcx        # d008 <g_dyn_entry_table+0x8>
    23ce:	48 8d 15 53 ac 00 00 	lea    0xac53(%rip),%rdx        # d028 <_ZZ14trim_EPC_pagesE8__func__>
    23d5:	be a1 01 00 00       	mov    $0x1a1,%esi
    23da:	48 8d 3d 2f ac 00 00 	lea    0xac2f(%rip),%rdi        # d010 <g_dyn_entry_table+0x10>
    23e1:	e8 fd 2e 00 00       	callq  52e3 <__assert>
    
    // trim commit ocall
    size_t i = start;
    23e6:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    23ea:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    while (i < end)
    23ee:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    23f2:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    23f6:	73 3e                	jae    2436 <trim_EPC_pages+0x134>
    {
        rc = trim_range_commit_ocall(i);
    23f8:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    23fc:	48 89 c7             	mov    %rax,%rdi
    23ff:	e8 91 14 00 00       	callq  3895 <trim_range_commit_ocall>
    2404:	89 45 e4             	mov    %eax,-0x1c(%rbp)
        assert(rc == 0);
    2407:	83 7d e4 00          	cmpl   $0x0,-0x1c(%rbp)
    240b:	74 1f                	je     242c <trim_EPC_pages+0x12a>
    240d:	48 8d 0d f4 ab 00 00 	lea    0xabf4(%rip),%rcx        # d008 <g_dyn_entry_table+0x8>
    2414:	48 8d 15 0d ac 00 00 	lea    0xac0d(%rip),%rdx        # d028 <_ZZ14trim_EPC_pagesE8__func__>
    241b:	be a8 01 00 00       	mov    $0x1a8,%esi
    2420:	48 8d 3d e9 ab 00 00 	lea    0xabe9(%rip),%rdi        # d010 <g_dyn_entry_table+0x10>
    2427:	e8 b7 2e 00 00       	callq  52e3 <__assert>
        i += SE_PAGE_SIZE;
    242c:	48 81 45 e8 00 10 00 	addq   $0x1000,-0x18(%rbp)
    2433:	00 
    while (i < end)
    2434:	eb b8                	jmp    23ee <trim_EPC_pages+0xec>
    }

    return rc;
    2436:	8b 45 e4             	mov    -0x1c(%rbp),%eax
#endif
}
    2439:	c9                   	leaveq 
    243a:	c3                   	retq   

000000000000243b <do_add_thread>:

// Create a thread dynamically.
// It will add necessary pages and transform one of them into type TCS.
sgx_status_t do_add_thread(void *ptcs)
{
    243b:	55                   	push   %rbp
    243c:	48 89 e5             	mov    %rsp,%rbp
    243f:	48 83 ec 50          	sub    $0x50,%rsp
    2443:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    2447:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    244e:	00 00 
    2450:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    2454:	31 c0                	xor    %eax,%eax
#ifdef SE_SIM
    (void)ptcs;
    return SGX_SUCCESS;
#else
    int ret = SGX_ERROR_UNEXPECTED;
    2456:	c7 45 c4 01 00 00 00 	movl   $0x1,-0x3c(%rbp)
    tcs_t *tcs = (tcs_t *)ptcs;
    245d:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2461:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    tcs_t *tcs_template = NULL;
    2465:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    246c:	00 
    size_t offset = 0;
    246d:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    2474:	00 
    size_t enclave_base = (size_t)get_enclave_base();
    2475:	e8 ea a1 00 00       	callq  c664 <get_enclave_base>
    247a:	48 89 45 e0          	mov    %rax,-0x20(%rbp)

    if ( 0 != check_dynamic_range((void *)tcs, 1, &offset, NULL))
    247e:	48 8d 55 c8          	lea    -0x38(%rbp),%rdx
    2482:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2486:	b9 00 00 00 00       	mov    $0x0,%ecx
    248b:	be 01 00 00 00       	mov    $0x1,%esi
    2490:	48 89 c7             	mov    %rax,%rdi
    2493:	e8 46 f9 ff ff       	callq  1dde <_ZL19check_dynamic_rangePvmPmP24dynamic_flags_attributes>
    2498:	85 c0                	test   %eax,%eax
    249a:	0f 95 c0             	setne  %al
    249d:	84 c0                	test   %al,%al
    249f:	74 0a                	je     24ab <do_add_thread+0x70>
        return SGX_ERROR_UNEXPECTED;
    24a1:	b8 01 00 00 00       	mov    $0x1,%eax
    24a6:	e9 bb 01 00 00       	jmpq   2666 <do_add_thread+0x22b>

    // check if the tcs provided exactly matches the one in signtool
    const volatile layout_t *tcs_layout = get_dynamic_layout_by_id(LAYOUT_ID_TCS_DYN);
    24ab:	bf 0e 00 00 00       	mov    $0xe,%edi
    24b0:	e8 e0 f4 ff ff       	callq  1995 <_Z24get_dynamic_layout_by_idt>
    24b5:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    if (!tcs_layout)
    24b9:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    24be:	75 0a                	jne    24ca <do_add_thread+0x8f>
        return SGX_ERROR_UNEXPECTED;
    24c0:	b8 01 00 00 00       	mov    $0x1,%eax
    24c5:	e9 9c 01 00 00       	jmpq   2666 <do_add_thread+0x22b>

    if ((size_t)(enclave_base + tcs_layout->entry.rva + offset) != (size_t)(tcs))
    24ca:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    24ce:	48 8b 50 08          	mov    0x8(%rax),%rdx
    24d2:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    24d6:	48 01 c2             	add    %rax,%rdx
    24d9:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    24dd:	48 01 c2             	add    %rax,%rdx
    24e0:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    24e4:	48 39 c2             	cmp    %rax,%rdx
    24e7:	0f 95 c0             	setne  %al
    24ea:	84 c0                	test   %al,%al
    24ec:	74 0a                	je     24f8 <do_add_thread+0xbd>
        return SGX_ERROR_UNEXPECTED;
    24ee:	b8 01 00 00 00       	mov    $0x1,%eax
    24f3:	e9 6e 01 00 00       	jmpq   2666 <do_add_thread+0x22b>

    // adding page for all the dynamic entries
    for (uint16_t id = LAYOUT_ID_TCS_DYN; id <= LAYOUT_ID_STACK_DYN_MIN; id++)
    24f8:	66 c7 45 c2 0e 00    	movw   $0xe,-0x3e(%rbp)
    24fe:	66 83 7d c2 12       	cmpw   $0x12,-0x3e(%rbp)
    2503:	0f 87 85 00 00 00    	ja     258e <do_add_thread+0x153>
    {
        const volatile layout_t *layout =  get_dynamic_layout_by_id(id);
    2509:	0f b7 45 c2          	movzwl -0x3e(%rbp),%eax
    250d:	89 c7                	mov    %eax,%edi
    250f:	e8 81 f4 ff ff       	callq  1995 <_Z24get_dynamic_layout_by_idt>
    2514:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
        if (layout && (layout->entry.attributes & PAGE_ATTR_DYN_THREAD))
    2518:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    251d:	74 19                	je     2538 <do_add_thread+0xfd>
    251f:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2523:	0f b7 40 02          	movzwl 0x2(%rax),%eax
    2527:	0f b7 c0             	movzwl %ax,%eax
    252a:	83 e0 20             	and    $0x20,%eax
    252d:	85 c0                	test   %eax,%eax
    252f:	74 07                	je     2538 <do_add_thread+0xfd>
    2531:	b8 01 00 00 00       	mov    $0x1,%eax
    2536:	eb 05                	jmp    253d <do_add_thread+0x102>
    2538:	b8 00 00 00 00       	mov    $0x0,%eax
    253d:	84 c0                	test   %al,%al
    253f:	74 3d                	je     257e <do_add_thread+0x143>
        {
            ret = apply_EPC_pages((void *)(enclave_base + layout->entry.rva + offset), layout->entry.page_count);
    2541:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2545:	8b 40 04             	mov    0x4(%rax),%eax
    2548:	89 c1                	mov    %eax,%ecx
    254a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    254e:	48 8b 50 08          	mov    0x8(%rax),%rdx
    2552:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    2556:	48 01 c2             	add    %rax,%rdx
    2559:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    255d:	48 01 d0             	add    %rdx,%rax
    2560:	48 89 ce             	mov    %rcx,%rsi
    2563:	48 89 c7             	mov    %rax,%rdi
    2566:	e8 c4 fc ff ff       	callq  222f <apply_EPC_pages>
    256b:	89 45 c4             	mov    %eax,-0x3c(%rbp)
            if (ret != 0)
    256e:	83 7d c4 00          	cmpl   $0x0,-0x3c(%rbp)
    2572:	74 0a                	je     257e <do_add_thread+0x143>
                return SGX_ERROR_UNEXPECTED;
    2574:	b8 01 00 00 00       	mov    $0x1,%eax
    2579:	e9 e8 00 00 00       	jmpq   2666 <do_add_thread+0x22b>
    for (uint16_t id = LAYOUT_ID_TCS_DYN; id <= LAYOUT_ID_STACK_DYN_MIN; id++)
    257e:	0f b7 45 c2          	movzwl -0x3e(%rbp),%eax
    2582:	83 c0 01             	add    $0x1,%eax
    2585:	66 89 45 c2          	mov    %ax,-0x3e(%rbp)
    2589:	e9 70 ff ff ff       	jmpq   24fe <do_add_thread+0xc3>
        }
    }

    //Copy and initialize TCS
    tcs_template = (tcs_t *)g_global_data.tcs_template;
    258e:	48 8d 05 eb ab 00 00 	lea    0xabeb(%rip),%rax        # d180 <g_global_data>
    2595:	48 8d 80 e0 00 00 00 	lea    0xe0(%rax),%rax
    259c:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    memcpy_s(tcs, TCS_SIZE, tcs_template, sizeof(g_global_data.tcs_template));
    25a0:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    25a4:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    25a8:	b9 48 00 00 00       	mov    $0x48,%ecx
    25ad:	be 00 10 00 00       	mov    $0x1000,%esi
    25b2:	48 89 c7             	mov    %rax,%rdi
    25b5:	e8 64 f1 ff ff       	callq  171e <memcpy_s>

    //Adjust the tcs fields
    tcs->ossa = (size_t)GET_PTR(size_t, (void *)tcs, tcs->ossa) - enclave_base;
    25ba:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    25be:	48 8b 50 10          	mov    0x10(%rax),%rdx
    25c2:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    25c6:	48 01 d0             	add    %rdx,%rax
    25c9:	48 2b 45 e0          	sub    -0x20(%rbp),%rax
    25cd:	48 89 c2             	mov    %rax,%rdx
    25d0:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    25d4:	48 89 50 10          	mov    %rdx,0x10(%rax)
    tcs->ofs_base = (size_t)GET_PTR(size_t, (void *)tcs, tcs->ofs_base) - enclave_base;
    25d8:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    25dc:	48 8b 50 30          	mov    0x30(%rax),%rdx
    25e0:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    25e4:	48 01 d0             	add    %rdx,%rax
    25e7:	48 2b 45 e0          	sub    -0x20(%rbp),%rax
    25eb:	48 89 c2             	mov    %rax,%rdx
    25ee:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    25f2:	48 89 50 30          	mov    %rdx,0x30(%rax)
    tcs->ogs_base = (size_t)GET_PTR(size_t, (void *)tcs, tcs->ogs_base) - enclave_base;
    25f6:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    25fa:	48 8b 50 38          	mov    0x38(%rax),%rdx
    25fe:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2602:	48 01 d0             	add    %rdx,%rax
    2605:	48 2b 45 e0          	sub    -0x20(%rbp),%rax
    2609:	48 89 c2             	mov    %rax,%rdx
    260c:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2610:	48 89 50 38          	mov    %rdx,0x38(%rax)

    //OCALL for MKTCS
    ret = sgx_ocall(0, tcs);
    2614:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2618:	48 89 c6             	mov    %rax,%rsi
    261b:	bf 00 00 00 00       	mov    $0x0,%edi
    2620:	e8 1d 10 00 00       	callq  3642 <sgx_ocall>
    2625:	89 45 c4             	mov    %eax,-0x3c(%rbp)
    if (ret != 0)
    2628:	83 7d c4 00          	cmpl   $0x0,-0x3c(%rbp)
    262c:	74 07                	je     2635 <do_add_thread+0x1fa>
        return SGX_ERROR_UNEXPECTED;
    262e:	b8 01 00 00 00       	mov    $0x1,%eax
    2633:	eb 31                	jmp    2666 <do_add_thread+0x22b>

    //EACCEPT for MKTCS
    ret = sgx_accept_backward(SI_FLAG_TCS | SI_FLAG_MODIFIED, (size_t)tcs, (size_t)tcs + SE_PAGE_SIZE);
    2635:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2639:	48 8d 90 00 10 00 00 	lea    0x1000(%rax),%rdx
    2640:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2644:	48 89 c6             	mov    %rax,%rsi
    2647:	bf 10 01 00 00       	mov    $0x110,%edi
    264c:	e8 14 f1 ff ff       	callq  1765 <_ZL19sgx_accept_backwardmmm>
    2651:	89 45 c4             	mov    %eax,-0x3c(%rbp)
    if (ret != 0)
    2654:	83 7d c4 00          	cmpl   $0x0,-0x3c(%rbp)
    2658:	74 07                	je     2661 <do_add_thread+0x226>
        return SGX_ERROR_UNEXPECTED;
    265a:	b8 01 00 00 00       	mov    $0x1,%eax
    265f:	eb 05                	jmp    2666 <do_add_thread+0x22b>

    return SGX_SUCCESS;
    2661:	b8 00 00 00 00       	mov    $0x0,%eax

#endif
}
    2666:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    266a:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    2671:	00 00 
    2673:	74 05                	je     267a <do_add_thread+0x23f>
    2675:	e8 60 2c 00 00       	callq  52da <__stack_chk_fail>
    267a:	c9                   	leaveq 
    267b:	c3                   	retq   

000000000000267c <memcpy_s>:
{
    267c:	55                   	push   %rbp
    267d:	48 89 e5             	mov    %rsp,%rbp
    2680:	48 83 ec 20          	sub    $0x20,%rsp
    2684:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    2688:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    268c:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    2690:	48 89 4d e0          	mov    %rcx,-0x20(%rbp)
    if(numberOfElements<count)
    2694:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2698:	48 3b 45 e0          	cmp    -0x20(%rbp),%rax
    269c:	73 07                	jae    26a5 <memcpy_s+0x29>
        return -1;
    269e:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    26a3:	eb 1c                	jmp    26c1 <memcpy_s+0x45>
    memcpy(dest, src, count);
    26a5:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    26a9:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
    26ad:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    26b1:	48 89 ce             	mov    %rcx,%rsi
    26b4:	48 89 c7             	mov    %rax,%rdi
    26b7:	e8 76 88 00 00       	callq  af32 <memcpy>
    return 0;
    26bc:	b8 00 00 00 00       	mov    $0x0,%eax
}
    26c1:	c9                   	leaveq 
    26c2:	c3                   	retq   

00000000000026c3 <_pthread_thread_run>:

#include "pthread_imp.h"
#include "sgx_random_buffers.h"
#include "se_page_attr.h"

__attribute__((weak)) sgx_status_t _pthread_thread_run(void* ms) {UNUSED(ms); return SGX_SUCCESS;}
    26c3:	55                   	push   %rbp
    26c4:	48 89 e5             	mov    %rsp,%rbp
    26c7:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    26cb:	b8 00 00 00 00       	mov    $0x0,%eax
    26d0:	5d                   	pop    %rbp
    26d1:	c3                   	retq   

00000000000026d2 <_Z16_pthread_enabledv>:
__attribute__((weak)) bool _pthread_enabled() {return false;}
    26d2:	55                   	push   %rbp
    26d3:	48 89 e5             	mov    %rsp,%rbp
    26d6:	b8 00 00 00 00       	mov    $0x0,%eax
    26db:	5d                   	pop    %rbp
    26dc:	c3                   	retq   

00000000000026dd <_Z24_pthread_tls_store_state9_status_t>:
__attribute__((weak)) void _pthread_tls_store_state(sgx_status_t state) {UNUSED(state);}
    26dd:	55                   	push   %rbp
    26de:	48 89 e5             	mov    %rsp,%rbp
    26e1:	89 7d fc             	mov    %edi,-0x4(%rbp)
    26e4:	90                   	nop
    26e5:	5d                   	pop    %rbp
    26e6:	c3                   	retq   

00000000000026e7 <_Z22_pthread_tls_get_statev>:
__attribute__((weak)) sgx_status_t _pthread_tls_get_state(void) {return SGX_SUCCESS;}
    26e7:	55                   	push   %rbp
    26e8:	48 89 e5             	mov    %rsp,%rbp
    26eb:	b8 00 00 00 00       	mov    $0x0,%eax
    26f0:	5d                   	pop    %rbp
    26f1:	c3                   	retq   

00000000000026f2 <_Z26_pthread_tls_store_contextPv>:
__attribute__((weak)) void _pthread_tls_store_context(void* context) {UNUSED(context);}
    26f2:	55                   	push   %rbp
    26f3:	48 89 e5             	mov    %rsp,%rbp
    26f6:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    26fa:	90                   	nop
    26fb:	5d                   	pop    %rbp
    26fc:	c3                   	retq   

00000000000026fd <_Z20_pthread_wakeup_joinPv>:
__attribute__((weak)) void _pthread_wakeup_join(void* ms) {UNUSED(ms);}
    26fd:	55                   	push   %rbp
    26fe:	48 89 e5             	mov    %rsp,%rbp
    2701:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    2705:	90                   	nop
    2706:	5d                   	pop    %rbp
    2707:	c3                   	retq   

0000000000002708 <_Z24_pthread_tls_destructorsv>:
__attribute__((weak)) void _pthread_tls_destructors(void) {}
    2708:	55                   	push   %rbp
    2709:	48 89 e5             	mov    %rsp,%rbp
    270c:	90                   	nop
    270d:	5d                   	pop    %rbp
    270e:	c3                   	retq   

000000000000270f <_ZL16is_ecall_allowedj>:

// is_ecall_allowed()
// check the index in the dynamic entry table
static sgx_status_t is_ecall_allowed(uint32_t ordinal)
{
    270f:	55                   	push   %rbp
    2710:	48 89 e5             	mov    %rsp,%rbp
    2713:	48 83 ec 30          	sub    $0x30,%rsp
    2717:	89 7d dc             	mov    %edi,-0x24(%rbp)
    if(ordinal >= g_ecall_table.nr_ecall)
    271a:	8b 55 dc             	mov    -0x24(%rbp),%edx
    271d:	48 8d 05 9c e6 00 00 	lea    0xe69c(%rip),%rax        # 10dc0 <g_ecall_table>
    2724:	48 8b 00             	mov    (%rax),%rax
    2727:	48 39 c2             	cmp    %rax,%rdx
    272a:	72 0a                	jb     2736 <_ZL16is_ecall_allowedj+0x27>
    {
        return SGX_ERROR_INVALID_FUNCTION;
    272c:	b8 01 10 00 00       	mov    $0x1001,%eax
    2731:	e9 c7 00 00 00       	jmpq   27fd <_ZL16is_ecall_allowedj+0xee>
    }
    thread_data_t *thread_data = get_thread_data();
    2736:	e8 64 9f 00 00       	callq  c69f <get_thread_data>
    273b:	48 89 45 e8          	mov    %rax,-0x18(%rbp)

    sgx_lfence();
    273f:	0f ae e8             	lfence 

    if(thread_data->last_sp == thread_data->stack_base_addr)
    2742:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2746:	48 8b 50 08          	mov    0x8(%rax),%rdx
    274a:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    274e:	48 8b 40 10          	mov    0x10(%rax),%rax
    2752:	48 39 c2             	cmp    %rax,%rdx
    2755:	75 2d                	jne    2784 <_ZL16is_ecall_allowedj+0x75>
    {
        // root ECALL, check the priv bits.
        if (g_ecall_table.ecall_table[ordinal].is_priv)
    2757:	48 8d 05 62 e6 00 00 	lea    0xe662(%rip),%rax        # 10dc0 <g_ecall_table>
    275e:	8b 55 dc             	mov    -0x24(%rbp),%edx
    2761:	48 c1 e2 04          	shl    $0x4,%rdx
    2765:	48 01 d0             	add    %rdx,%rax
    2768:	48 83 c0 10          	add    $0x10,%rax
    276c:	0f b6 00             	movzbl (%rax),%eax
    276f:	84 c0                	test   %al,%al
    2771:	74 0a                	je     277d <_ZL16is_ecall_allowedj+0x6e>
            return SGX_ERROR_ECALL_NOT_ALLOWED;
    2773:	b8 07 10 00 00       	mov    $0x1007,%eax
    2778:	e9 80 00 00 00       	jmpq   27fd <_ZL16is_ecall_allowedj+0xee>
        return SGX_SUCCESS;
    277d:	b8 00 00 00 00       	mov    $0x0,%eax
    2782:	eb 79                	jmp    27fd <_ZL16is_ecall_allowedj+0xee>
    }
    ocall_context_t *context = reinterpret_cast<ocall_context_t*>(thread_data->last_sp);
    2784:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2788:	48 8b 40 08          	mov    0x8(%rax),%rax
    278c:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    if(context->ocall_flag != OCALL_FLAG)
    2790:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2794:	48 8b 40 20          	mov    0x20(%rax),%rax
    2798:	48 3d 44 49 43 4f    	cmp    $0x4f434944,%rax
    279e:	74 05                	je     27a5 <_ZL16is_ecall_allowedj+0x96>
    {
        // abort the enclave if ocall frame is invalid
        abort();
    27a0:	e8 29 a2 00 00       	callq  c9ce <abort>
    }
    uintptr_t ocall_index = context->ocall_index;
    27a5:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    27a9:	48 8b 40 28          	mov    0x28(%rax),%rax
    27ad:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if(ocall_index >= g_dyn_entry_table.nr_ocall)
    27b1:	48 8d 05 48 a8 00 00 	lea    0xa848(%rip),%rax        # d000 <g_dyn_entry_table>
    27b8:	48 8b 00             	mov    (%rax),%rax
    27bb:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    27bf:	72 07                	jb     27c8 <_ZL16is_ecall_allowedj+0xb9>
    {
        return SGX_ERROR_INVALID_FUNCTION;
    27c1:	b8 01 10 00 00       	mov    $0x1001,%eax
    27c6:	eb 35                	jmp    27fd <_ZL16is_ecall_allowedj+0xee>
    }
    return (g_dyn_entry_table.entry_table[ocall_index * g_ecall_table.nr_ecall + ordinal] ? SGX_SUCCESS : SGX_ERROR_ECALL_NOT_ALLOWED);
    27c8:	48 8d 05 f1 e5 00 00 	lea    0xe5f1(%rip),%rax        # 10dc0 <g_ecall_table>
    27cf:	48 8b 00             	mov    (%rax),%rax
    27d2:	48 0f af 45 f8       	imul   -0x8(%rbp),%rax
    27d7:	48 89 c2             	mov    %rax,%rdx
    27da:	8b 45 dc             	mov    -0x24(%rbp),%eax
    27dd:	48 01 c2             	add    %rax,%rdx
    27e0:	48 8d 05 19 a8 00 00 	lea    0xa819(%rip),%rax        # d000 <g_dyn_entry_table>
    27e7:	0f b6 44 10 08       	movzbl 0x8(%rax,%rdx,1),%eax
    27ec:	84 c0                	test   %al,%al
    27ee:	74 07                	je     27f7 <_ZL16is_ecall_allowedj+0xe8>
    27f0:	b8 00 00 00 00       	mov    $0x0,%eax
    27f5:	eb 05                	jmp    27fc <_ZL16is_ecall_allowedj+0xed>
    27f7:	b8 07 10 00 00       	mov    $0x1007,%eax
    27fc:	90                   	nop
}
    27fd:	c9                   	leaveq 
    27fe:	c3                   	retq   

00000000000027ff <_ZL13get_func_addrjPPv>:
// Return Value:
//      non-zero - success
//      zero - fail
//
static sgx_status_t get_func_addr(uint32_t ordinal, void **addr)
{
    27ff:	55                   	push   %rbp
    2800:	48 89 e5             	mov    %rsp,%rbp
    2803:	48 83 ec 20          	sub    $0x20,%rsp
    2807:	89 7d ec             	mov    %edi,-0x14(%rbp)
    280a:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    if(ordinal == (uint32_t)ECMD_ECALL_PTHREAD)
    280e:	83 7d ec fa          	cmpl   $0xfffffffa,-0x14(%rbp)
    2812:	75 15                	jne    2829 <_ZL13get_func_addrjPPv+0x2a>
    {
        *addr = (void*) _pthread_thread_run;
    2814:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    2818:	48 8d 15 a4 fe ff ff 	lea    -0x15c(%rip),%rdx        # 26c3 <_pthread_thread_run>
    281f:	48 89 10             	mov    %rdx,(%rax)
        return SGX_SUCCESS;
    2822:	b8 00 00 00 00       	mov    $0x0,%eax
    2827:	eb 60                	jmp    2889 <_ZL13get_func_addrjPPv+0x8a>
    }

    // Normal user-defined ECalls
    sgx_status_t status = is_ecall_allowed(ordinal);
    2829:	8b 45 ec             	mov    -0x14(%rbp),%eax
    282c:	89 c7                	mov    %eax,%edi
    282e:	e8 dc fe ff ff       	callq  270f <_ZL16is_ecall_allowedj>
    2833:	89 45 fc             	mov    %eax,-0x4(%rbp)
    if(SGX_SUCCESS != status)
    2836:	83 7d fc 00          	cmpl   $0x0,-0x4(%rbp)
    283a:	74 05                	je     2841 <_ZL13get_func_addrjPPv+0x42>
    {
        return status;
    283c:	8b 45 fc             	mov    -0x4(%rbp),%eax
    283f:	eb 48                	jmp    2889 <_ZL13get_func_addrjPPv+0x8a>
    }

    *addr = const_cast<void *>(g_ecall_table.ecall_table[ordinal].ecall_addr);
    2841:	48 8d 05 78 e5 00 00 	lea    0xe578(%rip),%rax        # 10dc0 <g_ecall_table>
    2848:	8b 55 ec             	mov    -0x14(%rbp),%edx
    284b:	48 c1 e2 04          	shl    $0x4,%rdx
    284f:	48 01 d0             	add    %rdx,%rax
    2852:	48 83 c0 08          	add    $0x8,%rax
    2856:	48 8b 10             	mov    (%rax),%rdx
    2859:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    285d:	48 89 10             	mov    %rdx,(%rax)
    if(!sgx_is_within_enclave(*addr, 0))
    2860:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    2864:	48 8b 00             	mov    (%rax),%rax
    2867:	be 00 00 00 00       	mov    $0x0,%esi
    286c:	48 89 c7             	mov    %rax,%rdi
    286f:	e8 91 ea ff ff       	callq  1305 <sgx_is_within_enclave>
    2874:	85 c0                	test   %eax,%eax
    2876:	0f 94 c0             	sete   %al
    2879:	84 c0                	test   %al,%al
    287b:	74 07                	je     2884 <_ZL13get_func_addrjPPv+0x85>
    {
        return SGX_ERROR_UNEXPECTED;
    287d:	b8 01 00 00 00       	mov    $0x1,%eax
    2882:	eb 05                	jmp    2889 <_ZL13get_func_addrjPPv+0x8a>
    }

    return SGX_SUCCESS;
    2884:	b8 00 00 00 00       	mov    $0x0,%eax
}
    2889:	c9                   	leaveq 
    288a:	c3                   	retq   

000000000000288b <_Z11do_save_tcsPv>:
// Return Value:
//     zero - success
//     non-zero - fail
//
sgx_status_t do_save_tcs(void *ptcs)
{
    288b:	55                   	push   %rbp
    288c:	48 89 e5             	mov    %rsp,%rbp
    288f:	48 83 ec 30          	sub    $0x30,%rsp
    2893:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    2897:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    289e:	00 00 
    28a0:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    28a4:	31 c0                	xor    %eax,%eax
    if(!is_utility_thread())
    28a6:	e8 1c 14 00 00       	callq  3cc7 <is_utility_thread>
    28ab:	83 f0 01             	xor    $0x1,%eax
    28ae:	84 c0                	test   %al,%al
    28b0:	74 0a                	je     28bc <_Z11do_save_tcsPv+0x31>
        return SGX_ERROR_UNEXPECTED;
    28b2:	b8 01 00 00 00       	mov    $0x1,%eax
    28b7:	e9 b0 00 00 00       	jmpq   296c <_Z11do_save_tcsPv+0xe1>

    if(unlikely(g_tcs_cookie == 0))
    28bc:	48 8b 05 05 e8 00 00 	mov    0xe805(%rip),%rax        # 110c8 <_ZL12g_tcs_cookie>
    28c3:	48 85 c0             	test   %rax,%rax
    28c6:	0f 94 c0             	sete   %al
    28c9:	0f b6 c0             	movzbl %al,%eax
    28cc:	48 85 c0             	test   %rax,%rax
    28cf:	74 4b                	je     291c <_Z11do_save_tcsPv+0x91>
    {
        uintptr_t rand = 0;
    28d1:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    28d8:	00 
        do
        {
            if(SGX_SUCCESS != sgx_read_rand((unsigned char *)&rand, sizeof(rand)))
    28d9:	48 8d 45 e8          	lea    -0x18(%rbp),%rax
    28dd:	be 08 00 00 00       	mov    $0x8,%esi
    28e2:	48 89 c7             	mov    %rax,%rdi
    28e5:	e8 e1 ec ff ff       	callq  15cb <sgx_read_rand>
    28ea:	85 c0                	test   %eax,%eax
    28ec:	0f 95 c0             	setne  %al
    28ef:	84 c0                	test   %al,%al
    28f1:	74 07                	je     28fa <_Z11do_save_tcsPv+0x6f>
            {
                return SGX_ERROR_UNEXPECTED;
    28f3:	b8 01 00 00 00       	mov    $0x1,%eax
    28f8:	eb 72                	jmp    296c <_Z11do_save_tcsPv+0xe1>
            }
        } while(rand == 0);
    28fa:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    28fe:	48 85 c0             	test   %rax,%rax
    2901:	75 02                	jne    2905 <_Z11do_save_tcsPv+0x7a>
        do
    2903:	eb d4                	jmp    28d9 <_Z11do_save_tcsPv+0x4e>

        if(g_tcs_cookie == 0)
    2905:	48 8b 05 bc e7 00 00 	mov    0xe7bc(%rip),%rax        # 110c8 <_ZL12g_tcs_cookie>
    290c:	48 85 c0             	test   %rax,%rax
    290f:	75 0b                	jne    291c <_Z11do_save_tcsPv+0x91>
        {
            g_tcs_cookie = rand;
    2911:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2915:	48 89 05 ac e7 00 00 	mov    %rax,0xe7ac(%rip)        # 110c8 <_ZL12g_tcs_cookie>
        }
    }

    tcs_node_t *tcs_node = (tcs_node_t *)malloc(sizeof(tcs_node_t));
    291c:	bf 10 00 00 00       	mov    $0x10,%edi
    2921:	e8 82 64 00 00       	callq  8da8 <dlmalloc>
    2926:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    if(!tcs_node)
    292a:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    292f:	75 07                	jne    2938 <_Z11do_save_tcsPv+0xad>
    {
        return SGX_ERROR_UNEXPECTED;
    2931:	b8 01 00 00 00       	mov    $0x1,%eax
    2936:	eb 34                	jmp    296c <_Z11do_save_tcsPv+0xe1>
    }

    tcs_node->tcs = ENC_TCS_POINTER(ptcs);
    2938:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    293c:	48 8b 05 85 e7 00 00 	mov    0xe785(%rip),%rax        # 110c8 <_ZL12g_tcs_cookie>
    2943:	48 31 c2             	xor    %rax,%rdx
    2946:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    294a:	48 89 10             	mov    %rdx,(%rax)

    tcs_node->next = g_tcs_node;
    294d:	48 8b 15 6c e7 00 00 	mov    0xe76c(%rip),%rdx        # 110c0 <_ZL10g_tcs_node>
    2954:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2958:	48 89 50 08          	mov    %rdx,0x8(%rax)
    g_tcs_node = tcs_node;
    295c:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2960:	48 89 05 59 e7 00 00 	mov    %rax,0xe759(%rip)        # 110c0 <_ZL10g_tcs_node>

    return SGX_SUCCESS;
    2967:	b8 00 00 00 00       	mov    $0x0,%eax
}
    296c:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    2970:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    2977:	00 00 
    2979:	74 05                	je     2980 <_Z11do_save_tcsPv+0xf5>
    297b:	e8 5a 29 00 00       	callq  52da <__stack_chk_fail>
    2980:	c9                   	leaveq 
    2981:	c3                   	retq   

0000000000002982 <_ZL10do_del_tcsPv>:
//      [IN] ptcs - the tcs_t pointer which need to be deleted
// Return Value:
//     N/A
//
static void do_del_tcs(void *ptcs)
{
    2982:	55                   	push   %rbp
    2983:	48 89 e5             	mov    %rsp,%rbp
    2986:	48 83 ec 30          	sub    $0x30,%rsp
    298a:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    if(!is_utility_thread())
    298e:	e8 34 13 00 00       	callq  3cc7 <is_utility_thread>
    2993:	83 f0 01             	xor    $0x1,%eax
    2996:	84 c0                	test   %al,%al
    2998:	0f 85 c1 00 00 00    	jne    2a5f <_ZL10do_del_tcsPv+0xdd>
        return;

    if (g_tcs_node != NULL)
    299e:	48 8b 05 1b e7 00 00 	mov    0xe71b(%rip),%rax        # 110c0 <_ZL10g_tcs_node>
    29a5:	48 85 c0             	test   %rax,%rax
    29a8:	0f 84 b2 00 00 00    	je     2a60 <_ZL10do_del_tcsPv+0xde>
    {
        if (DEC_TCS_POINTER(g_tcs_node->tcs) == ptcs)
    29ae:	48 8b 05 0b e7 00 00 	mov    0xe70b(%rip),%rax        # 110c0 <_ZL10g_tcs_node>
    29b5:	48 8b 10             	mov    (%rax),%rdx
    29b8:	48 8b 05 09 e7 00 00 	mov    0xe709(%rip),%rax        # 110c8 <_ZL12g_tcs_cookie>
    29bf:	48 31 d0             	xor    %rdx,%rax
    29c2:	48 39 45 d8          	cmp    %rax,-0x28(%rbp)
    29c6:	75 2b                	jne    29f3 <_ZL10do_del_tcsPv+0x71>
        {
            tcs_node_t *tmp = g_tcs_node;
    29c8:	48 8b 05 f1 e6 00 00 	mov    0xe6f1(%rip),%rax        # 110c0 <_ZL10g_tcs_node>
    29cf:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
            g_tcs_node = g_tcs_node->next;
    29d3:	48 8b 05 e6 e6 00 00 	mov    0xe6e6(%rip),%rax        # 110c0 <_ZL10g_tcs_node>
    29da:	48 8b 40 08          	mov    0x8(%rax),%rax
    29de:	48 89 05 db e6 00 00 	mov    %rax,0xe6db(%rip)        # 110c0 <_ZL10g_tcs_node>
            free(tmp);
    29e5:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    29e9:	48 89 c7             	mov    %rax,%rdi
    29ec:	e8 ae 6e 00 00       	callq  989f <dlfree>
    29f1:	eb 6d                	jmp    2a60 <_ZL10do_del_tcsPv+0xde>
        }
        else
        {
            tcs_node_t *tcs_node = g_tcs_node->next;
    29f3:	48 8b 05 c6 e6 00 00 	mov    0xe6c6(%rip),%rax        # 110c0 <_ZL10g_tcs_node>
    29fa:	48 8b 40 08          	mov    0x8(%rax),%rax
    29fe:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
            tcs_node_t *pre_tcs_node = g_tcs_node;
    2a02:	48 8b 05 b7 e6 00 00 	mov    0xe6b7(%rip),%rax        # 110c0 <_ZL10g_tcs_node>
    2a09:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
            while (tcs_node != NULL)
    2a0d:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    2a12:	74 4c                	je     2a60 <_ZL10do_del_tcsPv+0xde>
            {
                if (DEC_TCS_POINTER(tcs_node->tcs) == ptcs)
    2a14:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2a18:	48 8b 10             	mov    (%rax),%rdx
    2a1b:	48 8b 05 a6 e6 00 00 	mov    0xe6a6(%rip),%rax        # 110c8 <_ZL12g_tcs_cookie>
    2a22:	48 31 d0             	xor    %rdx,%rax
    2a25:	48 39 45 d8          	cmp    %rax,-0x28(%rbp)
    2a29:	75 1e                	jne    2a49 <_ZL10do_del_tcsPv+0xc7>
                {
                    pre_tcs_node->next = tcs_node->next;
    2a2b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2a2f:	48 8b 50 08          	mov    0x8(%rax),%rdx
    2a33:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2a37:	48 89 50 08          	mov    %rdx,0x8(%rax)
                    free(tcs_node);
    2a3b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2a3f:	48 89 c7             	mov    %rax,%rdi
    2a42:	e8 58 6e 00 00       	callq  989f <dlfree>
                    break;
    2a47:	eb 17                	jmp    2a60 <_ZL10do_del_tcsPv+0xde>
                }

                pre_tcs_node = tcs_node;
    2a49:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2a4d:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
                tcs_node = tcs_node->next;
    2a51:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2a55:	48 8b 40 08          	mov    0x8(%rax),%rax
    2a59:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
            while (tcs_node != NULL)
    2a5d:	eb ae                	jmp    2a0d <_ZL10do_del_tcsPv+0x8b>
        return;
    2a5f:	90                   	nop
            }
        }
    }
}
    2a60:	c9                   	leaveq 
    2a61:	c3                   	retq   

0000000000002a62 <_ZL10trts_ecalljPv>:
static volatile bool           g_is_first_ecall = true;
static volatile sgx_spinlock_t g_ife_lock       = SGX_SPINLOCK_INITIALIZER;

typedef sgx_status_t (*ecall_func_t)(void *ms);
static sgx_status_t trts_ecall(uint32_t ordinal, void *ms)
{
    2a62:	55                   	push   %rbp
    2a63:	48 89 e5             	mov    %rsp,%rbp
    2a66:	48 83 ec 40          	sub    $0x40,%rsp
    2a6a:	89 7d cc             	mov    %edi,-0x34(%rbp)
    2a6d:	48 89 75 c0          	mov    %rsi,-0x40(%rbp)
    2a71:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    2a78:	00 00 
    2a7a:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    2a7e:	31 c0                	xor    %eax,%eax
    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    2a80:	c7 45 d4 01 00 00 00 	movl   $0x1,-0x2c(%rbp)

    if (unlikely(g_is_first_ecall))
    2a87:	0f b6 05 72 e5 00 00 	movzbl 0xe572(%rip),%eax        # 11000 <_ZL16g_is_first_ecall>
    2a8e:	0f b6 c0             	movzbl %al,%eax
    2a91:	48 85 c0             	test   %rax,%rax
    2a94:	0f 95 c0             	setne  %al
    2a97:	84 c0                	test   %al,%al
    2a99:	0f 84 9a 00 00 00    	je     2b39 <_ZL10trts_ecalljPv+0xd7>
    {
        // The thread performing the global initialization cannot do a nested ECall
        thread_data_t *thread_data = get_thread_data();
    2a9f:	e8 fb 9b 00 00       	callq  c69f <get_thread_data>
    2aa4:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
        if (thread_data->last_sp != thread_data->stack_base_addr)
    2aa8:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    2aac:	48 8b 50 08          	mov    0x8(%rax),%rdx
    2ab0:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    2ab4:	48 8b 40 10          	mov    0x10(%rax),%rax
    2ab8:	48 39 c2             	cmp    %rax,%rdx
    2abb:	74 0a                	je     2ac7 <_ZL10trts_ecalljPv+0x65>
        { // nested ecall
            return SGX_ERROR_ECALL_NOT_ALLOWED;
    2abd:	b8 07 10 00 00       	mov    $0x1007,%eax
    2ac2:	e9 b2 00 00 00       	jmpq   2b79 <_ZL10trts_ecalljPv+0x117>
        }

        sgx_spin_lock(&g_ife_lock);
    2ac7:	48 8d 3d 02 e6 00 00 	lea    0xe602(%rip),%rdi        # 110d0 <_ZL10g_ife_lock>
    2ace:	e8 2c 89 00 00       	callq  b3ff <sgx_spin_lock>
        if (g_is_first_ecall)
    2ad3:	0f b6 05 26 e5 00 00 	movzbl 0xe526(%rip),%eax        # 11000 <_ZL16g_is_first_ecall>
    2ada:	84 c0                	test   %al,%al
    2adc:	74 4f                	je     2b2d <_ZL10trts_ecalljPv+0xcb>
        {
#ifndef SE_SIM
            if(EDMM_supported)
    2ade:	48 8d 05 0b e3 00 00 	lea    0xe30b(%rip),%rax        # 10df0 <EDMM_supported>
    2ae5:	8b 00                	mov    (%rax),%eax
    2ae7:	85 c0                	test   %eax,%eax
    2ae9:	74 36                	je     2b21 <_ZL10trts_ecalljPv+0xbf>
            {
                //change back the page permission
                size_t enclave_start = (size_t)&__ImageBase;
    2aeb:	48 8d 05 0e d5 ff ff 	lea    -0x2af2(%rip),%rax        # 0 <enclave.so>
    2af2:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
                if((status = change_protection((void *)enclave_start)) != SGX_SUCCESS)
    2af6:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2afa:	48 89 c7             	mov    %rax,%rdi
    2afd:	e8 13 23 00 00       	callq  4e15 <change_protection>
    2b02:	89 45 d4             	mov    %eax,-0x2c(%rbp)
    2b05:	83 7d d4 00          	cmpl   $0x0,-0x2c(%rbp)
    2b09:	0f 95 c0             	setne  %al
    2b0c:	84 c0                	test   %al,%al
    2b0e:	74 11                	je     2b21 <_ZL10trts_ecalljPv+0xbf>
                {
                    sgx_spin_unlock(&g_ife_lock);
    2b10:	48 8d 3d b9 e5 00 00 	lea    0xe5b9(%rip),%rdi        # 110d0 <_ZL10g_ife_lock>
    2b17:	e8 4a 89 00 00       	callq  b466 <sgx_spin_unlock>
                    return status;
    2b1c:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    2b1f:	eb 58                	jmp    2b79 <_ZL10trts_ecalljPv+0x117>
                }
            }
#endif
            //invoke global object's construction
            init_global_object();
    2b21:	e8 97 27 00 00       	callq  52bd <init_global_object>
            g_is_first_ecall = false;
    2b26:	c6 05 d3 e4 00 00 00 	movb   $0x0,0xe4d3(%rip)        # 11000 <_ZL16g_is_first_ecall>
        }
        sgx_spin_unlock(&g_ife_lock);
    2b2d:	48 8d 3d 9c e5 00 00 	lea    0xe59c(%rip),%rdi        # 110d0 <_ZL10g_ife_lock>
    2b34:	e8 2d 89 00 00       	callq  b466 <sgx_spin_unlock>
    }

    void *addr = NULL;
    2b39:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    2b40:	00 
    status = get_func_addr(ordinal, &addr);
    2b41:	48 8d 55 d8          	lea    -0x28(%rbp),%rdx
    2b45:	8b 45 cc             	mov    -0x34(%rbp),%eax
    2b48:	48 89 d6             	mov    %rdx,%rsi
    2b4b:	89 c7                	mov    %eax,%edi
    2b4d:	e8 ad fc ff ff       	callq  27ff <_ZL13get_func_addrjPPv>
    2b52:	89 45 d4             	mov    %eax,-0x2c(%rbp)
    if(status == SGX_SUCCESS)
    2b55:	83 7d d4 00          	cmpl   $0x0,-0x2c(%rbp)
    2b59:	75 1b                	jne    2b76 <_ZL10trts_ecalljPv+0x114>
    {
        ecall_func_t func = (ecall_func_t)addr;
    2b5b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2b5f:	48 89 45 f0          	mov    %rax,-0x10(%rbp)

        sgx_lfence();
    2b63:	0f ae e8             	lfence 

        status = func(ms);
    2b66:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    2b6a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    2b6e:	48 89 d7             	mov    %rdx,%rdi
    2b71:	ff d0                	callq  *%rax
    2b73:	89 45 d4             	mov    %eax,-0x2c(%rbp)
    }
    
    return status;
    2b76:	8b 45 d4             	mov    -0x2c(%rbp),%eax
}
    2b79:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    2b7d:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    2b84:	00 00 
    2b86:	74 05                	je     2b8d <_ZL10trts_ecalljPv+0x12b>
    2b88:	e8 4d 27 00 00       	callq  52da <__stack_chk_fail>
    2b8d:	c9                   	leaveq 
    2b8e:	c3                   	retq   

0000000000002b8f <_ZL24init_static_stack_canaryPv>:

extern "C" uintptr_t __stack_chk_guard;
static void init_static_stack_canary(void *tcs)
{
    2b8f:	55                   	push   %rbp
    2b90:	48 89 e5             	mov    %rsp,%rbp
    2b93:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    size_t *canary = TCS2CANARY(tcs);
    2b97:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2b9b:	48 2d a8 02 01 00    	sub    $0x102a8,%rax
    2ba1:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    *canary = (size_t)__stack_chk_guard;
    2ba5:	48 8d 05 54 e2 00 00 	lea    0xe254(%rip),%rax        # 10e00 <__intel_security_cookie>
    2bac:	48 8b 10             	mov    (%rax),%rdx
    2baf:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    2bb3:	48 89 10             	mov    %rdx,(%rax)
}
    2bb6:	90                   	nop
    2bb7:	5d                   	pop    %rbp
    2bb8:	c3                   	retq   

0000000000002bb9 <do_init_thread>:

sgx_status_t do_init_thread(void *tcs, bool enclave_init)
{
    2bb9:	55                   	push   %rbp
    2bba:	48 89 e5             	mov    %rsp,%rbp
    2bbd:	48 83 ec 50          	sub    $0x50,%rsp
    2bc1:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    2bc5:	89 f0                	mov    %esi,%eax
    2bc7:	88 45 b4             	mov    %al,-0x4c(%rbp)
    2bca:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    2bd1:	00 00 
    2bd3:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    2bd7:	31 c0                	xor    %eax,%eax
    thread_data_t *thread_data = GET_PTR(thread_data_t, tcs, g_global_data.td_template.self_addr);
    2bd9:	48 8d 05 a0 a5 00 00 	lea    0xa5a0(%rip),%rax        # d180 <g_global_data>
    2be0:	48 8b 50 40          	mov    0x40(%rax),%rdx
    2be4:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2be8:	48 01 d0             	add    %rdx,%rax
    2beb:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
#ifndef SE_SIM
    size_t saved_stack_commit_addr = thread_data->stack_commit_addr;
    2bef:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2bf3:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    2bfa:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    bool thread_first_init = (saved_stack_commit_addr == 0) ? true : false;
    2bfe:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
    2c03:	0f 94 c0             	sete   %al
    2c06:	88 45 c3             	mov    %al,-0x3d(%rbp)
#endif
    size_t stack_guard = thread_data->stack_guard;
    2c09:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c0d:	48 8b 40 28          	mov    0x28(%rax),%rax
    2c11:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    size_t thread_flags = thread_data->flags;
    2c15:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c19:	48 8b 40 30          	mov    0x30(%rax),%rax
    2c1d:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    memcpy_s(thread_data, SE_PAGE_SIZE, const_cast<thread_data_t *>(&g_global_data.td_template), sizeof(thread_data_t));
    2c21:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c25:	b9 a0 00 00 00       	mov    $0xa0,%ecx
    2c2a:	48 8d 15 4f a5 00 00 	lea    0xa54f(%rip),%rdx        # d180 <g_global_data>
    2c31:	48 8d 52 40          	lea    0x40(%rdx),%rdx
    2c35:	be 00 10 00 00       	mov    $0x1000,%esi
    2c3a:	48 89 c7             	mov    %rax,%rdi
    2c3d:	e8 3a fa ff ff       	callq  267c <memcpy_s>
    thread_data->last_sp += (size_t)tcs;
    2c42:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c46:	48 8b 50 08          	mov    0x8(%rax),%rdx
    2c4a:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2c4e:	48 01 c2             	add    %rax,%rdx
    2c51:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c55:	48 89 50 08          	mov    %rdx,0x8(%rax)
    thread_data->self_addr += (size_t)tcs;
    2c59:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c5d:	48 8b 10             	mov    (%rax),%rdx
    2c60:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2c64:	48 01 c2             	add    %rax,%rdx
    2c67:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c6b:	48 89 10             	mov    %rdx,(%rax)
    thread_data->stack_base_addr += (size_t)tcs;
    2c6e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c72:	48 8b 50 10          	mov    0x10(%rax),%rdx
    2c76:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2c7a:	48 01 c2             	add    %rax,%rdx
    2c7d:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c81:	48 89 50 10          	mov    %rdx,0x10(%rax)
    thread_data->stack_limit_addr += (size_t)tcs;
    2c85:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c89:	48 8b 50 18          	mov    0x18(%rax),%rdx
    2c8d:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2c91:	48 01 c2             	add    %rax,%rdx
    2c94:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2c98:	48 89 50 18          	mov    %rdx,0x18(%rax)
    thread_data->stack_commit_addr = thread_data->stack_limit_addr;
    2c9c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2ca0:	48 8b 50 18          	mov    0x18(%rax),%rdx
    2ca4:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2ca8:	48 89 90 98 00 00 00 	mov    %rdx,0x98(%rax)
    thread_data->first_ssa_gpr += (size_t)tcs;
    2caf:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2cb3:	48 8b 50 20          	mov    0x20(%rax),%rdx
    2cb7:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2cbb:	48 01 c2             	add    %rax,%rdx
    2cbe:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2cc2:	48 89 50 20          	mov    %rdx,0x20(%rax)
    thread_data->tls_array += (size_t)tcs;
    2cc6:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2cca:	48 8b 50 58          	mov    0x58(%rax),%rdx
    2cce:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2cd2:	48 01 c2             	add    %rax,%rdx
    2cd5:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2cd9:	48 89 50 58          	mov    %rdx,0x58(%rax)
    thread_data->tls_addr += (size_t)tcs;
    2cdd:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2ce1:	48 8b 50 50          	mov    0x50(%rax),%rdx
    2ce5:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2ce9:	48 01 c2             	add    %rax,%rdx
    2cec:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2cf0:	48 89 50 50          	mov    %rdx,0x50(%rax)
    thread_data->last_sp -= (size_t)STATIC_STACK_SIZE;
    2cf4:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2cf8:	48 8b 40 08          	mov    0x8(%rax),%rax
    2cfc:	48 8d 90 50 fd ff ff 	lea    -0x2b0(%rax),%rdx
    2d03:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2d07:	48 89 50 08          	mov    %rdx,0x8(%rax)
    thread_data->stack_base_addr -= (size_t)STATIC_STACK_SIZE;
    2d0b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2d0f:	48 8b 40 10          	mov    0x10(%rax),%rax
    2d13:	48 8d 90 50 fd ff ff 	lea    -0x2b0(%rax),%rdx
    2d1a:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2d1e:	48 89 50 10          	mov    %rdx,0x10(%rax)
    thread_data->stack_guard = stack_guard;
    2d22:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2d26:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    2d2a:	48 89 50 28          	mov    %rdx,0x28(%rax)
    thread_data->flags = thread_flags;
    2d2e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2d32:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    2d36:	48 89 50 30          	mov    %rdx,0x30(%rax)
    init_static_stack_canary(tcs);
    2d3a:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2d3e:	48 89 c7             	mov    %rax,%rdi
    2d41:	e8 49 fe ff ff       	callq  2b8f <_ZL24init_static_stack_canaryPv>

    if (EDMM_supported && enclave_init)
    2d46:	48 8d 05 a3 e0 00 00 	lea    0xe0a3(%rip),%rax        # 10df0 <EDMM_supported>
    2d4d:	8b 00                	mov    (%rax),%eax
    2d4f:	85 c0                	test   %eax,%eax
    2d51:	74 12                	je     2d65 <do_init_thread+0x1ac>
    2d53:	80 7d b4 00          	cmpb   $0x0,-0x4c(%rbp)
    2d57:	74 0c                	je     2d65 <do_init_thread+0x1ac>
    {
        thread_data->flags = SGX_UTILITY_THREAD;
    2d59:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2d5d:	48 c7 40 30 01 00 00 	movq   $0x1,0x30(%rax)
    2d64:	00 
    }
#ifndef SE_SIM
    if (thread_first_init)
    2d65:	80 7d c3 00          	cmpb   $0x0,-0x3d(%rbp)
    2d69:	74 5d                	je     2dc8 <do_init_thread+0x20f>
    {
        if (EDMM_supported && (enclave_init || is_dynamic_thread(tcs)))
    2d6b:	48 8d 05 7e e0 00 00 	lea    0xe07e(%rip),%rax        # 10df0 <EDMM_supported>
    2d72:	8b 00                	mov    (%rax),%eax
    2d74:	85 c0                	test   %eax,%eax
    2d76:	74 1d                	je     2d95 <do_init_thread+0x1dc>
    2d78:	80 7d b4 00          	cmpb   $0x0,-0x4c(%rbp)
    2d7c:	75 10                	jne    2d8e <do_init_thread+0x1d5>
    2d7e:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    2d82:	48 89 c7             	mov    %rax,%rdi
    2d85:	e8 30 f2 ff ff       	callq  1fba <is_dynamic_thread>
    2d8a:	85 c0                	test   %eax,%eax
    2d8c:	74 07                	je     2d95 <do_init_thread+0x1dc>
    2d8e:	b8 01 00 00 00       	mov    $0x1,%eax
    2d93:	eb 05                	jmp    2d9a <do_init_thread+0x1e1>
    2d95:	b8 00 00 00 00       	mov    $0x0,%eax
    2d9a:	84 c0                	test   %al,%al
    2d9c:	74 39                	je     2dd7 <do_init_thread+0x21e>
        {
            uint32_t page_count = get_dynamic_stack_max_page();
    2d9e:	e8 d7 f2 ff ff       	callq  207a <get_dynamic_stack_max_page>
    2da3:	89 45 c4             	mov    %eax,-0x3c(%rbp)
            thread_data->stack_commit_addr += ((sys_word_t)page_count << SE_PAGE_SHIFT);
    2da6:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2daa:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    2db1:	8b 55 c4             	mov    -0x3c(%rbp),%edx
    2db4:	48 c1 e2 0c          	shl    $0xc,%rdx
    2db8:	48 01 c2             	add    %rax,%rdx
    2dbb:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2dbf:	48 89 90 98 00 00 00 	mov    %rdx,0x98(%rax)
    2dc6:	eb 0f                	jmp    2dd7 <do_init_thread+0x21e>
        }
    }
    else
    {
        thread_data->stack_commit_addr = saved_stack_commit_addr;
    2dc8:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2dcc:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    2dd0:	48 89 90 98 00 00 00 	mov    %rdx,0x98(%rax)
    }
#endif

    uintptr_t tls_addr = 0;
    2dd7:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    2dde:	00 
    size_t tdata_size = 0;
    2ddf:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    2de6:	00 

    if(0 != GET_TLS_INFO(&__ImageBase, &tls_addr, &tdata_size))
    2de7:	48 8d 55 d0          	lea    -0x30(%rbp),%rdx
    2deb:	48 8d 45 c8          	lea    -0x38(%rbp),%rax
    2def:	48 89 c6             	mov    %rax,%rsi
    2df2:	48 8d 05 07 d2 ff ff 	lea    -0x2df9(%rip),%rax        # 0 <enclave.so>
    2df9:	48 89 c7             	mov    %rax,%rdi
    2dfc:	e8 80 1b 00 00       	callq  4981 <elf_tls_info>
    2e01:	85 c0                	test   %eax,%eax
    2e03:	0f 95 c0             	setne  %al
    2e06:	84 c0                	test   %al,%al
    2e08:	74 0a                	je     2e14 <do_init_thread+0x25b>
    {
        return SGX_ERROR_UNEXPECTED;
    2e0a:	b8 01 00 00 00       	mov    $0x1,%eax
    2e0f:	e9 83 00 00 00       	jmpq   2e97 <do_init_thread+0x2de>
    }
    if(tls_addr)
    2e14:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    2e18:	48 85 c0             	test   %rax,%rax
    2e1b:	74 75                	je     2e92 <do_init_thread+0x2d9>
    {
        memset((void *)TRIM_TO_PAGE(thread_data->tls_addr), 0, ROUND_TO_PAGE(thread_data->self_addr - thread_data->tls_addr));
    2e1d:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2e21:	48 8b 10             	mov    (%rax),%rdx
    2e24:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2e28:	48 8b 40 50          	mov    0x50(%rax),%rax
    2e2c:	48 29 c2             	sub    %rax,%rdx
    2e2f:	48 89 d0             	mov    %rdx,%rax
    2e32:	48 05 ff 0f 00 00    	add    $0xfff,%rax
    2e38:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    2e3e:	48 89 c2             	mov    %rax,%rdx
    2e41:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2e45:	48 8b 40 50          	mov    0x50(%rax),%rax
    2e49:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    2e4f:	be 00 00 00 00       	mov    $0x0,%esi
    2e54:	48 89 c7             	mov    %rax,%rdi
    2e57:	e8 44 81 00 00       	callq  afa0 <memset>
        memcpy_s((void *)(thread_data->tls_addr), thread_data->self_addr - thread_data->tls_addr, (void *)tls_addr, tdata_size);
    2e5c:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    2e60:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    2e64:	49 89 d0             	mov    %rdx,%r8
    2e67:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    2e6b:	48 8b 0a             	mov    (%rdx),%rcx
    2e6e:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    2e72:	48 8b 52 50          	mov    0x50(%rdx),%rdx
    2e76:	48 29 d1             	sub    %rdx,%rcx
    2e79:	48 89 ce             	mov    %rcx,%rsi
    2e7c:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    2e80:	48 8b 52 50          	mov    0x50(%rdx),%rdx
    2e84:	48 89 d7             	mov    %rdx,%rdi
    2e87:	48 89 c1             	mov    %rax,%rcx
    2e8a:	4c 89 c2             	mov    %r8,%rdx
    2e8d:	e8 ea f7 ff ff       	callq  267c <memcpy_s>
    }

    return SGX_SUCCESS;
    2e92:	b8 00 00 00 00       	mov    $0x0,%eax
}
    2e97:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    2e9b:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    2ea2:	00 00 
    2ea4:	74 05                	je     2eab <do_init_thread+0x2f2>
    2ea6:	e8 2f 24 00 00       	callq  52da <__stack_chk_fail>
    2eab:	c9                   	leaveq 
    2eac:	c3                   	retq   

0000000000002ead <do_ecall>:

sgx_status_t do_ecall(int index, void *ms, void *tcs)
{
    2ead:	55                   	push   %rbp
    2eae:	48 89 e5             	mov    %rsp,%rbp
    2eb1:	48 83 c4 80          	add    $0xffffffffffffff80,%rsp
    2eb5:	89 7d 9c             	mov    %edi,-0x64(%rbp)
    2eb8:	48 89 75 90          	mov    %rsi,-0x70(%rbp)
    2ebc:	48 89 55 88          	mov    %rdx,-0x78(%rbp)
    2ec0:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    2ec7:	00 00 
    2ec9:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    2ecd:	31 c0                	xor    %eax,%eax
    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    2ecf:	c7 45 a4 01 00 00 00 	movl   $0x1,-0x5c(%rbp)
    if(ENCLAVE_INIT_DONE != get_enclave_state())
    2ed6:	e8 91 97 00 00       	callq  c66c <get_enclave_state>
    2edb:	83 f8 02             	cmp    $0x2,%eax
    2ede:	0f 95 c0             	setne  %al
    2ee1:	84 c0                	test   %al,%al
    2ee3:	74 08                	je     2eed <do_ecall+0x40>
    {
        return status;
    2ee5:	8b 45 a4             	mov    -0x5c(%rbp),%eax
    2ee8:	e9 8c 01 00 00       	jmpq   3079 <do_ecall+0x1cc>
    }
    thread_data_t *thread_data = get_thread_data();
    2eed:	e8 ad 97 00 00       	callq  c69f <get_thread_data>
    2ef2:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    if( (NULL == thread_data) || 
    2ef6:	48 83 7d a8 00       	cmpq   $0x0,-0x58(%rbp)
    2efb:	74 37                	je     2f34 <do_ecall+0x87>
            ((thread_data->stack_base_addr == thread_data->last_sp) && 
    2efd:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    2f01:	48 8b 50 10          	mov    0x10(%rax),%rdx
    2f05:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    2f09:	48 8b 40 08          	mov    0x8(%rax),%rax
    if( (NULL == thread_data) || 
    2f0d:	48 39 c2             	cmp    %rax,%rdx
    2f10:	75 29                	jne    2f3b <do_ecall+0x8e>
                    ( (0 != g_global_data.thread_policy) ||
    2f12:	48 8d 05 67 a2 00 00 	lea    0xa267(%rip),%rax        # d180 <g_global_data>
    2f19:	48 8b 40 30          	mov    0x30(%rax),%rax
            ((thread_data->stack_base_addr == thread_data->last_sp) && 
    2f1d:	48 85 c0             	test   %rax,%rax
    2f20:	75 12                	jne    2f34 <do_ecall+0x87>
                       (SGX_PTHREAD_EXIT == _pthread_tls_get_state()) ||    /*Force do initial thread if previous ECALL is exited by pthread_exit()*/
    2f22:	e8 c0 f7 ff ff       	callq  26e7 <_Z22_pthread_tls_get_statev>
                    ( (0 != g_global_data.thread_policy) ||
    2f27:	83 f8 09             	cmp    $0x9,%eax
    2f2a:	74 08                	je     2f34 <do_ecall+0x87>
                        (index == ECMD_ECALL_PTHREAD))))  /*Force do initial thread if this thread is created by SGX pthread_create() */
    2f2c:	8b 45 9c             	mov    -0x64(%rbp),%eax
                       (SGX_PTHREAD_EXIT == _pthread_tls_get_state()) ||    /*Force do initial thread if previous ECALL is exited by pthread_exit()*/
    2f2f:	83 f8 fa             	cmp    $0xfffffffa,%eax
    2f32:	75 07                	jne    2f3b <do_ecall+0x8e>
    if( (NULL == thread_data) || 
    2f34:	b8 01 00 00 00       	mov    $0x1,%eax
    2f39:	eb 05                	jmp    2f40 <do_ecall+0x93>
    2f3b:	b8 00 00 00 00       	mov    $0x0,%eax
    2f40:	84 c0                	test   %al,%al
    2f42:	74 22                	je     2f66 <do_ecall+0xb9>
    {
        status = do_init_thread(tcs, false);
    2f44:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    2f48:	be 00 00 00 00       	mov    $0x0,%esi
    2f4d:	48 89 c7             	mov    %rax,%rdi
    2f50:	e8 64 fc ff ff       	callq  2bb9 <do_init_thread>
    2f55:	89 45 a4             	mov    %eax,-0x5c(%rbp)
        if(0 != status)
    2f58:	83 7d a4 00          	cmpl   $0x0,-0x5c(%rbp)
    2f5c:	74 08                	je     2f66 <do_ecall+0xb9>
        {
            return status;
    2f5e:	8b 45 a4             	mov    -0x5c(%rbp),%eax
    2f61:	e9 13 01 00 00       	jmpq   3079 <do_ecall+0x1cc>
        }
    }
    thread_data = get_thread_data();
    2f66:	e8 34 97 00 00       	callq  c69f <get_thread_data>
    2f6b:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    if(thread_data->stack_base_addr == thread_data->last_sp)
    2f6f:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    2f73:	48 8b 50 10          	mov    0x10(%rax),%rdx
    2f77:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    2f7b:	48 8b 40 08          	mov    0x8(%rax),%rax
    2f7f:	48 39 c2             	cmp    %rax,%rdx
    2f82:	0f 85 da 00 00 00    	jne    3062 <do_ecall+0x1b5>
    {
        //root ecall
        if(_pthread_enabled())
    2f88:	e8 45 f7 ff ff       	callq  26d2 <_Z16_pthread_enabledv>
    2f8d:	84 c0                	test   %al,%al
    2f8f:	0f 84 b1 00 00 00    	je     3046 <do_ecall+0x199>
        {
            jmp_buf     buf = {0};
    2f95:	48 c7 45 b0 00 00 00 	movq   $0x0,-0x50(%rbp)
    2f9c:	00 
    2f9d:	48 c7 45 b8 00 00 00 	movq   $0x0,-0x48(%rbp)
    2fa4:	00 
    2fa5:	48 c7 45 c0 00 00 00 	movq   $0x0,-0x40(%rbp)
    2fac:	00 
    2fad:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    2fb4:	00 
    2fb5:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    2fbc:	00 
    2fbd:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    2fc4:	00 
    2fc5:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    2fcc:	00 
    2fcd:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    2fd4:	00 
            if(0 == setjmp(buf))
    2fd5:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    2fd9:	48 89 c7             	mov    %rax,%rdi
    2fdc:	e8 9e 84 00 00       	callq  b47f <_setjmp>
    2fe1:	85 c0                	test   %eax,%eax
    2fe3:	0f 94 c0             	sete   %al
    2fe6:	84 c0                	test   %al,%al
    2fe8:	74 28                	je     3012 <do_ecall+0x165>
            {
                _pthread_tls_store_context((void*)buf);
    2fea:	48 8d 45 b0          	lea    -0x50(%rbp),%rax
    2fee:	48 89 c7             	mov    %rax,%rdi
    2ff1:	e8 fc f6 ff ff       	callq  26f2 <_Z26_pthread_tls_store_contextPv>
                status = random_stack_advance<0x800>(trts_ecall, index, ms);
    2ff6:	48 8d 55 90          	lea    -0x70(%rbp),%rdx
    2ffa:	48 8d 45 9c          	lea    -0x64(%rbp),%rax
    2ffe:	48 89 c6             	mov    %rax,%rsi
    3001:	48 8d 3d 5a fa ff ff 	lea    -0x5a6(%rip),%rdi        # 2a62 <_ZL10trts_ecalljPv>
    3008:	e8 78 04 00 00       	callq  3485 <_Z20random_stack_advanceILj2048E9_status_tJjPvEJRiRS1_EET0_PFS4_DpT1_EDpOT2_>
    300d:	89 45 a4             	mov    %eax,-0x5c(%rbp)
    3010:	eb 21                	jmp    3033 <do_ecall+0x186>
            }
            else
            {
                //Enter here if pthread_exit() is called inside ECALL functions.
                _pthread_tls_store_state(SGX_PTHREAD_EXIT);
    3012:	bf 09 00 00 00       	mov    $0x9,%edi
    3017:	e8 c1 f6 ff ff       	callq  26dd <_Z24_pthread_tls_store_state9_status_t>
                //Important: manually reset the last_sp
                thread_data->last_sp = thread_data->stack_base_addr;
    301c:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3020:	48 8b 50 10          	mov    0x10(%rax),%rdx
    3024:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    3028:	48 89 50 08          	mov    %rdx,0x8(%rax)
                status = SGX_PTHREAD_EXIT;
    302c:	c7 45 a4 09 00 00 00 	movl   $0x9,-0x5c(%rbp)
            }
            //-- execute some resource recycle function here, such as tls resource recycle
            _pthread_tls_destructors();
    3033:	e8 d0 f6 ff ff       	callq  2708 <_Z24_pthread_tls_destructorsv>
            _pthread_wakeup_join(ms); 
    3038:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    303c:	48 89 c7             	mov    %rax,%rdi
    303f:	e8 b9 f6 ff ff       	callq  26fd <_Z20_pthread_wakeup_joinPv>
    3044:	eb 30                	jmp    3076 <do_ecall+0x1c9>
        }
        else 
        {
            //sgx pthread lib isn't linked
            status = random_stack_advance<0x800>(trts_ecall, index, ms);
    3046:	48 8d 55 90          	lea    -0x70(%rbp),%rdx
    304a:	48 8d 45 9c          	lea    -0x64(%rbp),%rax
    304e:	48 89 c6             	mov    %rax,%rsi
    3051:	48 8d 3d 0a fa ff ff 	lea    -0x5f6(%rip),%rdi        # 2a62 <_ZL10trts_ecalljPv>
    3058:	e8 28 04 00 00       	callq  3485 <_Z20random_stack_advanceILj2048E9_status_tJjPvEJRiRS1_EET0_PFS4_DpT1_EDpOT2_>
    305d:	89 45 a4             	mov    %eax,-0x5c(%rbp)
    3060:	eb 14                	jmp    3076 <do_ecall+0x1c9>
        }
    }
    else
    {
        status = trts_ecall(index, ms);
    3062:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    3066:	8b 55 9c             	mov    -0x64(%rbp),%edx
    3069:	48 89 c6             	mov    %rax,%rsi
    306c:	89 d7                	mov    %edx,%edi
    306e:	e8 ef f9 ff ff       	callq  2a62 <_ZL10trts_ecalljPv>
    3073:	89 45 a4             	mov    %eax,-0x5c(%rbp)
    }
    return status;
    3076:	8b 45 a4             	mov    -0x5c(%rbp),%eax
}
    3079:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    307d:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    3084:	00 00 
    3086:	74 05                	je     308d <do_ecall+0x1e0>
    3088:	e8 4d 22 00 00       	callq  52da <__stack_chk_fail>
    308d:	c9                   	leaveq 
    308e:	c3                   	retq   

000000000000308f <do_ecall_add_thread>:

sgx_status_t do_ecall_add_thread(void *ms)
{
    308f:	55                   	push   %rbp
    3090:	48 89 e5             	mov    %rsp,%rbp
    3093:	48 83 ec 30          	sub    $0x30,%rsp
    3097:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    309b:	c7 45 e4 01 00 00 00 	movl   $0x1,-0x1c(%rbp)

    if(!is_utility_thread())
    30a2:	e8 20 0c 00 00       	callq  3cc7 <is_utility_thread>
    30a7:	83 f0 01             	xor    $0x1,%eax
    30aa:	84 c0                	test   %al,%al
    30ac:	74 08                	je     30b6 <do_ecall_add_thread+0x27>
        return status;
    30ae:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    30b1:	e9 9b 00 00 00       	jmpq   3151 <do_ecall_add_thread+0xc2>

    struct ms_tcs *tcs = (struct ms_tcs*)ms;
    30b6:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    30ba:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    if (tcs == NULL)
    30be:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    30c3:	75 08                	jne    30cd <do_ecall_add_thread+0x3e>
    {
        return status;
    30c5:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    30c8:	e9 84 00 00 00       	jmpq   3151 <do_ecall_add_thread+0xc2>
    }

    if (!sgx_is_outside_enclave(tcs, sizeof(struct ms_tcs)))
    30cd:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    30d1:	be 08 00 00 00       	mov    $0x8,%esi
    30d6:	48 89 c7             	mov    %rax,%rdi
    30d9:	e8 b7 e2 ff ff       	callq  1395 <sgx_is_outside_enclave>
    30de:	85 c0                	test   %eax,%eax
    30e0:	0f 94 c0             	sete   %al
    30e3:	84 c0                	test   %al,%al
    30e5:	74 05                	je     30ec <do_ecall_add_thread+0x5d>
    {
        return status;
    30e7:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    30ea:	eb 65                	jmp    3151 <do_ecall_add_thread+0xc2>
    }

    const struct ms_tcs mtcs = *tcs;
    30ec:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    30f0:	48 8b 00             	mov    (%rax),%rax
    30f3:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    void* ptcs = mtcs.ptcs;
    30f7:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    30fb:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if (ptcs == NULL)
    30ff:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    3104:	75 05                	jne    310b <do_ecall_add_thread+0x7c>
    {
        return status;
    3106:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    3109:	eb 46                	jmp    3151 <do_ecall_add_thread+0xc2>
    }

    sgx_lfence();
    310b:	0f ae e8             	lfence 

    status = do_save_tcs(ptcs);
    310e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3112:	48 89 c7             	mov    %rax,%rdi
    3115:	e8 71 f7 ff ff       	callq  288b <_Z11do_save_tcsPv>
    311a:	89 45 e4             	mov    %eax,-0x1c(%rbp)
    if(SGX_SUCCESS != status)
    311d:	83 7d e4 00          	cmpl   $0x0,-0x1c(%rbp)
    3121:	74 05                	je     3128 <do_ecall_add_thread+0x99>
    {
        return status;
    3123:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    3126:	eb 29                	jmp    3151 <do_ecall_add_thread+0xc2>
    }

    status = do_add_thread(ptcs);
    3128:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    312c:	48 89 c7             	mov    %rax,%rdi
    312f:	e8 07 f3 ff ff       	callq  243b <do_add_thread>
    3134:	89 45 e4             	mov    %eax,-0x1c(%rbp)
    if (SGX_SUCCESS != status)
    3137:	83 7d e4 00          	cmpl   $0x0,-0x1c(%rbp)
    313b:	74 11                	je     314e <do_ecall_add_thread+0xbf>
    {
    	do_del_tcs(ptcs);
    313d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3141:	48 89 c7             	mov    %rax,%rdi
    3144:	e8 39 f8 ff ff       	callq  2982 <_ZL10do_del_tcsPv>
        return status;
    3149:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    314c:	eb 03                	jmp    3151 <do_ecall_add_thread+0xc2>
    }

    return status;
    314e:	8b 45 e4             	mov    -0x1c(%rbp),%eax
}
    3151:	c9                   	leaveq 
    3152:	c3                   	retq   

0000000000003153 <do_uninit_enclave>:
// Return Value:
//     zero - success
//     non-zero - fail
//
sgx_status_t do_uninit_enclave(void *tcs)
{
    3153:	55                   	push   %rbp
    3154:	48 89 e5             	mov    %rsp,%rbp
    3157:	48 83 ec 40          	sub    $0x40,%rsp
    315b:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    // This function should only be called when
    //  1. EDMM is enabled
    //  2. on HW mode
    // urts would not call this ECALL either on simulation mode
    // or on non-EDMM supported platform.
    if (!EDMM_supported)
    315f:	48 8d 05 8a dc 00 00 	lea    0xdc8a(%rip),%rax        # 10df0 <EDMM_supported>
    3166:	8b 00                	mov    (%rax),%eax
    3168:	85 c0                	test   %eax,%eax
    316a:	75 14                	jne    3180 <do_uninit_enclave+0x2d>
    {
        set_enclave_state(ENCLAVE_CRASHED);
    316c:	bf 03 00 00 00       	mov    $0x3,%edi
    3171:	e8 03 95 00 00       	callq  c679 <set_enclave_state>
        return SGX_ERROR_UNEXPECTED;
    3176:	b8 01 00 00 00       	mov    $0x1,%eax
    317b:	e9 4c 01 00 00       	jmpq   32cc <do_uninit_enclave+0x179>
    }

    if(!is_utility_thread() && is_dynamic_thread_exist())
    3180:	e8 42 0b 00 00       	callq  3cc7 <is_utility_thread>
    3185:	83 f0 01             	xor    $0x1,%eax
    3188:	84 c0                	test   %al,%al
    318a:	74 10                	je     319c <do_uninit_enclave+0x49>
    318c:	e8 aa ee ff ff       	callq  203b <is_dynamic_thread_exist>
    3191:	85 c0                	test   %eax,%eax
    3193:	74 07                	je     319c <do_uninit_enclave+0x49>
    3195:	b8 01 00 00 00       	mov    $0x1,%eax
    319a:	eb 05                	jmp    31a1 <do_uninit_enclave+0x4e>
    319c:	b8 00 00 00 00       	mov    $0x0,%eax
    31a1:	84 c0                	test   %al,%al
    31a3:	74 14                	je     31b9 <do_uninit_enclave+0x66>
    {
        set_enclave_state(ENCLAVE_CRASHED);
    31a5:	bf 03 00 00 00       	mov    $0x3,%edi
    31aa:	e8 ca 94 00 00       	callq  c679 <set_enclave_state>
        return SGX_ERROR_UNEXPECTED;
    31af:	b8 01 00 00 00       	mov    $0x1,%eax
    31b4:	e9 13 01 00 00       	jmpq   32cc <do_uninit_enclave+0x179>
    }

    // Set uninit_flag to indicate the do_uninit_enclave is called
    __sync_or_and_fetch(&g_uninit_flag, 1);
    31b9:	f0 83 0d 13 df 00 00 	lock orl $0x1,0xdf13(%rip)        # 110d4 <g_uninit_flag>
    31c0:	01 

    tcs_node_t *tcs_node = g_tcs_node;
    31c1:	48 8b 05 f8 de 00 00 	mov    0xdef8(%rip),%rax        # 110c0 <_ZL10g_tcs_node>
    31c8:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    g_tcs_node = NULL;
    31cc:	48 c7 05 e9 de 00 00 	movq   $0x0,0xdee9(%rip)        # 110c0 <_ZL10g_tcs_node>
    31d3:	00 00 00 00 
    while (tcs_node != NULL)
    31d7:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    31dc:	0f 84 b0 00 00 00    	je     3292 <do_uninit_enclave+0x13f>
    {
        if (DEC_TCS_POINTER(tcs_node->tcs) == tcs)
    31e2:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    31e6:	48 8b 10             	mov    (%rax),%rdx
    31e9:	48 8b 05 d8 de 00 00 	mov    0xded8(%rip),%rax        # 110c8 <_ZL12g_tcs_cookie>
    31f0:	48 31 d0             	xor    %rdx,%rax
    31f3:	48 39 45 c8          	cmp    %rax,-0x38(%rbp)
    31f7:	75 22                	jne    321b <do_uninit_enclave+0xc8>
        {
            tcs_node_t *tmp = tcs_node;
    31f9:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    31fd:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
            tcs_node = tcs_node->next;
    3201:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3205:	48 8b 40 08          	mov    0x8(%rax),%rax
    3209:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
            free(tmp);
    320d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3211:	48 89 c7             	mov    %rax,%rdi
    3214:	e8 86 66 00 00       	callq  989f <dlfree>
            continue;
    3219:	eb 72                	jmp    328d <do_uninit_enclave+0x13a>
        }

        size_t start = (size_t)DEC_TCS_POINTER(tcs_node->tcs);
    321b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    321f:	48 8b 10             	mov    (%rax),%rdx
    3222:	48 8b 05 9f de 00 00 	mov    0xde9f(%rip),%rax        # 110c8 <_ZL12g_tcs_cookie>
    3229:	48 31 d0             	xor    %rdx,%rax
    322c:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
        size_t end = start + (1 << SE_PAGE_SHIFT);
    3230:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3234:	48 05 00 10 00 00    	add    $0x1000,%rax
    323a:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
        int rc = sgx_accept_forward(SI_FLAG_TRIM | SI_FLAG_MODIFIED, start, end);
    323e:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    3242:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3246:	48 89 c6             	mov    %rax,%rsi
    3249:	bf 10 04 00 00       	mov    $0x410,%edi
    324e:	e8 54 ee ff ff       	callq  20a7 <sgx_accept_forward>
    3253:	89 45 d4             	mov    %eax,-0x2c(%rbp)
        if(rc != 0)
    3256:	83 7d d4 00          	cmpl   $0x0,-0x2c(%rbp)
    325a:	74 11                	je     326d <do_uninit_enclave+0x11a>
        {
            set_enclave_state(ENCLAVE_CRASHED);
    325c:	bf 03 00 00 00       	mov    $0x3,%edi
    3261:	e8 13 94 00 00       	callq  c679 <set_enclave_state>
            return SGX_ERROR_UNEXPECTED;
    3266:	b8 01 00 00 00       	mov    $0x1,%eax
    326b:	eb 5f                	jmp    32cc <do_uninit_enclave+0x179>
        }

        tcs_node_t *tmp = tcs_node;
    326d:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3271:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
        tcs_node = tcs_node->next;
    3275:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3279:	48 8b 40 08          	mov    0x8(%rax),%rax
    327d:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
        free(tmp);
    3281:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    3285:	48 89 c7             	mov    %rax,%rdi
    3288:	e8 12 66 00 00       	callq  989f <dlfree>
    while (tcs_node != NULL)
    328d:	e9 45 ff ff ff       	jmpq   31d7 <do_uninit_enclave+0x84>
    }

    sgx_spin_lock(&g_ife_lock);
    3292:	48 8d 3d 37 de 00 00 	lea    0xde37(%rip),%rdi        # 110d0 <_ZL10g_ife_lock>
    3299:	e8 61 81 00 00       	callq  b3ff <sgx_spin_lock>
    if (!g_is_first_ecall)
    329e:	0f b6 05 5b dd 00 00 	movzbl 0xdd5b(%rip),%eax        # 11000 <_ZL16g_is_first_ecall>
    32a5:	83 f0 01             	xor    $0x1,%eax
    32a8:	84 c0                	test   %al,%al
    32aa:	74 05                	je     32b1 <do_uninit_enclave+0x15e>
    {
        uninit_global_object();
    32ac:	e8 18 20 00 00       	callq  52c9 <uninit_global_object>
    }
    sgx_spin_unlock(&g_ife_lock);
    32b1:	48 8d 3d 18 de 00 00 	lea    0xde18(%rip),%rdi        # 110d0 <_ZL10g_ife_lock>
    32b8:	e8 a9 81 00 00       	callq  b466 <sgx_spin_unlock>
#else
    UNUSED(tcs);
#endif    
    set_enclave_state(ENCLAVE_CRASHED);
    32bd:	bf 03 00 00 00       	mov    $0x3,%edi
    32c2:	e8 b2 93 00 00       	callq  c679 <set_enclave_state>

    return SGX_SUCCESS;
    32c7:	b8 00 00 00 00       	mov    $0x0,%eax
}
    32cc:	c9                   	leaveq 
    32cd:	c3                   	retq   

00000000000032ce <trts_mprotect>:

extern sdk_version_t g_sdk_version;

extern "C" sgx_status_t trts_mprotect(size_t start, size_t size, uint64_t perms)
{
    32ce:	4c 8d 54 24 08       	lea    0x8(%rsp),%r10
    32d3:	48 83 e4 c0          	and    $0xffffffffffffffc0,%rsp
    32d7:	41 ff 72 f8          	pushq  -0x8(%r10)
    32db:	55                   	push   %rbp
    32dc:	48 89 e5             	mov    %rsp,%rbp
    32df:	41 52                	push   %r10
    32e1:	48 81 ec e8 00 00 00 	sub    $0xe8,%rsp
    32e8:	48 89 bd 38 ff ff ff 	mov    %rdi,-0xc8(%rbp)
    32ef:	48 89 b5 30 ff ff ff 	mov    %rsi,-0xd0(%rbp)
    32f6:	48 89 95 28 ff ff ff 	mov    %rdx,-0xd8(%rbp)
    32fd:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    3304:	00 00 
    3306:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    330a:	31 c0                	xor    %eax,%eax
    int rc = -1;
    330c:	c7 85 40 ff ff ff ff 	movl   $0xffffffff,-0xc0(%rbp)
    3313:	ff ff ff 
    size_t page;
    sgx_status_t ret = SGX_SUCCESS;
    3316:	c7 85 44 ff ff ff 00 	movl   $0x0,-0xbc(%rbp)
    331d:	00 00 00 
    SE_DECLSPEC_ALIGN(sizeof(sec_info_t)) sec_info_t si;

    //Error return if start or size is not page-aligned or size is zero.
    if (!IS_PAGE_ALIGNED(start) || (size == 0) || !IS_PAGE_ALIGNED(size))
    3320:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    3327:	25 ff 0f 00 00       	and    $0xfff,%eax
    332c:	48 85 c0             	test   %rax,%rax
    332f:	75 1b                	jne    334c <trts_mprotect+0x7e>
    3331:	48 83 bd 30 ff ff ff 	cmpq   $0x0,-0xd0(%rbp)
    3338:	00 
    3339:	74 11                	je     334c <trts_mprotect+0x7e>
    333b:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    3342:	25 ff 0f 00 00       	and    $0xfff,%eax
    3347:	48 85 c0             	test   %rax,%rax
    334a:	74 0a                	je     3356 <trts_mprotect+0x88>
        return SGX_ERROR_INVALID_PARAMETER;
    334c:	b8 02 00 00 00       	mov    $0x2,%eax
    3351:	e9 0c 01 00 00       	jmpq   3462 <trts_mprotect+0x194>
    if (g_sdk_version == SDK_VERSION_2_0)
    3356:	48 8d 05 97 da 00 00 	lea    0xda97(%rip),%rax        # 10df4 <g_sdk_version>
    335d:	8b 00                	mov    (%rax),%eax
    335f:	83 f8 01             	cmp    $0x1,%eax
    3362:	75 3a                	jne    339e <trts_mprotect+0xd0>
    {
        ret = change_permissions_ocall(start, size, perms);
    3364:	48 8b 95 28 ff ff ff 	mov    -0xd8(%rbp),%rdx
    336b:	48 8b 8d 30 ff ff ff 	mov    -0xd0(%rbp),%rcx
    3372:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    3379:	48 89 ce             	mov    %rcx,%rsi
    337c:	48 89 c7             	mov    %rax,%rdi
    337f:	e8 39 02 00 00       	callq  35bd <change_permissions_ocall>
    3384:	89 85 44 ff ff ff    	mov    %eax,-0xbc(%rbp)
        if (ret != SGX_SUCCESS)
    338a:	83 bd 44 ff ff ff 00 	cmpl   $0x0,-0xbc(%rbp)
    3391:	74 0b                	je     339e <trts_mprotect+0xd0>
            return ret;
    3393:	8b 85 44 ff ff ff    	mov    -0xbc(%rbp),%eax
    3399:	e9 c4 00 00 00       	jmpq   3462 <trts_mprotect+0x194>
    }

    si.flags = perms|SI_FLAG_REG|SI_FLAG_PR;
    339e:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    33a5:	48 0d 20 02 00 00    	or     $0x220,%rax
    33ab:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    memset(&si.reserved, 0, sizeof(si.reserved));
    33b2:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
    33b9:	48 83 c0 08          	add    $0x8,%rax
    33bd:	ba 38 00 00 00       	mov    $0x38,%edx
    33c2:	be 00 00 00 00       	mov    $0x0,%esi
    33c7:	48 89 c7             	mov    %rax,%rdi
    33ca:	e8 d1 7b 00 00       	callq  afa0 <memset>

    for(page = start; page < start + size; page += SE_PAGE_SIZE)
    33cf:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    33d6:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    33dd:	48 8b 95 38 ff ff ff 	mov    -0xc8(%rbp),%rdx
    33e4:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    33eb:	48 01 d0             	add    %rdx,%rax
    33ee:	48 39 85 48 ff ff ff 	cmp    %rax,-0xb8(%rbp)
    33f5:	73 66                	jae    345d <trts_mprotect+0x18f>
    {
        do_emodpe(&si, page);
    33f7:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    33fe:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
    3405:	48 89 d6             	mov    %rdx,%rsi
    3408:	48 89 c7             	mov    %rax,%rdi
    340b:	e8 8a 95 00 00       	callq  c99a <do_emodpe>
        // If the target permission to set is RWX, no EMODPR, hence no EACCEPT.
        if ((perms & (SI_FLAG_W|SI_FLAG_X)) != (SI_FLAG_W|SI_FLAG_X))
    3410:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    3417:	83 e0 06             	and    $0x6,%eax
    341a:	48 83 f8 06          	cmp    $0x6,%rax
    341e:	74 30                	je     3450 <trts_mprotect+0x182>
        {
            rc = do_eaccept(&si, page);
    3420:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    3427:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
    342e:	48 89 d6             	mov    %rdx,%rsi
    3431:	48 89 c7             	mov    %rax,%rdi
    3434:	e8 47 95 00 00       	callq  c980 <do_eaccept>
    3439:	89 85 40 ff ff ff    	mov    %eax,-0xc0(%rbp)
            if(rc != 0)
    343f:	83 bd 40 ff ff ff 00 	cmpl   $0x0,-0xc0(%rbp)
    3446:	74 08                	je     3450 <trts_mprotect+0x182>
                return (sgx_status_t)rc;
    3448:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    344e:	eb 12                	jmp    3462 <trts_mprotect+0x194>
    for(page = start; page < start + size; page += SE_PAGE_SIZE)
    3450:	48 81 85 48 ff ff ff 	addq   $0x1000,-0xb8(%rbp)
    3457:	00 10 00 00 
    345b:	eb 80                	jmp    33dd <trts_mprotect+0x10f>
        }
    }

    return SGX_SUCCESS;
    345d:	b8 00 00 00 00       	mov    $0x0,%eax
}
    3462:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    3466:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    346d:	00 00 
    346f:	74 05                	je     3476 <trts_mprotect+0x1a8>
    3471:	e8 64 1e 00 00       	callq  52da <__stack_chk_fail>
    3476:	48 81 c4 e8 00 00 00 	add    $0xe8,%rsp
    347d:	41 5a                	pop    %r10
    347f:	5d                   	pop    %rbp
    3480:	49 8d 62 f8          	lea    -0x8(%r10),%rsp
    3484:	c3                   	retq   

0000000000003485 <_Z20random_stack_advanceILj2048E9_status_tJjPvEJRiRS1_EET0_PFS4_DpT1_EDpOT2_>:
__attribute__((noinline)) static R _random_stack_noinline_wrapper(R(*f)(Ps...), Qs&&... args)
{
    return f(std::forward<Qs>(args)...);
}
template <unsigned M = 0x1000, class R, class... Ps, class... Qs>
R random_stack_advance(R(*f)(Ps...), Qs&&... args)
    3485:	55                   	push   %rbp
    3486:	48 89 e5             	mov    %rsp,%rbp
    3489:	41 57                	push   %r15
    348b:	41 56                	push   %r14
    348d:	41 55                	push   %r13
    348f:	41 54                	push   %r12
    3491:	53                   	push   %rbx
    3492:	48 83 ec 58          	sub    $0x58,%rsp
    3496:	48 89 7d 98          	mov    %rdi,-0x68(%rbp)
    349a:	48 89 75 90          	mov    %rsi,-0x70(%rbp)
    349e:	48 89 55 88          	mov    %rdx,-0x78(%rbp)
    34a2:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    34a9:	00 00 
    34ab:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    34af:	31 c0                	xor    %eax,%eax
        memset((void *)dummy_vla, 0, size);
#else
    (void)(dummy_vla);
#endif

    return _random_stack_noinline_wrapper(f, std::forward<Qs>(args)...);
    34b1:	48 89 e0             	mov    %rsp,%rax
    34b4:	48 89 c3             	mov    %rax,%rbx
    unsigned size = rdrand() % M + 1;
    34b7:	e8 b2 00 00 00       	callq  356e <_Z6rdrandIjET_v>
    34bc:	25 ff 07 00 00       	and    $0x7ff,%eax
    34c1:	83 c0 01             	add    $0x1,%eax
    34c4:	89 45 a4             	mov    %eax,-0x5c(%rbp)
    volatile char dummy_vla[size];
    34c7:	8b 45 a4             	mov    -0x5c(%rbp),%eax
    34ca:	48 83 e8 01          	sub    $0x1,%rax
    34ce:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    34d2:	48 89 c2             	mov    %rax,%rdx
    34d5:	48 83 c2 01          	add    $0x1,%rdx
    34d9:	49 89 d6             	mov    %rdx,%r14
    34dc:	41 bf 00 00 00 00    	mov    $0x0,%r15d
    34e2:	48 89 c2             	mov    %rax,%rdx
    34e5:	48 83 c2 01          	add    $0x1,%rdx
    34e9:	49 89 d4             	mov    %rdx,%r12
    34ec:	41 bd 00 00 00 00    	mov    $0x0,%r13d
    34f2:	48 8d 50 01          	lea    0x1(%rax),%rdx
    34f6:	b8 10 00 00 00       	mov    $0x10,%eax
    34fb:	48 83 e8 01          	sub    $0x1,%rax
    34ff:	48 01 d0             	add    %rdx,%rax
    3502:	be 10 00 00 00       	mov    $0x10,%esi
    3507:	ba 00 00 00 00       	mov    $0x0,%edx
    350c:	48 f7 f6             	div    %rsi
    350f:	48 6b c0 10          	imul   $0x10,%rax,%rax
    3513:	48 29 c4             	sub    %rax,%rsp
    3516:	48 89 e0             	mov    %rsp,%rax
    3519:	48 83 c0 00          	add    $0x0,%rax
    351d:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    3521:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    3525:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
template <class _Tp>
inline _LIBCPP_INLINE_VISIBILITY _LIBCPP_CONSTEXPR_AFTER_CXX11
_Tp&&
forward(typename remove_reference<_Tp>::type& __t) _NOEXCEPT
{
    return static_cast<_Tp&&>(__t);
    3529:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    352d:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    3531:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    3535:	48 8b 4d b8          	mov    -0x48(%rbp),%rcx
    return _random_stack_noinline_wrapper(f, std::forward<Qs>(args)...);
    3539:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    353d:	48 89 ce             	mov    %rcx,%rsi
    3540:	48 89 c7             	mov    %rax,%rdi
    3543:	e8 35 00 00 00       	callq  357d <_Z30_random_stack_noinline_wrapperI9_status_tJjPvEJRiRS1_EET_PFS4_DpT0_EDpOT1_>
    3548:	48 89 dc             	mov    %rbx,%rsp
}
    354b:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    354f:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    3556:	00 00 
    3558:	74 05                	je     355f <_Z20random_stack_advanceILj2048E9_status_tJjPvEJRiRS1_EET0_PFS4_DpT1_EDpOT2_+0xda>
    355a:	e8 7b 1d 00 00       	callq  52da <__stack_chk_fail>
    355f:	48 8d 65 d8          	lea    -0x28(%rbp),%rsp
    3563:	5b                   	pop    %rbx
    3564:	41 5c                	pop    %r12
    3566:	41 5d                	pop    %r13
    3568:	41 5e                	pop    %r14
    356a:	41 5f                	pop    %r15
    356c:	5d                   	pop    %rbp
    356d:	c3                   	retq   

000000000000356e <_Z6rdrandIjET_v>:
inline R rdrand(void)
    356e:	55                   	push   %rbp
    356f:	48 89 e5             	mov    %rsp,%rbp
    __asm__ volatile ("rdrand %0" : "=r"(r));
    3572:	0f c7 f0             	rdrand %eax
    3575:	89 45 fc             	mov    %eax,-0x4(%rbp)
    return r;
    3578:	8b 45 fc             	mov    -0x4(%rbp),%eax
}
    357b:	5d                   	pop    %rbp
    357c:	c3                   	retq   

000000000000357d <_Z30_random_stack_noinline_wrapperI9_status_tJjPvEJRiRS1_EET_PFS4_DpT0_EDpOT1_>:
__attribute__((noinline)) static R _random_stack_noinline_wrapper(R(*f)(Ps...), Qs&&... args)
    357d:	55                   	push   %rbp
    357e:	48 89 e5             	mov    %rsp,%rbp
    3581:	48 83 ec 30          	sub    $0x30,%rsp
    3585:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    3589:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    358d:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    3591:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3595:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    3599:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    return f(std::forward<Qs>(args)...);
    359d:	48 8b 10             	mov    (%rax),%rdx
    35a0:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    35a4:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    35a8:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    35ac:	8b 00                	mov    (%rax),%eax
    35ae:	89 c1                	mov    %eax,%ecx
    35b0:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    35b4:	48 89 d6             	mov    %rdx,%rsi
    35b7:	89 cf                	mov    %ecx,%edi
    35b9:	ff d0                	callq  *%rax
}
    35bb:	c9                   	leaveq 
    35bc:	c3                   	retq   

00000000000035bd <change_permissions_ocall>:
    size_t ms_size;
    uint64_t ms_epcm_perms;
} ms_change_permissions_ocall_t;

sgx_status_t SGXAPI change_permissions_ocall(size_t addr, size_t size, uint64_t epcm_perms)
{
    35bd:	55                   	push   %rbp
    35be:	48 89 e5             	mov    %rsp,%rbp
    35c1:	48 83 ec 40          	sub    $0x40,%rsp
    35c5:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    35c9:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    35cd:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
    (void)addr;
    (void)size;
    (void)epcm_perms;
    return SGX_SUCCESS;
#else
    sgx_status_t status = SGX_SUCCESS;
    35d1:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%rbp)

    ms_change_permissions_ocall_t* ms;
    OCALLOC(ms, ms_change_permissions_ocall_t*, sizeof(*ms));
    35d8:	bf 18 00 00 00       	mov    $0x18,%edi
    35dd:	e8 43 de ff ff       	callq  1425 <sgx_ocalloc>
    35e2:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    35e6:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    35eb:	75 0c                	jne    35f9 <change_permissions_ocall+0x3c>
    35ed:	e8 44 df ff ff       	callq  1536 <sgx_ocfree>
    35f2:	b8 01 00 00 00       	mov    $0x1,%eax
    35f7:	eb 47                	jmp    3640 <change_permissions_ocall+0x83>
    35f9:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    35fd:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

    ms->ms_addr = addr;
    3601:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3605:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    3609:	48 89 10             	mov    %rdx,(%rax)
    ms->ms_size = size;
    360c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3610:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    3614:	48 89 50 08          	mov    %rdx,0x8(%rax)
    ms->ms_epcm_perms = epcm_perms;
    3618:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    361c:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    3620:	48 89 50 10          	mov    %rdx,0x10(%rax)
    status = sgx_ocall(EDMM_MODPR, ms);
    3624:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3628:	48 89 c6             	mov    %rax,%rsi
    362b:	bf fc ff ff ff       	mov    $0xfffffffc,%edi
    3630:	e8 0d 00 00 00       	callq  3642 <sgx_ocall>
    3635:	89 45 ec             	mov    %eax,-0x14(%rbp)


    sgx_ocfree();
    3638:	e8 f9 de ff ff       	callq  1536 <sgx_ocfree>
    return status;
    363d:	8b 45 ec             	mov    -0x14(%rbp),%eax
#endif
}
    3640:	c9                   	leaveq 
    3641:	c3                   	retq   

0000000000003642 <sgx_ocall>:
//      ms - the mashalling structure
// Return Value:
//      OCALL status
//
sgx_status_t sgx_ocall(const unsigned int index, void *ms)
{
    3642:	55                   	push   %rbp
    3643:	48 89 e5             	mov    %rsp,%rbp
    3646:	48 83 ec 20          	sub    $0x20,%rsp
    364a:	89 7d ec             	mov    %edi,-0x14(%rbp)
    364d:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    // the OCALL index should be within the ocall table range
    // -2, -3 and -4 -5 should be allowed to test SDK 2.0 features
    if((index != 0) && !is_builtin_ocall((int)index) &&
    3651:	83 7d ec 00          	cmpl   $0x0,-0x14(%rbp)
    3655:	74 29                	je     3680 <sgx_ocall+0x3e>
    3657:	8b 45 ec             	mov    -0x14(%rbp),%eax
    365a:	83 f8 fc             	cmp    $0xfffffffc,%eax
    365d:	7c 08                	jl     3667 <sgx_ocall+0x25>
    365f:	8b 45 ec             	mov    -0x14(%rbp),%eax
    3662:	83 f8 ff             	cmp    $0xffffffff,%eax
    3665:	7c 19                	jl     3680 <sgx_ocall+0x3e>
            static_cast<size_t>(index) >= g_dyn_entry_table.nr_ocall)
    3667:	8b 55 ec             	mov    -0x14(%rbp),%edx
    366a:	48 8d 05 8f 99 00 00 	lea    0x998f(%rip),%rax        # d000 <g_dyn_entry_table>
    3671:	48 8b 00             	mov    (%rax),%rax
    if((index != 0) && !is_builtin_ocall((int)index) &&
    3674:	48 39 c2             	cmp    %rax,%rdx
    3677:	72 07                	jb     3680 <sgx_ocall+0x3e>
    {
        return SGX_ERROR_INVALID_FUNCTION;
    3679:	b8 01 10 00 00       	mov    $0x1001,%eax
    367e:	eb 17                	jmp    3697 <sgx_ocall+0x55>
    }

    // do sgx_ocall
    sgx_status_t status = do_ocall(index, ms);
    3680:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    3684:	8b 45 ec             	mov    -0x14(%rbp),%eax
    3687:	48 89 d6             	mov    %rdx,%rsi
    368a:	89 c7                	mov    %eax,%edi
    368c:	e8 42 92 00 00       	callq  c8d3 <__morestack>
    3691:	89 45 fc             	mov    %eax,-0x4(%rbp)

    return status;
    3694:	8b 45 fc             	mov    -0x4(%rbp),%eax
}
    3697:	c9                   	leaveq 
    3698:	c3                   	retq   

0000000000003699 <update_ocall_lastsp>:


extern "C"
uintptr_t update_ocall_lastsp(ocall_context_t* context)
{
    3699:	55                   	push   %rbp
    369a:	48 89 e5             	mov    %rsp,%rbp
    369d:	48 83 ec 30          	sub    $0x30,%rsp
    36a1:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    thread_data_t* thread_data = get_thread_data();
    36a5:	e8 f5 8f 00 00       	callq  c69f <get_thread_data>
    36aa:	48 89 45 e8          	mov    %rax,-0x18(%rbp)

    uintptr_t last_sp = 0;
    36ae:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
    36b5:	00 

    last_sp = thread_data->last_sp;
    36b6:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    36ba:	48 8b 40 08          	mov    0x8(%rax),%rax
    36be:	48 89 45 f0          	mov    %rax,-0x10(%rbp)

    context->pre_last_sp = last_sp;
    36c2:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    36c6:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    36ca:	48 89 50 30          	mov    %rdx,0x30(%rax)

    if (context->pre_last_sp == thread_data->stack_base_addr)
    36ce:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    36d2:	48 8b 50 30          	mov    0x30(%rax),%rdx
    36d6:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    36da:	48 8b 40 10          	mov    0x10(%rax),%rax
    36de:	48 39 c2             	cmp    %rax,%rdx
    36e1:	75 11                	jne    36f4 <update_ocall_lastsp+0x5b>
    {
        context->ocall_depth = 1;
    36e3:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    36e7:	48 c7 80 90 00 00 00 	movq   $0x1,0x90(%rax)
    36ee:	01 00 00 00 
    36f2:	eb 26                	jmp    371a <update_ocall_lastsp+0x81>
    } else {
        // thread_data->last_sp is only set when ocall or exception handling occurs
        // ocall is block during exception handling, so last_sp is always ocall frame here
        ocall_context_t* context_pre = reinterpret_cast<ocall_context_t*>(context->pre_last_sp);
    36f4:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    36f8:	48 8b 40 30          	mov    0x30(%rax),%rax
    36fc:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
        context->ocall_depth = context_pre->ocall_depth + 1;
    3700:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3704:	48 8b 80 90 00 00 00 	mov    0x90(%rax),%rax
    370b:	48 8d 50 01          	lea    0x1(%rax),%rdx
    370f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3713:	48 89 90 90 00 00 00 	mov    %rdx,0x90(%rax)
    }

    thread_data->last_sp = reinterpret_cast<uintptr_t>(context);
    371a:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    371e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3722:	48 89 50 08          	mov    %rdx,0x8(%rax)

    return last_sp;
    3726:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
}
    372a:	c9                   	leaveq 
    372b:	c3                   	retq   

000000000000372c <do_oret>:

sgx_status_t do_oret(void *ms)
{
    372c:	55                   	push   %rbp
    372d:	48 89 e5             	mov    %rsp,%rbp
    3730:	48 83 ec 30          	sub    $0x30,%rsp
    3734:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    3738:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    373f:	00 00 
    3741:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    3745:	31 c0                	xor    %eax,%eax
    thread_data_t *thread_data = get_thread_data();
    3747:	e8 53 8f 00 00       	callq  c69f <get_thread_data>
    374c:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    uintptr_t last_sp = thread_data->last_sp;
    3750:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3754:	48 8b 40 08          	mov    0x8(%rax),%rax
    3758:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    ocall_context_t *context = reinterpret_cast<ocall_context_t*>(thread_data->last_sp);
    375c:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3760:	48 8b 40 08          	mov    0x8(%rax),%rax
    3764:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    if(0 == last_sp || last_sp <= (uintptr_t)&context)
    3768:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    376d:	74 0a                	je     3779 <do_oret+0x4d>
    376f:	48 8d 45 e0          	lea    -0x20(%rbp),%rax
    3773:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    3777:	77 0a                	ja     3783 <do_oret+0x57>
    {
        return SGX_ERROR_UNEXPECTED;
    3779:	b8 01 00 00 00       	mov    $0x1,%eax
    377e:	e9 87 00 00 00       	jmpq   380a <do_oret+0xde>
    }
    // At least 1 ecall frame and 1 ocall frame are expected on stack. 
    // 30 is an estimated value: 8 for enclave_entry and 22 for do_ocall.
    if(last_sp > thread_data->stack_base_addr - 30 * sizeof(size_t))
    3783:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3787:	48 8b 40 10          	mov    0x10(%rax),%rax
    378b:	48 2d f0 00 00 00    	sub    $0xf0,%rax
    3791:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    3795:	76 07                	jbe    379e <do_oret+0x72>
    {
        return SGX_ERROR_UNEXPECTED;
    3797:	b8 01 00 00 00       	mov    $0x1,%eax
    379c:	eb 6c                	jmp    380a <do_oret+0xde>
    }
    if(context->ocall_flag != OCALL_FLAG)
    379e:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    37a2:	48 8b 40 20          	mov    0x20(%rax),%rax
    37a6:	48 3d 44 49 43 4f    	cmp    $0x4f434944,%rax
    37ac:	74 07                	je     37b5 <do_oret+0x89>
    {
        return SGX_ERROR_UNEXPECTED;
    37ae:	b8 01 00 00 00       	mov    $0x1,%eax
    37b3:	eb 55                	jmp    380a <do_oret+0xde>
    }
    if(context->pre_last_sp > thread_data->stack_base_addr
    37b5:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    37b9:	48 8b 50 30          	mov    0x30(%rax),%rdx
    37bd:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    37c1:	48 8b 40 10          	mov    0x10(%rax),%rax
    37c5:	48 39 c2             	cmp    %rax,%rdx
    37c8:	77 11                	ja     37db <do_oret+0xaf>
       || context->pre_last_sp <= (uintptr_t)context)
    37ca:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    37ce:	48 8b 40 30          	mov    0x30(%rax),%rax
    37d2:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    37d6:	48 39 d0             	cmp    %rdx,%rax
    37d9:	77 07                	ja     37e2 <do_oret+0xb6>
    {
        return SGX_ERROR_UNEXPECTED;
    37db:	b8 01 00 00 00       	mov    $0x1,%eax
    37e0:	eb 28                	jmp    380a <do_oret+0xde>
    }

    thread_data->last_sp = context->pre_last_sp;
    37e2:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    37e6:	48 8b 50 30          	mov    0x30(%rax),%rdx
    37ea:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    37ee:	48 89 50 08          	mov    %rdx,0x8(%rax)
    asm_oret(last_sp, ms);
    37f2:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    37f6:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    37fa:	48 89 d6             	mov    %rdx,%rsi
    37fd:	48 89 c7             	mov    %rax,%rdi
    3800:	e8 dd 90 00 00       	callq  c8e2 <asm_oret>
    
    // Should not come here
    return SGX_ERROR_UNEXPECTED;
    3805:	b8 01 00 00 00       	mov    $0x1,%eax
}
    380a:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    380e:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    3815:	00 00 
    3817:	74 05                	je     381e <do_oret+0xf2>
    3819:	e8 bc 1a 00 00       	callq  52da <__stack_chk_fail>
    381e:	c9                   	leaveq 
    381f:	c3                   	retq   

0000000000003820 <trim_range_ocall>:
typedef struct ms_trim_range_commit_ocall_t {
    size_t ms_addr;
} ms_trim_range_commit_ocall_t;

sgx_status_t SGXAPI trim_range_ocall(size_t fromaddr, size_t toaddr)
{
    3820:	55                   	push   %rbp
    3821:	48 89 e5             	mov    %rsp,%rbp
    3824:	48 83 ec 30          	sub    $0x30,%rsp
    3828:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    382c:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    sgx_status_t status = SGX_SUCCESS;
    3830:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%rbp)

    ms_trim_range_ocall_t* ms;
    OCALLOC(ms, ms_trim_range_ocall_t*, sizeof(*ms));
    3837:	bf 10 00 00 00       	mov    $0x10,%edi
    383c:	e8 e4 db ff ff       	callq  1425 <sgx_ocalloc>
    3841:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    3845:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    384a:	75 0c                	jne    3858 <trim_range_ocall+0x38>
    384c:	e8 e5 dc ff ff       	callq  1536 <sgx_ocfree>
    3851:	b8 01 00 00 00       	mov    $0x1,%eax
    3856:	eb 3b                	jmp    3893 <trim_range_ocall+0x73>
    3858:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    385c:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

    ms->ms_fromaddr = fromaddr;
    3860:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3864:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    3868:	48 89 10             	mov    %rdx,(%rax)
    ms->ms_toaddr = toaddr;
    386b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    386f:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    3873:	48 89 50 08          	mov    %rdx,0x8(%rax)
    status = sgx_ocall(EDMM_TRIM, ms);
    3877:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    387b:	48 89 c6             	mov    %rax,%rsi
    387e:	bf fe ff ff ff       	mov    $0xfffffffe,%edi
    3883:	e8 ba fd ff ff       	callq  3642 <sgx_ocall>
    3888:	89 45 ec             	mov    %eax,-0x14(%rbp)


    sgx_ocfree();
    388b:	e8 a6 dc ff ff       	callq  1536 <sgx_ocfree>
    return status;
    3890:	8b 45 ec             	mov    -0x14(%rbp),%eax
}
    3893:	c9                   	leaveq 
    3894:	c3                   	retq   

0000000000003895 <trim_range_commit_ocall>:

sgx_status_t SGXAPI trim_range_commit_ocall(size_t addr)
{
    3895:	55                   	push   %rbp
    3896:	48 89 e5             	mov    %rsp,%rbp
    3899:	48 83 ec 30          	sub    $0x30,%rsp
    389d:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    sgx_status_t status = SGX_SUCCESS;
    38a1:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%rbp)

    ms_trim_range_commit_ocall_t* ms;
    OCALLOC(ms, ms_trim_range_commit_ocall_t*, sizeof(*ms));
    38a8:	bf 08 00 00 00       	mov    $0x8,%edi
    38ad:	e8 73 db ff ff       	callq  1425 <sgx_ocalloc>
    38b2:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    38b6:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    38bb:	75 0c                	jne    38c9 <trim_range_commit_ocall+0x34>
    38bd:	e8 74 dc ff ff       	callq  1536 <sgx_ocfree>
    38c2:	b8 01 00 00 00       	mov    $0x1,%eax
    38c7:	eb 2f                	jmp    38f8 <trim_range_commit_ocall+0x63>
    38c9:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    38cd:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

    ms->ms_addr = addr;
    38d1:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    38d5:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    38d9:	48 89 10             	mov    %rdx,(%rax)
    status = sgx_ocall(EDMM_TRIM_COMMIT, ms);
    38dc:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    38e0:	48 89 c6             	mov    %rax,%rsi
    38e3:	bf fd ff ff ff       	mov    $0xfffffffd,%edi
    38e8:	e8 55 fd ff ff       	callq  3642 <sgx_ocall>
    38ed:	89 45 ec             	mov    %eax,-0x14(%rbp)


    sgx_ocfree();
    38f0:	e8 41 dc ff ff       	callq  1536 <sgx_ocfree>
    return status;
    38f5:	8b 45 ec             	mov    -0x14(%rbp),%eax
}
    38f8:	c9                   	leaveq 
    38f9:	c3                   	retq   

00000000000038fa <get_heap_base>:
{
    return (size_t)get_enclave_base() + (size_t)g_global_data.enclave_size - 1;
}

void * get_heap_base(void)
{
    38fa:	55                   	push   %rbp
    38fb:	48 89 e5             	mov    %rsp,%rbp
    return GET_PTR(void, &__ImageBase, g_global_data.heap_offset);
    38fe:	48 8d 05 7b 98 00 00 	lea    0x987b(%rip),%rax        # d180 <g_global_data>
    3905:	48 8b 40 08          	mov    0x8(%rax),%rax
    3909:	48 8d 15 f0 c6 ff ff 	lea    -0x3910(%rip),%rdx        # 0 <enclave.so>
    3910:	48 01 d0             	add    %rdx,%rax
}
    3913:	5d                   	pop    %rbp
    3914:	c3                   	retq   

0000000000003915 <get_heap_size>:

size_t get_heap_size(void)
{
    3915:	55                   	push   %rbp
    3916:	48 89 e5             	mov    %rsp,%rbp
    size_t heap_size = g_global_data.heap_size;
    3919:	48 8d 05 60 98 00 00 	lea    0x9860(%rip),%rax        # d180 <g_global_data>
    3920:	48 8b 40 10          	mov    0x10(%rax),%rax
    3924:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if (EDMM_supported)
    3928:	48 8d 05 c1 d4 00 00 	lea    0xd4c1(%rip),%rax        # 10df0 <EDMM_supported>
    392f:	8b 00                	mov    (%rax),%eax
    3931:	85 c0                	test   %eax,%eax
    3933:	74 6c                	je     39a1 <get_heap_size+0x8c>
    {
        for(uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    3935:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    393c:	48 8d 05 3d 98 00 00 	lea    0x983d(%rip),%rax        # d180 <g_global_data>
    3943:	8b 80 28 01 00 00    	mov    0x128(%rax),%eax
    3949:	39 45 f4             	cmp    %eax,-0xc(%rbp)
    394c:	0f 92 c0             	setb   %al
    394f:	84 c0                	test   %al,%al
    3951:	74 4e                	je     39a1 <get_heap_size+0x8c>
        {
            if(g_global_data.layout_table[i].entry.id == LAYOUT_ID_HEAP_MAX)
    3953:	48 8d 05 26 98 00 00 	lea    0x9826(%rip),%rax        # d180 <g_global_data>
    395a:	8b 55 f4             	mov    -0xc(%rbp),%edx
    395d:	48 c1 e2 05          	shl    $0x5,%rdx
    3961:	48 01 d0             	add    %rdx,%rax
    3964:	48 05 30 01 00 00    	add    $0x130,%rax
    396a:	0f b7 00             	movzwl (%rax),%eax
    396d:	66 83 f8 03          	cmp    $0x3,%ax
    3971:	0f 94 c0             	sete   %al
    3974:	84 c0                	test   %al,%al
    3976:	74 23                	je     399b <get_heap_size+0x86>
            {
                heap_size += ((size_t)g_global_data.layout_table[i].entry.page_count << SE_PAGE_SHIFT);
    3978:	48 8d 05 01 98 00 00 	lea    0x9801(%rip),%rax        # d180 <g_global_data>
    397f:	8b 55 f4             	mov    -0xc(%rbp),%edx
    3982:	48 c1 e2 05          	shl    $0x5,%rdx
    3986:	48 01 d0             	add    %rdx,%rax
    3989:	48 05 34 01 00 00    	add    $0x134,%rax
    398f:	8b 00                	mov    (%rax),%eax
    3991:	89 c0                	mov    %eax,%eax
    3993:	48 c1 e0 0c          	shl    $0xc,%rax
    3997:	48 01 45 f8          	add    %rax,-0x8(%rbp)
        for(uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    399b:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    399f:	eb 9b                	jmp    393c <get_heap_size+0x27>
            }
        }
    }
    return heap_size;
    39a1:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
}
    39a5:	5d                   	pop    %rbp
    39a6:	c3                   	retq   

00000000000039a7 <get_heap_min_size>:

size_t get_heap_min_size(void)
{
    39a7:	55                   	push   %rbp
    39a8:	48 89 e5             	mov    %rsp,%rbp
    size_t heap_size = 0;
    39ab:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    39b2:	00 
    for(uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    39b3:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    39ba:	48 8d 05 bf 97 00 00 	lea    0x97bf(%rip),%rax        # d180 <g_global_data>
    39c1:	8b 80 28 01 00 00    	mov    0x128(%rax),%eax
    39c7:	39 45 f4             	cmp    %eax,-0xc(%rbp)
    39ca:	0f 92 c0             	setb   %al
    39cd:	84 c0                	test   %al,%al
    39cf:	74 50                	je     3a21 <get_heap_min_size+0x7a>
    {
        if(g_global_data.layout_table[i].entry.id == LAYOUT_ID_HEAP_MIN)
    39d1:	48 8d 05 a8 97 00 00 	lea    0x97a8(%rip),%rax        # d180 <g_global_data>
    39d8:	8b 55 f4             	mov    -0xc(%rbp),%edx
    39db:	48 c1 e2 05          	shl    $0x5,%rdx
    39df:	48 01 d0             	add    %rdx,%rax
    39e2:	48 05 30 01 00 00    	add    $0x130,%rax
    39e8:	0f b7 00             	movzwl (%rax),%eax
    39eb:	66 83 f8 01          	cmp    $0x1,%ax
    39ef:	0f 94 c0             	sete   %al
    39f2:	84 c0                	test   %al,%al
    39f4:	74 25                	je     3a1b <get_heap_min_size+0x74>
        {
            heap_size = ((size_t)g_global_data.layout_table[i].entry.page_count << SE_PAGE_SHIFT);
    39f6:	48 8d 05 83 97 00 00 	lea    0x9783(%rip),%rax        # d180 <g_global_data>
    39fd:	8b 55 f4             	mov    -0xc(%rbp),%edx
    3a00:	48 c1 e2 05          	shl    $0x5,%rdx
    3a04:	48 01 d0             	add    %rdx,%rax
    3a07:	48 05 34 01 00 00    	add    $0x134,%rax
    3a0d:	8b 00                	mov    (%rax),%eax
    3a0f:	89 c0                	mov    %eax,%eax
    3a11:	48 c1 e0 0c          	shl    $0xc,%rax
    3a15:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
            break;
    3a19:	eb 06                	jmp    3a21 <get_heap_min_size+0x7a>
    for(uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    3a1b:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    3a1f:	eb 99                	jmp    39ba <get_heap_min_size+0x13>
        }
    }
    return heap_size;
    3a21:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
}
    3a25:	5d                   	pop    %rbp
    3a26:	c3                   	retq   

0000000000003a27 <get_rsrv_base>:

void * get_rsrv_base(void)
{
    3a27:	55                   	push   %rbp
    3a28:	48 89 e5             	mov    %rsp,%rbp
    return GET_PTR(void, &__ImageBase, g_global_data.rsrv_offset);
    3a2b:	48 8d 05 4e 97 00 00 	lea    0x974e(%rip),%rax        # d180 <g_global_data>
    3a32:	48 8b 40 18          	mov    0x18(%rax),%rax
    3a36:	48 8d 15 c3 c5 ff ff 	lea    -0x3a3d(%rip),%rdx        # 0 <enclave.so>
    3a3d:	48 01 d0             	add    %rdx,%rax
}
    3a40:	5d                   	pop    %rbp
    3a41:	c3                   	retq   

0000000000003a42 <get_rsrv_size>:
{
    return (size_t)get_rsrv_base() + (size_t)get_rsrv_size() - 1;
}

size_t get_rsrv_size(void)
{
    3a42:	55                   	push   %rbp
    3a43:	48 89 e5             	mov    %rsp,%rbp
    size_t rsrv_size = g_global_data.rsrv_size;
    3a46:	48 8d 05 33 97 00 00 	lea    0x9733(%rip),%rax        # d180 <g_global_data>
    3a4d:	48 8b 40 20          	mov    0x20(%rax),%rax
    3a51:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if (EDMM_supported)
    3a55:	48 8d 05 94 d3 00 00 	lea    0xd394(%rip),%rax        # 10df0 <EDMM_supported>
    3a5c:	8b 00                	mov    (%rax),%eax
    3a5e:	85 c0                	test   %eax,%eax
    3a60:	74 6c                	je     3ace <get_rsrv_size+0x8c>
    {
        for (uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    3a62:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    3a69:	48 8d 05 10 97 00 00 	lea    0x9710(%rip),%rax        # d180 <g_global_data>
    3a70:	8b 80 28 01 00 00    	mov    0x128(%rax),%eax
    3a76:	39 45 f4             	cmp    %eax,-0xc(%rbp)
    3a79:	0f 92 c0             	setb   %al
    3a7c:	84 c0                	test   %al,%al
    3a7e:	74 4e                	je     3ace <get_rsrv_size+0x8c>
        {
            if (g_global_data.layout_table[i].entry.id == LAYOUT_ID_RSRV_MAX)
    3a80:	48 8d 05 f9 96 00 00 	lea    0x96f9(%rip),%rax        # d180 <g_global_data>
    3a87:	8b 55 f4             	mov    -0xc(%rbp),%edx
    3a8a:	48 c1 e2 05          	shl    $0x5,%rdx
    3a8e:	48 01 d0             	add    %rdx,%rax
    3a91:	48 05 30 01 00 00    	add    $0x130,%rax
    3a97:	0f b7 00             	movzwl (%rax),%eax
    3a9a:	66 83 f8 16          	cmp    $0x16,%ax
    3a9e:	0f 94 c0             	sete   %al
    3aa1:	84 c0                	test   %al,%al
    3aa3:	74 23                	je     3ac8 <get_rsrv_size+0x86>
            {
                rsrv_size += ((size_t)g_global_data.layout_table[i].entry.page_count << SE_PAGE_SHIFT);
    3aa5:	48 8d 05 d4 96 00 00 	lea    0x96d4(%rip),%rax        # d180 <g_global_data>
    3aac:	8b 55 f4             	mov    -0xc(%rbp),%edx
    3aaf:	48 c1 e2 05          	shl    $0x5,%rdx
    3ab3:	48 01 d0             	add    %rdx,%rax
    3ab6:	48 05 34 01 00 00    	add    $0x134,%rax
    3abc:	8b 00                	mov    (%rax),%eax
    3abe:	89 c0                	mov    %eax,%eax
    3ac0:	48 c1 e0 0c          	shl    $0xc,%rax
    3ac4:	48 01 45 f8          	add    %rax,-0x8(%rbp)
        for (uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    3ac8:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    3acc:	eb 9b                	jmp    3a69 <get_rsrv_size+0x27>
            }
        }
    }
    return rsrv_size;
    3ace:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
}
    3ad2:	5d                   	pop    %rbp
    3ad3:	c3                   	retq   

0000000000003ad4 <get_rsrv_min_size>:

size_t get_rsrv_min_size(void)
{
    3ad4:	55                   	push   %rbp
    3ad5:	48 89 e5             	mov    %rsp,%rbp
    size_t rsrv_size = 0;
    3ad8:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    3adf:	00 
    for (uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    3ae0:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    3ae7:	48 8d 05 92 96 00 00 	lea    0x9692(%rip),%rax        # d180 <g_global_data>
    3aee:	8b 80 28 01 00 00    	mov    0x128(%rax),%eax
    3af4:	39 45 f4             	cmp    %eax,-0xc(%rbp)
    3af7:	0f 92 c0             	setb   %al
    3afa:	84 c0                	test   %al,%al
    3afc:	74 50                	je     3b4e <get_rsrv_min_size+0x7a>
    {
        if (g_global_data.layout_table[i].entry.id == LAYOUT_ID_RSRV_MIN)
    3afe:	48 8d 05 7b 96 00 00 	lea    0x967b(%rip),%rax        # d180 <g_global_data>
    3b05:	8b 55 f4             	mov    -0xc(%rbp),%edx
    3b08:	48 c1 e2 05          	shl    $0x5,%rdx
    3b0c:	48 01 d0             	add    %rdx,%rax
    3b0f:	48 05 30 01 00 00    	add    $0x130,%rax
    3b15:	0f b7 00             	movzwl (%rax),%eax
    3b18:	66 83 f8 14          	cmp    $0x14,%ax
    3b1c:	0f 94 c0             	sete   %al
    3b1f:	84 c0                	test   %al,%al
    3b21:	74 25                	je     3b48 <get_rsrv_min_size+0x74>
        {
            rsrv_size = ((size_t)g_global_data.layout_table[i].entry.page_count << SE_PAGE_SHIFT);
    3b23:	48 8d 05 56 96 00 00 	lea    0x9656(%rip),%rax        # d180 <g_global_data>
    3b2a:	8b 55 f4             	mov    -0xc(%rbp),%edx
    3b2d:	48 c1 e2 05          	shl    $0x5,%rdx
    3b31:	48 01 d0             	add    %rdx,%rax
    3b34:	48 05 34 01 00 00    	add    $0x134,%rax
    3b3a:	8b 00                	mov    (%rax),%eax
    3b3c:	89 c0                	mov    %eax,%eax
    3b3e:	48 c1 e0 0c          	shl    $0xc,%rax
    3b42:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
            break;
    3b46:	eb 06                	jmp    3b4e <get_rsrv_min_size+0x7a>
    for (uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    3b48:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    3b4c:	eb 99                	jmp    3ae7 <get_rsrv_min_size+0x13>
        }
    }
    return rsrv_size;
    3b4e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
}
    3b52:	5d                   	pop    %rbp
    3b53:	c3                   	retq   

0000000000003b54 <get_errno_addr>:

int * get_errno_addr(void)
{
    3b54:	55                   	push   %rbp
    3b55:	48 89 e5             	mov    %rsp,%rbp
    3b58:	48 83 ec 10          	sub    $0x10,%rsp
    thread_data_t *thread_data = get_thread_data();
    3b5c:	e8 3e 8b 00 00       	callq  c69f <get_thread_data>
    3b61:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    return reinterpret_cast<int *>(&thread_data->last_error);
    3b65:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3b69:	48 83 c0 40          	add    $0x40,%rax
}
    3b6d:	c9                   	leaveq 
    3b6e:	c3                   	retq   

0000000000003b6f <feature_supported>:
//Features listed in array[0], counting from right-most bit  to left-most bit,
//have feature shift values 0 ~ 62, while features listed in array[1], have feature
//shift values 64 ~ 126.

int feature_supported(const uint64_t *feature_set, uint32_t feature_shift)
{
    3b6f:	55                   	push   %rbp
    3b70:	48 89 e5             	mov    %rsp,%rbp
    3b73:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    3b77:	89 75 e4             	mov    %esi,-0x1c(%rbp)
    const uint64_t *f_set = feature_set;
    3b7a:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3b7e:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    uint32_t bit_position = 0, i = 0;
    3b82:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    3b89:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%rbp)

    if (!f_set)
    3b90:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    3b95:	75 07                	jne    3b9e <feature_supported+0x2f>
        return 0;
    3b97:	b8 00 00 00 00       	mov    $0x0,%eax
    3b9c:	eb 79                	jmp    3c17 <feature_supported+0xa8>

    while (((i+1) << 6) <= feature_shift)
    3b9e:	8b 45 f0             	mov    -0x10(%rbp),%eax
    3ba1:	83 c0 01             	add    $0x1,%eax
    3ba4:	c1 e0 06             	shl    $0x6,%eax
    3ba7:	39 45 e4             	cmp    %eax,-0x1c(%rbp)
    3baa:	72 27                	jb     3bd3 <feature_supported+0x64>
    {
        if (f_set[i] & (0x1ULL << 63))
    3bac:	8b 45 f0             	mov    -0x10(%rbp),%eax
    3baf:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3bb6:	00 
    3bb7:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3bbb:	48 01 d0             	add    %rdx,%rax
    3bbe:	48 8b 00             	mov    (%rax),%rax
    3bc1:	48 85 c0             	test   %rax,%rax
    3bc4:	79 07                	jns    3bcd <feature_supported+0x5e>
            return 0;
    3bc6:	b8 00 00 00 00       	mov    $0x0,%eax
    3bcb:	eb 4a                	jmp    3c17 <feature_supported+0xa8>
        i++;
    3bcd:	83 45 f0 01          	addl   $0x1,-0x10(%rbp)
    while (((i+1) << 6) <= feature_shift)
    3bd1:	eb cb                	jmp    3b9e <feature_supported+0x2f>
    }
    bit_position = feature_shift - (i << 6);
    3bd3:	8b 45 f0             	mov    -0x10(%rbp),%eax
    3bd6:	c1 e0 06             	shl    $0x6,%eax
    3bd9:	89 c2                	mov    %eax,%edx
    3bdb:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    3bde:	29 d0                	sub    %edx,%eax
    3be0:	89 45 f4             	mov    %eax,-0xc(%rbp)
    if (f_set[i] & (0x1ULL << bit_position))
    3be3:	8b 45 f0             	mov    -0x10(%rbp),%eax
    3be6:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    3bed:	00 
    3bee:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3bf2:	48 01 d0             	add    %rdx,%rax
    3bf5:	48 8b 10             	mov    (%rax),%rdx
    3bf8:	8b 45 f4             	mov    -0xc(%rbp),%eax
    3bfb:	89 c1                	mov    %eax,%ecx
    3bfd:	48 d3 ea             	shr    %cl,%rdx
    3c00:	48 89 d0             	mov    %rdx,%rax
    3c03:	83 e0 01             	and    $0x1,%eax
    3c06:	48 85 c0             	test   %rax,%rax
    3c09:	74 07                	je     3c12 <feature_supported+0xa3>
        return 1;
    3c0b:	b8 01 00 00 00       	mov    $0x1,%eax
    3c10:	eb 05                	jmp    3c17 <feature_supported+0xa8>
    else
        return 0;
    3c12:	b8 00 00 00 00       	mov    $0x0,%eax
}
    3c17:	5d                   	pop    %rbp
    3c18:	c3                   	retq   

0000000000003c19 <is_stack_addr>:

bool is_stack_addr(void *address, size_t size)
{
    3c19:	55                   	push   %rbp
    3c1a:	48 89 e5             	mov    %rsp,%rbp
    3c1d:	48 83 ec 30          	sub    $0x30,%rsp
    3c21:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    3c25:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    thread_data_t *thread_data = get_thread_data();
    3c29:	e8 71 8a 00 00       	callq  c69f <get_thread_data>
    3c2e:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    size_t stack_base = thread_data->stack_base_addr;
    3c32:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3c36:	48 8b 40 10          	mov    0x10(%rax),%rax
    3c3a:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    size_t stack_limit  = thread_data->stack_limit_addr;
    3c3e:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3c42:	48 8b 40 18          	mov    0x18(%rax),%rax
    3c46:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    size_t addr = (size_t) address;
    3c4a:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3c4e:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    return (addr <= (addr + size)) && (stack_base >= (addr + size)) && (stack_limit <= addr);
    3c52:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    3c56:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    3c5a:	48 01 d0             	add    %rdx,%rax
    3c5d:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    3c61:	77 22                	ja     3c85 <is_stack_addr+0x6c>
    3c63:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    3c67:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    3c6b:	48 01 d0             	add    %rdx,%rax
    3c6e:	48 39 45 e8          	cmp    %rax,-0x18(%rbp)
    3c72:	72 11                	jb     3c85 <is_stack_addr+0x6c>
    3c74:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    3c78:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    3c7c:	77 07                	ja     3c85 <is_stack_addr+0x6c>
    3c7e:	b8 01 00 00 00       	mov    $0x1,%eax
    3c83:	eb 05                	jmp    3c8a <is_stack_addr+0x71>
    3c85:	b8 00 00 00 00       	mov    $0x0,%eax
}
    3c8a:	c9                   	leaveq 
    3c8b:	c3                   	retq   

0000000000003c8c <is_valid_sp>:

bool is_valid_sp(uintptr_t sp)
{
    3c8c:	55                   	push   %rbp
    3c8d:	48 89 e5             	mov    %rsp,%rbp
    3c90:	48 83 ec 10          	sub    $0x10,%rsp
    3c94:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    return ( !(sp & (sizeof(uintptr_t) - 1))   // sp is expected to be 4/8 bytes aligned
    3c98:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3c9c:	83 e0 07             	and    $0x7,%eax
           && is_stack_addr((void*)sp, 0) );   // sp points to the top/bottom of stack are accepted
    3c9f:	48 85 c0             	test   %rax,%rax
    3ca2:	75 1c                	jne    3cc0 <is_valid_sp+0x34>
    3ca4:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3ca8:	be 00 00 00 00       	mov    $0x0,%esi
    3cad:	48 89 c7             	mov    %rax,%rdi
    3cb0:	e8 64 ff ff ff       	callq  3c19 <is_stack_addr>
    3cb5:	84 c0                	test   %al,%al
    3cb7:	74 07                	je     3cc0 <is_valid_sp+0x34>
    3cb9:	b8 01 00 00 00       	mov    $0x1,%eax
    3cbe:	eb 05                	jmp    3cc5 <is_valid_sp+0x39>
    3cc0:	b8 00 00 00 00       	mov    $0x0,%eax
}
    3cc5:	c9                   	leaveq 
    3cc6:	c3                   	retq   

0000000000003cc7 <is_utility_thread>:


bool is_utility_thread()
{
    3cc7:	55                   	push   %rbp
    3cc8:	48 89 e5             	mov    %rsp,%rbp
    3ccb:	48 83 ec 10          	sub    $0x10,%rsp
    thread_data_t *thread_data = get_thread_data();
    3ccf:	e8 cb 89 00 00       	callq  c69f <get_thread_data>
    3cd4:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if ((thread_data != NULL) && (thread_data->flags & SGX_UTILITY_THREAD))
    3cd8:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    3cdd:	74 17                	je     3cf6 <is_utility_thread+0x2f>
    3cdf:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3ce3:	48 8b 40 30          	mov    0x30(%rax),%rax
    3ce7:	83 e0 01             	and    $0x1,%eax
    3cea:	48 85 c0             	test   %rax,%rax
    3ced:	74 07                	je     3cf6 <is_utility_thread+0x2f>
    {
        return true;
    3cef:	b8 01 00 00 00       	mov    $0x1,%eax
    3cf4:	eb 05                	jmp    3cfb <is_utility_thread+0x34>
    }
    return false;
    3cf6:	b8 00 00 00 00       	mov    $0x0,%eax
}
    3cfb:	c9                   	leaveq 
    3cfc:	c3                   	retq   

0000000000003cfd <internal_handle_exception>:
// internal_handle_exception(sgx_exception_info_t *info):
//      the 2nd phrase exception handing, which traverse registered exception handlers.
//      if the exception can be handled, then continue execution
//      otherwise, throw abortion, go back to 1st phrase, and call the default handler.
extern "C" __attribute__((regparm(1))) void internal_handle_exception(sgx_exception_info_t *info)
{
    3cfd:	55                   	push   %rbp
    3cfe:	48 89 e5             	mov    %rsp,%rbp
    3d01:	48 83 ec 50          	sub    $0x50,%rsp
    3d05:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    int status = EXCEPTION_CONTINUE_SEARCH;
    3d09:	c7 45 c4 00 00 00 00 	movl   $0x0,-0x3c(%rbp)
    handler_node_t *node = NULL;
    3d10:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    3d17:	00 
    thread_data_t *thread_data = get_thread_data();
    3d18:	e8 82 89 00 00       	callq  c69f <get_thread_data>
    3d1d:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    size_t size = 0;
    3d21:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    3d28:	00 
    uintptr_t *nhead = NULL;
    3d29:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    3d30:	00 
    uintptr_t *ntmp = NULL;
    3d31:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    3d38:	00 
    uintptr_t xsp = 0;
    3d39:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
    3d40:	00 

    if (thread_data->exception_flag < 0)
    3d41:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3d45:	48 8b 40 60          	mov    0x60(%rax),%rax
    3d49:	48 85 c0             	test   %rax,%rax
    3d4c:	0f 88 8c 01 00 00    	js     3ede <internal_handle_exception+0x1e1>
        goto failed_end;
    thread_data->exception_flag++;
    3d52:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3d56:	48 8b 40 60          	mov    0x60(%rax),%rax
    3d5a:	48 8d 50 01          	lea    0x1(%rax),%rdx
    3d5e:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3d62:	48 89 50 60          	mov    %rdx,0x60(%rax)

    // read lock
    sgx_spin_lock(&g_handler_lock);
    3d66:	48 8d 3d 73 d3 00 00 	lea    0xd373(%rip),%rdi        # 110e0 <_ZL14g_handler_lock>
    3d6d:	e8 8d 76 00 00       	callq  b3ff <sgx_spin_lock>

    node = g_first_node;
    3d72:	48 8b 05 5f d3 00 00 	mov    0xd35f(%rip),%rax        # 110d8 <_ZL12g_first_node>
    3d79:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    while(node != NULL)
    3d7d:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    3d82:	74 13                	je     3d97 <internal_handle_exception+0x9a>
    {
        size += sizeof(uintptr_t);
    3d84:	48 83 45 d0 08       	addq   $0x8,-0x30(%rbp)
        node = node->next;
    3d89:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3d8d:	48 8b 40 08          	mov    0x8(%rax),%rax
    3d91:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    while(node != NULL)
    3d95:	eb e6                	jmp    3d7d <internal_handle_exception+0x80>
    }

    // There's no exception handler registered
    if (size == 0)
    3d97:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    3d9c:	75 24                	jne    3dc2 <internal_handle_exception+0xc5>
    {
        sgx_spin_unlock(&g_handler_lock);
    3d9e:	48 8d 3d 3b d3 00 00 	lea    0xd33b(%rip),%rdi        # 110e0 <_ZL14g_handler_lock>
    3da5:	e8 bc 76 00 00       	callq  b466 <sgx_spin_unlock>

        //exception cannot be handled
        thread_data->exception_flag = -1;
    3daa:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3dae:	48 c7 40 60 ff ff ff 	movq   $0xffffffffffffffff,0x60(%rax)
    3db5:	ff 

        //instruction triggering the exception will be executed again.
        continue_execution(info);
    3db6:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3dba:	48 89 c7             	mov    %rax,%rdi
    3dbd:	e8 1b 8c 00 00       	callq  c9dd <continue_execution>
    }

    if ((nhead = (uintptr_t *)malloc(size)) == NULL)
    3dc2:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    3dc6:	48 89 c7             	mov    %rax,%rdi
    3dc9:	e8 da 4f 00 00       	callq  8da8 <dlmalloc>
    3dce:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    3dd2:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    3dd7:	0f 94 c0             	sete   %al
    3dda:	84 c0                	test   %al,%al
    3ddc:	74 11                	je     3def <internal_handle_exception+0xf2>
    {
        sgx_spin_unlock(&g_handler_lock);
    3dde:	48 8d 3d fb d2 00 00 	lea    0xd2fb(%rip),%rdi        # 110e0 <_ZL14g_handler_lock>
    3de5:	e8 7c 76 00 00       	callq  b466 <sgx_spin_unlock>
        goto failed_end;
    3dea:	e9 f3 00 00 00       	jmpq   3ee2 <internal_handle_exception+0x1e5>
    }
    ntmp = nhead;
    3def:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3df3:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    node = g_first_node;
    3df7:	48 8b 05 da d2 00 00 	mov    0xd2da(%rip),%rax        # 110d8 <_ZL12g_first_node>
    3dfe:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    while(node != NULL)
    3e02:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    3e07:	74 21                	je     3e2a <internal_handle_exception+0x12d>
    {
        *ntmp = node->callback;
    3e09:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3e0d:	48 8b 10             	mov    (%rax),%rdx
    3e10:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3e14:	48 89 10             	mov    %rdx,(%rax)
        ntmp++;
    3e17:	48 83 45 d8 08       	addq   $0x8,-0x28(%rbp)
        node = node->next;
    3e1c:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3e20:	48 8b 40 08          	mov    0x8(%rax),%rax
    3e24:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    while(node != NULL)
    3e28:	eb d8                	jmp    3e02 <internal_handle_exception+0x105>
    }

    // read unlock
    sgx_spin_unlock(&g_handler_lock);
    3e2a:	48 8d 3d af d2 00 00 	lea    0xd2af(%rip),%rdi        # 110e0 <_ZL14g_handler_lock>
    3e31:	e8 30 76 00 00       	callq  b466 <sgx_spin_unlock>

    // call exception handler until EXCEPTION_CONTINUE_EXECUTION is returned
    ntmp = nhead;
    3e36:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3e3a:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    while(size > 0)
    3e3e:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    3e43:	74 38                	je     3e7d <internal_handle_exception+0x180>
    {
        sgx_exception_handler_t handler = DEC_VEH_POINTER(*ntmp);
    3e45:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    3e49:	48 8b 10             	mov    (%rax),%rdx
    3e4c:	48 8b 05 95 d2 00 00 	mov    0xd295(%rip),%rax        # 110e8 <_ZL12g_veh_cookie>
    3e53:	48 31 d0             	xor    %rdx,%rax
    3e56:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
        status = handler(info);
    3e5a:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
    3e5e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    3e62:	48 89 d7             	mov    %rdx,%rdi
    3e65:	ff d0                	callq  *%rax
    3e67:	89 45 c4             	mov    %eax,-0x3c(%rbp)
        if(EXCEPTION_CONTINUE_EXECUTION == status)
    3e6a:	83 7d c4 ff          	cmpl   $0xffffffff,-0x3c(%rbp)
    3e6e:	74 0c                	je     3e7c <internal_handle_exception+0x17f>
        {
            break;
        }
        ntmp++;
    3e70:	48 83 45 d8 08       	addq   $0x8,-0x28(%rbp)
        size -= sizeof(sgx_exception_handler_t);
    3e75:	48 83 6d d0 08       	subq   $0x8,-0x30(%rbp)
    while(size > 0)
    3e7a:	eb c2                	jmp    3e3e <internal_handle_exception+0x141>
            break;
    3e7c:	90                   	nop
    }
    free(nhead);
    3e7d:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3e81:	48 89 c7             	mov    %rax,%rdi
    3e84:	e8 16 5a 00 00       	callq  989f <dlfree>

    // call default handler
    // ignore invalid return value, treat to EXCEPTION_CONTINUE_SEARCH
    // check SP to be written on SSA is pointing to the trusted stack
    xsp = info->cpu_context.REG(sp);
    3e89:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3e8d:	48 8b 40 20          	mov    0x20(%rax),%rax
    3e91:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    if (!is_valid_sp(xsp))
    3e95:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    3e99:	48 89 c7             	mov    %rax,%rdi
    3e9c:	e8 eb fd ff ff       	callq  3c8c <is_valid_sp>
    3ea1:	83 f0 01             	xor    $0x1,%eax
    3ea4:	84 c0                	test   %al,%al
    3ea6:	75 39                	jne    3ee1 <internal_handle_exception+0x1e4>
    {
        goto failed_end;
    }

    if(EXCEPTION_CONTINUE_EXECUTION == status)
    3ea8:	83 7d c4 ff          	cmpl   $0xffffffff,-0x3c(%rbp)
    3eac:	75 16                	jne    3ec4 <internal_handle_exception+0x1c7>
    {
        //exception is handled, decrease the nested exception count
        thread_data->exception_flag--;
    3eae:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3eb2:	48 8b 40 60          	mov    0x60(%rax),%rax
    3eb6:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    3eba:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3ebe:	48 89 50 60          	mov    %rdx,0x60(%rax)
    3ec2:	eb 0c                	jmp    3ed0 <internal_handle_exception+0x1d3>
    }
    else
    {
        //exception cannot be handled
        thread_data->exception_flag = -1;
    3ec4:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3ec8:	48 c7 40 60 ff ff ff 	movq   $0xffffffffffffffff,0x60(%rax)
    3ecf:	ff 
    }

    //instruction triggering the exception will be executed again.
    continue_execution(info);
    3ed0:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3ed4:	48 89 c7             	mov    %rax,%rdi
    3ed7:	e8 01 8b 00 00       	callq  c9dd <continue_execution>
    3edc:	eb 04                	jmp    3ee2 <internal_handle_exception+0x1e5>
        goto failed_end;
    3ede:	90                   	nop
    3edf:	eb 01                	jmp    3ee2 <internal_handle_exception+0x1e5>
        goto failed_end;
    3ee1:	90                   	nop

failed_end:
    thread_data->exception_flag = -1; // mark the current exception cannot be handled
    3ee2:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    3ee6:	48 c7 40 60 ff ff ff 	movq   $0xffffffffffffffff,0x60(%rax)
    3eed:	ff 
    abort();    // throw abortion
    3eee:	e8 db 8a 00 00       	callq  c9ce <abort>

0000000000003ef3 <_ZL21expand_stack_by_pagesPvm>:
}

static int expand_stack_by_pages(void *start_addr, size_t page_count)
{
    3ef3:	55                   	push   %rbp
    3ef4:	48 89 e5             	mov    %rsp,%rbp
    3ef7:	48 83 ec 20          	sub    $0x20,%rsp
    3efb:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    3eff:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    int ret = -1;
    3f03:	c7 45 fc ff ff ff ff 	movl   $0xffffffff,-0x4(%rbp)

    if ((start_addr == NULL) || (page_count == 0))
    3f0a:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    3f0f:	74 07                	je     3f18 <_ZL21expand_stack_by_pagesPvm+0x25>
    3f11:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
    3f16:	75 07                	jne    3f1f <_ZL21expand_stack_by_pagesPvm+0x2c>
        return -1;
    3f18:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    3f1d:	eb 19                	jmp    3f38 <_ZL21expand_stack_by_pagesPvm+0x45>

    ret = apply_pages_within_exception(start_addr, page_count);
    3f1f:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    3f23:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3f27:	48 89 d6             	mov    %rdx,%rsi
    3f2a:	48 89 c7             	mov    %rax,%rdi
    3f2d:	e8 7c e2 ff ff       	callq  21ae <apply_pages_within_exception>
    3f32:	89 45 fc             	mov    %eax,-0x4(%rbp)
    return ret;
    3f35:	8b 45 fc             	mov    -0x4(%rbp),%eax
}
    3f38:	c9                   	leaveq 
    3f39:	c3                   	retq   

0000000000003f3a <trts_handle_exception>:
//      the pointer of TCS
// Return Value
//      none zero - success
//              0 - fail
extern "C" sgx_status_t trts_handle_exception(void *tcs)
{
    3f3a:	55                   	push   %rbp
    3f3b:	48 89 e5             	mov    %rsp,%rbp
    3f3e:	48 83 ec 50          	sub    $0x50,%rsp
    3f42:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    thread_data_t *thread_data = get_thread_data();
    3f46:	e8 54 87 00 00       	callq  c69f <get_thread_data>
    3f4b:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    ssa_gpr_t *ssa_gpr = NULL;
    3f4f:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    3f56:	00 
    sgx_exception_info_t *info = NULL;
    3f57:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    3f5e:	00 
    uintptr_t sp, *new_sp = NULL;
    3f5f:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    3f66:	00 
    size_t size = 0;
    3f67:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    3f6e:	00 

    if ((thread_data == NULL) || (tcs == NULL)) goto default_handler;
    3f6f:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    3f74:	0f 84 86 04 00 00    	je     4400 <trts_handle_exception+0x4c6>
    3f7a:	48 83 7d b8 00       	cmpq   $0x0,-0x48(%rbp)
    3f7f:	0f 84 7b 04 00 00    	je     4400 <trts_handle_exception+0x4c6>
    if (check_static_stack_canary(tcs) != 0)
    3f85:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3f89:	48 89 c7             	mov    %rax,%rdi
    3f8c:	e8 53 d7 ff ff       	callq  16e4 <check_static_stack_canary>
    3f91:	85 c0                	test   %eax,%eax
    3f93:	0f 95 c0             	setne  %al
    3f96:	84 c0                	test   %al,%al
    3f98:	0f 85 65 04 00 00    	jne    4403 <trts_handle_exception+0x4c9>
        goto default_handler;
 
    if(get_enclave_state() != ENCLAVE_INIT_DONE)
    3f9e:	e8 c9 86 00 00       	callq  c66c <get_enclave_state>
    3fa3:	83 f8 02             	cmp    $0x2,%eax
    3fa6:	0f 95 c0             	setne  %al
    3fa9:	84 c0                	test   %al,%al
    3fab:	0f 85 55 04 00 00    	jne    4406 <trts_handle_exception+0x4cc>
    {
        goto default_handler;
    }
    
    // check if the exception is raised from 2nd phrase
    if(thread_data->exception_flag == -1) {
    3fb1:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3fb5:	48 8b 40 60          	mov    0x60(%rax),%rax
    3fb9:	48 83 f8 ff          	cmp    $0xffffffffffffffff,%rax
    3fbd:	0f 84 46 04 00 00    	je     4409 <trts_handle_exception+0x4cf>
        goto default_handler;
    }
 
    if ((TD2TCS(thread_data) != tcs) 
    3fc3:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3fc7:	48 8b 40 10          	mov    0x10(%rax),%rax
    3fcb:	48 05 b0 02 01 00    	add    $0x102b0,%rax
    3fd1:	48 39 45 b8          	cmp    %rax,-0x48(%rbp)
    3fd5:	0f 85 25 04 00 00    	jne    4400 <trts_handle_exception+0x4c6>
            || (((thread_data->first_ssa_gpr)&(~0xfff)) - SE_PAGE_SIZE) != (uintptr_t)tcs) {
    3fdb:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3fdf:	48 8b 40 20          	mov    0x20(%rax),%rax
    3fe3:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    3fe9:	48 8d 90 00 f0 ff ff 	lea    -0x1000(%rax),%rdx
    3ff0:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    3ff4:	48 39 c2             	cmp    %rax,%rdx
    3ff7:	0f 85 03 04 00 00    	jne    4400 <trts_handle_exception+0x4c6>
        goto default_handler;
    }

    // no need to check the result of ssa_gpr because thread_data is always trusted
    ssa_gpr = reinterpret_cast<ssa_gpr_t *>(thread_data->first_ssa_gpr);
    3ffd:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4001:	48 8b 40 20          	mov    0x20(%rax),%rax
    4005:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    
    sp = ssa_gpr->REG(sp);
    4009:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    400d:	48 8b 40 20          	mov    0x20(%rax),%rax
    4011:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    if(!is_stack_addr((void*)sp, 0))  // check stack overrun only, alignment will be checked after exception handled
    4015:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4019:	be 00 00 00 00       	mov    $0x0,%esi
    401e:	48 89 c7             	mov    %rax,%rdi
    4021:	e8 f3 fb ff ff       	callq  3c19 <is_stack_addr>
    4026:	83 f0 01             	xor    $0x1,%eax
    4029:	84 c0                	test   %al,%al
    402b:	74 17                	je     4044 <trts_handle_exception+0x10a>
    {
        g_enclave_state = ENCLAVE_CRASHED;
    402d:	48 8d 05 6c d0 00 00 	lea    0xd06c(%rip),%rax        # 110a0 <g_enclave_state>
    4034:	c7 00 03 00 00 00    	movl   $0x3,(%rax)
        return SGX_ERROR_STACK_OVERRUN;
    403a:	b8 09 10 00 00       	mov    $0x1009,%eax
    403f:	e9 db 03 00 00       	jmpq   441f <trts_handle_exception+0x4e5>
    }

    size = 0;
    4044:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    404b:	00 
    // x86_64 requires a 128-bytes red zone, which begins directly
    // after the return addr and includes func's arguments
    size += RED_ZONE_SIZE;
    404c:	48 83 6d e8 80       	subq   $0xffffffffffffff80,-0x18(%rbp)

    // decrease the stack to give space for info
    size += sizeof(sgx_exception_info_t);
    4051:	48 81 45 e8 98 00 00 	addq   $0x98,-0x18(%rbp)
    4058:	00 
    sp -= size;
    4059:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    405d:	48 29 45 f0          	sub    %rax,-0x10(%rbp)
    sp = sp & ~0xF;
    4061:	48 83 65 f0 f0       	andq   $0xfffffffffffffff0,-0x10(%rbp)

    // check the decreased sp to make sure it is in the trusted stack range
    if(!is_stack_addr((void *)sp, size))
    4066:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    406a:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    406e:	48 89 d6             	mov    %rdx,%rsi
    4071:	48 89 c7             	mov    %rax,%rdi
    4074:	e8 a0 fb ff ff       	callq  3c19 <is_stack_addr>
    4079:	83 f0 01             	xor    $0x1,%eax
    407c:	84 c0                	test   %al,%al
    407e:	74 17                	je     4097 <trts_handle_exception+0x15d>
    {
        g_enclave_state = ENCLAVE_CRASHED;
    4080:	48 8d 05 19 d0 00 00 	lea    0xd019(%rip),%rax        # 110a0 <g_enclave_state>
    4087:	c7 00 03 00 00 00    	movl   $0x3,(%rax)
        return SGX_ERROR_STACK_OVERRUN;
    408d:	b8 09 10 00 00       	mov    $0x1009,%eax
    4092:	e9 88 03 00 00       	jmpq   441f <trts_handle_exception+0x4e5>
    }

    info = (sgx_exception_info_t *)sp;
    4097:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    409b:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    // decrease the stack to save the SSA[0]->ip
    size = sizeof(uintptr_t);
    409f:	48 c7 45 e8 08 00 00 	movq   $0x8,-0x18(%rbp)
    40a6:	00 
    sp -= size;
    40a7:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    40ab:	48 29 45 f0          	sub    %rax,-0x10(%rbp)
    if(!is_stack_addr((void *)sp, size))
    40af:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    40b3:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    40b7:	48 89 d6             	mov    %rdx,%rsi
    40ba:	48 89 c7             	mov    %rax,%rdi
    40bd:	e8 57 fb ff ff       	callq  3c19 <is_stack_addr>
    40c2:	83 f0 01             	xor    $0x1,%eax
    40c5:	84 c0                	test   %al,%al
    40c7:	74 17                	je     40e0 <trts_handle_exception+0x1a6>
    {
        g_enclave_state = ENCLAVE_CRASHED;
    40c9:	48 8d 05 d0 cf 00 00 	lea    0xcfd0(%rip),%rax        # 110a0 <g_enclave_state>
    40d0:	c7 00 03 00 00 00    	movl   $0x3,(%rax)
        return SGX_ERROR_STACK_OVERRUN;
    40d6:	b8 09 10 00 00       	mov    $0x1009,%eax
    40db:	e9 3f 03 00 00       	jmpq   441f <trts_handle_exception+0x4e5>
    }
    
    // sp is within limit_addr and commit_addr, currently only SGX 2.0 under hardware mode will enter this branch.^M
    if((size_t)sp < thread_data->stack_commit_addr)
    40e0:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    40e4:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    40eb:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    40ef:	0f 83 ca 00 00 00    	jae    41bf <trts_handle_exception+0x285>
    { 
        int ret = -1;
    40f5:	c7 45 c4 ff ff ff ff 	movl   $0xffffffff,-0x3c(%rbp)
        size_t page_aligned_delta = 0;
    40fc:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    4103:	00 
        /* try to allocate memory dynamically */
        page_aligned_delta = ROUND_TO(thread_data->stack_commit_addr - (size_t)sp, SE_PAGE_SIZE);
    4104:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4108:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    410f:	48 2b 45 f0          	sub    -0x10(%rbp),%rax
    4113:	48 05 ff 0f 00 00    	add    $0xfff,%rax
    4119:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    411f:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
        if ((thread_data->stack_commit_addr > page_aligned_delta)
    4123:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4127:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    412e:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    4132:	73 47                	jae    417b <trts_handle_exception+0x241>
                && ((thread_data->stack_commit_addr - page_aligned_delta) >= thread_data->stack_limit_addr))
    4134:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4138:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    413f:	48 2b 45 f8          	sub    -0x8(%rbp),%rax
    4143:	48 89 c2             	mov    %rax,%rdx
    4146:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    414a:	48 8b 40 18          	mov    0x18(%rax),%rax
    414e:	48 39 c2             	cmp    %rax,%rdx
    4151:	72 28                	jb     417b <trts_handle_exception+0x241>
        {
            ret = expand_stack_by_pages((void *)(thread_data->stack_commit_addr - page_aligned_delta), (page_aligned_delta >> SE_PAGE_SHIFT));
    4153:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4157:	48 c1 e8 0c          	shr    $0xc,%rax
    415b:	48 89 c2             	mov    %rax,%rdx
    415e:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4162:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    4169:	48 2b 45 f8          	sub    -0x8(%rbp),%rax
    416d:	48 89 d6             	mov    %rdx,%rsi
    4170:	48 89 c7             	mov    %rax,%rdi
    4173:	e8 7b fd ff ff       	callq  3ef3 <_ZL21expand_stack_by_pagesPvm>
    4178:	89 45 c4             	mov    %eax,-0x3c(%rbp)
        }
        if (ret == 0)
    417b:	83 7d c4 00          	cmpl   $0x0,-0x3c(%rbp)
    417f:	75 27                	jne    41a8 <trts_handle_exception+0x26e>
        {
            thread_data->stack_commit_addr -= page_aligned_delta;
    4181:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4185:	48 8b 80 98 00 00 00 	mov    0x98(%rax),%rax
    418c:	48 2b 45 f8          	sub    -0x8(%rbp),%rax
    4190:	48 89 c2             	mov    %rax,%rdx
    4193:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4197:	48 89 90 98 00 00 00 	mov    %rdx,0x98(%rax)
            return SGX_SUCCESS;
    419e:	b8 00 00 00 00       	mov    $0x0,%eax
    41a3:	e9 77 02 00 00       	jmpq   441f <trts_handle_exception+0x4e5>
        }
        else
        {
            g_enclave_state = ENCLAVE_CRASHED;
    41a8:	48 8d 05 f1 ce 00 00 	lea    0xcef1(%rip),%rax        # 110a0 <g_enclave_state>
    41af:	c7 00 03 00 00 00    	movl   $0x3,(%rax)
            return SGX_ERROR_STACK_OVERRUN;
    41b5:	b8 09 10 00 00       	mov    $0x1009,%eax
    41ba:	e9 60 02 00 00       	jmpq   441f <trts_handle_exception+0x4e5>
        }
    }
    if (size_t(&Lereport_inst) == ssa_gpr->REG(ip) && SE_EREPORT == ssa_gpr->REG(ax))
    41bf:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    41c3:	48 8b 80 88 00 00 00 	mov    0x88(%rax),%rax
    41ca:	48 8d 15 a5 87 00 00 	lea    0x87a5(%rip),%rdx        # c976 <Lereport_inst>
    41d1:	48 39 d0             	cmp    %rdx,%rax
    41d4:	75 4d                	jne    4223 <trts_handle_exception+0x2e9>
    41d6:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    41da:	48 8b 00             	mov    (%rax),%rax
    41dd:	48 85 c0             	test   %rax,%rax
    41e0:	75 41                	jne    4223 <trts_handle_exception+0x2e9>
    {
        // Handle the exception raised by EREPORT instruction
        ssa_gpr->REG(ip) += 3;     // Skip ENCLU, which is always a 3-byte instruction
    41e2:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    41e6:	48 8b 80 88 00 00 00 	mov    0x88(%rax),%rax
    41ed:	48 8d 50 03          	lea    0x3(%rax),%rdx
    41f1:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    41f5:	48 89 90 88 00 00 00 	mov    %rdx,0x88(%rax)
        ssa_gpr->REG(flags) |= 1;  // Set CF to indicate error condition, see implementation of do_report()
    41fc:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4200:	48 8b 80 80 00 00 00 	mov    0x80(%rax),%rax
    4207:	48 83 c8 01          	or     $0x1,%rax
    420b:	48 89 c2             	mov    %rax,%rdx
    420e:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4212:	48 89 90 80 00 00 00 	mov    %rdx,0x80(%rax)
        return SGX_SUCCESS;
    4219:	b8 00 00 00 00       	mov    $0x0,%eax
    421e:	e9 fc 01 00 00       	jmpq   441f <trts_handle_exception+0x4e5>
    }

    if(ssa_gpr->exit_info.valid != 1)
    4223:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4227:	0f b6 80 a3 00 00 00 	movzbl 0xa3(%rax),%eax
    422e:	83 e0 80             	and    $0xffffff80,%eax
    4231:	84 c0                	test   %al,%al
    4233:	0f 84 d3 01 00 00    	je     440c <trts_handle_exception+0x4d2>
    {   // exception handlers are not allowed to call in a non-exception state
        goto default_handler;
    }

    // initialize the info with SSA[0]
    info->exception_vector = (sgx_exception_vector_t)ssa_gpr->exit_info.vector;
    4239:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    423d:	0f b6 80 a0 00 00 00 	movzbl 0xa0(%rax),%eax
    4244:	0f b6 d0             	movzbl %al,%edx
    4247:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    424b:	89 90 90 00 00 00    	mov    %edx,0x90(%rax)
    info->exception_type = (sgx_exception_type_t)ssa_gpr->exit_info.exit_type;
    4251:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4255:	0f b6 80 a1 00 00 00 	movzbl 0xa1(%rax),%eax
    425c:	83 e0 07             	and    $0x7,%eax
    425f:	0f b6 d0             	movzbl %al,%edx
    4262:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4266:	89 90 94 00 00 00    	mov    %edx,0x94(%rax)

    info->cpu_context.REG(ax) = ssa_gpr->REG(ax);
    426c:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4270:	48 8b 10             	mov    (%rax),%rdx
    4273:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4277:	48 89 10             	mov    %rdx,(%rax)
    info->cpu_context.REG(cx) = ssa_gpr->REG(cx);
    427a:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    427e:	48 8b 50 08          	mov    0x8(%rax),%rdx
    4282:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4286:	48 89 50 08          	mov    %rdx,0x8(%rax)
    info->cpu_context.REG(dx) = ssa_gpr->REG(dx);
    428a:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    428e:	48 8b 50 10          	mov    0x10(%rax),%rdx
    4292:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4296:	48 89 50 10          	mov    %rdx,0x10(%rax)
    info->cpu_context.REG(bx) = ssa_gpr->REG(bx);
    429a:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    429e:	48 8b 50 18          	mov    0x18(%rax),%rdx
    42a2:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    42a6:	48 89 50 18          	mov    %rdx,0x18(%rax)
    info->cpu_context.REG(sp) = ssa_gpr->REG(sp);
    42aa:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    42ae:	48 8b 50 20          	mov    0x20(%rax),%rdx
    42b2:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    42b6:	48 89 50 20          	mov    %rdx,0x20(%rax)
    info->cpu_context.REG(bp) = ssa_gpr->REG(bp);
    42ba:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    42be:	48 8b 50 28          	mov    0x28(%rax),%rdx
    42c2:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    42c6:	48 89 50 28          	mov    %rdx,0x28(%rax)
    info->cpu_context.REG(si) = ssa_gpr->REG(si);
    42ca:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    42ce:	48 8b 50 30          	mov    0x30(%rax),%rdx
    42d2:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    42d6:	48 89 50 30          	mov    %rdx,0x30(%rax)
    info->cpu_context.REG(di) = ssa_gpr->REG(di);
    42da:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    42de:	48 8b 50 38          	mov    0x38(%rax),%rdx
    42e2:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    42e6:	48 89 50 38          	mov    %rdx,0x38(%rax)
    info->cpu_context.REG(flags) = ssa_gpr->REG(flags);
    42ea:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    42ee:	48 8b 90 80 00 00 00 	mov    0x80(%rax),%rdx
    42f5:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    42f9:	48 89 90 80 00 00 00 	mov    %rdx,0x80(%rax)
    info->cpu_context.REG(ip) = ssa_gpr->REG(ip);
    4300:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4304:	48 8b 90 88 00 00 00 	mov    0x88(%rax),%rdx
    430b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    430f:	48 89 90 88 00 00 00 	mov    %rdx,0x88(%rax)
#ifdef SE_64
    info->cpu_context.r8  = ssa_gpr->r8;
    4316:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    431a:	48 8b 50 40          	mov    0x40(%rax),%rdx
    431e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4322:	48 89 50 40          	mov    %rdx,0x40(%rax)
    info->cpu_context.r9  = ssa_gpr->r9;
    4326:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    432a:	48 8b 50 48          	mov    0x48(%rax),%rdx
    432e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4332:	48 89 50 48          	mov    %rdx,0x48(%rax)
    info->cpu_context.r10 = ssa_gpr->r10;
    4336:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    433a:	48 8b 50 50          	mov    0x50(%rax),%rdx
    433e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4342:	48 89 50 50          	mov    %rdx,0x50(%rax)
    info->cpu_context.r11 = ssa_gpr->r11;
    4346:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    434a:	48 8b 50 58          	mov    0x58(%rax),%rdx
    434e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4352:	48 89 50 58          	mov    %rdx,0x58(%rax)
    info->cpu_context.r12 = ssa_gpr->r12;
    4356:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    435a:	48 8b 50 60          	mov    0x60(%rax),%rdx
    435e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4362:	48 89 50 60          	mov    %rdx,0x60(%rax)
    info->cpu_context.r13 = ssa_gpr->r13;
    4366:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    436a:	48 8b 50 68          	mov    0x68(%rax),%rdx
    436e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4372:	48 89 50 68          	mov    %rdx,0x68(%rax)
    info->cpu_context.r14 = ssa_gpr->r14;
    4376:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    437a:	48 8b 50 70          	mov    0x70(%rax),%rdx
    437e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4382:	48 89 50 70          	mov    %rdx,0x70(%rax)
    info->cpu_context.r15 = ssa_gpr->r15;
    4386:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    438a:	48 8b 50 78          	mov    0x78(%rax),%rdx
    438e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4392:	48 89 50 78          	mov    %rdx,0x78(%rax)
#endif

    new_sp = (uintptr_t *)sp;
    4396:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    439a:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    ssa_gpr->REG(ip) = (size_t)internal_handle_exception; // prepare the ip for 2nd phrase handling
    439e:	48 8d 15 58 f9 ff ff 	lea    -0x6a8(%rip),%rdx        # 3cfd <internal_handle_exception>
    43a5:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    43a9:	48 89 90 88 00 00 00 	mov    %rdx,0x88(%rax)
    ssa_gpr->REG(sp) = (size_t)new_sp;      // new stack for internal_handle_exception
    43b0:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    43b4:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    43b8:	48 89 50 20          	mov    %rdx,0x20(%rax)
    ssa_gpr->REG(ax) = (size_t)info;        // 1st parameter (info) for LINUX32
    43bc:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    43c0:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    43c4:	48 89 10             	mov    %rdx,(%rax)
    ssa_gpr->REG(di) = (size_t)info;        // 1st parameter (info) for LINUX64, LINUX32 also uses it while restoring the context
    43c7:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    43cb:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    43cf:	48 89 50 38          	mov    %rdx,0x38(%rax)
    *new_sp = info->cpu_context.REG(ip);    // for debugger to get call trace
    43d3:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    43d7:	48 8b 90 88 00 00 00 	mov    0x88(%rax),%rdx
    43de:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    43e2:	48 89 10             	mov    %rdx,(%rax)
    
    //mark valid to 0 to prevent eenter again
    ssa_gpr->exit_info.valid = 0;
    43e5:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    43e9:	0f b6 90 a3 00 00 00 	movzbl 0xa3(%rax),%edx
    43f0:	83 e2 7f             	and    $0x7f,%edx
    43f3:	88 90 a3 00 00 00    	mov    %dl,0xa3(%rax)

    return SGX_SUCCESS;
    43f9:	b8 00 00 00 00       	mov    $0x0,%eax
    43fe:	eb 1f                	jmp    441f <trts_handle_exception+0x4e5>
 
default_handler:
    4400:	90                   	nop
    4401:	eb 0a                	jmp    440d <trts_handle_exception+0x4d3>
        goto default_handler;
    4403:	90                   	nop
    4404:	eb 07                	jmp    440d <trts_handle_exception+0x4d3>
        goto default_handler;
    4406:	90                   	nop
    4407:	eb 04                	jmp    440d <trts_handle_exception+0x4d3>
        goto default_handler;
    4409:	90                   	nop
    440a:	eb 01                	jmp    440d <trts_handle_exception+0x4d3>
        goto default_handler;
    440c:	90                   	nop
    g_enclave_state = ENCLAVE_CRASHED;
    440d:	48 8d 05 8c cc 00 00 	lea    0xcc8c(%rip),%rax        # 110a0 <g_enclave_state>
    4414:	c7 00 03 00 00 00    	movl   $0x3,(%rax)
    return SGX_ERROR_ENCLAVE_CRASHED;
    441a:	b8 06 10 00 00       	mov    $0x1006,%eax
}
    441f:	c9                   	leaveq 
    4420:	c3                   	retq   

0000000000004421 <get_xfeature_state>:
#define SE_OPTIMIZE_OFF
#endif

SE_OPTIMIZE_OFF
uint64_t get_xfeature_state()
{
    4421:	55                   	push   %rbp
    4422:	48 89 e5             	mov    %rsp,%rbp
    4425:	48 83 ec 10          	sub    $0x10,%rsp
    auto *report = sgx_self_report();
    4429:	e8 83 77 00 00       	callq  bbb1 <sgx_self_report>
    442e:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    g_xsave_enabled = (report->body.attributes.xfrm == SGX_XFRM_LEGACY) ? 0 : 1;
    4432:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4436:	48 8b 40 38          	mov    0x38(%rax),%rax
    443a:	48 83 f8 03          	cmp    $0x3,%rax
    443e:	0f 95 c0             	setne  %al
    4441:	0f b6 c0             	movzbl %al,%eax
    4444:	89 05 5a cc 00 00    	mov    %eax,0xcc5a(%rip)        # 110a4 <g_xsave_enabled>
    uint64_t xfrm = report->body.attributes.xfrm;
    444a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    444e:	48 8b 40 38          	mov    0x38(%rax),%rax
    4452:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
#endif

    // no secrets in target_info, report_data, and report. no need to clear them before return
    // tlibc functions cannot be used before calling init_optimized_libs().

    return xfrm;
    4456:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
}
    445a:	c9                   	leaveq 
    445b:	c3                   	retq   

000000000000445c <get_phdr>:

static int elf_tls_aligned_virtual_size(const void *enclave_base,
                            size_t *aligned_virtual_size);

static ElfW(Phdr)* get_phdr(const ElfW(Ehdr)* ehdr)
{
    445c:	55                   	push   %rbp
    445d:	48 89 e5             	mov    %rsp,%rbp
    4460:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    if (ehdr == NULL)
    4464:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    4469:	75 07                	jne    4472 <get_phdr+0x16>
        return NULL;  /* Invalid image. */
    446b:	b8 00 00 00 00       	mov    $0x0,%eax
    4470:	eb 5a                	jmp    44cc <get_phdr+0x70>

    /* Check the ElfW Magic number. */
    if ((ehdr->e_ident[EI_MAG0] != ELFMAG0) ||
    4472:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4476:	0f b6 00             	movzbl (%rax),%eax
    4479:	3c 7f                	cmp    $0x7f,%al
    447b:	75 24                	jne    44a1 <get_phdr+0x45>
        (ehdr->e_ident[EI_MAG1] != ELFMAG1) ||
    447d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4481:	0f b6 40 01          	movzbl 0x1(%rax),%eax
    if ((ehdr->e_ident[EI_MAG0] != ELFMAG0) ||
    4485:	3c 45                	cmp    $0x45,%al
    4487:	75 18                	jne    44a1 <get_phdr+0x45>
        (ehdr->e_ident[EI_MAG2] != ELFMAG2) ||
    4489:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    448d:	0f b6 40 02          	movzbl 0x2(%rax),%eax
        (ehdr->e_ident[EI_MAG1] != ELFMAG1) ||
    4491:	3c 4c                	cmp    $0x4c,%al
    4493:	75 0c                	jne    44a1 <get_phdr+0x45>
        (ehdr->e_ident[EI_MAG3] != ELFMAG3))
    4495:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4499:	0f b6 40 03          	movzbl 0x3(%rax),%eax
        (ehdr->e_ident[EI_MAG2] != ELFMAG2) ||
    449d:	3c 46                	cmp    $0x46,%al
    449f:	74 07                	je     44a8 <get_phdr+0x4c>
        return NULL;
    44a1:	b8 00 00 00 00       	mov    $0x0,%eax
    44a6:	eb 24                	jmp    44cc <get_phdr+0x70>

    /* Enclave image should be a shared object file. */
    if (ehdr->e_type != ET_DYN)
    44a8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    44ac:	0f b7 40 10          	movzwl 0x10(%rax),%eax
    44b0:	66 83 f8 03          	cmp    $0x3,%ax
    44b4:	74 07                	je     44bd <get_phdr+0x61>
        return NULL;
    44b6:	b8 00 00 00 00       	mov    $0x0,%eax
    44bb:	eb 0f                	jmp    44cc <get_phdr+0x70>

    return GET_PTR(ElfW(Phdr), ehdr, ehdr->e_phoff);
    44bd:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    44c1:	48 8b 50 20          	mov    0x20(%rax),%rdx
    44c5:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    44c9:	48 01 d0             	add    %rdx,%rax
}
    44cc:	5d                   	pop    %rbp
    44cd:	c3                   	retq   

00000000000044ce <get_sym>:

static ElfW(Sym)* get_sym(ElfW(Sym)* symtab, size_t idx)
{
    44ce:	55                   	push   %rbp
    44cf:	48 89 e5             	mov    %rsp,%rbp
    44d2:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    44d6:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    if(STB_WEAK == ELFW(ST_BIND)(symtab[idx].st_info)
    44da:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    44de:	48 89 d0             	mov    %rdx,%rax
    44e1:	48 01 c0             	add    %rax,%rax
    44e4:	48 01 d0             	add    %rdx,%rax
    44e7:	48 c1 e0 03          	shl    $0x3,%rax
    44eb:	48 89 c2             	mov    %rax,%rdx
    44ee:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    44f2:	48 01 d0             	add    %rdx,%rax
    44f5:	0f b6 40 04          	movzbl 0x4(%rax),%eax
    44f9:	c0 e8 04             	shr    $0x4,%al
    44fc:	3c 02                	cmp    $0x2,%al
    44fe:	75 2b                	jne    452b <get_sym+0x5d>
            && 0 == symtab[idx].st_value)
    4500:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    4504:	48 89 d0             	mov    %rdx,%rax
    4507:	48 01 c0             	add    %rax,%rax
    450a:	48 01 d0             	add    %rdx,%rax
    450d:	48 c1 e0 03          	shl    $0x3,%rax
    4511:	48 89 c2             	mov    %rax,%rdx
    4514:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4518:	48 01 d0             	add    %rdx,%rax
    451b:	48 8b 40 08          	mov    0x8(%rax),%rax
    451f:	48 85 c0             	test   %rax,%rax
    4522:	75 07                	jne    452b <get_sym+0x5d>
    {
        return NULL;
    4524:	b8 00 00 00 00       	mov    $0x0,%eax
    4529:	eb 1b                	jmp    4546 <get_sym+0x78>
    }

    return &symtab[idx];
    452b:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    452f:	48 89 d0             	mov    %rdx,%rax
    4532:	48 01 c0             	add    %rax,%rax
    4535:	48 01 d0             	add    %rdx,%rax
    4538:	48 c1 e0 03          	shl    $0x3,%rax
    453c:	48 89 c2             	mov    %rax,%rdx
    453f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4543:	48 01 d0             	add    %rdx,%rax
}
    4546:	5d                   	pop    %rbp
    4547:	c3                   	retq   

0000000000004548 <do_relocs>:
/* Relocation for x64 (with addend) */
static int do_relocs(const ElfW(Addr) enclave_base,
        ElfW(Addr) rela_offset,
        ElfW(Addr) sym_offset,
        size_t nr_relocs)
{
    4548:	55                   	push   %rbp
    4549:	48 89 e5             	mov    %rsp,%rbp
    454c:	48 83 ec 60          	sub    $0x60,%rsp
    4550:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    4554:	48 89 75 b0          	mov    %rsi,-0x50(%rbp)
    4558:	48 89 55 a8          	mov    %rdx,-0x58(%rbp)
    455c:	48 89 4d a0          	mov    %rcx,-0x60(%rbp)
    4560:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    4567:	00 00 
    4569:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    456d:	31 c0                	xor    %eax,%eax
    ElfW(Rela)* rela = GET_PTR(ElfW(Rela), enclave_base, rela_offset);
    456f:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
    4573:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    4577:	48 01 d0             	add    %rdx,%rax
    457a:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    ElfW(Sym)*  symtab = GET_PTR(ElfW(Sym), enclave_base, sym_offset);
    457e:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
    4582:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4586:	48 01 d0             	add    %rdx,%rax
    4589:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    ElfW(Sym)*  sym;
    size_t      i;
    size_t aligned_virtual_size = 0;
    458d:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    4594:	00 

    for (i = 0; i < nr_relocs; ++i, ++rela)
    4595:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    459c:	00 
    459d:	e9 a2 01 00 00       	jmpq   4744 <do_relocs+0x1fc>
    {
        ElfW(Addr)* reloc_addr = GET_PTR(ElfW(Addr), enclave_base, rela->r_offset);
    45a2:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    45a6:	48 8b 10             	mov    (%rax),%rdx
    45a9:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    45ad:	48 01 d0             	add    %rdx,%rax
    45b0:	48 89 45 e8          	mov    %rax,-0x18(%rbp)

        switch (ELF64_R_TYPE(rela->r_info))
    45b4:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    45b8:	48 8b 40 08          	mov    0x8(%rax),%rax
    45bc:	89 c0                	mov    %eax,%eax
    45be:	48 83 f8 12          	cmp    $0x12,%rax
    45c2:	0f 87 61 01 00 00    	ja     4729 <do_relocs+0x1e1>
    45c8:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
    45cf:	00 
    45d0:	48 8d 05 9d 8a 00 00 	lea    0x8a9d(%rip),%rax        # d074 <_ZZL16init_stack_guardPvE8__func__+0x14>
    45d7:	8b 04 02             	mov    (%rdx,%rax,1),%eax
    45da:	48 63 d0             	movslq %eax,%rdx
    45dd:	48 8d 05 90 8a 00 00 	lea    0x8a90(%rip),%rax        # d074 <_ZZL16init_stack_guardPvE8__func__+0x14>
    45e4:	48 01 d0             	add    %rdx,%rax
    45e7:	ff e0                	jmpq   *%rax
        {
            case R_X86_64_RELATIVE:
                *reloc_addr = enclave_base + (uintptr_t)rela->r_addend;
    45e9:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    45ed:	48 8b 40 10          	mov    0x10(%rax),%rax
    45f1:	48 89 c2             	mov    %rax,%rdx
    45f4:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    45f8:	48 01 c2             	add    %rax,%rdx
    45fb:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    45ff:	48 89 10             	mov    %rdx,(%rax)
                break;
    4602:	e9 33 01 00 00       	jmpq   473a <do_relocs+0x1f2>

            case R_X86_64_GLOB_DAT:
            case R_X86_64_JUMP_SLOT:
            case R_X86_64_64:
                sym = get_sym(symtab, ELF64_R_SYM(rela->r_info));
    4607:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    460b:	48 8b 40 08          	mov    0x8(%rax),%rax
    460f:	48 c1 e8 20          	shr    $0x20,%rax
    4613:	48 89 c2             	mov    %rax,%rdx
    4616:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    461a:	48 89 d6             	mov    %rdx,%rsi
    461d:	48 89 c7             	mov    %rax,%rdi
    4620:	e8 a9 fe ff ff       	callq  44ce <get_sym>
    4625:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
                if(!sym)
    4629:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    462e:	0f 84 ff 00 00 00    	je     4733 <do_relocs+0x1eb>
                    break;
                *reloc_addr = enclave_base + sym->st_value + (uintptr_t)rela->r_addend;
    4634:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4638:	48 8b 50 08          	mov    0x8(%rax),%rdx
    463c:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    4640:	48 01 c2             	add    %rax,%rdx
    4643:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4647:	48 8b 40 10          	mov    0x10(%rax),%rax
    464b:	48 01 c2             	add    %rax,%rdx
    464e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4652:	48 89 10             	mov    %rdx,(%rax)
                break;
    4655:	e9 e0 00 00 00       	jmpq   473a <do_relocs+0x1f2>

            case R_X86_64_DTPMOD64:
                *reloc_addr = 1;
    465a:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    465e:	48 c7 00 01 00 00 00 	movq   $0x1,(%rax)
                break;
    4665:	e9 d0 00 00 00       	jmpq   473a <do_relocs+0x1f2>
 
            case R_X86_64_DTPOFF64:
                sym = get_sym(symtab, ELF64_R_SYM(rela->r_info));
    466a:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    466e:	48 8b 40 08          	mov    0x8(%rax),%rax
    4672:	48 c1 e8 20          	shr    $0x20,%rax
    4676:	48 89 c2             	mov    %rax,%rdx
    4679:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    467d:	48 89 d6             	mov    %rdx,%rsi
    4680:	48 89 c7             	mov    %rax,%rdi
    4683:	e8 46 fe ff ff       	callq  44ce <get_sym>
    4688:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
                if(!sym)
    468c:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    4691:	0f 84 9f 00 00 00    	je     4736 <do_relocs+0x1ee>
                    break;
                *reloc_addr = sym->st_value + (uintptr_t)rela->r_addend;
    4697:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    469b:	48 8b 50 08          	mov    0x8(%rax),%rdx
    469f:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    46a3:	48 8b 40 10          	mov    0x10(%rax),%rax
    46a7:	48 01 c2             	add    %rax,%rdx
    46aa:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    46ae:	48 89 10             	mov    %rdx,(%rax)
                break;
    46b1:	e9 84 00 00 00       	jmpq   473a <do_relocs+0x1f2>

            case R_X86_64_TPOFF64:
                sym = get_sym(symtab, ELF64_R_SYM(rela->r_info));
    46b6:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    46ba:	48 8b 40 08          	mov    0x8(%rax),%rax
    46be:	48 c1 e8 20          	shr    $0x20,%rax
    46c2:	48 89 c2             	mov    %rax,%rdx
    46c5:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    46c9:	48 89 d6             	mov    %rdx,%rsi
    46cc:	48 89 c7             	mov    %rax,%rdi
    46cf:	e8 fa fd ff ff       	callq  44ce <get_sym>
    46d4:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
                if(!sym)
    46d8:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    46dd:	74 5a                	je     4739 <do_relocs+0x1f1>
                    break;

                if ((0 == elf_tls_aligned_virtual_size((void *)enclave_base, &aligned_virtual_size)) && (aligned_virtual_size))
    46df:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    46e3:	48 8d 55 c8          	lea    -0x38(%rbp),%rdx
    46e7:	48 89 d6             	mov    %rdx,%rsi
    46ea:	48 89 c7             	mov    %rax,%rdi
    46ed:	e8 4f 03 00 00       	callq  4a41 <elf_tls_aligned_virtual_size>
    46f2:	85 c0                	test   %eax,%eax
    46f4:	75 2c                	jne    4722 <do_relocs+0x1da>
    46f6:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    46fa:	48 85 c0             	test   %rax,%rax
    46fd:	74 23                	je     4722 <do_relocs+0x1da>
                {
                    *reloc_addr = sym->st_value + (uintptr_t)rela->r_addend - aligned_virtual_size;
    46ff:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4703:	48 8b 50 08          	mov    0x8(%rax),%rdx
    4707:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    470b:	48 8b 40 10          	mov    0x10(%rax),%rax
    470f:	48 01 c2             	add    %rax,%rdx
    4712:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4716:	48 29 c2             	sub    %rax,%rdx
    4719:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    471d:	48 89 10             	mov    %rdx,(%rax)
                    break;
    4720:	eb 18                	jmp    473a <do_relocs+0x1f2>
                }
                else
                    return -1;
    4722:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4727:	eb 2e                	jmp    4757 <do_relocs+0x20f>

            case R_X86_64_NONE:
                break;

            default:    /* unsupported relocs */
                return -1;
    4729:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    472e:	eb 27                	jmp    4757 <do_relocs+0x20f>
                break;
    4730:	90                   	nop
    4731:	eb 07                	jmp    473a <do_relocs+0x1f2>
                    break;
    4733:	90                   	nop
    4734:	eb 04                	jmp    473a <do_relocs+0x1f2>
                    break;
    4736:	90                   	nop
    4737:	eb 01                	jmp    473a <do_relocs+0x1f2>
                    break;
    4739:	90                   	nop
    for (i = 0; i < nr_relocs; ++i, ++rela)
    473a:	48 83 45 d8 01       	addq   $0x1,-0x28(%rbp)
    473f:	48 83 45 d0 18       	addq   $0x18,-0x30(%rbp)
    4744:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4748:	48 3b 45 a0          	cmp    -0x60(%rbp),%rax
    474c:	0f 82 50 fe ff ff    	jb     45a2 <do_relocs+0x5a>
        }
    }

    return 0;
    4752:	b8 00 00 00 00       	mov    $0x0,%eax
}
    4757:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    475b:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    4762:	00 00 
    4764:	74 05                	je     476b <do_relocs+0x223>
    4766:	e8 6f 0b 00 00       	callq  52da <__stack_chk_fail>
    476b:	c9                   	leaveq 
    476c:	c3                   	retq   

000000000000476d <relocate_enclave>:
 * it local symbol, so the code is like "fce3:	e8 98 12 00 00    call   10f80 <relocate_enclave>"
 * 0x9812=0x10f80-0xfce8
 */
__attribute__ ((visibility ("hidden")))
int relocate_enclave(void* enclave_base)
{
    476d:	55                   	push   %rbp
    476e:	48 89 e5             	mov    %rsp,%rbp
    4771:	48 83 c4 80          	add    $0xffffffffffffff80,%rsp
    4775:	48 89 7d 88          	mov    %rdi,-0x78(%rbp)
    ElfW(Half) phnum = 0;
    4779:	c7 45 94 00 00 00 00 	movl   $0x0,-0x6c(%rbp)
    ElfW(Ehdr) *ehdr = (ElfW(Ehdr)*)enclave_base;
    4780:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    4784:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    ElfW(Phdr) *phdr = get_phdr(ehdr);
    4788:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    478c:	48 89 c7             	mov    %rax,%rdi
    478f:	e8 c8 fc ff ff       	callq  445c <get_phdr>
    4794:	48 89 45 98          	mov    %rax,-0x68(%rbp)

    if (phdr == NULL)
    4798:	48 83 7d 98 00       	cmpq   $0x0,-0x68(%rbp)
    479d:	0f 85 c3 01 00 00    	jne    4966 <relocate_enclave+0x1f9>
        return -1;  /* Invalid image. */
    47a3:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    47a8:	e9 d2 01 00 00       	jmpq   497f <relocate_enclave+0x212>

    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    {
        /* Search for dynamic segment */
        if (phdr->p_type == PT_DYNAMIC)
    47ad:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    47b1:	8b 00                	mov    (%rax),%eax
    47b3:	83 f8 02             	cmp    $0x2,%eax
    47b6:	0f 85 a1 01 00 00    	jne    495d <relocate_enclave+0x1f0>
        {
            size_t      count;
            size_t      n_dyn = phdr->p_filesz/sizeof(ElfW(Dyn));
    47bc:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    47c0:	48 8b 40 20          	mov    0x20(%rax),%rax
    47c4:	48 c1 e8 04          	shr    $0x4,%rax
    47c8:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
            ElfW(Dyn)   *dyn = GET_PTR(ElfW(Dyn), ehdr, phdr->p_paddr);
    47cc:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    47d0:	48 8b 50 18          	mov    0x18(%rax),%rdx
    47d4:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    47d8:	48 01 d0             	add    %rdx,%rax
    47db:	48 89 45 a8          	mov    %rax,-0x58(%rbp)

            ElfW(Addr)   sym_offset = 0;
    47df:	48 c7 45 b0 00 00 00 	movq   $0x0,-0x50(%rbp)
    47e6:	00 
            ElfW(Addr)   rel_offset = 0;
    47e7:	48 c7 45 b8 00 00 00 	movq   $0x0,-0x48(%rbp)
    47ee:	00 
            ElfW(Addr)   plt_offset = 0;
    47ef:	48 c7 45 c0 00 00 00 	movq   $0x0,-0x40(%rbp)
    47f6:	00 

            size_t   rel_total_sz = 0;
    47f7:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    47fe:	00 
            size_t   rel_entry_sz = 0;
    47ff:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    4806:	00 
            size_t   plt_total_sz = 0;
    4807:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    480e:	00 

            for (count = 0; count < n_dyn; count++, dyn++)
    480f:	48 c7 45 a0 00 00 00 	movq   $0x0,-0x60(%rbp)
    4816:	00 
    4817:	e9 9b 00 00 00       	jmpq   48b7 <relocate_enclave+0x14a>
            {
                if (dyn->d_tag == DT_NULL)  /* End */
    481c:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4820:	48 8b 00             	mov    (%rax),%rax
    4823:	48 85 c0             	test   %rax,%rax
    4826:	0f 84 9b 00 00 00    	je     48c7 <relocate_enclave+0x15a>
                    break;

                switch (dyn->d_tag)
    482c:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4830:	48 8b 00             	mov    (%rax),%rax
    4833:	48 83 f8 17          	cmp    $0x17,%rax
    4837:	77 74                	ja     48ad <relocate_enclave+0x140>
    4839:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
    4840:	00 
    4841:	48 8d 05 78 88 00 00 	lea    0x8878(%rip),%rax        # d0c0 <_ZZL16init_stack_guardPvE8__func__+0x60>
    4848:	8b 04 02             	mov    (%rdx,%rax,1),%eax
    484b:	48 63 d0             	movslq %eax,%rdx
    484e:	48 8d 05 6b 88 00 00 	lea    0x886b(%rip),%rax        # d0c0 <_ZZL16init_stack_guardPvE8__func__+0x60>
    4855:	48 01 d0             	add    %rdx,%rax
    4858:	ff e0                	jmpq   *%rax
                {
                    case DT_SYMTAB: /* symbol table */
                        sym_offset = dyn->d_un.d_ptr;
    485a:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    485e:	48 8b 40 08          	mov    0x8(%rax),%rax
    4862:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
                        break;
    4866:	eb 45                	jmp    48ad <relocate_enclave+0x140>

                    case RTS_DT_REL:/* Rel (x86) or Rela (x64) relocs */
                        rel_offset = dyn->d_un.d_ptr;
    4868:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    486c:	48 8b 40 08          	mov    0x8(%rax),%rax
    4870:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
                        break;
    4874:	eb 37                	jmp    48ad <relocate_enclave+0x140>

                    case RTS_DT_RELSZ:
                        rel_total_sz = dyn->d_un.d_val;
    4876:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    487a:	48 8b 40 08          	mov    0x8(%rax),%rax
    487e:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
                        break;
    4882:	eb 29                	jmp    48ad <relocate_enclave+0x140>

                    case RTS_DT_RELENT:
                        rel_entry_sz = dyn->d_un.d_val;
    4884:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4888:	48 8b 40 08          	mov    0x8(%rax),%rax
    488c:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
                        break;
    4890:	eb 1b                	jmp    48ad <relocate_enclave+0x140>

                    case DT_JMPREL: /* PLT relocs */
                        plt_offset = dyn->d_un.d_ptr;
    4892:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4896:	48 8b 40 08          	mov    0x8(%rax),%rax
    489a:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
                        break;
    489e:	eb 0d                	jmp    48ad <relocate_enclave+0x140>

                    case DT_PLTRELSZ:
                        plt_total_sz = dyn->d_un.d_val;
    48a0:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    48a4:	48 8b 40 08          	mov    0x8(%rax),%rax
    48a8:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
                        break;
    48ac:	90                   	nop
            for (count = 0; count < n_dyn; count++, dyn++)
    48ad:	48 83 45 a0 01       	addq   $0x1,-0x60(%rbp)
    48b2:	48 83 45 a8 10       	addq   $0x10,-0x58(%rbp)
    48b7:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    48bb:	48 3b 45 e8          	cmp    -0x18(%rbp),%rax
    48bf:	0f 82 57 ff ff ff    	jb     481c <relocate_enclave+0xaf>
    48c5:	eb 01                	jmp    48c8 <relocate_enclave+0x15b>
                    break;
    48c7:	90                   	nop
                }
            }

            DO_REL(enclave_base, rel_offset, sym_offset, rel_total_sz, rel_entry_sz);
    48c8:	48 83 7d b8 00       	cmpq   $0x0,-0x48(%rbp)
    48cd:	74 45                	je     4914 <relocate_enclave+0x1a7>
    48cf:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    48d4:	75 0a                	jne    48e0 <relocate_enclave+0x173>
    48d6:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    48db:	e9 9f 00 00 00       	jmpq   497f <relocate_enclave+0x212>
    48e0:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    48e4:	ba 00 00 00 00       	mov    $0x0,%edx
    48e9:	48 f7 75 d0          	divq   -0x30(%rbp)
    48ed:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    48f1:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    48f5:	48 8b 4d f0          	mov    -0x10(%rbp),%rcx
    48f9:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    48fd:	48 8b 75 b8          	mov    -0x48(%rbp),%rsi
    4901:	48 89 c7             	mov    %rax,%rdi
    4904:	e8 3f fc ff ff       	callq  4548 <do_relocs>
    4909:	85 c0                	test   %eax,%eax
    490b:	74 07                	je     4914 <relocate_enclave+0x1a7>
    490d:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4912:	eb 6b                	jmp    497f <relocate_enclave+0x212>
            DO_REL(enclave_base, plt_offset, sym_offset, plt_total_sz, rel_entry_sz);
    4914:	48 83 7d c0 00       	cmpq   $0x0,-0x40(%rbp)
    4919:	74 42                	je     495d <relocate_enclave+0x1f0>
    491b:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    4920:	75 07                	jne    4929 <relocate_enclave+0x1bc>
    4922:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4927:	eb 56                	jmp    497f <relocate_enclave+0x212>
    4929:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    492d:	ba 00 00 00 00       	mov    $0x0,%edx
    4932:	48 f7 75 d0          	divq   -0x30(%rbp)
    4936:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    493a:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    493e:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    4942:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    4946:	48 8b 75 c0          	mov    -0x40(%rbp),%rsi
    494a:	48 89 c7             	mov    %rax,%rdi
    494d:	e8 f6 fb ff ff       	callq  4548 <do_relocs>
    4952:	85 c0                	test   %eax,%eax
    4954:	74 07                	je     495d <relocate_enclave+0x1f0>
    4956:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    495b:	eb 22                	jmp    497f <relocate_enclave+0x212>
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    495d:	83 45 94 01          	addl   $0x1,-0x6c(%rbp)
    4961:	48 83 45 98 38       	addq   $0x38,-0x68(%rbp)
    4966:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    496a:	0f b7 40 38          	movzwl 0x38(%rax),%eax
    496e:	0f b7 c0             	movzwl %ax,%eax
    4971:	39 45 94             	cmp    %eax,-0x6c(%rbp)
    4974:	0f 82 33 fe ff ff    	jb     47ad <relocate_enclave+0x40>
        }
    }

    return 0;
    497a:	b8 00 00 00 00       	mov    $0x0,%eax
}
    497f:	c9                   	leaveq 
    4980:	c3                   	retq   

0000000000004981 <elf_tls_info>:

int elf_tls_info(const void* enclave_base,
        uintptr_t *tls_addr, size_t *tdata_size)
{
    4981:	55                   	push   %rbp
    4982:	48 89 e5             	mov    %rsp,%rbp
    4985:	48 83 ec 38          	sub    $0x38,%rsp
    4989:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    498d:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    4991:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
    ElfW(Half) phnum = 0;
    4995:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%rbp)
    const ElfW(Ehdr) *ehdr = (const ElfW(Ehdr)*)enclave_base;
    499c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    49a0:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    ElfW(Phdr) *phdr = get_phdr(ehdr);
    49a4:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    49a8:	48 89 c7             	mov    %rax,%rdi
    49ab:	e8 ac fa ff ff       	callq  445c <get_phdr>
    49b0:	48 89 45 f0          	mov    %rax,-0x10(%rbp)

    if (!tls_addr || !tdata_size)
    49b4:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    49b9:	74 07                	je     49c2 <elf_tls_info+0x41>
    49bb:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    49c0:	75 07                	jne    49c9 <elf_tls_info+0x48>
        return -1;
    49c2:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    49c7:	eb 76                	jmp    4a3f <elf_tls_info+0xbe>

    if (phdr == NULL)
    49c9:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    49ce:	75 07                	jne    49d7 <elf_tls_info+0x56>
        return -1;  /* Invalid image. */
    49d0:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    49d5:	eb 68                	jmp    4a3f <elf_tls_info+0xbe>

    /* Search for TLS segment */
    *tls_addr = 0;
    49d7:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    49db:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    *tdata_size = 0;
    49e2:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    49e6:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    49ed:	eb 3b                	jmp    4a2a <elf_tls_info+0xa9>
    {
        if (phdr->p_type == PT_TLS)
    49ef:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    49f3:	8b 00                	mov    (%rax),%eax
    49f5:	83 f8 07             	cmp    $0x7,%eax
    49f8:	75 27                	jne    4a21 <elf_tls_info+0xa0>
        {
            /* tls_addr here is got from the program header, the address
             * need to be added by the enclave base.
             */
            *tls_addr = (size_t)enclave_base + phdr->p_vaddr;
    49fa:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    49fe:	48 8b 50 10          	mov    0x10(%rax),%rdx
    4a02:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4a06:	48 01 c2             	add    %rax,%rdx
    4a09:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4a0d:	48 89 10             	mov    %rdx,(%rax)
            *tdata_size = phdr->p_filesz;
    4a10:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4a14:	48 8b 50 20          	mov    0x20(%rax),%rdx
    4a18:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4a1c:	48 89 10             	mov    %rdx,(%rax)
            break;
    4a1f:	eb 19                	jmp    4a3a <elf_tls_info+0xb9>
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4a21:	83 45 ec 01          	addl   $0x1,-0x14(%rbp)
    4a25:	48 83 45 f0 38       	addq   $0x38,-0x10(%rbp)
    4a2a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4a2e:	0f b7 40 38          	movzwl 0x38(%rax),%eax
    4a32:	0f b7 c0             	movzwl %ax,%eax
    4a35:	39 45 ec             	cmp    %eax,-0x14(%rbp)
    4a38:	72 b5                	jb     49ef <elf_tls_info+0x6e>
        }
    }

    return 0;
    4a3a:	b8 00 00 00 00       	mov    $0x0,%eax
}
    4a3f:	c9                   	leaveq 
    4a40:	c3                   	retq   

0000000000004a41 <elf_tls_aligned_virtual_size>:

static int elf_tls_aligned_virtual_size(const void *enclave_base,
                                        size_t *aligned_virtual_size)
{
    4a41:	55                   	push   %rbp
    4a42:	48 89 e5             	mov    %rsp,%rbp
    4a45:	48 83 ec 40          	sub    $0x40,%rsp
    4a49:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    4a4d:	48 89 75 c0          	mov    %rsi,-0x40(%rbp)
    ElfW(Half) phnum = 0;
    4a51:	c7 45 dc 00 00 00 00 	movl   $0x0,-0x24(%rbp)
    const ElfW(Ehdr) *ehdr = (const ElfW(Ehdr)*)enclave_base;
    4a58:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4a5c:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    ElfW(Phdr) *phdr = get_phdr(ehdr);
    4a60:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4a64:	48 89 c7             	mov    %rax,%rdi
    4a67:	e8 f0 f9 ff ff       	callq  445c <get_phdr>
    4a6c:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    size_t virtual_size =0, align = 0;
    4a70:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
    4a77:	00 
    4a78:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    4a7f:	00 

    if (phdr == NULL)
    4a80:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
    4a85:	75 0a                	jne    4a91 <elf_tls_aligned_virtual_size+0x50>
        return -1;
    4a87:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4a8c:	e9 9c 00 00 00       	jmpq   4b2d <elf_tls_aligned_virtual_size+0xec>

    if (!aligned_virtual_size)
    4a91:	48 83 7d c0 00       	cmpq   $0x0,-0x40(%rbp)
    4a96:	75 0a                	jne    4aa2 <elf_tls_aligned_virtual_size+0x61>
        return -1;
    4a98:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4a9d:	e9 8b 00 00 00       	jmpq   4b2d <elf_tls_aligned_virtual_size+0xec>

    *aligned_virtual_size = 0;
    4aa2:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    4aa6:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4aad:	eb 69                	jmp    4b18 <elf_tls_aligned_virtual_size+0xd7>
    {
        if (phdr->p_type == PT_TLS)
    4aaf:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    4ab3:	8b 00                	mov    (%rax),%eax
    4ab5:	83 f8 07             	cmp    $0x7,%eax
    4ab8:	75 55                	jne    4b0f <elf_tls_aligned_virtual_size+0xce>
        {
            virtual_size = phdr->p_memsz;
    4aba:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    4abe:	48 8b 40 28          	mov    0x28(%rax),%rax
    4ac2:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
            align = phdr->p_align;
    4ac6:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    4aca:	48 8b 40 30          	mov    0x30(%rax),%rax
    4ace:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

            /* p_align == 0 or p_align == 1 means no alignment is required */
            if (align == 0 || align == 1)
    4ad2:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    4ad7:	74 07                	je     4ae0 <elf_tls_aligned_virtual_size+0x9f>
    4ad9:	48 83 7d f8 01       	cmpq   $0x1,-0x8(%rbp)
    4ade:	75 0d                	jne    4aed <elf_tls_aligned_virtual_size+0xac>
                *aligned_virtual_size = virtual_size;
    4ae0:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    4ae4:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    4ae8:	48 89 10             	mov    %rdx,(%rax)
            else
                *aligned_virtual_size = (virtual_size + align - 1) & (~(align - 1));

            break;
    4aeb:	eb 3b                	jmp    4b28 <elf_tls_aligned_virtual_size+0xe7>
                *aligned_virtual_size = (virtual_size + align - 1) & (~(align - 1));
    4aed:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    4af1:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4af5:	48 01 d0             	add    %rdx,%rax
    4af8:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    4afc:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4b00:	48 f7 d8             	neg    %rax
    4b03:	48 21 c2             	and    %rax,%rdx
    4b06:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    4b0a:	48 89 10             	mov    %rdx,(%rax)
            break;
    4b0d:	eb 19                	jmp    4b28 <elf_tls_aligned_virtual_size+0xe7>
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4b0f:	83 45 dc 01          	addl   $0x1,-0x24(%rbp)
    4b13:	48 83 45 e0 38       	addq   $0x38,-0x20(%rbp)
    4b18:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4b1c:	0f b7 40 38          	movzwl 0x38(%rax),%eax
    4b20:	0f b7 c0             	movzwl %ax,%eax
    4b23:	39 45 dc             	cmp    %eax,-0x24(%rbp)
    4b26:	72 87                	jb     4aaf <elf_tls_aligned_virtual_size+0x6e>
        }
    }

    return 0;
    4b28:	b8 00 00 00 00       	mov    $0x0,%eax
}
    4b2d:	c9                   	leaveq 
    4b2e:	c3                   	retq   

0000000000004b2f <elf_get_init_array>:

int elf_get_init_array(const void* enclave_base,
        uintptr_t *init_array_addr, size_t *init_array_size)
{
    4b2f:	55                   	push   %rbp
    4b30:	48 89 e5             	mov    %rsp,%rbp
    4b33:	48 83 ec 48          	sub    $0x48,%rsp
    4b37:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    4b3b:	48 89 75 c0          	mov    %rsi,-0x40(%rbp)
    4b3f:	48 89 55 b8          	mov    %rdx,-0x48(%rbp)
    ElfW(Half) phnum = 0;
    4b43:	c7 45 d4 00 00 00 00 	movl   $0x0,-0x2c(%rbp)
    const ElfW(Ehdr) *ehdr = (const ElfW(Ehdr)*)enclave_base;
    4b4a:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4b4e:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    ElfW(Phdr) *phdr = get_phdr(ehdr);
    4b52:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4b56:	48 89 c7             	mov    %rax,%rdi
    4b59:	e8 fe f8 ff ff       	callq  445c <get_phdr>
    4b5e:	48 89 45 d8          	mov    %rax,-0x28(%rbp)

    if (!init_array_addr || !init_array_size)
    4b62:	48 83 7d c0 00       	cmpq   $0x0,-0x40(%rbp)
    4b67:	74 07                	je     4b70 <elf_get_init_array+0x41>
    4b69:	48 83 7d b8 00       	cmpq   $0x0,-0x48(%rbp)
    4b6e:	75 0a                	jne    4b7a <elf_get_init_array+0x4b>
        return -1;
    4b70:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4b75:	e9 d0 00 00 00       	jmpq   4c4a <elf_get_init_array+0x11b>

    if (phdr == NULL)
    4b7a:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    4b7f:	75 0a                	jne    4b8b <elf_get_init_array+0x5c>
        return -1;  /* Invalid image. */
    4b81:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4b86:	e9 bf 00 00 00       	jmpq   4c4a <elf_get_init_array+0x11b>

    *init_array_addr = 0;
    4b8b:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    4b8f:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    *init_array_size = 0;
    4b96:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    4b9a:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)

    /* Search for Dynamic segment */
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4ba1:	e9 8b 00 00 00       	jmpq   4c31 <elf_get_init_array+0x102>
    {
        if (phdr->p_type == PT_DYNAMIC)
    4ba6:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4baa:	8b 00                	mov    (%rax),%eax
    4bac:	83 f8 02             	cmp    $0x2,%eax
    4baf:	75 77                	jne    4c28 <elf_get_init_array+0xf9>
        {
            size_t      count;
            size_t      n_dyn = phdr->p_filesz/sizeof(ElfW(Dyn));
    4bb1:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4bb5:	48 8b 40 20          	mov    0x20(%rax),%rax
    4bb9:	48 c1 e8 04          	shr    $0x4,%rax
    4bbd:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
            ElfW(Dyn)   *dyn = GET_PTR(ElfW(Dyn), ehdr, phdr->p_paddr);
    4bc1:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4bc5:	48 8b 50 18          	mov    0x18(%rax),%rdx
    4bc9:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4bcd:	48 01 d0             	add    %rdx,%rax
    4bd0:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
            
            for (count = 0; count < n_dyn; count++, dyn++)
    4bd4:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    4bdb:	00 
    4bdc:	eb 40                	jmp    4c1e <elf_get_init_array+0xef>
            {
                switch (dyn->d_tag)
    4bde:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4be2:	48 8b 00             	mov    (%rax),%rax
    4be5:	48 83 f8 19          	cmp    $0x19,%rax
    4be9:	74 08                	je     4bf3 <elf_get_init_array+0xc4>
    4beb:	48 83 f8 1b          	cmp    $0x1b,%rax
    4bef:	74 13                	je     4c04 <elf_get_init_array+0xd5>
    4bf1:	eb 21                	jmp    4c14 <elf_get_init_array+0xe5>
                {
                    case DT_INIT_ARRAY:
                        *init_array_addr = dyn->d_un.d_ptr;
    4bf3:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4bf7:	48 8b 50 08          	mov    0x8(%rax),%rdx
    4bfb:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    4bff:	48 89 10             	mov    %rdx,(%rax)
                        break;
    4c02:	eb 10                	jmp    4c14 <elf_get_init_array+0xe5>
                    case DT_INIT_ARRAYSZ:
                        *init_array_size = dyn->d_un.d_val;
    4c04:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4c08:	48 8b 50 08          	mov    0x8(%rax),%rdx
    4c0c:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    4c10:	48 89 10             	mov    %rdx,(%rax)
                        break;
    4c13:	90                   	nop
            for (count = 0; count < n_dyn; count++, dyn++)
    4c14:	48 83 45 e0 01       	addq   $0x1,-0x20(%rbp)
    4c19:	48 83 45 e8 10       	addq   $0x10,-0x18(%rbp)
    4c1e:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    4c22:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    4c26:	72 b6                	jb     4bde <elf_get_init_array+0xaf>
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4c28:	83 45 d4 01          	addl   $0x1,-0x2c(%rbp)
    4c2c:	48 83 45 d8 38       	addq   $0x38,-0x28(%rbp)
    4c31:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4c35:	0f b7 40 38          	movzwl 0x38(%rax),%eax
    4c39:	0f b7 c0             	movzwl %ax,%eax
    4c3c:	39 45 d4             	cmp    %eax,-0x2c(%rbp)
    4c3f:	0f 82 61 ff ff ff    	jb     4ba6 <elf_get_init_array+0x77>
                }
            }
        }
    }

    return 0;
    4c45:	b8 00 00 00 00       	mov    $0x0,%eax
}
    4c4a:	c9                   	leaveq 
    4c4b:	c3                   	retq   

0000000000004c4c <elf_get_uninit_array>:

int elf_get_uninit_array(const void* enclave_base,
        uintptr_t *uninit_array_addr, size_t *uninit_array_size)
{
    4c4c:	55                   	push   %rbp
    4c4d:	48 89 e5             	mov    %rsp,%rbp
    4c50:	48 83 ec 48          	sub    $0x48,%rsp
    4c54:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    4c58:	48 89 75 c0          	mov    %rsi,-0x40(%rbp)
    4c5c:	48 89 55 b8          	mov    %rdx,-0x48(%rbp)
    ElfW(Half) phnum = 0;
    4c60:	c7 45 d4 00 00 00 00 	movl   $0x0,-0x2c(%rbp)
    const ElfW(Ehdr) *ehdr = (const ElfW(Ehdr)*)enclave_base;
    4c67:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4c6b:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    ElfW(Phdr) *phdr = get_phdr(ehdr);
    4c6f:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4c73:	48 89 c7             	mov    %rax,%rdi
    4c76:	e8 e1 f7 ff ff       	callq  445c <get_phdr>
    4c7b:	48 89 45 d8          	mov    %rax,-0x28(%rbp)

    if (!uninit_array_addr || !uninit_array_size)
    4c7f:	48 83 7d c0 00       	cmpq   $0x0,-0x40(%rbp)
    4c84:	74 07                	je     4c8d <elf_get_uninit_array+0x41>
    4c86:	48 83 7d b8 00       	cmpq   $0x0,-0x48(%rbp)
    4c8b:	75 0a                	jne    4c97 <elf_get_uninit_array+0x4b>
        return -1;
    4c8d:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4c92:	e9 d0 00 00 00       	jmpq   4d67 <elf_get_uninit_array+0x11b>

    if (phdr == NULL)
    4c97:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    4c9c:	75 0a                	jne    4ca8 <elf_get_uninit_array+0x5c>
        return -1;  /* Invalid image. */
    4c9e:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    4ca3:	e9 bf 00 00 00       	jmpq   4d67 <elf_get_uninit_array+0x11b>

    *uninit_array_addr = 0;
    4ca8:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    4cac:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    *uninit_array_size = 0;
    4cb3:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    4cb7:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)

    /* Search for Dynamic segment */
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4cbe:	e9 8b 00 00 00       	jmpq   4d4e <elf_get_uninit_array+0x102>
    {
        if (phdr->p_type == PT_DYNAMIC)
    4cc3:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4cc7:	8b 00                	mov    (%rax),%eax
    4cc9:	83 f8 02             	cmp    $0x2,%eax
    4ccc:	75 77                	jne    4d45 <elf_get_uninit_array+0xf9>
        {
            size_t      count;
            size_t      n_dyn = phdr->p_filesz/sizeof(ElfW(Dyn));
    4cce:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4cd2:	48 8b 40 20          	mov    0x20(%rax),%rax
    4cd6:	48 c1 e8 04          	shr    $0x4,%rax
    4cda:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
            ElfW(Dyn)   *dyn = GET_PTR(ElfW(Dyn), ehdr, phdr->p_paddr);
    4cde:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4ce2:	48 8b 50 18          	mov    0x18(%rax),%rdx
    4ce6:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4cea:	48 01 d0             	add    %rdx,%rax
    4ced:	48 89 45 e8          	mov    %rax,-0x18(%rbp)

            for (count = 0; count < n_dyn; count++, dyn++)
    4cf1:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    4cf8:	00 
    4cf9:	eb 40                	jmp    4d3b <elf_get_uninit_array+0xef>
            {
                switch (dyn->d_tag)
    4cfb:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4cff:	48 8b 00             	mov    (%rax),%rax
    4d02:	48 83 f8 1a          	cmp    $0x1a,%rax
    4d06:	74 08                	je     4d10 <elf_get_uninit_array+0xc4>
    4d08:	48 83 f8 1c          	cmp    $0x1c,%rax
    4d0c:	74 13                	je     4d21 <elf_get_uninit_array+0xd5>
    4d0e:	eb 21                	jmp    4d31 <elf_get_uninit_array+0xe5>
                {
                    case DT_FINI_ARRAY:
                        *uninit_array_addr = dyn->d_un.d_ptr;
    4d10:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4d14:	48 8b 50 08          	mov    0x8(%rax),%rdx
    4d18:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    4d1c:	48 89 10             	mov    %rdx,(%rax)
                        break;
    4d1f:	eb 10                	jmp    4d31 <elf_get_uninit_array+0xe5>
                    case DT_FINI_ARRAYSZ:
                        *uninit_array_size = dyn->d_un.d_val;
    4d21:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4d25:	48 8b 50 08          	mov    0x8(%rax),%rdx
    4d29:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    4d2d:	48 89 10             	mov    %rdx,(%rax)
                        break;
    4d30:	90                   	nop
            for (count = 0; count < n_dyn; count++, dyn++)
    4d31:	48 83 45 e0 01       	addq   $0x1,-0x20(%rbp)
    4d36:	48 83 45 e8 10       	addq   $0x10,-0x18(%rbp)
    4d3b:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    4d3f:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    4d43:	72 b6                	jb     4cfb <elf_get_uninit_array+0xaf>
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4d45:	83 45 d4 01          	addl   $0x1,-0x2c(%rbp)
    4d49:	48 83 45 d8 38       	addq   $0x38,-0x28(%rbp)
    4d4e:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4d52:	0f b7 40 38          	movzwl 0x38(%rax),%eax
    4d56:	0f b7 c0             	movzwl %ax,%eax
    4d59:	39 45 d4             	cmp    %eax,-0x2c(%rbp)
    4d5c:	0f 82 61 ff ff ff    	jb     4cc3 <elf_get_uninit_array+0x77>
                }
            }
        }
    }

    return 0;
    4d62:	b8 00 00 00 00       	mov    $0x0,%eax
}
    4d67:	c9                   	leaveq 
    4d68:	c3                   	retq   

0000000000004d69 <has_text_relo>:

static int has_text_relo(const ElfW(Ehdr) *ehdr, const ElfW(Phdr) *phdr, ElfW(Half) phnum)
{
    4d69:	55                   	push   %rbp
    4d6a:	48 89 e5             	mov    %rsp,%rbp
    4d6d:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    4d71:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    4d75:	89 55 cc             	mov    %edx,-0x34(%rbp)
    ElfW(Half) phi = 0;
    4d78:	c7 45 e0 00 00 00 00 	movl   $0x0,-0x20(%rbp)
    int text_relo = 0;
    4d7f:	c7 45 e4 00 00 00 00 	movl   $0x0,-0x1c(%rbp)

    for (; phi < phnum; phi++, phdr++)
    4d86:	eb 7c                	jmp    4e04 <has_text_relo+0x9b>
    {
        if (phdr->p_type == PT_DYNAMIC)
    4d88:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4d8c:	8b 00                	mov    (%rax),%eax
    4d8e:	83 f8 02             	cmp    $0x2,%eax
    4d91:	75 68                	jne    4dfb <has_text_relo+0x92>
        {
            size_t count;
            size_t n_dyn = phdr->p_filesz/sizeof(ElfW(Dyn));
    4d93:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4d97:	48 8b 40 20          	mov    0x20(%rax),%rax
    4d9b:	48 c1 e8 04          	shr    $0x4,%rax
    4d9f:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
            ElfW(Dyn) *dyn = GET_PTR(ElfW(Dyn), ehdr, phdr->p_paddr);
    4da3:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    4da7:	48 8b 50 18          	mov    0x18(%rax),%rdx
    4dab:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4daf:	48 01 d0             	add    %rdx,%rax
    4db2:	48 89 45 f0          	mov    %rax,-0x10(%rbp)

            for (count = 0; count < n_dyn; count++, dyn++)
    4db6:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    4dbd:	00 
    4dbe:	eb 2c                	jmp    4dec <has_text_relo+0x83>
            {
                if (dyn->d_tag == DT_NULL)
    4dc0:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4dc4:	48 8b 00             	mov    (%rax),%rax
    4dc7:	48 85 c0             	test   %rax,%rax
    4dca:	74 2c                	je     4df8 <has_text_relo+0x8f>
                    break;

                if (dyn->d_tag == DT_TEXTREL)
    4dcc:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4dd0:	48 8b 00             	mov    (%rax),%rax
    4dd3:	48 83 f8 16          	cmp    $0x16,%rax
    4dd7:	75 09                	jne    4de2 <has_text_relo+0x79>
                {
                    text_relo = 1;
    4dd9:	c7 45 e4 01 00 00 00 	movl   $0x1,-0x1c(%rbp)
                    break;
    4de0:	eb 17                	jmp    4df9 <has_text_relo+0x90>
            for (count = 0; count < n_dyn; count++, dyn++)
    4de2:	48 83 45 e8 01       	addq   $0x1,-0x18(%rbp)
    4de7:	48 83 45 f0 10       	addq   $0x10,-0x10(%rbp)
    4dec:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4df0:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    4df4:	72 ca                	jb     4dc0 <has_text_relo+0x57>
                }
            }
            break;
    4df6:	eb 18                	jmp    4e10 <has_text_relo+0xa7>
                    break;
    4df8:	90                   	nop
            break;
    4df9:	eb 15                	jmp    4e10 <has_text_relo+0xa7>
    for (; phi < phnum; phi++, phdr++)
    4dfb:	83 45 e0 01          	addl   $0x1,-0x20(%rbp)
    4dff:	48 83 45 d0 38       	addq   $0x38,-0x30(%rbp)
    4e04:	8b 45 e0             	mov    -0x20(%rbp),%eax
    4e07:	3b 45 cc             	cmp    -0x34(%rbp),%eax
    4e0a:	0f 82 78 ff ff ff    	jb     4d88 <has_text_relo+0x1f>
        }
    }
    return text_relo;
    4e10:	8b 45 e4             	mov    -0x1c(%rbp),%eax
}
    4e13:	5d                   	pop    %rbp
    4e14:	c3                   	retq   

0000000000004e15 <change_protection>:

sgx_status_t change_protection(void *enclave_base)
{
    4e15:	55                   	push   %rbp
    4e16:	48 89 e5             	mov    %rsp,%rbp
    4e19:	48 83 ec 60          	sub    $0x60,%rsp
    4e1d:	48 89 7d a8          	mov    %rdi,-0x58(%rbp)
    ElfW(Half) phnum = 0;
    4e21:	c7 45 b8 00 00 00 00 	movl   $0x0,-0x48(%rbp)
    const ElfW(Ehdr) *ehdr = (const ElfW(Ehdr)*)enclave_base;
    4e28:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4e2c:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    const ElfW(Phdr) *phdr = get_phdr(ehdr);
    4e30:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4e34:	48 89 c7             	mov    %rax,%rdi
    4e37:	e8 20 f6 ff ff       	callq  445c <get_phdr>
    4e3c:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    uint64_t perms;
    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    4e40:	c7 45 c0 01 00 00 00 	movl   $0x1,-0x40(%rbp)

    if (phdr == NULL)
    4e47:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    4e4c:	75 08                	jne    4e56 <change_protection+0x41>
        return status;
    4e4e:	8b 45 c0             	mov    -0x40(%rbp),%eax
    4e51:	e9 65 02 00 00       	jmpq   50bb <change_protection+0x2a6>

    int text_relocation = has_text_relo(ehdr, phdr, ehdr->e_phnum);
    4e56:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4e5a:	0f b7 40 38          	movzwl 0x38(%rax),%eax
    4e5e:	0f b7 d0             	movzwl %ax,%edx
    4e61:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    4e65:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4e69:	48 89 ce             	mov    %rcx,%rsi
    4e6c:	48 89 c7             	mov    %rax,%rdi
    4e6f:	e8 f5 fe ff ff       	callq  4d69 <has_text_relo>
    4e74:	89 45 c4             	mov    %eax,-0x3c(%rbp)

    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4e77:	e9 6e 01 00 00       	jmpq   4fea <change_protection+0x1d5>
    {
        if (text_relocation && (phdr->p_type == PT_LOAD) && ((phdr->p_flags & PF_W) == 0))
    4e7c:	83 7d c4 00          	cmpl   $0x0,-0x3c(%rbp)
    4e80:	0f 84 c7 00 00 00    	je     4f4d <change_protection+0x138>
    4e86:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4e8a:	8b 00                	mov    (%rax),%eax
    4e8c:	83 f8 01             	cmp    $0x1,%eax
    4e8f:	0f 85 b8 00 00 00    	jne    4f4d <change_protection+0x138>
    4e95:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4e99:	8b 40 04             	mov    0x4(%rax),%eax
    4e9c:	83 e0 02             	and    $0x2,%eax
    4e9f:	85 c0                	test   %eax,%eax
    4ea1:	0f 85 a6 00 00 00    	jne    4f4d <change_protection+0x138>
        {
            perms = 0;
    4ea7:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    4eae:	00 
            size_t start = (size_t)enclave_base + (phdr->p_vaddr & (size_t)(~(SE_PAGE_SIZE-1)));
    4eaf:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4eb3:	48 8b 40 10          	mov    0x10(%rax),%rax
    4eb7:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    4ebd:	48 89 c2             	mov    %rax,%rdx
    4ec0:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4ec4:	48 01 d0             	add    %rdx,%rax
    4ec7:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
            size_t end = (size_t)enclave_base + ((phdr->p_vaddr + phdr->p_memsz + SE_PAGE_SIZE - 1) & (size_t)(~(SE_PAGE_SIZE-1)));
    4ecb:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4ecf:	48 8b 50 10          	mov    0x10(%rax),%rdx
    4ed3:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4ed7:	48 8b 40 28          	mov    0x28(%rax),%rax
    4edb:	48 01 d0             	add    %rdx,%rax
    4ede:	48 05 ff 0f 00 00    	add    $0xfff,%rax
    4ee4:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    4eea:	48 89 c2             	mov    %rax,%rdx
    4eed:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4ef1:	48 01 d0             	add    %rdx,%rax
    4ef4:	48 89 45 e8          	mov    %rax,-0x18(%rbp)

            if (phdr->p_flags & PF_R)
    4ef8:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4efc:	8b 40 04             	mov    0x4(%rax),%eax
    4eff:	83 e0 04             	and    $0x4,%eax
    4f02:	85 c0                	test   %eax,%eax
    4f04:	74 05                	je     4f0b <change_protection+0xf6>
                perms |= SI_FLAG_R;
    4f06:	48 83 4d d0 01       	orq    $0x1,-0x30(%rbp)
            if (phdr->p_flags & PF_X)
    4f0b:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4f0f:	8b 40 04             	mov    0x4(%rax),%eax
    4f12:	83 e0 01             	and    $0x1,%eax
    4f15:	85 c0                	test   %eax,%eax
    4f17:	74 05                	je     4f1e <change_protection+0x109>
                perms |= SI_FLAG_X;
    4f19:	48 83 4d d0 04       	orq    $0x4,-0x30(%rbp)

            if((status = trts_mprotect(start, end - start, perms)) != SGX_SUCCESS)
    4f1e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    4f22:	48 2b 45 e0          	sub    -0x20(%rbp),%rax
    4f26:	48 89 c1             	mov    %rax,%rcx
    4f29:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    4f2d:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    4f31:	48 89 ce             	mov    %rcx,%rsi
    4f34:	48 89 c7             	mov    %rax,%rdi
    4f37:	e8 92 e3 ff ff       	callq  32ce <trts_mprotect>
    4f3c:	89 45 c0             	mov    %eax,-0x40(%rbp)
    4f3f:	83 7d c0 00          	cmpl   $0x0,-0x40(%rbp)
    4f43:	74 08                	je     4f4d <change_protection+0x138>
                return status;
    4f45:	8b 45 c0             	mov    -0x40(%rbp),%eax
    4f48:	e9 6e 01 00 00       	jmpq   50bb <change_protection+0x2a6>
        }

        if (phdr->p_type == PT_GNU_RELRO)
    4f4d:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4f51:	8b 00                	mov    (%rax),%eax
    4f53:	3d 52 e5 74 64       	cmp    $0x6474e552,%eax
    4f58:	0f 85 83 00 00 00    	jne    4fe1 <change_protection+0x1cc>
        {
            size_t start = (size_t)enclave_base + (phdr->p_vaddr & (size_t)(~(SE_PAGE_SIZE-1)));
    4f5e:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4f62:	48 8b 40 10          	mov    0x10(%rax),%rax
    4f66:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    4f6c:	48 89 c2             	mov    %rax,%rdx
    4f6f:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4f73:	48 01 d0             	add    %rdx,%rax
    4f76:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
            size_t end = (size_t)enclave_base + ((phdr->p_vaddr + phdr->p_memsz + SE_PAGE_SIZE - 1) & (size_t)(~(SE_PAGE_SIZE-1)));
    4f7a:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4f7e:	48 8b 50 10          	mov    0x10(%rax),%rdx
    4f82:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    4f86:	48 8b 40 28          	mov    0x28(%rax),%rax
    4f8a:	48 01 d0             	add    %rdx,%rax
    4f8d:	48 05 ff 0f 00 00    	add    $0xfff,%rax
    4f93:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
    4f99:	48 89 c2             	mov    %rax,%rdx
    4f9c:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    4fa0:	48 01 d0             	add    %rdx,%rax
    4fa3:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
            if ((start != end) &&
    4fa7:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4fab:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    4faf:	74 30                	je     4fe1 <change_protection+0x1cc>
                    (status = trts_mprotect(start, end - start, SI_FLAG_R)) != SGX_SUCCESS)
    4fb1:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    4fb5:	48 2b 45 f0          	sub    -0x10(%rbp),%rax
    4fb9:	48 89 c1             	mov    %rax,%rcx
            if ((start != end) &&
    4fbc:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    4fc0:	ba 01 00 00 00       	mov    $0x1,%edx
    4fc5:	48 89 ce             	mov    %rcx,%rsi
    4fc8:	48 89 c7             	mov    %rax,%rdi
    4fcb:	e8 fe e2 ff ff       	callq  32ce <trts_mprotect>
    4fd0:	89 45 c0             	mov    %eax,-0x40(%rbp)
    4fd3:	83 7d c0 00          	cmpl   $0x0,-0x40(%rbp)
    4fd7:	74 08                	je     4fe1 <change_protection+0x1cc>
                return status;
    4fd9:	8b 45 c0             	mov    -0x40(%rbp),%eax
    4fdc:	e9 da 00 00 00       	jmpq   50bb <change_protection+0x2a6>
    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    4fe1:	83 45 b8 01          	addl   $0x1,-0x48(%rbp)
    4fe5:	48 83 45 c8 38       	addq   $0x38,-0x38(%rbp)
    4fea:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    4fee:	0f b7 40 38          	movzwl 0x38(%rax),%eax
    4ff2:	0f b7 c0             	movzwl %ax,%eax
    4ff5:	39 45 b8             	cmp    %eax,-0x48(%rbp)
    4ff8:	0f 82 7e fe ff ff    	jb     4e7c <change_protection+0x67>
        }
    }

    //The <ReservedMemMinSize> memory region's attributes has been set to RW if EDMM is supported by URTS.
    //So do_eaccept() to accept these pages.
    uint32_t i = 0;
    4ffe:	c7 45 bc 00 00 00 00 	movl   $0x0,-0x44(%rbp)
    for (i = 0; i < g_global_data.layout_entry_num; i++)
    5005:	c7 45 bc 00 00 00 00 	movl   $0x0,-0x44(%rbp)
    500c:	e9 93 00 00 00       	jmpq   50a4 <change_protection+0x28f>
    {
        if (g_global_data.layout_table[i].entry.id == LAYOUT_ID_RSRV_MIN && g_global_data.layout_table[i].entry.si_flags ==  SI_FLAGS_RWX)
    5011:	8b 45 bc             	mov    -0x44(%rbp),%eax
    5014:	48 c1 e0 05          	shl    $0x5,%rax
    5018:	48 89 c2             	mov    %rax,%rdx
    501b:	48 8d 05 8e 82 00 00 	lea    0x828e(%rip),%rax        # d2b0 <g_global_data+0x130>
    5022:	0f b7 04 02          	movzwl (%rdx,%rax,1),%eax
    5026:	66 83 f8 14          	cmp    $0x14,%ax
    502a:	75 74                	jne    50a0 <change_protection+0x28b>
    502c:	8b 45 bc             	mov    -0x44(%rbp),%eax
    502f:	48 83 c0 0a          	add    $0xa,%rax
    5033:	48 c1 e0 05          	shl    $0x5,%rax
    5037:	48 89 c2             	mov    %rax,%rdx
    503a:	48 8d 05 47 81 00 00 	lea    0x8147(%rip),%rax        # d188 <g_global_data+0x8>
    5041:	48 8b 04 02          	mov    (%rdx,%rax,1),%rax
    5045:	48 3d 07 02 00 00    	cmp    $0x207,%rax
    504b:	75 53                	jne    50a0 <change_protection+0x28b>
        {
            if((status = trts_mprotect((size_t)((size_t)enclave_base + g_global_data.layout_table[i].entry.rva), 
                                                                     g_global_data.layout_table[i].entry.page_count << SE_PAGE_SHIFT, 
    504d:	8b 45 bc             	mov    -0x44(%rbp),%eax
    5050:	48 c1 e0 05          	shl    $0x5,%rax
    5054:	48 89 c2             	mov    %rax,%rdx
    5057:	48 8d 05 56 82 00 00 	lea    0x8256(%rip),%rax        # d2b4 <g_global_data+0x134>
    505e:	8b 04 02             	mov    (%rdx,%rax,1),%eax
    5061:	c1 e0 0c             	shl    $0xc,%eax
            if((status = trts_mprotect((size_t)((size_t)enclave_base + g_global_data.layout_table[i].entry.rva), 
    5064:	89 c1                	mov    %eax,%ecx
    5066:	8b 45 bc             	mov    -0x44(%rbp),%eax
    5069:	48 c1 e0 05          	shl    $0x5,%rax
    506d:	48 89 c2             	mov    %rax,%rdx
    5070:	48 8d 05 41 82 00 00 	lea    0x8241(%rip),%rax        # d2b8 <g_global_data+0x138>
    5077:	48 8b 14 02          	mov    (%rdx,%rax,1),%rdx
    507b:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    507f:	48 01 d0             	add    %rdx,%rax
    5082:	ba 03 00 00 00       	mov    $0x3,%edx
    5087:	48 89 ce             	mov    %rcx,%rsi
    508a:	48 89 c7             	mov    %rax,%rdi
    508d:	e8 3c e2 ff ff       	callq  32ce <trts_mprotect>
    5092:	89 45 c0             	mov    %eax,-0x40(%rbp)
    5095:	83 7d c0 00          	cmpl   $0x0,-0x40(%rbp)
    5099:	74 1a                	je     50b5 <change_protection+0x2a0>
                                                                           SI_FLAG_R|SI_FLAG_W)) != SGX_SUCCESS)
                return status;
    509b:	8b 45 c0             	mov    -0x40(%rbp),%eax
    509e:	eb 1b                	jmp    50bb <change_protection+0x2a6>
    for (i = 0; i < g_global_data.layout_entry_num; i++)
    50a0:	83 45 bc 01          	addl   $0x1,-0x44(%rbp)
    50a4:	8b 05 fe 81 00 00    	mov    0x81fe(%rip),%eax        # d2a8 <g_global_data+0x128>
    50aa:	39 45 bc             	cmp    %eax,-0x44(%rbp)
    50ad:	0f 82 5e ff ff ff    	jb     5011 <change_protection+0x1fc>
    50b3:	eb 01                	jmp    50b6 <change_protection+0x2a1>
            break;
    50b5:	90                   	nop
        }
    }

    return SGX_SUCCESS;
    50b6:	b8 00 00 00 00       	mov    $0x0,%eax
}
    50bb:	c9                   	leaveq 
    50bc:	c3                   	retq   

00000000000050bd <do_atexit_aux>:
{
    return __cxa_atexit((void (*)(void *))fun, NULL, __dso_handle);
}

static void do_atexit_aux(void)
{
    50bd:	55                   	push   %rbp
    50be:	48 89 e5             	mov    %rsp,%rbp
    50c1:	48 83 ec 20          	sub    $0x20,%rsp
    exit_function_t *exit_function = g_exit_function;
    50c5:	48 8b 05 24 c0 00 00 	mov    0xc024(%rip),%rax        # 110f0 <g_exit_function>
    50cc:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    g_exit_function = NULL;
    50d0:	48 c7 05 15 c0 00 00 	movq   $0x0,0xc015(%rip)        # 110f0 <g_exit_function>
    50d7:	00 00 00 00 

    while (exit_function != NULL)
    50db:	eb 58                	jmp    5135 <do_atexit_aux+0x78>
    {
        cxa_function_t cxa_func = DEC_CXA_FUNC_POINTER(exit_function->cxa.fun);
    50dd:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    50e1:	48 8b 10             	mov    (%rax),%rdx
    50e4:	48 8b 05 0d c0 00 00 	mov    0xc00d(%rip),%rax        # 110f8 <g_exit_function_cookie>
    50eb:	48 31 d0             	xor    %rdx,%rax
    50ee:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
        void *para = DEC_CXA_PARA_POINTER(exit_function->cxa.para);
    50f2:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    50f6:	48 8b 50 08          	mov    0x8(%rax),%rdx
    50fa:	48 8b 05 f7 bf 00 00 	mov    0xbff7(%rip),%rax        # 110f8 <g_exit_function_cookie>
    5101:	48 31 d0             	xor    %rdx,%rax
    5104:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
        cxa_func(para);
    5108:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    510c:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    5110:	48 89 d7             	mov    %rdx,%rdi
    5113:	ff d0                	callq  *%rax

        exit_function_t *tmp = exit_function;
    5115:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5119:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
        exit_function = exit_function->next;
    511d:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5121:	48 8b 40 18          	mov    0x18(%rax),%rax
    5125:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
        free(tmp);
    5129:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    512d:	48 89 c7             	mov    %rax,%rdi
    5130:	e8 6a 47 00 00       	callq  989f <dlfree>
    while (exit_function != NULL)
    5135:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
    513a:	75 a1                	jne    50dd <do_atexit_aux+0x20>
    }
}
    513c:	90                   	nop
    513d:	c9                   	leaveq 
    513e:	c3                   	retq   

000000000000513f <do_ctors_aux>:

/* auxiliary routines */
static void do_ctors_aux(void)
{
    513f:	55                   	push   %rbp
    5140:	48 89 e5             	mov    %rsp,%rbp
    5143:	48 83 ec 40          	sub    $0x40,%rsp
    5147:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    514e:	00 00 
    5150:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    5154:	31 c0                	xor    %eax,%eax
    /* SGX RTS does not support .ctors currently */
   
    fp_t *p = NULL;
    5156:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    515d:	00 
    uintptr_t init_array_addr = 0;
    515e:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    5165:	00 
    size_t init_array_size = 0;
    5166:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    516d:	00 
    const void *enclave_start = (const void*)&__ImageBase;
    516e:	48 8d 05 8b ae ff ff 	lea    -0x5175(%rip),%rax        # 0 <enclave.so>
    5175:	48 89 45 e0          	mov    %rax,-0x20(%rbp)

    if (0 != elf_get_init_array(enclave_start, &init_array_addr, &init_array_size)|| init_array_addr == 0 || init_array_size == 0)
    5179:	48 8d 55 d0          	lea    -0x30(%rbp),%rdx
    517d:	48 8d 4d c8          	lea    -0x38(%rbp),%rcx
    5181:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5185:	48 89 ce             	mov    %rcx,%rsi
    5188:	48 89 c7             	mov    %rax,%rdi
    518b:	e8 9f f9 ff ff       	callq  4b2f <elf_get_init_array>
    5190:	85 c0                	test   %eax,%eax
    5192:	75 5b                	jne    51ef <do_ctors_aux+0xb0>
    5194:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    5198:	48 85 c0             	test   %rax,%rax
    519b:	74 52                	je     51ef <do_ctors_aux+0xb0>
    519d:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    51a1:	48 85 c0             	test   %rax,%rax
    51a4:	74 49                	je     51ef <do_ctors_aux+0xb0>
        return;

    fp_t *fp_start = (fp_t*)(init_array_addr + (uintptr_t)(enclave_start));
    51a6:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    51aa:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    51ae:	48 01 d0             	add    %rdx,%rax
    51b1:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    fp_t *fp_end = fp_start + (init_array_size / sizeof(fp_t));
    51b5:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    51b9:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    51bd:	48 89 c2             	mov    %rax,%rdx
    51c0:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    51c4:	48 01 d0             	add    %rdx,%rax
    51c7:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    
    /* traverse .init_array in forward order */
    for (p = fp_start; p < fp_end; p++)
    51cb:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    51cf:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    51d3:	eb 0e                	jmp    51e3 <do_ctors_aux+0xa4>
    {
        (*p)();
    51d5:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    51d9:	48 8b 00             	mov    (%rax),%rax
    51dc:	ff d0                	callq  *%rax
    for (p = fp_start; p < fp_end; p++)
    51de:	48 83 45 d8 08       	addq   $0x8,-0x28(%rbp)
    51e3:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    51e7:	48 3b 45 f0          	cmp    -0x10(%rbp),%rax
    51eb:	72 e8                	jb     51d5 <do_ctors_aux+0x96>
    51ed:	eb 01                	jmp    51f0 <do_ctors_aux+0xb1>
        return;
    51ef:	90                   	nop
    }
}
    51f0:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    51f4:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    51fb:	00 00 
    51fd:	74 05                	je     5204 <do_ctors_aux+0xc5>
    51ff:	e8 d6 00 00 00       	callq  52da <__stack_chk_fail>
    5204:	c9                   	leaveq 
    5205:	c3                   	retq   

0000000000005206 <do_dtors_aux>:

/* auxiliary routines */
static void do_dtors_aux(void)
{
    5206:	55                   	push   %rbp
    5207:	48 89 e5             	mov    %rsp,%rbp
    520a:	48 83 ec 40          	sub    $0x40,%rsp
    520e:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    5215:	00 00 
    5217:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    521b:	31 c0                	xor    %eax,%eax
    fp_t *p = NULL;
    521d:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    5224:	00 
    uintptr_t uninit_array_addr;
    size_t uninit_array_size;
    const void *enclave_start = (const void*)&__ImageBase;
    5225:	48 8d 05 d4 ad ff ff 	lea    -0x522c(%rip),%rax        # 0 <enclave.so>
    522c:	48 89 45 e0          	mov    %rax,-0x20(%rbp)

    elf_get_uninit_array(enclave_start, &uninit_array_addr, &uninit_array_size);
    5230:	48 8d 55 d0          	lea    -0x30(%rbp),%rdx
    5234:	48 8d 4d c8          	lea    -0x38(%rbp),%rcx
    5238:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    523c:	48 89 ce             	mov    %rcx,%rsi
    523f:	48 89 c7             	mov    %rax,%rdi
    5242:	e8 05 fa ff ff       	callq  4c4c <elf_get_uninit_array>

    if (uninit_array_addr == 0 || uninit_array_size == 0)
    5247:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    524b:	48 85 c0             	test   %rax,%rax
    524e:	74 56                	je     52a6 <do_dtors_aux+0xa0>
    5250:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    5254:	48 85 c0             	test   %rax,%rax
    5257:	74 4d                	je     52a6 <do_dtors_aux+0xa0>
        return;

    fp_t *fp_start = (fp_t*)(uninit_array_addr + (uintptr_t)(enclave_start));
    5259:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    525d:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5261:	48 01 d0             	add    %rdx,%rax
    5264:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    fp_t *fp_end = fp_start + (uninit_array_size / sizeof(fp_t));
    5268:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    526c:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    5270:	48 89 c2             	mov    %rax,%rdx
    5273:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    5277:	48 01 d0             	add    %rdx,%rax
    527a:	48 89 45 f0          	mov    %rax,-0x10(%rbp)

    /* traverse .fini_array in reverse order */
    for (p = fp_end - 1; p >= fp_start; p--)
    527e:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5282:	48 83 e8 08          	sub    $0x8,%rax
    5286:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    528a:	eb 0e                	jmp    529a <do_dtors_aux+0x94>
    {
        (*p)();
    528c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    5290:	48 8b 00             	mov    (%rax),%rax
    5293:	ff d0                	callq  *%rax
    for (p = fp_end - 1; p >= fp_start; p--)
    5295:	48 83 6d d8 08       	subq   $0x8,-0x28(%rbp)
    529a:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    529e:	48 3b 45 e8          	cmp    -0x18(%rbp),%rax
    52a2:	73 e8                	jae    528c <do_dtors_aux+0x86>
    52a4:	eb 01                	jmp    52a7 <do_dtors_aux+0xa1>
        return;
    52a6:	90                   	nop
    }
}
    52a7:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    52ab:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    52b2:	00 00 
    52b4:	74 05                	je     52bb <do_dtors_aux+0xb5>
    52b6:	e8 1f 00 00 00       	callq  52da <__stack_chk_fail>
    52bb:	c9                   	leaveq 
    52bc:	c3                   	retq   

00000000000052bd <init_global_object>:

void init_global_object(void)
{
    52bd:	55                   	push   %rbp
    52be:	48 89 e5             	mov    %rsp,%rbp
    do_ctors_aux();
    52c1:	e8 79 fe ff ff       	callq  513f <do_ctors_aux>
}
    52c6:	90                   	nop
    52c7:	5d                   	pop    %rbp
    52c8:	c3                   	retq   

00000000000052c9 <uninit_global_object>:

void uninit_global_object(void)
{
    52c9:	55                   	push   %rbp
    52ca:	48 89 e5             	mov    %rsp,%rbp
    do_atexit_aux();
    52cd:	e8 eb fd ff ff       	callq  50bd <do_atexit_aux>
    do_dtors_aux();
    52d2:	e8 2f ff ff ff       	callq  5206 <do_dtors_aux>
}
    52d7:	90                   	nop
    52d8:	5d                   	pop    %rbp
    52d9:	c3                   	retq   

00000000000052da <__stack_chk_fail>:
#include "stdlib.h"

void
__attribute__((noreturn))
__stack_chk_fail(void)
{
    52da:	55                   	push   %rbp
    52db:	48 89 e5             	mov    %rsp,%rbp
    abort();
    52de:	e8 eb 76 00 00       	callq  c9ce <abort>

00000000000052e3 <__assert>:
#include <stdio.h>
#include <stdlib.h>

void
__assert(const char *file, int line, const char *func, const char *failedexpr)
{
    52e3:	55                   	push   %rbp
    52e4:	48 89 e5             	mov    %rsp,%rbp
    52e7:	48 83 ec 20          	sub    $0x20,%rsp
    52eb:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    52ef:	89 75 f4             	mov    %esi,-0xc(%rbp)
    52f2:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    52f6:	48 89 4d e0          	mov    %rcx,-0x20(%rbp)
	(void)(line);
	(void)(func);
	(void)(failedexpr);
#endif

	abort();
    52fa:	e8 cf 76 00 00       	callq  c9ce <abort>

00000000000052ff <spin_acquire_lock>:
#define SPIN_LOCK_YIELD
#endif /* ... yield ... */

#if !defined(USE_RECURSIVE_LOCKS) || USE_RECURSIVE_LOCKS == 0
/* Plain spin locks use single word (embedded in malloc_states) */
static int spin_acquire_lock(int *sl) {
    52ff:	55                   	push   %rbp
    5300:	48 89 e5             	mov    %rsp,%rbp
    5303:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  int spins = 0;
    5307:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  while (*(volatile int *)sl != 0 || CAS_LOCK(sl)) {
    530e:	eb 04                	jmp    5314 <spin_acquire_lock+0x15>
    if ((++spins & SPINS_PER_YIELD) == 0) {
    5310:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  while (*(volatile int *)sl != 0 || CAS_LOCK(sl)) {
    5314:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    5318:	8b 00                	mov    (%rax),%eax
    531a:	85 c0                	test   %eax,%eax
    531c:	75 f2                	jne    5310 <spin_acquire_lock+0x11>
    531e:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    5322:	b8 01 00 00 00       	mov    $0x1,%eax
    5327:	87 02                	xchg   %eax,(%rdx)
    5329:	85 c0                	test   %eax,%eax
    532b:	75 e3                	jne    5310 <spin_acquire_lock+0x11>
      SPIN_LOCK_YIELD;
    }
  }
  return 0;
    532d:	b8 00 00 00 00       	mov    $0x0,%eax
}
    5332:	5d                   	pop    %rbp
    5333:	c3                   	retq   

0000000000005334 <segment_holding>:
/*  True if segment S holds address A */
#define segment_holds(S, A)\
  ((char*)(A) >= S->base && (char*)(A) < S->base + S->size)

/* Return segment holding given address */
static msegmentptr segment_holding(mstate m, char* addr) {
    5334:	55                   	push   %rbp
    5335:	48 89 e5             	mov    %rsp,%rbp
    5338:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    533c:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  msegmentptr sp = &m->seg;
    5340:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    5344:	48 05 78 03 00 00    	add    $0x378,%rax
    534a:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  for (;;) {
    if (addr >= sp->base && addr < sp->base + sp->size)
    534e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5352:	48 8b 00             	mov    (%rax),%rax
    5355:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    5359:	72 1e                	jb     5379 <segment_holding+0x45>
    535b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    535f:	48 8b 10             	mov    (%rax),%rdx
    5362:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5366:	48 8b 40 08          	mov    0x8(%rax),%rax
    536a:	48 01 d0             	add    %rdx,%rax
    536d:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    5371:	73 06                	jae    5379 <segment_holding+0x45>
      return sp;
    5373:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5377:	eb 18                	jmp    5391 <segment_holding+0x5d>
    if ((sp = sp->next) == 0)
    5379:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    537d:	48 8b 40 10          	mov    0x10(%rax),%rax
    5381:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    5385:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    538a:	75 c2                	jne    534e <segment_holding+0x1a>
      return 0;
    538c:	b8 00 00 00 00       	mov    $0x0,%eax
  }
}
    5391:	5d                   	pop    %rbp
    5392:	c3                   	retq   

0000000000005393 <init_mparams>:
static void post_fork_parent(void) { RELEASE_LOCK(&(gm)->mutex); }
static void post_fork_child(void)  { INITIAL_LOCK(&(gm)->mutex); }
#endif /* LOCK_AT_FORK */

/* Initialize mparams */
static int init_mparams(void) {
    5393:	55                   	push   %rbp
    5394:	48 89 e5             	mov    %rsp,%rbp
    5397:	48 83 ec 20          	sub    $0x20,%rsp
    539b:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    53a2:	00 00 
    53a4:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    53a8:	31 c0                	xor    %eax,%eax
#ifdef NEED_GLOBAL_LOCK_INIT
  if (malloc_global_mutex_status <= 0)
    init_malloc_global_mutex();
#endif

  ACQUIRE_MALLOC_GLOBAL_LOCK();
    53aa:	b8 01 00 00 00       	mov    $0x1,%eax
    53af:	87 05 4b bd 00 00    	xchg   %eax,0xbd4b(%rip)        # 11100 <malloc_global_mutex>
    53b5:	85 c0                	test   %eax,%eax
    53b7:	74 0c                	je     53c5 <init_mparams+0x32>
    53b9:	48 8d 3d 40 bd 00 00 	lea    0xbd40(%rip),%rdi        # 11100 <malloc_global_mutex>
    53c0:	e8 3a ff ff ff       	callq  52ff <spin_acquire_lock>
  if (mparams.magic == 0) {
    53c5:	48 8b 05 54 bd 00 00 	mov    0xbd54(%rip),%rax        # 11120 <mparams>
    53cc:	48 85 c0             	test   %rax,%rax
    53cf:	0f 85 d1 00 00 00    	jne    54a6 <init_mparams+0x113>
    size_t magic;
    size_t psize;
    size_t gsize;

#if !defined(WIN32) || defined(_TLIBC_)
    psize = malloc_getpagesize;
    53d5:	48 c7 45 e8 00 10 00 	movq   $0x1000,-0x18(%rbp)
    53dc:	00 
    gsize = ((DEFAULT_GRANULARITY != 0)? DEFAULT_GRANULARITY : psize);
    53dd:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    53e1:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
        (MAX_SIZE_T < MIN_CHUNK_SIZE)  ||
        (sizeof(int) < 4)  ||
        (MALLOC_ALIGNMENT < (size_t)8U) ||
        ((MALLOC_ALIGNMENT & (MALLOC_ALIGNMENT-SIZE_T_ONE)) != 0) ||
        ((MCHUNK_SIZE      & (MCHUNK_SIZE-SIZE_T_ONE))      != 0) ||
        ((gsize            & (gsize-SIZE_T_ONE))            != 0) ||
    53e5:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    53e9:	48 83 e8 01          	sub    $0x1,%rax
    53ed:	48 23 45 f0          	and    -0x10(%rbp),%rax
    if ((sizeof(size_t) != sizeof(char*)) ||
    53f1:	48 85 c0             	test   %rax,%rax
    53f4:	75 11                	jne    5407 <init_mparams+0x74>
        ((psize            & (psize-SIZE_T_ONE))            != 0))
    53f6:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    53fa:	48 83 e8 01          	sub    $0x1,%rax
    53fe:	48 23 45 e8          	and    -0x18(%rbp),%rax
        ((gsize            & (gsize-SIZE_T_ONE))            != 0) ||
    5402:	48 85 c0             	test   %rax,%rax
    5405:	74 05                	je     540c <init_mparams+0x79>
      ABORT;
    5407:	e8 c2 75 00 00       	callq  c9ce <abort>
    mparams.granularity = gsize;
    540c:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5410:	48 89 05 19 bd 00 00 	mov    %rax,0xbd19(%rip)        # 11130 <mparams+0x10>
    mparams.page_size = psize;
    5417:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    541b:	48 89 05 06 bd 00 00 	mov    %rax,0xbd06(%rip)        # 11128 <mparams+0x8>
    mparams.mmap_threshold = DEFAULT_MMAP_THRESHOLD;
    5422:	48 c7 05 0b bd 00 00 	movq   $0xffffffffffffffff,0xbd0b(%rip)        # 11138 <mparams+0x18>
    5429:	ff ff ff ff 
    mparams.trim_threshold = DEFAULT_TRIM_THRESHOLD;
    542d:	48 c7 05 08 bd 00 00 	movq   $0x200000,0xbd08(%rip)        # 11140 <mparams+0x20>
    5434:	00 00 20 00 
#if MORECORE_CONTIGUOUS
    mparams.default_mflags = USE_LOCK_BIT|USE_MMAP_BIT;
    5438:	c7 05 06 bd 00 00 02 	movl   $0x2,0xbd06(%rip)        # 11148 <mparams+0x28>
    543f:	00 00 00 
    mparams.default_mflags = USE_LOCK_BIT|USE_MMAP_BIT|USE_NONCONTIGUOUS_BIT;
#endif /* MORECORE_CONTIGUOUS */

#if !ONLY_MSPACES
    /* Set up lock for main malloc area */
    gm->mflags = mparams.default_mflags;
    5442:	8b 05 00 bd 00 00    	mov    0xbd00(%rip),%eax        # 11148 <mparams+0x28>
    5448:	89 05 82 c0 00 00    	mov    %eax,0xc082(%rip)        # 114d0 <_gm_+0x370>
    (void)INITIAL_LOCK(&gm->mutex);
    544e:	c7 05 7c c0 00 00 00 	movl   $0x0,0xc07c(%rip)        # 114d4 <_gm_+0x374>
    5455:	00 00 00 
      else
#endif /* USE_DEV_RANDOM */
#if defined(WIN32) && !defined(_TLIBC_)
      magic = (size_t)(GetTickCount() ^ (size_t)0x55555555U);
#elif defined(LACKS_TIME_H)
      if (SGX_SUCCESS != sgx_read_rand((unsigned char *)&magic, sizeof(size_t)))
    5458:	48 8d 45 e0          	lea    -0x20(%rbp),%rax
    545c:	be 08 00 00 00       	mov    $0x8,%esi
    5461:	48 89 c7             	mov    %rax,%rdi
    5464:	e8 62 c1 ff ff       	callq  15cb <sgx_read_rand>
    5469:	85 c0                	test   %eax,%eax
    546b:	74 05                	je     5472 <init_mparams+0xdf>
          ABORT;
    546d:	e8 5c 75 00 00       	callq  c9ce <abort>
      magic = (size_t)(magic ^ (size_t)0x55555555U);
    5472:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5476:	48 35 55 55 55 55    	xor    $0x55555555,%rax
    547c:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
#else
      magic = (size_t)(time(0) ^ (size_t)0x55555555U);
#endif
      magic |= (size_t)8U;    /* ensure nonzero */
    5480:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5484:	48 83 c8 08          	or     $0x8,%rax
    5488:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
      magic &= ~(size_t)7U;   /* improve chances of fault for bad values */
    548c:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5490:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    5494:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
      /* Until memory modes commonly available, use volatile-write */
      (*(volatile size_t *)(&(mparams.magic))) = magic;
    5498:	48 8d 05 81 bc 00 00 	lea    0xbc81(%rip),%rax        # 11120 <mparams>
    549f:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    54a3:	48 89 10             	mov    %rdx,(%rax)
    }
  }

  RELEASE_MALLOC_GLOBAL_LOCK();
    54a6:	b8 00 00 00 00       	mov    $0x0,%eax
    54ab:	89 05 4f bc 00 00    	mov    %eax,0xbc4f(%rip)        # 11100 <malloc_global_mutex>
  return 1;
    54b1:	b8 01 00 00 00       	mov    $0x1,%eax
}
    54b6:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    54ba:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    54c1:	00 00 
    54c3:	74 05                	je     54ca <init_mparams+0x137>
    54c5:	e8 10 fe ff ff       	callq  52da <__stack_chk_fail>
    54ca:	c9                   	leaveq 
    54cb:	c3                   	retq   

00000000000054cc <do_check_any_chunk>:

#if DEBUG
/* ------------------------- Debugging Support --------------------------- */

/* Check properties of any chunk, whether free, inuse, mmapped etc  */
static void do_check_any_chunk(mstate m, mchunkptr p) {
    54cc:	55                   	push   %rbp
    54cd:	48 89 e5             	mov    %rsp,%rbp
    54d0:	48 83 ec 10          	sub    $0x10,%rsp
    54d4:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    54d8:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
  assert((is_aligned(chunk2mem(p))) || (p->head == FENCEPOST_HEAD));
    54dc:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    54e0:	48 83 c0 10          	add    $0x10,%rax
    54e4:	83 e0 0f             	and    $0xf,%eax
    54e7:	48 85 c0             	test   %rax,%rax
    54ea:	74 13                	je     54ff <do_check_any_chunk+0x33>
    54ec:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    54f0:	48 8b 40 08          	mov    0x8(%rax),%rax
    54f4:	48 83 f8 0b          	cmp    $0xb,%rax
    54f8:	74 05                	je     54ff <do_check_any_chunk+0x33>
    54fa:	e8 cf 74 00 00       	callq  c9ce <abort>
  assert(ok_address(m, p));
    54ff:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5503:	48 8b 40 18          	mov    0x18(%rax),%rax
    5507:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    550b:	73 05                	jae    5512 <do_check_any_chunk+0x46>
    550d:	e8 bc 74 00 00       	callq  c9ce <abort>
}
    5512:	90                   	nop
    5513:	c9                   	leaveq 
    5514:	c3                   	retq   

0000000000005515 <do_check_top_chunk>:

/* Check properties of top chunk */
static void do_check_top_chunk(mstate m, mchunkptr p) {
    5515:	55                   	push   %rbp
    5516:	48 89 e5             	mov    %rsp,%rbp
    5519:	48 83 ec 20          	sub    $0x20,%rsp
    551d:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    5521:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  msegmentptr sp = segment_holding(m, (char*)p);
    5525:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    5529:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    552d:	48 89 d6             	mov    %rdx,%rsi
    5530:	48 89 c7             	mov    %rax,%rdi
    5533:	e8 fc fd ff ff       	callq  5334 <segment_holding>
    5538:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
  size_t  sz = p->head & ~INUSE_BITS; /* third-lowest bit can be set! */
    553c:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5540:	48 8b 40 08          	mov    0x8(%rax),%rax
    5544:	48 83 e0 fc          	and    $0xfffffffffffffffc,%rax
    5548:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  assert(sp != 0);
    554c:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    5551:	75 05                	jne    5558 <do_check_top_chunk+0x43>
    5553:	e8 76 74 00 00       	callq  c9ce <abort>
  assert((is_aligned(chunk2mem(p))) || (p->head == FENCEPOST_HEAD));
    5558:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    555c:	48 83 c0 10          	add    $0x10,%rax
    5560:	83 e0 0f             	and    $0xf,%eax
    5563:	48 85 c0             	test   %rax,%rax
    5566:	74 13                	je     557b <do_check_top_chunk+0x66>
    5568:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    556c:	48 8b 40 08          	mov    0x8(%rax),%rax
    5570:	48 83 f8 0b          	cmp    $0xb,%rax
    5574:	74 05                	je     557b <do_check_top_chunk+0x66>
    5576:	e8 53 74 00 00       	callq  c9ce <abort>
  assert(ok_address(m, p));
    557b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    557f:	48 8b 40 18          	mov    0x18(%rax),%rax
    5583:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    5587:	73 05                	jae    558e <do_check_top_chunk+0x79>
    5589:	e8 40 74 00 00       	callq  c9ce <abort>
  assert(sz == m->topsize);
    558e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    5592:	48 8b 40 10          	mov    0x10(%rax),%rax
    5596:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    559a:	74 05                	je     55a1 <do_check_top_chunk+0x8c>
    559c:	e8 2d 74 00 00       	callq  c9ce <abort>
  assert(sz > 0);
    55a1:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    55a6:	75 05                	jne    55ad <do_check_top_chunk+0x98>
    55a8:	e8 21 74 00 00       	callq  c9ce <abort>
  assert(sz == ((sp->base + sp->size) - (char*)p) - TOP_FOOT_SIZE);
    55ad:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    55b1:	48 8b 10             	mov    (%rax),%rdx
    55b4:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    55b8:	48 8b 40 08          	mov    0x8(%rax),%rax
    55bc:	48 01 d0             	add    %rdx,%rax
    55bf:	48 89 c2             	mov    %rax,%rdx
    55c2:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    55c6:	48 29 c2             	sub    %rax,%rdx
    55c9:	48 89 d0             	mov    %rdx,%rax
    55cc:	48 83 e8 50          	sub    $0x50,%rax
    55d0:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    55d4:	74 05                	je     55db <do_check_top_chunk+0xc6>
    55d6:	e8 f3 73 00 00       	callq  c9ce <abort>
  assert(pinuse(p));
    55db:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    55df:	48 8b 40 08          	mov    0x8(%rax),%rax
    55e3:	83 e0 01             	and    $0x1,%eax
    55e6:	48 85 c0             	test   %rax,%rax
    55e9:	75 05                	jne    55f0 <do_check_top_chunk+0xdb>
    55eb:	e8 de 73 00 00       	callq  c9ce <abort>
  assert(!pinuse(chunk_plus_offset(p, sz)));
    55f0:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    55f4:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    55f8:	48 01 d0             	add    %rdx,%rax
    55fb:	48 8b 40 08          	mov    0x8(%rax),%rax
    55ff:	83 e0 01             	and    $0x1,%eax
    5602:	48 85 c0             	test   %rax,%rax
    5605:	74 05                	je     560c <do_check_top_chunk+0xf7>
    5607:	e8 c2 73 00 00       	callq  c9ce <abort>
}
    560c:	90                   	nop
    560d:	c9                   	leaveq 
    560e:	c3                   	retq   

000000000000560f <do_check_mmapped_chunk>:

/* Check properties of (inuse) mmapped chunks */
static void do_check_mmapped_chunk(mstate m, mchunkptr p) {
    560f:	55                   	push   %rbp
    5610:	48 89 e5             	mov    %rsp,%rbp
    5613:	48 83 ec 20          	sub    $0x20,%rsp
    5617:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    561b:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  size_t  sz = chunksize(p);
    561f:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5623:	48 8b 40 08          	mov    0x8(%rax),%rax
    5627:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    562b:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
  size_t len = (sz + (p->prev_foot) + MMAP_FOOT_PAD);
    562f:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5633:	48 8b 10             	mov    (%rax),%rdx
    5636:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    563a:	48 01 d0             	add    %rdx,%rax
    563d:	48 83 c0 20          	add    $0x20,%rax
    5641:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  assert(is_mmapped(p));
    5645:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5649:	48 8b 40 08          	mov    0x8(%rax),%rax
    564d:	83 e0 03             	and    $0x3,%eax
    5650:	48 85 c0             	test   %rax,%rax
    5653:	74 05                	je     565a <do_check_mmapped_chunk+0x4b>
    5655:	e8 74 73 00 00       	callq  c9ce <abort>
  assert(use_mmap(m));
    565a:	e8 6f 73 00 00       	callq  c9ce <abort>

000000000000565f <do_check_inuse_chunk>:
  assert(chunk_plus_offset(p, sz)->head == FENCEPOST_HEAD);
  assert(chunk_plus_offset(p, sz+SIZE_T_SIZE)->head == 0);
}

/* Check properties of inuse chunks */
static void do_check_inuse_chunk(mstate m, mchunkptr p) {
    565f:	55                   	push   %rbp
    5660:	48 89 e5             	mov    %rsp,%rbp
    5663:	48 83 ec 10          	sub    $0x10,%rsp
    5667:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    566b:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
  do_check_any_chunk(m, p);
    566f:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    5673:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5677:	48 89 d6             	mov    %rdx,%rsi
    567a:	48 89 c7             	mov    %rax,%rdi
    567d:	e8 4a fe ff ff       	callq  54cc <do_check_any_chunk>
  assert(is_inuse(p));
    5682:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5686:	48 8b 40 08          	mov    0x8(%rax),%rax
    568a:	83 e0 03             	and    $0x3,%eax
    568d:	48 83 f8 01          	cmp    $0x1,%rax
    5691:	75 05                	jne    5698 <do_check_inuse_chunk+0x39>
    5693:	e8 36 73 00 00       	callq  c9ce <abort>
  assert(next_pinuse(p));
    5698:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    569c:	48 8b 40 08          	mov    0x8(%rax),%rax
    56a0:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    56a4:	48 89 c2             	mov    %rax,%rdx
    56a7:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    56ab:	48 01 d0             	add    %rdx,%rax
    56ae:	48 8b 40 08          	mov    0x8(%rax),%rax
    56b2:	83 e0 01             	and    $0x1,%eax
    56b5:	48 85 c0             	test   %rax,%rax
    56b8:	75 05                	jne    56bf <do_check_inuse_chunk+0x60>
    56ba:	e8 0f 73 00 00       	callq  c9ce <abort>
  /* If not pinuse and not mmapped, previous chunk has OK offset */
  assert(is_mmapped(p) || pinuse(p) || next_chunk(prev_chunk(p)) == p);
    56bf:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    56c3:	48 8b 40 08          	mov    0x8(%rax),%rax
    56c7:	83 e0 03             	and    $0x3,%eax
    56ca:	48 85 c0             	test   %rax,%rax
    56cd:	74 40                	je     570f <do_check_inuse_chunk+0xb0>
    56cf:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    56d3:	48 8b 40 08          	mov    0x8(%rax),%rax
    56d7:	83 e0 01             	and    $0x1,%eax
    56da:	48 85 c0             	test   %rax,%rax
    56dd:	75 30                	jne    570f <do_check_inuse_chunk+0xb0>
    56df:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    56e3:	48 8b 00             	mov    (%rax),%rax
    56e6:	48 f7 d8             	neg    %rax
    56e9:	48 89 c2             	mov    %rax,%rdx
    56ec:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    56f0:	48 01 d0             	add    %rdx,%rax
    56f3:	48 8b 40 08          	mov    0x8(%rax),%rax
    56f7:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    56fb:	48 89 c2             	mov    %rax,%rdx
    56fe:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5702:	48 8b 00             	mov    (%rax),%rax
    5705:	48 39 c2             	cmp    %rax,%rdx
    5708:	74 05                	je     570f <do_check_inuse_chunk+0xb0>
    570a:	e8 bf 72 00 00       	callq  c9ce <abort>
  if (is_mmapped(p))
    570f:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5713:	48 8b 40 08          	mov    0x8(%rax),%rax
    5717:	83 e0 03             	and    $0x3,%eax
    571a:	48 85 c0             	test   %rax,%rax
    571d:	75 13                	jne    5732 <do_check_inuse_chunk+0xd3>
    do_check_mmapped_chunk(m, p);
    571f:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    5723:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5727:	48 89 d6             	mov    %rdx,%rsi
    572a:	48 89 c7             	mov    %rax,%rdi
    572d:	e8 dd fe ff ff       	callq  560f <do_check_mmapped_chunk>
}
    5732:	90                   	nop
    5733:	c9                   	leaveq 
    5734:	c3                   	retq   

0000000000005735 <do_check_free_chunk>:

/* Check properties of free chunks */
static void do_check_free_chunk(mstate m, mchunkptr p) {
    5735:	55                   	push   %rbp
    5736:	48 89 e5             	mov    %rsp,%rbp
    5739:	48 83 ec 20          	sub    $0x20,%rsp
    573d:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    5741:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  size_t sz = chunksize(p);
    5745:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5749:	48 8b 40 08          	mov    0x8(%rax),%rax
    574d:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    5751:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
  mchunkptr next = chunk_plus_offset(p, sz);
    5755:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    5759:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    575d:	48 01 d0             	add    %rdx,%rax
    5760:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  do_check_any_chunk(m, p);
    5764:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    5768:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    576c:	48 89 d6             	mov    %rdx,%rsi
    576f:	48 89 c7             	mov    %rax,%rdi
    5772:	e8 55 fd ff ff       	callq  54cc <do_check_any_chunk>
  assert(!is_inuse(p));
    5777:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    577b:	48 8b 40 08          	mov    0x8(%rax),%rax
    577f:	83 e0 03             	and    $0x3,%eax
    5782:	48 83 f8 01          	cmp    $0x1,%rax
    5786:	74 05                	je     578d <do_check_free_chunk+0x58>
    5788:	e8 41 72 00 00       	callq  c9ce <abort>
  assert(!next_pinuse(p));
    578d:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5791:	48 8b 40 08          	mov    0x8(%rax),%rax
    5795:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    5799:	48 89 c2             	mov    %rax,%rdx
    579c:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    57a0:	48 01 d0             	add    %rdx,%rax
    57a3:	48 8b 40 08          	mov    0x8(%rax),%rax
    57a7:	83 e0 01             	and    $0x1,%eax
    57aa:	48 85 c0             	test   %rax,%rax
    57ad:	74 05                	je     57b4 <do_check_free_chunk+0x7f>
    57af:	e8 1a 72 00 00       	callq  c9ce <abort>
  assert (!is_mmapped(p));
    57b4:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    57b8:	48 8b 40 08          	mov    0x8(%rax),%rax
    57bc:	83 e0 03             	and    $0x3,%eax
    57bf:	48 85 c0             	test   %rax,%rax
    57c2:	75 05                	jne    57c9 <do_check_free_chunk+0x94>
    57c4:	e8 05 72 00 00       	callq  c9ce <abort>
  if (p != m->dv && p != m->top) {
    57c9:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    57cd:	48 8b 40 20          	mov    0x20(%rax),%rax
    57d1:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    57d5:	0f 84 c8 00 00 00    	je     58a3 <do_check_free_chunk+0x16e>
    57db:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    57df:	48 8b 40 28          	mov    0x28(%rax),%rax
    57e3:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    57e7:	0f 84 b6 00 00 00    	je     58a3 <do_check_free_chunk+0x16e>
    if (sz >= MIN_CHUNK_SIZE) {
    57ed:	48 83 7d f0 1f       	cmpq   $0x1f,-0x10(%rbp)
    57f2:	0f 86 9f 00 00 00    	jbe    5897 <do_check_free_chunk+0x162>
      assert((sz & CHUNK_ALIGN_MASK) == 0);
    57f8:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    57fc:	83 e0 0f             	and    $0xf,%eax
    57ff:	48 85 c0             	test   %rax,%rax
    5802:	74 05                	je     5809 <do_check_free_chunk+0xd4>
    5804:	e8 c5 71 00 00       	callq  c9ce <abort>
      assert(is_aligned(chunk2mem(p)));
    5809:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    580d:	48 83 c0 10          	add    $0x10,%rax
    5811:	83 e0 0f             	and    $0xf,%eax
    5814:	48 85 c0             	test   %rax,%rax
    5817:	74 05                	je     581e <do_check_free_chunk+0xe9>
    5819:	e8 b0 71 00 00       	callq  c9ce <abort>
      assert(next->prev_foot == sz);
    581e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5822:	48 8b 00             	mov    (%rax),%rax
    5825:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    5829:	74 05                	je     5830 <do_check_free_chunk+0xfb>
    582b:	e8 9e 71 00 00       	callq  c9ce <abort>
      assert(pinuse(p));
    5830:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5834:	48 8b 40 08          	mov    0x8(%rax),%rax
    5838:	83 e0 01             	and    $0x1,%eax
    583b:	48 85 c0             	test   %rax,%rax
    583e:	75 05                	jne    5845 <do_check_free_chunk+0x110>
    5840:	e8 89 71 00 00       	callq  c9ce <abort>
      assert (next == m->top || is_inuse(next));
    5845:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    5849:	48 8b 40 28          	mov    0x28(%rax),%rax
    584d:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    5851:	74 16                	je     5869 <do_check_free_chunk+0x134>
    5853:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5857:	48 8b 40 08          	mov    0x8(%rax),%rax
    585b:	83 e0 03             	and    $0x3,%eax
    585e:	48 83 f8 01          	cmp    $0x1,%rax
    5862:	75 05                	jne    5869 <do_check_free_chunk+0x134>
    5864:	e8 65 71 00 00       	callq  c9ce <abort>
      assert(p->fd->bk == p);
    5869:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    586d:	48 8b 40 10          	mov    0x10(%rax),%rax
    5871:	48 8b 40 18          	mov    0x18(%rax),%rax
    5875:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    5879:	74 05                	je     5880 <do_check_free_chunk+0x14b>
    587b:	e8 4e 71 00 00       	callq  c9ce <abort>
      assert(p->bk->fd == p);
    5880:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5884:	48 8b 40 18          	mov    0x18(%rax),%rax
    5888:	48 8b 40 10          	mov    0x10(%rax),%rax
    588c:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    5890:	74 11                	je     58a3 <do_check_free_chunk+0x16e>
    5892:	e8 37 71 00 00       	callq  c9ce <abort>
    }
    else  /* markers are always of size SIZE_T_SIZE */
      assert(sz == SIZE_T_SIZE);
    5897:	48 83 7d f0 08       	cmpq   $0x8,-0x10(%rbp)
    589c:	74 05                	je     58a3 <do_check_free_chunk+0x16e>
    589e:	e8 2b 71 00 00       	callq  c9ce <abort>
  }
}
    58a3:	90                   	nop
    58a4:	c9                   	leaveq 
    58a5:	c3                   	retq   

00000000000058a6 <do_check_malloced_chunk>:

/* Check properties of malloced chunks at the point they are malloced */
static void do_check_malloced_chunk(mstate m, void* mem, size_t s) {
    58a6:	55                   	push   %rbp
    58a7:	48 89 e5             	mov    %rsp,%rbp
    58aa:	48 83 ec 30          	sub    $0x30,%rsp
    58ae:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    58b2:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    58b6:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
  if (mem != 0) {
    58ba:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
    58bf:	74 7e                	je     593f <do_check_malloced_chunk+0x99>
    mchunkptr p = mem2chunk(mem);
    58c1:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    58c5:	48 83 e8 10          	sub    $0x10,%rax
    58c9:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    size_t sz = p->head & ~INUSE_BITS;
    58cd:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    58d1:	48 8b 40 08          	mov    0x8(%rax),%rax
    58d5:	48 83 e0 fc          	and    $0xfffffffffffffffc,%rax
    58d9:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    do_check_inuse_chunk(m, p);
    58dd:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    58e1:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    58e5:	48 89 d6             	mov    %rdx,%rsi
    58e8:	48 89 c7             	mov    %rax,%rdi
    58eb:	e8 6f fd ff ff       	callq  565f <do_check_inuse_chunk>
    assert((sz & CHUNK_ALIGN_MASK) == 0);
    58f0:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    58f4:	83 e0 0f             	and    $0xf,%eax
    58f7:	48 85 c0             	test   %rax,%rax
    58fa:	74 05                	je     5901 <do_check_malloced_chunk+0x5b>
    58fc:	e8 cd 70 00 00       	callq  c9ce <abort>
    assert(sz >= MIN_CHUNK_SIZE);
    5901:	48 83 7d f8 1f       	cmpq   $0x1f,-0x8(%rbp)
    5906:	77 05                	ja     590d <do_check_malloced_chunk+0x67>
    5908:	e8 c1 70 00 00       	callq  c9ce <abort>
    assert(sz >= s);
    590d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5911:	48 3b 45 d8          	cmp    -0x28(%rbp),%rax
    5915:	73 05                	jae    591c <do_check_malloced_chunk+0x76>
    5917:	e8 b2 70 00 00       	callq  c9ce <abort>
    /* unless mmapped, size is less than MIN_CHUNK_SIZE more than request */
    assert(is_mmapped(p) || sz < (s + MIN_CHUNK_SIZE));
    591c:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5920:	48 8b 40 08          	mov    0x8(%rax),%rax
    5924:	83 e0 03             	and    $0x3,%eax
    5927:	48 85 c0             	test   %rax,%rax
    592a:	74 13                	je     593f <do_check_malloced_chunk+0x99>
    592c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    5930:	48 83 c0 20          	add    $0x20,%rax
    5934:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    5938:	72 05                	jb     593f <do_check_malloced_chunk+0x99>
    593a:	e8 8f 70 00 00       	callq  c9ce <abort>
  }
}
    593f:	90                   	nop
    5940:	c9                   	leaveq 
    5941:	c3                   	retq   

0000000000005942 <init_top>:


/* -------------------------- mspace management -------------------------- */

/* Initialize top chunk and its size */
static void init_top(mstate m, mchunkptr p, size_t psize) {
    5942:	55                   	push   %rbp
    5943:	48 89 e5             	mov    %rsp,%rbp
    5946:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    594a:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    594e:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
  /* Ensure alignment */
  size_t offset = align_offset(chunk2mem(p));
    5952:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5956:	48 83 c0 10          	add    $0x10,%rax
    595a:	83 e0 0f             	and    $0xf,%eax
    595d:	48 85 c0             	test   %rax,%rax
    5960:	74 10                	je     5972 <init_top+0x30>
    5962:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    5966:	48 83 c0 10          	add    $0x10,%rax
    596a:	48 f7 d8             	neg    %rax
    596d:	83 e0 0f             	and    $0xf,%eax
    5970:	eb 05                	jmp    5977 <init_top+0x35>
    5972:	b8 00 00 00 00       	mov    $0x0,%eax
    5977:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  p = (mchunkptr)((char*)p + offset);
    597b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    597f:	48 01 45 e0          	add    %rax,-0x20(%rbp)
  psize -= offset;
    5983:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5987:	48 29 45 d8          	sub    %rax,-0x28(%rbp)

  m->top = p;
    598b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    598f:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    5993:	48 89 50 28          	mov    %rdx,0x28(%rax)
  m->topsize = psize;
    5997:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    599b:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    599f:	48 89 50 10          	mov    %rdx,0x10(%rax)
  p->head = psize | PINUSE_BIT;
    59a3:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    59a7:	48 83 c8 01          	or     $0x1,%rax
    59ab:	48 89 c2             	mov    %rax,%rdx
    59ae:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    59b2:	48 89 50 08          	mov    %rdx,0x8(%rax)
  /* set size of fake trailing chunk holding overhead space only once */
  chunk_plus_offset(p, psize)->head = TOP_FOOT_SIZE;
    59b6:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    59ba:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    59be:	48 01 d0             	add    %rdx,%rax
    59c1:	48 c7 40 08 50 00 00 	movq   $0x50,0x8(%rax)
    59c8:	00 
  m->trim_check = mparams.trim_threshold; /* reset on each update */
    59c9:	48 8b 15 70 b7 00 00 	mov    0xb770(%rip),%rdx        # 11140 <mparams+0x20>
    59d0:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    59d4:	48 89 50 30          	mov    %rdx,0x30(%rax)
}
    59d8:	90                   	nop
    59d9:	5d                   	pop    %rbp
    59da:	c3                   	retq   

00000000000059db <init_bins>:

/* Initialize bins for a new mstate that is otherwise zeroed out */
static void init_bins(mstate m) {
    59db:	55                   	push   %rbp
    59dc:	48 89 e5             	mov    %rsp,%rbp
    59df:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  /* Establish circular links for smallbins */
  bindex_t i;
  for (i = 0; i < NSMALLBINS; ++i) {
    59e3:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    59ea:	eb 42                	jmp    5a2e <init_bins+0x53>
    sbinptr bin = smallbin_at(m,i);
    59ec:	8b 45 f4             	mov    -0xc(%rbp),%eax
    59ef:	01 c0                	add    %eax,%eax
    59f1:	89 c0                	mov    %eax,%eax
    59f3:	48 83 c0 08          	add    $0x8,%rax
    59f7:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    59fe:	00 
    59ff:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    5a03:	48 01 d0             	add    %rdx,%rax
    5a06:	48 83 c0 08          	add    $0x8,%rax
    5a0a:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    bin->fd = bin->bk = bin;
    5a0e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5a12:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    5a16:	48 89 50 18          	mov    %rdx,0x18(%rax)
    5a1a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5a1e:	48 8b 50 18          	mov    0x18(%rax),%rdx
    5a22:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5a26:	48 89 50 10          	mov    %rdx,0x10(%rax)
  for (i = 0; i < NSMALLBINS; ++i) {
    5a2a:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    5a2e:	83 7d f4 1f          	cmpl   $0x1f,-0xc(%rbp)
    5a32:	76 b8                	jbe    59ec <init_bins+0x11>
  }
}
    5a34:	90                   	nop
    5a35:	5d                   	pop    %rbp
    5a36:	c3                   	retq   

0000000000005a37 <prepend_alloc>:
}
#endif /* PROCEED_ON_ERROR */

/* Allocate chunk and prepend remainder with chunk in successor base. */
static void* prepend_alloc(mstate m, char* newbase, char* oldbase,
                           size_t nb) {
    5a37:	55                   	push   %rbp
    5a38:	48 89 e5             	mov    %rsp,%rbp
    5a3b:	48 81 ec 10 01 00 00 	sub    $0x110,%rsp
    5a42:	48 89 bd 08 ff ff ff 	mov    %rdi,-0xf8(%rbp)
    5a49:	48 89 b5 00 ff ff ff 	mov    %rsi,-0x100(%rbp)
    5a50:	48 89 95 f8 fe ff ff 	mov    %rdx,-0x108(%rbp)
    5a57:	48 89 8d f0 fe ff ff 	mov    %rcx,-0x110(%rbp)
  mchunkptr p = align_as_chunk(newbase);
    5a5e:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    5a65:	48 83 c0 10          	add    $0x10,%rax
    5a69:	83 e0 0f             	and    $0xf,%eax
    5a6c:	48 85 c0             	test   %rax,%rax
    5a6f:	74 16                	je     5a87 <prepend_alloc+0x50>
    5a71:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    5a78:	48 83 c0 10          	add    $0x10,%rax
    5a7c:	48 f7 d8             	neg    %rax
    5a7f:	83 e0 0f             	and    $0xf,%eax
    5a82:	48 89 c2             	mov    %rax,%rdx
    5a85:	eb 05                	jmp    5a8c <prepend_alloc+0x55>
    5a87:	ba 00 00 00 00       	mov    $0x0,%edx
    5a8c:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    5a93:	48 01 d0             	add    %rdx,%rax
    5a96:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
  mchunkptr oldfirst = align_as_chunk(oldbase);
    5a9d:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    5aa4:	48 83 c0 10          	add    $0x10,%rax
    5aa8:	83 e0 0f             	and    $0xf,%eax
    5aab:	48 85 c0             	test   %rax,%rax
    5aae:	74 16                	je     5ac6 <prepend_alloc+0x8f>
    5ab0:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    5ab7:	48 83 c0 10          	add    $0x10,%rax
    5abb:	48 f7 d8             	neg    %rax
    5abe:	83 e0 0f             	and    $0xf,%eax
    5ac1:	48 89 c2             	mov    %rax,%rdx
    5ac4:	eb 05                	jmp    5acb <prepend_alloc+0x94>
    5ac6:	ba 00 00 00 00       	mov    $0x0,%edx
    5acb:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    5ad2:	48 01 d0             	add    %rdx,%rax
    5ad5:	48 89 85 28 ff ff ff 	mov    %rax,-0xd8(%rbp)
  size_t psize = (char*)oldfirst - (char*)p;
    5adc:	48 8b 95 28 ff ff ff 	mov    -0xd8(%rbp),%rdx
    5ae3:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    5aea:	48 29 c2             	sub    %rax,%rdx
    5aed:	48 89 d0             	mov    %rdx,%rax
    5af0:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
  mchunkptr q = chunk_plus_offset(p, nb);
    5af7:	48 8b 95 68 ff ff ff 	mov    -0x98(%rbp),%rdx
    5afe:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    5b05:	48 01 d0             	add    %rdx,%rax
    5b08:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
  size_t qsize = psize - nb;
    5b0f:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    5b16:	48 2b 85 f0 fe ff ff 	sub    -0x110(%rbp),%rax
    5b1d:	48 89 85 30 ff ff ff 	mov    %rax,-0xd0(%rbp)
  set_size_and_pinuse_of_inuse_chunk(m, p, nb);
    5b24:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    5b2b:	48 83 c8 03          	or     $0x3,%rax
    5b2f:	48 89 c2             	mov    %rax,%rdx
    5b32:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    5b39:	48 89 50 08          	mov    %rdx,0x8(%rax)
    5b3d:	48 8b 0d dc b5 00 00 	mov    0xb5dc(%rip),%rcx        # 11120 <mparams>
    5b44:	48 8b 95 08 ff ff ff 	mov    -0xf8(%rbp),%rdx
    5b4b:	48 8b b5 68 ff ff ff 	mov    -0x98(%rbp),%rsi
    5b52:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    5b59:	48 01 f0             	add    %rsi,%rax
    5b5c:	48 31 ca             	xor    %rcx,%rdx
    5b5f:	48 89 10             	mov    %rdx,(%rax)

  assert((char*)oldfirst > (char*)q);
    5b62:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5b69:	48 3b 85 78 ff ff ff 	cmp    -0x88(%rbp),%rax
    5b70:	77 05                	ja     5b77 <prepend_alloc+0x140>
    5b72:	e8 57 6e 00 00       	callq  c9ce <abort>
  assert(pinuse(oldfirst));
    5b77:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5b7e:	48 8b 40 08          	mov    0x8(%rax),%rax
    5b82:	83 e0 01             	and    $0x1,%eax
    5b85:	48 85 c0             	test   %rax,%rax
    5b88:	75 05                	jne    5b8f <prepend_alloc+0x158>
    5b8a:	e8 3f 6e 00 00       	callq  c9ce <abort>
  assert(qsize >= MIN_CHUNK_SIZE);
    5b8f:	48 83 bd 30 ff ff ff 	cmpq   $0x1f,-0xd0(%rbp)
    5b96:	1f 
    5b97:	77 05                	ja     5b9e <prepend_alloc+0x167>
    5b99:	e8 30 6e 00 00       	callq  c9ce <abort>

  /* consolidate remainder with first chunk of old base */
  if (oldfirst == m->top) {
    5b9e:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5ba5:	48 8b 40 28          	mov    0x28(%rax),%rax
    5ba9:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    5bb0:	75 75                	jne    5c27 <prepend_alloc+0x1f0>
    size_t tsize = m->topsize += qsize;
    5bb2:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5bb9:	48 8b 50 10          	mov    0x10(%rax),%rdx
    5bbd:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    5bc4:	48 01 c2             	add    %rax,%rdx
    5bc7:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5bce:	48 89 50 10          	mov    %rdx,0x10(%rax)
    5bd2:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5bd9:	48 8b 40 10          	mov    0x10(%rax),%rax
    5bdd:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    m->top = q;
    5be1:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5be8:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    5bef:	48 89 50 28          	mov    %rdx,0x28(%rax)
    q->head = tsize | PINUSE_BIT;
    5bf3:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    5bf7:	48 83 c8 01          	or     $0x1,%rax
    5bfb:	48 89 c2             	mov    %rax,%rdx
    5bfe:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    5c05:	48 89 50 08          	mov    %rdx,0x8(%rax)
    check_top_chunk(m, q);
    5c09:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    5c10:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5c17:	48 89 d6             	mov    %rdx,%rsi
    5c1a:	48 89 c7             	mov    %rax,%rdi
    5c1d:	e8 f3 f8 ff ff       	callq  5515 <do_check_top_chunk>
    5c22:	e9 95 0a 00 00       	jmpq   66bc <prepend_alloc+0xc85>
  }
  else if (oldfirst == m->dv) {
    5c27:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5c2e:	48 8b 40 20          	mov    0x20(%rax),%rax
    5c32:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    5c39:	75 71                	jne    5cac <prepend_alloc+0x275>
    size_t dsize = m->dvsize += qsize;
    5c3b:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5c42:	48 8b 50 08          	mov    0x8(%rax),%rdx
    5c46:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    5c4d:	48 01 c2             	add    %rax,%rdx
    5c50:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5c57:	48 89 50 08          	mov    %rdx,0x8(%rax)
    5c5b:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5c62:	48 8b 40 08          	mov    0x8(%rax),%rax
    5c66:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    m->dv = q;
    5c6a:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5c71:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    5c78:	48 89 50 20          	mov    %rdx,0x20(%rax)
    set_size_and_pinuse_of_free_chunk(q, dsize);
    5c7c:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5c80:	48 83 c8 01          	or     $0x1,%rax
    5c84:	48 89 c2             	mov    %rax,%rdx
    5c87:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    5c8e:	48 89 50 08          	mov    %rdx,0x8(%rax)
    5c92:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    5c99:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5c9d:	48 01 c2             	add    %rax,%rdx
    5ca0:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    5ca4:	48 89 02             	mov    %rax,(%rdx)
    5ca7:	e9 10 0a 00 00       	jmpq   66bc <prepend_alloc+0xc85>
  }
  else {
    if (!is_inuse(oldfirst)) {
    5cac:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5cb3:	48 8b 40 08          	mov    0x8(%rax),%rax
    5cb7:	83 e0 03             	and    $0x3,%eax
    5cba:	48 83 f8 01          	cmp    $0x1,%rax
    5cbe:	0f 85 70 05 00 00    	jne    6234 <prepend_alloc+0x7fd>
      size_t nsize = chunksize(oldfirst);
    5cc4:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5ccb:	48 8b 40 08          	mov    0x8(%rax),%rax
    5ccf:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    5cd3:	48 89 45 80          	mov    %rax,-0x80(%rbp)
      unlink_chunk(m, oldfirst, nsize);
    5cd7:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    5cdb:	48 c1 e8 03          	shr    $0x3,%rax
    5cdf:	48 83 f8 1f          	cmp    $0x1f,%rax
    5ce3:	0f 87 c6 01 00 00    	ja     5eaf <prepend_alloc+0x478>
    5ce9:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5cf0:	48 8b 40 10          	mov    0x10(%rax),%rax
    5cf4:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    5cf8:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5cff:	48 8b 40 18          	mov    0x18(%rax),%rax
    5d03:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    5d07:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    5d0b:	48 c1 e8 03          	shr    $0x3,%rax
    5d0f:	89 85 18 ff ff ff    	mov    %eax,-0xe8(%rbp)
    5d15:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5d1c:	48 3b 45 c0          	cmp    -0x40(%rbp),%rax
    5d20:	75 05                	jne    5d27 <prepend_alloc+0x2f0>
    5d22:	e8 a7 6c 00 00       	callq  c9ce <abort>
    5d27:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5d2e:	48 3b 45 b8          	cmp    -0x48(%rbp),%rax
    5d32:	75 05                	jne    5d39 <prepend_alloc+0x302>
    5d34:	e8 95 6c 00 00       	callq  c9ce <abort>
    5d39:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5d40:	48 8b 40 08          	mov    0x8(%rax),%rax
    5d44:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    5d48:	48 89 c2             	mov    %rax,%rdx
    5d4b:	8b 85 18 ff ff ff    	mov    -0xe8(%rbp),%eax
    5d51:	c1 e0 03             	shl    $0x3,%eax
    5d54:	89 c0                	mov    %eax,%eax
    5d56:	48 39 c2             	cmp    %rax,%rdx
    5d59:	74 05                	je     5d60 <prepend_alloc+0x329>
    5d5b:	e8 6e 6c 00 00       	callq  c9ce <abort>
    5d60:	8b 85 18 ff ff ff    	mov    -0xe8(%rbp),%eax
    5d66:	01 c0                	add    %eax,%eax
    5d68:	89 c0                	mov    %eax,%eax
    5d6a:	48 83 c0 08          	add    $0x8,%rax
    5d6e:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    5d75:	00 
    5d76:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5d7d:	48 01 d0             	add    %rdx,%rax
    5d80:	48 83 c0 08          	add    $0x8,%rax
    5d84:	48 39 45 b8          	cmp    %rax,-0x48(%rbp)
    5d88:	0f 94 c0             	sete   %al
    5d8b:	0f b6 c0             	movzbl %al,%eax
    5d8e:	48 85 c0             	test   %rax,%rax
    5d91:	75 48                	jne    5ddb <prepend_alloc+0x3a4>
    5d93:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5d9a:	48 8b 40 18          	mov    0x18(%rax),%rax
    5d9e:	48 39 45 b8          	cmp    %rax,-0x48(%rbp)
    5da2:	0f 93 c0             	setae  %al
    5da5:	0f b6 c0             	movzbl %al,%eax
    5da8:	48 85 c0             	test   %rax,%rax
    5dab:	74 21                	je     5dce <prepend_alloc+0x397>
    5dad:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    5db1:	48 8b 40 18          	mov    0x18(%rax),%rax
    5db5:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    5dbc:	0f 94 c0             	sete   %al
    5dbf:	0f b6 c0             	movzbl %al,%eax
    5dc2:	48 85 c0             	test   %rax,%rax
    5dc5:	74 07                	je     5dce <prepend_alloc+0x397>
    5dc7:	b8 01 00 00 00       	mov    $0x1,%eax
    5dcc:	eb 05                	jmp    5dd3 <prepend_alloc+0x39c>
    5dce:	b8 00 00 00 00       	mov    $0x0,%eax
    5dd3:	85 c0                	test   %eax,%eax
    5dd5:	0f 84 cf 00 00 00    	je     5eaa <prepend_alloc+0x473>
    5ddb:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    5ddf:	48 3b 45 b8          	cmp    -0x48(%rbp),%rax
    5de3:	75 2c                	jne    5e11 <prepend_alloc+0x3da>
    5de5:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5dec:	8b 10                	mov    (%rax),%edx
    5dee:	8b 85 18 ff ff ff    	mov    -0xe8(%rbp),%eax
    5df4:	be 01 00 00 00       	mov    $0x1,%esi
    5df9:	89 c1                	mov    %eax,%ecx
    5dfb:	d3 e6                	shl    %cl,%esi
    5dfd:	89 f0                	mov    %esi,%eax
    5dff:	f7 d0                	not    %eax
    5e01:	21 c2                	and    %eax,%edx
    5e03:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5e0a:	89 10                	mov    %edx,(%rax)
    5e0c:	e9 0d 04 00 00       	jmpq   621e <prepend_alloc+0x7e7>
    5e11:	8b 85 18 ff ff ff    	mov    -0xe8(%rbp),%eax
    5e17:	01 c0                	add    %eax,%eax
    5e19:	89 c0                	mov    %eax,%eax
    5e1b:	48 83 c0 08          	add    $0x8,%rax
    5e1f:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    5e26:	00 
    5e27:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5e2e:	48 01 d0             	add    %rdx,%rax
    5e31:	48 83 c0 08          	add    $0x8,%rax
    5e35:	48 39 45 c0          	cmp    %rax,-0x40(%rbp)
    5e39:	0f 94 c0             	sete   %al
    5e3c:	0f b6 c0             	movzbl %al,%eax
    5e3f:	48 85 c0             	test   %rax,%rax
    5e42:	75 44                	jne    5e88 <prepend_alloc+0x451>
    5e44:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5e4b:	48 8b 40 18          	mov    0x18(%rax),%rax
    5e4f:	48 39 45 c0          	cmp    %rax,-0x40(%rbp)
    5e53:	0f 93 c0             	setae  %al
    5e56:	0f b6 c0             	movzbl %al,%eax
    5e59:	48 85 c0             	test   %rax,%rax
    5e5c:	74 21                	je     5e7f <prepend_alloc+0x448>
    5e5e:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    5e62:	48 8b 40 10          	mov    0x10(%rax),%rax
    5e66:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    5e6d:	0f 94 c0             	sete   %al
    5e70:	0f b6 c0             	movzbl %al,%eax
    5e73:	48 85 c0             	test   %rax,%rax
    5e76:	74 07                	je     5e7f <prepend_alloc+0x448>
    5e78:	b8 01 00 00 00       	mov    $0x1,%eax
    5e7d:	eb 05                	jmp    5e84 <prepend_alloc+0x44d>
    5e7f:	b8 00 00 00 00       	mov    $0x0,%eax
    5e84:	85 c0                	test   %eax,%eax
    5e86:	74 1d                	je     5ea5 <prepend_alloc+0x46e>
    5e88:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    5e8c:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    5e90:	48 89 50 18          	mov    %rdx,0x18(%rax)
    5e94:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    5e98:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
    5e9c:	48 89 50 10          	mov    %rdx,0x10(%rax)
    5ea0:	e9 79 03 00 00       	jmpq   621e <prepend_alloc+0x7e7>
    5ea5:	e8 24 6b 00 00       	callq  c9ce <abort>
    5eaa:	e8 1f 6b 00 00       	callq  c9ce <abort>
    5eaf:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    5eb6:	48 89 45 88          	mov    %rax,-0x78(%rbp)
    5eba:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    5ebe:	48 8b 40 30          	mov    0x30(%rax),%rax
    5ec2:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    5ec6:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    5eca:	48 8b 40 18          	mov    0x18(%rax),%rax
    5ece:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    5ed2:	0f 84 9e 00 00 00    	je     5f76 <prepend_alloc+0x53f>
    5ed8:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    5edc:	48 8b 40 10          	mov    0x10(%rax),%rax
    5ee0:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    5ee4:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    5ee8:	48 8b 40 18          	mov    0x18(%rax),%rax
    5eec:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
    5ef3:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    5efa:	48 8b 40 18          	mov    0x18(%rax),%rax
    5efe:	48 39 45 98          	cmp    %rax,-0x68(%rbp)
    5f02:	0f 93 c0             	setae  %al
    5f05:	0f b6 c0             	movzbl %al,%eax
    5f08:	48 85 c0             	test   %rax,%rax
    5f0b:	74 1e                	je     5f2b <prepend_alloc+0x4f4>
    5f0d:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    5f11:	48 8b 40 18          	mov    0x18(%rax),%rax
    5f15:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    5f19:	0f 94 c0             	sete   %al
    5f1c:	0f b6 c0             	movzbl %al,%eax
    5f1f:	48 85 c0             	test   %rax,%rax
    5f22:	74 07                	je     5f2b <prepend_alloc+0x4f4>
    5f24:	b8 01 00 00 00       	mov    $0x1,%eax
    5f29:	eb 05                	jmp    5f30 <prepend_alloc+0x4f9>
    5f2b:	b8 00 00 00 00       	mov    $0x0,%eax
    5f30:	85 c0                	test   %eax,%eax
    5f32:	74 3d                	je     5f71 <prepend_alloc+0x53a>
    5f34:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    5f3b:	48 8b 40 10          	mov    0x10(%rax),%rax
    5f3f:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    5f43:	0f 94 c0             	sete   %al
    5f46:	0f b6 c0             	movzbl %al,%eax
    5f49:	48 85 c0             	test   %rax,%rax
    5f4c:	74 23                	je     5f71 <prepend_alloc+0x53a>
    5f4e:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    5f52:	48 8b 95 38 ff ff ff 	mov    -0xc8(%rbp),%rdx
    5f59:	48 89 50 18          	mov    %rdx,0x18(%rax)
    5f5d:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    5f64:	48 8b 55 98          	mov    -0x68(%rbp),%rdx
    5f68:	48 89 50 10          	mov    %rdx,0x10(%rax)
    5f6c:	e9 f2 00 00 00       	jmpq   6063 <prepend_alloc+0x62c>
    5f71:	e8 58 6a 00 00       	callq  c9ce <abort>
    5f76:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    5f7a:	48 83 c0 28          	add    $0x28,%rax
    5f7e:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
    5f85:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    5f8c:	48 8b 00             	mov    (%rax),%rax
    5f8f:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
    5f96:	48 83 bd 38 ff ff ff 	cmpq   $0x0,-0xc8(%rbp)
    5f9d:	00 
    5f9e:	75 4f                	jne    5fef <prepend_alloc+0x5b8>
    5fa0:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    5fa4:	48 83 c0 20          	add    $0x20,%rax
    5fa8:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
    5faf:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    5fb6:	48 8b 00             	mov    (%rax),%rax
    5fb9:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
    5fc0:	48 83 bd 38 ff ff ff 	cmpq   $0x0,-0xc8(%rbp)
    5fc7:	00 
    5fc8:	0f 84 95 00 00 00    	je     6063 <prepend_alloc+0x62c>
    5fce:	eb 1f                	jmp    5fef <prepend_alloc+0x5b8>
    5fd0:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    5fd7:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
    5fde:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    5fe5:	48 8b 00             	mov    (%rax),%rax
    5fe8:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
    5fef:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    5ff6:	48 83 c0 28          	add    $0x28,%rax
    5ffa:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    6001:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6008:	48 8b 00             	mov    (%rax),%rax
    600b:	48 85 c0             	test   %rax,%rax
    600e:	75 c0                	jne    5fd0 <prepend_alloc+0x599>
    6010:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    6017:	48 83 c0 20          	add    $0x20,%rax
    601b:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    6022:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6029:	48 8b 00             	mov    (%rax),%rax
    602c:	48 85 c0             	test   %rax,%rax
    602f:	75 9f                	jne    5fd0 <prepend_alloc+0x599>
    6031:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6038:	48 8b 40 18          	mov    0x18(%rax),%rax
    603c:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    6043:	0f 93 c0             	setae  %al
    6046:	0f b6 c0             	movzbl %al,%eax
    6049:	48 85 c0             	test   %rax,%rax
    604c:	74 10                	je     605e <prepend_alloc+0x627>
    604e:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    6055:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    605c:	eb 05                	jmp    6063 <prepend_alloc+0x62c>
    605e:	e8 6b 69 00 00       	callq  c9ce <abort>
    6063:	48 83 7d 90 00       	cmpq   $0x0,-0x70(%rbp)
    6068:	0f 84 b0 01 00 00    	je     621e <prepend_alloc+0x7e7>
    606e:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    6072:	8b 40 38             	mov    0x38(%rax),%eax
    6075:	89 c0                	mov    %eax,%eax
    6077:	48 83 c0 4a          	add    $0x4a,%rax
    607b:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    6082:	00 
    6083:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    608a:	48 01 d0             	add    %rdx,%rax
    608d:	48 83 c0 08          	add    $0x8,%rax
    6091:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
    6095:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    6099:	48 8b 00             	mov    (%rax),%rax
    609c:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    60a0:	75 46                	jne    60e8 <prepend_alloc+0x6b1>
    60a2:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    60a6:	48 8b 95 38 ff ff ff 	mov    -0xc8(%rbp),%rdx
    60ad:	48 89 10             	mov    %rdx,(%rax)
    60b0:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    60b4:	48 8b 00             	mov    (%rax),%rax
    60b7:	48 85 c0             	test   %rax,%rax
    60ba:	75 7b                	jne    6137 <prepend_alloc+0x700>
    60bc:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    60c3:	8b 50 04             	mov    0x4(%rax),%edx
    60c6:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    60ca:	8b 40 38             	mov    0x38(%rax),%eax
    60cd:	be 01 00 00 00       	mov    $0x1,%esi
    60d2:	89 c1                	mov    %eax,%ecx
    60d4:	d3 e6                	shl    %cl,%esi
    60d6:	89 f0                	mov    %esi,%eax
    60d8:	f7 d0                	not    %eax
    60da:	21 c2                	and    %eax,%edx
    60dc:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    60e3:	89 50 04             	mov    %edx,0x4(%rax)
    60e6:	eb 4f                	jmp    6137 <prepend_alloc+0x700>
    60e8:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    60ef:	48 8b 40 18          	mov    0x18(%rax),%rax
    60f3:	48 39 45 90          	cmp    %rax,-0x70(%rbp)
    60f7:	0f 93 c0             	setae  %al
    60fa:	0f b6 c0             	movzbl %al,%eax
    60fd:	48 85 c0             	test   %rax,%rax
    6100:	74 30                	je     6132 <prepend_alloc+0x6fb>
    6102:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    6106:	48 8b 40 20          	mov    0x20(%rax),%rax
    610a:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    610e:	75 11                	jne    6121 <prepend_alloc+0x6ea>
    6110:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    6114:	48 8b 95 38 ff ff ff 	mov    -0xc8(%rbp),%rdx
    611b:	48 89 50 20          	mov    %rdx,0x20(%rax)
    611f:	eb 16                	jmp    6137 <prepend_alloc+0x700>
    6121:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    6125:	48 8b 95 38 ff ff ff 	mov    -0xc8(%rbp),%rdx
    612c:	48 89 50 28          	mov    %rdx,0x28(%rax)
    6130:	eb 05                	jmp    6137 <prepend_alloc+0x700>
    6132:	e8 97 68 00 00       	callq  c9ce <abort>
    6137:	48 83 bd 38 ff ff ff 	cmpq   $0x0,-0xc8(%rbp)
    613e:	00 
    613f:	0f 84 d9 00 00 00    	je     621e <prepend_alloc+0x7e7>
    6145:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    614c:	48 8b 40 18          	mov    0x18(%rax),%rax
    6150:	48 39 85 38 ff ff ff 	cmp    %rax,-0xc8(%rbp)
    6157:	0f 93 c0             	setae  %al
    615a:	0f b6 c0             	movzbl %al,%eax
    615d:	48 85 c0             	test   %rax,%rax
    6160:	0f 84 b3 00 00 00    	je     6219 <prepend_alloc+0x7e2>
    6166:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    616d:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    6171:	48 89 50 30          	mov    %rdx,0x30(%rax)
    6175:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    6179:	48 8b 40 20          	mov    0x20(%rax),%rax
    617d:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    6181:	48 83 7d a8 00       	cmpq   $0x0,-0x58(%rbp)
    6186:	74 3f                	je     61c7 <prepend_alloc+0x790>
    6188:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    618f:	48 8b 40 18          	mov    0x18(%rax),%rax
    6193:	48 39 45 a8          	cmp    %rax,-0x58(%rbp)
    6197:	0f 93 c0             	setae  %al
    619a:	0f b6 c0             	movzbl %al,%eax
    619d:	48 85 c0             	test   %rax,%rax
    61a0:	74 20                	je     61c2 <prepend_alloc+0x78b>
    61a2:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    61a9:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    61ad:	48 89 50 20          	mov    %rdx,0x20(%rax)
    61b1:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    61b5:	48 8b 95 38 ff ff ff 	mov    -0xc8(%rbp),%rdx
    61bc:	48 89 50 30          	mov    %rdx,0x30(%rax)
    61c0:	eb 05                	jmp    61c7 <prepend_alloc+0x790>
    61c2:	e8 07 68 00 00       	callq  c9ce <abort>
    61c7:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    61cb:	48 8b 40 28          	mov    0x28(%rax),%rax
    61cf:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    61d3:	48 83 7d b0 00       	cmpq   $0x0,-0x50(%rbp)
    61d8:	74 44                	je     621e <prepend_alloc+0x7e7>
    61da:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    61e1:	48 8b 40 18          	mov    0x18(%rax),%rax
    61e5:	48 39 45 b0          	cmp    %rax,-0x50(%rbp)
    61e9:	0f 93 c0             	setae  %al
    61ec:	0f b6 c0             	movzbl %al,%eax
    61ef:	48 85 c0             	test   %rax,%rax
    61f2:	74 20                	je     6214 <prepend_alloc+0x7dd>
    61f4:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    61fb:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    61ff:	48 89 50 28          	mov    %rdx,0x28(%rax)
    6203:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    6207:	48 8b 95 38 ff ff ff 	mov    -0xc8(%rbp),%rdx
    620e:	48 89 50 30          	mov    %rdx,0x30(%rax)
    6212:	eb 0a                	jmp    621e <prepend_alloc+0x7e7>
    6214:	e8 b5 67 00 00       	callq  c9ce <abort>
    6219:	e8 b0 67 00 00       	callq  c9ce <abort>
      oldfirst = chunk_plus_offset(oldfirst, nsize);
    621e:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    6222:	48 01 85 28 ff ff ff 	add    %rax,-0xd8(%rbp)
      qsize += nsize;
    6229:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    622d:	48 01 85 30 ff ff ff 	add    %rax,-0xd0(%rbp)
    }
    set_free_with_pinuse(q, qsize, oldfirst);
    6234:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    623b:	48 8b 40 08          	mov    0x8(%rax),%rax
    623f:	48 83 e0 fe          	and    $0xfffffffffffffffe,%rax
    6243:	48 89 c2             	mov    %rax,%rdx
    6246:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    624d:	48 89 50 08          	mov    %rdx,0x8(%rax)
    6251:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    6258:	48 83 c8 01          	or     $0x1,%rax
    625c:	48 89 c2             	mov    %rax,%rdx
    625f:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    6266:	48 89 50 08          	mov    %rdx,0x8(%rax)
    626a:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    6271:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    6278:	48 01 c2             	add    %rax,%rdx
    627b:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    6282:	48 89 02             	mov    %rax,(%rdx)
    insert_chunk(m, q, qsize);
    6285:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    628c:	48 c1 e8 03          	shr    $0x3,%rax
    6290:	48 83 f8 1f          	cmp    $0x1f,%rax
    6294:	0f 87 18 01 00 00    	ja     63b2 <prepend_alloc+0x97b>
    629a:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    62a1:	48 c1 e8 03          	shr    $0x3,%rax
    62a5:	89 85 24 ff ff ff    	mov    %eax,-0xdc(%rbp)
    62ab:	8b 85 24 ff ff ff    	mov    -0xdc(%rbp),%eax
    62b1:	01 c0                	add    %eax,%eax
    62b3:	89 c0                	mov    %eax,%eax
    62b5:	48 83 c0 08          	add    $0x8,%rax
    62b9:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    62c0:	00 
    62c1:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    62c8:	48 01 d0             	add    %rdx,%rax
    62cb:	48 83 c0 08          	add    $0x8,%rax
    62cf:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    62d3:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    62d7:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    62de:	48 83 bd 30 ff ff ff 	cmpq   $0x1f,-0xd0(%rbp)
    62e5:	1f 
    62e6:	77 05                	ja     62ed <prepend_alloc+0x8b6>
    62e8:	e8 e1 66 00 00       	callq  c9ce <abort>
    62ed:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    62f4:	8b 10                	mov    (%rax),%edx
    62f6:	8b 85 24 ff ff ff    	mov    -0xdc(%rbp),%eax
    62fc:	be 01 00 00 00       	mov    $0x1,%esi
    6301:	89 c1                	mov    %eax,%ecx
    6303:	d3 e6                	shl    %cl,%esi
    6305:	89 f0                	mov    %esi,%eax
    6307:	21 d0                	and    %edx,%eax
    6309:	85 c0                	test   %eax,%eax
    630b:	75 27                	jne    6334 <prepend_alloc+0x8fd>
    630d:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6314:	8b 10                	mov    (%rax),%edx
    6316:	8b 85 24 ff ff ff    	mov    -0xdc(%rbp),%eax
    631c:	be 01 00 00 00       	mov    $0x1,%esi
    6321:	89 c1                	mov    %eax,%ecx
    6323:	d3 e6                	shl    %cl,%esi
    6325:	89 f0                	mov    %esi,%eax
    6327:	09 c2                	or     %eax,%edx
    6329:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6330:	89 10                	mov    %edx,(%rax)
    6332:	eb 37                	jmp    636b <prepend_alloc+0x934>
    6334:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    6338:	48 8b 50 10          	mov    0x10(%rax),%rdx
    633c:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6343:	48 8b 40 18          	mov    0x18(%rax),%rax
    6347:	48 39 c2             	cmp    %rax,%rdx
    634a:	0f 93 c0             	setae  %al
    634d:	0f b6 c0             	movzbl %al,%eax
    6350:	48 85 c0             	test   %rax,%rax
    6353:	74 11                	je     6366 <prepend_alloc+0x92f>
    6355:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    6359:	48 8b 40 10          	mov    0x10(%rax),%rax
    635d:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    6364:	eb 05                	jmp    636b <prepend_alloc+0x934>
    6366:	e8 63 66 00 00       	callq  c9ce <abort>
    636b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    636f:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    6376:	48 89 50 10          	mov    %rdx,0x10(%rax)
    637a:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    6381:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    6388:	48 89 50 18          	mov    %rdx,0x18(%rax)
    638c:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    6393:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    639a:	48 89 50 10          	mov    %rdx,0x10(%rax)
    639e:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    63a5:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    63a9:	48 89 50 18          	mov    %rdx,0x18(%rax)
    63ad:	e9 f1 02 00 00       	jmpq   66a3 <prepend_alloc+0xc6c>
    63b2:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    63b9:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    63bd:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    63c4:	48 c1 e8 08          	shr    $0x8,%rax
    63c8:	89 85 1c ff ff ff    	mov    %eax,-0xe4(%rbp)
    63ce:	83 bd 1c ff ff ff 00 	cmpl   $0x0,-0xe4(%rbp)
    63d5:	75 0c                	jne    63e3 <prepend_alloc+0x9ac>
    63d7:	c7 85 14 ff ff ff 00 	movl   $0x0,-0xec(%rbp)
    63de:	00 00 00 
    63e1:	eb 5d                	jmp    6440 <prepend_alloc+0xa09>
    63e3:	81 bd 1c ff ff ff ff 	cmpl   $0xffff,-0xe4(%rbp)
    63ea:	ff 00 00 
    63ed:	76 0c                	jbe    63fb <prepend_alloc+0x9c4>
    63ef:	c7 85 14 ff ff ff 1f 	movl   $0x1f,-0xec(%rbp)
    63f6:	00 00 00 
    63f9:	eb 45                	jmp    6440 <prepend_alloc+0xa09>
    63fb:	0f bd 85 1c ff ff ff 	bsr    -0xe4(%rbp),%eax
    6402:	83 f0 1f             	xor    $0x1f,%eax
    6405:	ba 1f 00 00 00       	mov    $0x1f,%edx
    640a:	29 c2                	sub    %eax,%edx
    640c:	89 d0                	mov    %edx,%eax
    640e:	89 85 20 ff ff ff    	mov    %eax,-0xe0(%rbp)
    6414:	8b 85 20 ff ff ff    	mov    -0xe0(%rbp),%eax
    641a:	8d 34 00             	lea    (%rax,%rax,1),%esi
    641d:	8b 85 20 ff ff ff    	mov    -0xe0(%rbp),%eax
    6423:	83 c0 07             	add    $0x7,%eax
    6426:	48 8b 95 30 ff ff ff 	mov    -0xd0(%rbp),%rdx
    642d:	89 c1                	mov    %eax,%ecx
    642f:	48 d3 ea             	shr    %cl,%rdx
    6432:	48 89 d0             	mov    %rdx,%rax
    6435:	83 e0 01             	and    $0x1,%eax
    6438:	01 f0                	add    %esi,%eax
    643a:	89 85 14 ff ff ff    	mov    %eax,-0xec(%rbp)
    6440:	8b 85 14 ff ff ff    	mov    -0xec(%rbp),%eax
    6446:	48 83 c0 4a          	add    $0x4a,%rax
    644a:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    6451:	00 
    6452:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6459:	48 01 d0             	add    %rdx,%rax
    645c:	48 83 c0 08          	add    $0x8,%rax
    6460:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    6464:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6468:	8b 95 14 ff ff ff    	mov    -0xec(%rbp),%edx
    646e:	89 50 38             	mov    %edx,0x38(%rax)
    6471:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6475:	48 c7 40 28 00 00 00 	movq   $0x0,0x28(%rax)
    647c:	00 
    647d:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6481:	48 8b 50 28          	mov    0x28(%rax),%rdx
    6485:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6489:	48 89 50 20          	mov    %rdx,0x20(%rax)
    648d:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6494:	8b 50 04             	mov    0x4(%rax),%edx
    6497:	8b 85 14 ff ff ff    	mov    -0xec(%rbp),%eax
    649d:	be 01 00 00 00       	mov    $0x1,%esi
    64a2:	89 c1                	mov    %eax,%ecx
    64a4:	d3 e6                	shl    %cl,%esi
    64a6:	89 f0                	mov    %esi,%eax
    64a8:	21 d0                	and    %edx,%eax
    64aa:	85 c0                	test   %eax,%eax
    64ac:	75 5f                	jne    650d <prepend_alloc+0xad6>
    64ae:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    64b5:	8b 50 04             	mov    0x4(%rax),%edx
    64b8:	8b 85 14 ff ff ff    	mov    -0xec(%rbp),%eax
    64be:	be 01 00 00 00       	mov    $0x1,%esi
    64c3:	89 c1                	mov    %eax,%ecx
    64c5:	d3 e6                	shl    %cl,%esi
    64c7:	89 f0                	mov    %esi,%eax
    64c9:	09 c2                	or     %eax,%edx
    64cb:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    64d2:	89 50 04             	mov    %edx,0x4(%rax)
    64d5:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    64d9:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    64dd:	48 89 10             	mov    %rdx,(%rax)
    64e0:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    64e4:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    64e8:	48 89 50 30          	mov    %rdx,0x30(%rax)
    64ec:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    64f0:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    64f4:	48 89 50 18          	mov    %rdx,0x18(%rax)
    64f8:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    64fc:	48 8b 50 18          	mov    0x18(%rax),%rdx
    6500:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6504:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6508:	e9 96 01 00 00       	jmpq   66a3 <prepend_alloc+0xc6c>
    650d:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    6511:	48 8b 00             	mov    (%rax),%rax
    6514:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
    651b:	83 bd 14 ff ff ff 1f 	cmpl   $0x1f,-0xec(%rbp)
    6522:	74 13                	je     6537 <prepend_alloc+0xb00>
    6524:	8b 85 14 ff ff ff    	mov    -0xec(%rbp),%eax
    652a:	d1 e8                	shr    %eax
    652c:	ba 39 00 00 00       	mov    $0x39,%edx
    6531:	29 c2                	sub    %eax,%edx
    6533:	89 d0                	mov    %edx,%eax
    6535:	eb 05                	jmp    653c <prepend_alloc+0xb05>
    6537:	b8 00 00 00 00       	mov    $0x0,%eax
    653c:	48 8b 95 30 ff ff ff 	mov    -0xd0(%rbp),%rdx
    6543:	89 c1                	mov    %eax,%ecx
    6545:	48 d3 e2             	shl    %cl,%rdx
    6548:	48 89 d0             	mov    %rdx,%rax
    654b:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
    6552:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    6559:	48 8b 40 08          	mov    0x8(%rax),%rax
    655d:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    6561:	48 39 85 30 ff ff ff 	cmp    %rax,-0xd0(%rbp)
    6568:	0f 84 a2 00 00 00    	je     6610 <prepend_alloc+0xbd9>
    656e:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    6575:	48 c1 e8 3f          	shr    $0x3f,%rax
    6579:	48 83 c0 04          	add    $0x4,%rax
    657d:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    6584:	00 
    6585:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    658c:	48 01 d0             	add    %rdx,%rax
    658f:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    6593:	48 d1 a5 60 ff ff ff 	shlq   -0xa0(%rbp)
    659a:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    659e:	48 8b 00             	mov    (%rax),%rax
    65a1:	48 85 c0             	test   %rax,%rax
    65a4:	74 10                	je     65b6 <prepend_alloc+0xb7f>
    65a6:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    65aa:	48 8b 00             	mov    (%rax),%rax
    65ad:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
    65b4:	eb 9c                	jmp    6552 <prepend_alloc+0xb1b>
    65b6:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    65bd:	48 8b 40 18          	mov    0x18(%rax),%rax
    65c1:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    65c5:	0f 93 c0             	setae  %al
    65c8:	0f b6 c0             	movzbl %al,%eax
    65cb:	48 85 c0             	test   %rax,%rax
    65ce:	74 3b                	je     660b <prepend_alloc+0xbd4>
    65d0:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    65d4:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    65d8:	48 89 10             	mov    %rdx,(%rax)
    65db:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    65df:	48 8b 95 58 ff ff ff 	mov    -0xa8(%rbp),%rdx
    65e6:	48 89 50 30          	mov    %rdx,0x30(%rax)
    65ea:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    65ee:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    65f2:	48 89 50 18          	mov    %rdx,0x18(%rax)
    65f6:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    65fa:	48 8b 50 18          	mov    0x18(%rax),%rdx
    65fe:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6602:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6606:	e9 98 00 00 00       	jmpq   66a3 <prepend_alloc+0xc6c>
    660b:	e8 be 63 00 00       	callq  c9ce <abort>
    6610:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    6617:	48 8b 40 10          	mov    0x10(%rax),%rax
    661b:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    661f:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6626:	48 8b 40 18          	mov    0x18(%rax),%rax
    662a:	48 39 85 58 ff ff ff 	cmp    %rax,-0xa8(%rbp)
    6631:	0f 93 c0             	setae  %al
    6634:	0f b6 c0             	movzbl %al,%eax
    6637:	48 85 c0             	test   %rax,%rax
    663a:	74 62                	je     669e <prepend_alloc+0xc67>
    663c:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    6643:	48 8b 40 18          	mov    0x18(%rax),%rax
    6647:	48 39 45 d8          	cmp    %rax,-0x28(%rbp)
    664b:	0f 93 c0             	setae  %al
    664e:	0f b6 c0             	movzbl %al,%eax
    6651:	48 85 c0             	test   %rax,%rax
    6654:	74 48                	je     669e <prepend_alloc+0xc67>
    6656:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    665a:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    665e:	48 89 50 18          	mov    %rdx,0x18(%rax)
    6662:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6666:	48 8b 50 18          	mov    0x18(%rax),%rdx
    666a:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    6671:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6675:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6679:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    667d:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6681:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6685:	48 8b 95 58 ff ff ff 	mov    -0xa8(%rbp),%rdx
    668c:	48 89 50 18          	mov    %rdx,0x18(%rax)
    6690:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6694:	48 c7 40 30 00 00 00 	movq   $0x0,0x30(%rax)
    669b:	00 
    669c:	eb 05                	jmp    66a3 <prepend_alloc+0xc6c>
    669e:	e8 2b 63 00 00       	callq  c9ce <abort>
    check_free_chunk(m, q);
    66a3:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    66aa:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    66b1:	48 89 d6             	mov    %rdx,%rsi
    66b4:	48 89 c7             	mov    %rax,%rdi
    66b7:	e8 79 f0 ff ff       	callq  5735 <do_check_free_chunk>
  }

  check_malloced_chunk(m, chunk2mem(p), nb);
    66bc:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    66c3:	48 8d 48 10          	lea    0x10(%rax),%rcx
    66c7:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    66ce:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    66d5:	48 89 ce             	mov    %rcx,%rsi
    66d8:	48 89 c7             	mov    %rax,%rdi
    66db:	e8 c6 f1 ff ff       	callq  58a6 <do_check_malloced_chunk>
  return chunk2mem(p);
    66e0:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    66e7:	48 83 c0 10          	add    $0x10,%rax
}
    66eb:	c9                   	leaveq 
    66ec:	c3                   	retq   

00000000000066ed <add_segment>:

/* Add a segment to hold a new noncontiguous region */
static void add_segment(mstate m, char* tbase, size_t tsize, flag_t mmapped) {
    66ed:	55                   	push   %rbp
    66ee:	48 89 e5             	mov    %rsp,%rbp
    66f1:	48 81 ec 00 01 00 00 	sub    $0x100,%rsp
    66f8:	48 89 bd 18 ff ff ff 	mov    %rdi,-0xe8(%rbp)
    66ff:	48 89 b5 10 ff ff ff 	mov    %rsi,-0xf0(%rbp)
    6706:	48 89 95 08 ff ff ff 	mov    %rdx,-0xf8(%rbp)
    670d:	89 8d 04 ff ff ff    	mov    %ecx,-0xfc(%rbp)
  /* Determine locations and sizes of segment, fenceposts, old top */
  char* old_top = (char*)m->top;
    6713:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    671a:	48 8b 40 28          	mov    0x28(%rax),%rax
    671e:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
  msegmentptr oldsp = segment_holding(m, old_top);
    6725:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    672c:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6733:	48 89 d6             	mov    %rdx,%rsi
    6736:	48 89 c7             	mov    %rax,%rdi
    6739:	e8 f6 eb ff ff       	callq  5334 <segment_holding>
    673e:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
  char* old_end = oldsp->base + oldsp->size;
    6745:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    674c:	48 8b 10             	mov    (%rax),%rdx
    674f:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    6756:	48 8b 40 08          	mov    0x8(%rax),%rax
    675a:	48 01 d0             	add    %rdx,%rax
    675d:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
  size_t ssize = pad_request(sizeof(struct malloc_segment));
    6764:	48 c7 85 78 ff ff ff 	movq   $0x30,-0x88(%rbp)
    676b:	30 00 00 00 
  char* rawsp = old_end - (ssize + FOUR_SIZE_T_SIZES + CHUNK_ALIGN_MASK);
    676f:	48 c7 c0 d1 ff ff ff 	mov    $0xffffffffffffffd1,%rax
    6776:	48 2b 85 78 ff ff ff 	sub    -0x88(%rbp),%rax
    677d:	48 89 c2             	mov    %rax,%rdx
    6780:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    6787:	48 01 d0             	add    %rdx,%rax
    678a:	48 89 45 80          	mov    %rax,-0x80(%rbp)
  size_t offset = align_offset(chunk2mem(rawsp));
    678e:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    6792:	48 83 c0 10          	add    $0x10,%rax
    6796:	83 e0 0f             	and    $0xf,%eax
    6799:	48 85 c0             	test   %rax,%rax
    679c:	74 10                	je     67ae <add_segment+0xc1>
    679e:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    67a2:	48 83 c0 10          	add    $0x10,%rax
    67a6:	48 f7 d8             	neg    %rax
    67a9:	83 e0 0f             	and    $0xf,%eax
    67ac:	eb 05                	jmp    67b3 <add_segment+0xc6>
    67ae:	b8 00 00 00 00       	mov    $0x0,%eax
    67b3:	48 89 45 88          	mov    %rax,-0x78(%rbp)
  char* asp = rawsp + offset;
    67b7:	48 8b 55 80          	mov    -0x80(%rbp),%rdx
    67bb:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    67bf:	48 01 d0             	add    %rdx,%rax
    67c2:	48 89 45 90          	mov    %rax,-0x70(%rbp)
  char* csp = (asp < (old_top + MIN_CHUNK_SIZE))? old_top : asp;
    67c6:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    67cd:	48 83 c0 20          	add    $0x20,%rax
    67d1:	48 39 45 90          	cmp    %rax,-0x70(%rbp)
    67d5:	73 09                	jae    67e0 <add_segment+0xf3>
    67d7:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    67de:	eb 04                	jmp    67e4 <add_segment+0xf7>
    67e0:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    67e4:	48 89 45 98          	mov    %rax,-0x68(%rbp)
  mchunkptr sp = (mchunkptr)csp;
    67e8:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    67ec:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
  msegmentptr ss = (msegmentptr)(chunk2mem(sp));
    67f0:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    67f4:	48 83 c0 10          	add    $0x10,%rax
    67f8:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
  mchunkptr tnext = chunk_plus_offset(sp, ssize);
    67fc:	48 8b 55 a0          	mov    -0x60(%rbp),%rdx
    6800:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    6807:	48 01 d0             	add    %rdx,%rax
    680a:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
  mchunkptr p = tnext;
    680e:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    6812:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
  int nfences = 0;
    6819:	c7 85 2c ff ff ff 00 	movl   $0x0,-0xd4(%rbp)
    6820:	00 00 00 

  /* reset top to new space */
  init_top(m, (mchunkptr)tbase, tsize - TOP_FOOT_SIZE);
    6823:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    682a:	48 8d 50 b0          	lea    -0x50(%rax),%rdx
    682e:	48 8b 8d 10 ff ff ff 	mov    -0xf0(%rbp),%rcx
    6835:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    683c:	48 89 ce             	mov    %rcx,%rsi
    683f:	48 89 c7             	mov    %rax,%rdi
    6842:	e8 fb f0 ff ff       	callq  5942 <init_top>

  /* Set up segment record */
  assert(is_aligned(ss));
    6847:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    684b:	83 e0 0f             	and    $0xf,%eax
    684e:	48 85 c0             	test   %rax,%rax
    6851:	74 05                	je     6858 <add_segment+0x16b>
    6853:	e8 76 61 00 00       	callq  c9ce <abort>
  set_size_and_pinuse_of_inuse_chunk(m, sp, ssize);
    6858:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    685f:	48 83 c8 03          	or     $0x3,%rax
    6863:	48 89 c2             	mov    %rax,%rdx
    6866:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    686a:	48 89 50 08          	mov    %rdx,0x8(%rax)
    686e:	48 8b 0d ab a8 00 00 	mov    0xa8ab(%rip),%rcx        # 11120 <mparams>
    6875:	48 8b 95 18 ff ff ff 	mov    -0xe8(%rbp),%rdx
    687c:	48 8b 75 a0          	mov    -0x60(%rbp),%rsi
    6880:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    6887:	48 01 f0             	add    %rsi,%rax
    688a:	48 31 ca             	xor    %rcx,%rdx
    688d:	48 89 10             	mov    %rdx,(%rax)
  *ss = m->seg; /* Push current record */
    6890:	48 8b 4d a8          	mov    -0x58(%rbp),%rcx
    6894:	48 8b b5 18 ff ff ff 	mov    -0xe8(%rbp),%rsi
    689b:	48 8b 86 78 03 00 00 	mov    0x378(%rsi),%rax
    68a2:	48 8b 96 80 03 00 00 	mov    0x380(%rsi),%rdx
    68a9:	48 89 01             	mov    %rax,(%rcx)
    68ac:	48 89 51 08          	mov    %rdx,0x8(%rcx)
    68b0:	48 8b 86 88 03 00 00 	mov    0x388(%rsi),%rax
    68b7:	48 8b 96 90 03 00 00 	mov    0x390(%rsi),%rdx
    68be:	48 89 41 10          	mov    %rax,0x10(%rcx)
    68c2:	48 89 51 18          	mov    %rdx,0x18(%rcx)
  m->seg.base = tbase;
    68c6:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    68cd:	48 8b 95 10 ff ff ff 	mov    -0xf0(%rbp),%rdx
    68d4:	48 89 90 78 03 00 00 	mov    %rdx,0x378(%rax)
  m->seg.size = tsize;
    68db:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    68e2:	48 8b 95 08 ff ff ff 	mov    -0xf8(%rbp),%rdx
    68e9:	48 89 90 80 03 00 00 	mov    %rdx,0x380(%rax)
  m->seg.sflags = mmapped;
    68f0:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    68f7:	8b 95 04 ff ff ff    	mov    -0xfc(%rbp),%edx
    68fd:	89 90 90 03 00 00    	mov    %edx,0x390(%rax)
  m->seg.next = ss;
    6903:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    690a:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    690e:	48 89 90 88 03 00 00 	mov    %rdx,0x388(%rax)

  /* Insert trailing fenceposts */
  for (;;) {
    mchunkptr nextp = chunk_plus_offset(p, SIZE_T_SIZE);
    6915:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    691c:	48 83 c0 08          	add    $0x8,%rax
    6920:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    p->head = FENCEPOST_HEAD;
    6924:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    692b:	48 c7 40 08 0b 00 00 	movq   $0xb,0x8(%rax)
    6932:	00 
    ++nfences;
    6933:	83 85 2c ff ff ff 01 	addl   $0x1,-0xd4(%rbp)
    if ((char*)(&(nextp->head)) < old_end)
    693a:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    693e:	48 83 c0 08          	add    $0x8,%rax
    6942:	48 39 85 70 ff ff ff 	cmp    %rax,-0x90(%rbp)
    6949:	76 0d                	jbe    6958 <add_segment+0x26b>
      p = nextp;
    694b:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    694f:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
  for (;;) {
    6956:	eb bd                	jmp    6915 <add_segment+0x228>
    else
      break;
    6958:	90                   	nop
  }
  assert(nfences >= 2);
    6959:	83 bd 2c ff ff ff 01 	cmpl   $0x1,-0xd4(%rbp)
    6960:	7f 05                	jg     6967 <add_segment+0x27a>
    6962:	e8 67 60 00 00       	callq  c9ce <abort>

  /* Insert the rest of old top into a bin as an ordinary free chunk */
  if (csp != old_top) {
    6967:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    696b:	48 3b 85 60 ff ff ff 	cmp    -0xa0(%rbp),%rax
    6972:	0f 84 65 04 00 00    	je     6ddd <add_segment+0x6f0>
    mchunkptr q = (mchunkptr)old_top;
    6978:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    697f:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    size_t psize = csp - old_top;
    6983:	48 8b 55 98          	mov    -0x68(%rbp),%rdx
    6987:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    698e:	48 29 c2             	sub    %rax,%rdx
    6991:	48 89 d0             	mov    %rdx,%rax
    6994:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    mchunkptr tn = chunk_plus_offset(q, psize);
    6998:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    699c:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    69a0:	48 01 d0             	add    %rdx,%rax
    69a3:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    set_free_with_pinuse(q, psize, tn);
    69a7:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    69ab:	48 8b 40 08          	mov    0x8(%rax),%rax
    69af:	48 83 e0 fe          	and    $0xfffffffffffffffe,%rax
    69b3:	48 89 c2             	mov    %rax,%rdx
    69b6:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    69ba:	48 89 50 08          	mov    %rdx,0x8(%rax)
    69be:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    69c2:	48 83 c8 01          	or     $0x1,%rax
    69c6:	48 89 c2             	mov    %rax,%rdx
    69c9:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    69cd:	48 89 50 08          	mov    %rdx,0x8(%rax)
    69d1:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    69d5:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    69d9:	48 01 c2             	add    %rax,%rdx
    69dc:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    69e0:	48 89 02             	mov    %rax,(%rdx)
    insert_chunk(m, q, psize);
    69e3:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    69e7:	48 c1 e8 03          	shr    $0x3,%rax
    69eb:	48 83 f8 1f          	cmp    $0x1f,%rax
    69ef:	0f 87 06 01 00 00    	ja     6afb <add_segment+0x40e>
    69f5:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    69f9:	48 c1 e8 03          	shr    $0x3,%rax
    69fd:	89 85 3c ff ff ff    	mov    %eax,-0xc4(%rbp)
    6a03:	8b 85 3c ff ff ff    	mov    -0xc4(%rbp),%eax
    6a09:	01 c0                	add    %eax,%eax
    6a0b:	89 c0                	mov    %eax,%eax
    6a0d:	48 83 c0 08          	add    $0x8,%rax
    6a11:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    6a18:	00 
    6a19:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6a20:	48 01 d0             	add    %rdx,%rax
    6a23:	48 83 c0 08          	add    $0x8,%rax
    6a27:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    6a2b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    6a2f:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    6a36:	48 83 7d c8 1f       	cmpq   $0x1f,-0x38(%rbp)
    6a3b:	77 05                	ja     6a42 <add_segment+0x355>
    6a3d:	e8 8c 5f 00 00       	callq  c9ce <abort>
    6a42:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6a49:	8b 10                	mov    (%rax),%edx
    6a4b:	8b 85 3c ff ff ff    	mov    -0xc4(%rbp),%eax
    6a51:	be 01 00 00 00       	mov    $0x1,%esi
    6a56:	89 c1                	mov    %eax,%ecx
    6a58:	d3 e6                	shl    %cl,%esi
    6a5a:	89 f0                	mov    %esi,%eax
    6a5c:	21 d0                	and    %edx,%eax
    6a5e:	85 c0                	test   %eax,%eax
    6a60:	75 27                	jne    6a89 <add_segment+0x39c>
    6a62:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6a69:	8b 10                	mov    (%rax),%edx
    6a6b:	8b 85 3c ff ff ff    	mov    -0xc4(%rbp),%eax
    6a71:	be 01 00 00 00       	mov    $0x1,%esi
    6a76:	89 c1                	mov    %eax,%ecx
    6a78:	d3 e6                	shl    %cl,%esi
    6a7a:	89 f0                	mov    %esi,%eax
    6a7c:	09 c2                	or     %eax,%edx
    6a7e:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6a85:	89 10                	mov    %edx,(%rax)
    6a87:	eb 37                	jmp    6ac0 <add_segment+0x3d3>
    6a89:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    6a8d:	48 8b 50 10          	mov    0x10(%rax),%rdx
    6a91:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6a98:	48 8b 40 18          	mov    0x18(%rax),%rax
    6a9c:	48 39 c2             	cmp    %rax,%rdx
    6a9f:	0f 93 c0             	setae  %al
    6aa2:	0f b6 c0             	movzbl %al,%eax
    6aa5:	48 85 c0             	test   %rax,%rax
    6aa8:	74 11                	je     6abb <add_segment+0x3ce>
    6aaa:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    6aae:	48 8b 40 10          	mov    0x10(%rax),%rax
    6ab2:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    6ab9:	eb 05                	jmp    6ac0 <add_segment+0x3d3>
    6abb:	e8 0e 5f 00 00       	callq  c9ce <abort>
    6ac0:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    6ac4:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    6ac8:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6acc:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6ad3:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    6ad7:	48 89 50 18          	mov    %rdx,0x18(%rax)
    6adb:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    6adf:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    6ae6:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6aea:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    6aee:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    6af2:	48 89 50 18          	mov    %rdx,0x18(%rax)
    6af6:	e9 e2 02 00 00       	jmpq   6ddd <add_segment+0x6f0>
    6afb:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    6aff:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    6b03:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    6b07:	48 c1 e8 08          	shr    $0x8,%rax
    6b0b:	89 85 34 ff ff ff    	mov    %eax,-0xcc(%rbp)
    6b11:	83 bd 34 ff ff ff 00 	cmpl   $0x0,-0xcc(%rbp)
    6b18:	75 0c                	jne    6b26 <add_segment+0x439>
    6b1a:	c7 85 30 ff ff ff 00 	movl   $0x0,-0xd0(%rbp)
    6b21:	00 00 00 
    6b24:	eb 5a                	jmp    6b80 <add_segment+0x493>
    6b26:	81 bd 34 ff ff ff ff 	cmpl   $0xffff,-0xcc(%rbp)
    6b2d:	ff 00 00 
    6b30:	76 0c                	jbe    6b3e <add_segment+0x451>
    6b32:	c7 85 30 ff ff ff 1f 	movl   $0x1f,-0xd0(%rbp)
    6b39:	00 00 00 
    6b3c:	eb 42                	jmp    6b80 <add_segment+0x493>
    6b3e:	0f bd 85 34 ff ff ff 	bsr    -0xcc(%rbp),%eax
    6b45:	83 f0 1f             	xor    $0x1f,%eax
    6b48:	ba 1f 00 00 00       	mov    $0x1f,%edx
    6b4d:	29 c2                	sub    %eax,%edx
    6b4f:	89 d0                	mov    %edx,%eax
    6b51:	89 85 38 ff ff ff    	mov    %eax,-0xc8(%rbp)
    6b57:	8b 85 38 ff ff ff    	mov    -0xc8(%rbp),%eax
    6b5d:	8d 34 00             	lea    (%rax,%rax,1),%esi
    6b60:	8b 85 38 ff ff ff    	mov    -0xc8(%rbp),%eax
    6b66:	83 c0 07             	add    $0x7,%eax
    6b69:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    6b6d:	89 c1                	mov    %eax,%ecx
    6b6f:	48 d3 ea             	shr    %cl,%rdx
    6b72:	48 89 d0             	mov    %rdx,%rax
    6b75:	83 e0 01             	and    $0x1,%eax
    6b78:	01 f0                	add    %esi,%eax
    6b7a:	89 85 30 ff ff ff    	mov    %eax,-0xd0(%rbp)
    6b80:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    6b86:	48 83 c0 4a          	add    $0x4a,%rax
    6b8a:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    6b91:	00 
    6b92:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6b99:	48 01 d0             	add    %rdx,%rax
    6b9c:	48 83 c0 08          	add    $0x8,%rax
    6ba0:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    6ba4:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6ba8:	8b 95 30 ff ff ff    	mov    -0xd0(%rbp),%edx
    6bae:	89 50 38             	mov    %edx,0x38(%rax)
    6bb1:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6bb5:	48 c7 40 28 00 00 00 	movq   $0x0,0x28(%rax)
    6bbc:	00 
    6bbd:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6bc1:	48 8b 50 28          	mov    0x28(%rax),%rdx
    6bc5:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6bc9:	48 89 50 20          	mov    %rdx,0x20(%rax)
    6bcd:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6bd4:	8b 50 04             	mov    0x4(%rax),%edx
    6bd7:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    6bdd:	be 01 00 00 00       	mov    $0x1,%esi
    6be2:	89 c1                	mov    %eax,%ecx
    6be4:	d3 e6                	shl    %cl,%esi
    6be6:	89 f0                	mov    %esi,%eax
    6be8:	21 d0                	and    %edx,%eax
    6bea:	85 c0                	test   %eax,%eax
    6bec:	75 5f                	jne    6c4d <add_segment+0x560>
    6bee:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6bf5:	8b 50 04             	mov    0x4(%rax),%edx
    6bf8:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    6bfe:	be 01 00 00 00       	mov    $0x1,%esi
    6c03:	89 c1                	mov    %eax,%ecx
    6c05:	d3 e6                	shl    %cl,%esi
    6c07:	89 f0                	mov    %esi,%eax
    6c09:	09 c2                	or     %eax,%edx
    6c0b:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6c12:	89 50 04             	mov    %edx,0x4(%rax)
    6c15:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    6c19:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    6c1d:	48 89 10             	mov    %rdx,(%rax)
    6c20:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6c24:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    6c28:	48 89 50 30          	mov    %rdx,0x30(%rax)
    6c2c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6c30:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    6c34:	48 89 50 18          	mov    %rdx,0x18(%rax)
    6c38:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6c3c:	48 8b 50 18          	mov    0x18(%rax),%rdx
    6c40:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6c44:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6c48:	e9 90 01 00 00       	jmpq   6ddd <add_segment+0x6f0>
    6c4d:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    6c51:	48 8b 00             	mov    (%rax),%rax
    6c54:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    6c5b:	83 bd 30 ff ff ff 1f 	cmpl   $0x1f,-0xd0(%rbp)
    6c62:	74 13                	je     6c77 <add_segment+0x58a>
    6c64:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    6c6a:	d1 e8                	shr    %eax
    6c6c:	ba 39 00 00 00       	mov    $0x39,%edx
    6c71:	29 c2                	sub    %eax,%edx
    6c73:	89 d0                	mov    %edx,%eax
    6c75:	eb 05                	jmp    6c7c <add_segment+0x58f>
    6c77:	b8 00 00 00 00       	mov    $0x0,%eax
    6c7c:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    6c80:	89 c1                	mov    %eax,%ecx
    6c82:	48 d3 e2             	shl    %cl,%rdx
    6c85:	48 89 d0             	mov    %rdx,%rax
    6c88:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
    6c8f:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    6c96:	48 8b 40 08          	mov    0x8(%rax),%rax
    6c9a:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    6c9e:	48 39 45 c8          	cmp    %rax,-0x38(%rbp)
    6ca2:	0f 84 a2 00 00 00    	je     6d4a <add_segment+0x65d>
    6ca8:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    6caf:	48 c1 e8 3f          	shr    $0x3f,%rax
    6cb3:	48 83 c0 04          	add    $0x4,%rax
    6cb7:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    6cbe:	00 
    6cbf:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    6cc6:	48 01 d0             	add    %rdx,%rax
    6cc9:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    6ccd:	48 d1 a5 58 ff ff ff 	shlq   -0xa8(%rbp)
    6cd4:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    6cd8:	48 8b 00             	mov    (%rax),%rax
    6cdb:	48 85 c0             	test   %rax,%rax
    6cde:	74 10                	je     6cf0 <add_segment+0x603>
    6ce0:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    6ce4:	48 8b 00             	mov    (%rax),%rax
    6ce7:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    6cee:	eb 9f                	jmp    6c8f <add_segment+0x5a2>
    6cf0:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6cf7:	48 8b 40 18          	mov    0x18(%rax),%rax
    6cfb:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    6cff:	0f 93 c0             	setae  %al
    6d02:	0f b6 c0             	movzbl %al,%eax
    6d05:	48 85 c0             	test   %rax,%rax
    6d08:	74 3b                	je     6d45 <add_segment+0x658>
    6d0a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    6d0e:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    6d12:	48 89 10             	mov    %rdx,(%rax)
    6d15:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6d19:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    6d20:	48 89 50 30          	mov    %rdx,0x30(%rax)
    6d24:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6d28:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    6d2c:	48 89 50 18          	mov    %rdx,0x18(%rax)
    6d30:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6d34:	48 8b 50 18          	mov    0x18(%rax),%rdx
    6d38:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6d3c:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6d40:	e9 98 00 00 00       	jmpq   6ddd <add_segment+0x6f0>
    6d45:	e8 84 5c 00 00       	callq  c9ce <abort>
    6d4a:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    6d51:	48 8b 40 10          	mov    0x10(%rax),%rax
    6d55:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    6d59:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6d60:	48 8b 40 18          	mov    0x18(%rax),%rax
    6d64:	48 39 85 50 ff ff ff 	cmp    %rax,-0xb0(%rbp)
    6d6b:	0f 93 c0             	setae  %al
    6d6e:	0f b6 c0             	movzbl %al,%eax
    6d71:	48 85 c0             	test   %rax,%rax
    6d74:	74 62                	je     6dd8 <add_segment+0x6eb>
    6d76:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6d7d:	48 8b 40 18          	mov    0x18(%rax),%rax
    6d81:	48 39 45 e8          	cmp    %rax,-0x18(%rbp)
    6d85:	0f 93 c0             	setae  %al
    6d88:	0f b6 c0             	movzbl %al,%eax
    6d8b:	48 85 c0             	test   %rax,%rax
    6d8e:	74 48                	je     6dd8 <add_segment+0x6eb>
    6d90:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    6d94:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    6d98:	48 89 50 18          	mov    %rdx,0x18(%rax)
    6d9c:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    6da0:	48 8b 50 18          	mov    0x18(%rax),%rdx
    6da4:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    6dab:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6daf:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6db3:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    6db7:	48 89 50 10          	mov    %rdx,0x10(%rax)
    6dbb:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6dbf:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    6dc6:	48 89 50 18          	mov    %rdx,0x18(%rax)
    6dca:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    6dce:	48 c7 40 30 00 00 00 	movq   $0x0,0x30(%rax)
    6dd5:	00 
    6dd6:	eb 05                	jmp    6ddd <add_segment+0x6f0>
    6dd8:	e8 f1 5b 00 00       	callq  c9ce <abort>
  }

  check_top_chunk(m, m->top);
    6ddd:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6de4:	48 8b 50 28          	mov    0x28(%rax),%rdx
    6de8:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    6def:	48 89 d6             	mov    %rdx,%rsi
    6df2:	48 89 c7             	mov    %rax,%rdi
    6df5:	e8 1b e7 ff ff       	callq  5515 <do_check_top_chunk>
}
    6dfa:	90                   	nop
    6dfb:	c9                   	leaveq 
    6dfc:	c3                   	retq   

0000000000006dfd <sys_alloc>:

/* -------------------------- System allocation -------------------------- */

/* Get memory from system using MORECORE or MMAP */
static void* sys_alloc(mstate m, size_t nb) {
    6dfd:	55                   	push   %rbp
    6dfe:	48 89 e5             	mov    %rsp,%rbp
    6e01:	48 81 ec c0 00 00 00 	sub    $0xc0,%rsp
    6e08:	48 89 bd 48 ff ff ff 	mov    %rdi,-0xb8(%rbp)
    6e0f:	48 89 b5 40 ff ff ff 	mov    %rsi,-0xc0(%rbp)
  char* tbase = CMFAIL;
    6e16:	48 c7 85 60 ff ff ff 	movq   $0xffffffffffffffff,-0xa0(%rbp)
    6e1d:	ff ff ff ff 
  size_t tsize = 0;
    6e21:	48 c7 85 68 ff ff ff 	movq   $0x0,-0x98(%rbp)
    6e28:	00 00 00 00 
  flag_t mmap_flag = 0;
    6e2c:	c7 85 5c ff ff ff 00 	movl   $0x0,-0xa4(%rbp)
    6e33:	00 00 00 
  size_t asize; /* allocation size */

  ensure_initialization();
    6e36:	48 8b 05 e3 a2 00 00 	mov    0xa2e3(%rip),%rax        # 11120 <mparams>
    6e3d:	48 85 c0             	test   %rax,%rax
    6e40:	75 07                	jne    6e49 <sys_alloc+0x4c>
    6e42:	e8 4c e5 ff ff       	callq  5393 <init_mparams>
    6e47:	85 c0                	test   %eax,%eax
    6e49:	90                   	nop
    void* mem = mmap_alloc(m, nb);
    if (mem != 0)
      return mem;
  }

  asize = granularity_align(nb + SYS_ALLOC_PADDING);
    6e4a:	48 8b 15 df a2 00 00 	mov    0xa2df(%rip),%rdx        # 11130 <mparams+0x10>
    6e51:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    6e58:	48 01 d0             	add    %rdx,%rax
    6e5b:	48 8d 50 5f          	lea    0x5f(%rax),%rdx
    6e5f:	48 8b 05 ca a2 00 00 	mov    0xa2ca(%rip),%rax        # 11130 <mparams+0x10>
    6e66:	48 f7 d8             	neg    %rax
    6e69:	48 21 d0             	and    %rdx,%rax
    6e6c:	48 89 45 88          	mov    %rax,-0x78(%rbp)
  if (asize <= nb)
    6e70:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    6e74:	48 3b 85 40 ff ff ff 	cmp    -0xc0(%rbp),%rax
    6e7b:	77 0a                	ja     6e87 <sys_alloc+0x8a>
    return 0; /* wraparound */
    6e7d:	b8 00 00 00 00       	mov    $0x0,%eax
    6e82:	e9 50 09 00 00       	jmpq   77d7 <sys_alloc+0x9da>
  if (m->footprint_limit != 0) {
    6e87:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6e8e:	48 8b 80 68 03 00 00 	mov    0x368(%rax),%rax
    6e95:	48 85 c0             	test   %rax,%rax
    6e98:	74 4b                	je     6ee5 <sys_alloc+0xe8>
    size_t fp = m->footprint + asize;
    6e9a:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6ea1:	48 8b 90 58 03 00 00 	mov    0x358(%rax),%rdx
    6ea8:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    6eac:	48 01 d0             	add    %rdx,%rax
    6eaf:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    if (fp <= m->footprint || fp > m->footprint_limit)
    6eb3:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6eba:	48 8b 80 58 03 00 00 	mov    0x358(%rax),%rax
    6ec1:	48 39 45 90          	cmp    %rax,-0x70(%rbp)
    6ec5:	76 14                	jbe    6edb <sys_alloc+0xde>
    6ec7:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6ece:	48 8b 80 68 03 00 00 	mov    0x368(%rax),%rax
    6ed5:	48 39 45 90          	cmp    %rax,-0x70(%rbp)
    6ed9:	76 0a                	jbe    6ee5 <sys_alloc+0xe8>
      return 0;
    6edb:	b8 00 00 00 00       	mov    $0x0,%eax
    6ee0:	e9 f2 08 00 00       	jmpq   77d7 <sys_alloc+0x9da>
   we can malloc nb bytes upon success, so pad with enough space for
   top_foot, plus alignment-pad to make sure we don't lose bytes if
   not on boundary, and round this up to a granularity unit.
  */

  if (MORECORE_CONTIGUOUS && !use_noncontiguous(m)) {
    6ee5:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6eec:	8b 80 70 03 00 00    	mov    0x370(%rax),%eax
    6ef2:	83 e0 04             	and    $0x4,%eax
    6ef5:	85 c0                	test   %eax,%eax
    6ef7:	0f 85 37 03 00 00    	jne    7234 <sys_alloc+0x437>
    char* br = CMFAIL;
    6efd:	48 c7 85 70 ff ff ff 	movq   $0xffffffffffffffff,-0x90(%rbp)
    6f04:	ff ff ff ff 
    size_t ssize = asize; /* sbrk call size */
    6f08:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    6f0c:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
    msegmentptr ss = (m->top == 0)? 0 : segment_holding(m, (char*)m->top);
    6f13:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6f1a:	48 8b 40 28          	mov    0x28(%rax),%rax
    6f1e:	48 85 c0             	test   %rax,%rax
    6f21:	74 1f                	je     6f42 <sys_alloc+0x145>
    6f23:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6f2a:	48 8b 50 28          	mov    0x28(%rax),%rdx
    6f2e:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6f35:	48 89 d6             	mov    %rdx,%rsi
    6f38:	48 89 c7             	mov    %rax,%rdi
    6f3b:	e8 f4 e3 ff ff       	callq  5334 <segment_holding>
    6f40:	eb 05                	jmp    6f47 <sys_alloc+0x14a>
    6f42:	b8 00 00 00 00       	mov    $0x0,%eax
    6f47:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    ACQUIRE_MALLOC_GLOBAL_LOCK();
    6f4b:	b8 01 00 00 00       	mov    $0x1,%eax
    6f50:	87 05 aa a1 00 00    	xchg   %eax,0xa1aa(%rip)        # 11100 <malloc_global_mutex>
    6f56:	85 c0                	test   %eax,%eax
    6f58:	74 0c                	je     6f66 <sys_alloc+0x169>
    6f5a:	48 8d 3d 9f a1 00 00 	lea    0xa19f(%rip),%rdi        # 11100 <malloc_global_mutex>
    6f61:	e8 99 e3 ff ff       	callq  52ff <spin_acquire_lock>

    if (ss == 0) {  /* First time through or recovery */
    6f66:	48 83 7d 98 00       	cmpq   $0x0,-0x68(%rbp)
    6f6b:	0f 85 2f 01 00 00    	jne    70a0 <sys_alloc+0x2a3>
      char* base = (char*)CALL_MORECORE(0);
    6f71:	bf 00 00 00 00       	mov    $0x0,%edi
    6f76:	e8 83 41 00 00       	callq  b0fe <sbrk>
    6f7b:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
      if (base != CMFAIL) {
    6f7f:	48 83 7d a0 ff       	cmpq   $0xffffffffffffffff,-0x60(%rbp)
    6f84:	0f 84 ad 01 00 00    	je     7137 <sys_alloc+0x33a>
        size_t fp;
        /* Adjust to end on a page boundary */
        if (!is_page_aligned(base))
    6f8a:	48 8b 05 97 a1 00 00 	mov    0xa197(%rip),%rax        # 11128 <mparams+0x8>
    6f91:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    6f95:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    6f99:	48 21 d0             	and    %rdx,%rax
    6f9c:	48 85 c0             	test   %rax,%rax
    6f9f:	74 30                	je     6fd1 <sys_alloc+0x1d4>
          ssize += (page_align((size_t)base) - (size_t)base);
    6fa1:	48 8b 15 80 a1 00 00 	mov    0xa180(%rip),%rdx        # 11128 <mparams+0x8>
    6fa8:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    6fac:	48 01 d0             	add    %rdx,%rax
    6faf:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    6fb3:	48 8b 05 6e a1 00 00 	mov    0xa16e(%rip),%rax        # 11128 <mparams+0x8>
    6fba:	48 f7 d8             	neg    %rax
    6fbd:	48 21 c2             	and    %rax,%rdx
    6fc0:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    6fc4:	48 29 c2             	sub    %rax,%rdx
    6fc7:	48 89 d0             	mov    %rdx,%rax
    6fca:	48 01 85 78 ff ff ff 	add    %rax,-0x88(%rbp)
        fp = m->footprint + ssize; /* recheck limits */
    6fd1:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    6fd8:	48 8b 90 58 03 00 00 	mov    0x358(%rax),%rdx
    6fdf:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    6fe6:	48 01 d0             	add    %rdx,%rax
    6fe9:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
        if (ssize > nb && ssize < HALF_MAX_SIZE_T &&
    6fed:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    6ff4:	48 3b 85 40 ff ff ff 	cmp    -0xc0(%rbp),%rax
    6ffb:	0f 86 36 01 00 00    	jbe    7137 <sys_alloc+0x33a>
    7001:	48 b8 fe ff ff ff ff 	movabs $0x7ffffffffffffffe,%rax
    7008:	ff ff 7f 
    700b:	48 39 85 78 ff ff ff 	cmp    %rax,-0x88(%rbp)
    7012:	0f 87 1f 01 00 00    	ja     7137 <sys_alloc+0x33a>
            (m->footprint_limit == 0 ||
    7018:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    701f:	48 8b 80 68 03 00 00 	mov    0x368(%rax),%rax
        if (ssize > nb && ssize < HALF_MAX_SIZE_T &&
    7026:	48 85 c0             	test   %rax,%rax
    7029:	74 30                	je     705b <sys_alloc+0x25e>
             (fp > m->footprint && fp <= m->footprint_limit)) &&
    702b:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7032:	48 8b 80 58 03 00 00 	mov    0x358(%rax),%rax
            (m->footprint_limit == 0 ||
    7039:	48 39 45 a8          	cmp    %rax,-0x58(%rbp)
    703d:	0f 86 f4 00 00 00    	jbe    7137 <sys_alloc+0x33a>
             (fp > m->footprint && fp <= m->footprint_limit)) &&
    7043:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    704a:	48 8b 80 68 03 00 00 	mov    0x368(%rax),%rax
    7051:	48 39 45 a8          	cmp    %rax,-0x58(%rbp)
    7055:	0f 87 dc 00 00 00    	ja     7137 <sys_alloc+0x33a>
            (br = (char*)(CALL_MORECORE(ssize))) == base) {
    705b:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
             (fp > m->footprint && fp <= m->footprint_limit)) &&
    7062:	48 89 c7             	mov    %rax,%rdi
    7065:	e8 94 40 00 00       	callq  b0fe <sbrk>
    706a:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
    7071:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    7078:	48 3b 45 a0          	cmp    -0x60(%rbp),%rax
    707c:	0f 85 b5 00 00 00    	jne    7137 <sys_alloc+0x33a>
          tbase = base;
    7082:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    7086:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
          tsize = ssize;
    708d:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    7094:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
    709b:	e9 97 00 00 00       	jmpq   7137 <sys_alloc+0x33a>
        }
      }
    }
    else {
      /* Subtract out existing available top space from MORECORE request. */
      ssize = granularity_align(nb - m->topsize + SYS_ALLOC_PADDING);
    70a0:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    70a7:	48 8b 40 10          	mov    0x10(%rax),%rax
    70ab:	48 8b 95 40 ff ff ff 	mov    -0xc0(%rbp),%rdx
    70b2:	48 29 c2             	sub    %rax,%rdx
    70b5:	48 8b 05 74 a0 00 00 	mov    0xa074(%rip),%rax        # 11130 <mparams+0x10>
    70bc:	48 01 d0             	add    %rdx,%rax
    70bf:	48 8d 50 5f          	lea    0x5f(%rax),%rdx
    70c3:	48 8b 05 66 a0 00 00 	mov    0xa066(%rip),%rax        # 11130 <mparams+0x10>
    70ca:	48 f7 d8             	neg    %rax
    70cd:	48 21 d0             	and    %rdx,%rax
    70d0:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
      /* Use mem here only if it did continuously extend old space */
      if (ssize < HALF_MAX_SIZE_T &&
    70d7:	48 b8 fe ff ff ff ff 	movabs $0x7ffffffffffffffe,%rax
    70de:	ff ff 7f 
    70e1:	48 39 85 78 ff ff ff 	cmp    %rax,-0x88(%rbp)
    70e8:	77 4d                	ja     7137 <sys_alloc+0x33a>
          (br = (char*)(CALL_MORECORE(ssize))) == ss->base+ss->size) {
    70ea:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
      if (ssize < HALF_MAX_SIZE_T &&
    70f1:	48 89 c7             	mov    %rax,%rdi
    70f4:	e8 05 40 00 00       	callq  b0fe <sbrk>
    70f9:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
          (br = (char*)(CALL_MORECORE(ssize))) == ss->base+ss->size) {
    7100:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    7104:	48 8b 10             	mov    (%rax),%rdx
    7107:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    710b:	48 8b 40 08          	mov    0x8(%rax),%rax
    710f:	48 01 d0             	add    %rdx,%rax
      if (ssize < HALF_MAX_SIZE_T &&
    7112:	48 39 85 70 ff ff ff 	cmp    %rax,-0x90(%rbp)
    7119:	75 1c                	jne    7137 <sys_alloc+0x33a>
        tbase = br;
    711b:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    7122:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
        tsize = ssize;
    7129:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    7130:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
      }
    }

    if (tbase == CMFAIL) {    /* Cope with partial failure */
    7137:	48 83 bd 60 ff ff ff 	cmpq   $0xffffffffffffffff,-0xa0(%rbp)
    713e:	ff 
    713f:	0f 85 e4 00 00 00    	jne    7229 <sys_alloc+0x42c>
      if (br != CMFAIL) {    /* Try to use/extend the space we did get */
    7145:	48 83 bd 70 ff ff ff 	cmpq   $0xffffffffffffffff,-0x90(%rbp)
    714c:	ff 
    714d:	0f 84 b0 00 00 00    	je     7203 <sys_alloc+0x406>
        if (ssize < HALF_MAX_SIZE_T &&
    7153:	48 b8 fe ff ff ff ff 	movabs $0x7ffffffffffffffe,%rax
    715a:	ff ff 7f 
    715d:	48 39 85 78 ff ff ff 	cmp    %rax,-0x88(%rbp)
    7164:	0f 87 99 00 00 00    	ja     7203 <sys_alloc+0x406>
            ssize < nb + SYS_ALLOC_PADDING) {
    716a:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    7171:	48 83 c0 60          	add    $0x60,%rax
        if (ssize < HALF_MAX_SIZE_T &&
    7175:	48 39 85 78 ff ff ff 	cmp    %rax,-0x88(%rbp)
    717c:	0f 83 81 00 00 00    	jae    7203 <sys_alloc+0x406>
          size_t esize = granularity_align(nb + SYS_ALLOC_PADDING - ssize);
    7182:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    7189:	48 2b 85 78 ff ff ff 	sub    -0x88(%rbp),%rax
    7190:	48 89 c2             	mov    %rax,%rdx
    7193:	48 8b 05 96 9f 00 00 	mov    0x9f96(%rip),%rax        # 11130 <mparams+0x10>
    719a:	48 01 d0             	add    %rdx,%rax
    719d:	48 8d 50 5f          	lea    0x5f(%rax),%rdx
    71a1:	48 8b 05 88 9f 00 00 	mov    0x9f88(%rip),%rax        # 11130 <mparams+0x10>
    71a8:	48 f7 d8             	neg    %rax
    71ab:	48 21 d0             	and    %rdx,%rax
    71ae:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
          if (esize < HALF_MAX_SIZE_T) {
    71b2:	48 b8 fe ff ff ff ff 	movabs $0x7ffffffffffffffe,%rax
    71b9:	ff ff 7f 
    71bc:	48 39 45 b0          	cmp    %rax,-0x50(%rbp)
    71c0:	77 41                	ja     7203 <sys_alloc+0x406>
            char* end = (char*)CALL_MORECORE(esize);
    71c2:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    71c6:	48 89 c7             	mov    %rax,%rdi
    71c9:	e8 30 3f 00 00       	callq  b0fe <sbrk>
    71ce:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
            if (end != CMFAIL)
    71d2:	48 83 7d b8 ff       	cmpq   $0xffffffffffffffff,-0x48(%rbp)
    71d7:	74 0d                	je     71e6 <sys_alloc+0x3e9>
              ssize += esize;
    71d9:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    71dd:	48 01 85 78 ff ff ff 	add    %rax,-0x88(%rbp)
    71e4:	eb 1d                	jmp    7203 <sys_alloc+0x406>
            else {            /* Can't use; try to release */
              (void) CALL_MORECORE(-ssize);
    71e6:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    71ed:	48 f7 d8             	neg    %rax
    71f0:	48 89 c7             	mov    %rax,%rdi
    71f3:	e8 06 3f 00 00       	callq  b0fe <sbrk>
              br = CMFAIL;
    71f8:	48 c7 85 70 ff ff ff 	movq   $0xffffffffffffffff,-0x90(%rbp)
    71ff:	ff ff ff ff 
            }
          }
        }
      }
      if (br != CMFAIL) {    /* Use the space we did get */
    7203:	48 83 bd 70 ff ff ff 	cmpq   $0xffffffffffffffff,-0x90(%rbp)
    720a:	ff 
    720b:	74 1c                	je     7229 <sys_alloc+0x42c>
        tbase = br;
    720d:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    7214:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
        tsize = ssize;
    721b:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    7222:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
      else
        disable_contiguous(m); /* Don't try contiguous path in the future */
#endif
    }

    RELEASE_MALLOC_GLOBAL_LOCK();
    7229:	b8 00 00 00 00       	mov    $0x0,%eax
    722e:	89 05 cc 9e 00 00    	mov    %eax,0x9ecc(%rip)        # 11100 <malloc_global_mutex>
      tsize = asize;
      mmap_flag = USE_MMAP_BIT;
    }
  }

  if (HAVE_MORECORE && tbase == CMFAIL) { /* Try noncontiguous MORECORE */
    7234:	48 83 bd 60 ff ff ff 	cmpq   $0xffffffffffffffff,-0xa0(%rbp)
    723b:	ff 
    723c:	0f 85 b9 00 00 00    	jne    72fb <sys_alloc+0x4fe>
    if (asize < HALF_MAX_SIZE_T) {
    7242:	48 b8 fe ff ff ff ff 	movabs $0x7ffffffffffffffe,%rax
    7249:	ff ff 7f 
    724c:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    7250:	0f 87 a5 00 00 00    	ja     72fb <sys_alloc+0x4fe>
      char* br = CMFAIL;
    7256:	48 c7 45 c0 ff ff ff 	movq   $0xffffffffffffffff,-0x40(%rbp)
    725d:	ff 
      char* end = CMFAIL;
    725e:	48 c7 45 c8 ff ff ff 	movq   $0xffffffffffffffff,-0x38(%rbp)
    7265:	ff 
      ACQUIRE_MALLOC_GLOBAL_LOCK();
    7266:	b8 01 00 00 00       	mov    $0x1,%eax
    726b:	87 05 8f 9e 00 00    	xchg   %eax,0x9e8f(%rip)        # 11100 <malloc_global_mutex>
    7271:	85 c0                	test   %eax,%eax
    7273:	74 0c                	je     7281 <sys_alloc+0x484>
    7275:	48 8d 3d 84 9e 00 00 	lea    0x9e84(%rip),%rdi        # 11100 <malloc_global_mutex>
    727c:	e8 7e e0 ff ff       	callq  52ff <spin_acquire_lock>
      br = (char*)(CALL_MORECORE(asize));
    7281:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    7285:	48 89 c7             	mov    %rax,%rdi
    7288:	e8 71 3e 00 00       	callq  b0fe <sbrk>
    728d:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
      end = (char*)(CALL_MORECORE(0));
    7291:	bf 00 00 00 00       	mov    $0x0,%edi
    7296:	e8 63 3e 00 00       	callq  b0fe <sbrk>
    729b:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
      RELEASE_MALLOC_GLOBAL_LOCK();
    729f:	b8 00 00 00 00       	mov    $0x0,%eax
    72a4:	89 05 56 9e 00 00    	mov    %eax,0x9e56(%rip)        # 11100 <malloc_global_mutex>
      if (br != CMFAIL && end != CMFAIL && br < end) {
    72aa:	48 83 7d c0 ff       	cmpq   $0xffffffffffffffff,-0x40(%rbp)
    72af:	74 4a                	je     72fb <sys_alloc+0x4fe>
    72b1:	48 83 7d c8 ff       	cmpq   $0xffffffffffffffff,-0x38(%rbp)
    72b6:	74 43                	je     72fb <sys_alloc+0x4fe>
    72b8:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    72bc:	48 3b 45 c8          	cmp    -0x38(%rbp),%rax
    72c0:	73 39                	jae    72fb <sys_alloc+0x4fe>
        size_t ssize = end - br;
    72c2:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    72c6:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    72ca:	48 29 c2             	sub    %rax,%rdx
    72cd:	48 89 d0             	mov    %rdx,%rax
    72d0:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
        if (ssize > nb + TOP_FOOT_SIZE) {
    72d4:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    72db:	48 83 c0 50          	add    $0x50,%rax
    72df:	48 39 45 d0          	cmp    %rax,-0x30(%rbp)
    72e3:	76 16                	jbe    72fb <sys_alloc+0x4fe>
          tbase = br;
    72e5:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    72e9:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
          tsize = ssize;
    72f0:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    72f4:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
        }
      }
    }
  }

  if (tbase != CMFAIL) {
    72fb:	48 83 bd 60 ff ff ff 	cmpq   $0xffffffffffffffff,-0xa0(%rbp)
    7302:	ff 
    7303:	0f 84 be 04 00 00    	je     77c7 <sys_alloc+0x9ca>

    if ((m->footprint += tsize) > m->max_footprint)
    7309:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7310:	48 8b 90 58 03 00 00 	mov    0x358(%rax),%rdx
    7317:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    731e:	48 01 c2             	add    %rax,%rdx
    7321:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7328:	48 89 90 58 03 00 00 	mov    %rdx,0x358(%rax)
    732f:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7336:	48 8b 90 58 03 00 00 	mov    0x358(%rax),%rdx
    733d:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7344:	48 8b 80 60 03 00 00 	mov    0x360(%rax),%rax
    734b:	48 39 c2             	cmp    %rax,%rdx
    734e:	76 1c                	jbe    736c <sys_alloc+0x56f>
      m->max_footprint = m->footprint;
    7350:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7357:	48 8b 90 58 03 00 00 	mov    0x358(%rax),%rdx
    735e:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7365:	48 89 90 60 03 00 00 	mov    %rdx,0x360(%rax)

    if (!is_initialized(m)) { /* first-time initialization */
    736c:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7373:	48 8b 40 28          	mov    0x28(%rax),%rax
    7377:	48 85 c0             	test   %rax,%rax
    737a:	0f 85 3e 01 00 00    	jne    74be <sys_alloc+0x6c1>
      if (m->least_addr == 0 || tbase < m->least_addr)
    7380:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7387:	48 8b 40 18          	mov    0x18(%rax),%rax
    738b:	48 85 c0             	test   %rax,%rax
    738e:	74 14                	je     73a4 <sys_alloc+0x5a7>
    7390:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7397:	48 8b 40 18          	mov    0x18(%rax),%rax
    739b:	48 39 85 60 ff ff ff 	cmp    %rax,-0xa0(%rbp)
    73a2:	73 12                	jae    73b6 <sys_alloc+0x5b9>
        m->least_addr = tbase;
    73a4:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    73ab:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    73b2:	48 89 50 18          	mov    %rdx,0x18(%rax)
      m->seg.base = tbase;
    73b6:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    73bd:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    73c4:	48 89 90 78 03 00 00 	mov    %rdx,0x378(%rax)
      m->seg.size = tsize;
    73cb:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    73d2:	48 8b 95 68 ff ff ff 	mov    -0x98(%rbp),%rdx
    73d9:	48 89 90 80 03 00 00 	mov    %rdx,0x380(%rax)
      m->seg.sflags = mmap_flag;
    73e0:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    73e7:	8b 95 5c ff ff ff    	mov    -0xa4(%rbp),%edx
    73ed:	89 90 90 03 00 00    	mov    %edx,0x390(%rax)
      m->magic = mparams.magic;
    73f3:	48 8b 15 26 9d 00 00 	mov    0x9d26(%rip),%rdx        # 11120 <mparams>
    73fa:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7401:	48 89 50 40          	mov    %rdx,0x40(%rax)
      m->release_checks = MAX_RELEASE_CHECK_RATE;
    7405:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    740c:	48 c7 40 38 ff ff ff 	movq   $0xffffffffffffffff,0x38(%rax)
    7413:	ff 
      init_bins(m);
    7414:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    741b:	48 89 c7             	mov    %rax,%rdi
    741e:	e8 b8 e5 ff ff       	callq  59db <init_bins>
#if !ONLY_MSPACES
      if (is_global(m))
    7423:	48 8d 05 36 9d 00 00 	lea    0x9d36(%rip),%rax        # 11160 <_gm_>
    742a:	48 39 85 48 ff ff ff 	cmp    %rax,-0xb8(%rbp)
    7431:	75 29                	jne    745c <sys_alloc+0x65f>
        init_top(m, (mchunkptr)tbase, tsize - TOP_FOOT_SIZE);
    7433:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    743a:	48 8d 50 b0          	lea    -0x50(%rax),%rdx
    743e:	48 8b 8d 60 ff ff ff 	mov    -0xa0(%rbp),%rcx
    7445:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    744c:	48 89 ce             	mov    %rcx,%rsi
    744f:	48 89 c7             	mov    %rax,%rdi
    7452:	e8 eb e4 ff ff       	callq  5942 <init_top>
    7457:	e9 5a 02 00 00       	jmpq   76b6 <sys_alloc+0x8b9>
      else
#endif
      {
        /* Offset top by embedded malloc_state */
        mchunkptr mn = next_chunk(mem2chunk(m));
    745c:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7463:	48 83 e8 10          	sub    $0x10,%rax
    7467:	48 8b 40 08          	mov    0x8(%rax),%rax
    746b:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    746f:	48 8d 50 f0          	lea    -0x10(%rax),%rdx
    7473:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    747a:	48 01 d0             	add    %rdx,%rax
    747d:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
        init_top(m, mn, (size_t)((tbase + tsize) - (char*)mn) -TOP_FOOT_SIZE);
    7481:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    7488:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    748f:	48 01 d0             	add    %rdx,%rax
    7492:	48 89 c2             	mov    %rax,%rdx
    7495:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    7499:	48 29 c2             	sub    %rax,%rdx
    749c:	48 89 d0             	mov    %rdx,%rax
    749f:	48 8d 50 b0          	lea    -0x50(%rax),%rdx
    74a3:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    74a7:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    74ae:	48 89 ce             	mov    %rcx,%rsi
    74b1:	48 89 c7             	mov    %rax,%rdi
    74b4:	e8 89 e4 ff ff       	callq  5942 <init_top>
    74b9:	e9 f8 01 00 00       	jmpq   76b6 <sys_alloc+0x8b9>
      }
    }

    else {
      /* Try to merge with an existing segment */
      msegmentptr sp = &m->seg;
    74be:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    74c5:	48 05 78 03 00 00    	add    $0x378,%rax
    74cb:	48 89 45 80          	mov    %rax,-0x80(%rbp)
      /* Only consider most recent segment if traversal suppressed */
      while (sp != 0 && tbase != sp->base + sp->size)
    74cf:	eb 0c                	jmp    74dd <sys_alloc+0x6e0>
        sp = (NO_SEGMENT_TRAVERSAL) ? 0 : sp->next;
    74d1:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    74d5:	48 8b 40 10          	mov    0x10(%rax),%rax
    74d9:	48 89 45 80          	mov    %rax,-0x80(%rbp)
      while (sp != 0 && tbase != sp->base + sp->size)
    74dd:	48 83 7d 80 00       	cmpq   $0x0,-0x80(%rbp)
    74e2:	74 1b                	je     74ff <sys_alloc+0x702>
    74e4:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    74e8:	48 8b 10             	mov    (%rax),%rdx
    74eb:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    74ef:	48 8b 40 08          	mov    0x8(%rax),%rax
    74f3:	48 01 d0             	add    %rdx,%rax
    74f6:	48 39 85 60 ff ff ff 	cmp    %rax,-0xa0(%rbp)
    74fd:	75 d2                	jne    74d1 <sys_alloc+0x6d4>
      if (sp != 0 &&
    74ff:	48 83 7d 80 00       	cmpq   $0x0,-0x80(%rbp)
    7504:	0f 84 a9 00 00 00    	je     75b3 <sys_alloc+0x7b6>
          !is_extern_segment(sp) &&
    750a:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    750e:	8b 40 18             	mov    0x18(%rax),%eax
    7511:	83 e0 08             	and    $0x8,%eax
      if (sp != 0 &&
    7514:	85 c0                	test   %eax,%eax
    7516:	0f 85 97 00 00 00    	jne    75b3 <sys_alloc+0x7b6>
          !is_extern_segment(sp) &&
    751c:	83 bd 5c ff ff ff 00 	cmpl   $0x0,-0xa4(%rbp)
    7523:	0f 85 8a 00 00 00    	jne    75b3 <sys_alloc+0x7b6>
          (sp->sflags & USE_MMAP_BIT) == mmap_flag &&
          segment_holds(sp, m->top)) { /* append */
    7529:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7530:	48 8b 50 28          	mov    0x28(%rax),%rdx
    7534:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    7538:	48 8b 00             	mov    (%rax),%rax
          (sp->sflags & USE_MMAP_BIT) == mmap_flag &&
    753b:	48 39 c2             	cmp    %rax,%rdx
    753e:	72 73                	jb     75b3 <sys_alloc+0x7b6>
          segment_holds(sp, m->top)) { /* append */
    7540:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7547:	48 8b 50 28          	mov    0x28(%rax),%rdx
    754b:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    754f:	48 8b 08             	mov    (%rax),%rcx
    7552:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    7556:	48 8b 40 08          	mov    0x8(%rax),%rax
    755a:	48 01 c8             	add    %rcx,%rax
    755d:	48 39 c2             	cmp    %rax,%rdx
    7560:	73 51                	jae    75b3 <sys_alloc+0x7b6>
        sp->size += tsize;
    7562:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    7566:	48 8b 50 08          	mov    0x8(%rax),%rdx
    756a:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    7571:	48 01 c2             	add    %rax,%rdx
    7574:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    7578:	48 89 50 08          	mov    %rdx,0x8(%rax)
        init_top(m, m->top, m->topsize + tsize);
    757c:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7583:	48 8b 50 10          	mov    0x10(%rax),%rdx
    7587:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    758e:	48 01 c2             	add    %rax,%rdx
    7591:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7598:	48 8b 48 28          	mov    0x28(%rax),%rcx
    759c:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    75a3:	48 89 ce             	mov    %rcx,%rsi
    75a6:	48 89 c7             	mov    %rax,%rdi
    75a9:	e8 94 e3 ff ff       	callq  5942 <init_top>
    75ae:	e9 03 01 00 00       	jmpq   76b6 <sys_alloc+0x8b9>
      }
      else {
        if (tbase < m->least_addr)
    75b3:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    75ba:	48 8b 40 18          	mov    0x18(%rax),%rax
    75be:	48 39 85 60 ff ff ff 	cmp    %rax,-0xa0(%rbp)
    75c5:	73 12                	jae    75d9 <sys_alloc+0x7dc>
          m->least_addr = tbase;
    75c7:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    75ce:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    75d5:	48 89 50 18          	mov    %rdx,0x18(%rax)
        sp = &m->seg;
    75d9:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    75e0:	48 05 78 03 00 00    	add    $0x378,%rax
    75e6:	48 89 45 80          	mov    %rax,-0x80(%rbp)
        while (sp != 0 && sp->base != tbase + tsize)
    75ea:	eb 0c                	jmp    75f8 <sys_alloc+0x7fb>
          sp = (NO_SEGMENT_TRAVERSAL) ? 0 : sp->next;
    75ec:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    75f0:	48 8b 40 10          	mov    0x10(%rax),%rax
    75f4:	48 89 45 80          	mov    %rax,-0x80(%rbp)
        while (sp != 0 && sp->base != tbase + tsize)
    75f8:	48 83 7d 80 00       	cmpq   $0x0,-0x80(%rbp)
    75fd:	74 1d                	je     761c <sys_alloc+0x81f>
    75ff:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    7603:	48 8b 00             	mov    (%rax),%rax
    7606:	48 8b 8d 60 ff ff ff 	mov    -0xa0(%rbp),%rcx
    760d:	48 8b 95 68 ff ff ff 	mov    -0x98(%rbp),%rdx
    7614:	48 01 ca             	add    %rcx,%rdx
    7617:	48 39 d0             	cmp    %rdx,%rax
    761a:	75 d0                	jne    75ec <sys_alloc+0x7ef>
        if (sp != 0 &&
    761c:	48 83 7d 80 00       	cmpq   $0x0,-0x80(%rbp)
    7621:	74 70                	je     7693 <sys_alloc+0x896>
            !is_extern_segment(sp) &&
    7623:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    7627:	8b 40 18             	mov    0x18(%rax),%eax
    762a:	83 e0 08             	and    $0x8,%eax
        if (sp != 0 &&
    762d:	85 c0                	test   %eax,%eax
    762f:	75 62                	jne    7693 <sys_alloc+0x896>
            !is_extern_segment(sp) &&
    7631:	83 bd 5c ff ff ff 00 	cmpl   $0x0,-0xa4(%rbp)
    7638:	75 59                	jne    7693 <sys_alloc+0x896>
            (sp->sflags & USE_MMAP_BIT) == mmap_flag) {
          char* oldbase = sp->base;
    763a:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    763e:	48 8b 00             	mov    (%rax),%rax
    7641:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
          sp->base = tbase;
    7645:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    7649:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    7650:	48 89 10             	mov    %rdx,(%rax)
          sp->size += tsize;
    7653:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    7657:	48 8b 50 08          	mov    0x8(%rax),%rdx
    765b:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    7662:	48 01 c2             	add    %rax,%rdx
    7665:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    7669:	48 89 50 08          	mov    %rdx,0x8(%rax)
          return prepend_alloc(m, tbase, oldbase, nb);
    766d:	48 8b 8d 40 ff ff ff 	mov    -0xc0(%rbp),%rcx
    7674:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    7678:	48 8b b5 60 ff ff ff 	mov    -0xa0(%rbp),%rsi
    767f:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7686:	48 89 c7             	mov    %rax,%rdi
    7689:	e8 a9 e3 ff ff       	callq  5a37 <prepend_alloc>
    768e:	e9 44 01 00 00       	jmpq   77d7 <sys_alloc+0x9da>
        }
        else
          add_segment(m, tbase, tsize, mmap_flag);
    7693:	8b 8d 5c ff ff ff    	mov    -0xa4(%rbp),%ecx
    7699:	48 8b 95 68 ff ff ff 	mov    -0x98(%rbp),%rdx
    76a0:	48 8b b5 60 ff ff ff 	mov    -0xa0(%rbp),%rsi
    76a7:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    76ae:	48 89 c7             	mov    %rax,%rdi
    76b1:	e8 37 f0 ff ff       	callq  66ed <add_segment>
      }
    }

    if (nb < m->topsize) { /* Allocate from new or extended top space */
    76b6:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    76bd:	48 8b 40 10          	mov    0x10(%rax),%rax
    76c1:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    76c8:	0f 83 f9 00 00 00    	jae    77c7 <sys_alloc+0x9ca>
      size_t rsize = m->topsize -= nb;
    76ce:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    76d5:	48 8b 40 10          	mov    0x10(%rax),%rax
    76d9:	48 2b 85 40 ff ff ff 	sub    -0xc0(%rbp),%rax
    76e0:	48 89 c2             	mov    %rax,%rdx
    76e3:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    76ea:	48 89 50 10          	mov    %rdx,0x10(%rax)
    76ee:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    76f5:	48 8b 40 10          	mov    0x10(%rax),%rax
    76f9:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
      mchunkptr p = m->top;
    76fd:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7704:	48 8b 40 28          	mov    0x28(%rax),%rax
    7708:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
      mchunkptr r = m->top = chunk_plus_offset(p, nb);
    770c:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    7710:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    7717:	48 01 c2             	add    %rax,%rdx
    771a:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7721:	48 89 50 28          	mov    %rdx,0x28(%rax)
    7725:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    772c:	48 8b 40 28          	mov    0x28(%rax),%rax
    7730:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
      r->head = rsize | PINUSE_BIT;
    7734:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    7738:	48 83 c8 01          	or     $0x1,%rax
    773c:	48 89 c2             	mov    %rax,%rdx
    773f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    7743:	48 89 50 08          	mov    %rdx,0x8(%rax)
      set_size_and_pinuse_of_inuse_chunk(m, p, nb);
    7747:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    774e:	48 83 c8 03          	or     $0x3,%rax
    7752:	48 89 c2             	mov    %rax,%rdx
    7755:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    7759:	48 89 50 08          	mov    %rdx,0x8(%rax)
    775d:	48 8b 0d bc 99 00 00 	mov    0x99bc(%rip),%rcx        # 11120 <mparams>
    7764:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    776b:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi
    776f:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    7776:	48 01 f0             	add    %rsi,%rax
    7779:	48 31 ca             	xor    %rcx,%rdx
    777c:	48 89 10             	mov    %rdx,(%rax)
      check_top_chunk(m, m->top);
    777f:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7786:	48 8b 50 28          	mov    0x28(%rax),%rdx
    778a:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7791:	48 89 d6             	mov    %rdx,%rsi
    7794:	48 89 c7             	mov    %rax,%rdi
    7797:	e8 79 dd ff ff       	callq  5515 <do_check_top_chunk>
      check_malloced_chunk(m, chunk2mem(p), nb);
    779c:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    77a0:	48 8d 48 10          	lea    0x10(%rax),%rcx
    77a4:	48 8b 95 40 ff ff ff 	mov    -0xc0(%rbp),%rdx
    77ab:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    77b2:	48 89 ce             	mov    %rcx,%rsi
    77b5:	48 89 c7             	mov    %rax,%rdi
    77b8:	e8 e9 e0 ff ff       	callq  58a6 <do_check_malloced_chunk>
      return chunk2mem(p);
    77bd:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    77c1:	48 83 c0 10          	add    $0x10,%rax
    77c5:	eb 10                	jmp    77d7 <sys_alloc+0x9da>
    }
  }

  MALLOC_FAILURE_ACTION;
    77c7:	e8 78 3e 00 00       	callq  b644 <__errno>
    77cc:	c7 00 0c 00 00 00    	movl   $0xc,(%rax)
  return 0;
    77d2:	b8 00 00 00 00       	mov    $0x0,%eax
}
    77d7:	c9                   	leaveq 
    77d8:	c3                   	retq   

00000000000077d9 <release_unused_segments>:

/* -----------------------  system deallocation -------------------------- */

/* Unmap and unlink any mmapped segments that don't contain used chunks */
static size_t release_unused_segments(mstate m) {
    77d9:	55                   	push   %rbp
    77da:	48 89 e5             	mov    %rsp,%rbp
    77dd:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
  size_t released = 0;
    77e1:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    77e8:	00 
  int nsegs = 0;
    77e9:	c7 45 cc 00 00 00 00 	movl   $0x0,-0x34(%rbp)
  msegmentptr pred = &m->seg;
    77f0:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    77f4:	48 05 78 03 00 00    	add    $0x378,%rax
    77fa:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
  msegmentptr sp = pred->next;
    77fe:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    7802:	48 8b 40 10          	mov    0x10(%rax),%rax
    7806:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
  while (sp != 0) {
    780a:	eb 37                	jmp    7843 <release_unused_segments+0x6a>
    char* base = sp->base;
    780c:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    7810:	48 8b 00             	mov    (%rax),%rax
    7813:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    size_t size = sp->size;
    7817:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    781b:	48 8b 40 08          	mov    0x8(%rax),%rax
    781f:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    msegmentptr next = sp->next;
    7823:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    7827:	48 8b 40 10          	mov    0x10(%rax),%rax
    782b:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    ++nsegs;
    782f:	83 45 cc 01          	addl   $0x1,-0x34(%rbp)
        }
      }
    }
    if (NO_SEGMENT_TRAVERSAL) /* scan only first segment */
      break;
    pred = sp;
    7833:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    7837:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    sp = next;
    783b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    783f:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
  while (sp != 0) {
    7843:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    7848:	75 c2                	jne    780c <release_unused_segments+0x33>
  }
  /* Reset check counter */
  m->release_checks = (((size_t) nsegs > (size_t) MAX_RELEASE_CHECK_RATE)?
    784a:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    784e:	48 c7 40 38 ff ff ff 	movq   $0xffffffffffffffff,0x38(%rax)
    7855:	ff 
                       (size_t) nsegs : (size_t) MAX_RELEASE_CHECK_RATE);
  return released;
    7856:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
}
    785a:	5d                   	pop    %rbp
    785b:	c3                   	retq   

000000000000785c <sys_trim>:

static int sys_trim(mstate m, size_t pad) {
    785c:	55                   	push   %rbp
    785d:	48 89 e5             	mov    %rsp,%rbp
    7860:	48 83 ec 50          	sub    $0x50,%rsp
    7864:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    7868:	48 89 75 b0          	mov    %rsi,-0x50(%rbp)
  size_t released = 0;
    786c:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    7873:	00 
  ensure_initialization();
    7874:	48 8b 05 a5 98 00 00 	mov    0x98a5(%rip),%rax        # 11120 <mparams>
    787b:	48 85 c0             	test   %rax,%rax
    787e:	75 07                	jne    7887 <sys_trim+0x2b>
    7880:	e8 0e db ff ff       	callq  5393 <init_mparams>
    7885:	85 c0                	test   %eax,%eax
    7887:	90                   	nop
  if (pad < MAX_REQUEST && is_initialized(m)) {
    7888:	48 81 7d b0 7f ff ff 	cmpq   $0xffffffffffffff7f,-0x50(%rbp)
    788f:	ff 
    7890:	0f 87 e5 01 00 00    	ja     7a7b <sys_trim+0x21f>
    7896:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    789a:	48 8b 40 28          	mov    0x28(%rax),%rax
    789e:	48 85 c0             	test   %rax,%rax
    78a1:	0f 84 d4 01 00 00    	je     7a7b <sys_trim+0x21f>
    pad += TOP_FOOT_SIZE; /* ensure enough room for segment overhead */
    78a7:	48 83 45 b0 50       	addq   $0x50,-0x50(%rbp)

    if (m->topsize > pad) {
    78ac:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    78b0:	48 8b 40 10          	mov    0x10(%rax),%rax
    78b4:	48 39 45 b0          	cmp    %rax,-0x50(%rbp)
    78b8:	0f 83 95 01 00 00    	jae    7a53 <sys_trim+0x1f7>
      /* Shrink top space in granularity-size units, keeping at least one */
      size_t unit = mparams.granularity;
    78be:	48 8b 05 6b 98 00 00 	mov    0x986b(%rip),%rax        # 11130 <mparams+0x10>
    78c5:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
      size_t extra = ((m->topsize - pad + (unit - SIZE_T_ONE)) / unit -
    78c9:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    78cd:	48 8b 40 10          	mov    0x10(%rax),%rax
    78d1:	48 2b 45 b0          	sub    -0x50(%rbp),%rax
    78d5:	48 89 c2             	mov    %rax,%rdx
    78d8:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    78dc:	48 01 d0             	add    %rdx,%rax
    78df:	48 83 e8 01          	sub    $0x1,%rax
    78e3:	ba 00 00 00 00       	mov    $0x0,%edx
    78e8:	48 f7 75 d8          	divq   -0x28(%rbp)
    78ec:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    78f0:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    78f4:	48 0f af c2          	imul   %rdx,%rax
    78f8:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
                      SIZE_T_ONE) * unit;
      msegmentptr sp = segment_holding(m, (char*)m->top);
    78fc:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    7900:	48 8b 50 28          	mov    0x28(%rax),%rdx
    7904:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    7908:	48 89 d6             	mov    %rdx,%rsi
    790b:	48 89 c7             	mov    %rax,%rdi
    790e:	e8 21 da ff ff       	callq  5334 <segment_holding>
    7913:	48 89 45 e0          	mov    %rax,-0x20(%rbp)

      if (!is_extern_segment(sp)) {
    7917:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    791b:	8b 40 18             	mov    0x18(%rax),%eax
    791e:	83 e0 08             	and    $0x8,%eax
    7921:	85 c0                	test   %eax,%eax
    7923:	0f 85 b2 00 00 00    	jne    79db <sys_trim+0x17f>
              released = extra;
            }
          }
        }
        else if (HAVE_MORECORE) {
          if (extra >= HALF_MAX_SIZE_T) /* Avoid wrapping negative */
    7929:	48 b8 fe ff ff ff ff 	movabs $0x7ffffffffffffffe,%rax
    7930:	ff ff 7f 
    7933:	48 39 45 d0          	cmp    %rax,-0x30(%rbp)
    7937:	76 12                	jbe    794b <sys_trim+0xef>
            extra = (HALF_MAX_SIZE_T) + SIZE_T_ONE - unit;
    7939:	48 b8 00 00 00 00 00 	movabs $0x8000000000000000,%rax
    7940:	00 00 80 
    7943:	48 2b 45 d8          	sub    -0x28(%rbp),%rax
    7947:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
          ACQUIRE_MALLOC_GLOBAL_LOCK();
    794b:	b8 01 00 00 00       	mov    $0x1,%eax
    7950:	87 05 aa 97 00 00    	xchg   %eax,0x97aa(%rip)        # 11100 <malloc_global_mutex>
    7956:	85 c0                	test   %eax,%eax
    7958:	74 0c                	je     7966 <sys_trim+0x10a>
    795a:	48 8d 3d 9f 97 00 00 	lea    0x979f(%rip),%rdi        # 11100 <malloc_global_mutex>
    7961:	e8 99 d9 ff ff       	callq  52ff <spin_acquire_lock>
          {
            /* Make sure end of memory is where we last set it. */
            char* old_br = (char*)(CALL_MORECORE(0));
    7966:	bf 00 00 00 00       	mov    $0x0,%edi
    796b:	e8 8e 37 00 00       	callq  b0fe <sbrk>
    7970:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
            if (old_br == sp->base + sp->size) {
    7974:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    7978:	48 8b 10             	mov    (%rax),%rdx
    797b:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    797f:	48 8b 40 08          	mov    0x8(%rax),%rax
    7983:	48 01 d0             	add    %rdx,%rax
    7986:	48 39 45 e8          	cmp    %rax,-0x18(%rbp)
    798a:	75 44                	jne    79d0 <sys_trim+0x174>
              char* rel_br = (char*)(CALL_MORECORE(-extra));
    798c:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    7990:	48 f7 d8             	neg    %rax
    7993:	48 89 c7             	mov    %rax,%rdi
    7996:	e8 63 37 00 00       	callq  b0fe <sbrk>
    799b:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
              char* new_br = (char*)(CALL_MORECORE(0));
    799f:	bf 00 00 00 00       	mov    $0x0,%edi
    79a4:	e8 55 37 00 00       	callq  b0fe <sbrk>
    79a9:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
              if (rel_br != CMFAIL && new_br < old_br)
    79ad:	48 83 7d f0 ff       	cmpq   $0xffffffffffffffff,-0x10(%rbp)
    79b2:	74 1c                	je     79d0 <sys_trim+0x174>
    79b4:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    79b8:	48 3b 45 e8          	cmp    -0x18(%rbp),%rax
    79bc:	73 12                	jae    79d0 <sys_trim+0x174>
                released = old_br - new_br;
    79be:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    79c2:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    79c6:	48 29 c2             	sub    %rax,%rdx
    79c9:	48 89 d0             	mov    %rdx,%rax
    79cc:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
            }
          }
          RELEASE_MALLOC_GLOBAL_LOCK();
    79d0:	b8 00 00 00 00       	mov    $0x0,%eax
    79d5:	89 05 25 97 00 00    	mov    %eax,0x9725(%rip)        # 11100 <malloc_global_mutex>
        }
      }

      if (released != 0) {
    79db:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    79e0:	74 71                	je     7a53 <sys_trim+0x1f7>
        sp->size -= released;
    79e2:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    79e6:	48 8b 40 08          	mov    0x8(%rax),%rax
    79ea:	48 2b 45 c8          	sub    -0x38(%rbp),%rax
    79ee:	48 89 c2             	mov    %rax,%rdx
    79f1:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    79f5:	48 89 50 08          	mov    %rdx,0x8(%rax)
        m->footprint -= released;
    79f9:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    79fd:	48 8b 80 58 03 00 00 	mov    0x358(%rax),%rax
    7a04:	48 2b 45 c8          	sub    -0x38(%rbp),%rax
    7a08:	48 89 c2             	mov    %rax,%rdx
    7a0b:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    7a0f:	48 89 90 58 03 00 00 	mov    %rdx,0x358(%rax)
        init_top(m, m->top, m->topsize - released);
    7a16:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    7a1a:	48 8b 40 10          	mov    0x10(%rax),%rax
    7a1e:	48 2b 45 c8          	sub    -0x38(%rbp),%rax
    7a22:	48 89 c2             	mov    %rax,%rdx
    7a25:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    7a29:	48 8b 48 28          	mov    0x28(%rax),%rcx
    7a2d:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    7a31:	48 89 ce             	mov    %rcx,%rsi
    7a34:	48 89 c7             	mov    %rax,%rdi
    7a37:	e8 06 df ff ff       	callq  5942 <init_top>
        check_top_chunk(m, m->top);
    7a3c:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    7a40:	48 8b 50 28          	mov    0x28(%rax),%rdx
    7a44:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    7a48:	48 89 d6             	mov    %rdx,%rsi
    7a4b:	48 89 c7             	mov    %rax,%rdi
    7a4e:	e8 c2 da ff ff       	callq  5515 <do_check_top_chunk>
    /* Unmap any unused mmapped segments */
    if (HAVE_MMAP)
      released += release_unused_segments(m);

    /* On failure, disable autotrim to avoid repeated failed future calls */
    if (released == 0 && m->topsize > m->trim_check)
    7a53:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    7a58:	75 21                	jne    7a7b <sys_trim+0x21f>
    7a5a:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    7a5e:	48 8b 50 10          	mov    0x10(%rax),%rdx
    7a62:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    7a66:	48 8b 40 30          	mov    0x30(%rax),%rax
    7a6a:	48 39 c2             	cmp    %rax,%rdx
    7a6d:	76 0c                	jbe    7a7b <sys_trim+0x21f>
      m->trim_check = MAX_SIZE_T;
    7a6f:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    7a73:	48 c7 40 30 ff ff ff 	movq   $0xffffffffffffffff,0x30(%rax)
    7a7a:	ff 
  }

  return (released != 0)? 1 : 0;
    7a7b:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    7a80:	0f 95 c0             	setne  %al
    7a83:	0f b6 c0             	movzbl %al,%eax
}
    7a86:	c9                   	leaveq 
    7a87:	c3                   	retq   

0000000000007a88 <tmalloc_large>:
}

/* ---------------------------- malloc --------------------------- */

/* allocate a large request from the best fitting chunk in a treebin */
static void* tmalloc_large(mstate m, size_t nb) {
    7a88:	55                   	push   %rbp
    7a89:	48 89 e5             	mov    %rsp,%rbp
    7a8c:	48 81 ec 10 01 00 00 	sub    $0x110,%rsp
    7a93:	48 89 bd f8 fe ff ff 	mov    %rdi,-0x108(%rbp)
    7a9a:	48 89 b5 f0 fe ff ff 	mov    %rsi,-0x110(%rbp)
  tchunkptr v = 0;
    7aa1:	48 c7 85 38 ff ff ff 	movq   $0x0,-0xc8(%rbp)
    7aa8:	00 00 00 00 
  size_t rsize = -nb; /* Unsigned negation */
    7aac:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    7ab3:	48 f7 d8             	neg    %rax
    7ab6:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
  tchunkptr t;
  bindex_t idx;
  compute_tree_index(nb, idx);
    7abd:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    7ac4:	48 c1 e8 08          	shr    $0x8,%rax
    7ac8:	89 85 14 ff ff ff    	mov    %eax,-0xec(%rbp)
    7ace:	83 bd 14 ff ff ff 00 	cmpl   $0x0,-0xec(%rbp)
    7ad5:	75 0c                	jne    7ae3 <tmalloc_large+0x5b>
    7ad7:	c7 85 0c ff ff ff 00 	movl   $0x0,-0xf4(%rbp)
    7ade:	00 00 00 
    7ae1:	eb 5d                	jmp    7b40 <tmalloc_large+0xb8>
    7ae3:	81 bd 14 ff ff ff ff 	cmpl   $0xffff,-0xec(%rbp)
    7aea:	ff 00 00 
    7aed:	76 0c                	jbe    7afb <tmalloc_large+0x73>
    7aef:	c7 85 0c ff ff ff 1f 	movl   $0x1f,-0xf4(%rbp)
    7af6:	00 00 00 
    7af9:	eb 45                	jmp    7b40 <tmalloc_large+0xb8>
    7afb:	0f bd 85 14 ff ff ff 	bsr    -0xec(%rbp),%eax
    7b02:	83 f0 1f             	xor    $0x1f,%eax
    7b05:	ba 1f 00 00 00       	mov    $0x1f,%edx
    7b0a:	29 c2                	sub    %eax,%edx
    7b0c:	89 d0                	mov    %edx,%eax
    7b0e:	89 85 18 ff ff ff    	mov    %eax,-0xe8(%rbp)
    7b14:	8b 85 18 ff ff ff    	mov    -0xe8(%rbp),%eax
    7b1a:	8d 34 00             	lea    (%rax,%rax,1),%esi
    7b1d:	8b 85 18 ff ff ff    	mov    -0xe8(%rbp),%eax
    7b23:	83 c0 07             	add    $0x7,%eax
    7b26:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    7b2d:	89 c1                	mov    %eax,%ecx
    7b2f:	48 d3 ea             	shr    %cl,%rdx
    7b32:	48 89 d0             	mov    %rdx,%rax
    7b35:	83 e0 01             	and    $0x1,%eax
    7b38:	01 f0                	add    %esi,%eax
    7b3a:	89 85 0c ff ff ff    	mov    %eax,-0xf4(%rbp)
  if ((t = *treebin_at(m, idx)) != 0) {
    7b40:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    7b47:	8b 95 0c ff ff ff    	mov    -0xf4(%rbp),%edx
    7b4d:	48 83 c2 4a          	add    $0x4a,%rdx
    7b51:	48 8b 44 d0 08       	mov    0x8(%rax,%rdx,8),%rax
    7b56:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    7b5d:	48 83 bd 48 ff ff ff 	cmpq   $0x0,-0xb8(%rbp)
    7b64:	00 
    7b65:	0f 84 05 01 00 00    	je     7c70 <tmalloc_large+0x1e8>
    /* Traverse tree for this bin looking for node with size == nb */
    size_t sizebits = nb << leftshift_for_tree_index(idx);
    7b6b:	83 bd 0c ff ff ff 1f 	cmpl   $0x1f,-0xf4(%rbp)
    7b72:	74 13                	je     7b87 <tmalloc_large+0xff>
    7b74:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    7b7a:	d1 e8                	shr    %eax
    7b7c:	ba 39 00 00 00       	mov    $0x39,%edx
    7b81:	29 c2                	sub    %eax,%edx
    7b83:	89 d0                	mov    %edx,%eax
    7b85:	eb 05                	jmp    7b8c <tmalloc_large+0x104>
    7b87:	b8 00 00 00 00       	mov    $0x0,%eax
    7b8c:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    7b93:	89 c1                	mov    %eax,%ecx
    7b95:	48 d3 e2             	shl    %cl,%rdx
    7b98:	48 89 d0             	mov    %rdx,%rax
    7b9b:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    tchunkptr rst = 0;  /* The deepest untaken right subtree */
    7ba2:	48 c7 85 58 ff ff ff 	movq   $0x0,-0xa8(%rbp)
    7ba9:	00 00 00 00 
    for (;;) {
      tchunkptr rt;
      size_t trem = chunksize(t) - nb;
    7bad:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7bb4:	48 8b 40 08          	mov    0x8(%rax),%rax
    7bb8:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    7bbc:	48 2b 85 f0 fe ff ff 	sub    -0x110(%rbp),%rax
    7bc3:	48 89 45 90          	mov    %rax,-0x70(%rbp)
      if (trem < rsize) {
    7bc7:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    7bcb:	48 3b 85 40 ff ff ff 	cmp    -0xc0(%rbp),%rax
    7bd2:	73 23                	jae    7bf7 <tmalloc_large+0x16f>
        v = t;
    7bd4:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7bdb:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
        if ((rsize = trem) == 0)
    7be2:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    7be6:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
    7bed:	48 83 bd 40 ff ff ff 	cmpq   $0x0,-0xc0(%rbp)
    7bf4:	00 
    7bf5:	74 78                	je     7c6f <tmalloc_large+0x1e7>
          break;
      }
      rt = t->child[1];
    7bf7:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7bfe:	48 8b 40 28          	mov    0x28(%rax),%rax
    7c02:	48 89 45 98          	mov    %rax,-0x68(%rbp)
      t = t->child[(sizebits >> (SIZE_T_BITSIZE-SIZE_T_ONE)) & 1];
    7c06:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    7c0d:	48 c1 e8 3f          	shr    $0x3f,%rax
    7c11:	48 89 c2             	mov    %rax,%rdx
    7c14:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7c1b:	48 83 c2 04          	add    $0x4,%rdx
    7c1f:	48 8b 04 d0          	mov    (%rax,%rdx,8),%rax
    7c23:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
      if (rt != 0 && rt != t)
    7c2a:	48 83 7d 98 00       	cmpq   $0x0,-0x68(%rbp)
    7c2f:	74 18                	je     7c49 <tmalloc_large+0x1c1>
    7c31:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    7c35:	48 3b 85 48 ff ff ff 	cmp    -0xb8(%rbp),%rax
    7c3c:	74 0b                	je     7c49 <tmalloc_large+0x1c1>
        rst = rt;
    7c3e:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    7c42:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
      if (t == 0) {
    7c49:	48 83 bd 48 ff ff ff 	cmpq   $0x0,-0xb8(%rbp)
    7c50:	00 
    7c51:	75 10                	jne    7c63 <tmalloc_large+0x1db>
        t = rst; /* set t to least subtree holding sizes > nb */
    7c53:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    7c5a:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
        break;
    7c61:	eb 0d                	jmp    7c70 <tmalloc_large+0x1e8>
      }
      sizebits <<= 1;
    7c63:	48 d1 a5 50 ff ff ff 	shlq   -0xb0(%rbp)
    for (;;) {
    7c6a:	e9 3e ff ff ff       	jmpq   7bad <tmalloc_large+0x125>
          break;
    7c6f:	90                   	nop
    }
  }
  if (t == 0 && v == 0) { /* set t to root of next non-empty treebin */
    7c70:	48 83 bd 48 ff ff ff 	cmpq   $0x0,-0xb8(%rbp)
    7c77:	00 
    7c78:	0f 85 14 01 00 00    	jne    7d92 <tmalloc_large+0x30a>
    7c7e:	48 83 bd 38 ff ff ff 	cmpq   $0x0,-0xc8(%rbp)
    7c85:	00 
    7c86:	0f 85 06 01 00 00    	jne    7d92 <tmalloc_large+0x30a>
    binmap_t leftbits = left_bits(idx2bit(idx)) & m->treemap;
    7c8c:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    7c92:	ba 01 00 00 00       	mov    $0x1,%edx
    7c97:	89 c1                	mov    %eax,%ecx
    7c99:	d3 e2                	shl    %cl,%edx
    7c9b:	89 d0                	mov    %edx,%eax
    7c9d:	8d 14 00             	lea    (%rax,%rax,1),%edx
    7ca0:	8b 85 0c ff ff ff    	mov    -0xf4(%rbp),%eax
    7ca6:	be 01 00 00 00       	mov    $0x1,%esi
    7cab:	89 c1                	mov    %eax,%ecx
    7cad:	d3 e6                	shl    %cl,%esi
    7caf:	89 f0                	mov    %esi,%eax
    7cb1:	01 c0                	add    %eax,%eax
    7cb3:	f7 d8                	neg    %eax
    7cb5:	09 c2                	or     %eax,%edx
    7cb7:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    7cbe:	8b 40 04             	mov    0x4(%rax),%eax
    7cc1:	21 d0                	and    %edx,%eax
    7cc3:	89 85 1c ff ff ff    	mov    %eax,-0xe4(%rbp)
    if (leftbits != 0) {
    7cc9:	83 bd 1c ff ff ff 00 	cmpl   $0x0,-0xe4(%rbp)
    7cd0:	0f 84 bc 00 00 00    	je     7d92 <tmalloc_large+0x30a>
      bindex_t i;
      binmap_t leastbit = least_bit(leftbits);
    7cd6:	8b 85 1c ff ff ff    	mov    -0xe4(%rbp),%eax
    7cdc:	f7 d8                	neg    %eax
    7cde:	23 85 1c ff ff ff    	and    -0xe4(%rbp),%eax
    7ce4:	89 85 20 ff ff ff    	mov    %eax,-0xe0(%rbp)
      compute_bit2idx(leastbit, i);
    7cea:	f3 0f bc 85 20 ff ff 	tzcnt  -0xe0(%rbp),%eax
    7cf1:	ff 
    7cf2:	89 85 24 ff ff ff    	mov    %eax,-0xdc(%rbp)
    7cf8:	8b 85 24 ff ff ff    	mov    -0xdc(%rbp),%eax
    7cfe:	89 85 28 ff ff ff    	mov    %eax,-0xd8(%rbp)
      t = *treebin_at(m, i);
    7d04:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    7d0b:	8b 95 28 ff ff ff    	mov    -0xd8(%rbp),%edx
    7d11:	48 83 c2 4a          	add    $0x4a,%rdx
    7d15:	48 8b 44 d0 08       	mov    0x8(%rax,%rdx,8),%rax
    7d1a:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    }
  }

  while (t != 0) { /* find smallest of tree or subtree */
    7d21:	eb 6f                	jmp    7d92 <tmalloc_large+0x30a>
    size_t trem = chunksize(t) - nb;
    7d23:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7d2a:	48 8b 40 08          	mov    0x8(%rax),%rax
    7d2e:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    7d32:	48 2b 85 f0 fe ff ff 	sub    -0x110(%rbp),%rax
    7d39:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if (trem < rsize) {
    7d3d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    7d41:	48 3b 85 40 ff ff ff 	cmp    -0xc0(%rbp),%rax
    7d48:	73 19                	jae    7d63 <tmalloc_large+0x2db>
      rsize = trem;
    7d4a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    7d4e:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
      v = t;
    7d55:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7d5c:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
    }
    t = leftmost_child(t);
    7d63:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7d6a:	48 8b 40 20          	mov    0x20(%rax),%rax
    7d6e:	48 85 c0             	test   %rax,%rax
    7d71:	74 0d                	je     7d80 <tmalloc_large+0x2f8>
    7d73:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7d7a:	48 8b 40 20          	mov    0x20(%rax),%rax
    7d7e:	eb 0b                	jmp    7d8b <tmalloc_large+0x303>
    7d80:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    7d87:	48 8b 40 28          	mov    0x28(%rax),%rax
    7d8b:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
  while (t != 0) { /* find smallest of tree or subtree */
    7d92:	48 83 bd 48 ff ff ff 	cmpq   $0x0,-0xb8(%rbp)
    7d99:	00 
    7d9a:	75 87                	jne    7d23 <tmalloc_large+0x29b>
  }

  /*  If dv is a better fit, return 0 so malloc will use it */
  if (v != 0 && rsize < (size_t)(m->dvsize - nb)) {
    7d9c:	48 83 bd 38 ff ff ff 	cmpq   $0x0,-0xc8(%rbp)
    7da3:	00 
    7da4:	0f 84 41 09 00 00    	je     86eb <tmalloc_large+0xc63>
    7daa:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    7db1:	48 8b 40 08          	mov    0x8(%rax),%rax
    7db5:	48 2b 85 f0 fe ff ff 	sub    -0x110(%rbp),%rax
    7dbc:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    7dc3:	0f 83 22 09 00 00    	jae    86eb <tmalloc_large+0xc63>
    if (RTCHECK(ok_address(m, v))) { /* split */
    7dc9:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    7dd0:	48 8b 40 18          	mov    0x18(%rax),%rax
    7dd4:	48 39 85 38 ff ff ff 	cmp    %rax,-0xc8(%rbp)
    7ddb:	0f 93 c0             	setae  %al
    7dde:	0f b6 c0             	movzbl %al,%eax
    7de1:	48 85 c0             	test   %rax,%rax
    7de4:	0f 84 fc 08 00 00    	je     86e6 <tmalloc_large+0xc5e>
      mchunkptr r = chunk_plus_offset(v, nb);
    7dea:	48 8b 95 38 ff ff ff 	mov    -0xc8(%rbp),%rdx
    7df1:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    7df8:	48 01 d0             	add    %rdx,%rax
    7dfb:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
      assert(chunksize(v) == rsize + nb);
    7dff:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7e06:	48 8b 40 08          	mov    0x8(%rax),%rax
    7e0a:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    7e0e:	48 89 c1             	mov    %rax,%rcx
    7e11:	48 8b 95 40 ff ff ff 	mov    -0xc0(%rbp),%rdx
    7e18:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    7e1f:	48 01 d0             	add    %rdx,%rax
    7e22:	48 39 c1             	cmp    %rax,%rcx
    7e25:	74 05                	je     7e2c <tmalloc_large+0x3a4>
    7e27:	e8 a2 4b 00 00       	callq  c9ce <abort>
      if (RTCHECK(ok_next(v, r))) {
    7e2c:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7e33:	48 3b 45 a0          	cmp    -0x60(%rbp),%rax
    7e37:	0f 92 c0             	setb   %al
    7e3a:	0f b6 c0             	movzbl %al,%eax
    7e3d:	48 85 c0             	test   %rax,%rax
    7e40:	0f 84 a0 08 00 00    	je     86e6 <tmalloc_large+0xc5e>
        unlink_large_chunk(m, v);
    7e46:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7e4d:	48 8b 40 30          	mov    0x30(%rax),%rax
    7e51:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    7e55:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7e5c:	48 8b 40 18          	mov    0x18(%rax),%rax
    7e60:	48 39 85 38 ff ff ff 	cmp    %rax,-0xc8(%rbp)
    7e67:	0f 84 aa 00 00 00    	je     7f17 <tmalloc_large+0x48f>
    7e6d:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7e74:	48 8b 40 10          	mov    0x10(%rax),%rax
    7e78:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    7e7c:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7e83:	48 8b 40 18          	mov    0x18(%rax),%rax
    7e87:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
    7e8e:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    7e95:	48 8b 40 18          	mov    0x18(%rax),%rax
    7e99:	48 39 45 b0          	cmp    %rax,-0x50(%rbp)
    7e9d:	0f 93 c0             	setae  %al
    7ea0:	0f b6 c0             	movzbl %al,%eax
    7ea3:	48 85 c0             	test   %rax,%rax
    7ea6:	74 21                	je     7ec9 <tmalloc_large+0x441>
    7ea8:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    7eac:	48 8b 40 18          	mov    0x18(%rax),%rax
    7eb0:	48 39 85 38 ff ff ff 	cmp    %rax,-0xc8(%rbp)
    7eb7:	0f 94 c0             	sete   %al
    7eba:	0f b6 c0             	movzbl %al,%eax
    7ebd:	48 85 c0             	test   %rax,%rax
    7ec0:	74 07                	je     7ec9 <tmalloc_large+0x441>
    7ec2:	b8 01 00 00 00       	mov    $0x1,%eax
    7ec7:	eb 05                	jmp    7ece <tmalloc_large+0x446>
    7ec9:	b8 00 00 00 00       	mov    $0x0,%eax
    7ece:	85 c0                	test   %eax,%eax
    7ed0:	74 40                	je     7f12 <tmalloc_large+0x48a>
    7ed2:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    7ed9:	48 8b 40 10          	mov    0x10(%rax),%rax
    7edd:	48 39 85 38 ff ff ff 	cmp    %rax,-0xc8(%rbp)
    7ee4:	0f 94 c0             	sete   %al
    7ee7:	0f b6 c0             	movzbl %al,%eax
    7eea:	48 85 c0             	test   %rax,%rax
    7eed:	74 23                	je     7f12 <tmalloc_large+0x48a>
    7eef:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    7ef3:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    7efa:	48 89 50 18          	mov    %rdx,0x18(%rax)
    7efe:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    7f05:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    7f09:	48 89 50 10          	mov    %rdx,0x10(%rax)
    7f0d:	e9 f8 00 00 00       	jmpq   800a <tmalloc_large+0x582>
    7f12:	e8 b7 4a 00 00       	callq  c9ce <abort>
    7f17:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7f1e:	48 83 c0 28          	add    $0x28,%rax
    7f22:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
    7f29:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    7f30:	48 8b 00             	mov    (%rax),%rax
    7f33:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
    7f3a:	48 83 bd 60 ff ff ff 	cmpq   $0x0,-0xa0(%rbp)
    7f41:	00 
    7f42:	75 52                	jne    7f96 <tmalloc_large+0x50e>
    7f44:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7f4b:	48 83 c0 20          	add    $0x20,%rax
    7f4f:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
    7f56:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    7f5d:	48 8b 00             	mov    (%rax),%rax
    7f60:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
    7f67:	48 83 bd 60 ff ff ff 	cmpq   $0x0,-0xa0(%rbp)
    7f6e:	00 
    7f6f:	0f 84 95 00 00 00    	je     800a <tmalloc_large+0x582>
    7f75:	eb 1f                	jmp    7f96 <tmalloc_large+0x50e>
    7f77:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    7f7e:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
    7f85:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    7f8c:	48 8b 00             	mov    (%rax),%rax
    7f8f:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
    7f96:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    7f9d:	48 83 c0 28          	add    $0x28,%rax
    7fa1:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
    7fa8:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    7faf:	48 8b 00             	mov    (%rax),%rax
    7fb2:	48 85 c0             	test   %rax,%rax
    7fb5:	75 c0                	jne    7f77 <tmalloc_large+0x4ef>
    7fb7:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    7fbe:	48 83 c0 20          	add    $0x20,%rax
    7fc2:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
    7fc9:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    7fd0:	48 8b 00             	mov    (%rax),%rax
    7fd3:	48 85 c0             	test   %rax,%rax
    7fd6:	75 9f                	jne    7f77 <tmalloc_large+0x4ef>
    7fd8:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    7fdf:	48 8b 40 18          	mov    0x18(%rax),%rax
    7fe3:	48 39 85 68 ff ff ff 	cmp    %rax,-0x98(%rbp)
    7fea:	0f 93 c0             	setae  %al
    7fed:	0f b6 c0             	movzbl %al,%eax
    7ff0:	48 85 c0             	test   %rax,%rax
    7ff3:	74 10                	je     8005 <tmalloc_large+0x57d>
    7ff5:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    7ffc:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    8003:	eb 05                	jmp    800a <tmalloc_large+0x582>
    8005:	e8 c4 49 00 00       	callq  c9ce <abort>
    800a:	48 83 7d a8 00       	cmpq   $0x0,-0x58(%rbp)
    800f:	0f 84 c6 01 00 00    	je     81db <tmalloc_large+0x753>
    8015:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    801c:	8b 40 38             	mov    0x38(%rax),%eax
    801f:	89 c0                	mov    %eax,%eax
    8021:	48 83 c0 4a          	add    $0x4a,%rax
    8025:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    802c:	00 
    802d:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    8034:	48 01 d0             	add    %rdx,%rax
    8037:	48 83 c0 08          	add    $0x8,%rax
    803b:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    803f:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    8043:	48 8b 00             	mov    (%rax),%rax
    8046:	48 39 85 38 ff ff ff 	cmp    %rax,-0xc8(%rbp)
    804d:	75 4d                	jne    809c <tmalloc_large+0x614>
    804f:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    8053:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    805a:	48 89 10             	mov    %rdx,(%rax)
    805d:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    8061:	48 8b 00             	mov    (%rax),%rax
    8064:	48 85 c0             	test   %rax,%rax
    8067:	0f 85 81 00 00 00    	jne    80ee <tmalloc_large+0x666>
    806d:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    8074:	8b 50 04             	mov    0x4(%rax),%edx
    8077:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    807e:	8b 40 38             	mov    0x38(%rax),%eax
    8081:	be 01 00 00 00       	mov    $0x1,%esi
    8086:	89 c1                	mov    %eax,%ecx
    8088:	d3 e6                	shl    %cl,%esi
    808a:	89 f0                	mov    %esi,%eax
    808c:	f7 d0                	not    %eax
    808e:	21 c2                	and    %eax,%edx
    8090:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    8097:	89 50 04             	mov    %edx,0x4(%rax)
    809a:	eb 52                	jmp    80ee <tmalloc_large+0x666>
    809c:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    80a3:	48 8b 40 18          	mov    0x18(%rax),%rax
    80a7:	48 39 45 a8          	cmp    %rax,-0x58(%rbp)
    80ab:	0f 93 c0             	setae  %al
    80ae:	0f b6 c0             	movzbl %al,%eax
    80b1:	48 85 c0             	test   %rax,%rax
    80b4:	74 33                	je     80e9 <tmalloc_large+0x661>
    80b6:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    80ba:	48 8b 40 20          	mov    0x20(%rax),%rax
    80be:	48 39 85 38 ff ff ff 	cmp    %rax,-0xc8(%rbp)
    80c5:	75 11                	jne    80d8 <tmalloc_large+0x650>
    80c7:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    80cb:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    80d2:	48 89 50 20          	mov    %rdx,0x20(%rax)
    80d6:	eb 16                	jmp    80ee <tmalloc_large+0x666>
    80d8:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    80dc:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    80e3:	48 89 50 28          	mov    %rdx,0x28(%rax)
    80e7:	eb 05                	jmp    80ee <tmalloc_large+0x666>
    80e9:	e8 e0 48 00 00       	callq  c9ce <abort>
    80ee:	48 83 bd 60 ff ff ff 	cmpq   $0x0,-0xa0(%rbp)
    80f5:	00 
    80f6:	0f 84 df 00 00 00    	je     81db <tmalloc_large+0x753>
    80fc:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    8103:	48 8b 40 18          	mov    0x18(%rax),%rax
    8107:	48 39 85 60 ff ff ff 	cmp    %rax,-0xa0(%rbp)
    810e:	0f 93 c0             	setae  %al
    8111:	0f b6 c0             	movzbl %al,%eax
    8114:	48 85 c0             	test   %rax,%rax
    8117:	0f 84 b9 00 00 00    	je     81d6 <tmalloc_large+0x74e>
    811d:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    8124:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    8128:	48 89 50 30          	mov    %rdx,0x30(%rax)
    812c:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    8133:	48 8b 40 20          	mov    0x20(%rax),%rax
    8137:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    813b:	48 83 7d c0 00       	cmpq   $0x0,-0x40(%rbp)
    8140:	74 3f                	je     8181 <tmalloc_large+0x6f9>
    8142:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    8149:	48 8b 40 18          	mov    0x18(%rax),%rax
    814d:	48 39 45 c0          	cmp    %rax,-0x40(%rbp)
    8151:	0f 93 c0             	setae  %al
    8154:	0f b6 c0             	movzbl %al,%eax
    8157:	48 85 c0             	test   %rax,%rax
    815a:	74 20                	je     817c <tmalloc_large+0x6f4>
    815c:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    8163:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    8167:	48 89 50 20          	mov    %rdx,0x20(%rax)
    816b:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    816f:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    8176:	48 89 50 30          	mov    %rdx,0x30(%rax)
    817a:	eb 05                	jmp    8181 <tmalloc_large+0x6f9>
    817c:	e8 4d 48 00 00       	callq  c9ce <abort>
    8181:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    8188:	48 8b 40 28          	mov    0x28(%rax),%rax
    818c:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    8190:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    8195:	74 44                	je     81db <tmalloc_large+0x753>
    8197:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    819e:	48 8b 40 18          	mov    0x18(%rax),%rax
    81a2:	48 39 45 c8          	cmp    %rax,-0x38(%rbp)
    81a6:	0f 93 c0             	setae  %al
    81a9:	0f b6 c0             	movzbl %al,%eax
    81ac:	48 85 c0             	test   %rax,%rax
    81af:	74 20                	je     81d1 <tmalloc_large+0x749>
    81b1:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    81b8:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    81bc:	48 89 50 28          	mov    %rdx,0x28(%rax)
    81c0:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    81c4:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    81cb:	48 89 50 30          	mov    %rdx,0x30(%rax)
    81cf:	eb 0a                	jmp    81db <tmalloc_large+0x753>
    81d1:	e8 f8 47 00 00       	callq  c9ce <abort>
    81d6:	e8 f3 47 00 00       	callq  c9ce <abort>
        if (rsize < MIN_CHUNK_SIZE)
    81db:	48 83 bd 40 ff ff ff 	cmpq   $0x1f,-0xc0(%rbp)
    81e2:	1f 
    81e3:	0f 87 99 00 00 00    	ja     8282 <tmalloc_large+0x7fa>
          set_inuse_and_pinuse(m, v, (rsize + nb));
    81e9:	48 8b 95 40 ff ff ff 	mov    -0xc0(%rbp),%rdx
    81f0:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    81f7:	48 01 d0             	add    %rdx,%rax
    81fa:	48 83 c8 03          	or     $0x3,%rax
    81fe:	48 89 c2             	mov    %rax,%rdx
    8201:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    8208:	48 89 50 08          	mov    %rdx,0x8(%rax)
    820c:	48 8b 95 40 ff ff ff 	mov    -0xc0(%rbp),%rdx
    8213:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    821a:	48 01 c2             	add    %rax,%rdx
    821d:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    8224:	48 01 d0             	add    %rdx,%rax
    8227:	48 8b 50 08          	mov    0x8(%rax),%rdx
    822b:	48 8b 8d 40 ff ff ff 	mov    -0xc0(%rbp),%rcx
    8232:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    8239:	48 01 c1             	add    %rax,%rcx
    823c:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    8243:	48 01 c8             	add    %rcx,%rax
    8246:	48 83 ca 01          	or     $0x1,%rdx
    824a:	48 89 50 08          	mov    %rdx,0x8(%rax)
    824e:	48 8b 0d cb 8e 00 00 	mov    0x8ecb(%rip),%rcx        # 11120 <mparams>
    8255:	48 8b 95 f8 fe ff ff 	mov    -0x108(%rbp),%rdx
    825c:	48 8b b5 40 ff ff ff 	mov    -0xc0(%rbp),%rsi
    8263:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    826a:	48 01 c6             	add    %rax,%rsi
    826d:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    8274:	48 01 f0             	add    %rsi,%rax
    8277:	48 31 ca             	xor    %rcx,%rdx
    827a:	48 89 10             	mov    %rdx,(%rax)
    827d:	e9 57 04 00 00       	jmpq   86d9 <tmalloc_large+0xc51>
        else {
          set_size_and_pinuse_of_inuse_chunk(m, v, nb);
    8282:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    8289:	48 83 c8 03          	or     $0x3,%rax
    828d:	48 89 c2             	mov    %rax,%rdx
    8290:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    8297:	48 89 50 08          	mov    %rdx,0x8(%rax)
    829b:	48 8b 0d 7e 8e 00 00 	mov    0x8e7e(%rip),%rcx        # 11120 <mparams>
    82a2:	48 8b 95 f8 fe ff ff 	mov    -0x108(%rbp),%rdx
    82a9:	48 8b b5 38 ff ff ff 	mov    -0xc8(%rbp),%rsi
    82b0:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    82b7:	48 01 f0             	add    %rsi,%rax
    82ba:	48 31 ca             	xor    %rcx,%rdx
    82bd:	48 89 10             	mov    %rdx,(%rax)
          set_size_and_pinuse_of_free_chunk(r, rsize);
    82c0:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    82c7:	48 83 c8 01          	or     $0x1,%rax
    82cb:	48 89 c2             	mov    %rax,%rdx
    82ce:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    82d2:	48 89 50 08          	mov    %rdx,0x8(%rax)
    82d6:	48 8b 55 a0          	mov    -0x60(%rbp),%rdx
    82da:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    82e1:	48 01 c2             	add    %rax,%rdx
    82e4:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    82eb:	48 89 02             	mov    %rax,(%rdx)
          insert_chunk(m, r, rsize);
    82ee:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    82f5:	48 c1 e8 03          	shr    $0x3,%rax
    82f9:	48 83 f8 1f          	cmp    $0x1f,%rax
    82fd:	0f 87 0c 01 00 00    	ja     840f <tmalloc_large+0x987>
    8303:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    830a:	48 c1 e8 03          	shr    $0x3,%rax
    830e:	89 85 34 ff ff ff    	mov    %eax,-0xcc(%rbp)
    8314:	8b 85 34 ff ff ff    	mov    -0xcc(%rbp),%eax
    831a:	01 c0                	add    %eax,%eax
    831c:	89 c0                	mov    %eax,%eax
    831e:	48 83 c0 08          	add    $0x8,%rax
    8322:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    8329:	00 
    832a:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    8331:	48 01 d0             	add    %rdx,%rax
    8334:	48 83 c0 08          	add    $0x8,%rax
    8338:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    833c:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    8340:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
    8347:	48 83 bd 40 ff ff ff 	cmpq   $0x1f,-0xc0(%rbp)
    834e:	1f 
    834f:	77 05                	ja     8356 <tmalloc_large+0x8ce>
    8351:	e8 78 46 00 00       	callq  c9ce <abort>
    8356:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    835d:	8b 10                	mov    (%rax),%edx
    835f:	8b 85 34 ff ff ff    	mov    -0xcc(%rbp),%eax
    8365:	be 01 00 00 00       	mov    $0x1,%esi
    836a:	89 c1                	mov    %eax,%ecx
    836c:	d3 e6                	shl    %cl,%esi
    836e:	89 f0                	mov    %esi,%eax
    8370:	21 d0                	and    %edx,%eax
    8372:	85 c0                	test   %eax,%eax
    8374:	75 27                	jne    839d <tmalloc_large+0x915>
    8376:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    837d:	8b 10                	mov    (%rax),%edx
    837f:	8b 85 34 ff ff ff    	mov    -0xcc(%rbp),%eax
    8385:	be 01 00 00 00       	mov    $0x1,%esi
    838a:	89 c1                	mov    %eax,%ecx
    838c:	d3 e6                	shl    %cl,%esi
    838e:	89 f0                	mov    %esi,%eax
    8390:	09 c2                	or     %eax,%edx
    8392:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    8399:	89 10                	mov    %edx,(%rax)
    839b:	eb 37                	jmp    83d4 <tmalloc_large+0x94c>
    839d:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    83a1:	48 8b 50 10          	mov    0x10(%rax),%rdx
    83a5:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    83ac:	48 8b 40 18          	mov    0x18(%rax),%rax
    83b0:	48 39 c2             	cmp    %rax,%rdx
    83b3:	0f 93 c0             	setae  %al
    83b6:	0f b6 c0             	movzbl %al,%eax
    83b9:	48 85 c0             	test   %rax,%rax
    83bc:	74 11                	je     83cf <tmalloc_large+0x947>
    83be:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    83c2:	48 8b 40 10          	mov    0x10(%rax),%rax
    83c6:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
    83cd:	eb 05                	jmp    83d4 <tmalloc_large+0x94c>
    83cf:	e8 fa 45 00 00       	callq  c9ce <abort>
    83d4:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    83d8:	48 8b 55 a0          	mov    -0x60(%rbp),%rdx
    83dc:	48 89 50 10          	mov    %rdx,0x10(%rax)
    83e0:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    83e7:	48 8b 55 a0          	mov    -0x60(%rbp),%rdx
    83eb:	48 89 50 18          	mov    %rdx,0x18(%rax)
    83ef:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    83f3:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    83fa:	48 89 50 10          	mov    %rdx,0x10(%rax)
    83fe:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    8402:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    8406:	48 89 50 18          	mov    %rdx,0x18(%rax)
    840a:	e9 ca 02 00 00       	jmpq   86d9 <tmalloc_large+0xc51>
    840f:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    8413:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    8417:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    841e:	48 c1 e8 08          	shr    $0x8,%rax
    8422:	89 85 2c ff ff ff    	mov    %eax,-0xd4(%rbp)
    8428:	83 bd 2c ff ff ff 00 	cmpl   $0x0,-0xd4(%rbp)
    842f:	75 0c                	jne    843d <tmalloc_large+0x9b5>
    8431:	c7 85 10 ff ff ff 00 	movl   $0x0,-0xf0(%rbp)
    8438:	00 00 00 
    843b:	eb 5d                	jmp    849a <tmalloc_large+0xa12>
    843d:	81 bd 2c ff ff ff ff 	cmpl   $0xffff,-0xd4(%rbp)
    8444:	ff 00 00 
    8447:	76 0c                	jbe    8455 <tmalloc_large+0x9cd>
    8449:	c7 85 10 ff ff ff 1f 	movl   $0x1f,-0xf0(%rbp)
    8450:	00 00 00 
    8453:	eb 45                	jmp    849a <tmalloc_large+0xa12>
    8455:	0f bd 85 2c ff ff ff 	bsr    -0xd4(%rbp),%eax
    845c:	83 f0 1f             	xor    $0x1f,%eax
    845f:	ba 1f 00 00 00       	mov    $0x1f,%edx
    8464:	29 c2                	sub    %eax,%edx
    8466:	89 d0                	mov    %edx,%eax
    8468:	89 85 30 ff ff ff    	mov    %eax,-0xd0(%rbp)
    846e:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    8474:	8d 34 00             	lea    (%rax,%rax,1),%esi
    8477:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    847d:	83 c0 07             	add    $0x7,%eax
    8480:	48 8b 95 40 ff ff ff 	mov    -0xc0(%rbp),%rdx
    8487:	89 c1                	mov    %eax,%ecx
    8489:	48 d3 ea             	shr    %cl,%rdx
    848c:	48 89 d0             	mov    %rdx,%rax
    848f:	83 e0 01             	and    $0x1,%eax
    8492:	01 f0                	add    %esi,%eax
    8494:	89 85 10 ff ff ff    	mov    %eax,-0xf0(%rbp)
    849a:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    84a0:	48 83 c0 4a          	add    $0x4a,%rax
    84a4:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    84ab:	00 
    84ac:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    84b3:	48 01 d0             	add    %rdx,%rax
    84b6:	48 83 c0 08          	add    $0x8,%rax
    84ba:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    84be:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    84c2:	8b 95 10 ff ff ff    	mov    -0xf0(%rbp),%edx
    84c8:	89 50 38             	mov    %edx,0x38(%rax)
    84cb:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    84cf:	48 c7 40 28 00 00 00 	movq   $0x0,0x28(%rax)
    84d6:	00 
    84d7:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    84db:	48 8b 50 28          	mov    0x28(%rax),%rdx
    84df:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    84e3:	48 89 50 20          	mov    %rdx,0x20(%rax)
    84e7:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    84ee:	8b 50 04             	mov    0x4(%rax),%edx
    84f1:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    84f7:	be 01 00 00 00       	mov    $0x1,%esi
    84fc:	89 c1                	mov    %eax,%ecx
    84fe:	d3 e6                	shl    %cl,%esi
    8500:	89 f0                	mov    %esi,%eax
    8502:	21 d0                	and    %edx,%eax
    8504:	85 c0                	test   %eax,%eax
    8506:	75 5f                	jne    8567 <tmalloc_large+0xadf>
    8508:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    850f:	8b 50 04             	mov    0x4(%rax),%edx
    8512:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    8518:	be 01 00 00 00       	mov    $0x1,%esi
    851d:	89 c1                	mov    %eax,%ecx
    851f:	d3 e6                	shl    %cl,%esi
    8521:	89 f0                	mov    %esi,%eax
    8523:	09 c2                	or     %eax,%edx
    8525:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    852c:	89 50 04             	mov    %edx,0x4(%rax)
    852f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    8533:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    8537:	48 89 10             	mov    %rdx,(%rax)
    853a:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    853e:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    8542:	48 89 50 30          	mov    %rdx,0x30(%rax)
    8546:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    854a:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    854e:	48 89 50 18          	mov    %rdx,0x18(%rax)
    8552:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    8556:	48 8b 50 18          	mov    0x18(%rax),%rdx
    855a:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    855e:	48 89 50 10          	mov    %rdx,0x10(%rax)
    8562:	e9 72 01 00 00       	jmpq   86d9 <tmalloc_large+0xc51>
    8567:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    856b:	48 8b 00             	mov    (%rax),%rax
    856e:	48 89 45 80          	mov    %rax,-0x80(%rbp)
    8572:	83 bd 10 ff ff ff 1f 	cmpl   $0x1f,-0xf0(%rbp)
    8579:	74 13                	je     858e <tmalloc_large+0xb06>
    857b:	8b 85 10 ff ff ff    	mov    -0xf0(%rbp),%eax
    8581:	d1 e8                	shr    %eax
    8583:	ba 39 00 00 00       	mov    $0x39,%edx
    8588:	29 c2                	sub    %eax,%edx
    858a:	89 d0                	mov    %edx,%eax
    858c:	eb 05                	jmp    8593 <tmalloc_large+0xb0b>
    858e:	b8 00 00 00 00       	mov    $0x0,%eax
    8593:	48 8b 95 40 ff ff ff 	mov    -0xc0(%rbp),%rdx
    859a:	89 c1                	mov    %eax,%ecx
    859c:	48 d3 e2             	shl    %cl,%rdx
    859f:	48 89 d0             	mov    %rdx,%rax
    85a2:	48 89 45 88          	mov    %rax,-0x78(%rbp)
    85a6:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    85aa:	48 8b 40 08          	mov    0x8(%rax),%rax
    85ae:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    85b2:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    85b9:	0f 84 93 00 00 00    	je     8652 <tmalloc_large+0xbca>
    85bf:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    85c3:	48 c1 e8 3f          	shr    $0x3f,%rax
    85c7:	48 83 c0 04          	add    $0x4,%rax
    85cb:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    85d2:	00 
    85d3:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    85d7:	48 01 d0             	add    %rdx,%rax
    85da:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    85de:	48 d1 65 88          	shlq   -0x78(%rbp)
    85e2:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    85e6:	48 8b 00             	mov    (%rax),%rax
    85e9:	48 85 c0             	test   %rax,%rax
    85ec:	74 0d                	je     85fb <tmalloc_large+0xb73>
    85ee:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    85f2:	48 8b 00             	mov    (%rax),%rax
    85f5:	48 89 45 80          	mov    %rax,-0x80(%rbp)
    85f9:	eb ab                	jmp    85a6 <tmalloc_large+0xb1e>
    85fb:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    8602:	48 8b 40 18          	mov    0x18(%rax),%rax
    8606:	48 39 45 e8          	cmp    %rax,-0x18(%rbp)
    860a:	0f 93 c0             	setae  %al
    860d:	0f b6 c0             	movzbl %al,%eax
    8610:	48 85 c0             	test   %rax,%rax
    8613:	74 38                	je     864d <tmalloc_large+0xbc5>
    8615:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    8619:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    861d:	48 89 10             	mov    %rdx,(%rax)
    8620:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    8624:	48 8b 55 80          	mov    -0x80(%rbp),%rdx
    8628:	48 89 50 30          	mov    %rdx,0x30(%rax)
    862c:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    8630:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    8634:	48 89 50 18          	mov    %rdx,0x18(%rax)
    8638:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    863c:	48 8b 50 18          	mov    0x18(%rax),%rdx
    8640:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    8644:	48 89 50 10          	mov    %rdx,0x10(%rax)
    8648:	e9 8c 00 00 00       	jmpq   86d9 <tmalloc_large+0xc51>
    864d:	e8 7c 43 00 00       	callq  c9ce <abort>
    8652:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8656:	48 8b 40 10          	mov    0x10(%rax),%rax
    865a:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    865e:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    8665:	48 8b 40 18          	mov    0x18(%rax),%rax
    8669:	48 39 45 80          	cmp    %rax,-0x80(%rbp)
    866d:	0f 93 c0             	setae  %al
    8670:	0f b6 c0             	movzbl %al,%eax
    8673:	48 85 c0             	test   %rax,%rax
    8676:	74 5c                	je     86d4 <tmalloc_large+0xc4c>
    8678:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    867f:	48 8b 40 18          	mov    0x18(%rax),%rax
    8683:	48 39 45 e0          	cmp    %rax,-0x20(%rbp)
    8687:	0f 93 c0             	setae  %al
    868a:	0f b6 c0             	movzbl %al,%eax
    868d:	48 85 c0             	test   %rax,%rax
    8690:	74 42                	je     86d4 <tmalloc_large+0xc4c>
    8692:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    8696:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    869a:	48 89 50 18          	mov    %rdx,0x18(%rax)
    869e:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    86a2:	48 8b 50 18          	mov    0x18(%rax),%rdx
    86a6:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    86aa:	48 89 50 10          	mov    %rdx,0x10(%rax)
    86ae:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    86b2:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    86b6:	48 89 50 10          	mov    %rdx,0x10(%rax)
    86ba:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    86be:	48 8b 55 80          	mov    -0x80(%rbp),%rdx
    86c2:	48 89 50 18          	mov    %rdx,0x18(%rax)
    86c6:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    86ca:	48 c7 40 30 00 00 00 	movq   $0x0,0x30(%rax)
    86d1:	00 
    86d2:	eb 05                	jmp    86d9 <tmalloc_large+0xc51>
    86d4:	e8 f5 42 00 00       	callq  c9ce <abort>
        }
        return chunk2mem(v);
    86d9:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    86e0:	48 83 c0 10          	add    $0x10,%rax
    86e4:	eb 0a                	jmp    86f0 <tmalloc_large+0xc68>
      }
    }
    CORRUPTION_ERROR_ACTION(m);
    86e6:	e8 e3 42 00 00       	callq  c9ce <abort>
  }
  return 0;
    86eb:	b8 00 00 00 00       	mov    $0x0,%eax
}
    86f0:	c9                   	leaveq 
    86f1:	c3                   	retq   

00000000000086f2 <tmalloc_small>:

/* allocate a small request from the best fitting chunk in a treebin */
static void* tmalloc_small(mstate m, size_t nb) {
    86f2:	55                   	push   %rbp
    86f3:	48 89 e5             	mov    %rsp,%rbp
    86f6:	48 81 ec b0 00 00 00 	sub    $0xb0,%rsp
    86fd:	48 89 bd 58 ff ff ff 	mov    %rdi,-0xa8(%rbp)
    8704:	48 89 b5 50 ff ff ff 	mov    %rsi,-0xb0(%rbp)
  tchunkptr t, v;
  size_t rsize;
  bindex_t i;
  binmap_t leastbit = least_bit(m->treemap);
    870b:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8712:	8b 50 04             	mov    0x4(%rax),%edx
    8715:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    871c:	8b 40 04             	mov    0x4(%rax),%eax
    871f:	f7 d8                	neg    %eax
    8721:	21 d0                	and    %edx,%eax
    8723:	89 85 68 ff ff ff    	mov    %eax,-0x98(%rbp)
  compute_bit2idx(leastbit, i);
    8729:	f3 0f bc 85 68 ff ff 	tzcnt  -0x98(%rbp),%eax
    8730:	ff 
    8731:	89 85 6c ff ff ff    	mov    %eax,-0x94(%rbp)
    8737:	8b 85 6c ff ff ff    	mov    -0x94(%rbp),%eax
    873d:	89 85 70 ff ff ff    	mov    %eax,-0x90(%rbp)
  v = t = *treebin_at(m, i);
    8743:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    874a:	8b 95 70 ff ff ff    	mov    -0x90(%rbp),%edx
    8750:	48 83 c2 4a          	add    $0x4a,%rdx
    8754:	48 8b 44 d0 08       	mov    0x8(%rax,%rdx,8),%rax
    8759:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
    8760:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    8767:	48 89 45 80          	mov    %rax,-0x80(%rbp)
  rsize = chunksize(t) - nb;
    876b:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    8772:	48 8b 40 08          	mov    0x8(%rax),%rax
    8776:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    877a:	48 2b 85 50 ff ff ff 	sub    -0xb0(%rbp),%rax
    8781:	48 89 45 88          	mov    %rax,-0x78(%rbp)

  while ((t = leftmost_child(t)) != 0) {
    8785:	eb 37                	jmp    87be <tmalloc_small+0xcc>
    size_t trem = chunksize(t) - nb;
    8787:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    878e:	48 8b 40 08          	mov    0x8(%rax),%rax
    8792:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    8796:	48 2b 85 50 ff ff ff 	sub    -0xb0(%rbp),%rax
    879d:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if (trem < rsize) {
    87a1:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    87a5:	48 3b 45 88          	cmp    -0x78(%rbp),%rax
    87a9:	73 13                	jae    87be <tmalloc_small+0xcc>
      rsize = trem;
    87ab:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    87af:	48 89 45 88          	mov    %rax,-0x78(%rbp)
      v = t;
    87b3:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    87ba:	48 89 45 80          	mov    %rax,-0x80(%rbp)
  while ((t = leftmost_child(t)) != 0) {
    87be:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    87c5:	48 8b 40 20          	mov    0x20(%rax),%rax
    87c9:	48 85 c0             	test   %rax,%rax
    87cc:	74 0d                	je     87db <tmalloc_small+0xe9>
    87ce:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    87d5:	48 8b 40 20          	mov    0x20(%rax),%rax
    87d9:	eb 0b                	jmp    87e6 <tmalloc_small+0xf4>
    87db:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    87e2:	48 8b 40 28          	mov    0x28(%rax),%rax
    87e6:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
    87ed:	48 83 bd 78 ff ff ff 	cmpq   $0x0,-0x88(%rbp)
    87f4:	00 
    87f5:	75 90                	jne    8787 <tmalloc_small+0x95>
    }
  }

  if (RTCHECK(ok_address(m, v))) {
    87f7:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    87fe:	48 8b 40 18          	mov    0x18(%rax),%rax
    8802:	48 39 45 80          	cmp    %rax,-0x80(%rbp)
    8806:	0f 93 c0             	setae  %al
    8809:	0f b6 c0             	movzbl %al,%eax
    880c:	48 85 c0             	test   %rax,%rax
    880f:	0f 84 8c 05 00 00    	je     8da1 <tmalloc_small+0x6af>
    mchunkptr r = chunk_plus_offset(v, nb);
    8815:	48 8b 55 80          	mov    -0x80(%rbp),%rdx
    8819:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    8820:	48 01 d0             	add    %rdx,%rax
    8823:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    assert(chunksize(v) == rsize + nb);
    8827:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    882b:	48 8b 40 08          	mov    0x8(%rax),%rax
    882f:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    8833:	48 89 c1             	mov    %rax,%rcx
    8836:	48 8b 55 88          	mov    -0x78(%rbp),%rdx
    883a:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    8841:	48 01 d0             	add    %rdx,%rax
    8844:	48 39 c1             	cmp    %rax,%rcx
    8847:	74 05                	je     884e <tmalloc_small+0x15c>
    8849:	e8 80 41 00 00       	callq  c9ce <abort>
    if (RTCHECK(ok_next(v, r))) {
    884e:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8852:	48 3b 45 b0          	cmp    -0x50(%rbp),%rax
    8856:	0f 92 c0             	setb   %al
    8859:	0f b6 c0             	movzbl %al,%eax
    885c:	48 85 c0             	test   %rax,%rax
    885f:	0f 84 3c 05 00 00    	je     8da1 <tmalloc_small+0x6af>
      unlink_large_chunk(m, v);
    8865:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8869:	48 8b 40 30          	mov    0x30(%rax),%rax
    886d:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    8871:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8875:	48 8b 40 18          	mov    0x18(%rax),%rax
    8879:	48 39 45 80          	cmp    %rax,-0x80(%rbp)
    887d:	0f 84 92 00 00 00    	je     8915 <tmalloc_small+0x223>
    8883:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8887:	48 8b 40 10          	mov    0x10(%rax),%rax
    888b:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    888f:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8893:	48 8b 40 18          	mov    0x18(%rax),%rax
    8897:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    889b:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    88a2:	48 8b 40 18          	mov    0x18(%rax),%rax
    88a6:	48 39 45 c0          	cmp    %rax,-0x40(%rbp)
    88aa:	0f 93 c0             	setae  %al
    88ad:	0f b6 c0             	movzbl %al,%eax
    88b0:	48 85 c0             	test   %rax,%rax
    88b3:	74 1e                	je     88d3 <tmalloc_small+0x1e1>
    88b5:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    88b9:	48 8b 40 18          	mov    0x18(%rax),%rax
    88bd:	48 39 45 80          	cmp    %rax,-0x80(%rbp)
    88c1:	0f 94 c0             	sete   %al
    88c4:	0f b6 c0             	movzbl %al,%eax
    88c7:	48 85 c0             	test   %rax,%rax
    88ca:	74 07                	je     88d3 <tmalloc_small+0x1e1>
    88cc:	b8 01 00 00 00       	mov    $0x1,%eax
    88d1:	eb 05                	jmp    88d8 <tmalloc_small+0x1e6>
    88d3:	b8 00 00 00 00       	mov    $0x0,%eax
    88d8:	85 c0                	test   %eax,%eax
    88da:	74 34                	je     8910 <tmalloc_small+0x21e>
    88dc:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    88e0:	48 8b 40 10          	mov    0x10(%rax),%rax
    88e4:	48 39 45 80          	cmp    %rax,-0x80(%rbp)
    88e8:	0f 94 c0             	sete   %al
    88eb:	0f b6 c0             	movzbl %al,%eax
    88ee:	48 85 c0             	test   %rax,%rax
    88f1:	74 1d                	je     8910 <tmalloc_small+0x21e>
    88f3:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    88f7:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    88fb:	48 89 50 18          	mov    %rdx,0x18(%rax)
    88ff:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    8903:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    8907:	48 89 50 10          	mov    %rdx,0x10(%rax)
    890b:	e9 b2 00 00 00       	jmpq   89c2 <tmalloc_small+0x2d0>
    8910:	e8 b9 40 00 00       	callq  c9ce <abort>
    8915:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8919:	48 83 c0 28          	add    $0x28,%rax
    891d:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    8921:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    8925:	48 8b 00             	mov    (%rax),%rax
    8928:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    892c:	48 83 7d 90 00       	cmpq   $0x0,-0x70(%rbp)
    8931:	75 33                	jne    8966 <tmalloc_small+0x274>
    8933:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8937:	48 83 c0 20          	add    $0x20,%rax
    893b:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    893f:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    8943:	48 8b 00             	mov    (%rax),%rax
    8946:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    894a:	48 83 7d 90 00       	cmpq   $0x0,-0x70(%rbp)
    894f:	74 71                	je     89c2 <tmalloc_small+0x2d0>
    8951:	eb 13                	jmp    8966 <tmalloc_small+0x274>
    8953:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    8957:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    895b:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    895f:	48 8b 00             	mov    (%rax),%rax
    8962:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    8966:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    896a:	48 83 c0 28          	add    $0x28,%rax
    896e:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
    8972:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    8976:	48 8b 00             	mov    (%rax),%rax
    8979:	48 85 c0             	test   %rax,%rax
    897c:	75 d5                	jne    8953 <tmalloc_small+0x261>
    897e:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    8982:	48 83 c0 20          	add    $0x20,%rax
    8986:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
    898a:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    898e:	48 8b 00             	mov    (%rax),%rax
    8991:	48 85 c0             	test   %rax,%rax
    8994:	75 bd                	jne    8953 <tmalloc_small+0x261>
    8996:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    899d:	48 8b 40 18          	mov    0x18(%rax),%rax
    89a1:	48 39 45 98          	cmp    %rax,-0x68(%rbp)
    89a5:	0f 93 c0             	setae  %al
    89a8:	0f b6 c0             	movzbl %al,%eax
    89ab:	48 85 c0             	test   %rax,%rax
    89ae:	74 0d                	je     89bd <tmalloc_small+0x2cb>
    89b0:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    89b4:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    89bb:	eb 05                	jmp    89c2 <tmalloc_small+0x2d0>
    89bd:	e8 0c 40 00 00       	callq  c9ce <abort>
    89c2:	48 83 7d b8 00       	cmpq   $0x0,-0x48(%rbp)
    89c7:	0f 84 92 01 00 00    	je     8b5f <tmalloc_small+0x46d>
    89cd:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    89d1:	8b 40 38             	mov    0x38(%rax),%eax
    89d4:	89 c0                	mov    %eax,%eax
    89d6:	48 83 c0 4a          	add    $0x4a,%rax
    89da:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    89e1:	00 
    89e2:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    89e9:	48 01 d0             	add    %rdx,%rax
    89ec:	48 83 c0 08          	add    $0x8,%rax
    89f0:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    89f4:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    89f8:	48 8b 00             	mov    (%rax),%rax
    89fb:	48 39 45 80          	cmp    %rax,-0x80(%rbp)
    89ff:	75 43                	jne    8a44 <tmalloc_small+0x352>
    8a01:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    8a05:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    8a09:	48 89 10             	mov    %rdx,(%rax)
    8a0c:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    8a10:	48 8b 00             	mov    (%rax),%rax
    8a13:	48 85 c0             	test   %rax,%rax
    8a16:	75 75                	jne    8a8d <tmalloc_small+0x39b>
    8a18:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8a1f:	8b 50 04             	mov    0x4(%rax),%edx
    8a22:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8a26:	8b 40 38             	mov    0x38(%rax),%eax
    8a29:	be 01 00 00 00       	mov    $0x1,%esi
    8a2e:	89 c1                	mov    %eax,%ecx
    8a30:	d3 e6                	shl    %cl,%esi
    8a32:	89 f0                	mov    %esi,%eax
    8a34:	f7 d0                	not    %eax
    8a36:	21 c2                	and    %eax,%edx
    8a38:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8a3f:	89 50 04             	mov    %edx,0x4(%rax)
    8a42:	eb 49                	jmp    8a8d <tmalloc_small+0x39b>
    8a44:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8a4b:	48 8b 40 18          	mov    0x18(%rax),%rax
    8a4f:	48 39 45 b8          	cmp    %rax,-0x48(%rbp)
    8a53:	0f 93 c0             	setae  %al
    8a56:	0f b6 c0             	movzbl %al,%eax
    8a59:	48 85 c0             	test   %rax,%rax
    8a5c:	74 2a                	je     8a88 <tmalloc_small+0x396>
    8a5e:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    8a62:	48 8b 40 20          	mov    0x20(%rax),%rax
    8a66:	48 39 45 80          	cmp    %rax,-0x80(%rbp)
    8a6a:	75 0e                	jne    8a7a <tmalloc_small+0x388>
    8a6c:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    8a70:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    8a74:	48 89 50 20          	mov    %rdx,0x20(%rax)
    8a78:	eb 13                	jmp    8a8d <tmalloc_small+0x39b>
    8a7a:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    8a7e:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    8a82:	48 89 50 28          	mov    %rdx,0x28(%rax)
    8a86:	eb 05                	jmp    8a8d <tmalloc_small+0x39b>
    8a88:	e8 41 3f 00 00       	callq  c9ce <abort>
    8a8d:	48 83 7d 90 00       	cmpq   $0x0,-0x70(%rbp)
    8a92:	0f 84 c7 00 00 00    	je     8b5f <tmalloc_small+0x46d>
    8a98:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8a9f:	48 8b 40 18          	mov    0x18(%rax),%rax
    8aa3:	48 39 45 90          	cmp    %rax,-0x70(%rbp)
    8aa7:	0f 93 c0             	setae  %al
    8aaa:	0f b6 c0             	movzbl %al,%eax
    8aad:	48 85 c0             	test   %rax,%rax
    8ab0:	0f 84 a4 00 00 00    	je     8b5a <tmalloc_small+0x468>
    8ab6:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    8aba:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
    8abe:	48 89 50 30          	mov    %rdx,0x30(%rax)
    8ac2:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8ac6:	48 8b 40 20          	mov    0x20(%rax),%rax
    8aca:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    8ace:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
    8ad3:	74 39                	je     8b0e <tmalloc_small+0x41c>
    8ad5:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8adc:	48 8b 40 18          	mov    0x18(%rax),%rax
    8ae0:	48 39 45 d0          	cmp    %rax,-0x30(%rbp)
    8ae4:	0f 93 c0             	setae  %al
    8ae7:	0f b6 c0             	movzbl %al,%eax
    8aea:	48 85 c0             	test   %rax,%rax
    8aed:	74 1a                	je     8b09 <tmalloc_small+0x417>
    8aef:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    8af3:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    8af7:	48 89 50 20          	mov    %rdx,0x20(%rax)
    8afb:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    8aff:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    8b03:	48 89 50 30          	mov    %rdx,0x30(%rax)
    8b07:	eb 05                	jmp    8b0e <tmalloc_small+0x41c>
    8b09:	e8 c0 3e 00 00       	callq  c9ce <abort>
    8b0e:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8b12:	48 8b 40 28          	mov    0x28(%rax),%rax
    8b16:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    8b1a:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    8b1f:	74 3e                	je     8b5f <tmalloc_small+0x46d>
    8b21:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8b28:	48 8b 40 18          	mov    0x18(%rax),%rax
    8b2c:	48 39 45 d8          	cmp    %rax,-0x28(%rbp)
    8b30:	0f 93 c0             	setae  %al
    8b33:	0f b6 c0             	movzbl %al,%eax
    8b36:	48 85 c0             	test   %rax,%rax
    8b39:	74 1a                	je     8b55 <tmalloc_small+0x463>
    8b3b:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    8b3f:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    8b43:	48 89 50 28          	mov    %rdx,0x28(%rax)
    8b47:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    8b4b:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    8b4f:	48 89 50 30          	mov    %rdx,0x30(%rax)
    8b53:	eb 0a                	jmp    8b5f <tmalloc_small+0x46d>
    8b55:	e8 74 3e 00 00       	callq  c9ce <abort>
    8b5a:	e8 6f 3e 00 00       	callq  c9ce <abort>
      if (rsize < MIN_CHUNK_SIZE)
    8b5f:	48 83 7d 88 1f       	cmpq   $0x1f,-0x78(%rbp)
    8b64:	0f 87 81 00 00 00    	ja     8beb <tmalloc_small+0x4f9>
        set_inuse_and_pinuse(m, v, (rsize + nb));
    8b6a:	48 8b 55 88          	mov    -0x78(%rbp),%rdx
    8b6e:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    8b75:	48 01 d0             	add    %rdx,%rax
    8b78:	48 83 c8 03          	or     $0x3,%rax
    8b7c:	48 89 c2             	mov    %rax,%rdx
    8b7f:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8b83:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8b87:	48 8b 55 88          	mov    -0x78(%rbp),%rdx
    8b8b:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    8b92:	48 01 c2             	add    %rax,%rdx
    8b95:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8b99:	48 01 d0             	add    %rdx,%rax
    8b9c:	48 8b 50 08          	mov    0x8(%rax),%rdx
    8ba0:	48 8b 4d 88          	mov    -0x78(%rbp),%rcx
    8ba4:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    8bab:	48 01 c1             	add    %rax,%rcx
    8bae:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8bb2:	48 01 c8             	add    %rcx,%rax
    8bb5:	48 83 ca 01          	or     $0x1,%rdx
    8bb9:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8bbd:	48 8b 0d 5c 85 00 00 	mov    0x855c(%rip),%rcx        # 11120 <mparams>
    8bc4:	48 8b 95 58 ff ff ff 	mov    -0xa8(%rbp),%rdx
    8bcb:	48 8b 75 88          	mov    -0x78(%rbp),%rsi
    8bcf:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    8bd6:	48 01 c6             	add    %rax,%rsi
    8bd9:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8bdd:	48 01 f0             	add    %rsi,%rax
    8be0:	48 31 ca             	xor    %rcx,%rdx
    8be3:	48 89 10             	mov    %rdx,(%rax)
    8be6:	e9 ac 01 00 00       	jmpq   8d97 <tmalloc_small+0x6a5>
      else {
        set_size_and_pinuse_of_inuse_chunk(m, v, nb);
    8beb:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    8bf2:	48 83 c8 03          	or     $0x3,%rax
    8bf6:	48 89 c2             	mov    %rax,%rdx
    8bf9:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8bfd:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8c01:	48 8b 0d 18 85 00 00 	mov    0x8518(%rip),%rcx        # 11120 <mparams>
    8c08:	48 8b 95 58 ff ff ff 	mov    -0xa8(%rbp),%rdx
    8c0f:	48 8b 75 80          	mov    -0x80(%rbp),%rsi
    8c13:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    8c1a:	48 01 f0             	add    %rsi,%rax
    8c1d:	48 31 ca             	xor    %rcx,%rdx
    8c20:	48 89 10             	mov    %rdx,(%rax)
        set_size_and_pinuse_of_free_chunk(r, rsize);
    8c23:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    8c27:	48 83 c8 01          	or     $0x1,%rax
    8c2b:	48 89 c2             	mov    %rax,%rdx
    8c2e:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    8c32:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8c36:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    8c3a:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    8c3e:	48 01 c2             	add    %rax,%rdx
    8c41:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    8c45:	48 89 02             	mov    %rax,(%rdx)
        replace_dv(m, r, rsize);
    8c48:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8c4f:	48 8b 40 08          	mov    0x8(%rax),%rax
    8c53:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    8c57:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    8c5b:	48 c1 e8 03          	shr    $0x3,%rax
    8c5f:	48 83 f8 1f          	cmp    $0x1f,%rax
    8c63:	76 05                	jbe    8c6a <tmalloc_small+0x578>
    8c65:	e8 64 3d 00 00       	callq  c9ce <abort>
    8c6a:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
    8c6f:	0f 84 04 01 00 00    	je     8d79 <tmalloc_small+0x687>
    8c75:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8c7c:	48 8b 40 20          	mov    0x20(%rax),%rax
    8c80:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    8c84:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    8c88:	48 c1 e8 03          	shr    $0x3,%rax
    8c8c:	89 85 74 ff ff ff    	mov    %eax,-0x8c(%rbp)
    8c92:	8b 85 74 ff ff ff    	mov    -0x8c(%rbp),%eax
    8c98:	01 c0                	add    %eax,%eax
    8c9a:	89 c0                	mov    %eax,%eax
    8c9c:	48 83 c0 08          	add    $0x8,%rax
    8ca0:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    8ca7:	00 
    8ca8:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8caf:	48 01 d0             	add    %rdx,%rax
    8cb2:	48 83 c0 08          	add    $0x8,%rax
    8cb6:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    8cba:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    8cbe:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    8cc2:	48 83 7d e0 1f       	cmpq   $0x1f,-0x20(%rbp)
    8cc7:	77 05                	ja     8cce <tmalloc_small+0x5dc>
    8cc9:	e8 00 3d 00 00       	callq  c9ce <abort>
    8cce:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8cd5:	8b 10                	mov    (%rax),%edx
    8cd7:	8b 85 74 ff ff ff    	mov    -0x8c(%rbp),%eax
    8cdd:	be 01 00 00 00       	mov    $0x1,%esi
    8ce2:	89 c1                	mov    %eax,%ecx
    8ce4:	d3 e6                	shl    %cl,%esi
    8ce6:	89 f0                	mov    %esi,%eax
    8ce8:	21 d0                	and    %edx,%eax
    8cea:	85 c0                	test   %eax,%eax
    8cec:	75 27                	jne    8d15 <tmalloc_small+0x623>
    8cee:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8cf5:	8b 10                	mov    (%rax),%edx
    8cf7:	8b 85 74 ff ff ff    	mov    -0x8c(%rbp),%eax
    8cfd:	be 01 00 00 00       	mov    $0x1,%esi
    8d02:	89 c1                	mov    %eax,%ecx
    8d04:	d3 e6                	shl    %cl,%esi
    8d06:	89 f0                	mov    %esi,%eax
    8d08:	09 c2                	or     %eax,%edx
    8d0a:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8d11:	89 10                	mov    %edx,(%rax)
    8d13:	eb 34                	jmp    8d49 <tmalloc_small+0x657>
    8d15:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    8d19:	48 8b 50 10          	mov    0x10(%rax),%rdx
    8d1d:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8d24:	48 8b 40 18          	mov    0x18(%rax),%rax
    8d28:	48 39 c2             	cmp    %rax,%rdx
    8d2b:	0f 93 c0             	setae  %al
    8d2e:	0f b6 c0             	movzbl %al,%eax
    8d31:	48 85 c0             	test   %rax,%rax
    8d34:	74 0e                	je     8d44 <tmalloc_small+0x652>
    8d36:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    8d3a:	48 8b 40 10          	mov    0x10(%rax),%rax
    8d3e:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    8d42:	eb 05                	jmp    8d49 <tmalloc_small+0x657>
    8d44:	e8 85 3c 00 00       	callq  c9ce <abort>
    8d49:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    8d4d:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    8d51:	48 89 50 10          	mov    %rdx,0x10(%rax)
    8d55:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8d59:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    8d5d:	48 89 50 18          	mov    %rdx,0x18(%rax)
    8d61:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    8d65:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    8d69:	48 89 50 10          	mov    %rdx,0x10(%rax)
    8d6d:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    8d71:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    8d75:	48 89 50 18          	mov    %rdx,0x18(%rax)
    8d79:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8d80:	48 8b 55 88          	mov    -0x78(%rbp),%rdx
    8d84:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8d88:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    8d8f:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    8d93:	48 89 50 20          	mov    %rdx,0x20(%rax)
      }
      return chunk2mem(v);
    8d97:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    8d9b:	48 83 c0 10          	add    $0x10,%rax
    8d9f:	eb 05                	jmp    8da6 <tmalloc_small+0x6b4>
    }
  }

  CORRUPTION_ERROR_ACTION(m);
    8da1:	e8 28 3c 00 00       	callq  c9ce <abort>
  return 0;
}
    8da6:	c9                   	leaveq 
    8da7:	c3                   	retq   

0000000000008da8 <dlmalloc>:

#if !ONLY_MSPACES

void* dlmalloc(size_t bytes) {
    8da8:	55                   	push   %rbp
    8da9:	48 89 e5             	mov    %rsp,%rbp
    8dac:	53                   	push   %rbx
    8dad:	48 81 ec e8 00 00 00 	sub    $0xe8,%rsp
    8db4:	48 89 bd 18 ff ff ff 	mov    %rdi,-0xe8(%rbp)

     The ugly goto's here ensure that postaction occurs along all paths.
  */

#if USE_LOCKS
  ensure_initialization(); /* initialize in sys_alloc if not using locks */
    8dbb:	48 8b 05 5e 83 00 00 	mov    0x835e(%rip),%rax        # 11120 <mparams>
    8dc2:	48 85 c0             	test   %rax,%rax
    8dc5:	75 07                	jne    8dce <dlmalloc+0x26>
    8dc7:	e8 c7 c5 ff ff       	callq  5393 <init_mparams>
    8dcc:	85 c0                	test   %eax,%eax
    8dce:	90                   	nop
#endif

  if (!PREACTION(gm)) {
    8dcf:	8b 05 fb 86 00 00    	mov    0x86fb(%rip),%eax        # 114d0 <_gm_+0x370>
    8dd5:	83 e0 02             	and    $0x2,%eax
    8dd8:	85 c0                	test   %eax,%eax
    8dda:	74 23                	je     8dff <dlmalloc+0x57>
    8ddc:	b8 01 00 00 00       	mov    $0x1,%eax
    8de1:	87 05 ed 86 00 00    	xchg   %eax,0x86ed(%rip)        # 114d4 <_gm_+0x374>
    8de7:	85 c0                	test   %eax,%eax
    8de9:	74 14                	je     8dff <dlmalloc+0x57>
    8deb:	48 8d 3d e2 86 00 00 	lea    0x86e2(%rip),%rdi        # 114d4 <_gm_+0x374>
    8df2:	e8 08 c5 ff ff       	callq  52ff <spin_acquire_lock>
    8df7:	85 c0                	test   %eax,%eax
    8df9:	0f 85 91 0a 00 00    	jne    9890 <dlmalloc+0xae8>
    void* mem;
    size_t nb;
    if (bytes <= MAX_SMALL_REQUEST) {
    8dff:	48 81 bd 18 ff ff ff 	cmpq   $0xe0,-0xe8(%rbp)
    8e06:	e0 00 00 00 
    8e0a:	0f 87 12 07 00 00    	ja     9522 <dlmalloc+0x77a>
      bindex_t idx;
      binmap_t smallbits;
      nb = (bytes < MIN_REQUEST)? MIN_CHUNK_SIZE : pad_request(bytes);
    8e10:	48 83 bd 18 ff ff ff 	cmpq   $0xe,-0xe8(%rbp)
    8e17:	0e 
    8e18:	76 11                	jbe    8e2b <dlmalloc+0x83>
    8e1a:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    8e21:	48 83 c0 1f          	add    $0x1f,%rax
    8e25:	48 83 e0 f0          	and    $0xfffffffffffffff0,%rax
    8e29:	eb 05                	jmp    8e30 <dlmalloc+0x88>
    8e2b:	b8 20 00 00 00       	mov    $0x20,%eax
    8e30:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
      idx = small_index(nb);
    8e37:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    8e3e:	48 c1 e8 03          	shr    $0x3,%rax
    8e42:	89 85 2c ff ff ff    	mov    %eax,-0xd4(%rbp)
      smallbits = gm->smallmap >> idx;
    8e48:	8b 15 12 83 00 00    	mov    0x8312(%rip),%edx        # 11160 <_gm_>
    8e4e:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8e54:	89 c1                	mov    %eax,%ecx
    8e56:	d3 ea                	shr    %cl,%edx
    8e58:	89 d0                	mov    %edx,%eax
    8e5a:	89 85 30 ff ff ff    	mov    %eax,-0xd0(%rbp)

      if ((smallbits & 0x3U) != 0) { /* Remainderless fit to a smallbin. */
    8e60:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    8e66:	83 e0 03             	and    $0x3,%eax
    8e69:	85 c0                	test   %eax,%eax
    8e6b:	0f 84 d3 01 00 00    	je     9044 <dlmalloc+0x29c>
        mchunkptr b, p;
        idx += ~smallbits & 1;       /* Uses next bin if idx empty */
    8e71:	8b 85 30 ff ff ff    	mov    -0xd0(%rbp),%eax
    8e77:	83 e0 01             	and    $0x1,%eax
    8e7a:	85 c0                	test   %eax,%eax
    8e7c:	0f 94 c0             	sete   %al
    8e7f:	0f b6 c0             	movzbl %al,%eax
    8e82:	01 85 2c ff ff ff    	add    %eax,-0xd4(%rbp)
        b = smallbin_at(gm, idx);
    8e88:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8e8e:	01 c0                	add    %eax,%eax
    8e90:	89 c0                	mov    %eax,%eax
    8e92:	48 83 c0 08          	add    $0x8,%rax
    8e96:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    8e9d:	00 
    8e9e:	48 8d 05 bb 82 00 00 	lea    0x82bb(%rip),%rax        # 11160 <_gm_>
    8ea5:	48 01 d0             	add    %rdx,%rax
    8ea8:	48 83 c0 08          	add    $0x8,%rax
    8eac:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
        p = b->fd;
    8eb0:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    8eb4:	48 8b 40 10          	mov    0x10(%rax),%rax
    8eb8:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
        assert(chunksize(p) == small_index2size(idx));
    8ebc:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8ec0:	48 8b 40 08          	mov    0x8(%rax),%rax
    8ec4:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    8ec8:	48 89 c2             	mov    %rax,%rdx
    8ecb:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8ed1:	c1 e0 03             	shl    $0x3,%eax
    8ed4:	89 c0                	mov    %eax,%eax
    8ed6:	48 39 c2             	cmp    %rax,%rdx
    8ed9:	74 05                	je     8ee0 <dlmalloc+0x138>
    8edb:	e8 ee 3a 00 00       	callq  c9ce <abort>
        unlink_first_small_chunk(gm, b, p, idx);
    8ee0:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8ee4:	48 8b 40 10          	mov    0x10(%rax),%rax
    8ee8:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    8eec:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8ef0:	48 3b 45 a0          	cmp    -0x60(%rbp),%rax
    8ef4:	75 05                	jne    8efb <dlmalloc+0x153>
    8ef6:	e8 d3 3a 00 00       	callq  c9ce <abort>
    8efb:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8eff:	48 3b 45 b0          	cmp    -0x50(%rbp),%rax
    8f03:	75 05                	jne    8f0a <dlmalloc+0x162>
    8f05:	e8 c4 3a 00 00       	callq  c9ce <abort>
    8f0a:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8f0e:	48 8b 40 08          	mov    0x8(%rax),%rax
    8f12:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    8f16:	48 89 c2             	mov    %rax,%rdx
    8f19:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8f1f:	c1 e0 03             	shl    $0x3,%eax
    8f22:	89 c0                	mov    %eax,%eax
    8f24:	48 39 c2             	cmp    %rax,%rdx
    8f27:	74 05                	je     8f2e <dlmalloc+0x186>
    8f29:	e8 a0 3a 00 00       	callq  c9ce <abort>
    8f2e:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    8f32:	48 3b 45 b0          	cmp    -0x50(%rbp),%rax
    8f36:	75 23                	jne    8f5b <dlmalloc+0x1b3>
    8f38:	8b 15 22 82 00 00    	mov    0x8222(%rip),%edx        # 11160 <_gm_>
    8f3e:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8f44:	be 01 00 00 00       	mov    $0x1,%esi
    8f49:	89 c1                	mov    %eax,%ecx
    8f4b:	d3 e6                	shl    %cl,%esi
    8f4d:	89 f0                	mov    %esi,%eax
    8f4f:	f7 d0                	not    %eax
    8f51:	21 d0                	and    %edx,%eax
    8f53:	89 05 07 82 00 00    	mov    %eax,0x8207(%rip)        # 11160 <_gm_>
    8f59:	eb 4c                	jmp    8fa7 <dlmalloc+0x1ff>
    8f5b:	48 8b 05 16 82 00 00 	mov    0x8216(%rip),%rax        # 11178 <_gm_+0x18>
    8f62:	48 39 45 b0          	cmp    %rax,-0x50(%rbp)
    8f66:	0f 93 c0             	setae  %al
    8f69:	0f b6 c0             	movzbl %al,%eax
    8f6c:	48 85 c0             	test   %rax,%rax
    8f6f:	74 31                	je     8fa2 <dlmalloc+0x1fa>
    8f71:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    8f75:	48 8b 40 18          	mov    0x18(%rax),%rax
    8f79:	48 39 45 a8          	cmp    %rax,-0x58(%rbp)
    8f7d:	0f 94 c0             	sete   %al
    8f80:	0f b6 c0             	movzbl %al,%eax
    8f83:	48 85 c0             	test   %rax,%rax
    8f86:	74 1a                	je     8fa2 <dlmalloc+0x1fa>
    8f88:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    8f8c:	48 8b 55 a0          	mov    -0x60(%rbp),%rdx
    8f90:	48 89 50 18          	mov    %rdx,0x18(%rax)
    8f94:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    8f98:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    8f9c:	48 89 50 10          	mov    %rdx,0x10(%rax)
    8fa0:	eb 05                	jmp    8fa7 <dlmalloc+0x1ff>
    8fa2:	e8 27 3a 00 00       	callq  c9ce <abort>
        set_inuse_and_pinuse(gm, p, small_index2size(idx));
    8fa7:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8fad:	c1 e0 03             	shl    $0x3,%eax
    8fb0:	83 c8 03             	or     $0x3,%eax
    8fb3:	89 c2                	mov    %eax,%edx
    8fb5:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8fb9:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8fbd:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8fc3:	c1 e0 03             	shl    $0x3,%eax
    8fc6:	89 c2                	mov    %eax,%edx
    8fc8:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8fcc:	48 01 d0             	add    %rdx,%rax
    8fcf:	48 8b 50 08          	mov    0x8(%rax),%rdx
    8fd3:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    8fd9:	c1 e0 03             	shl    $0x3,%eax
    8fdc:	89 c1                	mov    %eax,%ecx
    8fde:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8fe2:	48 01 c8             	add    %rcx,%rax
    8fe5:	48 83 ca 01          	or     $0x1,%rdx
    8fe9:	48 89 50 08          	mov    %rdx,0x8(%rax)
    8fed:	48 8b 0d 2c 81 00 00 	mov    0x812c(%rip),%rcx        # 11120 <mparams>
    8ff4:	48 8d 15 65 81 00 00 	lea    0x8165(%rip),%rdx        # 11160 <_gm_>
    8ffb:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    9001:	c1 e0 03             	shl    $0x3,%eax
    9004:	89 c6                	mov    %eax,%esi
    9006:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    900a:	48 01 f0             	add    %rsi,%rax
    900d:	48 31 ca             	xor    %rcx,%rdx
    9010:	48 89 10             	mov    %rdx,(%rax)
        mem = chunk2mem(p);
    9013:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    9017:	48 83 c0 10          	add    $0x10,%rax
    901b:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
        check_malloced_chunk(gm, mem, nb);
    9022:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    9029:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    9030:	48 89 c6             	mov    %rax,%rsi
    9033:	48 8d 3d 26 81 00 00 	lea    0x8126(%rip),%rdi        # 11160 <_gm_>
    903a:	e8 67 c8 ff ff       	callq  58a6 <do_check_malloced_chunk>
        goto postaction;
    903f:	e9 d8 07 00 00       	jmpq   981c <dlmalloc+0xa74>
      }

      else if (nb > gm->dvsize) {
    9044:	48 8b 05 1d 81 00 00 	mov    0x811d(%rip),%rax        # 11168 <_gm_+0x8>
    904b:	48 39 85 50 ff ff ff 	cmp    %rax,-0xb0(%rbp)
    9052:	0f 86 4d 05 00 00    	jbe    95a5 <dlmalloc+0x7fd>
        if (smallbits != 0) { /* Use chunk in next nonempty smallbin */
    9058:	83 bd 30 ff ff ff 00 	cmpl   $0x0,-0xd0(%rbp)
    905f:	0f 84 62 04 00 00    	je     94c7 <dlmalloc+0x71f>
          mchunkptr b, p, r;
          size_t rsize;
          bindex_t i;
          binmap_t leftbits = (smallbits << idx) & left_bits(idx2bit(idx));
    9065:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    906b:	8b 95 30 ff ff ff    	mov    -0xd0(%rbp),%edx
    9071:	89 c1                	mov    %eax,%ecx
    9073:	d3 e2                	shl    %cl,%edx
    9075:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    907b:	be 01 00 00 00       	mov    $0x1,%esi
    9080:	89 c1                	mov    %eax,%ecx
    9082:	d3 e6                	shl    %cl,%esi
    9084:	89 f0                	mov    %esi,%eax
    9086:	8d 34 00             	lea    (%rax,%rax,1),%esi
    9089:	8b 85 2c ff ff ff    	mov    -0xd4(%rbp),%eax
    908f:	bf 01 00 00 00       	mov    $0x1,%edi
    9094:	89 c1                	mov    %eax,%ecx
    9096:	d3 e7                	shl    %cl,%edi
    9098:	89 f8                	mov    %edi,%eax
    909a:	01 c0                	add    %eax,%eax
    909c:	f7 d8                	neg    %eax
    909e:	09 f0                	or     %esi,%eax
    90a0:	21 d0                	and    %edx,%eax
    90a2:	89 85 34 ff ff ff    	mov    %eax,-0xcc(%rbp)
          binmap_t leastbit = least_bit(leftbits);
    90a8:	8b 85 34 ff ff ff    	mov    -0xcc(%rbp),%eax
    90ae:	f7 d8                	neg    %eax
    90b0:	23 85 34 ff ff ff    	and    -0xcc(%rbp),%eax
    90b6:	89 85 38 ff ff ff    	mov    %eax,-0xc8(%rbp)
          compute_bit2idx(leastbit, i);
    90bc:	f3 0f bc 85 38 ff ff 	tzcnt  -0xc8(%rbp),%eax
    90c3:	ff 
    90c4:	89 85 3c ff ff ff    	mov    %eax,-0xc4(%rbp)
    90ca:	8b 85 3c ff ff ff    	mov    -0xc4(%rbp),%eax
    90d0:	89 85 40 ff ff ff    	mov    %eax,-0xc0(%rbp)
          b = smallbin_at(gm, i);
    90d6:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    90dc:	01 c0                	add    %eax,%eax
    90de:	89 c0                	mov    %eax,%eax
    90e0:	48 83 c0 08          	add    $0x8,%rax
    90e4:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    90eb:	00 
    90ec:	48 8d 05 6d 80 00 00 	lea    0x806d(%rip),%rax        # 11160 <_gm_>
    90f3:	48 01 d0             	add    %rdx,%rax
    90f6:	48 83 c0 08          	add    $0x8,%rax
    90fa:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
          p = b->fd;
    9101:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    9108:	48 8b 40 10          	mov    0x10(%rax),%rax
    910c:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
          assert(chunksize(p) == small_index2size(i));
    9113:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    911a:	48 8b 40 08          	mov    0x8(%rax),%rax
    911e:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    9122:	48 89 c2             	mov    %rax,%rdx
    9125:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    912b:	c1 e0 03             	shl    $0x3,%eax
    912e:	89 c0                	mov    %eax,%eax
    9130:	48 39 c2             	cmp    %rax,%rdx
    9133:	74 05                	je     913a <dlmalloc+0x392>
    9135:	e8 94 38 00 00       	callq  c9ce <abort>
          unlink_first_small_chunk(gm, b, p, i);
    913a:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    9141:	48 8b 40 10          	mov    0x10(%rax),%rax
    9145:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
    914c:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    9153:	48 3b 85 60 ff ff ff 	cmp    -0xa0(%rbp),%rax
    915a:	75 05                	jne    9161 <dlmalloc+0x3b9>
    915c:	e8 6d 38 00 00       	callq  c9ce <abort>
    9161:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    9168:	48 3b 85 70 ff ff ff 	cmp    -0x90(%rbp),%rax
    916f:	75 05                	jne    9176 <dlmalloc+0x3ce>
    9171:	e8 58 38 00 00       	callq  c9ce <abort>
    9176:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    917d:	48 8b 40 08          	mov    0x8(%rax),%rax
    9181:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    9185:	48 89 c2             	mov    %rax,%rdx
    9188:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    918e:	c1 e0 03             	shl    $0x3,%eax
    9191:	89 c0                	mov    %eax,%eax
    9193:	48 39 c2             	cmp    %rax,%rdx
    9196:	74 05                	je     919d <dlmalloc+0x3f5>
    9198:	e8 31 38 00 00       	callq  c9ce <abort>
    919d:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    91a4:	48 3b 85 70 ff ff ff 	cmp    -0x90(%rbp),%rax
    91ab:	75 23                	jne    91d0 <dlmalloc+0x428>
    91ad:	8b 15 ad 7f 00 00    	mov    0x7fad(%rip),%edx        # 11160 <_gm_>
    91b3:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    91b9:	be 01 00 00 00       	mov    $0x1,%esi
    91be:	89 c1                	mov    %eax,%ecx
    91c0:	d3 e6                	shl    %cl,%esi
    91c2:	89 f0                	mov    %esi,%eax
    91c4:	f7 d0                	not    %eax
    91c6:	21 d0                	and    %edx,%eax
    91c8:	89 05 92 7f 00 00    	mov    %eax,0x7f92(%rip)        # 11160 <_gm_>
    91ce:	eb 61                	jmp    9231 <dlmalloc+0x489>
    91d0:	48 8b 05 a1 7f 00 00 	mov    0x7fa1(%rip),%rax        # 11178 <_gm_+0x18>
    91d7:	48 39 85 70 ff ff ff 	cmp    %rax,-0x90(%rbp)
    91de:	0f 93 c0             	setae  %al
    91e1:	0f b6 c0             	movzbl %al,%eax
    91e4:	48 85 c0             	test   %rax,%rax
    91e7:	74 43                	je     922c <dlmalloc+0x484>
    91e9:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    91f0:	48 8b 40 18          	mov    0x18(%rax),%rax
    91f4:	48 39 85 68 ff ff ff 	cmp    %rax,-0x98(%rbp)
    91fb:	0f 94 c0             	sete   %al
    91fe:	0f b6 c0             	movzbl %al,%eax
    9201:	48 85 c0             	test   %rax,%rax
    9204:	74 26                	je     922c <dlmalloc+0x484>
    9206:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    920d:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    9214:	48 89 50 18          	mov    %rdx,0x18(%rax)
    9218:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    921f:	48 8b 95 70 ff ff ff 	mov    -0x90(%rbp),%rdx
    9226:	48 89 50 10          	mov    %rdx,0x10(%rax)
    922a:	eb 05                	jmp    9231 <dlmalloc+0x489>
    922c:	e8 9d 37 00 00       	callq  c9ce <abort>
          rsize = small_index2size(i) - nb;
    9231:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    9237:	c1 e0 03             	shl    $0x3,%eax
    923a:	89 c0                	mov    %eax,%eax
    923c:	48 2b 85 50 ff ff ff 	sub    -0xb0(%rbp),%rax
    9243:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
          /* Fit here cannot be remainderless if 4byte sizes */
          if (SIZE_T_SIZE != 4 && rsize < MIN_CHUNK_SIZE)
    924a:	48 83 bd 78 ff ff ff 	cmpq   $0x1f,-0x88(%rbp)
    9251:	1f 
    9252:	77 7d                	ja     92d1 <dlmalloc+0x529>
            set_inuse_and_pinuse(gm, p, small_index2size(i));
    9254:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    925a:	c1 e0 03             	shl    $0x3,%eax
    925d:	83 c8 03             	or     $0x3,%eax
    9260:	89 c2                	mov    %eax,%edx
    9262:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    9269:	48 89 50 08          	mov    %rdx,0x8(%rax)
    926d:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    9273:	c1 e0 03             	shl    $0x3,%eax
    9276:	89 c2                	mov    %eax,%edx
    9278:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    927f:	48 01 d0             	add    %rdx,%rax
    9282:	48 8b 50 08          	mov    0x8(%rax),%rdx
    9286:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    928c:	c1 e0 03             	shl    $0x3,%eax
    928f:	89 c1                	mov    %eax,%ecx
    9291:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    9298:	48 01 c8             	add    %rcx,%rax
    929b:	48 83 ca 01          	or     $0x1,%rdx
    929f:	48 89 50 08          	mov    %rdx,0x8(%rax)
    92a3:	48 8b 0d 76 7e 00 00 	mov    0x7e76(%rip),%rcx        # 11120 <mparams>
    92aa:	48 8d 15 af 7e 00 00 	lea    0x7eaf(%rip),%rdx        # 11160 <_gm_>
    92b1:	8b 85 40 ff ff ff    	mov    -0xc0(%rbp),%eax
    92b7:	c1 e0 03             	shl    $0x3,%eax
    92ba:	89 c6                	mov    %eax,%esi
    92bc:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    92c3:	48 01 f0             	add    %rsi,%rax
    92c6:	48 31 ca             	xor    %rcx,%rdx
    92c9:	48 89 10             	mov    %rdx,(%rax)
    92cc:	e9 c2 01 00 00       	jmpq   9493 <dlmalloc+0x6eb>
          else {
            set_size_and_pinuse_of_inuse_chunk(gm, p, nb);
    92d1:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    92d8:	48 83 c8 03          	or     $0x3,%rax
    92dc:	48 89 c2             	mov    %rax,%rdx
    92df:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    92e6:	48 89 50 08          	mov    %rdx,0x8(%rax)
    92ea:	48 8b 0d 2f 7e 00 00 	mov    0x7e2f(%rip),%rcx        # 11120 <mparams>
    92f1:	48 8d 15 68 7e 00 00 	lea    0x7e68(%rip),%rdx        # 11160 <_gm_>
    92f8:	48 8b b5 68 ff ff ff 	mov    -0x98(%rbp),%rsi
    92ff:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    9306:	48 01 f0             	add    %rsi,%rax
    9309:	48 31 ca             	xor    %rcx,%rdx
    930c:	48 89 10             	mov    %rdx,(%rax)
            r = chunk_plus_offset(p, nb);
    930f:	48 8b 95 68 ff ff ff 	mov    -0x98(%rbp),%rdx
    9316:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    931d:	48 01 d0             	add    %rdx,%rax
    9320:	48 89 45 80          	mov    %rax,-0x80(%rbp)
            set_size_and_pinuse_of_free_chunk(r, rsize);
    9324:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    932b:	48 83 c8 01          	or     $0x1,%rax
    932f:	48 89 c2             	mov    %rax,%rdx
    9332:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    9336:	48 89 50 08          	mov    %rdx,0x8(%rax)
    933a:	48 8b 55 80          	mov    -0x80(%rbp),%rdx
    933e:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    9345:	48 01 c2             	add    %rax,%rdx
    9348:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    934f:	48 89 02             	mov    %rax,(%rdx)
            replace_dv(gm, r, rsize);
    9352:	48 8b 05 0f 7e 00 00 	mov    0x7e0f(%rip),%rax        # 11168 <_gm_+0x8>
    9359:	48 89 45 88          	mov    %rax,-0x78(%rbp)
    935d:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    9361:	48 c1 e8 03          	shr    $0x3,%rax
    9365:	48 83 f8 1f          	cmp    $0x1f,%rax
    9369:	76 05                	jbe    9370 <dlmalloc+0x5c8>
    936b:	e8 5e 36 00 00       	callq  c9ce <abort>
    9370:	48 83 7d 88 00       	cmpq   $0x0,-0x78(%rbp)
    9375:	0f 84 ff 00 00 00    	je     947a <dlmalloc+0x6d2>
    937b:	48 8b 05 fe 7d 00 00 	mov    0x7dfe(%rip),%rax        # 11180 <_gm_+0x20>
    9382:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    9386:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    938a:	48 c1 e8 03          	shr    $0x3,%rax
    938e:	89 85 44 ff ff ff    	mov    %eax,-0xbc(%rbp)
    9394:	8b 85 44 ff ff ff    	mov    -0xbc(%rbp),%eax
    939a:	01 c0                	add    %eax,%eax
    939c:	89 c0                	mov    %eax,%eax
    939e:	48 83 c0 08          	add    $0x8,%rax
    93a2:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    93a9:	00 
    93aa:	48 8d 05 af 7d 00 00 	lea    0x7daf(%rip),%rax        # 11160 <_gm_>
    93b1:	48 01 d0             	add    %rdx,%rax
    93b4:	48 83 c0 08          	add    $0x8,%rax
    93b8:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    93bc:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    93c0:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
    93c7:	48 83 7d 88 1f       	cmpq   $0x1f,-0x78(%rbp)
    93cc:	77 05                	ja     93d3 <dlmalloc+0x62b>
    93ce:	e8 fb 35 00 00       	callq  c9ce <abort>
    93d3:	8b 15 87 7d 00 00    	mov    0x7d87(%rip),%edx        # 11160 <_gm_>
    93d9:	8b 85 44 ff ff ff    	mov    -0xbc(%rbp),%eax
    93df:	be 01 00 00 00       	mov    $0x1,%esi
    93e4:	89 c1                	mov    %eax,%ecx
    93e6:	d3 e6                	shl    %cl,%esi
    93e8:	89 f0                	mov    %esi,%eax
    93ea:	21 d0                	and    %edx,%eax
    93ec:	85 c0                	test   %eax,%eax
    93ee:	75 21                	jne    9411 <dlmalloc+0x669>
    93f0:	8b 15 6a 7d 00 00    	mov    0x7d6a(%rip),%edx        # 11160 <_gm_>
    93f6:	8b 85 44 ff ff ff    	mov    -0xbc(%rbp),%eax
    93fc:	be 01 00 00 00       	mov    $0x1,%esi
    9401:	89 c1                	mov    %eax,%ecx
    9403:	d3 e6                	shl    %cl,%esi
    9405:	89 f0                	mov    %esi,%eax
    9407:	09 d0                	or     %edx,%eax
    9409:	89 05 51 7d 00 00    	mov    %eax,0x7d51(%rip)        # 11160 <_gm_>
    940f:	eb 33                	jmp    9444 <dlmalloc+0x69c>
    9411:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    9415:	48 8b 50 10          	mov    0x10(%rax),%rdx
    9419:	48 8b 05 58 7d 00 00 	mov    0x7d58(%rip),%rax        # 11178 <_gm_+0x18>
    9420:	48 39 c2             	cmp    %rax,%rdx
    9423:	0f 93 c0             	setae  %al
    9426:	0f b6 c0             	movzbl %al,%eax
    9429:	48 85 c0             	test   %rax,%rax
    942c:	74 11                	je     943f <dlmalloc+0x697>
    942e:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    9432:	48 8b 40 10          	mov    0x10(%rax),%rax
    9436:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
    943d:	eb 05                	jmp    9444 <dlmalloc+0x69c>
    943f:	e8 8a 35 00 00       	callq  c9ce <abort>
    9444:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    9448:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    944c:	48 89 50 10          	mov    %rdx,0x10(%rax)
    9450:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    9457:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    945b:	48 89 50 18          	mov    %rdx,0x18(%rax)
    945f:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    9463:	48 8b 95 58 ff ff ff 	mov    -0xa8(%rbp),%rdx
    946a:	48 89 50 10          	mov    %rdx,0x10(%rax)
    946e:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    9472:	48 8b 55 98          	mov    -0x68(%rbp),%rdx
    9476:	48 89 50 18          	mov    %rdx,0x18(%rax)
    947a:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    9481:	48 89 05 e0 7c 00 00 	mov    %rax,0x7ce0(%rip)        # 11168 <_gm_+0x8>
    9488:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    948c:	48 89 05 ed 7c 00 00 	mov    %rax,0x7ced(%rip)        # 11180 <_gm_+0x20>
          }
          mem = chunk2mem(p);
    9493:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    949a:	48 83 c0 10          	add    $0x10,%rax
    949e:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
          check_malloced_chunk(gm, mem, nb);
    94a5:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    94ac:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    94b3:	48 89 c6             	mov    %rax,%rsi
    94b6:	48 8d 3d a3 7c 00 00 	lea    0x7ca3(%rip),%rdi        # 11160 <_gm_>
    94bd:	e8 e4 c3 ff ff       	callq  58a6 <do_check_malloced_chunk>
          goto postaction;
    94c2:	e9 55 03 00 00       	jmpq   981c <dlmalloc+0xa74>
        }

        else if (gm->treemap != 0 && (mem = tmalloc_small(gm, nb)) != 0) {
    94c7:	8b 05 97 7c 00 00    	mov    0x7c97(%rip),%eax        # 11164 <_gm_+0x4>
    94cd:	85 c0                	test   %eax,%eax
    94cf:	0f 84 d0 00 00 00    	je     95a5 <dlmalloc+0x7fd>
    94d5:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    94dc:	48 89 c6             	mov    %rax,%rsi
    94df:	48 8d 3d 7a 7c 00 00 	lea    0x7c7a(%rip),%rdi        # 11160 <_gm_>
    94e6:	e8 07 f2 ff ff       	callq  86f2 <tmalloc_small>
    94eb:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    94f2:	48 83 bd 48 ff ff ff 	cmpq   $0x0,-0xb8(%rbp)
    94f9:	00 
    94fa:	0f 84 a5 00 00 00    	je     95a5 <dlmalloc+0x7fd>
          check_malloced_chunk(gm, mem, nb);
    9500:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    9507:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    950e:	48 89 c6             	mov    %rax,%rsi
    9511:	48 8d 3d 48 7c 00 00 	lea    0x7c48(%rip),%rdi        # 11160 <_gm_>
    9518:	e8 89 c3 ff ff       	callq  58a6 <do_check_malloced_chunk>
          goto postaction;
    951d:	e9 fa 02 00 00       	jmpq   981c <dlmalloc+0xa74>
        }
      }
    }
    else if (bytes >= MAX_REQUEST)
    9522:	48 81 bd 18 ff ff ff 	cmpq   $0xffffffffffffff7f,-0xe8(%rbp)
    9529:	7f ff ff ff 
    952d:	76 0d                	jbe    953c <dlmalloc+0x794>
      nb = MAX_SIZE_T; /* Too big to allocate. Force failure (in sys alloc) */
    952f:	48 c7 85 50 ff ff ff 	movq   $0xffffffffffffffff,-0xb0(%rbp)
    9536:	ff ff ff ff 
    953a:	eb 69                	jmp    95a5 <dlmalloc+0x7fd>
    else {
      nb = pad_request(bytes);
    953c:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    9543:	48 83 c0 1f          	add    $0x1f,%rax
    9547:	48 83 e0 f0          	and    $0xfffffffffffffff0,%rax
    954b:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
      if (gm->treemap != 0 && (mem = tmalloc_large(gm, nb)) != 0) {
    9552:	8b 05 0c 7c 00 00    	mov    0x7c0c(%rip),%eax        # 11164 <_gm_+0x4>
    9558:	85 c0                	test   %eax,%eax
    955a:	74 49                	je     95a5 <dlmalloc+0x7fd>
    955c:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    9563:	48 89 c6             	mov    %rax,%rsi
    9566:	48 8d 3d f3 7b 00 00 	lea    0x7bf3(%rip),%rdi        # 11160 <_gm_>
    956d:	e8 16 e5 ff ff       	callq  7a88 <tmalloc_large>
    9572:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    9579:	48 83 bd 48 ff ff ff 	cmpq   $0x0,-0xb8(%rbp)
    9580:	00 
    9581:	74 22                	je     95a5 <dlmalloc+0x7fd>
        check_malloced_chunk(gm, mem, nb);
    9583:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    958a:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    9591:	48 89 c6             	mov    %rax,%rsi
    9594:	48 8d 3d c5 7b 00 00 	lea    0x7bc5(%rip),%rdi        # 11160 <_gm_>
    959b:	e8 06 c3 ff ff       	callq  58a6 <do_check_malloced_chunk>
        goto postaction;
    95a0:	e9 77 02 00 00       	jmpq   981c <dlmalloc+0xa74>
      }
    }

    if (nb <= gm->dvsize) {
    95a5:	48 8b 05 bc 7b 00 00 	mov    0x7bbc(%rip),%rax        # 11168 <_gm_+0x8>
    95ac:	48 39 85 50 ff ff ff 	cmp    %rax,-0xb0(%rbp)
    95b3:	0f 87 58 01 00 00    	ja     9711 <dlmalloc+0x969>
      size_t rsize = gm->dvsize - nb;
    95b9:	48 8b 05 a8 7b 00 00 	mov    0x7ba8(%rip),%rax        # 11168 <_gm_+0x8>
    95c0:	48 2b 85 50 ff ff ff 	sub    -0xb0(%rbp),%rax
    95c7:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
      mchunkptr p = gm->dv;
    95cb:	48 8b 05 ae 7b 00 00 	mov    0x7bae(%rip),%rax        # 11180 <_gm_+0x20>
    95d2:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
      if (rsize >= MIN_CHUNK_SIZE) { /* split dv */
    95d6:	48 83 7d d0 1f       	cmpq   $0x1f,-0x30(%rbp)
    95db:	0f 86 8a 00 00 00    	jbe    966b <dlmalloc+0x8c3>
        mchunkptr r = gm->dv = chunk_plus_offset(p, nb);
    95e1:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    95e5:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    95ec:	48 01 d0             	add    %rdx,%rax
    95ef:	48 89 05 8a 7b 00 00 	mov    %rax,0x7b8a(%rip)        # 11180 <_gm_+0x20>
    95f6:	48 8b 05 83 7b 00 00 	mov    0x7b83(%rip),%rax        # 11180 <_gm_+0x20>
    95fd:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
        gm->dvsize = rsize;
    9601:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    9605:	48 89 05 5c 7b 00 00 	mov    %rax,0x7b5c(%rip)        # 11168 <_gm_+0x8>
        set_size_and_pinuse_of_free_chunk(r, rsize);
    960c:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    9610:	48 83 c8 01          	or     $0x1,%rax
    9614:	48 89 c2             	mov    %rax,%rdx
    9617:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    961b:	48 89 50 08          	mov    %rdx,0x8(%rax)
    961f:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    9623:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    9627:	48 01 c2             	add    %rax,%rdx
    962a:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    962e:	48 89 02             	mov    %rax,(%rdx)
        set_size_and_pinuse_of_inuse_chunk(gm, p, nb);
    9631:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    9638:	48 83 c8 03          	or     $0x3,%rax
    963c:	48 89 c2             	mov    %rax,%rdx
    963f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    9643:	48 89 50 08          	mov    %rdx,0x8(%rax)
    9647:	48 8b 0d d2 7a 00 00 	mov    0x7ad2(%rip),%rcx        # 11120 <mparams>
    964e:	48 8d 15 0b 7b 00 00 	lea    0x7b0b(%rip),%rdx        # 11160 <_gm_>
    9655:	48 8b 75 d8          	mov    -0x28(%rbp),%rsi
    9659:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    9660:	48 01 f0             	add    %rsi,%rax
    9663:	48 31 ca             	xor    %rcx,%rdx
    9666:	48 89 10             	mov    %rdx,(%rax)
    9669:	eb 75                	jmp    96e0 <dlmalloc+0x938>
      }
      else { /* exhaust dv */
        size_t dvs = gm->dvsize;
    966b:	48 8b 05 f6 7a 00 00 	mov    0x7af6(%rip),%rax        # 11168 <_gm_+0x8>
    9672:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
        gm->dvsize = 0;
    9676:	48 c7 05 e7 7a 00 00 	movq   $0x0,0x7ae7(%rip)        # 11168 <_gm_+0x8>
    967d:	00 00 00 00 
        gm->dv = 0;
    9681:	48 c7 05 f4 7a 00 00 	movq   $0x0,0x7af4(%rip)        # 11180 <_gm_+0x20>
    9688:	00 00 00 00 
        set_inuse_and_pinuse(gm, p, dvs);
    968c:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    9690:	48 83 c8 03          	or     $0x3,%rax
    9694:	48 89 c2             	mov    %rax,%rdx
    9697:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    969b:	48 89 50 08          	mov    %rdx,0x8(%rax)
    969f:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    96a3:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    96a7:	48 01 d0             	add    %rdx,%rax
    96aa:	48 8b 50 08          	mov    0x8(%rax),%rdx
    96ae:	48 8b 4d d8          	mov    -0x28(%rbp),%rcx
    96b2:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    96b6:	48 01 c8             	add    %rcx,%rax
    96b9:	48 83 ca 01          	or     $0x1,%rdx
    96bd:	48 89 50 08          	mov    %rdx,0x8(%rax)
    96c1:	48 8b 0d 58 7a 00 00 	mov    0x7a58(%rip),%rcx        # 11120 <mparams>
    96c8:	48 8d 15 91 7a 00 00 	lea    0x7a91(%rip),%rdx        # 11160 <_gm_>
    96cf:	48 8b 75 d8          	mov    -0x28(%rbp),%rsi
    96d3:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    96d7:	48 01 f0             	add    %rsi,%rax
    96da:	48 31 ca             	xor    %rcx,%rdx
    96dd:	48 89 10             	mov    %rdx,(%rax)
      }
      mem = chunk2mem(p);
    96e0:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    96e4:	48 83 c0 10          	add    $0x10,%rax
    96e8:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
      check_malloced_chunk(gm, mem, nb);
    96ef:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    96f6:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    96fd:	48 89 c6             	mov    %rax,%rsi
    9700:	48 8d 3d 59 7a 00 00 	lea    0x7a59(%rip),%rdi        # 11160 <_gm_>
    9707:	e8 9a c1 ff ff       	callq  58a6 <do_check_malloced_chunk>
      goto postaction;
    970c:	e9 0b 01 00 00       	jmpq   981c <dlmalloc+0xa74>
    }

    else if (nb < gm->topsize) { /* Split top */
    9711:	48 8b 05 58 7a 00 00 	mov    0x7a58(%rip),%rax        # 11170 <_gm_+0x10>
    9718:	48 39 85 50 ff ff ff 	cmp    %rax,-0xb0(%rbp)
    971f:	0f 83 da 00 00 00    	jae    97ff <dlmalloc+0xa57>
      size_t rsize = gm->topsize -= nb;
    9725:	48 8b 05 44 7a 00 00 	mov    0x7a44(%rip),%rax        # 11170 <_gm_+0x10>
    972c:	48 2b 85 50 ff ff ff 	sub    -0xb0(%rbp),%rax
    9733:	48 89 05 36 7a 00 00 	mov    %rax,0x7a36(%rip)        # 11170 <_gm_+0x10>
    973a:	48 8b 05 2f 7a 00 00 	mov    0x7a2f(%rip),%rax        # 11170 <_gm_+0x10>
    9741:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
      mchunkptr p = gm->top;
    9745:	48 8b 05 3c 7a 00 00 	mov    0x7a3c(%rip),%rax        # 11188 <_gm_+0x28>
    974c:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
      mchunkptr r = gm->top = chunk_plus_offset(p, nb);
    9750:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    9754:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    975b:	48 01 d0             	add    %rdx,%rax
    975e:	48 89 05 23 7a 00 00 	mov    %rax,0x7a23(%rip)        # 11188 <_gm_+0x28>
    9765:	48 8b 05 1c 7a 00 00 	mov    0x7a1c(%rip),%rax        # 11188 <_gm_+0x28>
    976c:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
      r->head = rsize | PINUSE_BIT;
    9770:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    9774:	48 83 c8 01          	or     $0x1,%rax
    9778:	48 89 c2             	mov    %rax,%rdx
    977b:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    977f:	48 89 50 08          	mov    %rdx,0x8(%rax)
      set_size_and_pinuse_of_inuse_chunk(gm, p, nb);
    9783:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    978a:	48 83 c8 03          	or     $0x3,%rax
    978e:	48 89 c2             	mov    %rax,%rdx
    9791:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    9795:	48 89 50 08          	mov    %rdx,0x8(%rax)
    9799:	48 8b 0d 80 79 00 00 	mov    0x7980(%rip),%rcx        # 11120 <mparams>
    97a0:	48 8d 15 b9 79 00 00 	lea    0x79b9(%rip),%rdx        # 11160 <_gm_>
    97a7:	48 8b 75 c0          	mov    -0x40(%rbp),%rsi
    97ab:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    97b2:	48 01 f0             	add    %rsi,%rax
    97b5:	48 31 ca             	xor    %rcx,%rdx
    97b8:	48 89 10             	mov    %rdx,(%rax)
      mem = chunk2mem(p);
    97bb:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    97bf:	48 83 c0 10          	add    $0x10,%rax
    97c3:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
      check_top_chunk(gm, gm->top);
    97ca:	48 8b 05 b7 79 00 00 	mov    0x79b7(%rip),%rax        # 11188 <_gm_+0x28>
    97d1:	48 89 c6             	mov    %rax,%rsi
    97d4:	48 8d 3d 85 79 00 00 	lea    0x7985(%rip),%rdi        # 11160 <_gm_>
    97db:	e8 35 bd ff ff       	callq  5515 <do_check_top_chunk>
      check_malloced_chunk(gm, mem, nb);
    97e0:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    97e7:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    97ee:	48 89 c6             	mov    %rax,%rsi
    97f1:	48 8d 3d 68 79 00 00 	lea    0x7968(%rip),%rdi        # 11160 <_gm_>
    97f8:	e8 a9 c0 ff ff       	callq  58a6 <do_check_malloced_chunk>
      goto postaction;
    97fd:	eb 1d                	jmp    981c <dlmalloc+0xa74>
    }

    mem = sys_alloc(gm, nb);
    97ff:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    9806:	48 89 c6             	mov    %rax,%rsi
    9809:	48 8d 3d 50 79 00 00 	lea    0x7950(%rip),%rdi        # 11160 <_gm_>
    9810:	e8 e8 d5 ff ff       	callq  6dfd <sys_alloc>
    9815:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)

  postaction:
    if (mem != 0 && !ok_heap_range(mem, bytes)) ABORT;
    981c:	48 83 bd 48 ff ff ff 	cmpq   $0x0,-0xb8(%rbp)
    9823:	00 
    9824:	74 49                	je     986f <dlmalloc+0xac7>
    9826:	e8 cf a0 ff ff       	callq  38fa <get_heap_base>
    982b:	48 39 85 48 ff ff ff 	cmp    %rax,-0xb8(%rbp)
    9832:	72 36                	jb     986a <dlmalloc+0xac2>
    9834:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    983b:	48 f7 d0             	not    %rax
    983e:	48 39 85 18 ff ff ff 	cmp    %rax,-0xe8(%rbp)
    9845:	77 23                	ja     986a <dlmalloc+0xac2>
    9847:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    984e:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    9855:	48 01 d0             	add    %rdx,%rax
    9858:	48 89 c3             	mov    %rax,%rbx
    985b:	bf 00 00 00 00       	mov    $0x0,%edi
    9860:	e8 99 18 00 00       	callq  b0fe <sbrk>
    9865:	48 39 c3             	cmp    %rax,%rbx
    9868:	76 05                	jbe    986f <dlmalloc+0xac7>
    986a:	e8 5f 31 00 00       	callq  c9ce <abort>
    POSTACTION(gm);
    986f:	8b 05 5b 7c 00 00    	mov    0x7c5b(%rip),%eax        # 114d0 <_gm_+0x370>
    9875:	83 e0 02             	and    $0x2,%eax
    9878:	85 c0                	test   %eax,%eax
    987a:	74 0b                	je     9887 <dlmalloc+0xadf>
    987c:	b8 00 00 00 00       	mov    $0x0,%eax
    9881:	89 05 4d 7c 00 00    	mov    %eax,0x7c4d(%rip)        # 114d4 <_gm_+0x374>
    return mem;
    9887:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    988e:	eb 05                	jmp    9895 <dlmalloc+0xaed>
  }

  return 0;
    9890:	b8 00 00 00 00       	mov    $0x0,%eax
}
    9895:	48 81 c4 e8 00 00 00 	add    $0xe8,%rsp
    989c:	5b                   	pop    %rbx
    989d:	5d                   	pop    %rbp
    989e:	c3                   	retq   

000000000000989f <dlfree>:

/* ---------------------------- free --------------------------- */

void dlfree(void* mem) {
    989f:	55                   	push   %rbp
    98a0:	48 89 e5             	mov    %rsp,%rbp
    98a3:	48 81 ec 60 01 00 00 	sub    $0x160,%rsp
    98aa:	48 89 bd a8 fe ff ff 	mov    %rdi,-0x158(%rbp)
     Consolidate freed chunks with preceeding or succeeding bordering
     free chunks, if they exist, and then place in a bin.  Intermixed
     with special cases for top, dv, mmapped chunks, and usage errors.
  */

  if (mem != 0) {
    98b1:	48 83 bd a8 fe ff ff 	cmpq   $0x0,-0x158(%rbp)
    98b8:	00 
    98b9:	0f 84 ff 14 00 00    	je     adbe <dlfree+0x151f>
    mchunkptr p  = mem2chunk(mem);
    98bf:	48 8b 85 a8 fe ff ff 	mov    -0x158(%rbp),%rax
    98c6:	48 83 e8 10          	sub    $0x10,%rax
    98ca:	48 89 85 c8 fe ff ff 	mov    %rax,-0x138(%rbp)
#if FOOTERS
    mstate fm = get_mstate_for(p);
    98d1:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    98d8:	48 8b 40 08          	mov    0x8(%rax),%rax
    98dc:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    98e0:	48 89 c2             	mov    %rax,%rdx
    98e3:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    98ea:	48 01 d0             	add    %rdx,%rax
    98ed:	48 8b 10             	mov    (%rax),%rdx
    98f0:	48 8b 05 29 78 00 00 	mov    0x7829(%rip),%rax        # 11120 <mparams>
    98f7:	48 31 d0             	xor    %rdx,%rax
    98fa:	48 89 85 20 ff ff ff 	mov    %rax,-0xe0(%rbp)
    if (!ok_magic(fm)) {
    9901:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9908:	48 8b 50 40          	mov    0x40(%rax),%rdx
    990c:	48 8b 05 0d 78 00 00 	mov    0x780d(%rip),%rax        # 11120 <mparams>
    9913:	48 39 c2             	cmp    %rax,%rdx
    9916:	74 05                	je     991d <dlfree+0x7e>
      USAGE_ERROR_ACTION(fm, p);
    9918:	e8 b1 30 00 00       	callq  c9ce <abort>
      return;
    }
#else /* FOOTERS */
#define fm gm
#endif /* FOOTERS */
    if (!PREACTION(fm)) {
    991d:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9924:	8b 80 70 03 00 00    	mov    0x370(%rax),%eax
    992a:	83 e0 02             	and    $0x2,%eax
    992d:	85 c0                	test   %eax,%eax
    992f:	74 36                	je     9967 <dlfree+0xc8>
    9931:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9938:	48 8d 90 74 03 00 00 	lea    0x374(%rax),%rdx
    993f:	b8 01 00 00 00       	mov    $0x1,%eax
    9944:	87 02                	xchg   %eax,(%rdx)
    9946:	85 c0                	test   %eax,%eax
    9948:	74 1d                	je     9967 <dlfree+0xc8>
    994a:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9951:	48 05 74 03 00 00    	add    $0x374,%rax
    9957:	48 89 c7             	mov    %rax,%rdi
    995a:	e8 a0 b9 ff ff       	callq  52ff <spin_acquire_lock>
    995f:	85 c0                	test   %eax,%eax
    9961:	0f 85 57 14 00 00    	jne    adbe <dlfree+0x151f>
      check_inuse_chunk(fm, p);
    9967:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    996e:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9975:	48 89 d6             	mov    %rdx,%rsi
    9978:	48 89 c7             	mov    %rax,%rdi
    997b:	e8 df bc ff ff       	callq  565f <do_check_inuse_chunk>
      if (RTCHECK(ok_address(fm, p) && ok_inuse(p))) {
    9980:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9987:	48 8b 40 18          	mov    0x18(%rax),%rax
    998b:	48 39 85 c8 fe ff ff 	cmp    %rax,-0x138(%rbp)
    9992:	0f 93 c0             	setae  %al
    9995:	0f b6 c0             	movzbl %al,%eax
    9998:	48 85 c0             	test   %rax,%rax
    999b:	0f 84 e8 13 00 00    	je     ad89 <dlfree+0x14ea>
    99a1:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    99a8:	48 8b 40 08          	mov    0x8(%rax),%rax
    99ac:	83 e0 03             	and    $0x3,%eax
    99af:	48 83 f8 01          	cmp    $0x1,%rax
    99b3:	0f 95 c0             	setne  %al
    99b6:	0f b6 c0             	movzbl %al,%eax
    99b9:	48 85 c0             	test   %rax,%rax
    99bc:	0f 84 c7 13 00 00    	je     ad89 <dlfree+0x14ea>
        size_t psize = chunksize(p);
    99c2:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    99c9:	48 8b 40 08          	mov    0x8(%rax),%rax
    99cd:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    99d1:	48 89 85 d0 fe ff ff 	mov    %rax,-0x130(%rbp)
        mchunkptr next = chunk_plus_offset(p, psize);
    99d8:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    99df:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    99e6:	48 01 d0             	add    %rdx,%rax
    99e9:	48 89 85 28 ff ff ff 	mov    %rax,-0xd8(%rbp)
        if (!pinuse(p)) {
    99f0:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    99f7:	48 8b 40 08          	mov    0x8(%rax),%rax
    99fb:	83 e0 01             	and    $0x1,%eax
    99fe:	48 85 c0             	test   %rax,%rax
    9a01:	0f 85 3a 07 00 00    	jne    a141 <dlfree+0x8a2>
          size_t prevsize = p->prev_foot;
    9a07:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9a0e:	48 8b 00             	mov    (%rax),%rax
    9a11:	48 89 85 30 ff ff ff 	mov    %rax,-0xd0(%rbp)
          if (is_mmapped(p)) {
    9a18:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9a1f:	48 8b 40 08          	mov    0x8(%rax),%rax
    9a23:	83 e0 03             	and    $0x3,%eax
    9a26:	48 85 c0             	test   %rax,%rax
    9a29:	75 21                	jne    9a4c <dlfree+0x1ad>
            psize += prevsize + MMAP_FOOT_PAD;
    9a2b:	48 8b 95 30 ff ff ff 	mov    -0xd0(%rbp),%rdx
    9a32:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    9a39:	48 01 d0             	add    %rdx,%rax
    9a3c:	48 83 c0 20          	add    $0x20,%rax
    9a40:	48 89 85 d0 fe ff ff 	mov    %rax,-0x130(%rbp)
            if (CALL_MUNMAP((char*)p - prevsize, psize) == 0)
              fm->footprint -= psize;
            goto postaction;
    9a47:	e9 4a 13 00 00       	jmpq   ad96 <dlfree+0x14f7>
          }
          else {
            mchunkptr prev = chunk_minus_offset(p, prevsize);
    9a4c:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    9a53:	48 f7 d8             	neg    %rax
    9a56:	48 89 c2             	mov    %rax,%rdx
    9a59:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9a60:	48 01 d0             	add    %rdx,%rax
    9a63:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
            psize += prevsize;
    9a6a:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    9a71:	48 01 85 d0 fe ff ff 	add    %rax,-0x130(%rbp)
            p = prev;
    9a78:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    9a7f:	48 89 85 c8 fe ff ff 	mov    %rax,-0x138(%rbp)
            if (RTCHECK(ok_address(fm, prev))) { /* consolidate backward */
    9a86:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9a8d:	48 8b 40 18          	mov    0x18(%rax),%rax
    9a91:	48 39 85 38 ff ff ff 	cmp    %rax,-0xc8(%rbp)
    9a98:	0f 93 c0             	setae  %al
    9a9b:	0f b6 c0             	movzbl %al,%eax
    9a9e:	48 85 c0             	test   %rax,%rax
    9aa1:	0f 84 e5 12 00 00    	je     ad8c <dlfree+0x14ed>
              if (p != fm->dv) {
    9aa7:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9aae:	48 8b 40 20          	mov    0x20(%rax),%rax
    9ab2:	48 39 85 c8 fe ff ff 	cmp    %rax,-0x138(%rbp)
    9ab9:	0f 84 06 06 00 00    	je     a0c5 <dlfree+0x826>
                unlink_chunk(fm, p, prevsize);
    9abf:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    9ac6:	48 c1 e8 03          	shr    $0x3,%rax
    9aca:	48 83 f8 1f          	cmp    $0x1f,%rax
    9ace:	0f 87 f9 01 00 00    	ja     9ccd <dlfree+0x42e>
    9ad4:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9adb:	48 8b 40 10          	mov    0x10(%rax),%rax
    9adf:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
    9ae6:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9aed:	48 8b 40 18          	mov    0x18(%rax),%rax
    9af1:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
    9af8:	48 8b 85 30 ff ff ff 	mov    -0xd0(%rbp),%rax
    9aff:	48 c1 e8 03          	shr    $0x3,%rax
    9b03:	89 85 b4 fe ff ff    	mov    %eax,-0x14c(%rbp)
    9b09:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9b10:	48 3b 85 78 ff ff ff 	cmp    -0x88(%rbp),%rax
    9b17:	75 05                	jne    9b1e <dlfree+0x27f>
    9b19:	e8 b0 2e 00 00       	callq  c9ce <abort>
    9b1e:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9b25:	48 3b 85 70 ff ff ff 	cmp    -0x90(%rbp),%rax
    9b2c:	75 05                	jne    9b33 <dlfree+0x294>
    9b2e:	e8 9b 2e 00 00       	callq  c9ce <abort>
    9b33:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9b3a:	48 8b 40 08          	mov    0x8(%rax),%rax
    9b3e:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    9b42:	48 89 c2             	mov    %rax,%rdx
    9b45:	8b 85 b4 fe ff ff    	mov    -0x14c(%rbp),%eax
    9b4b:	c1 e0 03             	shl    $0x3,%eax
    9b4e:	89 c0                	mov    %eax,%eax
    9b50:	48 39 c2             	cmp    %rax,%rdx
    9b53:	74 05                	je     9b5a <dlfree+0x2bb>
    9b55:	e8 74 2e 00 00       	callq  c9ce <abort>
    9b5a:	8b 85 b4 fe ff ff    	mov    -0x14c(%rbp),%eax
    9b60:	01 c0                	add    %eax,%eax
    9b62:	89 c0                	mov    %eax,%eax
    9b64:	48 83 c0 08          	add    $0x8,%rax
    9b68:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    9b6f:	00 
    9b70:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9b77:	48 01 d0             	add    %rdx,%rax
    9b7a:	48 83 c0 08          	add    $0x8,%rax
    9b7e:	48 39 85 70 ff ff ff 	cmp    %rax,-0x90(%rbp)
    9b85:	0f 94 c0             	sete   %al
    9b88:	0f b6 c0             	movzbl %al,%eax
    9b8b:	48 85 c0             	test   %rax,%rax
    9b8e:	75 4e                	jne    9bde <dlfree+0x33f>
    9b90:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9b97:	48 8b 40 18          	mov    0x18(%rax),%rax
    9b9b:	48 39 85 70 ff ff ff 	cmp    %rax,-0x90(%rbp)
    9ba2:	0f 93 c0             	setae  %al
    9ba5:	0f b6 c0             	movzbl %al,%eax
    9ba8:	48 85 c0             	test   %rax,%rax
    9bab:	74 24                	je     9bd1 <dlfree+0x332>
    9bad:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    9bb4:	48 8b 40 18          	mov    0x18(%rax),%rax
    9bb8:	48 39 85 c8 fe ff ff 	cmp    %rax,-0x138(%rbp)
    9bbf:	0f 94 c0             	sete   %al
    9bc2:	0f b6 c0             	movzbl %al,%eax
    9bc5:	48 85 c0             	test   %rax,%rax
    9bc8:	74 07                	je     9bd1 <dlfree+0x332>
    9bca:	b8 01 00 00 00       	mov    $0x1,%eax
    9bcf:	eb 05                	jmp    9bd6 <dlfree+0x337>
    9bd1:	b8 00 00 00 00       	mov    $0x0,%eax
    9bd6:	85 c0                	test   %eax,%eax
    9bd8:	0f 84 ea 00 00 00    	je     9cc8 <dlfree+0x429>
    9bde:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    9be5:	48 3b 85 70 ff ff ff 	cmp    -0x90(%rbp),%rax
    9bec:	75 2c                	jne    9c1a <dlfree+0x37b>
    9bee:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9bf5:	8b 10                	mov    (%rax),%edx
    9bf7:	8b 85 b4 fe ff ff    	mov    -0x14c(%rbp),%eax
    9bfd:	be 01 00 00 00       	mov    $0x1,%esi
    9c02:	89 c1                	mov    %eax,%ecx
    9c04:	d3 e6                	shl    %cl,%esi
    9c06:	89 f0                	mov    %esi,%eax
    9c08:	f7 d0                	not    %eax
    9c0a:	21 c2                	and    %eax,%edx
    9c0c:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9c13:	89 10                	mov    %edx,(%rax)
    9c15:	e9 27 05 00 00       	jmpq   a141 <dlfree+0x8a2>
    9c1a:	8b 85 b4 fe ff ff    	mov    -0x14c(%rbp),%eax
    9c20:	01 c0                	add    %eax,%eax
    9c22:	89 c0                	mov    %eax,%eax
    9c24:	48 83 c0 08          	add    $0x8,%rax
    9c28:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    9c2f:	00 
    9c30:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9c37:	48 01 d0             	add    %rdx,%rax
    9c3a:	48 83 c0 08          	add    $0x8,%rax
    9c3e:	48 39 85 78 ff ff ff 	cmp    %rax,-0x88(%rbp)
    9c45:	0f 94 c0             	sete   %al
    9c48:	0f b6 c0             	movzbl %al,%eax
    9c4b:	48 85 c0             	test   %rax,%rax
    9c4e:	75 4a                	jne    9c9a <dlfree+0x3fb>
    9c50:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9c57:	48 8b 40 18          	mov    0x18(%rax),%rax
    9c5b:	48 39 85 78 ff ff ff 	cmp    %rax,-0x88(%rbp)
    9c62:	0f 93 c0             	setae  %al
    9c65:	0f b6 c0             	movzbl %al,%eax
    9c68:	48 85 c0             	test   %rax,%rax
    9c6b:	74 24                	je     9c91 <dlfree+0x3f2>
    9c6d:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    9c74:	48 8b 40 10          	mov    0x10(%rax),%rax
    9c78:	48 39 85 c8 fe ff ff 	cmp    %rax,-0x138(%rbp)
    9c7f:	0f 94 c0             	sete   %al
    9c82:	0f b6 c0             	movzbl %al,%eax
    9c85:	48 85 c0             	test   %rax,%rax
    9c88:	74 07                	je     9c91 <dlfree+0x3f2>
    9c8a:	b8 01 00 00 00       	mov    $0x1,%eax
    9c8f:	eb 05                	jmp    9c96 <dlfree+0x3f7>
    9c91:	b8 00 00 00 00       	mov    $0x0,%eax
    9c96:	85 c0                	test   %eax,%eax
    9c98:	74 29                	je     9cc3 <dlfree+0x424>
    9c9a:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
    9ca1:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
    9ca8:	48 89 50 18          	mov    %rdx,0x18(%rax)
    9cac:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    9cb3:	48 8b 95 70 ff ff ff 	mov    -0x90(%rbp),%rdx
    9cba:	48 89 50 10          	mov    %rdx,0x10(%rax)
    9cbe:	e9 7e 04 00 00       	jmpq   a141 <dlfree+0x8a2>
    9cc3:	e8 06 2d 00 00       	callq  c9ce <abort>
    9cc8:	e8 01 2d 00 00       	callq  c9ce <abort>
    9ccd:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    9cd4:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
    9cdb:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9ce2:	48 8b 40 30          	mov    0x30(%rax),%rax
    9ce6:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    9ced:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9cf4:	48 8b 40 18          	mov    0x18(%rax),%rax
    9cf8:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    9cff:	0f 84 b9 00 00 00    	je     9dbe <dlfree+0x51f>
    9d05:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9d0c:	48 8b 40 10          	mov    0x10(%rax),%rax
    9d10:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    9d17:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9d1e:	48 8b 40 18          	mov    0x18(%rax),%rax
    9d22:	48 89 85 d8 fe ff ff 	mov    %rax,-0x128(%rbp)
    9d29:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9d30:	48 8b 40 18          	mov    0x18(%rax),%rax
    9d34:	48 39 85 50 ff ff ff 	cmp    %rax,-0xb0(%rbp)
    9d3b:	0f 93 c0             	setae  %al
    9d3e:	0f b6 c0             	movzbl %al,%eax
    9d41:	48 85 c0             	test   %rax,%rax
    9d44:	74 24                	je     9d6a <dlfree+0x4cb>
    9d46:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    9d4d:	48 8b 40 18          	mov    0x18(%rax),%rax
    9d51:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    9d58:	0f 94 c0             	sete   %al
    9d5b:	0f b6 c0             	movzbl %al,%eax
    9d5e:	48 85 c0             	test   %rax,%rax
    9d61:	74 07                	je     9d6a <dlfree+0x4cb>
    9d63:	b8 01 00 00 00       	mov    $0x1,%eax
    9d68:	eb 05                	jmp    9d6f <dlfree+0x4d0>
    9d6a:	b8 00 00 00 00       	mov    $0x0,%eax
    9d6f:	85 c0                	test   %eax,%eax
    9d71:	74 46                	je     9db9 <dlfree+0x51a>
    9d73:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    9d7a:	48 8b 40 10          	mov    0x10(%rax),%rax
    9d7e:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    9d85:	0f 94 c0             	sete   %al
    9d88:	0f b6 c0             	movzbl %al,%eax
    9d8b:	48 85 c0             	test   %rax,%rax
    9d8e:	74 29                	je     9db9 <dlfree+0x51a>
    9d90:	48 8b 85 50 ff ff ff 	mov    -0xb0(%rbp),%rax
    9d97:	48 8b 95 d8 fe ff ff 	mov    -0x128(%rbp),%rdx
    9d9e:	48 89 50 18          	mov    %rdx,0x18(%rax)
    9da2:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    9da9:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    9db0:	48 89 50 10          	mov    %rdx,0x10(%rax)
    9db4:	e9 f8 00 00 00       	jmpq   9eb1 <dlfree+0x612>
    9db9:	e8 10 2c 00 00       	callq  c9ce <abort>
    9dbe:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9dc5:	48 83 c0 28          	add    $0x28,%rax
    9dc9:	48 89 85 e0 fe ff ff 	mov    %rax,-0x120(%rbp)
    9dd0:	48 8b 85 e0 fe ff ff 	mov    -0x120(%rbp),%rax
    9dd7:	48 8b 00             	mov    (%rax),%rax
    9dda:	48 89 85 d8 fe ff ff 	mov    %rax,-0x128(%rbp)
    9de1:	48 83 bd d8 fe ff ff 	cmpq   $0x0,-0x128(%rbp)
    9de8:	00 
    9de9:	75 52                	jne    9e3d <dlfree+0x59e>
    9deb:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9df2:	48 83 c0 20          	add    $0x20,%rax
    9df6:	48 89 85 e0 fe ff ff 	mov    %rax,-0x120(%rbp)
    9dfd:	48 8b 85 e0 fe ff ff 	mov    -0x120(%rbp),%rax
    9e04:	48 8b 00             	mov    (%rax),%rax
    9e07:	48 89 85 d8 fe ff ff 	mov    %rax,-0x128(%rbp)
    9e0e:	48 83 bd d8 fe ff ff 	cmpq   $0x0,-0x128(%rbp)
    9e15:	00 
    9e16:	0f 84 95 00 00 00    	je     9eb1 <dlfree+0x612>
    9e1c:	eb 1f                	jmp    9e3d <dlfree+0x59e>
    9e1e:	48 8b 85 e8 fe ff ff 	mov    -0x118(%rbp),%rax
    9e25:	48 89 85 e0 fe ff ff 	mov    %rax,-0x120(%rbp)
    9e2c:	48 8b 85 e0 fe ff ff 	mov    -0x120(%rbp),%rax
    9e33:	48 8b 00             	mov    (%rax),%rax
    9e36:	48 89 85 d8 fe ff ff 	mov    %rax,-0x128(%rbp)
    9e3d:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    9e44:	48 83 c0 28          	add    $0x28,%rax
    9e48:	48 89 85 e8 fe ff ff 	mov    %rax,-0x118(%rbp)
    9e4f:	48 8b 85 e8 fe ff ff 	mov    -0x118(%rbp),%rax
    9e56:	48 8b 00             	mov    (%rax),%rax
    9e59:	48 85 c0             	test   %rax,%rax
    9e5c:	75 c0                	jne    9e1e <dlfree+0x57f>
    9e5e:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    9e65:	48 83 c0 20          	add    $0x20,%rax
    9e69:	48 89 85 e8 fe ff ff 	mov    %rax,-0x118(%rbp)
    9e70:	48 8b 85 e8 fe ff ff 	mov    -0x118(%rbp),%rax
    9e77:	48 8b 00             	mov    (%rax),%rax
    9e7a:	48 85 c0             	test   %rax,%rax
    9e7d:	75 9f                	jne    9e1e <dlfree+0x57f>
    9e7f:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9e86:	48 8b 40 18          	mov    0x18(%rax),%rax
    9e8a:	48 39 85 e0 fe ff ff 	cmp    %rax,-0x120(%rbp)
    9e91:	0f 93 c0             	setae  %al
    9e94:	0f b6 c0             	movzbl %al,%eax
    9e97:	48 85 c0             	test   %rax,%rax
    9e9a:	74 10                	je     9eac <dlfree+0x60d>
    9e9c:	48 8b 85 e0 fe ff ff 	mov    -0x120(%rbp),%rax
    9ea3:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    9eaa:	eb 05                	jmp    9eb1 <dlfree+0x612>
    9eac:	e8 1d 2b 00 00       	callq  c9ce <abort>
    9eb1:	48 83 bd 48 ff ff ff 	cmpq   $0x0,-0xb8(%rbp)
    9eb8:	00 
    9eb9:	0f 84 82 02 00 00    	je     a141 <dlfree+0x8a2>
    9ebf:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9ec6:	8b 40 38             	mov    0x38(%rax),%eax
    9ec9:	89 c0                	mov    %eax,%eax
    9ecb:	48 83 c0 4a          	add    $0x4a,%rax
    9ecf:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    9ed6:	00 
    9ed7:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9ede:	48 01 d0             	add    %rdx,%rax
    9ee1:	48 83 c0 08          	add    $0x8,%rax
    9ee5:	48 89 85 58 ff ff ff 	mov    %rax,-0xa8(%rbp)
    9eec:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    9ef3:	48 8b 00             	mov    (%rax),%rax
    9ef6:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    9efd:	75 53                	jne    9f52 <dlfree+0x6b3>
    9eff:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    9f06:	48 8b 95 d8 fe ff ff 	mov    -0x128(%rbp),%rdx
    9f0d:	48 89 10             	mov    %rdx,(%rax)
    9f10:	48 8b 85 58 ff ff ff 	mov    -0xa8(%rbp),%rax
    9f17:	48 8b 00             	mov    (%rax),%rax
    9f1a:	48 85 c0             	test   %rax,%rax
    9f1d:	0f 85 8d 00 00 00    	jne    9fb0 <dlfree+0x711>
    9f23:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9f2a:	8b 50 04             	mov    0x4(%rax),%edx
    9f2d:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9f34:	8b 40 38             	mov    0x38(%rax),%eax
    9f37:	be 01 00 00 00       	mov    $0x1,%esi
    9f3c:	89 c1                	mov    %eax,%ecx
    9f3e:	d3 e6                	shl    %cl,%esi
    9f40:	89 f0                	mov    %esi,%eax
    9f42:	f7 d0                	not    %eax
    9f44:	21 c2                	and    %eax,%edx
    9f46:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9f4d:	89 50 04             	mov    %edx,0x4(%rax)
    9f50:	eb 5e                	jmp    9fb0 <dlfree+0x711>
    9f52:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9f59:	48 8b 40 18          	mov    0x18(%rax),%rax
    9f5d:	48 39 85 48 ff ff ff 	cmp    %rax,-0xb8(%rbp)
    9f64:	0f 93 c0             	setae  %al
    9f67:	0f b6 c0             	movzbl %al,%eax
    9f6a:	48 85 c0             	test   %rax,%rax
    9f6d:	74 3c                	je     9fab <dlfree+0x70c>
    9f6f:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    9f76:	48 8b 40 20          	mov    0x20(%rax),%rax
    9f7a:	48 39 85 40 ff ff ff 	cmp    %rax,-0xc0(%rbp)
    9f81:	75 14                	jne    9f97 <dlfree+0x6f8>
    9f83:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    9f8a:	48 8b 95 d8 fe ff ff 	mov    -0x128(%rbp),%rdx
    9f91:	48 89 50 20          	mov    %rdx,0x20(%rax)
    9f95:	eb 19                	jmp    9fb0 <dlfree+0x711>
    9f97:	48 8b 85 48 ff ff ff 	mov    -0xb8(%rbp),%rax
    9f9e:	48 8b 95 d8 fe ff ff 	mov    -0x128(%rbp),%rdx
    9fa5:	48 89 50 28          	mov    %rdx,0x28(%rax)
    9fa9:	eb 05                	jmp    9fb0 <dlfree+0x711>
    9fab:	e8 1e 2a 00 00       	callq  c9ce <abort>
    9fb0:	48 83 bd d8 fe ff ff 	cmpq   $0x0,-0x128(%rbp)
    9fb7:	00 
    9fb8:	0f 84 83 01 00 00    	je     a141 <dlfree+0x8a2>
    9fbe:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    9fc5:	48 8b 40 18          	mov    0x18(%rax),%rax
    9fc9:	48 39 85 d8 fe ff ff 	cmp    %rax,-0x128(%rbp)
    9fd0:	0f 93 c0             	setae  %al
    9fd3:	0f b6 c0             	movzbl %al,%eax
    9fd6:	48 85 c0             	test   %rax,%rax
    9fd9:	0f 84 e1 00 00 00    	je     a0c0 <dlfree+0x821>
    9fdf:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    9fe6:	48 8b 95 48 ff ff ff 	mov    -0xb8(%rbp),%rdx
    9fed:	48 89 50 30          	mov    %rdx,0x30(%rax)
    9ff1:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    9ff8:	48 8b 40 20          	mov    0x20(%rax),%rax
    9ffc:	48 89 85 60 ff ff ff 	mov    %rax,-0xa0(%rbp)
    a003:	48 83 bd 60 ff ff ff 	cmpq   $0x0,-0xa0(%rbp)
    a00a:	00 
    a00b:	74 48                	je     a055 <dlfree+0x7b6>
    a00d:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a014:	48 8b 40 18          	mov    0x18(%rax),%rax
    a018:	48 39 85 60 ff ff ff 	cmp    %rax,-0xa0(%rbp)
    a01f:	0f 93 c0             	setae  %al
    a022:	0f b6 c0             	movzbl %al,%eax
    a025:	48 85 c0             	test   %rax,%rax
    a028:	74 26                	je     a050 <dlfree+0x7b1>
    a02a:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    a031:	48 8b 95 60 ff ff ff 	mov    -0xa0(%rbp),%rdx
    a038:	48 89 50 20          	mov    %rdx,0x20(%rax)
    a03c:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
    a043:	48 8b 95 d8 fe ff ff 	mov    -0x128(%rbp),%rdx
    a04a:	48 89 50 30          	mov    %rdx,0x30(%rax)
    a04e:	eb 05                	jmp    a055 <dlfree+0x7b6>
    a050:	e8 79 29 00 00       	callq  c9ce <abort>
    a055:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    a05c:	48 8b 40 28          	mov    0x28(%rax),%rax
    a060:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
    a067:	48 83 bd 68 ff ff ff 	cmpq   $0x0,-0x98(%rbp)
    a06e:	00 
    a06f:	0f 84 cc 00 00 00    	je     a141 <dlfree+0x8a2>
    a075:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a07c:	48 8b 40 18          	mov    0x18(%rax),%rax
    a080:	48 39 85 68 ff ff ff 	cmp    %rax,-0x98(%rbp)
    a087:	0f 93 c0             	setae  %al
    a08a:	0f b6 c0             	movzbl %al,%eax
    a08d:	48 85 c0             	test   %rax,%rax
    a090:	74 29                	je     a0bb <dlfree+0x81c>
    a092:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    a099:	48 8b 95 68 ff ff ff 	mov    -0x98(%rbp),%rdx
    a0a0:	48 89 50 28          	mov    %rdx,0x28(%rax)
    a0a4:	48 8b 85 68 ff ff ff 	mov    -0x98(%rbp),%rax
    a0ab:	48 8b 95 d8 fe ff ff 	mov    -0x128(%rbp),%rdx
    a0b2:	48 89 50 30          	mov    %rdx,0x30(%rax)
    a0b6:	e9 86 00 00 00       	jmpq   a141 <dlfree+0x8a2>
    a0bb:	e8 0e 29 00 00       	callq  c9ce <abort>
    a0c0:	e8 09 29 00 00       	callq  c9ce <abort>
              }
              else if ((next->head & INUSE_BITS) == INUSE_BITS) {
    a0c5:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a0cc:	48 8b 40 08          	mov    0x8(%rax),%rax
    a0d0:	83 e0 03             	and    $0x3,%eax
    a0d3:	48 83 f8 03          	cmp    $0x3,%rax
    a0d7:	75 68                	jne    a141 <dlfree+0x8a2>
                fm->dvsize = psize;
    a0d9:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a0e0:	48 8b 95 d0 fe ff ff 	mov    -0x130(%rbp),%rdx
    a0e7:	48 89 50 08          	mov    %rdx,0x8(%rax)
                set_free_with_pinuse(p, psize, next);
    a0eb:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a0f2:	48 8b 40 08          	mov    0x8(%rax),%rax
    a0f6:	48 83 e0 fe          	and    $0xfffffffffffffffe,%rax
    a0fa:	48 89 c2             	mov    %rax,%rdx
    a0fd:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a104:	48 89 50 08          	mov    %rdx,0x8(%rax)
    a108:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a10f:	48 83 c8 01          	or     $0x1,%rax
    a113:	48 89 c2             	mov    %rax,%rdx
    a116:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    a11d:	48 89 50 08          	mov    %rdx,0x8(%rax)
    a121:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a128:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a12f:	48 01 c2             	add    %rax,%rdx
    a132:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a139:	48 89 02             	mov    %rax,(%rdx)
                goto postaction;
    a13c:	e9 55 0c 00 00       	jmpq   ad96 <dlfree+0x14f7>
            else
              goto erroraction;
          }
        }

        if (RTCHECK(ok_next(p, next) && ok_pinuse(next))) {
    a141:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    a148:	48 3b 85 28 ff ff ff 	cmp    -0xd8(%rbp),%rax
    a14f:	0f 92 c0             	setb   %al
    a152:	0f b6 c0             	movzbl %al,%eax
    a155:	48 85 c0             	test   %rax,%rax
    a158:	0f 84 2b 0c 00 00    	je     ad89 <dlfree+0x14ea>
    a15e:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a165:	48 8b 40 08          	mov    0x8(%rax),%rax
    a169:	83 e0 01             	and    $0x1,%eax
    a16c:	48 85 c0             	test   %rax,%rax
    a16f:	0f 95 c0             	setne  %al
    a172:	0f b6 c0             	movzbl %al,%eax
    a175:	48 85 c0             	test   %rax,%rax
    a178:	0f 84 0b 0c 00 00    	je     ad89 <dlfree+0x14ea>
          if (!cinuse(next)) {  /* consolidate forward */
    a17e:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a185:	48 8b 40 08          	mov    0x8(%rax),%rax
    a189:	83 e0 02             	and    $0x2,%eax
    a18c:	48 85 c0             	test   %rax,%rax
    a18f:	0f 85 18 07 00 00    	jne    a8ad <dlfree+0x100e>
            if (next == fm->top) {
    a195:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a19c:	48 8b 40 28          	mov    0x28(%rax),%rax
    a1a0:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    a1a7:	0f 85 b7 00 00 00    	jne    a264 <dlfree+0x9c5>
              size_t tsize = fm->topsize += psize;
    a1ad:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a1b4:	48 8b 50 10          	mov    0x10(%rax),%rdx
    a1b8:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a1bf:	48 01 c2             	add    %rax,%rdx
    a1c2:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a1c9:	48 89 50 10          	mov    %rdx,0x10(%rax)
    a1cd:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a1d4:	48 8b 40 10          	mov    0x10(%rax),%rax
    a1d8:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
              fm->top = p;
    a1dc:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a1e3:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a1ea:	48 89 50 28          	mov    %rdx,0x28(%rax)
              p->head = tsize | PINUSE_BIT;
    a1ee:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    a1f2:	48 83 c8 01          	or     $0x1,%rax
    a1f6:	48 89 c2             	mov    %rax,%rdx
    a1f9:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    a200:	48 89 50 08          	mov    %rdx,0x8(%rax)
              if (p == fm->dv) {
    a204:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a20b:	48 8b 40 20          	mov    0x20(%rax),%rax
    a20f:	48 39 85 c8 fe ff ff 	cmp    %rax,-0x138(%rbp)
    a216:	75 1e                	jne    a236 <dlfree+0x997>
                fm->dv = 0;
    a218:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a21f:	48 c7 40 20 00 00 00 	movq   $0x0,0x20(%rax)
    a226:	00 
                fm->dvsize = 0;
    a227:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a22e:	48 c7 40 08 00 00 00 	movq   $0x0,0x8(%rax)
    a235:	00 
              }
              if (should_trim(fm, tsize))
    a236:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a23d:	48 8b 40 30          	mov    0x30(%rax),%rax
    a241:	48 39 45 d0          	cmp    %rax,-0x30(%rbp)
    a245:	0f 86 47 0b 00 00    	jbe    ad92 <dlfree+0x14f3>
                sys_trim(fm, 0);
    a24b:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a252:	be 00 00 00 00       	mov    $0x0,%esi
    a257:	48 89 c7             	mov    %rax,%rdi
    a25a:	e8 fd d5 ff ff       	callq  785c <sys_trim>
              goto postaction;
    a25f:	e9 2e 0b 00 00       	jmpq   ad92 <dlfree+0x14f3>
            }
            else if (next == fm->dv) {
    a264:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a26b:	48 8b 40 20          	mov    0x20(%rax),%rax
    a26f:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    a276:	75 71                	jne    a2e9 <dlfree+0xa4a>
              size_t dsize = fm->dvsize += psize;
    a278:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a27f:	48 8b 50 08          	mov    0x8(%rax),%rdx
    a283:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a28a:	48 01 c2             	add    %rax,%rdx
    a28d:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a294:	48 89 50 08          	mov    %rdx,0x8(%rax)
    a298:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a29f:	48 8b 40 08          	mov    0x8(%rax),%rax
    a2a3:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
              fm->dv = p;
    a2a7:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a2ae:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a2b5:	48 89 50 20          	mov    %rdx,0x20(%rax)
              set_size_and_pinuse_of_free_chunk(p, dsize);
    a2b9:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    a2bd:	48 83 c8 01          	or     $0x1,%rax
    a2c1:	48 89 c2             	mov    %rax,%rdx
    a2c4:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    a2cb:	48 89 50 08          	mov    %rdx,0x8(%rax)
    a2cf:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a2d6:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    a2da:	48 01 c2             	add    %rax,%rdx
    a2dd:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    a2e1:	48 89 02             	mov    %rax,(%rdx)
              goto postaction;
    a2e4:	e9 ad 0a 00 00       	jmpq   ad96 <dlfree+0x14f7>
            }
            else {
              size_t nsize = chunksize(next);
    a2e9:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a2f0:	48 8b 40 08          	mov    0x8(%rax),%rax
    a2f4:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    a2f8:	48 89 45 80          	mov    %rax,-0x80(%rbp)
              psize += nsize;
    a2fc:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    a300:	48 01 85 d0 fe ff ff 	add    %rax,-0x130(%rbp)
              unlink_chunk(fm, next, nsize);
    a307:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    a30b:	48 c1 e8 03          	shr    $0x3,%rax
    a30f:	48 83 f8 1f          	cmp    $0x1f,%rax
    a313:	0f 87 c6 01 00 00    	ja     a4df <dlfree+0xc40>
    a319:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a320:	48 8b 40 10          	mov    0x10(%rax),%rax
    a324:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    a328:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a32f:	48 8b 40 18          	mov    0x18(%rax),%rax
    a333:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    a337:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    a33b:	48 c1 e8 03          	shr    $0x3,%rax
    a33f:	89 85 b8 fe ff ff    	mov    %eax,-0x148(%rbp)
    a345:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a34c:	48 3b 45 c0          	cmp    -0x40(%rbp),%rax
    a350:	75 05                	jne    a357 <dlfree+0xab8>
    a352:	e8 77 26 00 00       	callq  c9ce <abort>
    a357:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a35e:	48 3b 45 b8          	cmp    -0x48(%rbp),%rax
    a362:	75 05                	jne    a369 <dlfree+0xaca>
    a364:	e8 65 26 00 00       	callq  c9ce <abort>
    a369:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a370:	48 8b 40 08          	mov    0x8(%rax),%rax
    a374:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    a378:	48 89 c2             	mov    %rax,%rdx
    a37b:	8b 85 b8 fe ff ff    	mov    -0x148(%rbp),%eax
    a381:	c1 e0 03             	shl    $0x3,%eax
    a384:	89 c0                	mov    %eax,%eax
    a386:	48 39 c2             	cmp    %rax,%rdx
    a389:	74 05                	je     a390 <dlfree+0xaf1>
    a38b:	e8 3e 26 00 00       	callq  c9ce <abort>
    a390:	8b 85 b8 fe ff ff    	mov    -0x148(%rbp),%eax
    a396:	01 c0                	add    %eax,%eax
    a398:	89 c0                	mov    %eax,%eax
    a39a:	48 83 c0 08          	add    $0x8,%rax
    a39e:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    a3a5:	00 
    a3a6:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a3ad:	48 01 d0             	add    %rdx,%rax
    a3b0:	48 83 c0 08          	add    $0x8,%rax
    a3b4:	48 39 45 b8          	cmp    %rax,-0x48(%rbp)
    a3b8:	0f 94 c0             	sete   %al
    a3bb:	0f b6 c0             	movzbl %al,%eax
    a3be:	48 85 c0             	test   %rax,%rax
    a3c1:	75 48                	jne    a40b <dlfree+0xb6c>
    a3c3:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a3ca:	48 8b 40 18          	mov    0x18(%rax),%rax
    a3ce:	48 39 45 b8          	cmp    %rax,-0x48(%rbp)
    a3d2:	0f 93 c0             	setae  %al
    a3d5:	0f b6 c0             	movzbl %al,%eax
    a3d8:	48 85 c0             	test   %rax,%rax
    a3db:	74 21                	je     a3fe <dlfree+0xb5f>
    a3dd:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    a3e1:	48 8b 40 18          	mov    0x18(%rax),%rax
    a3e5:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    a3ec:	0f 94 c0             	sete   %al
    a3ef:	0f b6 c0             	movzbl %al,%eax
    a3f2:	48 85 c0             	test   %rax,%rax
    a3f5:	74 07                	je     a3fe <dlfree+0xb5f>
    a3f7:	b8 01 00 00 00       	mov    $0x1,%eax
    a3fc:	eb 05                	jmp    a403 <dlfree+0xb64>
    a3fe:	b8 00 00 00 00       	mov    $0x0,%eax
    a403:	85 c0                	test   %eax,%eax
    a405:	0f 84 cf 00 00 00    	je     a4da <dlfree+0xc3b>
    a40b:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    a40f:	48 3b 45 b8          	cmp    -0x48(%rbp),%rax
    a413:	75 2c                	jne    a441 <dlfree+0xba2>
    a415:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a41c:	8b 10                	mov    (%rax),%edx
    a41e:	8b 85 b8 fe ff ff    	mov    -0x148(%rbp),%eax
    a424:	be 01 00 00 00       	mov    $0x1,%esi
    a429:	89 c1                	mov    %eax,%ecx
    a42b:	d3 e6                	shl    %cl,%esi
    a42d:	89 f0                	mov    %esi,%eax
    a42f:	f7 d0                	not    %eax
    a431:	21 c2                	and    %eax,%edx
    a433:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a43a:	89 10                	mov    %edx,(%rax)
    a43c:	e9 0d 04 00 00       	jmpq   a84e <dlfree+0xfaf>
    a441:	8b 85 b8 fe ff ff    	mov    -0x148(%rbp),%eax
    a447:	01 c0                	add    %eax,%eax
    a449:	89 c0                	mov    %eax,%eax
    a44b:	48 83 c0 08          	add    $0x8,%rax
    a44f:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    a456:	00 
    a457:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a45e:	48 01 d0             	add    %rdx,%rax
    a461:	48 83 c0 08          	add    $0x8,%rax
    a465:	48 39 45 c0          	cmp    %rax,-0x40(%rbp)
    a469:	0f 94 c0             	sete   %al
    a46c:	0f b6 c0             	movzbl %al,%eax
    a46f:	48 85 c0             	test   %rax,%rax
    a472:	75 44                	jne    a4b8 <dlfree+0xc19>
    a474:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a47b:	48 8b 40 18          	mov    0x18(%rax),%rax
    a47f:	48 39 45 c0          	cmp    %rax,-0x40(%rbp)
    a483:	0f 93 c0             	setae  %al
    a486:	0f b6 c0             	movzbl %al,%eax
    a489:	48 85 c0             	test   %rax,%rax
    a48c:	74 21                	je     a4af <dlfree+0xc10>
    a48e:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    a492:	48 8b 40 10          	mov    0x10(%rax),%rax
    a496:	48 39 85 28 ff ff ff 	cmp    %rax,-0xd8(%rbp)
    a49d:	0f 94 c0             	sete   %al
    a4a0:	0f b6 c0             	movzbl %al,%eax
    a4a3:	48 85 c0             	test   %rax,%rax
    a4a6:	74 07                	je     a4af <dlfree+0xc10>
    a4a8:	b8 01 00 00 00       	mov    $0x1,%eax
    a4ad:	eb 05                	jmp    a4b4 <dlfree+0xc15>
    a4af:	b8 00 00 00 00       	mov    $0x0,%eax
    a4b4:	85 c0                	test   %eax,%eax
    a4b6:	74 1d                	je     a4d5 <dlfree+0xc36>
    a4b8:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    a4bc:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    a4c0:	48 89 50 18          	mov    %rdx,0x18(%rax)
    a4c4:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    a4c8:	48 8b 55 b8          	mov    -0x48(%rbp),%rdx
    a4cc:	48 89 50 10          	mov    %rdx,0x10(%rax)
    a4d0:	e9 79 03 00 00       	jmpq   a84e <dlfree+0xfaf>
    a4d5:	e8 f4 24 00 00       	callq  c9ce <abort>
    a4da:	e8 ef 24 00 00       	callq  c9ce <abort>
    a4df:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a4e6:	48 89 45 88          	mov    %rax,-0x78(%rbp)
    a4ea:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a4ee:	48 8b 40 30          	mov    0x30(%rax),%rax
    a4f2:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    a4f6:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a4fa:	48 8b 40 18          	mov    0x18(%rax),%rax
    a4fe:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    a502:	0f 84 9e 00 00 00    	je     a5a6 <dlfree+0xd07>
    a508:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a50c:	48 8b 40 10          	mov    0x10(%rax),%rax
    a510:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    a514:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a518:	48 8b 40 18          	mov    0x18(%rax),%rax
    a51c:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    a523:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a52a:	48 8b 40 18          	mov    0x18(%rax),%rax
    a52e:	48 39 45 98          	cmp    %rax,-0x68(%rbp)
    a532:	0f 93 c0             	setae  %al
    a535:	0f b6 c0             	movzbl %al,%eax
    a538:	48 85 c0             	test   %rax,%rax
    a53b:	74 1e                	je     a55b <dlfree+0xcbc>
    a53d:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    a541:	48 8b 40 18          	mov    0x18(%rax),%rax
    a545:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    a549:	0f 94 c0             	sete   %al
    a54c:	0f b6 c0             	movzbl %al,%eax
    a54f:	48 85 c0             	test   %rax,%rax
    a552:	74 07                	je     a55b <dlfree+0xcbc>
    a554:	b8 01 00 00 00       	mov    $0x1,%eax
    a559:	eb 05                	jmp    a560 <dlfree+0xcc1>
    a55b:	b8 00 00 00 00       	mov    $0x0,%eax
    a560:	85 c0                	test   %eax,%eax
    a562:	74 3d                	je     a5a1 <dlfree+0xd02>
    a564:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    a56b:	48 8b 40 10          	mov    0x10(%rax),%rax
    a56f:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    a573:	0f 94 c0             	sete   %al
    a576:	0f b6 c0             	movzbl %al,%eax
    a579:	48 85 c0             	test   %rax,%rax
    a57c:	74 23                	je     a5a1 <dlfree+0xd02>
    a57e:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    a582:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    a589:	48 89 50 18          	mov    %rdx,0x18(%rax)
    a58d:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    a594:	48 8b 55 98          	mov    -0x68(%rbp),%rdx
    a598:	48 89 50 10          	mov    %rdx,0x10(%rax)
    a59c:	e9 f2 00 00 00       	jmpq   a693 <dlfree+0xdf4>
    a5a1:	e8 28 24 00 00       	callq  c9ce <abort>
    a5a6:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a5aa:	48 83 c0 28          	add    $0x28,%rax
    a5ae:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
    a5b5:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    a5bc:	48 8b 00             	mov    (%rax),%rax
    a5bf:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    a5c6:	48 83 bd f0 fe ff ff 	cmpq   $0x0,-0x110(%rbp)
    a5cd:	00 
    a5ce:	75 4f                	jne    a61f <dlfree+0xd80>
    a5d0:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a5d4:	48 83 c0 20          	add    $0x20,%rax
    a5d8:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
    a5df:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    a5e6:	48 8b 00             	mov    (%rax),%rax
    a5e9:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    a5f0:	48 83 bd f0 fe ff ff 	cmpq   $0x0,-0x110(%rbp)
    a5f7:	00 
    a5f8:	0f 84 95 00 00 00    	je     a693 <dlfree+0xdf4>
    a5fe:	eb 1f                	jmp    a61f <dlfree+0xd80>
    a600:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    a607:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
    a60e:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    a615:	48 8b 00             	mov    (%rax),%rax
    a618:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    a61f:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    a626:	48 83 c0 28          	add    $0x28,%rax
    a62a:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
    a631:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    a638:	48 8b 00             	mov    (%rax),%rax
    a63b:	48 85 c0             	test   %rax,%rax
    a63e:	75 c0                	jne    a600 <dlfree+0xd61>
    a640:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    a647:	48 83 c0 20          	add    $0x20,%rax
    a64b:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
    a652:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    a659:	48 8b 00             	mov    (%rax),%rax
    a65c:	48 85 c0             	test   %rax,%rax
    a65f:	75 9f                	jne    a600 <dlfree+0xd61>
    a661:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a668:	48 8b 40 18          	mov    0x18(%rax),%rax
    a66c:	48 39 85 f8 fe ff ff 	cmp    %rax,-0x108(%rbp)
    a673:	0f 93 c0             	setae  %al
    a676:	0f b6 c0             	movzbl %al,%eax
    a679:	48 85 c0             	test   %rax,%rax
    a67c:	74 10                	je     a68e <dlfree+0xdef>
    a67e:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    a685:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
    a68c:	eb 05                	jmp    a693 <dlfree+0xdf4>
    a68e:	e8 3b 23 00 00       	callq  c9ce <abort>
    a693:	48 83 7d 90 00       	cmpq   $0x0,-0x70(%rbp)
    a698:	0f 84 b0 01 00 00    	je     a84e <dlfree+0xfaf>
    a69e:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a6a2:	8b 40 38             	mov    0x38(%rax),%eax
    a6a5:	89 c0                	mov    %eax,%eax
    a6a7:	48 83 c0 4a          	add    $0x4a,%rax
    a6ab:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    a6b2:	00 
    a6b3:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a6ba:	48 01 d0             	add    %rdx,%rax
    a6bd:	48 83 c0 08          	add    $0x8,%rax
    a6c1:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
    a6c5:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    a6c9:	48 8b 00             	mov    (%rax),%rax
    a6cc:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    a6d0:	75 46                	jne    a718 <dlfree+0xe79>
    a6d2:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    a6d6:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    a6dd:	48 89 10             	mov    %rdx,(%rax)
    a6e0:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    a6e4:	48 8b 00             	mov    (%rax),%rax
    a6e7:	48 85 c0             	test   %rax,%rax
    a6ea:	75 7b                	jne    a767 <dlfree+0xec8>
    a6ec:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a6f3:	8b 50 04             	mov    0x4(%rax),%edx
    a6f6:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a6fa:	8b 40 38             	mov    0x38(%rax),%eax
    a6fd:	be 01 00 00 00       	mov    $0x1,%esi
    a702:	89 c1                	mov    %eax,%ecx
    a704:	d3 e6                	shl    %cl,%esi
    a706:	89 f0                	mov    %esi,%eax
    a708:	f7 d0                	not    %eax
    a70a:	21 c2                	and    %eax,%edx
    a70c:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a713:	89 50 04             	mov    %edx,0x4(%rax)
    a716:	eb 4f                	jmp    a767 <dlfree+0xec8>
    a718:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a71f:	48 8b 40 18          	mov    0x18(%rax),%rax
    a723:	48 39 45 90          	cmp    %rax,-0x70(%rbp)
    a727:	0f 93 c0             	setae  %al
    a72a:	0f b6 c0             	movzbl %al,%eax
    a72d:	48 85 c0             	test   %rax,%rax
    a730:	74 30                	je     a762 <dlfree+0xec3>
    a732:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    a736:	48 8b 40 20          	mov    0x20(%rax),%rax
    a73a:	48 39 45 88          	cmp    %rax,-0x78(%rbp)
    a73e:	75 11                	jne    a751 <dlfree+0xeb2>
    a740:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    a744:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    a74b:	48 89 50 20          	mov    %rdx,0x20(%rax)
    a74f:	eb 16                	jmp    a767 <dlfree+0xec8>
    a751:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    a755:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    a75c:	48 89 50 28          	mov    %rdx,0x28(%rax)
    a760:	eb 05                	jmp    a767 <dlfree+0xec8>
    a762:	e8 67 22 00 00       	callq  c9ce <abort>
    a767:	48 83 bd f0 fe ff ff 	cmpq   $0x0,-0x110(%rbp)
    a76e:	00 
    a76f:	0f 84 d9 00 00 00    	je     a84e <dlfree+0xfaf>
    a775:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a77c:	48 8b 40 18          	mov    0x18(%rax),%rax
    a780:	48 39 85 f0 fe ff ff 	cmp    %rax,-0x110(%rbp)
    a787:	0f 93 c0             	setae  %al
    a78a:	0f b6 c0             	movzbl %al,%eax
    a78d:	48 85 c0             	test   %rax,%rax
    a790:	0f 84 b3 00 00 00    	je     a849 <dlfree+0xfaa>
    a796:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    a79d:	48 8b 55 90          	mov    -0x70(%rbp),%rdx
    a7a1:	48 89 50 30          	mov    %rdx,0x30(%rax)
    a7a5:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a7a9:	48 8b 40 20          	mov    0x20(%rax),%rax
    a7ad:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    a7b1:	48 83 7d a8 00       	cmpq   $0x0,-0x58(%rbp)
    a7b6:	74 3f                	je     a7f7 <dlfree+0xf58>
    a7b8:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a7bf:	48 8b 40 18          	mov    0x18(%rax),%rax
    a7c3:	48 39 45 a8          	cmp    %rax,-0x58(%rbp)
    a7c7:	0f 93 c0             	setae  %al
    a7ca:	0f b6 c0             	movzbl %al,%eax
    a7cd:	48 85 c0             	test   %rax,%rax
    a7d0:	74 20                	je     a7f2 <dlfree+0xf53>
    a7d2:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    a7d9:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    a7dd:	48 89 50 20          	mov    %rdx,0x20(%rax)
    a7e1:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    a7e5:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    a7ec:	48 89 50 30          	mov    %rdx,0x30(%rax)
    a7f0:	eb 05                	jmp    a7f7 <dlfree+0xf58>
    a7f2:	e8 d7 21 00 00       	callq  c9ce <abort>
    a7f7:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a7fb:	48 8b 40 28          	mov    0x28(%rax),%rax
    a7ff:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    a803:	48 83 7d b0 00       	cmpq   $0x0,-0x50(%rbp)
    a808:	74 44                	je     a84e <dlfree+0xfaf>
    a80a:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a811:	48 8b 40 18          	mov    0x18(%rax),%rax
    a815:	48 39 45 b0          	cmp    %rax,-0x50(%rbp)
    a819:	0f 93 c0             	setae  %al
    a81c:	0f b6 c0             	movzbl %al,%eax
    a81f:	48 85 c0             	test   %rax,%rax
    a822:	74 20                	je     a844 <dlfree+0xfa5>
    a824:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    a82b:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
    a82f:	48 89 50 28          	mov    %rdx,0x28(%rax)
    a833:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    a837:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    a83e:	48 89 50 30          	mov    %rdx,0x30(%rax)
    a842:	eb 0a                	jmp    a84e <dlfree+0xfaf>
    a844:	e8 85 21 00 00       	callq  c9ce <abort>
    a849:	e8 80 21 00 00       	callq  c9ce <abort>
              set_size_and_pinuse_of_free_chunk(p, psize);
    a84e:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a855:	48 83 c8 01          	or     $0x1,%rax
    a859:	48 89 c2             	mov    %rax,%rdx
    a85c:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    a863:	48 89 50 08          	mov    %rdx,0x8(%rax)
    a867:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a86e:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a875:	48 01 c2             	add    %rax,%rdx
    a878:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a87f:	48 89 02             	mov    %rax,(%rdx)
              if (p == fm->dv) {
    a882:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a889:	48 8b 40 20          	mov    0x20(%rax),%rax
    a88d:	48 39 85 c8 fe ff ff 	cmp    %rax,-0x138(%rbp)
    a894:	75 68                	jne    a8fe <dlfree+0x105f>
                fm->dvsize = psize;
    a896:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a89d:	48 8b 95 d0 fe ff ff 	mov    -0x130(%rbp),%rdx
    a8a4:	48 89 50 08          	mov    %rdx,0x8(%rax)
                goto postaction;
    a8a8:	e9 e9 04 00 00       	jmpq   ad96 <dlfree+0x14f7>
              }
            }
          }
          else
            set_free_with_pinuse(p, psize, next);
    a8ad:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a8b4:	48 8b 40 08          	mov    0x8(%rax),%rax
    a8b8:	48 83 e0 fe          	and    $0xfffffffffffffffe,%rax
    a8bc:	48 89 c2             	mov    %rax,%rdx
    a8bf:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    a8c6:	48 89 50 08          	mov    %rdx,0x8(%rax)
    a8ca:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a8d1:	48 83 c8 01          	or     $0x1,%rax
    a8d5:	48 89 c2             	mov    %rax,%rdx
    a8d8:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    a8df:	48 89 50 08          	mov    %rdx,0x8(%rax)
    a8e3:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a8ea:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a8f1:	48 01 c2             	add    %rax,%rdx
    a8f4:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a8fb:	48 89 02             	mov    %rax,(%rdx)

          if (is_small(psize)) {
    a8fe:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a905:	48 c1 e8 03          	shr    $0x3,%rax
    a909:	48 83 f8 1f          	cmp    $0x1f,%rax
    a90d:	0f 87 31 01 00 00    	ja     aa44 <dlfree+0x11a5>
            insert_small_chunk(fm, p, psize);
    a913:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    a91a:	48 c1 e8 03          	shr    $0x3,%rax
    a91e:	89 85 c4 fe ff ff    	mov    %eax,-0x13c(%rbp)
    a924:	8b 85 c4 fe ff ff    	mov    -0x13c(%rbp),%eax
    a92a:	01 c0                	add    %eax,%eax
    a92c:	89 c0                	mov    %eax,%eax
    a92e:	48 83 c0 08          	add    $0x8,%rax
    a932:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    a939:	00 
    a93a:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a941:	48 01 d0             	add    %rdx,%rax
    a944:	48 83 c0 08          	add    $0x8,%rax
    a948:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    a94c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a950:	48 89 85 08 ff ff ff 	mov    %rax,-0xf8(%rbp)
    a957:	48 83 bd d0 fe ff ff 	cmpq   $0x1f,-0x130(%rbp)
    a95e:	1f 
    a95f:	77 05                	ja     a966 <dlfree+0x10c7>
    a961:	e8 68 20 00 00       	callq  c9ce <abort>
    a966:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a96d:	8b 10                	mov    (%rax),%edx
    a96f:	8b 85 c4 fe ff ff    	mov    -0x13c(%rbp),%eax
    a975:	be 01 00 00 00       	mov    $0x1,%esi
    a97a:	89 c1                	mov    %eax,%ecx
    a97c:	d3 e6                	shl    %cl,%esi
    a97e:	89 f0                	mov    %esi,%eax
    a980:	21 d0                	and    %edx,%eax
    a982:	85 c0                	test   %eax,%eax
    a984:	75 27                	jne    a9ad <dlfree+0x110e>
    a986:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a98d:	8b 10                	mov    (%rax),%edx
    a98f:	8b 85 c4 fe ff ff    	mov    -0x13c(%rbp),%eax
    a995:	be 01 00 00 00       	mov    $0x1,%esi
    a99a:	89 c1                	mov    %eax,%ecx
    a99c:	d3 e6                	shl    %cl,%esi
    a99e:	89 f0                	mov    %esi,%eax
    a9a0:	09 c2                	or     %eax,%edx
    a9a2:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a9a9:	89 10                	mov    %edx,(%rax)
    a9ab:	eb 37                	jmp    a9e4 <dlfree+0x1145>
    a9ad:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a9b1:	48 8b 50 10          	mov    0x10(%rax),%rdx
    a9b5:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    a9bc:	48 8b 40 18          	mov    0x18(%rax),%rax
    a9c0:	48 39 c2             	cmp    %rax,%rdx
    a9c3:	0f 93 c0             	setae  %al
    a9c6:	0f b6 c0             	movzbl %al,%eax
    a9c9:	48 85 c0             	test   %rax,%rax
    a9cc:	74 11                	je     a9df <dlfree+0x1140>
    a9ce:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a9d2:	48 8b 40 10          	mov    0x10(%rax),%rax
    a9d6:	48 89 85 08 ff ff ff 	mov    %rax,-0xf8(%rbp)
    a9dd:	eb 05                	jmp    a9e4 <dlfree+0x1145>
    a9df:	e8 ea 1f 00 00       	callq  c9ce <abort>
    a9e4:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    a9e8:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    a9ef:	48 89 50 10          	mov    %rdx,0x10(%rax)
    a9f3:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    a9fa:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    aa01:	48 89 50 18          	mov    %rdx,0x18(%rax)
    aa05:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    aa0c:	48 8b 95 08 ff ff ff 	mov    -0xf8(%rbp),%rdx
    aa13:	48 89 50 10          	mov    %rdx,0x10(%rax)
    aa17:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    aa1e:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    aa22:	48 89 50 18          	mov    %rdx,0x18(%rax)
            check_free_chunk(fm, p);
    aa26:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    aa2d:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    aa34:	48 89 d6             	mov    %rdx,%rsi
    aa37:	48 89 c7             	mov    %rax,%rdi
    aa3a:	e8 f6 ac ff ff       	callq  5735 <do_check_free_chunk>
            insert_large_chunk(fm, tp, psize);
            check_free_chunk(fm, p);
            if (--fm->release_checks == 0)
              release_unused_segments(fm);
          }
          goto postaction;
    aa3f:	e9 51 03 00 00       	jmpq   ad95 <dlfree+0x14f6>
            tchunkptr tp = (tchunkptr)p;
    aa44:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
    aa4b:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
            insert_large_chunk(fm, tp, psize);
    aa4f:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    aa56:	48 c1 e8 08          	shr    $0x8,%rax
    aa5a:	89 85 bc fe ff ff    	mov    %eax,-0x144(%rbp)
    aa60:	83 bd bc fe ff ff 00 	cmpl   $0x0,-0x144(%rbp)
    aa67:	75 0c                	jne    aa75 <dlfree+0x11d6>
    aa69:	c7 85 b0 fe ff ff 00 	movl   $0x0,-0x150(%rbp)
    aa70:	00 00 00 
    aa73:	eb 5d                	jmp    aad2 <dlfree+0x1233>
    aa75:	81 bd bc fe ff ff ff 	cmpl   $0xffff,-0x144(%rbp)
    aa7c:	ff 00 00 
    aa7f:	76 0c                	jbe    aa8d <dlfree+0x11ee>
    aa81:	c7 85 b0 fe ff ff 1f 	movl   $0x1f,-0x150(%rbp)
    aa88:	00 00 00 
    aa8b:	eb 45                	jmp    aad2 <dlfree+0x1233>
    aa8d:	0f bd 85 bc fe ff ff 	bsr    -0x144(%rbp),%eax
    aa94:	83 f0 1f             	xor    $0x1f,%eax
    aa97:	ba 1f 00 00 00       	mov    $0x1f,%edx
    aa9c:	29 c2                	sub    %eax,%edx
    aa9e:	89 d0                	mov    %edx,%eax
    aaa0:	89 85 c0 fe ff ff    	mov    %eax,-0x140(%rbp)
    aaa6:	8b 85 c0 fe ff ff    	mov    -0x140(%rbp),%eax
    aaac:	8d 34 00             	lea    (%rax,%rax,1),%esi
    aaaf:	8b 85 c0 fe ff ff    	mov    -0x140(%rbp),%eax
    aab5:	83 c0 07             	add    $0x7,%eax
    aab8:	48 8b 95 d0 fe ff ff 	mov    -0x130(%rbp),%rdx
    aabf:	89 c1                	mov    %eax,%ecx
    aac1:	48 d3 ea             	shr    %cl,%rdx
    aac4:	48 89 d0             	mov    %rdx,%rax
    aac7:	83 e0 01             	and    $0x1,%eax
    aaca:	01 f0                	add    %esi,%eax
    aacc:	89 85 b0 fe ff ff    	mov    %eax,-0x150(%rbp)
    aad2:	8b 85 b0 fe ff ff    	mov    -0x150(%rbp),%eax
    aad8:	48 83 c0 4a          	add    $0x4a,%rax
    aadc:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    aae3:	00 
    aae4:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    aaeb:	48 01 d0             	add    %rdx,%rax
    aaee:	48 83 c0 08          	add    $0x8,%rax
    aaf2:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    aaf6:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    aafa:	8b 95 b0 fe ff ff    	mov    -0x150(%rbp),%edx
    ab00:	89 50 38             	mov    %edx,0x38(%rax)
    ab03:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ab07:	48 c7 40 28 00 00 00 	movq   $0x0,0x28(%rax)
    ab0e:	00 
    ab0f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ab13:	48 8b 50 28          	mov    0x28(%rax),%rdx
    ab17:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ab1b:	48 89 50 20          	mov    %rdx,0x20(%rax)
    ab1f:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ab26:	8b 50 04             	mov    0x4(%rax),%edx
    ab29:	8b 85 b0 fe ff ff    	mov    -0x150(%rbp),%eax
    ab2f:	be 01 00 00 00       	mov    $0x1,%esi
    ab34:	89 c1                	mov    %eax,%ecx
    ab36:	d3 e6                	shl    %cl,%esi
    ab38:	89 f0                	mov    %esi,%eax
    ab3a:	21 d0                	and    %edx,%eax
    ab3c:	85 c0                	test   %eax,%eax
    ab3e:	75 5f                	jne    ab9f <dlfree+0x1300>
    ab40:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ab47:	8b 50 04             	mov    0x4(%rax),%edx
    ab4a:	8b 85 b0 fe ff ff    	mov    -0x150(%rbp),%eax
    ab50:	be 01 00 00 00       	mov    $0x1,%esi
    ab55:	89 c1                	mov    %eax,%ecx
    ab57:	d3 e6                	shl    %cl,%esi
    ab59:	89 f0                	mov    %esi,%eax
    ab5b:	09 c2                	or     %eax,%edx
    ab5d:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ab64:	89 50 04             	mov    %edx,0x4(%rax)
    ab67:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    ab6b:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    ab6f:	48 89 10             	mov    %rdx,(%rax)
    ab72:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ab76:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    ab7a:	48 89 50 30          	mov    %rdx,0x30(%rax)
    ab7e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ab82:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    ab86:	48 89 50 18          	mov    %rdx,0x18(%rax)
    ab8a:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ab8e:	48 8b 50 18          	mov    0x18(%rax),%rdx
    ab92:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ab96:	48 89 50 10          	mov    %rdx,0x10(%rax)
    ab9a:	e9 96 01 00 00       	jmpq   ad35 <dlfree+0x1496>
    ab9f:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    aba3:	48 8b 00             	mov    (%rax),%rax
    aba6:	48 89 85 10 ff ff ff 	mov    %rax,-0xf0(%rbp)
    abad:	83 bd b0 fe ff ff 1f 	cmpl   $0x1f,-0x150(%rbp)
    abb4:	74 13                	je     abc9 <dlfree+0x132a>
    abb6:	8b 85 b0 fe ff ff    	mov    -0x150(%rbp),%eax
    abbc:	d1 e8                	shr    %eax
    abbe:	ba 39 00 00 00       	mov    $0x39,%edx
    abc3:	29 c2                	sub    %eax,%edx
    abc5:	89 d0                	mov    %edx,%eax
    abc7:	eb 05                	jmp    abce <dlfree+0x132f>
    abc9:	b8 00 00 00 00       	mov    $0x0,%eax
    abce:	48 8b 95 d0 fe ff ff 	mov    -0x130(%rbp),%rdx
    abd5:	89 c1                	mov    %eax,%ecx
    abd7:	48 d3 e2             	shl    %cl,%rdx
    abda:	48 89 d0             	mov    %rdx,%rax
    abdd:	48 89 85 18 ff ff ff 	mov    %rax,-0xe8(%rbp)
    abe4:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    abeb:	48 8b 40 08          	mov    0x8(%rax),%rax
    abef:	48 83 e0 f8          	and    $0xfffffffffffffff8,%rax
    abf3:	48 39 85 d0 fe ff ff 	cmp    %rax,-0x130(%rbp)
    abfa:	0f 84 a2 00 00 00    	je     aca2 <dlfree+0x1403>
    ac00:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
    ac07:	48 c1 e8 3f          	shr    $0x3f,%rax
    ac0b:	48 83 c0 04          	add    $0x4,%rax
    ac0f:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    ac16:	00 
    ac17:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    ac1e:	48 01 d0             	add    %rdx,%rax
    ac21:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    ac25:	48 d1 a5 18 ff ff ff 	shlq   -0xe8(%rbp)
    ac2c:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    ac30:	48 8b 00             	mov    (%rax),%rax
    ac33:	48 85 c0             	test   %rax,%rax
    ac36:	74 10                	je     ac48 <dlfree+0x13a9>
    ac38:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    ac3c:	48 8b 00             	mov    (%rax),%rax
    ac3f:	48 89 85 10 ff ff ff 	mov    %rax,-0xf0(%rbp)
    ac46:	eb 9c                	jmp    abe4 <dlfree+0x1345>
    ac48:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ac4f:	48 8b 40 18          	mov    0x18(%rax),%rax
    ac53:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    ac57:	0f 93 c0             	setae  %al
    ac5a:	0f b6 c0             	movzbl %al,%eax
    ac5d:	48 85 c0             	test   %rax,%rax
    ac60:	74 3b                	je     ac9d <dlfree+0x13fe>
    ac62:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    ac66:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    ac6a:	48 89 10             	mov    %rdx,(%rax)
    ac6d:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ac71:	48 8b 95 10 ff ff ff 	mov    -0xf0(%rbp),%rdx
    ac78:	48 89 50 30          	mov    %rdx,0x30(%rax)
    ac7c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ac80:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    ac84:	48 89 50 18          	mov    %rdx,0x18(%rax)
    ac88:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ac8c:	48 8b 50 18          	mov    0x18(%rax),%rdx
    ac90:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ac94:	48 89 50 10          	mov    %rdx,0x10(%rax)
    ac98:	e9 98 00 00 00       	jmpq   ad35 <dlfree+0x1496>
    ac9d:	e8 2c 1d 00 00       	callq  c9ce <abort>
    aca2:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    aca9:	48 8b 40 10          	mov    0x10(%rax),%rax
    acad:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    acb1:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    acb8:	48 8b 40 18          	mov    0x18(%rax),%rax
    acbc:	48 39 85 10 ff ff ff 	cmp    %rax,-0xf0(%rbp)
    acc3:	0f 93 c0             	setae  %al
    acc6:	0f b6 c0             	movzbl %al,%eax
    acc9:	48 85 c0             	test   %rax,%rax
    accc:	74 62                	je     ad30 <dlfree+0x1491>
    acce:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    acd5:	48 8b 40 18          	mov    0x18(%rax),%rax
    acd9:	48 39 45 e8          	cmp    %rax,-0x18(%rbp)
    acdd:	0f 93 c0             	setae  %al
    ace0:	0f b6 c0             	movzbl %al,%eax
    ace3:	48 85 c0             	test   %rax,%rax
    ace6:	74 48                	je     ad30 <dlfree+0x1491>
    ace8:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    acec:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    acf0:	48 89 50 18          	mov    %rdx,0x18(%rax)
    acf4:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    acf8:	48 8b 50 18          	mov    0x18(%rax),%rdx
    acfc:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    ad03:	48 89 50 10          	mov    %rdx,0x10(%rax)
    ad07:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ad0b:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    ad0f:	48 89 50 10          	mov    %rdx,0x10(%rax)
    ad13:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ad17:	48 8b 95 10 ff ff ff 	mov    -0xf0(%rbp),%rdx
    ad1e:	48 89 50 18          	mov    %rdx,0x18(%rax)
    ad22:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    ad26:	48 c7 40 30 00 00 00 	movq   $0x0,0x30(%rax)
    ad2d:	00 
    ad2e:	eb 05                	jmp    ad35 <dlfree+0x1496>
    ad30:	e8 99 1c 00 00       	callq  c9ce <abort>
            check_free_chunk(fm, p);
    ad35:	48 8b 95 c8 fe ff ff 	mov    -0x138(%rbp),%rdx
    ad3c:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ad43:	48 89 d6             	mov    %rdx,%rsi
    ad46:	48 89 c7             	mov    %rax,%rdi
    ad49:	e8 e7 a9 ff ff       	callq  5735 <do_check_free_chunk>
            if (--fm->release_checks == 0)
    ad4e:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ad55:	48 8b 40 38          	mov    0x38(%rax),%rax
    ad59:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
    ad5d:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ad64:	48 89 50 38          	mov    %rdx,0x38(%rax)
    ad68:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ad6f:	48 8b 40 38          	mov    0x38(%rax),%rax
    ad73:	48 85 c0             	test   %rax,%rax
    ad76:	75 1d                	jne    ad95 <dlfree+0x14f6>
              release_unused_segments(fm);
    ad78:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ad7f:	48 89 c7             	mov    %rax,%rdi
    ad82:	e8 52 ca ff ff       	callq  77d9 <release_unused_segments>
          goto postaction;
    ad87:	eb 0c                	jmp    ad95 <dlfree+0x14f6>
        }
      }
    erroraction:
    ad89:	90                   	nop
    ad8a:	eb 01                	jmp    ad8d <dlfree+0x14ee>
              goto erroraction;
    ad8c:	90                   	nop
      USAGE_ERROR_ACTION(fm, p);
    ad8d:	e8 3c 1c 00 00       	callq  c9ce <abort>
              goto postaction;
    ad92:	90                   	nop
    ad93:	eb 01                	jmp    ad96 <dlfree+0x14f7>
          goto postaction;
    ad95:	90                   	nop
    postaction:
      POSTACTION(fm);
    ad96:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    ad9d:	8b 80 70 03 00 00    	mov    0x370(%rax),%eax
    ada3:	83 e0 02             	and    $0x2,%eax
    ada6:	85 c0                	test   %eax,%eax
    ada8:	74 14                	je     adbe <dlfree+0x151f>
    adaa:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    adb1:	48 05 74 03 00 00    	add    $0x374,%rax
    adb7:	ba 00 00 00 00       	mov    $0x0,%edx
    adbc:	89 10                	mov    %edx,(%rax)
    }
  }
#if !FOOTERS
#undef fm
#endif /* FOOTERS */
}
    adbe:	90                   	nop
    adbf:	c9                   	leaveq 
    adc0:	c3                   	retq   

000000000000adc1 <__memcpy>:
/*
 * Copy a block of memory, not handling overlap.
 */
void *
__memcpy(void *dst0, const void *src0, size_t length)
{
    adc1:	55                   	push   %rbp
    adc2:	48 89 e5             	mov    %rsp,%rbp
    adc5:	48 83 ec 40          	sub    $0x40,%rsp
    adc9:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    adcd:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    add1:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
	char *dst = (char *)dst0;
    add5:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    add9:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
	const char *src = (const char *)src0;
    addd:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    ade1:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
	size_t t;

	if (length == 0 || dst == src)		/* nothing to do */
    ade5:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    adea:	0f 84 3b 01 00 00    	je     af2b <__memcpy+0x16a>
    adf0:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    adf4:	48 3b 45 f0          	cmp    -0x10(%rbp),%rax
    adf8:	0f 84 2d 01 00 00    	je     af2b <__memcpy+0x16a>
		goto done;

	if ((dst < src && dst + length > src) ||
    adfe:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    ae02:	48 3b 45 f0          	cmp    -0x10(%rbp),%rax
    ae06:	73 11                	jae    ae19 <__memcpy+0x58>
    ae08:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    ae0c:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    ae10:	48 01 d0             	add    %rdx,%rax
    ae13:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    ae17:	72 1b                	jb     ae34 <__memcpy+0x73>
    ae19:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    ae1d:	48 3b 45 e8          	cmp    -0x18(%rbp),%rax
    ae21:	73 16                	jae    ae39 <__memcpy+0x78>
	    (src < dst && src + length > dst)) {
    ae23:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    ae27:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    ae2b:	48 01 d0             	add    %rdx,%rax
    ae2e:	48 39 45 e8          	cmp    %rax,-0x18(%rbp)
    ae32:	73 05                	jae    ae39 <__memcpy+0x78>
        /* backwards memcpy */
		abort();
    ae34:	e8 95 1b 00 00       	callq  c9ce <abort>
#define	TLOOP1(s) do { s; } while (--t)

	/*
	 * Copy forward.
	 */
	t = (long)src;	/* only need low bits */
    ae39:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    ae3d:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
	if ((t | (long)dst) & wmask) {
    ae41:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    ae45:	48 0b 45 f8          	or     -0x8(%rbp),%rax
    ae49:	83 e0 07             	and    $0x7,%eax
    ae4c:	48 85 c0             	test   %rax,%rax
    ae4f:	74 68                	je     aeb9 <__memcpy+0xf8>
		/*
		 * Try to align operands.  This cannot be done
		 * unless the low bits match.
		 */
		if ((t ^ (long)dst) & wmask || length < wsize)
    ae51:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    ae55:	48 33 45 f8          	xor    -0x8(%rbp),%rax
    ae59:	83 e0 07             	and    $0x7,%eax
    ae5c:	48 85 c0             	test   %rax,%rax
    ae5f:	75 07                	jne    ae68 <__memcpy+0xa7>
    ae61:	48 83 7d c8 07       	cmpq   $0x7,-0x38(%rbp)
    ae66:	77 0a                	ja     ae72 <__memcpy+0xb1>
			t = length;
    ae68:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    ae6c:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    ae70:	eb 16                	jmp    ae88 <__memcpy+0xc7>
		else
			t = wsize - (t & wmask);
    ae72:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ae76:	83 e0 07             	and    $0x7,%eax
    ae79:	ba 08 00 00 00       	mov    $0x8,%edx
    ae7e:	48 29 c2             	sub    %rax,%rdx
    ae81:	48 89 d0             	mov    %rdx,%rax
    ae84:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
		length -= t;
    ae88:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    ae8c:	48 29 45 c8          	sub    %rax,-0x38(%rbp)
		TLOOP1(*dst++ = *src++);
    ae90:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    ae94:	48 8d 42 01          	lea    0x1(%rdx),%rax
    ae98:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    ae9c:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    aea0:	48 8d 48 01          	lea    0x1(%rax),%rcx
    aea4:	48 89 4d e8          	mov    %rcx,-0x18(%rbp)
    aea8:	0f b6 12             	movzbl (%rdx),%edx
    aeab:	88 10                	mov    %dl,(%rax)
    aead:	48 83 6d f8 01       	subq   $0x1,-0x8(%rbp)
    aeb2:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    aeb7:	75 d7                	jne    ae90 <__memcpy+0xcf>
	}
	/*
	 * Copy whole words, then mop up any trailing bytes.
	 */
	t = length / wsize;
    aeb9:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    aebd:	48 c1 e8 03          	shr    $0x3,%rax
    aec1:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
	TLOOP(*(word *)dst = *(word *)src; src += wsize; dst += wsize);
    aec5:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    aeca:	74 24                	je     aef0 <__memcpy+0x12f>
    aecc:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    aed0:	48 8b 10             	mov    (%rax),%rdx
    aed3:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    aed7:	48 89 10             	mov    %rdx,(%rax)
    aeda:	48 83 45 f0 08       	addq   $0x8,-0x10(%rbp)
    aedf:	48 83 45 e8 08       	addq   $0x8,-0x18(%rbp)
    aee4:	48 83 6d f8 01       	subq   $0x1,-0x8(%rbp)
    aee9:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    aeee:	75 dc                	jne    aecc <__memcpy+0x10b>
	t = length & wmask;
    aef0:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    aef4:	83 e0 07             	and    $0x7,%eax
    aef7:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
	TLOOP(*dst++ = *src++);
    aefb:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    af00:	74 29                	je     af2b <__memcpy+0x16a>
    af02:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    af06:	48 8d 42 01          	lea    0x1(%rdx),%rax
    af0a:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    af0e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    af12:	48 8d 48 01          	lea    0x1(%rax),%rcx
    af16:	48 89 4d e8          	mov    %rcx,-0x18(%rbp)
    af1a:	0f b6 12             	movzbl (%rdx),%edx
    af1d:	88 10                	mov    %dl,(%rax)
    af1f:	48 83 6d f8 01       	subq   $0x1,-0x8(%rbp)
    af24:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    af29:	75 d7                	jne    af02 <__memcpy+0x141>
done:
    af2b:	90                   	nop
	return (dst0);
    af2c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
}
    af30:	c9                   	leaveq 
    af31:	c3                   	retq   

000000000000af32 <memcpy>:


void *
memcpy(void *dst0, const void *src0, size_t length)
{
    af32:	55                   	push   %rbp
    af33:	48 89 e5             	mov    %rsp,%rbp
    af36:	48 83 ec 20          	sub    $0x20,%rsp
    af3a:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    af3e:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    af42:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
#ifdef _TLIBC_USE_INTEL_FAST_STRING_
 	return _intel_fast_memcpy(dst0, (void*)src0, length);
#else
	return __memcpy(dst0, src0, length);
    af46:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    af4a:	48 8b 4d f0          	mov    -0x10(%rbp),%rcx
    af4e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    af52:	48 89 ce             	mov    %rcx,%rsi
    af55:	48 89 c7             	mov    %rax,%rdi
    af58:	e8 64 fe ff ff       	callq  adc1 <__memcpy>
#endif
}
    af5d:	c9                   	leaveq 
    af5e:	c3                   	retq   

000000000000af5f <__memset>:
extern void *_intel_fast_memset(void *, void *, size_t);
#endif

void * __attribute__((optimize("O0")))
__memset(void *dst, int c, size_t n)
{
    af5f:	55                   	push   %rbp
    af60:	48 89 e5             	mov    %rsp,%rbp
    af63:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    af67:	89 75 e4             	mov    %esi,-0x1c(%rbp)
    af6a:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
	if (n != 0) {
    af6e:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    af73:	74 25                	je     af9a <__memset+0x3b>
                unsigned char *d = dst;
    af75:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    af79:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

                do
                        *d++ = (unsigned char)c;
    af7d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    af81:	48 8d 50 01          	lea    0x1(%rax),%rdx
    af85:	48 89 55 f8          	mov    %rdx,-0x8(%rbp)
    af89:	8b 55 e4             	mov    -0x1c(%rbp),%edx
    af8c:	88 10                	mov    %dl,(%rax)
                while (--n != 0);
    af8e:	48 83 6d d8 01       	subq   $0x1,-0x28(%rbp)
    af93:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
    af98:	75 e3                	jne    af7d <__memset+0x1e>
        }
        return (dst);
    af9a:	48 8b 45 e8          	mov    -0x18(%rbp),%rax


}
    af9e:	5d                   	pop    %rbp
    af9f:	c3                   	retq   

000000000000afa0 <memset>:

void *
memset(void *dst, int c, size_t n)
{
    afa0:	55                   	push   %rbp
    afa1:	48 89 e5             	mov    %rsp,%rbp
    afa4:	48 83 ec 18          	sub    $0x18,%rsp
    afa8:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    afac:	89 75 f4             	mov    %esi,-0xc(%rbp)
    afaf:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
#ifdef _TLIBC_USE_INTEL_FAST_STRING_
	return _intel_fast_memset(dst, (void*)c, n);
#else
	return __memset(dst, c, n);
    afb3:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    afb7:	8b 4d f4             	mov    -0xc(%rbp),%ecx
    afba:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    afbe:	89 ce                	mov    %ecx,%esi
    afc0:	48 89 c7             	mov    %rax,%rdi
    afc3:	e8 97 ff ff ff       	callq  af5f <__memset>
#endif /* !_TLIBC_USE_INTEL_FAST_STRING_ */	
}
    afc8:	c9                   	leaveq 
    afc9:	c3                   	retq   

000000000000afca <memset_s>:

#undef memset_s /* in case it was defined as a macro */

errno_t
memset_s(void *s, size_t smax, int c, size_t n)
{
    afca:	55                   	push   %rbp
    afcb:	48 89 e5             	mov    %rsp,%rbp
    afce:	48 83 ec 30          	sub    $0x30,%rsp
    afd2:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    afd6:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    afda:	89 55 dc             	mov    %edx,-0x24(%rbp)
    afdd:	48 89 4d d0          	mov    %rcx,-0x30(%rbp)
    errno_t err = 0;
    afe1:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)

    if (s == NULL) {
    afe8:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    afed:	75 09                	jne    aff8 <memset_s+0x2e>
        err = EINVAL;
    afef:	c7 45 fc 16 00 00 00 	movl   $0x16,-0x4(%rbp)
        goto out;
    aff6:	eb 30                	jmp    b028 <memset_s+0x5e>
    }
    if (n > SIZE_MAX) {
        err = E2BIG;
        n = smax;
    }
    if (n > smax) {
    aff8:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    affc:	48 3b 45 e0          	cmp    -0x20(%rbp),%rax
    b000:	76 0f                	jbe    b011 <memset_s+0x47>
        err = EOVERFLOW;
    b002:	c7 45 fc 4b 00 00 00 	movl   $0x4b,-0x4(%rbp)
        n = smax;
    b009:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    b00d:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    }

    /* Calling through a volatile pointer should never be optimised away. */
    (*__memset_vp)(s, c, n);
    b011:	48 8b 05 18 60 00 00 	mov    0x6018(%rip),%rax        # 11030 <__memset_vp>
    b018:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
    b01c:	8b 75 dc             	mov    -0x24(%rbp),%esi
    b01f:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
    b023:	48 89 cf             	mov    %rcx,%rdi
    b026:	ff d0                	callq  *%rax

    out:
    if (err == 0)
    b028:	83 7d fc 00          	cmpl   $0x0,-0x4(%rbp)
    b02c:	75 07                	jne    b035 <memset_s+0x6b>
        return 0;
    b02e:	b8 00 00 00 00       	mov    $0x0,%eax
    b033:	eb 10                	jmp    b045 <memset_s+0x7b>
    else {
        errno = err;
    b035:	e8 0a 06 00 00       	callq  b644 <__errno>
    b03a:	48 89 c2             	mov    %rax,%rdx
    b03d:	8b 45 fc             	mov    -0x4(%rbp),%eax
    b040:	89 02                	mov    %eax,(%rdx)
        /* XXX call runtime-constraint handler */
        return err;
    b042:	8b 45 fc             	mov    -0x4(%rbp),%eax
    }
}
    b045:	c9                   	leaveq 
    b046:	c3                   	retq   

000000000000b047 <heap_init>:
static size_t heap_size __attribute__((section(RELRO_SECTION_NAME))) = 0;
static int is_edmm_supported __attribute__((section(RELRO_SECTION_NAME))) = 0;
static size_t heap_min_size __attribute__((section(RELRO_SECTION_NAME))) = 0;

int heap_init(void *_heap_base, size_t _heap_size, size_t _heap_min_size, int _is_edmm_supported)
{
    b047:	55                   	push   %rbp
    b048:	48 89 e5             	mov    %rsp,%rbp
    b04b:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    b04f:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    b053:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    b057:	89 4d e4             	mov    %ecx,-0x1c(%rbp)
    if (heap_base != NULL)
    b05a:	48 8b 05 a7 5d 00 00 	mov    0x5da7(%rip),%rax        # 10e08 <heap_base>
    b061:	48 85 c0             	test   %rax,%rax
    b064:	74 0a                	je     b070 <heap_init+0x29>
        return SGX_ERROR_UNEXPECTED;
    b066:	b8 01 00 00 00       	mov    $0x1,%eax
    b06b:	e9 8c 00 00 00       	jmpq   b0fc <heap_init+0xb5>

    if ((_heap_base == NULL) || (((size_t) _heap_base) & (SE_PAGE_SIZE - 1)))
    b070:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    b075:	74 0e                	je     b085 <heap_init+0x3e>
    b077:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b07b:	25 ff 0f 00 00       	and    $0xfff,%eax
    b080:	48 85 c0             	test   %rax,%rax
    b083:	74 07                	je     b08c <heap_init+0x45>
        return SGX_ERROR_UNEXPECTED;
    b085:	b8 01 00 00 00       	mov    $0x1,%eax
    b08a:	eb 70                	jmp    b0fc <heap_init+0xb5>

    if (_heap_size & (SE_PAGE_SIZE - 1))
    b08c:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b090:	25 ff 0f 00 00       	and    $0xfff,%eax
    b095:	48 85 c0             	test   %rax,%rax
    b098:	74 07                	je     b0a1 <heap_init+0x5a>
        return SGX_ERROR_UNEXPECTED;
    b09a:	b8 01 00 00 00       	mov    $0x1,%eax
    b09f:	eb 5b                	jmp    b0fc <heap_init+0xb5>

    if (_heap_min_size & (SE_PAGE_SIZE - 1))
    b0a1:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b0a5:	25 ff 0f 00 00       	and    $0xfff,%eax
    b0aa:	48 85 c0             	test   %rax,%rax
    b0ad:	74 07                	je     b0b6 <heap_init+0x6f>
        return SGX_ERROR_UNEXPECTED;
    b0af:	b8 01 00 00 00       	mov    $0x1,%eax
    b0b4:	eb 46                	jmp    b0fc <heap_init+0xb5>

    if (_heap_size > SIZE_MAX - (size_t)heap_base)
    b0b6:	48 8b 05 4b 5d 00 00 	mov    0x5d4b(%rip),%rax        # 10e08 <heap_base>
    b0bd:	48 f7 d0             	not    %rax
    b0c0:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    b0c4:	76 07                	jbe    b0cd <heap_init+0x86>
        return SGX_ERROR_UNEXPECTED;
    b0c6:	b8 01 00 00 00       	mov    $0x1,%eax
    b0cb:	eb 2f                	jmp    b0fc <heap_init+0xb5>

    heap_base = _heap_base;
    b0cd:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b0d1:	48 89 05 30 5d 00 00 	mov    %rax,0x5d30(%rip)        # 10e08 <heap_base>
    heap_size = _heap_size;
    b0d8:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b0dc:	48 89 05 2d 5d 00 00 	mov    %rax,0x5d2d(%rip)        # 10e10 <heap_size>
    heap_min_size = _heap_min_size;
    b0e3:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b0e7:	48 89 05 32 5d 00 00 	mov    %rax,0x5d32(%rip)        # 10e20 <heap_min_size>
    is_edmm_supported = _is_edmm_supported;
    b0ee:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    b0f1:	89 05 21 5d 00 00    	mov    %eax,0x5d21(%rip)        # 10e18 <is_edmm_supported>

    return SGX_SUCCESS;
    b0f7:	b8 00 00 00 00       	mov    $0x0,%eax
}
    b0fc:	5d                   	pop    %rbp
    b0fd:	c3                   	retq   

000000000000b0fe <sbrk>:

void* sbrk(intptr_t n)
{
    b0fe:	55                   	push   %rbp
    b0ff:	48 89 e5             	mov    %rsp,%rbp
    b102:	48 83 ec 40          	sub    $0x40,%rsp
    b106:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    static size_t heap_used;
    void *heap_ptr = NULL;
    b10a:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
    b111:	00 
    size_t prev_heap_used = heap_used;
    b112:	48 8b 05 f7 63 00 00 	mov    0x63f7(%rip),%rax        # 11510 <heap_used.2393>
    b119:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    void * start_addr;
    size_t size = 0;
    b11d:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    b124:	00 

    if (!heap_base)
    b125:	48 8b 05 dc 5c 00 00 	mov    0x5cdc(%rip),%rax        # 10e08 <heap_base>
    b12c:	48 85 c0             	test   %rax,%rax
    b12f:	75 0c                	jne    b13d <sbrk+0x3f>
        return (void *)(~(size_t)0);
    b131:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
    b138:	e9 9d 02 00 00       	jmpq   b3da <sbrk+0x2dc>

    /* shrink the heap */
    if (n < 0) {
    b13d:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
    b142:	0f 89 31 01 00 00    	jns    b279 <sbrk+0x17b>

        n *= -1;
    b148:	48 f7 5d c8          	negq   -0x38(%rbp)
        if (heap_used < n)
    b14c:	48 8b 15 bd 63 00 00 	mov    0x63bd(%rip),%rdx        # 11510 <heap_used.2393>
    b153:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b157:	48 39 c2             	cmp    %rax,%rdx
    b15a:	73 0c                	jae    b168 <sbrk+0x6a>
            return (void *)(~(size_t)0);
    b15c:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
    b163:	e9 72 02 00 00       	jmpq   b3da <sbrk+0x2dc>

        heap_used -= n;
    b168:	48 8b 15 a1 63 00 00 	mov    0x63a1(%rip),%rdx        # 11510 <heap_used.2393>
    b16f:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b173:	48 29 c2             	sub    %rax,%rdx
    b176:	48 89 d0             	mov    %rdx,%rax
    b179:	48 89 05 90 63 00 00 	mov    %rax,0x6390(%rip)        # 11510 <heap_used.2393>

        /* heap_used is never larger than heap_size, and since heap_size <= SIZE_MAX - (size_t)heap_base,
           there's no integer overflow here.
         */  
        heap_ptr = (void *)((size_t)heap_base + (size_t)heap_used);
    b180:	48 8b 05 81 5c 00 00 	mov    0x5c81(%rip),%rax        # 10e08 <heap_base>
    b187:	48 89 c2             	mov    %rax,%rdx
    b18a:	48 8b 05 7f 63 00 00 	mov    0x637f(%rip),%rax        # 11510 <heap_used.2393>
    b191:	48 01 d0             	add    %rdx,%rax
    b194:	48 89 45 f0          	mov    %rax,-0x10(%rbp)

        if (is_edmm_supported && (prev_heap_used > heap_min_size)) 
    b198:	8b 05 7a 5c 00 00    	mov    0x5c7a(%rip),%eax        # 10e18 <is_edmm_supported>
    b19e:	85 c0                	test   %eax,%eax
    b1a0:	0f 84 ca 00 00 00    	je     b270 <sbrk+0x172>
    b1a6:	48 8b 05 73 5c 00 00 	mov    0x5c73(%rip),%rax        # 10e20 <heap_min_size>
    b1ad:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    b1b1:	0f 86 b9 00 00 00    	jbe    b270 <sbrk+0x172>
        {
            assert((n & (SE_PAGE_SIZE - 1)) == 0);
    b1b7:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b1bb:	25 ff 0f 00 00       	and    $0xfff,%eax
    b1c0:	48 85 c0             	test   %rax,%rax
    b1c3:	74 1f                	je     b1e4 <sbrk+0xe6>
    b1c5:	48 8d 0d 54 1f 00 00 	lea    0x1f54(%rip),%rcx        # d120 <_ZZL16init_stack_guardPvE8__func__+0xc0>
    b1cc:	48 8d 15 76 1f 00 00 	lea    0x1f76(%rip),%rdx        # d149 <__func__.2398>
    b1d3:	be 65 00 00 00       	mov    $0x65,%esi
    b1d8:	48 8d 3d 5f 1f 00 00 	lea    0x1f5f(%rip),%rdi        # d13e <_ZZL16init_stack_guardPvE8__func__+0xde>
    b1df:	e8 ff a0 ff ff       	callq  52e3 <__assert>

            if (heap_used > heap_min_size)
    b1e4:	48 8b 15 25 63 00 00 	mov    0x6325(%rip),%rdx        # 11510 <heap_used.2393>
    b1eb:	48 8b 05 2e 5c 00 00 	mov    0x5c2e(%rip),%rax        # 10e20 <heap_min_size>
    b1f2:	48 39 c2             	cmp    %rax,%rdx
    b1f5:	76 12                	jbe    b209 <sbrk+0x10b>
            {
                start_addr = heap_ptr;
    b1f7:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b1fb:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
                size = n;
    b1ff:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b203:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    b207:	eb 2d                	jmp    b236 <sbrk+0x138>
            else
            {
                /* heap_min_size is never larger than heap_size, and since heap_size <= SIZE_MAX - (size_t)heap_base,
                   there's no integer overflow here.
                 */  
                start_addr = (void *)((size_t)(heap_base) + heap_min_size);
    b209:	48 8b 05 f8 5b 00 00 	mov    0x5bf8(%rip),%rax        # 10e08 <heap_base>
    b210:	48 89 c2             	mov    %rax,%rdx
    b213:	48 8b 05 06 5c 00 00 	mov    0x5c06(%rip),%rax        # 10e20 <heap_min_size>
    b21a:	48 01 d0             	add    %rdx,%rax
    b21d:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
                size = prev_heap_used - heap_min_size;
    b221:	48 8b 05 f8 5b 00 00 	mov    0x5bf8(%rip),%rax        # 10e20 <heap_min_size>
    b228:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    b22c:	48 29 c2             	sub    %rax,%rdx
    b22f:	48 89 d0             	mov    %rdx,%rax
    b232:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
            }
            int ret = trim_EPC_pages(start_addr, size >> SE_PAGE_SHIFT);
    b236:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b23a:	48 c1 e8 0c          	shr    $0xc,%rax
    b23e:	48 89 c2             	mov    %rax,%rdx
    b241:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    b245:	48 89 d6             	mov    %rdx,%rsi
    b248:	48 89 c7             	mov    %rax,%rdi
    b24b:	e8 b2 70 ff ff       	callq  2302 <trim_EPC_pages>
    b250:	89 45 dc             	mov    %eax,-0x24(%rbp)
            if (ret != 0)
    b253:	83 7d dc 00          	cmpl   $0x0,-0x24(%rbp)
    b257:	74 17                	je     b270 <sbrk+0x172>
            {
                heap_used = prev_heap_used;
    b259:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b25d:	48 89 05 ac 62 00 00 	mov    %rax,0x62ac(%rip)        # 11510 <heap_used.2393>
                return (void *)(~(size_t)0);
    b264:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
    b26b:	e9 6a 01 00 00       	jmpq   b3da <sbrk+0x2dc>
            }
        }
        return heap_ptr;
    b270:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b274:	e9 61 01 00 00       	jmpq   b3da <sbrk+0x2dc>
    }

    /* extend the heap */
    if((heap_used > (SIZE_MAX - n)) || ((heap_used + n) > heap_size))
    b279:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b27d:	48 f7 d0             	not    %rax
    b280:	48 89 c2             	mov    %rax,%rdx
    b283:	48 8b 05 86 62 00 00 	mov    0x6286(%rip),%rax        # 11510 <heap_used.2393>
    b28a:	48 39 c2             	cmp    %rax,%rdx
    b28d:	72 1a                	jb     b2a9 <sbrk+0x1ab>
    b28f:	48 8b 15 7a 62 00 00 	mov    0x627a(%rip),%rdx        # 11510 <heap_used.2393>
    b296:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b29a:	48 01 c2             	add    %rax,%rdx
    b29d:	48 8b 05 6c 5b 00 00 	mov    0x5b6c(%rip),%rax        # 10e10 <heap_size>
    b2a4:	48 39 c2             	cmp    %rax,%rdx
    b2a7:	76 0c                	jbe    b2b5 <sbrk+0x1b7>
        return (void *)(~(size_t)0);
    b2a9:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
    b2b0:	e9 25 01 00 00       	jmpq   b3da <sbrk+0x2dc>

    /* heap_used is never larger than heap_size, and since heap_size <= SIZE_MAX - (size_t)heap_base,
       there's no integer overflow here.
     */  
    heap_ptr = (void *)((size_t)heap_base + (size_t)heap_used);
    b2b5:	48 8b 05 4c 5b 00 00 	mov    0x5b4c(%rip),%rax        # 10e08 <heap_base>
    b2bc:	48 89 c2             	mov    %rax,%rdx
    b2bf:	48 8b 05 4a 62 00 00 	mov    0x624a(%rip),%rax        # 11510 <heap_used.2393>
    b2c6:	48 01 d0             	add    %rdx,%rax
    b2c9:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    heap_used += n;
    b2cd:	48 8b 15 3c 62 00 00 	mov    0x623c(%rip),%rdx        # 11510 <heap_used.2393>
    b2d4:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b2d8:	48 01 d0             	add    %rdx,%rax
    b2db:	48 89 05 2e 62 00 00 	mov    %rax,0x622e(%rip)        # 11510 <heap_used.2393>

    /* update g_peak_heap_used */
    g_peak_heap_used = (g_peak_heap_used < heap_used) ? heap_used : g_peak_heap_used;
    b2e2:	48 8b 15 1f 62 00 00 	mov    0x621f(%rip),%rdx        # 11508 <g_peak_heap_used>
    b2e9:	48 8b 05 20 62 00 00 	mov    0x6220(%rip),%rax        # 11510 <heap_used.2393>
    b2f0:	48 39 c2             	cmp    %rax,%rdx
    b2f3:	48 0f 43 c2          	cmovae %rdx,%rax
    b2f7:	48 89 05 0a 62 00 00 	mov    %rax,0x620a(%rip)        # 11508 <g_peak_heap_used>

    if (is_edmm_supported && heap_used > heap_min_size)
    b2fe:	8b 05 14 5b 00 00    	mov    0x5b14(%rip),%eax        # 10e18 <is_edmm_supported>
    b304:	85 c0                	test   %eax,%eax
    b306:	0f 84 ca 00 00 00    	je     b3d6 <sbrk+0x2d8>
    b30c:	48 8b 15 fd 61 00 00 	mov    0x61fd(%rip),%rdx        # 11510 <heap_used.2393>
    b313:	48 8b 05 06 5b 00 00 	mov    0x5b06(%rip),%rax        # 10e20 <heap_min_size>
    b31a:	48 39 c2             	cmp    %rax,%rdx
    b31d:	0f 86 b3 00 00 00    	jbe    b3d6 <sbrk+0x2d8>
    {
        assert((n & (SE_PAGE_SIZE - 1)) == 0);
    b323:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b327:	25 ff 0f 00 00       	and    $0xfff,%eax
    b32c:	48 85 c0             	test   %rax,%rax
    b32f:	74 1f                	je     b350 <sbrk+0x252>
    b331:	48 8d 0d e8 1d 00 00 	lea    0x1de8(%rip),%rcx        # d120 <_ZZL16init_stack_guardPvE8__func__+0xc0>
    b338:	48 8d 15 0a 1e 00 00 	lea    0x1e0a(%rip),%rdx        # d149 <__func__.2398>
    b33f:	be 8d 00 00 00       	mov    $0x8d,%esi
    b344:	48 8d 3d f3 1d 00 00 	lea    0x1df3(%rip),%rdi        # d13e <_ZZL16init_stack_guardPvE8__func__+0xde>
    b34b:	e8 93 9f ff ff       	callq  52e3 <__assert>

        if (prev_heap_used > heap_min_size)
    b350:	48 8b 05 c9 5a 00 00 	mov    0x5ac9(%rip),%rax        # 10e20 <heap_min_size>
    b357:	48 39 45 f8          	cmp    %rax,-0x8(%rbp)
    b35b:	76 12                	jbe    b36f <sbrk+0x271>
        {
            start_addr = heap_ptr;
    b35d:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b361:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
            size = n;
    b365:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    b369:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    b36d:	eb 30                	jmp    b39f <sbrk+0x2a1>
        {

            /* heap_min_size is never larger than heap_size, and since heap_size <= SIZE_MAX - (size_t)heap_base,
               there's no integer overflow here.
             */  
            start_addr = (void *)((size_t)(heap_base) + heap_min_size);
    b36f:	48 8b 05 92 5a 00 00 	mov    0x5a92(%rip),%rax        # 10e08 <heap_base>
    b376:	48 89 c2             	mov    %rax,%rdx
    b379:	48 8b 05 a0 5a 00 00 	mov    0x5aa0(%rip),%rax        # 10e20 <heap_min_size>
    b380:	48 01 d0             	add    %rdx,%rax
    b383:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
            size = heap_used - heap_min_size;
    b387:	48 8b 15 82 61 00 00 	mov    0x6182(%rip),%rdx        # 11510 <heap_used.2393>
    b38e:	48 8b 05 8b 5a 00 00 	mov    0x5a8b(%rip),%rax        # 10e20 <heap_min_size>
    b395:	48 29 c2             	sub    %rax,%rdx
    b398:	48 89 d0             	mov    %rdx,%rax
    b39b:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
        }
        int ret = apply_EPC_pages(start_addr, size >> SE_PAGE_SHIFT);
    b39f:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b3a3:	48 c1 e8 0c          	shr    $0xc,%rax
    b3a7:	48 89 c2             	mov    %rax,%rdx
    b3aa:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    b3ae:	48 89 d6             	mov    %rdx,%rsi
    b3b1:	48 89 c7             	mov    %rax,%rdi
    b3b4:	e8 76 6e ff ff       	callq  222f <apply_EPC_pages>
    b3b9:	89 45 d8             	mov    %eax,-0x28(%rbp)
        if (ret != 0)
    b3bc:	83 7d d8 00          	cmpl   $0x0,-0x28(%rbp)
    b3c0:	74 14                	je     b3d6 <sbrk+0x2d8>
        {
            heap_used = prev_heap_used;
    b3c2:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b3c6:	48 89 05 43 61 00 00 	mov    %rax,0x6143(%rip)        # 11510 <heap_used.2393>
            return (void *)(~(size_t)0);
    b3cd:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
    b3d4:	eb 04                	jmp    b3da <sbrk+0x2dc>
        }
    }
    return heap_ptr;
    b3d6:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
}
    b3da:	c9                   	leaveq 
    b3db:	c3                   	retq   

000000000000b3dc <tstdc_access_version_dummy1>:
#include "stdint.h"
#include "se_cpu_feature.h"
#include "se_cdefs.h"

// add a version to tlibc.
SGX_ACCESS_VERSION(tstdc, 1)
    b3dc:	55                   	push   %rbp
    b3dd:	48 89 e5             	mov    %rsp,%rbp
    b3e0:	c6 05 59 5c 00 00 73 	movb   $0x73,0x5c59(%rip)        # 11040 <sgx_tstdc_version>
    b3e7:	48 8d 05 52 5c 00 00 	lea    0x5c52(%rip),%rax        # 11040 <sgx_tstdc_version>
    b3ee:	5d                   	pop    %rbp
    b3ef:	c3                   	retq   

000000000000b3f0 <sgx_init_string_lib>:
    return _intel_cpu_indicator_init(cpu_feature_indicator);
}

#else
int sgx_init_string_lib(uint64_t cpu_feature_indicator)
{
    b3f0:	55                   	push   %rbp
    b3f1:	48 89 e5             	mov    %rsp,%rbp
    b3f4:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    (void)cpu_feature_indicator; 
    return 0;
    b3f8:	b8 00 00 00 00       	mov    $0x0,%eax
}
    b3fd:	5d                   	pop    %rbp
    b3fe:	c3                   	retq   

000000000000b3ff <sgx_spin_lock>:
    return (res);
   
}

uint32_t sgx_spin_lock(sgx_spinlock_t *lock)
{
    b3ff:	55                   	push   %rbp
    b400:	48 89 e5             	mov    %rsp,%rbp
    b403:	48 83 ec 30          	sub    $0x30,%rsp
    b407:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    b40b:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    b412:	00 00 
    b414:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    b418:	31 c0                	xor    %eax,%eax
    while(_InterlockedExchange((volatile int *)lock, 1) != 0) {
    b41a:	eb 0c                	jmp    b428 <sgx_spin_lock+0x29>
    __asm __volatile(
    b41c:	f3 90                	pause  
        while (*lock) {
    b41e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    b422:	8b 00                	mov    (%rax),%eax
    b424:	85 c0                	test   %eax,%eax
    b426:	75 f4                	jne    b41c <sgx_spin_lock+0x1d>
    b428:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    b42c:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    b430:	c7 45 ec 01 00 00 00 	movl   $0x1,-0x14(%rbp)
    __asm __volatile(
    b437:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b43b:	8b 55 ec             	mov    -0x14(%rbp),%edx
    b43e:	f0 87 10             	lock xchg %edx,(%rax)
    b441:	89 55 e8             	mov    %edx,-0x18(%rbp)
    return (res);
    b444:	8b 45 e8             	mov    -0x18(%rbp),%eax
    while(_InterlockedExchange((volatile int *)lock, 1) != 0) {
    b447:	85 c0                	test   %eax,%eax
    b449:	75 d3                	jne    b41e <sgx_spin_lock+0x1f>
            /* tell cpu we are spinning */
            _mm_pause();
        } 
    }

    return (0);
    b44b:	b8 00 00 00 00       	mov    $0x0,%eax
}
    b450:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    b454:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    b45b:	00 00 
    b45d:	74 05                	je     b464 <sgx_spin_lock+0x65>
    b45f:	e8 76 9e ff ff       	callq  52da <__stack_chk_fail>
    b464:	c9                   	leaveq 
    b465:	c3                   	retq   

000000000000b466 <sgx_spin_unlock>:

uint32_t sgx_spin_unlock(sgx_spinlock_t *lock)
{
    b466:	55                   	push   %rbp
    b467:	48 89 e5             	mov    %rsp,%rbp
    b46a:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    *lock = 0;
    b46e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b472:	c7 00 00 00 00 00    	movl   $0x0,(%rax)

    return (0);
    b478:	b8 00 00 00 00       	mov    $0x0,%eax
}
    b47d:	5d                   	pop    %rbp
    b47e:	c3                   	retq   

000000000000b47f <_setjmp>:
    xorl    %edx, (_JB_EBP * SE_WORDSIZE)(%eax)
    xorl    %edx, (_JB_ESI * SE_WORDSIZE)(%eax)
    xorl    %edx, (_JB_EDI * SE_WORDSIZE)(%eax)
#endif
#ifdef LINUX64
    PUSHAQ
    b47f:	50                   	push   %rax
    b480:	53                   	push   %rbx
    b481:	51                   	push   %rcx
    b482:	52                   	push   %rdx
    b483:	56                   	push   %rsi
    b484:	57                   	push   %rdi
    b485:	41 50                	push   %r8
    b487:	41 51                	push   %r9
    b489:	41 52                	push   %r10
    b48b:	41 53                	push   %r11
    b48d:	41 54                	push   %r12
    b48f:	41 55                	push   %r13
    b491:	41 56                	push   %r14
    b493:	41 57                	push   %r15
    /* check the buf is within the enclave */
    movq    $SE_WORDSIZE, %rsi
    b495:	48 c7 c6 08 00 00 00 	mov    $0x8,%rsi
    call    sgx_is_within_enclave
    b49c:	e8 64 5e ff ff       	callq  1305 <sgx_is_within_enclave>
    cmpl    $0, %eax
    b4a1:	83 f8 00             	cmp    $0x0,%eax
    jz      .crash
    b4a4:	74 60                	je     b506 <.crash>
    POPAQ
    b4a6:	41 5f                	pop    %r15
    b4a8:	41 5e                	pop    %r14
    b4aa:	41 5d                	pop    %r13
    b4ac:	41 5c                	pop    %r12
    b4ae:	41 5b                	pop    %r11
    b4b0:	41 5a                	pop    %r10
    b4b2:	41 59                	pop    %r9
    b4b4:	41 58                	pop    %r8
    b4b6:	5f                   	pop    %rdi
    b4b7:	5e                   	pop    %rsi
    b4b8:	5a                   	pop    %rdx
    b4b9:	59                   	pop    %rcx
    b4ba:	5b                   	pop    %rbx
    b4bb:	58                   	pop    %rax
    /* store the registers */
    movq    (%rsp),%r11
    b4bc:	4c 8b 1c 24          	mov    (%rsp),%r11
    movq    %rbx, (_JB_RBX * SE_WORDSIZE)(%rdi)
    b4c0:	48 89 1f             	mov    %rbx,(%rdi)
    movq    %rbp, (_JB_RBP * SE_WORDSIZE)(%rdi)
    b4c3:	48 89 6f 08          	mov    %rbp,0x8(%rdi)
    movq    %r12, (_JB_R12 * SE_WORDSIZE)(%rdi)
    b4c7:	4c 89 67 10          	mov    %r12,0x10(%rdi)
    movq    %r13, (_JB_R13 * SE_WORDSIZE)(%rdi)
    b4cb:	4c 89 6f 18          	mov    %r13,0x18(%rdi)
    movq    %r14, (_JB_R14 * SE_WORDSIZE)(%rdi)
    b4cf:	4c 89 77 20          	mov    %r14,0x20(%rdi)
    movq    %r15, (_JB_R15 * SE_WORDSIZE)(%rdi)
    b4d3:	4c 89 7f 28          	mov    %r15,0x28(%rdi)
    movq    %rsp, (_JB_RSP * SE_WORDSIZE)(%rdi)
    b4d7:	48 89 67 30          	mov    %rsp,0x30(%rdi)
    movq    %r11, (_JB_PC  * SE_WORDSIZE)(%rdi)
    b4db:	4c 89 5f 38          	mov    %r11,0x38(%rdi)
    /* use statck_guard as cookie*/
    call    get_stack_guard
    b4df:	e8 c5 11 00 00       	callq  c6a9 <get_stack_guard>
    xorq    %rax, (_JB_RBX * SE_WORDSIZE)(%rdi)
    b4e4:	48 31 07             	xor    %rax,(%rdi)
    xorq    %rax, (_JB_RBP * SE_WORDSIZE)(%rdi)
    b4e7:	48 31 47 08          	xor    %rax,0x8(%rdi)
    xorq    %rax, (_JB_R12 * SE_WORDSIZE)(%rdi)
    b4eb:	48 31 47 10          	xor    %rax,0x10(%rdi)
    xorq    %rax, (_JB_R13 * SE_WORDSIZE)(%rdi)
    b4ef:	48 31 47 18          	xor    %rax,0x18(%rdi)
    xorq    %rax, (_JB_R14 * SE_WORDSIZE)(%rdi)
    b4f3:	48 31 47 20          	xor    %rax,0x20(%rdi)
    xorq    %rax, (_JB_R15 * SE_WORDSIZE)(%rdi)
    b4f7:	48 31 47 28          	xor    %rax,0x28(%rdi)
    xorq    %rax, (_JB_RSP * SE_WORDSIZE)(%rdi)
    b4fb:	48 31 47 30          	xor    %rax,0x30(%rdi)
    xorq    %rax, (_JB_PC  * SE_WORDSIZE)(%rdi)
    b4ff:	48 31 47 38          	xor    %rax,0x38(%rdi)
#endif	
    xorl    %eax,%eax
    b503:	31 c0                	xor    %eax,%eax
    ret
    b505:	c3                   	retq   

000000000000b506 <.crash>:
.crash:
    ud2
    b506:	0f 0b                	ud2    

000000000000b508 <_longjmp>:
    movl    %ecx, (0)(%edx)
    popl    %eax   
    movl    %edx, %esp
#endif
#ifdef LINUX64
    PUSHAQ
    b508:	50                   	push   %rax
    b509:	53                   	push   %rbx
    b50a:	51                   	push   %rcx
    b50b:	52                   	push   %rdx
    b50c:	56                   	push   %rsi
    b50d:	57                   	push   %rdi
    b50e:	41 50                	push   %r8
    b510:	41 51                	push   %r9
    b512:	41 52                	push   %r10
    b514:	41 53                	push   %r11
    b516:	41 54                	push   %r12
    b518:	41 55                	push   %r13
    b51a:	41 56                	push   %r14
    b51c:	41 57                	push   %r15
    pushq   %rdi
    b51e:	57                   	push   %rdi
    /* check the buf is within the enclave */
    movq    $SE_WORDSIZE, %rsi
    b51f:	48 c7 c6 08 00 00 00 	mov    $0x8,%rsi
    call    sgx_is_within_enclave
    b526:	e8 da 5d ff ff       	callq  1305 <sgx_is_within_enclave>
    cmpl    $0, %eax
    b52b:	83 f8 00             	cmp    $0x0,%eax
    jz      .crash
    b52e:	74 d6                	je     b506 <.crash>
    popq     %rdi
    b530:	5f                   	pop    %rdi
    /* restore xsp*/
    movq    (_JB_RSP * SE_WORDSIZE)(%rdi),%rdx
    b531:	48 8b 57 30          	mov    0x30(%rdi),%rdx
    call    get_stack_guard
    b535:	e8 6f 11 00 00       	callq  c6a9 <get_stack_guard>
    xorq    %rax, %rdx
    b53a:	48 31 c2             	xor    %rax,%rdx
    pushq   %rdx
    b53d:	52                   	push   %rdx
    /* check restored rsp is on current statck */
    popq    %rdi
    b53e:	5f                   	pop    %rdi
    call    is_valid_sp
    b53f:	e8 48 87 ff ff       	callq  3c8c <is_valid_sp>
    cmpl    $0, %eax
    b544:	83 f8 00             	cmp    $0x0,%eax
    jz      .crash
    b547:	74 bd                	je     b506 <.crash>
    POPAQ
    b549:	41 5f                	pop    %r15
    b54b:	41 5e                	pop    %r14
    b54d:	41 5d                	pop    %r13
    b54f:	41 5c                	pop    %r12
    b551:	41 5b                	pop    %r11
    b553:	41 5a                	pop    %r10
    b555:	41 59                	pop    %r9
    b557:	41 58                	pop    %r8
    b559:	5f                   	pop    %rdi
    b55a:	5e                   	pop    %rsi
    b55b:	5a                   	pop    %rdx
    b55c:	59                   	pop    %rcx
    b55d:	5b                   	pop    %rbx
    b55e:	58                   	pop    %rax
    /* restore the registers */
    movl    %esi,%eax
    b55f:	89 f0                	mov    %esi,%eax
    movq    (_JB_RBX * SE_WORDSIZE)(%rdi),%rbx
    b561:	48 8b 1f             	mov    (%rdi),%rbx
    movq    (_JB_RBP * SE_WORDSIZE)(%rdi),%rsi
    b564:	48 8b 77 08          	mov    0x8(%rdi),%rsi
    movq    (_JB_R12 * SE_WORDSIZE)(%rdi),%r12
    b568:	4c 8b 67 10          	mov    0x10(%rdi),%r12
    movq    (_JB_R13 * SE_WORDSIZE)(%rdi),%r13
    b56c:	4c 8b 6f 18          	mov    0x18(%rdi),%r13
    movq    (_JB_R14 * SE_WORDSIZE)(%rdi),%r14
    b570:	4c 8b 77 20          	mov    0x20(%rdi),%r14
    movq    (_JB_R15 * SE_WORDSIZE)(%rdi),%r15
    b574:	4c 8b 7f 28          	mov    0x28(%rdi),%r15
    movq    (_JB_RSP * SE_WORDSIZE)(%rdi),%rdx
    b578:	48 8b 57 30          	mov    0x30(%rdi),%rdx
    movq    (_JB_PC  * SE_WORDSIZE)(%rdi),%rcx
    b57c:	48 8b 4f 38          	mov    0x38(%rdi),%rcx
    pushq   %rax
    b580:	50                   	push   %rax
    call    get_stack_guard
    b581:	e8 23 11 00 00       	callq  c6a9 <get_stack_guard>
    xorq    %rax, %rbx
    b586:	48 31 c3             	xor    %rax,%rbx
    xorq    %rax, %rsi
    b589:	48 31 c6             	xor    %rax,%rsi
    xorq    %rax, %r12
    b58c:	49 31 c4             	xor    %rax,%r12
    xorq    %rax, %r13
    b58f:	49 31 c5             	xor    %rax,%r13
    xorq    %rax, %r14
    b592:	49 31 c6             	xor    %rax,%r14
    xorq    %rax, %r15
    b595:	49 31 c7             	xor    %rax,%r15
    xorq    %rax, %rdx
    b598:	48 31 c2             	xor    %rax,%rdx
    xorq    %rax, %rcx
    b59b:	48 31 c1             	xor    %rax,%rcx
    popq    %rax
    b59e:	58                   	pop    %rax
    movq    %rsi, %rbp
    b59f:	48 89 f5             	mov    %rsi,%rbp
    movq    %rcx, 0(%rdx)
    b5a2:	48 89 0a             	mov    %rcx,(%rdx)
    movq    %rdx, %rsp
    b5a5:	48 89 d4             	mov    %rdx,%rsp
#endif
    testl   %eax,%eax
    b5a8:	85 c0                	test   %eax,%eax
    jnz     1f
    b5aa:	75 02                	jne    b5ae <_longjmp+0xa6>
    incl    %eax
    b5ac:	ff c0                	inc    %eax
1:  ret
    b5ae:	c3                   	retq   

000000000000b5af <rsrv_mem_init>:

SE_DECLSPEC_EXPORT size_t g_peak_rsrv_mem_committed = 0;


extern "C" int rsrv_mem_init(void *_rsrv_mem_base, size_t _rsrv_mem_size, size_t _rsrv_mem_min_size)
{
    b5af:	55                   	push   %rbp
    b5b0:	48 89 e5             	mov    %rsp,%rbp
    b5b3:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    b5b7:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    b5bb:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    if ((_rsrv_mem_base == NULL) || (((size_t) _rsrv_mem_base) & (SE_PAGE_SIZE - 1)))
    b5bf:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    b5c4:	74 0e                	je     b5d4 <rsrv_mem_init+0x25>
    b5c6:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b5ca:	25 ff 0f 00 00       	and    $0xfff,%eax
    b5cf:	48 85 c0             	test   %rax,%rax
    b5d2:	74 07                	je     b5db <rsrv_mem_init+0x2c>
        return SGX_ERROR_UNEXPECTED;
    b5d4:	b8 01 00 00 00       	mov    $0x1,%eax
    b5d9:	eb 67                	jmp    b642 <rsrv_mem_init+0x93>

    if (_rsrv_mem_size & (SE_PAGE_SIZE - 1))
    b5db:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b5df:	25 ff 0f 00 00       	and    $0xfff,%eax
    b5e4:	48 85 c0             	test   %rax,%rax
    b5e7:	74 07                	je     b5f0 <rsrv_mem_init+0x41>
        return SGX_ERROR_UNEXPECTED;
    b5e9:	b8 01 00 00 00       	mov    $0x1,%eax
    b5ee:	eb 52                	jmp    b642 <rsrv_mem_init+0x93>

    if (_rsrv_mem_min_size & (SE_PAGE_SIZE - 1))
    b5f0:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b5f4:	25 ff 0f 00 00       	and    $0xfff,%eax
    b5f9:	48 85 c0             	test   %rax,%rax
    b5fc:	74 07                	je     b605 <rsrv_mem_init+0x56>
        return SGX_ERROR_UNEXPECTED;
    b5fe:	b8 01 00 00 00       	mov    $0x1,%eax
    b603:	eb 3d                	jmp    b642 <rsrv_mem_init+0x93>

    if (_rsrv_mem_size > SIZE_MAX - (size_t)rsrv_mem_base)
    b605:	48 8b 05 1c 58 00 00 	mov    0x581c(%rip),%rax        # 10e28 <rsrv_mem_base>
    b60c:	48 f7 d0             	not    %rax
    b60f:	48 39 45 f0          	cmp    %rax,-0x10(%rbp)
    b613:	76 07                	jbe    b61c <rsrv_mem_init+0x6d>
        return SGX_ERROR_UNEXPECTED;
    b615:	b8 01 00 00 00       	mov    $0x1,%eax
    b61a:	eb 26                	jmp    b642 <rsrv_mem_init+0x93>

    rsrv_mem_base = _rsrv_mem_base;
    b61c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b620:	48 89 05 01 58 00 00 	mov    %rax,0x5801(%rip)        # 10e28 <rsrv_mem_base>
    rsrv_mem_size = _rsrv_mem_size;
    b627:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    b62b:	48 89 05 fe 57 00 00 	mov    %rax,0x57fe(%rip)        # 10e30 <rsrv_mem_size>
    rsrv_mem_min_size = _rsrv_mem_min_size;
    b632:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b636:	48 89 05 fb 57 00 00 	mov    %rax,0x57fb(%rip)        # 10e38 <rsrv_mem_min_size>

    return SGX_SUCCESS;
    b63d:	b8 00 00 00 00       	mov    $0x0,%eax
}
    b642:	5d                   	pop    %rbp
    b643:	c3                   	retq   

000000000000b644 <__errno>:
#include <errno.h>

extern int *get_errno_addr(void);

int *__errno(void)
{
    b644:	55                   	push   %rbp
    b645:	48 89 e5             	mov    %rsp,%rbp
/*
 * get errno's address from TD section.
 */
    return get_errno_addr();
    b648:	e8 07 85 ff ff       	callq  3b54 <get_errno_addr>
}
    b64d:	5d                   	pop    %rbp
    b64e:	c3                   	retq   

000000000000b64f <tcrypto_access_version_dummy1>:
#include "ippcp.h"
#include "se_cpu_feature.h"
#include "se_cdefs.h"

// add a version to tcrypto.
SGX_ACCESS_VERSION(tcrypto, 1)
    b64f:	55                   	push   %rbp
    b650:	48 89 e5             	mov    %rsp,%rbp
    b653:	c6 05 06 5a 00 00 73 	movb   $0x73,0x5a06(%rip)        # 11060 <sgx_tcrypto_version>
    b65a:	48 8d 05 ff 59 00 00 	lea    0x59ff(%rip),%rax        # 11060 <sgx_tcrypto_version>
    b661:	5d                   	pop    %rbp
    b662:	c3                   	retq   

000000000000b663 <sgx_init_crypto_lib>:
/* Crypto Library Initialization
* Parameters:
* 	Return: sgx_status_t  - SGX_SUCCESS or failure as defined sgx_error.h
*	Inputs: uint64_t cpu_feature_indicator - Bit array of host CPU feature bits */
extern "C" sgx_status_t sgx_init_crypto_lib(uint64_t cpu_feature_indicator, uint32_t *cpuid_table)
{
    b663:	55                   	push   %rbp
    b664:	48 89 e5             	mov    %rsp,%rbp
    b667:	48 83 ec 10          	sub    $0x10,%rsp
    b66b:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    b66f:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    (void)(cpuid_table);

    return init_ipp_cpuid(cpu_feature_indicator);
    b673:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b677:	48 89 c7             	mov    %rax,%rdi
    b67a:	e8 02 00 00 00       	callq  b681 <init_ipp_cpuid>
}
    b67f:	c9                   	leaveq 
    b680:	c3                   	retq   

000000000000b681 <init_ipp_cpuid>:
/* IPP library Initialization
* Parameters:
* 	Return: sgx_status_t  - SGX_SUCCESS or failure as defined sgx_error.h
*	Inputs: uint64_t cpu_feature_indicator - Bit array of host CPU feature bits */
extern "C" sgx_status_t init_ipp_cpuid(uint64_t cpu_feature_indicator)
{
    b681:	55                   	push   %rbp
    b682:	48 89 e5             	mov    %rsp,%rbp
    b685:	48 83 ec 20          	sub    $0x20,%rsp
    b689:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    IppStatus error_code = ippStsNoOperation;
    b68d:	c7 45 f4 01 00 00 00 	movl   $0x1,-0xc(%rbp)
    if (ippcpSetCpuFeatures == NULL) {
    b694:	48 8b 05 45 59 00 00 	mov    0x5945(%rip),%rax        # 10fe0 <ippcpSetCpuFeatures>
    b69b:	48 85 c0             	test   %rax,%rax
    b69e:	75 0a                	jne    b6aa <init_ipp_cpuid+0x29>
        return SGX_SUCCESS;
    b6a0:	b8 00 00 00 00       	mov    $0x0,%eax
    b6a5:	e9 81 02 00 00       	jmpq   b92b <init_ipp_cpuid+0x2aa>
    //       1. AVX2
    //       2. SSE4.1
    //  We set SSE4.1 as the baseline.
    // Set the IPP feature bits based on host attributes that have been collected
    // NOTE: Some sanity check
    Ipp64u ippCpuFeatures = 0;
    b6aa:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
    b6b1:	00 
    if ((cpu_feature_indicator & CPU_FEATURE_SSE4_1) == CPU_FEATURE_SSE4_1)
    b6b2:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b6b6:	25 00 02 00 00       	and    $0x200,%eax
    b6bb:	48 85 c0             	test   %rax,%rax
    b6be:	0f 84 31 02 00 00    	je     b8f5 <init_ipp_cpuid+0x274>
    {
        // Some sanity checking has been performed when setting the feature mask
        // If SSE4.1 is set, then all earlier SSE/MMX ISA enhancements are available
        ippCpuFeatures |= (ippCPUID_SSE41 | ippCPUID_MMX | ippCPUID_SSE |
    b6c4:	48 83 4d f8 5f       	orq    $0x5f,-0x8(%rbp)
            ippCPUID_SSE2 | ippCPUID_SSE3 | ippCPUID_SSSE3);
        if ((cpu_feature_indicator & CPU_FEATURE_MOVBE) == CPU_FEATURE_MOVBE)
    b6c9:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b6cd:	25 00 08 00 00       	and    $0x800,%eax
    b6d2:	48 85 c0             	test   %rax,%rax
    b6d5:	74 05                	je     b6dc <init_ipp_cpuid+0x5b>
        {
            ippCpuFeatures |= ippCPUID_MOVBE;
    b6d7:	48 83 4d f8 20       	orq    $0x20,-0x8(%rbp)
        }
        if ((cpu_feature_indicator & CPU_FEATURE_SSE4_2) == CPU_FEATURE_SSE4_2)
    b6dc:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b6e0:	25 00 04 00 00       	and    $0x400,%eax
    b6e5:	48 85 c0             	test   %rax,%rax
    b6e8:	74 08                	je     b6f2 <init_ipp_cpuid+0x71>
        {
            ippCpuFeatures |= ippCPUID_SSE42;
    b6ea:	48 81 4d f8 80 00 00 	orq    $0x80,-0x8(%rbp)
    b6f1:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX) == CPU_FEATURE_AVX)
    b6f2:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b6f6:	25 00 00 01 00       	and    $0x10000,%eax
    b6fb:	48 85 c0             	test   %rax,%rax
    b6fe:	74 10                	je     b710 <init_ipp_cpuid+0x8f>
        {
            ippCpuFeatures |= ippCPUID_AVX;
    b700:	48 81 4d f8 00 01 00 	orq    $0x100,-0x8(%rbp)
    b707:	00 
            ippCpuFeatures |= ippAVX_ENABLEDBYOS;
    b708:	48 81 4d f8 00 02 00 	orq    $0x200,-0x8(%rbp)
    b70f:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AES) == CPU_FEATURE_AES)
    b710:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b714:	25 00 40 00 00       	and    $0x4000,%eax
    b719:	48 85 c0             	test   %rax,%rax
    b71c:	74 08                	je     b726 <init_ipp_cpuid+0xa5>
        {
            ippCpuFeatures |= ippCPUID_AES;
    b71e:	48 81 4d f8 00 04 00 	orq    $0x400,-0x8(%rbp)
    b725:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_PCLMULQDQ) == CPU_FEATURE_PCLMULQDQ)
    b726:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b72a:	25 00 20 00 00       	and    $0x2000,%eax
    b72f:	48 85 c0             	test   %rax,%rax
    b732:	74 08                	je     b73c <init_ipp_cpuid+0xbb>
        {
            ippCpuFeatures |= ippCPUID_CLMUL;
    b734:	48 81 4d f8 00 08 00 	orq    $0x800,-0x8(%rbp)
    b73b:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_RDRND) == CPU_FEATURE_RDRND)
    b73c:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b740:	25 00 00 02 00       	and    $0x20000,%eax
    b745:	48 85 c0             	test   %rax,%rax
    b748:	74 08                	je     b752 <init_ipp_cpuid+0xd1>
        {
            ippCpuFeatures |= ippCPUID_RDRAND;
    b74a:	48 81 4d f8 00 20 00 	orq    $0x2000,-0x8(%rbp)
    b751:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_F16C) == CPU_FEATURE_F16C)
    b752:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b756:	25 00 80 00 00       	and    $0x8000,%eax
    b75b:	48 85 c0             	test   %rax,%rax
    b75e:	74 08                	je     b768 <init_ipp_cpuid+0xe7>
        {
            ippCpuFeatures |= ippCPUID_F16C;
    b760:	48 81 4d f8 00 40 00 	orq    $0x4000,-0x8(%rbp)
    b767:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX2) == CPU_FEATURE_AVX2)
    b768:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b76c:	25 00 00 80 00       	and    $0x800000,%eax
    b771:	48 85 c0             	test   %rax,%rax
    b774:	74 08                	je     b77e <init_ipp_cpuid+0xfd>
        {
            ippCpuFeatures |= ippCPUID_AVX2;
    b776:	48 81 4d f8 00 80 00 	orq    $0x8000,-0x8(%rbp)
    b77d:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_ADX) == CPU_FEATURE_ADX)
    b77e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b782:	25 00 00 00 10       	and    $0x10000000,%eax
    b787:	48 85 c0             	test   %rax,%rax
    b78a:	74 08                	je     b794 <init_ipp_cpuid+0x113>
        {
            ippCpuFeatures |= ippCPUID_ADCOX;
    b78c:	48 81 4d f8 00 00 01 	orq    $0x10000,-0x8(%rbp)
    b793:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_RDSEED) == CPU_FEATURE_RDSEED)
    b794:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b798:	25 00 00 00 20       	and    $0x20000000,%eax
    b79d:	48 85 c0             	test   %rax,%rax
    b7a0:	74 08                	je     b7aa <init_ipp_cpuid+0x129>
        {
            ippCpuFeatures |= ippCPUID_RDSEED;
    b7a2:	48 81 4d f8 00 00 02 	orq    $0x20000,-0x8(%rbp)
    b7a9:	00 
        }
	if ((cpu_feature_indicator & CPU_FEATURE_SHA) == CPU_FEATURE_SHA)
    b7aa:	48 b8 00 00 00 00 08 	movabs $0x800000000,%rax
    b7b1:	00 00 00 
    b7b4:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b7b8:	48 85 c0             	test   %rax,%rax
    b7bb:	74 08                	je     b7c5 <init_ipp_cpuid+0x144>
        {
            ippCpuFeatures |= ippCPUID_SHA;
    b7bd:	48 81 4d f8 00 00 08 	orq    $0x80000,-0x8(%rbp)
    b7c4:	00 
        }
        
	// AVX512
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512F) == CPU_FEATURE_AVX512F)
    b7c5:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b7c9:	25 00 00 00 08       	and    $0x8000000,%eax
    b7ce:	48 85 c0             	test   %rax,%rax
    b7d1:	74 16                	je     b7e9 <init_ipp_cpuid+0x168>
        {
            ippCpuFeatures |= ippCPUID_AVX512F;
    b7d3:	48 81 4d f8 00 00 10 	orq    $0x100000,-0x8(%rbp)
    b7da:	00 
            ippCpuFeatures |= ippAVX512_ENABLEDBYOS;
    b7db:	48 b8 00 00 00 00 02 	movabs $0x200000000,%rax
    b7e2:	00 00 00 
    b7e5:	48 09 45 f8          	or     %rax,-0x8(%rbp)
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512PF) == CPU_FEATURE_AVX512PF)
    b7e9:	48 b8 00 00 00 00 02 	movabs $0x200000000,%rax
    b7f0:	00 00 00 
    b7f3:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b7f7:	48 85 c0             	test   %rax,%rax
    b7fa:	74 08                	je     b804 <init_ipp_cpuid+0x183>
        {
            ippCpuFeatures |= ippCPUID_AVX512PF;
    b7fc:	48 81 4d f8 00 00 80 	orq    $0x800000,-0x8(%rbp)
    b803:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512ER) == CPU_FEATURE_AVX512ER)
    b804:	48 b8 00 00 00 00 01 	movabs $0x100000000,%rax
    b80b:	00 00 00 
    b80e:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b812:	48 85 c0             	test   %rax,%rax
    b815:	74 08                	je     b81f <init_ipp_cpuid+0x19e>
        {
            ippCpuFeatures |= ippCPUID_AVX512ER;
    b817:	48 81 4d f8 00 00 40 	orq    $0x400000,-0x8(%rbp)
    b81e:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512CD) == CPU_FEATURE_AVX512CD)
    b81f:	48 b8 00 00 00 00 04 	movabs $0x400000000,%rax
    b826:	00 00 00 
    b829:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b82d:	48 85 c0             	test   %rax,%rax
    b830:	74 08                	je     b83a <init_ipp_cpuid+0x1b9>
        {
            ippCpuFeatures |= ippCPUID_AVX512CD;
    b832:	48 81 4d f8 00 00 20 	orq    $0x200000,-0x8(%rbp)
    b839:	00 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512DQ) == CPU_FEATURE_AVX512DQ)
    b83a:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b83e:	25 00 00 00 01       	and    $0x1000000,%eax
    b843:	48 85 c0             	test   %rax,%rax
    b846:	74 08                	je     b850 <init_ipp_cpuid+0x1cf>
        {
            ippCpuFeatures |= ippCPUID_AVX512DQ;
    b848:	48 81 4d f8 00 00 00 	orq    $0x2000000,-0x8(%rbp)
    b84f:	02 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512BW) == CPU_FEATURE_AVX512BW)
    b850:	48 b8 00 00 00 00 20 	movabs $0x2000000000,%rax
    b857:	00 00 00 
    b85a:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b85e:	48 85 c0             	test   %rax,%rax
    b861:	74 08                	je     b86b <init_ipp_cpuid+0x1ea>
        {
            ippCpuFeatures |= ippCPUID_AVX512BW;
    b863:	48 81 4d f8 00 00 00 	orq    $0x1000000,-0x8(%rbp)
    b86a:	01 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512VL) == CPU_FEATURE_AVX512VL)
    b86b:	48 b8 00 00 00 00 40 	movabs $0x4000000000,%rax
    b872:	00 00 00 
    b875:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b879:	48 85 c0             	test   %rax,%rax
    b87c:	74 08                	je     b886 <init_ipp_cpuid+0x205>
        {
            ippCpuFeatures |= ippCPUID_AVX512VL;
    b87e:	48 81 4d f8 00 00 00 	orq    $0x4000000,-0x8(%rbp)
    b885:	04 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512VBMI) == CPU_FEATURE_AVX512VBMI)
    b886:	48 b8 00 00 00 00 80 	movabs $0x8000000000,%rax
    b88d:	00 00 00 
    b890:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b894:	48 85 c0             	test   %rax,%rax
    b897:	74 08                	je     b8a1 <init_ipp_cpuid+0x220>
        {
            ippCpuFeatures |= ippCPUID_AVX512VBMI;
    b899:	48 81 4d f8 00 00 00 	orq    $0x8000000,-0x8(%rbp)
    b8a0:	08 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512_4VNNIW) == CPU_FEATURE_AVX512_4VNNIW)
    b8a1:	48 b8 00 00 00 00 00 	movabs $0x20000000000,%rax
    b8a8:	02 00 00 
    b8ab:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b8af:	48 85 c0             	test   %rax,%rax
    b8b2:	74 08                	je     b8bc <init_ipp_cpuid+0x23b>
        {
            ippCpuFeatures |= ippCPUID_AVX512_4VNNIW;
    b8b4:	48 81 4d f8 00 00 00 	orq    $0x40000000,-0x8(%rbp)
    b8bb:	40 
        }
        if ((cpu_feature_indicator & CPU_FEATURE_AVX512_4FMAPS) == CPU_FEATURE_AVX512_4FMAPS)
    b8bc:	48 b8 00 00 00 00 00 	movabs $0x10000000000,%rax
    b8c3:	01 00 00 
    b8c6:	48 23 45 e8          	and    -0x18(%rbp),%rax
    b8ca:	48 85 c0             	test   %rax,%rax
    b8cd:	74 08                	je     b8d7 <init_ipp_cpuid+0x256>
        {
            ippCpuFeatures |= ippCPUID_AVX512_4FMADDPS;
    b8cf:	48 81 4d f8 00 00 00 	orq    $0x20000000,-0x8(%rbp)
    b8d6:	20 
        }

        if ((cpu_feature_indicator & CPU_FEATURE_AVX512IFMA52) == CPU_FEATURE_AVX512IFMA52)
    b8d7:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    b8db:	25 00 00 00 40       	and    $0x40000000,%eax
    b8e0:	48 85 c0             	test   %rax,%rax
    b8e3:	74 17                	je     b8fc <init_ipp_cpuid+0x27b>
        {
            ippCpuFeatures |= ippCPUID_AVX512IFMA;
    b8e5:	48 b8 00 00 00 00 01 	movabs $0x100000000,%rax
    b8ec:	00 00 00 
    b8ef:	48 09 45 f8          	or     %rax,-0x8(%rbp)
    b8f3:	eb 07                	jmp    b8fc <init_ipp_cpuid+0x27b>
        }
    }
    else
    {
        // Return error if the old platoform has no SSE4.1
        return SGX_ERROR_INVALID_PARAMETER;
    b8f5:	b8 02 00 00 00       	mov    $0x2,%eax
    b8fa:	eb 2f                	jmp    b92b <init_ipp_cpuid+0x2aa>

    }

    // Call SetCpuFeatures() to set the IPP library with the collected CPU features
    ippCpuFeatures |= ippCPUID_NOCHECK; /* Force ippcpSetCpuFeatures to set CPU features without check */
    b8fc:	48 b8 00 00 00 00 00 	movabs $0x8000000000000000,%rax
    b903:	00 00 80 
    b906:	48 09 45 f8          	or     %rax,-0x8(%rbp)
    error_code = ippcpSetCpuFeatures(ippCpuFeatures);
    b90a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    b90e:	48 89 c7             	mov    %rax,%rdi
    b911:	e8 02 57 ff ff       	callq  1018 <ippcpSetCpuFeatures@plt>
    b916:	89 45 f4             	mov    %eax,-0xc(%rbp)

    if (error_code != ippStsNoErr)
    b919:	83 7d f4 00          	cmpl   $0x0,-0xc(%rbp)
    b91d:	74 07                	je     b926 <init_ipp_cpuid+0x2a5>
    {
        return SGX_ERROR_INVALID_PARAMETER;
    b91f:	b8 02 00 00 00       	mov    $0x2,%eax
    b924:	eb 05                	jmp    b92b <init_ipp_cpuid+0x2aa>
    }
    return SGX_SUCCESS;
    b926:	b8 00 00 00 00       	mov    $0x0,%eax
}
    b92b:	c9                   	leaveq 
    b92c:	c3                   	retq   

000000000000b92d <tservice_access_version_dummy1>:
#include "sgx_trts.h"
#include "trts_inst.h"
#include "se_cdefs.h"

// add a version to tservice.
SGX_ACCESS_VERSION(tservice, 1)
    b92d:	55                   	push   %rbp
    b92e:	48 89 e5             	mov    %rsp,%rbp
    b931:	c6 05 48 57 00 00 73 	movb   $0x73,0x5748(%rip)        # 11080 <sgx_tservice_version>
    b938:	48 8d 05 41 57 00 00 	lea    0x5741(%rip),%rax        # 11080 <sgx_tservice_version>
    b93f:	5d                   	pop    %rbp
    b940:	c3                   	retq   

000000000000b941 <sgx_create_report>:

extern "C" void * __memset(void *dst, int c, size_t n);

sgx_status_t sgx_create_report(const sgx_target_info_t *target_info, const sgx_report_data_t *report_data, sgx_report_t *report)
{
    b941:	4c 8d 54 24 08       	lea    0x8(%rsp),%r10
    b946:	48 81 e4 00 fe ff ff 	and    $0xfffffffffffffe00,%rsp
    b94d:	41 ff 72 f8          	pushq  -0x8(%r10)
    b951:	55                   	push   %rbp
    b952:	48 89 e5             	mov    %rsp,%rbp
    b955:	41 52                	push   %r10
    b957:	48 81 ec e8 09 00 00 	sub    $0x9e8,%rsp
    b95e:	48 89 bd 78 f7 ff ff 	mov    %rdi,-0x888(%rbp)
    b965:	48 89 b5 70 f7 ff ff 	mov    %rsi,-0x890(%rbp)
    b96c:	48 89 95 68 f7 ff ff 	mov    %rdx,-0x898(%rbp)
    b973:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    b97a:	00 00 
    b97c:	48 89 85 08 fe ff ff 	mov    %rax,-0x1f8(%rbp)
    b983:	31 c0                	xor    %eax,%eax
    static_assert(sizeof(*target_info) == 512, "sgx_target_info_t");
    static_assert(sizeof(*report_data) == 64, "sgx_report_data_t");
    static_assert(sizeof(*report) == 432, "sgx_report_t");

    alignas(REPORT_DATA_ALIGN_SIZE) sgx_report_data_t tmp_report_data;
    __memset((void *)&tmp_report_data, 0, sizeof(sgx_report_data_t));
    b985:	48 8d 85 90 f7 ff ff 	lea    -0x870(%rbp),%rax
    b98c:	ba 40 00 00 00       	mov    $0x40,%edx
    b991:	be 00 00 00 00       	mov    $0x0,%esi
    b996:	48 89 c7             	mov    %rax,%rdi
    b999:	e8 c1 f5 ff ff       	callq  af5f <__memset>
    alignas(TARGET_INFO_ALIGN_SIZE) sgx_target_info_t tmp_target_info;
    __memset((void *)&tmp_target_info, 0, sizeof(sgx_target_info_t));    
    b99e:	48 8d 85 10 fa ff ff 	lea    -0x5f0(%rbp),%rax
    b9a5:	ba 00 02 00 00       	mov    $0x200,%edx
    b9aa:	be 00 00 00 00       	mov    $0x0,%esi
    b9af:	48 89 c7             	mov    %rax,%rdi
    b9b2:	e8 a8 f5 ff ff       	callq  af5f <__memset>
    alignas(REPORT_ALIGN_SIZE)sgx_report_t tmp_report;
    __memset((void *)&tmp_report, 0, sizeof(sgx_report_t));
    b9b7:	48 8d 85 10 f8 ff ff 	lea    -0x7f0(%rbp),%rax
    b9be:	ba b0 01 00 00       	mov    $0x1b0,%edx
    b9c3:	be 00 00 00 00       	mov    $0x0,%esi
    b9c8:	48 89 c7             	mov    %rax,%rdi
    b9cb:	e8 8f f5 ff ff       	callq  af5f <__memset>

    // check parameters
    //
    // target_info is allowed to be NULL, but if it is not NULL, it must be within the enclave
    if(target_info)
    b9d0:	48 83 bd 78 f7 ff ff 	cmpq   $0x0,-0x888(%rbp)
    b9d7:	00 
    b9d8:	74 46                	je     ba20 <sgx_create_report+0xdf>
    {
        if (!sgx_is_within_enclave(target_info, sizeof(*target_info)))
    b9da:	48 8b 85 78 f7 ff ff 	mov    -0x888(%rbp),%rax
    b9e1:	be 00 02 00 00       	mov    $0x200,%esi
    b9e6:	48 89 c7             	mov    %rax,%rdi
    b9e9:	e8 17 59 ff ff       	callq  1305 <sgx_is_within_enclave>
    b9ee:	85 c0                	test   %eax,%eax
    b9f0:	0f 94 c0             	sete   %al
    b9f3:	84 c0                	test   %al,%al
    b9f5:	74 0a                	je     ba01 <sgx_create_report+0xc0>
            return SGX_ERROR_INVALID_PARAMETER;
    b9f7:	b8 02 00 00 00       	mov    $0x2,%eax
    b9fc:	e9 8a 01 00 00       	jmpq   bb8b <sgx_create_report+0x24a>
        tmp_target_info = *target_info;
    ba01:	48 8b 95 78 f7 ff ff 	mov    -0x888(%rbp),%rdx
    ba08:	48 8d 85 10 fa ff ff 	lea    -0x5f0(%rbp),%rax
    ba0f:	48 89 d6             	mov    %rdx,%rsi
    ba12:	ba 40 00 00 00       	mov    $0x40,%edx
    ba17:	48 89 c7             	mov    %rax,%rdi
    ba1a:	48 89 d1             	mov    %rdx,%rcx
    ba1d:	f3 48 a5             	rep movsq %ds:(%rsi),%es:(%rdi)
    }
    // report_data is allowed to be NULL, but if it is not NULL, it must be within the enclave
    if(report_data)
    ba20:	48 83 bd 70 f7 ff ff 	cmpq   $0x0,-0x890(%rbp)
    ba27:	00 
    ba28:	0f 84 85 00 00 00    	je     bab3 <sgx_create_report+0x172>
    {
        if(!sgx_is_within_enclave(report_data, sizeof(*report_data)))
    ba2e:	48 8b 85 70 f7 ff ff 	mov    -0x890(%rbp),%rax
    ba35:	be 40 00 00 00       	mov    $0x40,%esi
    ba3a:	48 89 c7             	mov    %rax,%rdi
    ba3d:	e8 c3 58 ff ff       	callq  1305 <sgx_is_within_enclave>
    ba42:	85 c0                	test   %eax,%eax
    ba44:	0f 94 c0             	sete   %al
    ba47:	84 c0                	test   %al,%al
    ba49:	74 0a                	je     ba55 <sgx_create_report+0x114>
            return SGX_ERROR_INVALID_PARAMETER;
    ba4b:	b8 02 00 00 00       	mov    $0x2,%eax
    ba50:	e9 36 01 00 00       	jmpq   bb8b <sgx_create_report+0x24a>
        tmp_report_data = *report_data;
    ba55:	48 8b 8d 70 f7 ff ff 	mov    -0x890(%rbp),%rcx
    ba5c:	48 8b 01             	mov    (%rcx),%rax
    ba5f:	48 8b 51 08          	mov    0x8(%rcx),%rdx
    ba63:	48 89 85 90 f7 ff ff 	mov    %rax,-0x870(%rbp)
    ba6a:	48 89 95 98 f7 ff ff 	mov    %rdx,-0x868(%rbp)
    ba71:	48 8b 41 10          	mov    0x10(%rcx),%rax
    ba75:	48 8b 51 18          	mov    0x18(%rcx),%rdx
    ba79:	48 89 85 a0 f7 ff ff 	mov    %rax,-0x860(%rbp)
    ba80:	48 89 95 a8 f7 ff ff 	mov    %rdx,-0x858(%rbp)
    ba87:	48 8b 41 20          	mov    0x20(%rcx),%rax
    ba8b:	48 8b 51 28          	mov    0x28(%rcx),%rdx
    ba8f:	48 89 85 b0 f7 ff ff 	mov    %rax,-0x850(%rbp)
    ba96:	48 89 95 b8 f7 ff ff 	mov    %rdx,-0x848(%rbp)
    ba9d:	48 8b 41 30          	mov    0x30(%rcx),%rax
    baa1:	48 8b 51 38          	mov    0x38(%rcx),%rdx
    baa5:	48 89 85 c0 f7 ff ff 	mov    %rax,-0x840(%rbp)
    baac:	48 89 95 c8 f7 ff ff 	mov    %rdx,-0x838(%rbp)
    }
    // report must be within the enclave
    if(!report || !sgx_is_within_enclave(report, sizeof(*report)))
    bab3:	48 83 bd 68 f7 ff ff 	cmpq   $0x0,-0x898(%rbp)
    baba:	00 
    babb:	74 18                	je     bad5 <sgx_create_report+0x194>
    babd:	48 8b 85 68 f7 ff ff 	mov    -0x898(%rbp),%rax
    bac4:	be b0 01 00 00       	mov    $0x1b0,%esi
    bac9:	48 89 c7             	mov    %rax,%rdi
    bacc:	e8 34 58 ff ff       	callq  1305 <sgx_is_within_enclave>
    bad1:	85 c0                	test   %eax,%eax
    bad3:	75 07                	jne    badc <sgx_create_report+0x19b>
    bad5:	b8 01 00 00 00       	mov    $0x1,%eax
    bada:	eb 05                	jmp    bae1 <sgx_create_report+0x1a0>
    badc:	b8 00 00 00 00       	mov    $0x0,%eax
    bae1:	84 c0                	test   %al,%al
    bae3:	74 0a                	je     baef <sgx_create_report+0x1ae>
    {
        return SGX_ERROR_INVALID_PARAMETER;
    bae5:	b8 02 00 00 00       	mov    $0x2,%eax
    baea:	e9 9c 00 00 00       	jmpq   bb8b <sgx_create_report+0x24a>
    }


    // Do EREPORT
    auto failed = do_ereport(&tmp_target_info, &tmp_report_data, &tmp_report);
    baef:	48 8d 95 10 f8 ff ff 	lea    -0x7f0(%rbp),%rdx
    baf6:	48 8d 8d 90 f7 ff ff 	lea    -0x870(%rbp),%rcx
    bafd:	48 8d 85 10 fa ff ff 	lea    -0x5f0(%rbp),%rax
    bb04:	48 89 ce             	mov    %rcx,%rsi
    bb07:	48 89 c7             	mov    %rax,%rdi
    bb0a:	e8 56 0e 00 00       	callq  c965 <do_ereport>
    bb0f:	89 85 84 f7 ff ff    	mov    %eax,-0x87c(%rbp)
    
    // Copy data to the user buffer: *report = tmp_report; 
    // Use a loop to avoid compiler to call memcpy, 
    // which cannot be used during enclave initialization.
    // No need to cleanup the tmp_report as it is not secret.
    if (!failed)
    bb15:	83 bd 84 f7 ff ff 00 	cmpl   $0x0,-0x87c(%rbp)
    bb1c:	75 57                	jne    bb75 <sgx_create_report+0x234>
    {
        static_assert(sizeof(*report) % sizeof(uint64_t) == 0, "sizeof(sgx_report_t) should be multiple of 8");
        for(size_t i = 0; i < sizeof(*report)/sizeof(uint64_t); i++)
    bb1e:	48 c7 85 88 f7 ff ff 	movq   $0x0,-0x878(%rbp)
    bb25:	00 00 00 00 
    bb29:	48 83 bd 88 f7 ff ff 	cmpq   $0x35,-0x878(%rbp)
    bb30:	35 
    bb31:	77 42                	ja     bb75 <sgx_create_report+0x234>
        {
            ((uint64_t*)report)[i] = ((uint64_t*)&tmp_report)[i];
    bb33:	48 8b 85 88 f7 ff ff 	mov    -0x878(%rbp),%rax
    bb3a:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    bb41:	00 
    bb42:	48 8d 85 10 f8 ff ff 	lea    -0x7f0(%rbp),%rax
    bb49:	48 01 d0             	add    %rdx,%rax
    bb4c:	48 8b 95 88 f7 ff ff 	mov    -0x878(%rbp),%rdx
    bb53:	48 8d 0c d5 00 00 00 	lea    0x0(,%rdx,8),%rcx
    bb5a:	00 
    bb5b:	48 8b 95 68 f7 ff ff 	mov    -0x898(%rbp),%rdx
    bb62:	48 01 ca             	add    %rcx,%rdx
    bb65:	48 8b 00             	mov    (%rax),%rax
    bb68:	48 89 02             	mov    %rax,(%rdx)
        for(size_t i = 0; i < sizeof(*report)/sizeof(uint64_t); i++)
    bb6b:	48 83 85 88 f7 ff ff 	addq   $0x1,-0x878(%rbp)
    bb72:	01 
    bb73:	eb b4                	jmp    bb29 <sgx_create_report+0x1e8>
        }
    }


    return failed ? SGX_ERROR_UNEXPECTED : SGX_SUCCESS;
    bb75:	83 bd 84 f7 ff ff 00 	cmpl   $0x0,-0x87c(%rbp)
    bb7c:	74 07                	je     bb85 <sgx_create_report+0x244>
    bb7e:	b8 01 00 00 00       	mov    $0x1,%eax
    bb83:	eb 06                	jmp    bb8b <sgx_create_report+0x24a>
    bb85:	b8 00 00 00 00       	mov    $0x0,%eax
    bb8a:	90                   	nop
}
    bb8b:	48 8b b5 08 fe ff ff 	mov    -0x1f8(%rbp),%rsi
    bb92:	64 48 33 34 25 28 00 	xor    %fs:0x28,%rsi
    bb99:	00 00 
    bb9b:	74 05                	je     bba2 <sgx_create_report+0x261>
    bb9d:	e8 38 97 ff ff       	callq  52da <__stack_chk_fail>
    bba2:	48 81 c4 e8 09 00 00 	add    $0x9e8,%rsp
    bba9:	41 5a                	pop    %r10
    bbab:	5d                   	pop    %rbp
    bbac:	49 8d 62 f8          	lea    -0x8(%r10),%rsp
    bbb0:	c3                   	retq   

000000000000bbb1 <sgx_self_report>:

const sgx_report_t *sgx_self_report(void)
{
    bbb1:	55                   	push   %rbp
    bbb2:	48 89 e5             	mov    %rsp,%rbp
        .mac = {0}
    };

    // Below sgx_create_report() will be called only once during the enclave initialization,
    // so there is no potential race conditional.
    if (0 == _report.body.attributes.flags)
    bbb5:	48 8b 05 94 59 00 00 	mov    0x5994(%rip),%rax        # 11550 <_ZZ15sgx_self_reportE7_report+0x30>
    bbbc:	48 85 c0             	test   %rax,%rax
    bbbf:	75 16                	jne    bbd7 <sgx_self_report+0x26>
        sgx_create_report(nullptr, nullptr, &_report);
    bbc1:	48 8d 15 58 59 00 00 	lea    0x5958(%rip),%rdx        # 11520 <_ZZ15sgx_self_reportE7_report>
    bbc8:	be 00 00 00 00       	mov    $0x0,%esi
    bbcd:	bf 00 00 00 00       	mov    $0x0,%edi
    bbd2:	e8 6a fd ff ff       	callq  b941 <sgx_create_report>

    return &_report;
    bbd7:	48 8d 05 42 59 00 00 	lea    0x5942(%rip),%rax        # 11520 <_ZZ15sgx_self_reportE7_report>
}
    bbde:	5d                   	pop    %rbp
    bbdf:	c3                   	retq   

Disassembly of section .nipx:

000000000000bbe0 <do_init_enclave>:
#endif

extern size_t rsrv_mem_min_size;

sgx_status_t do_init_enclave(void *ms, void *tcs)
{
    bbe0:	55                   	push   %rbp
    bbe1:	48 89 e5             	mov    %rsp,%rbp
    bbe4:	48 83 ec 20          	sub    $0x20,%rsp
    bbe8:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    bbec:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
#ifdef SE_SIM
    UNUSED(tcs);
#endif
    void *enclave_base = get_enclave_base();
    bbf0:	e8 6f 0a 00 00       	callq  c664 <get_enclave_base>
    bbf5:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    if(ENCLAVE_INIT_NOT_STARTED != lock_enclave())
    bbf9:	e8 85 0a 00 00       	callq  c683 <lock_enclave>
    bbfe:	85 c0                	test   %eax,%eax
    bc00:	0f 95 c0             	setne  %al
    bc03:	84 c0                	test   %al,%al
    bc05:	74 0a                	je     bc11 <do_init_enclave+0x31>
    {
        return SGX_ERROR_UNEXPECTED;
    bc07:	b8 01 00 00 00       	mov    $0x1,%eax
    bc0c:	e9 fa 01 00 00       	jmpq   be0b <do_init_enclave+0x22b>
    }
    if(0 != init_enclave(enclave_base, ms))
    bc11:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    bc15:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    bc19:	48 89 d6             	mov    %rdx,%rsi
    bc1c:	48 89 c7             	mov    %rax,%rdi
    bc1f:	e8 e9 01 00 00       	callq  be0d <init_enclave>
    bc24:	85 c0                	test   %eax,%eax
    bc26:	0f 95 c0             	setne  %al
    bc29:	84 c0                	test   %al,%al
    bc2b:	74 0a                	je     bc37 <do_init_enclave+0x57>
    {
        return SGX_ERROR_UNEXPECTED;
    bc2d:	b8 01 00 00 00       	mov    $0x1,%eax
    bc32:	e9 d4 01 00 00       	jmpq   be0b <do_init_enclave+0x22b>
    }

#ifndef SE_SIM
    if (SGX_SUCCESS != do_init_thread(tcs, true))
    bc37:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    bc3b:	be 01 00 00 00       	mov    $0x1,%esi
    bc40:	48 89 c7             	mov    %rax,%rdi
    bc43:	e8 71 6f ff ff       	callq  2bb9 <do_init_thread>
    bc48:	85 c0                	test   %eax,%eax
    bc4a:	0f 95 c0             	setne  %al
    bc4d:	84 c0                	test   %al,%al
    bc4f:	74 0a                	je     bc5b <do_init_enclave+0x7b>
    {
        return SGX_ERROR_UNEXPECTED;
    bc51:	b8 01 00 00 00       	mov    $0x1,%eax
    bc56:	e9 b0 01 00 00       	jmpq   be0b <do_init_enclave+0x22b>
    }

    /* for EDMM, we need to accept the trimming of the POST_REMOVE pages. */
    if (EDMM_supported)
    bc5b:	8b 05 8f 51 00 00    	mov    0x518f(%rip),%eax        # 10df0 <EDMM_supported>
    bc61:	85 c0                	test   %eax,%eax
    bc63:	0f 84 1d 01 00 00    	je     bd86 <do_init_enclave+0x1a6>
    {
        if (0 != accept_post_remove(&g_global_data.layout_table[0], &g_global_data.layout_table[0] + g_global_data.layout_entry_num, 0))
    bc69:	48 8d 05 10 15 00 00 	lea    0x1510(%rip),%rax        # d180 <g_global_data>
    bc70:	8b 80 28 01 00 00    	mov    0x128(%rax),%eax
    bc76:	89 c0                	mov    %eax,%eax
    bc78:	48 c1 e0 05          	shl    $0x5,%rax
    bc7c:	48 89 c2             	mov    %rax,%rdx
    bc7f:	48 8d 05 fa 14 00 00 	lea    0x14fa(%rip),%rax        # d180 <g_global_data>
    bc86:	48 8d 80 30 01 00 00 	lea    0x130(%rax),%rax
    bc8d:	48 01 d0             	add    %rdx,%rax
    bc90:	ba 00 00 00 00       	mov    $0x0,%edx
    bc95:	48 89 c6             	mov    %rax,%rsi
    bc98:	48 8d 05 e1 14 00 00 	lea    0x14e1(%rip),%rax        # d180 <g_global_data>
    bc9f:	48 8d b8 30 01 00 00 	lea    0x130(%rax),%rdi
    bca6:	e8 5e 5d ff ff       	callq  1a09 <_Z18accept_post_removePVK9_layout_tS1_m>
    bcab:	85 c0                	test   %eax,%eax
    bcad:	0f 95 c0             	setne  %al
    bcb0:	84 c0                	test   %al,%al
    bcb2:	74 0a                	je     bcbe <do_init_enclave+0xde>
            return SGX_ERROR_UNEXPECTED;
    bcb4:	b8 01 00 00 00       	mov    $0x1,%eax
    bcb9:	e9 4d 01 00 00       	jmpq   be0b <do_init_enclave+0x22b>

        size_t heap_min_size = get_heap_min_size();
    bcbe:	e8 e4 7c ff ff       	callq  39a7 <get_heap_min_size>
    bcc3:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
        memset_s(GET_PTR(void, enclave_base, g_global_data.heap_offset), heap_min_size, 0, heap_min_size);
    bcc7:	48 8d 05 b2 14 00 00 	lea    0x14b2(%rip),%rax        # d180 <g_global_data>
    bcce:	48 8b 50 08          	mov    0x8(%rax),%rdx
    bcd2:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    bcd6:	48 01 d0             	add    %rdx,%rax
    bcd9:	48 89 c7             	mov    %rax,%rdi
    bcdc:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    bce0:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    bce4:	48 89 d1             	mov    %rdx,%rcx
    bce7:	ba 00 00 00 00       	mov    $0x0,%edx
    bcec:	48 89 c6             	mov    %rax,%rsi
    bcef:	e8 d6 f2 ff ff       	callq  afca <memset_s>

        memset_s(GET_PTR(void, enclave_base, g_global_data.rsrv_offset), rsrv_mem_min_size, 0, rsrv_mem_min_size);
    bcf4:	48 8d 05 3d 51 00 00 	lea    0x513d(%rip),%rax        # 10e38 <rsrv_mem_min_size>
    bcfb:	48 8b 10             	mov    (%rax),%rdx
    bcfe:	48 8d 05 33 51 00 00 	lea    0x5133(%rip),%rax        # 10e38 <rsrv_mem_min_size>
    bd05:	48 8b 00             	mov    (%rax),%rax
    bd08:	48 8d 0d 71 14 00 00 	lea    0x1471(%rip),%rcx        # d180 <g_global_data>
    bd0f:	48 8b 71 18          	mov    0x18(%rcx),%rsi
    bd13:	48 8b 4d f0          	mov    -0x10(%rbp),%rcx
    bd17:	48 01 f1             	add    %rsi,%rcx
    bd1a:	48 89 cf             	mov    %rcx,%rdi
    bd1d:	48 89 d1             	mov    %rdx,%rcx
    bd20:	ba 00 00 00 00       	mov    $0x0,%edx
    bd25:	48 89 c6             	mov    %rax,%rsi
    bd28:	e8 9d f2 ff ff       	callq  afca <memset_s>
        // save all the static threads into the thread table. These TCS would be trimmed in the uninit flow
        if (add_static_threads(
            &g_global_data.layout_table[0],
            &g_global_data.layout_table[0] + g_global_data.layout_entry_num,
    bd2d:	48 8d 05 4c 14 00 00 	lea    0x144c(%rip),%rax        # d180 <g_global_data>
    bd34:	8b 80 28 01 00 00    	mov    0x128(%rax),%eax
    bd3a:	89 c0                	mov    %eax,%eax
    bd3c:	48 c1 e0 05          	shl    $0x5,%rax
    bd40:	48 89 c2             	mov    %rax,%rdx
        if (add_static_threads(
    bd43:	48 8d 05 36 14 00 00 	lea    0x1436(%rip),%rax        # d180 <g_global_data>
    bd4a:	48 8d 80 30 01 00 00 	lea    0x130(%rax),%rax
    bd51:	48 01 d0             	add    %rdx,%rax
    bd54:	ba 00 00 00 00       	mov    $0x0,%edx
    bd59:	48 89 c6             	mov    %rax,%rsi
    bd5c:	48 8d 05 1d 14 00 00 	lea    0x141d(%rip),%rax        # d180 <g_global_data>
    bd63:	48 8d b8 30 01 00 00 	lea    0x130(%rax),%rdi
    bd6a:	e8 16 05 00 00       	callq  c285 <_ZL18add_static_threadsPVK9_layout_tS1_m>
            0) != 0)
    bd6f:	85 c0                	test   %eax,%eax
    bd71:	0f 95 c0             	setne  %al
        if (add_static_threads(
    bd74:	84 c0                	test   %al,%al
    bd76:	0f 84 80 00 00 00    	je     bdfc <do_init_enclave+0x21c>
        {
            return SGX_ERROR_UNEXPECTED;
    bd7c:	b8 01 00 00 00       	mov    $0x1,%eax
    bd81:	e9 85 00 00 00       	jmpq   be0b <do_init_enclave+0x22b>
        }
    }
    else
    {
        memset_s(GET_PTR(void, enclave_base, g_global_data.heap_offset), g_global_data.heap_size, 0, g_global_data.heap_size);
    bd86:	48 8d 05 f3 13 00 00 	lea    0x13f3(%rip),%rax        # d180 <g_global_data>
    bd8d:	48 8b 50 10          	mov    0x10(%rax),%rdx
    bd91:	48 8d 05 e8 13 00 00 	lea    0x13e8(%rip),%rax        # d180 <g_global_data>
    bd98:	48 8b 40 10          	mov    0x10(%rax),%rax
    bd9c:	48 8d 0d dd 13 00 00 	lea    0x13dd(%rip),%rcx        # d180 <g_global_data>
    bda3:	48 8b 71 08          	mov    0x8(%rcx),%rsi
    bda7:	48 8b 4d f0          	mov    -0x10(%rbp),%rcx
    bdab:	48 01 f1             	add    %rsi,%rcx
    bdae:	48 89 cf             	mov    %rcx,%rdi
    bdb1:	48 89 d1             	mov    %rdx,%rcx
    bdb4:	ba 00 00 00 00       	mov    $0x0,%edx
    bdb9:	48 89 c6             	mov    %rax,%rsi
    bdbc:	e8 09 f2 ff ff       	callq  afca <memset_s>
        memset_s(GET_PTR(void, enclave_base, g_global_data.rsrv_offset), g_global_data.rsrv_size, 0, g_global_data.rsrv_size);
    bdc1:	48 8d 05 b8 13 00 00 	lea    0x13b8(%rip),%rax        # d180 <g_global_data>
    bdc8:	48 8b 50 20          	mov    0x20(%rax),%rdx
    bdcc:	48 8d 05 ad 13 00 00 	lea    0x13ad(%rip),%rax        # d180 <g_global_data>
    bdd3:	48 8b 40 20          	mov    0x20(%rax),%rax
    bdd7:	48 8d 0d a2 13 00 00 	lea    0x13a2(%rip),%rcx        # d180 <g_global_data>
    bdde:	48 8b 71 18          	mov    0x18(%rcx),%rsi
    bde2:	48 8b 4d f0          	mov    -0x10(%rbp),%rcx
    bde6:	48 01 f1             	add    %rsi,%rcx
    bde9:	48 89 cf             	mov    %rcx,%rdi
    bdec:	48 89 d1             	mov    %rdx,%rcx
    bdef:	ba 00 00 00 00       	mov    $0x0,%edx
    bdf4:	48 89 c6             	mov    %rax,%rsi
    bdf7:	e8 ce f1 ff ff       	callq  afca <memset_s>
    }
#endif

    g_enclave_state = ENCLAVE_INIT_DONE;
    bdfc:	c7 05 9a 52 00 00 02 	movl   $0x2,0x529a(%rip)        # 110a0 <g_enclave_state>
    be03:	00 00 00 
    return SGX_SUCCESS;
    be06:	b8 00 00 00 00       	mov    $0x0,%eax
}
    be0b:	c9                   	leaveq 
    be0c:	c3                   	retq   

000000000000be0d <init_enclave>:
{
    be0d:	55                   	push   %rbp
    be0e:	48 89 e5             	mov    %rsp,%rbp
    be11:	41 55                	push   %r13
    be13:	41 54                	push   %r12
    be15:	53                   	push   %rbx
    be16:	48 81 ec 18 01 00 00 	sub    $0x118,%rsp
    be1d:	48 89 bd d8 fe ff ff 	mov    %rdi,-0x128(%rbp)
    be24:	48 89 b5 d0 fe ff ff 	mov    %rsi,-0x130(%rbp)
    be2b:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    be32:	00 00 
    be34:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    be38:	31 c0                	xor    %eax,%eax
    if(enclave_base == NULL || ms == NULL)
    be3a:	48 83 bd d8 fe ff ff 	cmpq   $0x0,-0x128(%rbp)
    be41:	00 
    be42:	74 0a                	je     be4e <init_enclave+0x41>
    be44:	48 83 bd d0 fe ff ff 	cmpq   $0x0,-0x130(%rbp)
    be4b:	00 
    be4c:	75 0a                	jne    be58 <init_enclave+0x4b>
        return -1;
    be4e:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    be53:	e9 0b 04 00 00       	jmpq   c263 <init_enclave+0x456>
    if(NULL != pcl_entry)
    be58:	48 8b 05 79 51 00 00 	mov    0x5179(%rip),%rax        # 10fd8 <_Z9pcl_entryPvS_>
    be5f:	48 85 c0             	test   %rax,%rax
    be62:	74 67                	je     becb <init_enclave+0xbe>
        sgx_lfence();
    be64:	0f ae e8             	lfence 
        system_features_t * csi = (system_features_t *)ms;
    be67:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    be6e:	48 89 85 08 ff ff ff 	mov    %rax,-0xf8(%rbp)
        if(NULL == csi->sealed_key)
    be75:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    be7c:	48 8b 80 94 00 00 00 	mov    0x94(%rax),%rax
    be83:	48 85 c0             	test   %rax,%rax
    be86:	75 0a                	jne    be92 <init_enclave+0x85>
            return -1;
    be88:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    be8d:	e9 d1 03 00 00       	jmpq   c263 <init_enclave+0x456>
        sgx_status_t ret = pcl_entry(enclave_base, csi->sealed_key);
    be92:	48 8b 85 08 ff ff ff 	mov    -0xf8(%rbp),%rax
    be99:	48 8b 90 94 00 00 00 	mov    0x94(%rax),%rdx
    bea0:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    bea7:	48 89 d6             	mov    %rdx,%rsi
    beaa:	48 89 c7             	mov    %rax,%rdi
    bead:	e8 5e 51 ff ff       	callq  1010 <_Z9pcl_entryPvS_@plt>
    beb2:	89 85 ec fe ff ff    	mov    %eax,-0x114(%rbp)
        if(SGX_SUCCESS != ret)
    beb8:	83 bd ec fe ff ff 00 	cmpl   $0x0,-0x114(%rbp)
    bebf:	74 0a                	je     becb <init_enclave+0xbe>
            return -1;
    bec1:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    bec6:	e9 98 03 00 00       	jmpq   c263 <init_enclave+0x456>
    if(0 != relocate_enclave(enclave_base))
    becb:	48 8b 85 d8 fe ff ff 	mov    -0x128(%rbp),%rax
    bed2:	48 89 c7             	mov    %rax,%rdi
    bed5:	e8 93 88 ff ff       	callq  476d <relocate_enclave>
    beda:	85 c0                	test   %eax,%eax
    bedc:	0f 95 c0             	setne  %al
    bedf:	84 c0                	test   %al,%al
    bee1:	74 0a                	je     beed <init_enclave+0xe0>
        return -1;
    bee3:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    bee8:	e9 76 03 00 00       	jmpq   c263 <init_enclave+0x456>
    system_features_t *info = (system_features_t *)ms;
    beed:	48 8b 85 d0 fe ff ff 	mov    -0x130(%rbp),%rax
    bef4:	48 89 85 10 ff ff ff 	mov    %rax,-0xf0(%rbp)
    if(!sgx_is_outside_enclave(info, sizeof(system_features_t)))
    befb:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    bf02:	be b0 00 00 00       	mov    $0xb0,%esi
    bf07:	48 89 c7             	mov    %rax,%rdi
    bf0a:	e8 86 54 ff ff       	callq  1395 <sgx_is_outside_enclave>
    bf0f:	85 c0                	test   %eax,%eax
    bf11:	0f 94 c0             	sete   %al
    bf14:	84 c0                	test   %al,%al
    bf16:	74 0a                	je     bf22 <init_enclave+0x115>
        return -1;
    bf18:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    bf1d:	e9 41 03 00 00       	jmpq   c263 <init_enclave+0x456>
    sgx_lfence();
    bf22:	0f ae e8             	lfence 
    system_features_t sys_features = *info;
    bf25:	48 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%rax
    bf2c:	48 8b 10             	mov    (%rax),%rdx
    bf2f:	48 8b 48 08          	mov    0x8(%rax),%rcx
    bf33:	48 89 95 20 ff ff ff 	mov    %rdx,-0xe0(%rbp)
    bf3a:	48 89 8d 28 ff ff ff 	mov    %rcx,-0xd8(%rbp)
    bf41:	48 8b 50 10          	mov    0x10(%rax),%rdx
    bf45:	48 8b 48 18          	mov    0x18(%rax),%rcx
    bf49:	48 89 95 30 ff ff ff 	mov    %rdx,-0xd0(%rbp)
    bf50:	48 89 8d 38 ff ff ff 	mov    %rcx,-0xc8(%rbp)
    bf57:	48 8b 50 20          	mov    0x20(%rax),%rdx
    bf5b:	48 8b 48 28          	mov    0x28(%rax),%rcx
    bf5f:	48 89 95 40 ff ff ff 	mov    %rdx,-0xc0(%rbp)
    bf66:	48 89 8d 48 ff ff ff 	mov    %rcx,-0xb8(%rbp)
    bf6d:	48 8b 50 30          	mov    0x30(%rax),%rdx
    bf71:	48 8b 48 38          	mov    0x38(%rax),%rcx
    bf75:	48 89 95 50 ff ff ff 	mov    %rdx,-0xb0(%rbp)
    bf7c:	48 89 8d 58 ff ff ff 	mov    %rcx,-0xa8(%rbp)
    bf83:	48 8b 50 40          	mov    0x40(%rax),%rdx
    bf87:	48 8b 48 48          	mov    0x48(%rax),%rcx
    bf8b:	48 89 95 60 ff ff ff 	mov    %rdx,-0xa0(%rbp)
    bf92:	48 89 8d 68 ff ff ff 	mov    %rcx,-0x98(%rbp)
    bf99:	48 8b 50 50          	mov    0x50(%rax),%rdx
    bf9d:	48 8b 48 58          	mov    0x58(%rax),%rcx
    bfa1:	48 89 95 70 ff ff ff 	mov    %rdx,-0x90(%rbp)
    bfa8:	48 89 8d 78 ff ff ff 	mov    %rcx,-0x88(%rbp)
    bfaf:	48 8b 50 60          	mov    0x60(%rax),%rdx
    bfb3:	48 8b 48 68          	mov    0x68(%rax),%rcx
    bfb7:	48 89 55 80          	mov    %rdx,-0x80(%rbp)
    bfbb:	48 89 4d 88          	mov    %rcx,-0x78(%rbp)
    bfbf:	48 8b 50 70          	mov    0x70(%rax),%rdx
    bfc3:	48 8b 48 78          	mov    0x78(%rax),%rcx
    bfc7:	48 89 55 90          	mov    %rdx,-0x70(%rbp)
    bfcb:	48 89 4d 98          	mov    %rcx,-0x68(%rbp)
    bfcf:	48 8b 90 80 00 00 00 	mov    0x80(%rax),%rdx
    bfd6:	48 8b 88 88 00 00 00 	mov    0x88(%rax),%rcx
    bfdd:	48 89 55 a0          	mov    %rdx,-0x60(%rbp)
    bfe1:	48 89 4d a8          	mov    %rcx,-0x58(%rbp)
    bfe5:	48 8b 90 90 00 00 00 	mov    0x90(%rax),%rdx
    bfec:	48 8b 88 98 00 00 00 	mov    0x98(%rax),%rcx
    bff3:	48 89 55 b0          	mov    %rdx,-0x50(%rbp)
    bff7:	48 89 4d b8          	mov    %rcx,-0x48(%rbp)
    bffb:	48 8b 90 a8 00 00 00 	mov    0xa8(%rax),%rdx
    c002:	48 8b 80 a0 00 00 00 	mov    0xa0(%rax),%rax
    c009:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    c00d:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
    size_t offset = 0;
    c011:	48 c7 85 f0 fe ff ff 	movq   $0x0,-0x110(%rbp)
    c018:	00 00 00 00 
    if(sys_features.system_feature_set[0] & (1ULL<< SYS_FEATURE_EXTEND))
    c01c:	48 8b 95 2c ff ff ff 	mov    -0xd4(%rbp),%rdx
    c023:	48 b8 00 00 00 00 00 	movabs $0x4000000000000000,%rax
    c02a:	00 00 40 
    c02d:	48 21 d0             	and    %rdx,%rax
    c030:	48 85 c0             	test   %rax,%rax
    c033:	74 1c                	je     c051 <init_enclave+0x244>
        offset = (sys_features.size < sizeof(sys_features)) ? sys_features.size : sizeof(sys_features);
    c035:	48 8b 45 bc          	mov    -0x44(%rbp),%rax
    c039:	ba b0 00 00 00       	mov    $0xb0,%edx
    c03e:	48 3d b0 00 00 00    	cmp    $0xb0,%rax
    c044:	48 0f 47 c2          	cmova  %rdx,%rax
    c048:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    c04f:	eb 0b                	jmp    c05c <init_enclave+0x24f>
        offset = offsetof(system_features_t, size);
    c051:	48 c7 85 f0 fe ff ff 	movq   $0x9c,-0x110(%rbp)
    c058:	9c 00 00 00 
    for(size_t i = 0; i < sizeof(sys_features) - offset; i++)
    c05c:	48 c7 85 f8 fe ff ff 	movq   $0x0,-0x108(%rbp)
    c063:	00 00 00 00 
    c067:	b8 b0 00 00 00       	mov    $0xb0,%eax
    c06c:	48 2b 85 f0 fe ff ff 	sub    -0x110(%rbp),%rax
    c073:	48 39 85 f8 fe ff ff 	cmp    %rax,-0x108(%rbp)
    c07a:	73 28                	jae    c0a4 <init_enclave+0x297>
        *((uint8_t *)&sys_features + offset + i) = 0;
    c07c:	48 8b 95 f0 fe ff ff 	mov    -0x110(%rbp),%rdx
    c083:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    c08a:	48 01 c2             	add    %rax,%rdx
    c08d:	48 8d 85 20 ff ff ff 	lea    -0xe0(%rbp),%rax
    c094:	48 01 d0             	add    %rdx,%rax
    c097:	c6 00 00             	movb   $0x0,(%rax)
    for(size_t i = 0; i < sizeof(sys_features) - offset; i++)
    c09a:	48 83 85 f8 fe ff ff 	addq   $0x1,-0x108(%rbp)
    c0a1:	01 
    c0a2:	eb c3                	jmp    c067 <init_enclave+0x25a>
    g_cpu_core_num = sys_features.cpu_core_num;
    c0a4:	8b 45 cc             	mov    -0x34(%rbp),%eax
    c0a7:	89 05 4b 4d 00 00    	mov    %eax,0x4d4b(%rip)        # 10df8 <g_cpu_core_num>
    g_sdk_version = sys_features.version;
    c0ad:	8b 85 28 ff ff ff    	mov    -0xd8(%rbp),%eax
    c0b3:	89 05 3b 4d 00 00    	mov    %eax,0x4d3b(%rip)        # 10df4 <g_sdk_version>
    if (g_sdk_version == SDK_VERSION_1_5)
    c0b9:	8b 05 35 4d 00 00    	mov    0x4d35(%rip),%eax        # 10df4 <g_sdk_version>
    c0bf:	85 c0                	test   %eax,%eax
    c0c1:	75 0c                	jne    c0cf <init_enclave+0x2c2>
        EDMM_supported = 0;
    c0c3:	c7 05 23 4d 00 00 00 	movl   $0x0,0x4d23(%rip)        # 10df0 <EDMM_supported>
    c0ca:	00 00 00 
    c0cd:	eb 34                	jmp    c103 <init_enclave+0x2f6>
    else if (g_sdk_version >= SDK_VERSION_2_0)
    c0cf:	8b 05 1f 4d 00 00    	mov    0x4d1f(%rip),%eax        # 10df4 <g_sdk_version>
    c0d5:	85 c0                	test   %eax,%eax
    c0d7:	7e 20                	jle    c0f9 <init_enclave+0x2ec>
        EDMM_supported = feature_supported((const uint64_t *)sys_features.system_feature_set, 0);
    c0d9:	48 8d 85 20 ff ff ff 	lea    -0xe0(%rbp),%rax
    c0e0:	48 83 c0 0c          	add    $0xc,%rax
    c0e4:	be 00 00 00 00       	mov    $0x0,%esi
    c0e9:	48 89 c7             	mov    %rax,%rdi
    c0ec:	e8 7e 7a ff ff       	callq  3b6f <feature_supported>
    c0f1:	89 05 f9 4c 00 00    	mov    %eax,0x4cf9(%rip)        # 10df0 <EDMM_supported>
    c0f7:	eb 0a                	jmp    c103 <init_enclave+0x2f6>
        return -1;
    c0f9:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c0fe:	e9 60 01 00 00       	jmpq   c263 <init_enclave+0x456>
    if (heap_init(get_heap_base(), get_heap_size(), get_heap_min_size(), EDMM_supported) != SGX_SUCCESS)
    c103:	8b 1d e7 4c 00 00    	mov    0x4ce7(%rip),%ebx        # 10df0 <EDMM_supported>
    c109:	e8 99 78 ff ff       	callq  39a7 <get_heap_min_size>
    c10e:	49 89 c5             	mov    %rax,%r13
    c111:	e8 ff 77 ff ff       	callq  3915 <get_heap_size>
    c116:	49 89 c4             	mov    %rax,%r12
    c119:	e8 dc 77 ff ff       	callq  38fa <get_heap_base>
    c11e:	89 d9                	mov    %ebx,%ecx
    c120:	4c 89 ea             	mov    %r13,%rdx
    c123:	4c 89 e6             	mov    %r12,%rsi
    c126:	48 89 c7             	mov    %rax,%rdi
    c129:	e8 19 ef ff ff       	callq  b047 <heap_init>
    c12e:	85 c0                	test   %eax,%eax
    c130:	0f 95 c0             	setne  %al
    c133:	84 c0                	test   %al,%al
    c135:	74 0a                	je     c141 <init_enclave+0x334>
        return -1;
    c137:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c13c:	e9 22 01 00 00       	jmpq   c263 <init_enclave+0x456>
    uint64_t xfrm = get_xfeature_state();
    c141:	e8 db 82 ff ff       	callq  4421 <get_xfeature_state>
    c146:	48 89 85 18 ff ff ff 	mov    %rax,-0xe8(%rbp)
    uint64_t cpu_features = (sys_features.cpu_features | INCOMPAT_FEATURE_BIT);
    c14d:	48 8b 85 20 ff ff ff 	mov    -0xe0(%rbp),%rax
    c154:	48 0d 00 18 00 1e    	or     $0x1e001800,%rax
    c15a:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
    if (sys_features.system_feature_set[0] & ((uint64_t)(1ULL << SYS_FEATURE_EXTEND)))
    c161:	48 8b 95 2c ff ff ff 	mov    -0xd4(%rbp),%rdx
    c168:	48 b8 00 00 00 00 00 	movabs $0x4000000000000000,%rax
    c16f:	00 00 40 
    c172:	48 21 d0             	and    %rdx,%rax
    c175:	48 85 c0             	test   %rax,%rax
    c178:	74 0b                	je     c185 <init_enclave+0x378>
        cpu_features = sys_features.cpu_features_ext;
    c17a:	48 8b 45 c4          	mov    -0x3c(%rbp),%rax
    c17e:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
    if (SDK_VERSION_2_0 < g_sdk_version || sys_features.size != 0)
    c185:	8b 05 69 4c 00 00    	mov    0x4c69(%rip),%eax        # 10df4 <g_sdk_version>
    c18b:	83 f8 01             	cmp    $0x1,%eax
    c18e:	7f 09                	jg     c199 <init_enclave+0x38c>
    c190:	48 8b 45 bc          	mov    -0x44(%rbp),%rax
    c194:	48 85 c0             	test   %rax,%rax
    c197:	74 37                	je     c1d0 <init_enclave+0x3c3>
        if (0 != init_optimized_libs(cpu_features, (uint32_t*)sys_features.cpuinfo_table, xfrm))
    c199:	48 8b 95 18 ff ff ff 	mov    -0xe8(%rbp),%rdx
    c1a0:	48 8d 85 20 ff ff ff 	lea    -0xe0(%rbp),%rax
    c1a7:	48 8d 48 14          	lea    0x14(%rax),%rcx
    c1ab:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    c1b2:	48 89 ce             	mov    %rcx,%rsi
    c1b5:	48 89 c7             	mov    %rax,%rdi
    c1b8:	e8 93 50 ff ff       	callq  1250 <init_optimized_libs>
    c1bd:	85 c0                	test   %eax,%eax
    c1bf:	0f 95 c0             	setne  %al
    c1c2:	84 c0                	test   %al,%al
    c1c4:	74 35                	je     c1fb <init_enclave+0x3ee>
            return -1;
    c1c6:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c1cb:	e9 93 00 00 00       	jmpq   c263 <init_enclave+0x456>
        if (0 != init_optimized_libs(cpu_features, NULL, xfrm))
    c1d0:	48 8b 95 18 ff ff ff 	mov    -0xe8(%rbp),%rdx
    c1d7:	48 8b 85 00 ff ff ff 	mov    -0x100(%rbp),%rax
    c1de:	be 00 00 00 00       	mov    $0x0,%esi
    c1e3:	48 89 c7             	mov    %rax,%rdi
    c1e6:	e8 65 50 ff ff       	callq  1250 <init_optimized_libs>
    c1eb:	85 c0                	test   %eax,%eax
    c1ed:	0f 95 c0             	setne  %al
    c1f0:	84 c0                	test   %al,%al
    c1f2:	74 07                	je     c1fb <init_enclave+0x3ee>
            return -1;
    c1f4:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c1f9:	eb 68                	jmp    c263 <init_enclave+0x456>
    if ( get_rsrv_size() != 0)
    c1fb:	e8 42 78 ff ff       	callq  3a42 <get_rsrv_size>
    c200:	48 85 c0             	test   %rax,%rax
    c203:	0f 95 c0             	setne  %al
    c206:	84 c0                	test   %al,%al
    c208:	74 33                	je     c23d <init_enclave+0x430>
        if(rsrv_mem_init(get_rsrv_base(), get_rsrv_size(), get_rsrv_min_size()) != SGX_SUCCESS)
    c20a:	e8 c5 78 ff ff       	callq  3ad4 <get_rsrv_min_size>
    c20f:	49 89 c4             	mov    %rax,%r12
    c212:	e8 2b 78 ff ff       	callq  3a42 <get_rsrv_size>
    c217:	48 89 c3             	mov    %rax,%rbx
    c21a:	e8 08 78 ff ff       	callq  3a27 <get_rsrv_base>
    c21f:	4c 89 e2             	mov    %r12,%rdx
    c222:	48 89 de             	mov    %rbx,%rsi
    c225:	48 89 c7             	mov    %rax,%rdi
    c228:	e8 82 f3 ff ff       	callq  b5af <rsrv_mem_init>
    c22d:	85 c0                	test   %eax,%eax
    c22f:	0f 95 c0             	setne  %al
    c232:	84 c0                	test   %al,%al
    c234:	74 07                	je     c23d <init_enclave+0x430>
            return -1;
    c236:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c23b:	eb 26                	jmp    c263 <init_enclave+0x456>
    if(SGX_SUCCESS != sgx_read_rand((unsigned char*)&__stack_chk_guard,
    c23d:	be 08 00 00 00       	mov    $0x8,%esi
    c242:	48 8d 3d b7 4b 00 00 	lea    0x4bb7(%rip),%rdi        # 10e00 <__intel_security_cookie>
    c249:	e8 7d 53 ff ff       	callq  15cb <sgx_read_rand>
    c24e:	85 c0                	test   %eax,%eax
    c250:	0f 95 c0             	setne  %al
    c253:	84 c0                	test   %al,%al
    c255:	74 07                	je     c25e <init_enclave+0x451>
        return -1;
    c257:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c25c:	eb 05                	jmp    c263 <init_enclave+0x456>
    return 0;
    c25e:	b8 00 00 00 00       	mov    $0x0,%eax
}
    c263:	48 8b 4d d8          	mov    -0x28(%rbp),%rcx
    c267:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    c26e:	00 00 
    c270:	74 05                	je     c277 <init_enclave+0x46a>
    c272:	e8 63 90 ff ff       	callq  52da <__stack_chk_fail>
    c277:	48 81 c4 18 01 00 00 	add    $0x118,%rsp
    c27e:	5b                   	pop    %rbx
    c27f:	41 5c                	pop    %r12
    c281:	41 5d                	pop    %r13
    c283:	5d                   	pop    %rbp
    c284:	c3                   	retq   

000000000000c285 <_ZL18add_static_threadsPVK9_layout_tS1_m>:
{
    c285:	55                   	push   %rbp
    c286:	48 89 e5             	mov    %rsp,%rbp
    c289:	53                   	push   %rbx
    c28a:	48 83 ec 48          	sub    $0x48,%rsp
    c28e:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    c292:	48 89 75 c0          	mov    %rsi,-0x40(%rbp)
    c296:	48 89 55 b8          	mov    %rdx,-0x48(%rbp)
    int ret = -1;
    c29a:	c7 45 d4 ff ff ff ff 	movl   $0xffffffff,-0x2c(%rbp)
    for (const volatile layout_t *layout = layout_start; layout < layout_end; layout++)
    c2a1:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    c2a5:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    c2a9:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c2ad:	48 3b 45 c0          	cmp    -0x40(%rbp),%rax
    c2b1:	0f 83 1a 01 00 00    	jae    c3d1 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x14c>
        if (!IS_GROUP_ID(layout->group.id) && (layout->entry.si_flags & SI_FLAGS_TCS) && layout->entry.attributes == (PAGE_ATTR_EADD | PAGE_ATTR_EEXTEND))
    c2b7:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c2bb:	0f b7 00             	movzwl (%rax),%eax
    c2be:	0f b7 c0             	movzwl %ax,%eax
    c2c1:	25 00 10 00 00       	and    $0x1000,%eax
    c2c6:	85 c0                	test   %eax,%eax
    c2c8:	75 27                	jne    c2f1 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x6c>
    c2ca:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c2ce:	48 8b 40 18          	mov    0x18(%rax),%rax
    c2d2:	25 00 01 00 00       	and    $0x100,%eax
    c2d7:	48 85 c0             	test   %rax,%rax
    c2da:	74 15                	je     c2f1 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x6c>
    c2dc:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c2e0:	0f b7 40 02          	movzwl 0x2(%rax),%eax
    c2e4:	66 83 f8 03          	cmp    $0x3,%ax
    c2e8:	75 07                	jne    c2f1 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x6c>
    c2ea:	b8 01 00 00 00       	mov    $0x1,%eax
    c2ef:	eb 05                	jmp    c2f6 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x71>
    c2f1:	b8 00 00 00 00       	mov    $0x0,%eax
    c2f6:	84 c0                	test   %al,%al
    c2f8:	74 3f                	je     c339 <_ZL18add_static_threadsPVK9_layout_tS1_m+0xb4>
            uintptr_t tcs_addr = (uintptr_t)layout->entry.rva + offset + (uintptr_t)get_enclave_base();
    c2fa:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c2fe:	48 8b 50 08          	mov    0x8(%rax),%rdx
    c302:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    c306:	48 8d 1c 02          	lea    (%rdx,%rax,1),%rbx
    c30a:	e8 55 03 00 00       	callq  c664 <get_enclave_base>
    c30f:	48 01 d8             	add    %rbx,%rax
    c312:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
            if (do_save_tcs(reinterpret_cast<void *>(tcs_addr)) != SGX_SUCCESS)
    c316:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    c31a:	48 89 c7             	mov    %rax,%rdi
    c31d:	e8 69 65 ff ff       	callq  288b <_Z11do_save_tcsPv>
    c322:	85 c0                	test   %eax,%eax
    c324:	0f 95 c0             	setne  %al
    c327:	84 c0                	test   %al,%al
    c329:	0f 84 98 00 00 00    	je     c3c7 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x142>
		    return (-1);
    c32f:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c334:	e9 9d 00 00 00       	jmpq   c3d6 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x151>
        else if (IS_GROUP_ID(layout->group.id)){
    c339:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c33d:	0f b7 00             	movzwl (%rax),%eax
    c340:	0f b7 c0             	movzwl %ax,%eax
    c343:	25 00 10 00 00       	and    $0x1000,%eax
    c348:	85 c0                	test   %eax,%eax
    c34a:	0f 95 c0             	setne  %al
    c34d:	84 c0                	test   %al,%al
    c34f:	74 76                	je     c3c7 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x142>
            size_t step = 0;
    c351:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    c358:	00 
            for(uint32_t j = 0; j < layout->group.load_times; j++)
    c359:	c7 45 d0 00 00 00 00 	movl   $0x0,-0x30(%rbp)
    c360:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c364:	8b 40 04             	mov    0x4(%rax),%eax
    c367:	39 45 d0             	cmp    %eax,-0x30(%rbp)
    c36a:	0f 92 c0             	setb   %al
    c36d:	84 c0                	test   %al,%al
    c36f:	74 56                	je     c3c7 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x142>
                step += (size_t)layout->group.load_step;
    c371:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c375:	48 8b 40 08          	mov    0x8(%rax),%rax
    c379:	48 01 45 e0          	add    %rax,-0x20(%rbp)
                if(0 != (ret = add_static_threads(&layout[-layout->group.entry_count], layout, step)))
    c37d:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c381:	0f b7 40 02          	movzwl 0x2(%rax),%eax
    c385:	0f b7 c0             	movzwl %ax,%eax
    c388:	f7 d8                	neg    %eax
    c38a:	48 98                	cltq   
    c38c:	48 c1 e0 05          	shl    $0x5,%rax
    c390:	48 89 c2             	mov    %rax,%rdx
    c393:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c397:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
    c39b:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    c39f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c3a3:	48 89 c6             	mov    %rax,%rsi
    c3a6:	48 89 cf             	mov    %rcx,%rdi
    c3a9:	e8 d7 fe ff ff       	callq  c285 <_ZL18add_static_threadsPVK9_layout_tS1_m>
    c3ae:	89 45 d4             	mov    %eax,-0x2c(%rbp)
    c3b1:	83 7d d4 00          	cmpl   $0x0,-0x2c(%rbp)
    c3b5:	0f 95 c0             	setne  %al
    c3b8:	84 c0                	test   %al,%al
    c3ba:	74 05                	je     c3c1 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x13c>
                    return ret;
    c3bc:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    c3bf:	eb 15                	jmp    c3d6 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x151>
            for(uint32_t j = 0; j < layout->group.load_times; j++)
    c3c1:	83 45 d0 01          	addl   $0x1,-0x30(%rbp)
    c3c5:	eb 99                	jmp    c360 <_ZL18add_static_threadsPVK9_layout_tS1_m+0xdb>
    for (const volatile layout_t *layout = layout_start; layout < layout_end; layout++)
    c3c7:	48 83 45 d8 20       	addq   $0x20,-0x28(%rbp)
    c3cc:	e9 d8 fe ff ff       	jmpq   c2a9 <_ZL18add_static_threadsPVK9_layout_tS1_m+0x24>
    return 0;
    c3d1:	b8 00 00 00 00       	mov    $0x0,%eax
}
    c3d6:	48 83 c4 48          	add    $0x48,%rsp
    c3da:	5b                   	pop    %rbx
    c3db:	5d                   	pop    %rbp
    c3dc:	c3                   	retq   

000000000000c3dd <sgx_is_enclave_crashed>:
{
    c3dd:	55                   	push   %rbp
    c3de:	48 89 e5             	mov    %rsp,%rbp
    return get_enclave_state() == ENCLAVE_CRASHED;
    c3e1:	e8 86 02 00 00       	callq  c66c <get_enclave_state>
    c3e6:	83 f8 03             	cmp    $0x3,%eax
    c3e9:	0f 94 c0             	sete   %al
    c3ec:	0f b6 c0             	movzbl %al,%eax
}
    c3ef:	5d                   	pop    %rbp
    c3f0:	c3                   	retq   

000000000000c3f1 <_ZL16init_stack_guardPv>:
#include "global_data.h"
#include "trts_internal.h"
#include "internal/rts.h"

static void __attribute__((section(".nipx"))) init_stack_guard(void *tcs)
{
    c3f1:	55                   	push   %rbp
    c3f2:	48 89 e5             	mov    %rsp,%rbp
    c3f5:	48 83 ec 20          	sub    $0x20,%rsp
    c3f9:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    thread_data_t *thread_data = get_thread_data();
    c3fd:	e8 9d 02 00 00       	callq  c69f <get_thread_data>
    c402:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    if( (NULL == thread_data) || ((thread_data->stack_base_addr == thread_data->last_sp) && (0 != g_global_data.thread_policy)))
    c406:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    c40b:	74 25                	je     c432 <_ZL16init_stack_guardPv+0x41>
    c40d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    c411:	48 8b 50 10          	mov    0x10(%rax),%rdx
    c415:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    c419:	48 8b 40 08          	mov    0x8(%rax),%rax
    c41d:	48 39 c2             	cmp    %rax,%rdx
    c420:	75 17                	jne    c439 <_ZL16init_stack_guardPv+0x48>
    c422:	48 8d 05 57 0d 00 00 	lea    0xd57(%rip),%rax        # d180 <g_global_data>
    c429:	48 8b 40 30          	mov    0x30(%rax),%rax
    c42d:	48 85 c0             	test   %rax,%rax
    c430:	74 07                	je     c439 <_ZL16init_stack_guardPv+0x48>
    c432:	b8 01 00 00 00       	mov    $0x1,%eax
    c437:	eb 05                	jmp    c43e <_ZL16init_stack_guardPv+0x4d>
    c439:	b8 00 00 00 00       	mov    $0x0,%eax
    c43e:	84 c0                	test   %al,%al
    c440:	74 71                	je     c4b3 <_ZL16init_stack_guardPv+0xc2>
    {
         thread_data = GET_PTR(thread_data_t, tcs, g_global_data.td_template.self_addr);
    c442:	48 8d 05 37 0d 00 00 	lea    0xd37(%rip),%rax        # d180 <g_global_data>
    c449:	48 8b 50 40          	mov    0x40(%rax),%rdx
    c44d:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    c451:	48 01 d0             	add    %rdx,%rax
    c454:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    else
    {
        return;
    }

    assert(thread_data != NULL);
    c458:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    c45d:	75 1f                	jne    c47e <_ZL16init_stack_guardPv+0x8d>
    c45f:	48 8d 0d d1 0b 00 00 	lea    0xbd1(%rip),%rcx        # d037 <_ZZ14trim_EPC_pagesE8__func__+0xf>
    c466:	48 8d 15 f3 0b 00 00 	lea    0xbf3(%rip),%rdx        # d060 <_ZZL16init_stack_guardPvE8__func__>
    c46d:	be 3f 00 00 00       	mov    $0x3f,%esi
    c472:	48 8d 3d d2 0b 00 00 	lea    0xbd2(%rip),%rdi        # d04b <_ZZ14trim_EPC_pagesE8__func__+0x23>
    c479:	e8 65 8e ff ff       	callq  52e3 <__assert>

    size_t tmp_stack_guard = 0;
    c47e:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
    c485:	00 
    if (SGX_SUCCESS != sgx_read_rand(
    c486:	48 8d 45 f0          	lea    -0x10(%rbp),%rax
    c48a:	be 08 00 00 00       	mov    $0x8,%esi
    c48f:	48 89 c7             	mov    %rax,%rdi
    c492:	e8 34 51 ff ff       	callq  15cb <sgx_read_rand>
    c497:	85 c0                	test   %eax,%eax
    c499:	0f 95 c0             	setne  %al
    c49c:	84 c0                	test   %al,%al
    c49e:	74 05                	je     c4a5 <_ZL16init_stack_guardPv+0xb4>
                (unsigned char*)&tmp_stack_guard,
                sizeof(tmp_stack_guard)))
        abort();
    c4a0:	e8 29 05 00 00       	callq  c9ce <abort>

    thread_data->stack_guard = tmp_stack_guard;
    c4a5:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    c4a9:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    c4ad:	48 89 50 28          	mov    %rdx,0x28(%rax)
    c4b1:	eb 01                	jmp    c4b4 <_ZL16init_stack_guardPv+0xc3>
        return;
    c4b3:	90                   	nop
}
    c4b4:	c9                   	leaveq 
    c4b5:	c3                   	retq   

000000000000c4b6 <enter_enclave>:

extern "C" int enter_enclave(int index, void *ms, void *tcs, int cssa) __attribute__((section(".nipx")));

extern "C" int enter_enclave(int index, void *ms, void *tcs, int cssa)
{
    c4b6:	55                   	push   %rbp
    c4b7:	48 89 e5             	mov    %rsp,%rbp
    c4ba:	48 83 ec 30          	sub    $0x30,%rsp
    c4be:	89 7d ec             	mov    %edi,-0x14(%rbp)
    c4c1:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    c4c5:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    c4c9:	89 4d e8             	mov    %ecx,-0x18(%rbp)
    sgx_status_t error = SGX_ERROR_UNEXPECTED;
    c4cc:	c7 45 fc 01 00 00 00 	movl   $0x1,-0x4(%rbp)

    if(sgx_is_enclave_crashed())
    c4d3:	e8 05 ff ff ff       	callq  c3dd <sgx_is_enclave_crashed>
    c4d8:	85 c0                	test   %eax,%eax
    c4da:	0f 95 c0             	setne  %al
    c4dd:	84 c0                	test   %al,%al
    c4df:	74 0a                	je     c4eb <enter_enclave+0x35>
    {
        return SGX_ERROR_ENCLAVE_CRASHED;
    c4e1:	b8 06 10 00 00       	mov    $0x1006,%eax
    c4e6:	e9 1e 01 00 00       	jmpq   c609 <enter_enclave+0x153>
    }
    if((ECMD_INIT_ENCLAVE != index) && (ENCLAVE_INIT_DONE != get_enclave_state()))
    c4eb:	83 7d ec ff          	cmpl   $0xffffffff,-0x14(%rbp)
    c4ef:	74 11                	je     c502 <enter_enclave+0x4c>
    c4f1:	e8 76 01 00 00       	callq  c66c <get_enclave_state>
    c4f6:	83 f8 02             	cmp    $0x2,%eax
    c4f9:	74 07                	je     c502 <enter_enclave+0x4c>
    c4fb:	b8 01 00 00 00       	mov    $0x1,%eax
    c500:	eb 05                	jmp    c507 <enter_enclave+0x51>
    c502:	b8 00 00 00 00       	mov    $0x0,%eax
    c507:	84 c0                	test   %al,%al
    c509:	74 12                	je     c51d <enter_enclave+0x67>
    {
        set_enclave_state(ENCLAVE_CRASHED);
    c50b:	bf 03 00 00 00       	mov    $0x3,%edi
    c510:	e8 64 01 00 00       	callq  c679 <set_enclave_state>
        return error;
    c515:	8b 45 fc             	mov    -0x4(%rbp),%eax
    c518:	e9 ec 00 00 00       	jmpq   c609 <enter_enclave+0x153>
    }

    if(cssa == 0)
    c51d:	83 7d e8 00          	cmpl   $0x0,-0x18(%rbp)
    c521:	0f 85 98 00 00 00    	jne    c5bf <enter_enclave+0x109>
    {
        if((index >= 0) || (index == ECMD_ECALL_PTHREAD))
    c527:	83 7d ec 00          	cmpl   $0x0,-0x14(%rbp)
    c52b:	79 06                	jns    c533 <enter_enclave+0x7d>
    c52d:	83 7d ec fa          	cmpl   $0xfffffffa,-0x14(%rbp)
    c531:	75 29                	jne    c55c <enter_enclave+0xa6>
        {
            // Initialize stack guard if necessary
            init_stack_guard(tcs);
    c533:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c537:	48 89 c7             	mov    %rax,%rdi
    c53a:	e8 b2 fe ff ff       	callq  c3f1 <_ZL16init_stack_guardPv>
            error = do_ecall(index, ms, tcs);
    c53f:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    c543:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    c547:	8b 45 ec             	mov    -0x14(%rbp),%eax
    c54a:	48 89 ce             	mov    %rcx,%rsi
    c54d:	89 c7                	mov    %eax,%edi
    c54f:	e8 59 69 ff ff       	callq  2ead <do_ecall>
    c554:	89 45 fc             	mov    %eax,-0x4(%rbp)
    c557:	e9 9a 00 00 00       	jmpq   c5f6 <enter_enclave+0x140>
        }
        else if(index == ECMD_INIT_ENCLAVE)
    c55c:	83 7d ec ff          	cmpl   $0xffffffff,-0x14(%rbp)
    c560:	75 18                	jne    c57a <enter_enclave+0xc4>
        {
            error = do_init_enclave(ms, tcs);
    c562:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    c566:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    c56a:	48 89 d6             	mov    %rdx,%rsi
    c56d:	48 89 c7             	mov    %rax,%rdi
    c570:	e8 6b f6 ff ff       	callq  bbe0 <do_init_enclave>
    c575:	89 45 fc             	mov    %eax,-0x4(%rbp)
    c578:	eb 7c                	jmp    c5f6 <enter_enclave+0x140>
        }
        else if(index == ECMD_ORET)
    c57a:	83 7d ec fe          	cmpl   $0xfffffffe,-0x14(%rbp)
    c57e:	75 11                	jne    c591 <enter_enclave+0xdb>
        {
            error = do_oret(ms);
    c580:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    c584:	48 89 c7             	mov    %rax,%rdi
    c587:	e8 a0 71 ff ff       	callq  372c <do_oret>
    c58c:	89 45 fc             	mov    %eax,-0x4(%rbp)
    c58f:	eb 65                	jmp    c5f6 <enter_enclave+0x140>
        }
        else if(index == ECMD_MKTCS)
    c591:	83 7d ec fc          	cmpl   $0xfffffffc,-0x14(%rbp)
    c595:	75 11                	jne    c5a8 <enter_enclave+0xf2>
        {
            error = do_ecall_add_thread(ms);
    c597:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    c59b:	48 89 c7             	mov    %rax,%rdi
    c59e:	e8 ec 6a ff ff       	callq  308f <do_ecall_add_thread>
    c5a3:	89 45 fc             	mov    %eax,-0x4(%rbp)
    c5a6:	eb 4e                	jmp    c5f6 <enter_enclave+0x140>
        }
        else if(index == ECMD_UNINIT_ENCLAVE)
    c5a8:	83 7d ec fb          	cmpl   $0xfffffffb,-0x14(%rbp)
    c5ac:	75 48                	jne    c5f6 <enter_enclave+0x140>
        {
            error = do_uninit_enclave(tcs);
    c5ae:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c5b2:	48 89 c7             	mov    %rax,%rdi
    c5b5:	e8 99 6b ff ff       	callq  3153 <do_uninit_enclave>
    c5ba:	89 45 fc             	mov    %eax,-0x4(%rbp)
    c5bd:	eb 37                	jmp    c5f6 <enter_enclave+0x140>
        }
    }
    else if((cssa == 1) && (index == ECMD_EXCEPT))
    c5bf:	83 7d e8 01          	cmpl   $0x1,-0x18(%rbp)
    c5c3:	75 31                	jne    c5f6 <enter_enclave+0x140>
    c5c5:	83 7d ec fd          	cmpl   $0xfffffffd,-0x14(%rbp)
    c5c9:	75 2b                	jne    c5f6 <enter_enclave+0x140>
    {
        error = trts_handle_exception(tcs);
    c5cb:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c5cf:	48 89 c7             	mov    %rax,%rdi
    c5d2:	e8 63 79 ff ff       	callq  3f3a <trts_handle_exception>
    c5d7:	89 45 fc             	mov    %eax,-0x4(%rbp)
        if (check_static_stack_canary(tcs) != 0)
    c5da:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    c5de:	48 89 c7             	mov    %rax,%rdi
    c5e1:	e8 fe 50 ff ff       	callq  16e4 <check_static_stack_canary>
    c5e6:	85 c0                	test   %eax,%eax
    c5e8:	0f 95 c0             	setne  %al
    c5eb:	84 c0                	test   %al,%al
    c5ed:	74 07                	je     c5f6 <enter_enclave+0x140>
        {
            error = SGX_ERROR_STACK_OVERRUN;
    c5ef:	c7 45 fc 09 10 00 00 	movl   $0x1009,-0x4(%rbp)
        }
    }
    if(error == SGX_ERROR_UNEXPECTED)
    c5f6:	83 7d fc 01          	cmpl   $0x1,-0x4(%rbp)
    c5fa:	75 0a                	jne    c606 <enter_enclave+0x150>
    {
        set_enclave_state(ENCLAVE_CRASHED);
    c5fc:	bf 03 00 00 00       	mov    $0x3,%edi
    c601:	e8 73 00 00 00       	callq  c679 <set_enclave_state>
    }
    return error;
    c606:	8b 45 fc             	mov    -0x4(%rbp),%eax
}
    c609:	c9                   	leaveq 
    c60a:	c3                   	retq   

000000000000c60b <restore_xregs>:
DECLARE_LOCAL_FUNC restore_xregs
#if defined(LINUX32)
    mov     SE_WORDSIZE(%esp), %ecx
    lea     g_xsave_enabled, %eax
#else
    mov     %rdi, %rcx
    c60b:	48 89 f9             	mov    %rdi,%rcx
    lea_pic g_xsave_enabled, %rax
    c60e:	48 8d 05 8f 4a 00 00 	lea    0x4a8f(%rip),%rax        # 110a4 <g_xsave_enabled>
#endif
    movl    (%xax), %eax
    c615:	8b 00                	mov    (%rax),%eax
    cmpl    $0, %eax
    c617:	83 f8 00             	cmp    $0x0,%eax
    jz      1f
    c61a:	74 16                	je     c632 <restore_xregs+0x27>
    SET_XSAVE_MASK
    c61c:	48 31 c0             	xor    %rax,%rax
    c61f:	48 31 d2             	xor    %rdx,%rdx
    c622:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c627:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    c62c:	48 0f ae 29          	xrstor64 (%rcx)
    DO_XRSTOR
    jmp     2f
    c630:	eb 04                	jmp    c636 <restore_xregs+0x2b>
    c632:	48 0f ae 09          	fxrstor64 (%rcx)
1:
    DO_FXRSTOR
2:
    ret
    c636:	c3                   	retq   

000000000000c637 <save_xregs>:
DECLARE_LOCAL_FUNC save_xregs
#if defined(LINUX32)
    mov     SE_WORDSIZE(%esp), %ecx
    lea     g_xsave_enabled, %eax
#else
    mov     %rdi, %rcx
    c637:	48 89 f9             	mov    %rdi,%rcx
    lea_pic g_xsave_enabled, %rax
    c63a:	48 8d 05 63 4a 00 00 	lea    0x4a63(%rip),%rax        # 110a4 <g_xsave_enabled>
#endif
    fwait
    c641:	9b                   	fwait
    movl    (%xax), %eax
    c642:	8b 00                	mov    (%rax),%eax
    cmpl    $0, %eax
    c644:	83 f8 00             	cmp    $0x0,%eax
    jz      1f
    c647:	74 16                	je     c65f <save_xregs+0x28>
    SET_XSAVE_MASK
    c649:	48 31 c0             	xor    %rax,%rax
    c64c:	48 31 d2             	xor    %rdx,%rdx
    c64f:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    c654:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    c659:	48 0f c7 21          	xsavec64 (%rcx)
    DO_XSAVEC
    jmp     2f
    c65d:	eb 04                	jmp    c663 <save_xregs+0x2c>
    c65f:	48 0f ae 01          	fxsave64 (%rcx)
1:
    DO_FXSAVE
2:
    ret
    c663:	c3                   	retq   

000000000000c664 <get_enclave_base>:

    /* .text */
    .section .nipx,"ax",@progbits

DECLARE_LOCAL_FUNC get_enclave_base
    lea_pic __ImageBase, %xax
    c664:	48 8d 05 95 39 ff ff 	lea    -0xc66b(%rip),%rax        # 0 <enclave.so>
    ret
    c66b:	c3                   	retq   

000000000000c66c <get_enclave_state>:
DECLARE_LOCAL_FUNC get_enclave_state
    lea_pic g_enclave_state, %xcx
    c66c:	48 8d 0d 2d 4a 00 00 	lea    0x4a2d(%rip),%rcx        # 110a0 <g_enclave_state>
    xor     %xax, %xax
    c673:	48 31 c0             	xor    %rax,%rax
    movl    (%xcx), %eax
    c676:	8b 01                	mov    (%rcx),%eax
    ret
    c678:	c3                   	retq   

000000000000c679 <set_enclave_state>:
DECLARE_LOCAL_FUNC set_enclave_state
    lea_pic g_enclave_state, %xax
    c679:	48 8d 05 20 4a 00 00 	lea    0x4a20(%rip),%rax        # 110a0 <g_enclave_state>
#ifdef LINUX32
    mov     SE_WORDSIZE(%esp), %edi
#endif
    movl    %edi, (%xax)
    c680:	89 38                	mov    %edi,(%rax)
    ret
    c682:	c3                   	retq   

000000000000c683 <lock_enclave>:

DECLARE_LOCAL_FUNC lock_enclave
    lea_pic g_enclave_state, %xdx
    c683:	48 8d 15 16 4a 00 00 	lea    0x4a16(%rip),%rdx        # 110a0 <g_enclave_state>
    xor     %xax, %xax
    c68a:	48 31 c0             	xor    %rax,%rax
    mov     $ENCLAVE_INIT_NOT_STARTED, %eax
    c68d:	b8 00 00 00 00       	mov    $0x0,%eax
    xor     %xcx, %xcx
    c692:	48 31 c9             	xor    %rcx,%rcx
    mov     $ENCLAVE_INIT_IN_PROGRESS, %ecx     /* if (g_global_data.enclave_state == ENCLAVE_INIT_NOT_STARTED) */
    c695:	b9 01 00 00 00       	mov    $0x1,%ecx
    lock cmpxchgl %ecx, (%xdx)                  /*   g_global_data.enclave_state == ENCLAVE_INIT_IN_PROGRESS */
    c69a:	f0 0f b1 0a          	lock cmpxchg %ecx,(%rdx)
    ret                                         /* xax: the initial value of enclave state */
    c69e:	c3                   	retq   

000000000000c69f <get_thread_data>:
 *
 *     Get the address of thread_data
 * ---------------------------------------------------------------------
 */
DECLARE_LOCAL_FUNC get_thread_data
    READ_TD_DATA self_addr 
    c69f:	65 48 8b 04 25 00 00 	mov    %gs:0x0,%rax
    c6a6:	00 00 
    ret
    c6a8:	c3                   	retq   

000000000000c6a9 <get_stack_guard>:
 *
 *     Get the value of stack_guard
 * ---------------------------------------------------------------------
 */
DECLARE_LOCAL_FUNC get_stack_guard 
    READ_TD_DATA stack_guard 
    c6a9:	65 48 8b 04 25 28 00 	mov    %gs:0x28,%rax
    c6b0:	00 00 
    ret
    c6b2:	c3                   	retq   

000000000000c6b3 <enclave_entry>:
 * ----------------------------------------------------------------------
 */
    .cfi_startproc

    /* Clear unused general registers */
    xor     %xdx, %xdx
    c6b3:	48 31 d2             	xor    %rdx,%rdx
    add     %xdx, %xdx          /* OF = SF = AF = CF = 0; ZF = PF = 1 */
    c6b6:	48 01 d2             	add    %rdx,%rdx
    cld                         /* DF = 0 */
    c6b9:	fc                   	cld    
#if defined(LINUX64)
    xor     %r8, %r8
    c6ba:	4d 31 c0             	xor    %r8,%r8
    xor     %r9, %r9
    c6bd:	4d 31 c9             	xor    %r9,%r9
    xor     %r10, %r10
    c6c0:	4d 31 d2             	xor    %r10,%r10
    xor     %r11, %r11
    c6c3:	4d 31 db             	xor    %r11,%r11
    xor     %r12, %r12
    c6c6:	4d 31 e4             	xor    %r12,%r12
    xor     %r13, %r13
    c6c9:	4d 31 ed             	xor    %r13,%r13
    xor     %r14, %r14
    c6cc:	4d 31 f6             	xor    %r14,%r14
    xor     %r15, %r15
    c6cf:	4d 31 ff             	xor    %r15,%r15
#endif

    /* switch to trusted stack */
    cmp     $0, %xax
    c6d2:	48 83 f8 00          	cmp    $0x0,%rax
    jne     .Ldo_handler                /* handle exception state */
    c6d6:	0f 85 cb 00 00 00    	jne    c7a7 <enclave_entry+0xf4>
    /* xor     %xdx, %xdx                  xdx is cssa, make sure it is 0 */
    READ_TD_DATA last_sp
    c6dc:	65 48 8b 04 25 08 00 	mov    %gs:0x8,%rax
    c6e3:	00 00 
    cmp     $0, %xax
    c6e5:	48 83 f8 00          	cmp    $0x0,%rax
    jne .Lswitch_stack
    c6e9:	75 0f                	jne    c6fa <enclave_entry+0x47>
    GET_STACK_BASE  %xbx                /* if last_sp == 0, set sp to stack base */
    c6eb:	48 89 d8             	mov    %rbx,%rax
    c6ee:	48 2d 00 00 01 00    	sub    $0x10000,%rax
    sub     $STATIC_STACK_SIZE, %xax    /* give space for static stack */
    c6f4:	48 2d b0 02 00 00    	sub    $0x2b0,%rax
.Lswitch_stack:
    xchg    %xsp, %xax
    c6fa:	48 94                	xchg   %rax,%rsp
    push    %xcx
    c6fc:	51                   	push   %rcx
    push    %xbp
    c6fd:	55                   	push   %rbp

    .cfi_def_cfa_offset   2 * SE_WORDSIZE
    .cfi_offset           xbp, -2 * SE_WORDSIZE
    mov     %xsp, %xbp
    c6fe:	48 89 e5             	mov    %rsp,%rbp
    .cfi_def_cfa_register xbp

    CLEAN_XFLAGS
    c701:	9c                   	pushfq 
    c702:	48 f7 14 24          	notq   (%rsp)
    c706:	48 81 0c 24 00 00 04 	orq    $0x40000,(%rsp)
    c70d:	00 
    c70e:	48 f7 14 24          	notq   (%rsp)
    c712:	9d                   	popfq  


    /* Save the registers */
    sub     $(6*SE_WORDSIZE), %xsp
    c713:	48 83 ec 30          	sub    $0x30,%rsp
    mov     %xax, -1*SE_WORDSIZE(%xbp)  /* xsp_u */
    c717:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    mov     %xdx, -3*SE_WORDSIZE(%xbp)  /* cssa */
    c71b:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    mov     %xbx, -4*SE_WORDSIZE(%xbp)  /* TCS */
    c71f:	48 89 5d e0          	mov    %rbx,-0x20(%rbp)
    mov     %xsi, -5*SE_WORDSIZE(%xbp)  /* XSI */
    c723:	48 89 75 d8          	mov    %rsi,-0x28(%rbp)
    mov     %xdi, -6*SE_WORDSIZE(%xbp)  /* XDI */
    c727:	48 89 7d d0          	mov    %rdi,-0x30(%rbp)

    /* clean extended feature registers */
    sub     $(4*SE_WORDSIZE), %xsp
    c72b:	48 83 ec 20          	sub    $0x20,%rsp

    lea_pic SYNTHETIC_STATE, %xdi
    c72f:	48 8d 3d ca 10 00 00 	lea    0x10ca(%rip),%rdi        # d800 <SYNTHETIC_STATE>
#ifdef LINUX32
    mov     %xdi, (%xsp)
#endif
    call    restore_xregs
    c736:	e8 d0 fe ff ff       	callq  c60b <restore_xregs>
    add     $(4*SE_WORDSIZE), %xsp
    c73b:	48 83 c4 20          	add    $0x20,%rsp

    /* switch to C code */
#ifdef LINUX64
    mov     -6*SE_WORDSIZE(%xbp), %xdi  /* index */
    c73f:	48 8b 7d d0          	mov    -0x30(%rbp),%rdi
    mov     -5*SE_WORDSIZE(%xbp), %xsi  /* ms */
    c743:	48 8b 75 d8          	mov    -0x28(%rbp),%rsi
    mov     -4*SE_WORDSIZE(%xbp), %xdx  /* TCS */
    c747:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    mov     -3*SE_WORDSIZE(%xbp), %xcx  /* cssa */
    c74b:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
#endif
    call    enter_enclave
    c74f:	e8 62 fd ff ff       	callq  c4b6 <enter_enclave>
    mov     %xax, %xbx
    c754:	48 89 c3             	mov    %rax,%rbx

.Lexit_enclave:
/* clean extended feature registers */
    lea_pic SYNTHETIC_STATE, %xdi
    c757:	48 8d 3d a2 10 00 00 	lea    0x10a2(%rip),%rdi        # d800 <SYNTHETIC_STATE>
#ifdef LINUX32
    mov     %xdi, (%xsp)
#endif
    call    restore_xregs
    c75e:	e8 a8 fe ff ff       	callq  c60b <restore_xregs>

/* set xdi and xsi */
    mov     $OCMD_ERET, %xdi
    c763:	48 c7 c7 ff ff ff ff 	mov    $0xffffffffffffffff,%rdi
    mov     %xbx, %xsi
    c76a:	48 89 de             	mov    %rbx,%rsi

/* restore stack */
    mov     -1*SE_WORDSIZE(%xbp), %xdx  /* xdx: xsp_u  */
    c76d:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    mov     %xbp, %xsp
    c771:	48 89 ec             	mov    %rbp,%rsp
    pop     %xbp                        /* xbp_u */
    c774:	5d                   	pop    %rbp
    pop     %xbx                        /* ret_u */
    c775:	5b                   	pop    %rbx
    mov     %xdx, %xsp                  /* xsp_u */
    c776:	48 89 d4             	mov    %rdx,%rsp

.Lclear_and_exit_enclave:
    /* Clear all GPRs, except xax, xbx, xdi and xsi */
    xor     %xcx, %xcx
    c779:	48 31 c9             	xor    %rcx,%rcx
    xor     %xdx, %xdx
    c77c:	48 31 d2             	xor    %rdx,%rdx
#if defined(LINUX64)
    xor     %r8, %r8
    c77f:	4d 31 c0             	xor    %r8,%r8
    xor     %r9, %r9
    c782:	4d 31 c9             	xor    %r9,%r9
    xor     %r10, %r10
    c785:	4d 31 d2             	xor    %r10,%r10
    xor     %r11, %r11
    c788:	4d 31 db             	xor    %r11,%r11
    xor     %r12, %r12
    c78b:	4d 31 e4             	xor    %r12,%r12
    xor     %r13, %r13
    c78e:	4d 31 ed             	xor    %r13,%r13
    xor     %r14, %r14
    c791:	4d 31 f6             	xor    %r14,%r14
    xor     %r15, %r15
    c794:	4d 31 ff             	xor    %r15,%r15
#endif

    /* Set status flags to pre-defined values */
    add     %xdx, %xdx          /* OF = SF = AF = CF = 0; ZF = PF = 1 */
    c797:	48 01 d2             	add    %rdx,%rdx
    cld                         /* DF = 0 */
    c79a:	fc                   	cld    

    /* EEXIT */
    mov     $SE_EEXIT, %xax     /* EEXIT leaf */
    c79b:	48 c7 c0 04 00 00 00 	mov    $0x4,%rax
    c7a2:	0f 01 d7             	enclu  
    ENCLU

    /* Should not come here */
    ud2
    c7a5:	0f 0b                	ud2    

.Ldo_handler:
    mov     %xax, %xdx          /* XDX: cssa */
    c7a7:	48 89 c2             	mov    %rax,%rdx
    GET_STACK_BASE %xbx         /* XAX: static stack, set sp to stack base */
    c7aa:	48 89 d8             	mov    %rbx,%rax
    c7ad:	48 2d 00 00 01 00    	sub    $0x10000,%rax
    jmp     .Lswitch_stack   
    c7b3:	e9 42 ff ff ff       	jmpq   c6fa <enclave_entry+0x47>
 
    /* Should not come here */
    ud2
    c7b8:	0f 0b                	ud2    

000000000000c7ba <do_ocall>:
/* 
 * 8 for GPR, 1 for TD.last_sp, 1 for ocall_index
 * 1 for OCALL_FLAG, 4 for shadow space.
 * Stack Pointer is 16-byte aligned under x86_64.
 */
    push    %xbp
    c7ba:	55                   	push   %rbp
    mov     %xsp, %xbp
    c7bb:	48 89 e5             	mov    %rsp,%rbp

/* save parameters in stack */
#ifdef LINUX64
    mov     %xdi, 2*SE_WORDSIZE(%xbp)
    c7be:	48 89 7d 10          	mov    %rdi,0x10(%rbp)
    mov     %xsi, 3*SE_WORDSIZE(%xbp)
    c7c2:	48 89 75 18          	mov    %rsi,0x18(%rbp)
#endif

/* save and clean extended feature registers */
    READ_TD_DATA xsave_size
    c7c6:	65 48 8b 04 25 38 00 	mov    %gs:0x38,%rax
    c7cd:	00 00 
    sub     %xax, %xsp                 /* allocate buffer to save xregs */
    c7cf:	48 29 c4             	sub    %rax,%rsp
    mov     $0x3f, %xax
    c7d2:	48 c7 c0 3f 00 00 00 	mov    $0x3f,%rax
    not     %xax
    c7d9:	48 f7 d0             	not    %rax
    and     %xax, %xsp                 /* xsave requires 64 byte aligned */
    c7dc:	48 21 c4             	and    %rax,%rsp
    mov     %xsp, %xcx                 # xsave pointer
    c7df:	48 89 e1             	mov    %rsp,%rcx

    sub     $(20*SE_WORDSIZE), %xsp    /* 20 slots for GPRs and other info */
    c7e2:	48 81 ec a0 00 00 00 	sub    $0xa0,%rsp
    mov     %xcx, SE_WORDSIZE*19(%xsp) /* addr for xsave */
    c7e9:	48 89 8c 24 98 00 00 	mov    %rcx,0x98(%rsp)
    c7f0:	00 
/* save non-volatile registers, except xsp */
    mov     %xbx, SE_WORDSIZE*14(%xsp)
    c7f1:	48 89 5c 24 70       	mov    %rbx,0x70(%rsp)
    mov     %xsi, SE_WORDSIZE*13(%xsp)
    c7f6:	48 89 74 24 68       	mov    %rsi,0x68(%rsp)
    mov     %xdi, SE_WORDSIZE*12(%xsp)
    c7fb:	48 89 7c 24 60       	mov    %rdi,0x60(%rsp)
    mov     %xbp, SE_WORDSIZE*11(%xsp)
    c800:	48 89 6c 24 58       	mov    %rbp,0x58(%rsp)

#ifdef LINUX64
    mov     %r12, SE_WORDSIZE*10(%rsp)
    c805:	4c 89 64 24 50       	mov    %r12,0x50(%rsp)
    mov     %r13, SE_WORDSIZE* 9(%rsp)
    c80a:	4c 89 6c 24 48       	mov    %r13,0x48(%rsp)
    mov     %r14, SE_WORDSIZE* 8(%rsp)
    c80f:	4c 89 74 24 40       	mov    %r14,0x40(%rsp)
    mov     %r15, SE_WORDSIZE* 7(%rsp)
    c814:	4c 89 7c 24 38       	mov    %r15,0x38(%rsp)
#endif

/* save and clean extended feature registers */
    mov     SE_WORDSIZE*19(%xsp), %xdi /* xsave pointer */
    c819:	48 8b bc 24 98 00 00 	mov    0x98(%rsp),%rdi
    c820:	00 
    READ_TD_DATA xsave_size
    c821:	65 48 8b 04 25 38 00 	mov    %gs:0x38,%rax
    c828:	00 00 
    mov     %xax, %xcx
    c82a:	48 89 c1             	mov    %rax,%rcx
    shr     $2, %xcx                   /* xsave size in dword */
    c82d:	48 c1 e9 02          	shr    $0x2,%rcx
    xor     %xax, %xax
    c831:	48 31 c0             	xor    %rax,%rax
    cld
    c834:	fc                   	cld    
    rep stos %eax, %es:(%xdi)
    c835:	f3 ab                	rep stos %eax,%es:(%rdi)

    mov     SE_WORDSIZE*19(%xsp), %xdi # xsave pointer
    c837:	48 8b bc 24 98 00 00 	mov    0x98(%rsp),%rdi
    c83e:	00 
    mov     %xdi, (%xsp)
    c83f:	48 89 3c 24          	mov    %rdi,(%rsp)
    call    save_xregs
    c843:	e8 ef fd ff ff       	callq  c637 <save_xregs>
    lea_pic SYNTHETIC_STATE, %xdi
    c848:	48 8d 3d b1 0f 00 00 	lea    0xfb1(%rip),%rdi        # d800 <SYNTHETIC_STATE>
    mov     %xdi, (%xsp)
    c84f:	48 89 3c 24          	mov    %rdi,(%rsp)
    call    restore_xregs
    c853:	e8 b3 fd ff ff       	callq  c60b <restore_xregs>

    /* set xdi and xsi using the input parameters */
#ifdef LINUX64
    mov     SE_WORDSIZE*12(%xsp), %xdi
    c858:	48 8b 7c 24 60       	mov    0x60(%rsp),%rdi
    mov     SE_WORDSIZE*13(%xsp), %xsi
    c85d:	48 8b 74 24 68       	mov    0x68(%rsp),%rsi
    mov     SE_WORDSIZE*2(%ebp), %edi
    mov     SE_WORDSIZE*3(%ebp), %esi
#endif

    /* save ocall index to the stack */
    mov     $OCALL_FLAG, %xax
    c862:	48 c7 c0 44 49 43 4f 	mov    $0x4f434944,%rax
    mov     %xax, SE_WORDSIZE*4(%xsp)   /* save OCALL_FLAG */
    c869:	48 89 44 24 20       	mov    %rax,0x20(%rsp)
    mov     %xdi, SE_WORDSIZE*5(%xsp)   /* save ocall_index */
    c86e:	48 89 7c 24 28       	mov    %rdi,0x28(%rsp)
    /*
     * save the inside stack context
     *     push TD.last_sp
     *     set TD.last_sp = xsp
     */
    READ_TD_DATA self_addr
    c873:	65 48 8b 04 25 00 00 	mov    %gs:0x0,%rax
    c87a:	00 00 
    mov     %xax, %xbx 
    c87c:	48 89 c3             	mov    %rax,%rbx

    /* call update_ocall_lastsp */
#ifdef LINUX32
    mov     %xsp, (%xsp)
#else
    mov     %xsp, %xdi
    c87f:	48 89 e7             	mov    %rsp,%rdi
#endif
    
    call    update_ocall_lastsp         /* xax: td.last_sp */
    c882:	e8 12 6e ff ff       	callq  3699 <update_ocall_lastsp>

#ifdef LINUX64
    mov     SE_WORDSIZE*12(%xsp), %xdi   /* restore xdi */
    c887:	48 8b 7c 24 60       	mov    0x60(%rsp),%rdi
    mov     SE_WORDSIZE*13(%xsp), %xsi   /* restore xdi */
    c88c:	48 8b 74 24 68       	mov    0x68(%rsp),%rsi
#endif

    /* restore outside stack context */
    mov     first_ssa_gpr(%xbx), %xdx
    c891:	48 8b 53 20          	mov    0x20(%rbx),%rdx
    mov     ssa_bp_u(%xdx), %xbp
    c895:	48 8b aa 98 00 00 00 	mov    0x98(%rdx),%rbp
    mov     ssa_sp_u(%xdx), %xsp
    c89c:	48 8b a2 90 00 00 00 	mov    0x90(%rdx),%rsp
     *                    | ret_addr    |
     *                    | xbp_u       |
     *                    | xsp_u       |
     *                    | ...         |
     */
    mov     -1*SE_WORDSIZE(%xax), %xbx  /* return address */
    c8a3:	48 8b 58 f8          	mov    -0x8(%rax),%rbx
    mov     $SE_EEXIT, %xax             /* EEXIT leaf */
    c8a7:	48 c7 c0 04 00 00 00 	mov    $0x4,%rax

    /* Clear all GPRs, except xax, xbx, xdi, and xsi*/
    xor     %xcx, %xcx
    c8ae:	48 31 c9             	xor    %rcx,%rcx
    xor     %xdx, %xdx
    c8b1:	48 31 d2             	xor    %rdx,%rdx
#ifdef LINUX64
    xor     %r8,  %r8
    c8b4:	4d 31 c0             	xor    %r8,%r8
    xor     %r9,  %r9
    c8b7:	4d 31 c9             	xor    %r9,%r9
    xor     %r10, %r10
    c8ba:	4d 31 d2             	xor    %r10,%r10
    xor     %r11, %r11
    c8bd:	4d 31 db             	xor    %r11,%r11
    xor     %r12, %r12
    c8c0:	4d 31 e4             	xor    %r12,%r12
    xor     %r13, %r13
    c8c3:	4d 31 ed             	xor    %r13,%r13
    xor     %r14, %r14
    c8c6:	4d 31 f6             	xor    %r14,%r14
    xor     %r15, %r15
    c8c9:	4d 31 ff             	xor    %r15,%r15
#endif

    /* Set status flags to pre-defined values */
    add     %xdx, %xdx          /* OF = SF = AF = CF = 0; ZF = PF = 1 */
    c8cc:	48 01 d2             	add    %rdx,%rdx
    cld                         /* DF = 0 */
    c8cf:	fc                   	cld    
    c8d0:	0f 01 d7             	enclu  

000000000000c8d3 <__morestack>:
 * stick ocall bridge and proxy frame together
 * ------------------------------------------------------------------
 */
DECLARE_LOCAL_FUNC __morestack
    .cfi_startproc
    push %xbp
    c8d3:	55                   	push   %rbp
    .cfi_def_cfa_offset     2*SE_WORDSIZE
    .cfi_offset             xbp,-2*SE_WORDSIZE
    mov %xsp, %xbp
    c8d4:	48 89 e5             	mov    %rsp,%rbp
    .cfi_def_cfa_register   xbp
    sub $(4*SE_WORDSIZE), %xsp
    c8d7:	48 83 ec 20          	sub    $0x20,%rsp
    mov (2*SE_WORDSIZE)(%xbp), %xax
    mov %xax, (0*SE_WORDSIZE)(%xsp)
    mov (3*SE_WORDSIZE)(%xbp), %xax
    mov %xax, (1*SE_WORDSIZE)(%xsp)
#endif
    call        do_ocall
    c8db:	e8 da fe ff ff       	callq  c7ba <do_ocall>
    leave
    c8e0:	c9                   	leaveq 
    ret
    c8e1:	c3                   	retq   

000000000000c8e2 <asm_oret>:
    .cfi_endproc

DECLARE_GLOBAL_FUNC asm_oret
    mov     %xsp, %xbx
    c8e2:	48 89 e3             	mov    %rsp,%rbx
#ifdef LINUX64
    mov     %xdi, SE_WORDSIZE(%xsp)
    c8e5:	48 89 7c 24 08       	mov    %rdi,0x8(%rsp)
    mov     %xsi, 2*SE_WORDSIZE(%xsp)
    c8ea:	48 89 74 24 10       	mov    %rsi,0x10(%rsp)
#endif
    mov     SE_WORDSIZE(%xbx), %xsp    /* restore thread_data.last_sp */
    c8ef:	48 8b 63 08          	mov    0x8(%rbx),%rsp

/* restore extended feature registers */
    mov     19*SE_WORDSIZE(%xsp), %xdi
    c8f3:	48 8b bc 24 98 00 00 	mov    0x98(%rsp),%rdi
    c8fa:	00 
#ifdef LINUX32
    mov     %xdi, (%xsp)
#endif
    call    restore_xregs
    c8fb:	e8 0b fd ff ff       	callq  c60b <restore_xregs>

/* memset_s */
    xor     %xax, %xax
    c900:	48 31 c0             	xor    %rax,%rax
    mov     11*SE_WORDSIZE(%xsp), %xcx
    c903:	48 8b 4c 24 58       	mov    0x58(%rsp),%rcx
    sub     %xdi, %xcx
    c908:	48 29 f9             	sub    %rdi,%rcx
    sub     $SE_WORDSIZE, %xcx
    c90b:	48 83 e9 08          	sub    $0x8,%rcx
    shr     $2, %xcx
    c90f:	48 c1 e9 02          	shr    $0x2,%rcx
    cld
    c913:	fc                   	cld    
    rep stos %eax,%es:(%xdi)
    c914:	f3 ab                	rep stos %eax,%es:(%rdi)

    mov     2*SE_WORDSIZE(%xbx), %xax  /* ocall return value */
    c916:	48 8b 43 10          	mov    0x10(%rbx),%rax

#ifdef LINUX64
    mov     7*SE_WORDSIZE(%xsp), %r15
    c91a:	4c 8b 7c 24 38       	mov    0x38(%rsp),%r15
    mov     8*SE_WORDSIZE(%xsp), %r14
    c91f:	4c 8b 74 24 40       	mov    0x40(%rsp),%r14
    mov     9*SE_WORDSIZE(%xsp), %r13
    c924:	4c 8b 6c 24 48       	mov    0x48(%rsp),%r13
    mov    10*SE_WORDSIZE(%xsp), %r12
    c929:	4c 8b 64 24 50       	mov    0x50(%rsp),%r12
#endif

    mov    11*SE_WORDSIZE(%xsp), %xbp
    c92e:	48 8b 6c 24 58       	mov    0x58(%rsp),%rbp
    mov    12*SE_WORDSIZE(%xsp), %xdi
    c933:	48 8b 7c 24 60       	mov    0x60(%rsp),%rdi
    mov    13*SE_WORDSIZE(%xsp), %xsi
    c938:	48 8b 74 24 68       	mov    0x68(%rsp),%rsi
    mov    14*SE_WORDSIZE(%xsp), %xbx
    c93d:	48 8b 5c 24 70       	mov    0x70(%rsp),%rbx

    mov     %xbp, %xsp
    c942:	48 89 ec             	mov    %rbp,%rsp
    pop     %xbp
    c945:	5d                   	pop    %rbp

    ret
    c946:	c3                   	retq   
    /* should not come here */
    ud2
    c947:	0f 0b                	ud2    

000000000000c949 <do_egetkey>:
 * EGETKEY: rbx - the address of KEYREQUEST structure
 *	   rcx - the address where the key is outputted
 * ------------------------------------------------------------------------
 */
DECLARE_LOCAL_FUNC do_egetkey
    SE_PROLOG
    c949:	53                   	push   %rbx
    c94a:	51                   	push   %rcx
    c94b:	52                   	push   %rdx
    c94c:	48 89 fb             	mov    %rdi,%rbx
    c94f:	48 89 f1             	mov    %rsi,%rcx
    mov  $SE_EGETKEY, %xax      /* EGETKEY leaf */
    c952:	48 c7 c0 01 00 00 00 	mov    $0x1,%rax
    c959:	0f 01 d7             	enclu  
    ENCLU
#ifdef SE_SIM
    cmp  $SGX_SUCCESS, %xax     /* In simulation mode, ZF flag will not be set */
    jnz	 .Legetkey_done         /* because the stack clean operation will always clean ZF flag */
#else
    jz   .Legetkey_done         /* if EGETKEY error, ZF flag is set and error code is set to xax */
    c95c:	74 03                	je     c961 <do_egetkey+0x18>
#endif
    xor  %xax, %xax
    c95e:	48 31 c0             	xor    %rax,%rax
.Legetkey_done:
    SE_EPILOG
    c961:	5a                   	pop    %rdx
    c962:	59                   	pop    %rcx
    c963:	5b                   	pop    %rbx
    c964:	c3                   	retq   

000000000000c965 <do_ereport>:
 *          non-zero: failure
 * -------------------------------------------------------------------------
 */
.global Lereport_inst
DECLARE_LOCAL_FUNC do_ereport
    SE_PROLOG
    c965:	53                   	push   %rbx
    c966:	51                   	push   %rcx
    c967:	52                   	push   %rdx
    c968:	48 89 fb             	mov    %rdi,%rbx
    c96b:	48 89 f1             	mov    %rsi,%rcx
    mov       $SE_EREPORT, %xax  /* EREPORT leaf */
    c96e:	48 c7 c0 00 00 00 00 	mov    $0x0,%rax
    clc
    c975:	f8                   	clc    

000000000000c976 <Lereport_inst>:
    c976:	0f 01 d7             	enclu  
Lereport_inst:
    ENCLU
    setc      %al
    c979:	0f 92 c0             	setb   %al
    SE_EPILOG
    c97c:	5a                   	pop    %rdx
    c97d:	59                   	pop    %rcx
    c97e:	5b                   	pop    %rbx
    c97f:	c3                   	retq   

000000000000c980 <do_eaccept>:
    
DECLARE_GLOBAL_FUNC do_eaccept
    SE_PROLOG
    c980:	53                   	push   %rbx
    c981:	51                   	push   %rcx
    c982:	52                   	push   %rdx
    c983:	48 89 fb             	mov    %rdi,%rbx
    c986:	48 89 f1             	mov    %rsi,%rcx
    mov     $SE_EACCEPT, %eax
    c989:	b8 05 00 00 00       	mov    $0x5,%eax
    c98e:	0f 01 d7             	enclu  
    ENCLU
    cmp  $SGX_SUCCESS, %eax 
    c991:	83 f8 00             	cmp    $0x0,%eax
    jnz	 abort 
    c994:	75 38                	jne    c9ce <abort>
    SE_EPILOG
    c996:	5a                   	pop    %rdx
    c997:	59                   	pop    %rcx
    c998:	5b                   	pop    %rbx
    c999:	c3                   	retq   

000000000000c99a <do_emodpe>:

DECLARE_GLOBAL_FUNC do_emodpe
    SE_PROLOG
    c99a:	53                   	push   %rbx
    c99b:	51                   	push   %rcx
    c99c:	52                   	push   %rdx
    c99d:	48 89 fb             	mov    %rdi,%rbx
    c9a0:	48 89 f1             	mov    %rsi,%rcx
    mov     $SE_EMODPE, %eax 
    c9a3:	b8 06 00 00 00       	mov    $0x6,%eax
    c9a8:	0f 01 d7             	enclu  
    ENCLU
    SE_EPILOG
    c9ab:	5a                   	pop    %rdx
    c9ac:	59                   	pop    %rcx
    c9ad:	5b                   	pop    %rbx
    c9ae:	c3                   	retq   

000000000000c9af <do_rdrand>:
 *	non-zero: rdrand succeeded
 *	zero: rdrand failed
 * -------------------------------------
 */
DECLARE_LOCAL_FUNC do_rdrand
    mov $_RDRAND_RETRY_TIMES, %ecx
    c9af:	b9 0a 00 00 00       	mov    $0xa,%ecx
    c9b4:	0f c7 f0             	rdrand %eax
.Lrdrand_retry:
    .byte 0x0F, 0xC7, 0xF0	    /* rdrand %eax */
    jc	.Lrdrand_return
    c9b7:	72 08                	jb     c9c1 <do_rdrand+0x12>
    dec	%ecx
    c9b9:	ff c9                	dec    %ecx
    jnz 	.Lrdrand_retry
    c9bb:	75 f7                	jne    c9b4 <do_rdrand+0x5>
    xor 	%xax, %xax
    c9bd:	48 31 c0             	xor    %rax,%rax
    ret
    c9c0:	c3                   	retq   
.Lrdrand_return:
#ifdef LINUX32
    mov     SE_WORDSIZE(%esp), %ecx
#else
    mov     %rdi, %rcx
    c9c1:	48 89 f9             	mov    %rdi,%rcx
#endif
    movl    %eax, (%xcx)
    c9c4:	89 01                	mov    %eax,(%rcx)
    mov     $1, %xax
    c9c6:	48 c7 c0 01 00 00 00 	mov    $0x1,%rax
    ret
    c9cd:	c3                   	retq   

000000000000c9ce <abort>:
 * -------------------------------------------------------------------------
 * extern "C" void abort(void) __attribute__(__noreturn__);
 * -------------------------------------------------------------------------
 */
DECLARE_LOCAL_FUNC abort
    lea_pic g_enclave_state, %xax
    c9ce:	48 8d 05 cb 46 00 00 	lea    0x46cb(%rip),%rax        # 110a0 <g_enclave_state>
    movl    $ENCLAVE_CRASHED, (%xax)
    c9d5:	c7 00 03 00 00 00    	movl   $0x3,(%rax)
    ud2
    c9db:	0f 0b                	ud2    

000000000000c9dd <continue_execution>:
 */
DECLARE_LOCAL_FUNC continue_execution
#ifdef LINUX32
    mov     %xax, %xcx
#else
    mov     %xdi, %xcx
    c9dd:	48 89 f9             	mov    %rdi,%rcx
#endif
    mov     SE_WORDSIZE*0(%xcx), %xax
    c9e0:	48 8b 01             	mov    (%rcx),%rax
    push    %xax                       /* push xax */
    c9e3:	50                   	push   %rax
    mov     SE_WORDSIZE*1(%xcx), %xax
    c9e4:	48 8b 41 08          	mov    0x8(%rcx),%rax
    push    %xax                       /* push xcx */
    c9e8:	50                   	push   %rax
    mov     SE_WORDSIZE*4(%xcx), %xax  /* xax: xsp */
    c9e9:	48 8b 41 20          	mov    0x20(%rcx),%rax
/* x86_64 requires a 128-bytes red zone. We need to allocate buffer to avoid touching the red zone. */
    sub     $(SE_WORDSIZE + RED_ZONE_SIZE), %xax   /* allocate buffer to skip red zone and save xip */
    c9ed:	48 2d 88 00 00 00    	sub    $0x88,%rax

/* restore registers except xax, xcx, xsp */
    mov     SE_WORDSIZE*2(%xcx), %xdx
    c9f3:	48 8b 51 10          	mov    0x10(%rcx),%rdx
    mov     SE_WORDSIZE*3(%xcx), %xbx
    c9f7:	48 8b 59 18          	mov    0x18(%rcx),%rbx
    mov     SE_WORDSIZE*5(%xcx), %xbp
    c9fb:	48 8b 69 28          	mov    0x28(%rcx),%rbp
    mov     SE_WORDSIZE*6(%xcx), %xsi
    c9ff:	48 8b 71 30          	mov    0x30(%rcx),%rsi
    mov     SE_WORDSIZE*7(%xcx), %xdi
    ca03:	48 8b 79 38          	mov    0x38(%rcx),%rdi
#ifdef LINUX64
    mov     SE_WORDSIZE*8(%xcx), %r8
    ca07:	4c 8b 41 40          	mov    0x40(%rcx),%r8
    mov     SE_WORDSIZE*9(%xcx), %r9
    ca0b:	4c 8b 49 48          	mov    0x48(%rcx),%r9
    mov     SE_WORDSIZE*10(%xcx), %r10
    ca0f:	4c 8b 51 50          	mov    0x50(%rcx),%r10
    mov     SE_WORDSIZE*11(%xcx), %r11
    ca13:	4c 8b 59 58          	mov    0x58(%rcx),%r11
    mov     SE_WORDSIZE*12(%xcx), %r12
    ca17:	4c 8b 61 60          	mov    0x60(%rcx),%r12
    mov     SE_WORDSIZE*13(%xcx), %r13
    ca1b:	4c 8b 69 68          	mov    0x68(%rcx),%r13
    mov     SE_WORDSIZE*14(%xcx), %r14
    ca1f:	4c 8b 71 70          	mov    0x70(%rcx),%r14
    mov     SE_WORDSIZE*15(%xcx), %r15
    ca23:	4c 8b 79 78          	mov    0x78(%rcx),%r15
    push    SE_WORDSIZE*16(%xcx)
    ca27:	ff b1 80 00 00 00    	pushq  0x80(%rcx)
    popf    /* make sure the following instructions do not affect flags */
    ca2d:	9d                   	popfq  
    push    SE_WORDSIZE*8(%xcx)
    popf
#endif

#ifdef LINUX64
    mov     SE_WORDSIZE*17(%xcx), %xcx
    ca2e:	48 8b 89 88 00 00 00 	mov    0x88(%rcx),%rcx
#endif

/* do not setup the new stack until info is not needed any more
 * otherwise, info will be overwritten
 */
    mov     %xcx, (%xax)               /* save xip to the new stack */
    ca35:	48 89 08             	mov    %rcx,(%rax)
    pop     %xcx                       /* restore xcx */
    ca38:	59                   	pop    %rcx
    pop     %xsp                       /* xsp: xax */
    ca39:	5c                   	pop    %rsp
    xchg    %xax, %xsp
    ca3a:	48 94                	xchg   %rax,%rsp
    ret     $(RED_ZONE_SIZE)           /* pop xip and red zone (if any) */
    ca3c:	c2 80 00             	retq   $0x80
