
./fin:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:	48 83 ec 08          	sub    $0x8,%rsp
    1004:	48 8b 05 dd 2f 00 00 	mov    0x2fdd(%rip),%rax        # 3fe8 <__gmon_start__>
    100b:	48 85 c0             	test   %rax,%rax
    100e:	74 02                	je     1012 <_init+0x12>
    1010:	ff d0                	callq  *%rax
    1012:	48 83 c4 08          	add    $0x8,%rsp
    1016:	c3                   	retq   

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 a2 2f 00 00    	pushq  0x2fa2(%rip)        # 3fc8 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	ff 25 a4 2f 00 00    	jmpq   *0x2fa4(%rip)        # 3fd0 <_GLOBAL_OFFSET_TABLE_+0x10>
    102c:	0f 1f 40 00          	nopl   0x0(%rax)

Disassembly of section .plt.got:

0000000000001030 <__cxa_finalize@plt>:
    1030:	ff 25 c2 2f 00 00    	jmpq   *0x2fc2(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1036:	66 90                	xchg   %ax,%ax

Disassembly of section .text:

0000000000001040 <_start>:
    1040:	31 ed                	xor    %ebp,%ebp
    1042:	49 89 d1             	mov    %rdx,%r9
    1045:	5e                   	pop    %rsi
    1046:	48 89 e2             	mov    %rsp,%rdx
    1049:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    104d:	50                   	push   %rax
    104e:	54                   	push   %rsp
    104f:	4c 8d 05 8a 01 00 00 	lea    0x18a(%rip),%r8        # 11e0 <__libc_csu_fini>
    1056:	48 8d 0d 13 01 00 00 	lea    0x113(%rip),%rcx        # 1170 <__libc_csu_init>
    105d:	48 8d 3d e6 00 00 00 	lea    0xe6(%rip),%rdi        # 114a <main>
    1064:	ff 15 76 2f 00 00    	callq  *0x2f76(%rip)        # 3fe0 <__libc_start_main@GLIBC_2.2.5>
    106a:	f4                   	hlt    
    106b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001070 <deregister_tm_clones>:
    1070:	48 8d 3d 99 2f 00 00 	lea    0x2f99(%rip),%rdi        # 4010 <__TMC_END__>
    1077:	55                   	push   %rbp
    1078:	48 8d 05 91 2f 00 00 	lea    0x2f91(%rip),%rax        # 4010 <__TMC_END__>
    107f:	48 39 f8             	cmp    %rdi,%rax
    1082:	48 89 e5             	mov    %rsp,%rbp
    1085:	74 19                	je     10a0 <deregister_tm_clones+0x30>
    1087:	48 8b 05 4a 2f 00 00 	mov    0x2f4a(%rip),%rax        # 3fd8 <_ITM_deregisterTMCloneTable>
    108e:	48 85 c0             	test   %rax,%rax
    1091:	74 0d                	je     10a0 <deregister_tm_clones+0x30>
    1093:	5d                   	pop    %rbp
    1094:	ff e0                	jmpq   *%rax
    1096:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    109d:	00 00 00 
    10a0:	5d                   	pop    %rbp
    10a1:	c3                   	retq   
    10a2:	0f 1f 40 00          	nopl   0x0(%rax)
    10a6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    10ad:	00 00 00 

00000000000010b0 <register_tm_clones>:
    10b0:	48 8d 3d 59 2f 00 00 	lea    0x2f59(%rip),%rdi        # 4010 <__TMC_END__>
    10b7:	48 8d 35 52 2f 00 00 	lea    0x2f52(%rip),%rsi        # 4010 <__TMC_END__>
    10be:	55                   	push   %rbp
    10bf:	48 29 fe             	sub    %rdi,%rsi
    10c2:	48 89 e5             	mov    %rsp,%rbp
    10c5:	48 c1 fe 03          	sar    $0x3,%rsi
    10c9:	48 89 f0             	mov    %rsi,%rax
    10cc:	48 c1 e8 3f          	shr    $0x3f,%rax
    10d0:	48 01 c6             	add    %rax,%rsi
    10d3:	48 d1 fe             	sar    %rsi
    10d6:	74 18                	je     10f0 <register_tm_clones+0x40>
    10d8:	48 8b 05 11 2f 00 00 	mov    0x2f11(%rip),%rax        # 3ff0 <_ITM_registerTMCloneTable>
    10df:	48 85 c0             	test   %rax,%rax
    10e2:	74 0c                	je     10f0 <register_tm_clones+0x40>
    10e4:	5d                   	pop    %rbp
    10e5:	ff e0                	jmpq   *%rax
    10e7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    10ee:	00 00 
    10f0:	5d                   	pop    %rbp
    10f1:	c3                   	retq   
    10f2:	0f 1f 40 00          	nopl   0x0(%rax)
    10f6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    10fd:	00 00 00 

0000000000001100 <__do_global_dtors_aux>:
    1100:	80 3d 09 2f 00 00 00 	cmpb   $0x0,0x2f09(%rip)        # 4010 <__TMC_END__>
    1107:	75 2f                	jne    1138 <__do_global_dtors_aux+0x38>
    1109:	48 83 3d e7 2e 00 00 	cmpq   $0x0,0x2ee7(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1110:	00 
    1111:	55                   	push   %rbp
    1112:	48 89 e5             	mov    %rsp,%rbp
    1115:	74 0c                	je     1123 <__do_global_dtors_aux+0x23>
    1117:	48 8b 3d ea 2e 00 00 	mov    0x2eea(%rip),%rdi        # 4008 <__dso_handle>
    111e:	e8 0d ff ff ff       	callq  1030 <__cxa_finalize@plt>
    1123:	e8 48 ff ff ff       	callq  1070 <deregister_tm_clones>
    1128:	c6 05 e1 2e 00 00 01 	movb   $0x1,0x2ee1(%rip)        # 4010 <__TMC_END__>
    112f:	5d                   	pop    %rbp
    1130:	c3                   	retq   
    1131:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    1138:	f3 c3                	repz retq 
    113a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000001140 <frame_dummy>:
    1140:	55                   	push   %rbp
    1141:	48 89 e5             	mov    %rsp,%rbp
    1144:	5d                   	pop    %rbp
    1145:	e9 66 ff ff ff       	jmpq   10b0 <register_tm_clones>

000000000000114a <main>:
extern void asm_call();
int main() {
    114a:	55                   	push   %rbp
    114b:	48 89 e5             	mov    %rsp,%rbp
	asm_call();
    114e:	b8 00 00 00 00       	mov    $0x0,%eax
    1153:	e8 07 00 00 00       	callq  115f <asm_call>
    1158:	b8 00 00 00 00       	mov    $0x0,%eax
}
    115d:	5d                   	pop    %rbp
    115e:	c3                   	retq   

000000000000115f <asm_call>:
	.globl asm_call
	.type asm_call,@function 
asm_call:
	rdrand %rcx  
    115f:	48 0f c7 f1          	rdrand %rcx
    1163:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    116a:	00 00 00 
    116d:	0f 1f 00             	nopl   (%rax)

0000000000001170 <__libc_csu_init>:
    1170:	41 57                	push   %r15
    1172:	41 56                	push   %r14
    1174:	49 89 d7             	mov    %rdx,%r15
    1177:	41 55                	push   %r13
    1179:	41 54                	push   %r12
    117b:	4c 8d 25 6e 2c 00 00 	lea    0x2c6e(%rip),%r12        # 3df0 <__frame_dummy_init_array_entry>
    1182:	55                   	push   %rbp
    1183:	48 8d 2d 6e 2c 00 00 	lea    0x2c6e(%rip),%rbp        # 3df8 <__init_array_end>
    118a:	53                   	push   %rbx
    118b:	41 89 fd             	mov    %edi,%r13d
    118e:	49 89 f6             	mov    %rsi,%r14
    1191:	4c 29 e5             	sub    %r12,%rbp
    1194:	48 83 ec 08          	sub    $0x8,%rsp
    1198:	48 c1 fd 03          	sar    $0x3,%rbp
    119c:	e8 5f fe ff ff       	callq  1000 <_init>
    11a1:	48 85 ed             	test   %rbp,%rbp
    11a4:	74 20                	je     11c6 <__libc_csu_init+0x56>
    11a6:	31 db                	xor    %ebx,%ebx
    11a8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    11af:	00 
    11b0:	4c 89 fa             	mov    %r15,%rdx
    11b3:	4c 89 f6             	mov    %r14,%rsi
    11b6:	44 89 ef             	mov    %r13d,%edi
    11b9:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
    11bd:	48 83 c3 01          	add    $0x1,%rbx
    11c1:	48 39 dd             	cmp    %rbx,%rbp
    11c4:	75 ea                	jne    11b0 <__libc_csu_init+0x40>
    11c6:	48 83 c4 08          	add    $0x8,%rsp
    11ca:	5b                   	pop    %rbx
    11cb:	5d                   	pop    %rbp
    11cc:	41 5c                	pop    %r12
    11ce:	41 5d                	pop    %r13
    11d0:	41 5e                	pop    %r14
    11d2:	41 5f                	pop    %r15
    11d4:	c3                   	retq   
    11d5:	90                   	nop
    11d6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    11dd:	00 00 00 

00000000000011e0 <__libc_csu_fini>:
    11e0:	f3 c3                	repz retq 

Disassembly of section .fini:

00000000000011e4 <_fini>:
    11e4:	48 83 ec 08          	sub    $0x8,%rsp
    11e8:	48 83 c4 08          	add    $0x8,%rsp
    11ec:	c3                   	retq   
