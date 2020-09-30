
./a.out:     file format elf64-x86-64


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
    1020:	ff 35 8a 2f 00 00    	pushq  0x2f8a(%rip)        # 3fb0 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	ff 25 8c 2f 00 00    	jmpq   *0x2f8c(%rip)        # 3fb8 <_GLOBAL_OFFSET_TABLE_+0x10>
    102c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000001030 <__stack_chk_fail@plt>:
    1030:	ff 25 8a 2f 00 00    	jmpq   *0x2f8a(%rip)        # 3fc0 <__stack_chk_fail@GLIBC_2.4>
    1036:	68 00 00 00 00       	pushq  $0x0
    103b:	e9 e0 ff ff ff       	jmpq   1020 <.plt>

0000000000001040 <printf@plt>:
    1040:	ff 25 82 2f 00 00    	jmpq   *0x2f82(%rip)        # 3fc8 <printf@GLIBC_2.2.5>
    1046:	68 01 00 00 00       	pushq  $0x1
    104b:	e9 d0 ff ff ff       	jmpq   1020 <.plt>

0000000000001050 <__assert_fail@plt>:
    1050:	ff 25 7a 2f 00 00    	jmpq   *0x2f7a(%rip)        # 3fd0 <__assert_fail@GLIBC_2.2.5>
    1056:	68 02 00 00 00       	pushq  $0x2
    105b:	e9 c0 ff ff ff       	jmpq   1020 <.plt>

Disassembly of section .plt.got:

0000000000001060 <__cxa_finalize@plt>:
    1060:	ff 25 92 2f 00 00    	jmpq   *0x2f92(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1066:	66 90                	xchg   %ax,%ax

Disassembly of section .text:

0000000000001070 <_start>:
    1070:	31 ed                	xor    %ebp,%ebp
    1072:	49 89 d1             	mov    %rdx,%r9
    1075:	5e                   	pop    %rsi
    1076:	48 89 e2             	mov    %rsp,%rdx
    1079:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    107d:	50                   	push   %rax
    107e:	54                   	push   %rsp
    107f:	4c 8d 05 4a 03 00 00 	lea    0x34a(%rip),%r8        # 13d0 <__libc_csu_fini>
    1086:	48 8d 0d d3 02 00 00 	lea    0x2d3(%rip),%rcx        # 1360 <__libc_csu_init>
    108d:	48 8d 3d 45 02 00 00 	lea    0x245(%rip),%rdi        # 12d9 <main>
    1094:	ff 15 46 2f 00 00    	callq  *0x2f46(%rip)        # 3fe0 <__libc_start_main@GLIBC_2.2.5>
    109a:	f4                   	hlt    
    109b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000010a0 <deregister_tm_clones>:
    10a0:	48 8d 3d 69 2f 00 00 	lea    0x2f69(%rip),%rdi        # 4010 <__TMC_END__>
    10a7:	55                   	push   %rbp
    10a8:	48 8d 05 61 2f 00 00 	lea    0x2f61(%rip),%rax        # 4010 <__TMC_END__>
    10af:	48 39 f8             	cmp    %rdi,%rax
    10b2:	48 89 e5             	mov    %rsp,%rbp
    10b5:	74 19                	je     10d0 <deregister_tm_clones+0x30>
    10b7:	48 8b 05 1a 2f 00 00 	mov    0x2f1a(%rip),%rax        # 3fd8 <_ITM_deregisterTMCloneTable>
    10be:	48 85 c0             	test   %rax,%rax
    10c1:	74 0d                	je     10d0 <deregister_tm_clones+0x30>
    10c3:	5d                   	pop    %rbp
    10c4:	ff e0                	jmpq   *%rax
    10c6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    10cd:	00 00 00 
    10d0:	5d                   	pop    %rbp
    10d1:	c3                   	retq   
    10d2:	0f 1f 40 00          	nopl   0x0(%rax)
    10d6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    10dd:	00 00 00 

00000000000010e0 <register_tm_clones>:
    10e0:	48 8d 3d 29 2f 00 00 	lea    0x2f29(%rip),%rdi        # 4010 <__TMC_END__>
    10e7:	48 8d 35 22 2f 00 00 	lea    0x2f22(%rip),%rsi        # 4010 <__TMC_END__>
    10ee:	55                   	push   %rbp
    10ef:	48 29 fe             	sub    %rdi,%rsi
    10f2:	48 89 e5             	mov    %rsp,%rbp
    10f5:	48 c1 fe 03          	sar    $0x3,%rsi
    10f9:	48 89 f0             	mov    %rsi,%rax
    10fc:	48 c1 e8 3f          	shr    $0x3f,%rax
    1100:	48 01 c6             	add    %rax,%rsi
    1103:	48 d1 fe             	sar    %rsi
    1106:	74 18                	je     1120 <register_tm_clones+0x40>
    1108:	48 8b 05 e1 2e 00 00 	mov    0x2ee1(%rip),%rax        # 3ff0 <_ITM_registerTMCloneTable>
    110f:	48 85 c0             	test   %rax,%rax
    1112:	74 0c                	je     1120 <register_tm_clones+0x40>
    1114:	5d                   	pop    %rbp
    1115:	ff e0                	jmpq   *%rax
    1117:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    111e:	00 00 
    1120:	5d                   	pop    %rbp
    1121:	c3                   	retq   
    1122:	0f 1f 40 00          	nopl   0x0(%rax)
    1126:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    112d:	00 00 00 

0000000000001130 <__do_global_dtors_aux>:
    1130:	80 3d d9 2e 00 00 00 	cmpb   $0x0,0x2ed9(%rip)        # 4010 <__TMC_END__>
    1137:	75 2f                	jne    1168 <__do_global_dtors_aux+0x38>
    1139:	48 83 3d b7 2e 00 00 	cmpq   $0x0,0x2eb7(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1140:	00 
    1141:	55                   	push   %rbp
    1142:	48 89 e5             	mov    %rsp,%rbp
    1145:	74 0c                	je     1153 <__do_global_dtors_aux+0x23>
    1147:	48 8b 3d ba 2e 00 00 	mov    0x2eba(%rip),%rdi        # 4008 <__dso_handle>
    114e:	e8 0d ff ff ff       	callq  1060 <__cxa_finalize@plt>
    1153:	e8 48 ff ff ff       	callq  10a0 <deregister_tm_clones>
    1158:	c6 05 b1 2e 00 00 01 	movb   $0x1,0x2eb1(%rip)        # 4010 <__TMC_END__>
    115f:	5d                   	pop    %rbp
    1160:	c3                   	retq   
    1161:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    1168:	f3 c3                	repz retq 
    116a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000001170 <frame_dummy>:
    1170:	55                   	push   %rbp
    1171:	48 89 e5             	mov    %rsp,%rbp
    1174:	5d                   	pop    %rbp
    1175:	e9 66 ff ff ff       	jmpq   10e0 <register_tm_clones>

000000000000117a <_Z14ecall_array_inPi>:
    117a:	55                   	push   %rbp
    117b:	48 89 e5             	mov    %rsp,%rbp
    117e:	48 83 ec 20          	sub    $0x20,%rsp
    1182:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    1186:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    118d:	83 7d fc 03          	cmpl   $0x3,-0x4(%rbp)
    1191:	0f 8f 8d 00 00 00    	jg     1224 <_Z14ecall_array_inPi+0xaa>
    1197:	8b 45 fc             	mov    -0x4(%rbp),%eax
    119a:	48 98                	cltq   
    119c:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
    11a3:	00 
    11a4:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    11a8:	48 01 d0             	add    %rdx,%rax
    11ab:	8b 10                	mov    (%rax),%edx
    11ad:	8b 45 fc             	mov    -0x4(%rbp),%eax
    11b0:	89 c6                	mov    %eax,%esi
    11b2:	48 8d 3d 57 0e 00 00 	lea    0xe57(%rip),%rdi        # 2010 <_IO_stdin_used+0x10>
    11b9:	b8 00 00 00 00       	mov    $0x0,%eax
    11be:	e8 7d fe ff ff       	callq  1040 <printf@plt>
    11c3:	8b 45 fc             	mov    -0x4(%rbp),%eax
    11c6:	48 98                	cltq   
    11c8:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
    11cf:	00 
    11d0:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    11d4:	48 01 d0             	add    %rdx,%rax
    11d7:	8b 00                	mov    (%rax),%eax
    11d9:	39 45 fc             	cmp    %eax,-0x4(%rbp)
    11dc:	74 1f                	je     11fd <_Z14ecall_array_inPi+0x83>
    11de:	48 8d 0d 8b 0e 00 00 	lea    0xe8b(%rip),%rcx        # 2070 <_ZZ14ecall_array_inPiE19__PRETTY_FUNCTION__>
    11e5:	ba 0b 00 00 00       	mov    $0xb,%edx
    11ea:	48 8d 35 37 0e 00 00 	lea    0xe37(%rip),%rsi        # 2028 <_IO_stdin_used+0x28>
    11f1:	48 8d 3d 3a 0e 00 00 	lea    0xe3a(%rip),%rdi        # 2032 <_IO_stdin_used+0x32>
    11f8:	e8 53 fe ff ff       	callq  1050 <__assert_fail@plt>
    11fd:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1200:	48 98                	cltq   
    1202:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
    1209:	00 
    120a:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    120e:	48 01 c2             	add    %rax,%rdx
    1211:	b8 03 00 00 00       	mov    $0x3,%eax
    1216:	2b 45 fc             	sub    -0x4(%rbp),%eax
    1219:	89 02                	mov    %eax,(%rdx)
    121b:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    121f:	e9 69 ff ff ff       	jmpq   118d <_Z14ecall_array_inPi+0x13>
    1224:	90                   	nop
    1225:	c9                   	leaveq 
    1226:	c3                   	retq   

0000000000001227 <_Z12almost_equalff>:
    1227:	55                   	push   %rbp
    1228:	48 89 e5             	mov    %rsp,%rbp
    122b:	48 83 ec 10          	sub    $0x10,%rsp
    122f:	f3 0f 11 45 fc       	movss  %xmm0,-0x4(%rbp)
    1234:	f3 0f 11 4d f8       	movss  %xmm1,-0x8(%rbp)
    1239:	f3 0f 10 45 fc       	movss  -0x4(%rbp),%xmm0
    123e:	f3 0f 5c 45 f8       	subss  -0x8(%rbp),%xmm0
    1243:	e8 eb 00 00 00       	callq  1333 <_ZSt3absf>
    1248:	f3 0f 11 45 f4       	movss  %xmm0,-0xc(%rbp)
    124d:	e8 fc 00 00 00       	callq  134e <_ZNSt14numeric_limitsIfE7epsilonEv>
    1252:	f3 0f 11 45 f0       	movss  %xmm0,-0x10(%rbp)
    1257:	f3 0f 10 45 fc       	movss  -0x4(%rbp),%xmm0
    125c:	f3 0f 58 45 f8       	addss  -0x8(%rbp),%xmm0
    1261:	e8 cd 00 00 00       	callq  1333 <_ZSt3absf>
    1266:	f3 0f 59 45 f0       	mulss  -0x10(%rbp),%xmm0
    126b:	f3 0f 58 c0          	addss  %xmm0,%xmm0
    126f:	0f 2e 45 f4          	ucomiss -0xc(%rbp),%xmm0
    1273:	0f 93 c0             	setae  %al
    1276:	c9                   	leaveq 
    1277:	c3                   	retq   

0000000000001278 <_Z16ecall_type_floatf>:
    1278:	55                   	push   %rbp
    1279:	48 89 e5             	mov    %rsp,%rbp
    127c:	48 83 ec 10          	sub    $0x10,%rsp
    1280:	f3 0f 11 45 fc       	movss  %xmm0,-0x4(%rbp)
    1285:	f3 0f 5a 45 fc       	cvtss2sd -0x4(%rbp),%xmm0
    128a:	48 8d 3d ad 0d 00 00 	lea    0xdad(%rip),%rdi        # 203e <_IO_stdin_used+0x3e>
    1291:	b8 01 00 00 00       	mov    $0x1,%eax
    1296:	e8 a5 fd ff ff       	callq  1040 <printf@plt>
    129b:	8b 45 fc             	mov    -0x4(%rbp),%eax
    129e:	f3 0f 10 0d 1e 0e 00 	movss  0xe1e(%rip),%xmm1        # 20c4 <_ZZ16ecall_type_floatfE19__PRETTY_FUNCTION__+0x34>
    12a5:	00 
    12a6:	89 45 f8             	mov    %eax,-0x8(%rbp)
    12a9:	f3 0f 10 45 f8       	movss  -0x8(%rbp),%xmm0
    12ae:	e8 74 ff ff ff       	callq  1227 <_Z12almost_equalff>
    12b3:	84 c0                	test   %al,%al
    12b5:	75 1f                	jne    12d6 <_Z16ecall_type_floatf+0x5e>
    12b7:	48 8d 0d d2 0d 00 00 	lea    0xdd2(%rip),%rcx        # 2090 <_ZZ16ecall_type_floatfE19__PRETTY_FUNCTION__>
    12be:	ba 1b 00 00 00       	mov    $0x1b,%edx
    12c3:	48 8d 35 5e 0d 00 00 	lea    0xd5e(%rip),%rsi        # 2028 <_IO_stdin_used+0x28>
    12ca:	48 8d 3d 77 0d 00 00 	lea    0xd77(%rip),%rdi        # 2048 <_IO_stdin_used+0x48>
    12d1:	e8 7a fd ff ff       	callq  1050 <__assert_fail@plt>
    12d6:	90                   	nop
    12d7:	c9                   	leaveq 
    12d8:	c3                   	retq   

00000000000012d9 <main>:
    12d9:	55                   	push   %rbp
    12da:	48 89 e5             	mov    %rsp,%rbp
    12dd:	48 83 ec 20          	sub    $0x20,%rsp
    12e1:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    12e8:	00 00 
    12ea:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    12ee:	31 c0                	xor    %eax,%eax
    12f0:	c7 45 e0 00 00 00 00 	movl   $0x0,-0x20(%rbp)
    12f7:	c7 45 e4 01 00 00 00 	movl   $0x1,-0x1c(%rbp)
    12fe:	c7 45 e8 02 00 00 00 	movl   $0x2,-0x18(%rbp)
    1305:	c7 45 ec 03 00 00 00 	movl   $0x3,-0x14(%rbp)
    130c:	48 8d 45 e0          	lea    -0x20(%rbp),%rax
    1310:	48 89 c7             	mov    %rax,%rdi
    1313:	e8 62 fe ff ff       	callq  117a <_Z14ecall_array_inPi>
    1318:	b8 00 00 00 00       	mov    $0x0,%eax
    131d:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    1321:	64 48 33 14 25 28 00 	xor    %fs:0x28,%rdx
    1328:	00 00 
    132a:	74 05                	je     1331 <main+0x58>
    132c:	e8 ff fc ff ff       	callq  1030 <__stack_chk_fail@plt>
    1331:	c9                   	leaveq 
    1332:	c3                   	retq   

0000000000001333 <_ZSt3absf>:
    1333:	55                   	push   %rbp
    1334:	48 89 e5             	mov    %rsp,%rbp
    1337:	f3 0f 11 45 fc       	movss  %xmm0,-0x4(%rbp)
    133c:	f3 0f 10 4d fc       	movss  -0x4(%rbp),%xmm1
    1341:	f3 0f 10 05 67 0d 00 	movss  0xd67(%rip),%xmm0        # 20b0 <_ZZ16ecall_type_floatfE19__PRETTY_FUNCTION__+0x20>
    1348:	00 
    1349:	0f 54 c1             	andps  %xmm1,%xmm0
    134c:	5d                   	pop    %rbp
    134d:	c3                   	retq   

000000000000134e <_ZNSt14numeric_limitsIfE7epsilonEv>:
    134e:	55                   	push   %rbp
    134f:	48 89 e5             	mov    %rsp,%rbp
    1352:	f3 0f 10 05 66 0d 00 	movss  0xd66(%rip),%xmm0        # 20c0 <_ZZ16ecall_type_floatfE19__PRETTY_FUNCTION__+0x30>
    1359:	00 
    135a:	5d                   	pop    %rbp
    135b:	c3                   	retq   
    135c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000001360 <__libc_csu_init>:
    1360:	41 57                	push   %r15
    1362:	41 56                	push   %r14
    1364:	49 89 d7             	mov    %rdx,%r15
    1367:	41 55                	push   %r13
    1369:	41 54                	push   %r12
    136b:	4c 8d 25 36 2a 00 00 	lea    0x2a36(%rip),%r12        # 3da8 <__frame_dummy_init_array_entry>
    1372:	55                   	push   %rbp
    1373:	48 8d 2d 36 2a 00 00 	lea    0x2a36(%rip),%rbp        # 3db0 <__init_array_end>
    137a:	53                   	push   %rbx
    137b:	41 89 fd             	mov    %edi,%r13d
    137e:	49 89 f6             	mov    %rsi,%r14
    1381:	4c 29 e5             	sub    %r12,%rbp
    1384:	48 83 ec 08          	sub    $0x8,%rsp
    1388:	48 c1 fd 03          	sar    $0x3,%rbp
    138c:	e8 6f fc ff ff       	callq  1000 <_init>
    1391:	48 85 ed             	test   %rbp,%rbp
    1394:	74 20                	je     13b6 <__libc_csu_init+0x56>
    1396:	31 db                	xor    %ebx,%ebx
    1398:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    139f:	00 
    13a0:	4c 89 fa             	mov    %r15,%rdx
    13a3:	4c 89 f6             	mov    %r14,%rsi
    13a6:	44 89 ef             	mov    %r13d,%edi
    13a9:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
    13ad:	48 83 c3 01          	add    $0x1,%rbx
    13b1:	48 39 dd             	cmp    %rbx,%rbp
    13b4:	75 ea                	jne    13a0 <__libc_csu_init+0x40>
    13b6:	48 83 c4 08          	add    $0x8,%rsp
    13ba:	5b                   	pop    %rbx
    13bb:	5d                   	pop    %rbp
    13bc:	41 5c                	pop    %r12
    13be:	41 5d                	pop    %r13
    13c0:	41 5e                	pop    %r14
    13c2:	41 5f                	pop    %r15
    13c4:	c3                   	retq   
    13c5:	90                   	nop
    13c6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    13cd:	00 00 00 

00000000000013d0 <__libc_csu_fini>:
    13d0:	f3 c3                	repz retq 

Disassembly of section .fini:

00000000000013d4 <_fini>:
    13d4:	48 83 ec 08          	sub    $0x8,%rsp
    13d8:	48 83 c4 08          	add    $0x8,%rsp
    13dc:	c3                   	retq   
