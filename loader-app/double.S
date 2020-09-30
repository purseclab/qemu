
./a.out:     file format elf64-x86-64


Disassembly of section .interp:

00000000000002a8 <.interp>:
 2a8:	2f                   	(bad)  
 2a9:	6c                   	insb   (%dx),%es:(%rdi)
 2aa:	69 62 36 34 2f 6c 64 	imul   $0x646c2f34,0x36(%rdx),%esp
 2b1:	2d 6c 69 6e 75       	sub    $0x756e696c,%eax
 2b6:	78 2d                	js     2e5 <_init-0xd1b>
 2b8:	78 38                	js     2f2 <_init-0xd0e>
 2ba:	36 2d 36 34 2e 73    	ss sub $0x732e3436,%eax
 2c0:	6f                   	outsl  %ds:(%rsi),(%dx)
 2c1:	2e 32 00             	xor    %cs:(%rax),%al

Disassembly of section .note.gnu.build-id:

00000000000002c4 <.note.gnu.build-id>:
 2c4:	04 00                	add    $0x0,%al
 2c6:	00 00                	add    %al,(%rax)
 2c8:	14 00                	adc    $0x0,%al
 2ca:	00 00                	add    %al,(%rax)
 2cc:	03 00                	add    (%rax),%eax
 2ce:	00 00                	add    %al,(%rax)
 2d0:	47                   	rex.RXB
 2d1:	4e 55                	rex.WRX push %rbp
 2d3:	00 72 af             	add    %dh,-0x51(%rdx)
 2d6:	89 cc                	mov    %ecx,%esp
 2d8:	b6 f4                	mov    $0xf4,%dh
 2da:	5e                   	pop    %rsi
 2db:	5f                   	pop    %rdi
 2dc:	cd c8                	int    $0xc8
 2de:	08 dd                	or     %bl,%ch
 2e0:	57                   	push   %rdi
 2e1:	65 67 47 fe          	gs addr32 rex.RXB (bad) 
 2e5:	67 b1 91             	addr32 mov $0x91,%cl

Disassembly of section .note.ABI-tag:

00000000000002e8 <.note.ABI-tag>:
 2e8:	04 00                	add    $0x0,%al
 2ea:	00 00                	add    %al,(%rax)
 2ec:	10 00                	adc    %al,(%rax)
 2ee:	00 00                	add    %al,(%rax)
 2f0:	01 00                	add    %eax,(%rax)
 2f2:	00 00                	add    %al,(%rax)
 2f4:	47                   	rex.RXB
 2f5:	4e 55                	rex.WRX push %rbp
 2f7:	00 00                	add    %al,(%rax)
 2f9:	00 00                	add    %al,(%rax)
 2fb:	00 03                	add    %al,(%rbx)
 2fd:	00 00                	add    %al,(%rax)
 2ff:	00 02                	add    %al,(%rdx)
 301:	00 00                	add    %al,(%rax)
 303:	00 00                	add    %al,(%rax)
 305:	00 00                	add    %al,(%rax)
	...

Disassembly of section .gnu.hash:

0000000000000308 <.gnu.hash>:
 308:	02 00                	add    (%rax),%al
 30a:	00 00                	add    %al,(%rax)
 30c:	08 00                	or     %al,(%rax)
 30e:	00 00                	add    %al,(%rax)
 310:	01 00                	add    %eax,(%rax)
 312:	00 00                	add    %al,(%rax)
 314:	06                   	(bad)  
 315:	00 00                	add    %al,(%rax)
 317:	00 00                	add    %al,(%rax)
 319:	00 81 00 00 00 00    	add    %al,0x0(%rcx)
 31f:	00 08                	add    %cl,(%rax)
 321:	00 00                	add    %al,(%rax)
 323:	00 00                	add    %al,(%rax)
 325:	00 00                	add    %al,(%rax)
 327:	00 d1                	add    %dl,%cl
 329:	65 ce                	gs (bad) 
 32b:	6d                   	insl   (%dx),%es:(%rdi)

Disassembly of section .dynsym:

0000000000000330 <.dynsym>:
	...
 348:	68 00 00 00 20       	pushq  $0x20000000
	...
 35d:	00 00                	add    %al,(%rax)
 35f:	00 0b                	add    %cl,(%rbx)
 361:	00 00                	add    %al,(%rax)
 363:	00 12                	add    %dl,(%rdx)
	...
 375:	00 00                	add    %al,(%rax)
 377:	00 2a                	add    %ch,(%rdx)
 379:	00 00                	add    %al,(%rax)
 37b:	00 12                	add    %dl,(%rdx)
	...
 38d:	00 00                	add    %al,(%rax)
 38f:	00 1c 00             	add    %bl,(%rax,%rax,1)
 392:	00 00                	add    %al,(%rax)
 394:	12 00                	adc    (%rax),%al
	...
 3a6:	00 00                	add    %al,(%rax)
 3a8:	40 00 00             	add    %al,(%rax)
 3ab:	00 12                	add    %dl,(%rdx)
	...
 3bd:	00 00                	add    %al,(%rax)
 3bf:	00 84 00 00 00 20 00 	add    %al,0x200000(%rax,%rax,1)
	...
 3d6:	00 00                	add    %al,(%rax)
 3d8:	93                   	xchg   %eax,%ebx
 3d9:	00 00                	add    %al,(%rax)
 3db:	00 20                	add    %ah,(%rax)
	...
 3ed:	00 00                	add    %al,(%rax)
 3ef:	00 31                	add    %dh,(%rcx)
 3f1:	00 00                	add    %al,(%rax)
 3f3:	00 22                	add    %ah,(%rdx)
	...

Disassembly of section .dynstr:

0000000000000408 <.dynstr>:
 408:	00 6c 69 62          	add    %ch,0x62(%rcx,%rbp,2)
 40c:	63 2e                	movslq (%rsi),%ebp
 40e:	73 6f                	jae    47f <_init-0xb81>
 410:	2e 36 00 5f 5f       	cs add %bl,%ss:0x5f(%rdi)
 415:	73 74                	jae    48b <_init-0xb75>
 417:	61                   	(bad)  
 418:	63 6b 5f             	movslq 0x5f(%rbx),%ebp
 41b:	63 68 6b             	movslq 0x6b(%rax),%ebp
 41e:	5f                   	pop    %rdi
 41f:	66 61                	data16 (bad) 
 421:	69 6c 00 5f 5f 61 73 	imul   $0x7373615f,0x5f(%rax,%rax,1),%ebp
 428:	73 
 429:	65 72 74             	gs jb  4a0 <_init-0xb60>
 42c:	5f                   	pop    %rdi
 42d:	66 61                	data16 (bad) 
 42f:	69 6c 00 70 72 69 6e 	imul   $0x746e6972,0x70(%rax,%rax,1),%ebp
 436:	74 
 437:	66 00 5f 5f          	data16 add %bl,0x5f(%rdi)
 43b:	63 78 61             	movslq 0x61(%rax),%edi
 43e:	5f                   	pop    %rdi
 43f:	66 69 6e 61 6c 69    	imul   $0x696c,0x61(%rsi),%bp
 445:	7a 65                	jp     4ac <_init-0xb54>
 447:	00 5f 5f             	add    %bl,0x5f(%rdi)
 44a:	6c                   	insb   (%dx),%es:(%rdi)
 44b:	69 62 63 5f 73 74 61 	imul   $0x6174735f,0x63(%rdx),%esp
 452:	72 74                	jb     4c8 <_init-0xb38>
 454:	5f                   	pop    %rdi
 455:	6d                   	insl   (%dx),%es:(%rdi)
 456:	61                   	(bad)  
 457:	69 6e 00 47 4c 49 42 	imul   $0x42494c47,0x0(%rsi),%ebp
 45e:	43 5f                	rex.XB pop %r15
 460:	32 2e                	xor    (%rsi),%ch
 462:	32 2e                	xor    (%rsi),%ch
 464:	35 00 47 4c 49       	xor    $0x494c4700,%eax
 469:	42                   	rex.X
 46a:	43 5f                	rex.XB pop %r15
 46c:	32 2e                	xor    (%rsi),%ch
 46e:	34 00                	xor    $0x0,%al
 470:	5f                   	pop    %rdi
 471:	49 54                	rex.WB push %r12
 473:	4d 5f                	rex.WRB pop %r15
 475:	64 65 72 65          	fs gs jb 4de <_init-0xb22>
 479:	67 69 73 74 65 72 54 	imul   $0x4d547265,0x74(%ebx),%esi
 480:	4d 
 481:	43 6c                	rex.XB insb (%dx),%es:(%rdi)
 483:	6f                   	outsl  %ds:(%rsi),(%dx)
 484:	6e                   	outsb  %ds:(%rsi),(%dx)
 485:	65 54                	gs push %rsp
 487:	61                   	(bad)  
 488:	62                   	(bad)  
 489:	6c                   	insb   (%dx),%es:(%rdi)
 48a:	65 00 5f 5f          	add    %bl,%gs:0x5f(%rdi)
 48e:	67 6d                	insl   (%dx),%es:(%edi)
 490:	6f                   	outsl  %ds:(%rsi),(%dx)
 491:	6e                   	outsb  %ds:(%rsi),(%dx)
 492:	5f                   	pop    %rdi
 493:	73 74                	jae    509 <_init-0xaf7>
 495:	61                   	(bad)  
 496:	72 74                	jb     50c <_init-0xaf4>
 498:	5f                   	pop    %rdi
 499:	5f                   	pop    %rdi
 49a:	00 5f 49             	add    %bl,0x49(%rdi)
 49d:	54                   	push   %rsp
 49e:	4d 5f                	rex.WRB pop %r15
 4a0:	72 65                	jb     507 <_init-0xaf9>
 4a2:	67 69 73 74 65 72 54 	imul   $0x4d547265,0x74(%ebx),%esi
 4a9:	4d 
 4aa:	43 6c                	rex.XB insb (%dx),%es:(%rdi)
 4ac:	6f                   	outsl  %ds:(%rsi),(%dx)
 4ad:	6e                   	outsb  %ds:(%rsi),(%dx)
 4ae:	65 54                	gs push %rsp
 4b0:	61                   	(bad)  
 4b1:	62                   	.byte 0x62
 4b2:	6c                   	insb   (%dx),%es:(%rdi)
 4b3:	65                   	gs
	...

Disassembly of section .gnu.version:

00000000000004b6 <.gnu.version>:
 4b6:	00 00                	add    %al,(%rax)
 4b8:	00 00                	add    %al,(%rax)
 4ba:	02 00                	add    (%rax),%al
 4bc:	03 00                	add    (%rax),%eax
 4be:	03 00                	add    (%rax),%eax
 4c0:	03 00                	add    (%rax),%eax
 4c2:	00 00                	add    %al,(%rax)
 4c4:	00 00                	add    %al,(%rax)
 4c6:	03 00                	add    (%rax),%eax

Disassembly of section .gnu.version_r:

00000000000004c8 <.gnu.version_r>:
 4c8:	01 00                	add    %eax,(%rax)
 4ca:	02 00                	add    (%rax),%al
 4cc:	01 00                	add    %eax,(%rax)
 4ce:	00 00                	add    %al,(%rax)
 4d0:	10 00                	adc    %al,(%rax)
 4d2:	00 00                	add    %al,(%rax)
 4d4:	00 00                	add    %al,(%rax)
 4d6:	00 00                	add    %al,(%rax)
 4d8:	75 1a                	jne    4f4 <_init-0xb0c>
 4da:	69 09 00 00 03 00    	imul   $0x30000,(%rcx),%ecx
 4e0:	52                   	push   %rdx
 4e1:	00 00                	add    %al,(%rax)
 4e3:	00 10                	add    %dl,(%rax)
 4e5:	00 00                	add    %al,(%rax)
 4e7:	00 14 69             	add    %dl,(%rcx,%rbp,2)
 4ea:	69 0d 00 00 02 00 5e 	imul   $0x5e,0x20000(%rip),%ecx        # 204f4 <_end+0x1c4dc>
 4f1:	00 00 00 
 4f4:	00 00                	add    %al,(%rax)
	...

Disassembly of section .rela.dyn:

00000000000004f8 <.rela.dyn>:
 4f8:	a8 3d                	test   $0x3d,%al
 4fa:	00 00                	add    %al,(%rax)
 4fc:	00 00                	add    %al,(%rax)
 4fe:	00 00                	add    %al,(%rax)
 500:	08 00                	or     %al,(%rax)
 502:	00 00                	add    %al,(%rax)
 504:	00 00                	add    %al,(%rax)
 506:	00 00                	add    %al,(%rax)
 508:	70 11                	jo     51b <_init-0xae5>
 50a:	00 00                	add    %al,(%rax)
 50c:	00 00                	add    %al,(%rax)
 50e:	00 00                	add    %al,(%rax)
 510:	b0 3d                	mov    $0x3d,%al
 512:	00 00                	add    %al,(%rax)
 514:	00 00                	add    %al,(%rax)
 516:	00 00                	add    %al,(%rax)
 518:	08 00                	or     %al,(%rax)
 51a:	00 00                	add    %al,(%rax)
 51c:	00 00                	add    %al,(%rax)
 51e:	00 00                	add    %al,(%rax)
 520:	30 11                	xor    %dl,(%rcx)
 522:	00 00                	add    %al,(%rax)
 524:	00 00                	add    %al,(%rax)
 526:	00 00                	add    %al,(%rax)
 528:	08 40 00             	or     %al,0x0(%rax)
 52b:	00 00                	add    %al,(%rax)
 52d:	00 00                	add    %al,(%rax)
 52f:	00 08                	add    %cl,(%rax)
 531:	00 00                	add    %al,(%rax)
 533:	00 00                	add    %al,(%rax)
 535:	00 00                	add    %al,(%rax)
 537:	00 08                	add    %cl,(%rax)
 539:	40 00 00             	add    %al,(%rax)
 53c:	00 00                	add    %al,(%rax)
 53e:	00 00                	add    %al,(%rax)
 540:	d8 3f                	fdivrs (%rdi)
 542:	00 00                	add    %al,(%rax)
 544:	00 00                	add    %al,(%rax)
 546:	00 00                	add    %al,(%rax)
 548:	06                   	(bad)  
 549:	00 00                	add    %al,(%rax)
 54b:	00 01                	add    %al,(%rcx)
	...
 555:	00 00                	add    %al,(%rax)
 557:	00 e0                	add    %ah,%al
 559:	3f                   	(bad)  
 55a:	00 00                	add    %al,(%rax)
 55c:	00 00                	add    %al,(%rax)
 55e:	00 00                	add    %al,(%rax)
 560:	06                   	(bad)  
 561:	00 00                	add    %al,(%rax)
 563:	00 05 00 00 00 00    	add    %al,0x0(%rip)        # 569 <_init-0xa97>
 569:	00 00                	add    %al,(%rax)
 56b:	00 00                	add    %al,(%rax)
 56d:	00 00                	add    %al,(%rax)
 56f:	00 e8                	add    %ch,%al
 571:	3f                   	(bad)  
 572:	00 00                	add    %al,(%rax)
 574:	00 00                	add    %al,(%rax)
 576:	00 00                	add    %al,(%rax)
 578:	06                   	(bad)  
 579:	00 00                	add    %al,(%rax)
 57b:	00 06                	add    %al,(%rsi)
	...
 585:	00 00                	add    %al,(%rax)
 587:	00 f0                	add    %dh,%al
 589:	3f                   	(bad)  
 58a:	00 00                	add    %al,(%rax)
 58c:	00 00                	add    %al,(%rax)
 58e:	00 00                	add    %al,(%rax)
 590:	06                   	(bad)  
 591:	00 00                	add    %al,(%rax)
 593:	00 07                	add    %al,(%rdi)
	...
 59d:	00 00                	add    %al,(%rax)
 59f:	00 f8                	add    %bh,%al
 5a1:	3f                   	(bad)  
 5a2:	00 00                	add    %al,(%rax)
 5a4:	00 00                	add    %al,(%rax)
 5a6:	00 00                	add    %al,(%rax)
 5a8:	06                   	(bad)  
 5a9:	00 00                	add    %al,(%rax)
 5ab:	00 08                	add    %cl,(%rax)
	...

Disassembly of section .rela.plt:

00000000000005b8 <.rela.plt>:
 5b8:	c0 3f 00             	sarb   $0x0,(%rdi)
 5bb:	00 00                	add    %al,(%rax)
 5bd:	00 00                	add    %al,(%rax)
 5bf:	00 07                	add    %al,(%rdi)
 5c1:	00 00                	add    %al,(%rax)
 5c3:	00 02                	add    %al,(%rdx)
	...
 5cd:	00 00                	add    %al,(%rax)
 5cf:	00 c8                	add    %cl,%al
 5d1:	3f                   	(bad)  
 5d2:	00 00                	add    %al,(%rax)
 5d4:	00 00                	add    %al,(%rax)
 5d6:	00 00                	add    %al,(%rax)
 5d8:	07                   	(bad)  
 5d9:	00 00                	add    %al,(%rax)
 5db:	00 03                	add    %al,(%rbx)
	...
 5e5:	00 00                	add    %al,(%rax)
 5e7:	00 d0                	add    %dl,%al
 5e9:	3f                   	(bad)  
 5ea:	00 00                	add    %al,(%rax)
 5ec:	00 00                	add    %al,(%rax)
 5ee:	00 00                	add    %al,(%rax)
 5f0:	07                   	(bad)  
 5f1:	00 00                	add    %al,(%rax)
 5f3:	00 04 00             	add    %al,(%rax,%rax,1)
	...

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
    107f:	4c 8d 05 8a 03 00 00 	lea    0x38a(%rip),%r8        # 1410 <__libc_csu_fini>
    1086:	48 8d 0d 13 03 00 00 	lea    0x313(%rip),%rcx        # 13a0 <__libc_csu_init>
    108d:	48 8d 3d 72 02 00 00 	lea    0x272(%rip),%rdi        # 1306 <main>
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
    11f1:	48 8d 3d 3b 0e 00 00 	lea    0xe3b(%rip),%rdi        # 2033 <_IO_stdin_used+0x33>
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

0000000000001227 <_Z12almost_equaldd>:
    1227:	55                   	push   %rbp
    1228:	48 89 e5             	mov    %rsp,%rbp
    122b:	48 83 ec 20          	sub    $0x20,%rsp
    122f:	f2 0f 11 45 f8       	movsd  %xmm0,-0x8(%rbp)
    1234:	f2 0f 11 4d f0       	movsd  %xmm1,-0x10(%rbp)
    1239:	f2 0f 10 45 f8       	movsd  -0x8(%rbp),%xmm0
    123e:	f2 0f 5c 45 f0       	subsd  -0x10(%rbp),%xmm0
    1243:	e8 2d 01 00 00       	callq  1375 <_ZSt3absd>
    1248:	f2 0f 11 45 e8       	movsd  %xmm0,-0x18(%rbp)
    124d:	e8 3f 01 00 00       	callq  1391 <_ZNSt14numeric_limitsIdE7epsilonEv>
    1252:	f2 0f 11 45 e0       	movsd  %xmm0,-0x20(%rbp)
    1257:	f2 0f 10 45 f8       	movsd  -0x8(%rbp),%xmm0
    125c:	f2 0f 58 45 f0       	addsd  -0x10(%rbp),%xmm0
    1261:	e8 0f 01 00 00       	callq  1375 <_ZSt3absd>
    1266:	f2 0f 59 45 e0       	mulsd  -0x20(%rbp),%xmm0
    126b:	f2 0f 58 c0          	addsd  %xmm0,%xmm0
    126f:	66 0f 2e 45 e8       	ucomisd -0x18(%rbp),%xmm0
    1274:	0f 93 c0             	setae  %al
    1277:	c9                   	leaveq 
    1278:	c3                   	retq   

0000000000001279 <_Z17ecall_type_doubled>:
    1279:	55                   	push   %rbp
    127a:	48 89 e5             	mov    %rsp,%rbp
    127d:	48 83 ec 10          	sub    $0x10,%rsp
    1281:	f2 0f 11 45 f8       	movsd  %xmm0,-0x8(%rbp)
    1286:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    128a:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    128e:	f2 0f 10 45 f0       	movsd  -0x10(%rbp),%xmm0
    1293:	48 8d 3d a5 0d 00 00 	lea    0xda5(%rip),%rdi        # 203f <_IO_stdin_used+0x3f>
    129a:	b8 01 00 00 00       	mov    $0x1,%eax
    129f:	e8 9c fd ff ff       	callq  1040 <printf@plt>
    12a4:	f2 0f 10 05 1c 0e 00 	movsd  0xe1c(%rip),%xmm0        # 20c8 <_ZZ17ecall_type_doubledE19__PRETTY_FUNCTION__+0x38>
    12ab:	00 
    12ac:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    12b0:	66 0f 28 c8          	movapd %xmm0,%xmm1
    12b4:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    12b8:	f2 0f 10 45 f0       	movsd  -0x10(%rbp),%xmm0
    12bd:	e8 65 ff ff ff       	callq  1227 <_Z12almost_equaldd>
    12c2:	84 c0                	test   %al,%al
    12c4:	75 1f                	jne    12e5 <_Z17ecall_type_doubled+0x6c>
    12c6:	48 8d 0d c3 0d 00 00 	lea    0xdc3(%rip),%rcx        # 2090 <_ZZ17ecall_type_doubledE19__PRETTY_FUNCTION__>
    12cd:	ba 1b 00 00 00       	mov    $0x1b,%edx
    12d2:	48 8d 35 4f 0d 00 00 	lea    0xd4f(%rip),%rsi        # 2028 <_IO_stdin_used+0x28>
    12d9:	48 8d 3d 68 0d 00 00 	lea    0xd68(%rip),%rdi        # 2048 <_IO_stdin_used+0x48>
    12e0:	e8 6b fd ff ff       	callq  1050 <__assert_fail@plt>
    12e5:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    12e9:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    12ed:	f2 0f 10 45 f0       	movsd  -0x10(%rbp),%xmm0
    12f2:	48 8d 3d 46 0d 00 00 	lea    0xd46(%rip),%rdi        # 203f <_IO_stdin_used+0x3f>
    12f9:	b8 01 00 00 00       	mov    $0x1,%eax
    12fe:	e8 3d fd ff ff       	callq  1040 <printf@plt>
    1303:	90                   	nop
    1304:	c9                   	leaveq 
    1305:	c3                   	retq   

0000000000001306 <main>:
    1306:	55                   	push   %rbp
    1307:	48 89 e5             	mov    %rsp,%rbp
    130a:	48 83 ec 30          	sub    $0x30,%rsp
    130e:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    1315:	00 00 
    1317:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    131b:	31 c0                	xor    %eax,%eax
    131d:	c7 45 e0 00 00 00 00 	movl   $0x0,-0x20(%rbp)
    1324:	c7 45 e4 01 00 00 00 	movl   $0x1,-0x1c(%rbp)
    132b:	c7 45 e8 02 00 00 00 	movl   $0x2,-0x18(%rbp)
    1332:	c7 45 ec 03 00 00 00 	movl   $0x3,-0x14(%rbp)
    1339:	48 8d 45 e0          	lea    -0x20(%rbp),%rax
    133d:	48 89 c7             	mov    %rax,%rdi
    1340:	e8 35 fe ff ff       	callq  117a <_Z14ecall_array_inPi>
    1345:	48 8b 05 84 0d 00 00 	mov    0xd84(%rip),%rax        # 20d0 <_ZZ17ecall_type_doubledE19__PRETTY_FUNCTION__+0x40>
    134c:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    1350:	f2 0f 10 45 d8       	movsd  -0x28(%rbp),%xmm0
    1355:	e8 1f ff ff ff       	callq  1279 <_Z17ecall_type_doubled>
    135a:	b8 00 00 00 00       	mov    $0x0,%eax
    135f:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    1363:	64 48 33 14 25 28 00 	xor    %fs:0x28,%rdx
    136a:	00 00 
    136c:	74 05                	je     1373 <main+0x6d>
    136e:	e8 bd fc ff ff       	callq  1030 <__stack_chk_fail@plt>
    1373:	c9                   	leaveq 
    1374:	c3                   	retq   

0000000000001375 <_ZSt3absd>:
    1375:	55                   	push   %rbp
    1376:	48 89 e5             	mov    %rsp,%rbp
    1379:	f2 0f 11 45 f8       	movsd  %xmm0,-0x8(%rbp)
    137e:	f2 0f 10 4d f8       	movsd  -0x8(%rbp),%xmm1
    1383:	f3 0f 7e 05 25 0d 00 	movq   0xd25(%rip),%xmm0        # 20b0 <_ZZ17ecall_type_doubledE19__PRETTY_FUNCTION__+0x20>
    138a:	00 
    138b:	66 0f 54 c1          	andpd  %xmm1,%xmm0
    138f:	5d                   	pop    %rbp
    1390:	c3                   	retq   

0000000000001391 <_ZNSt14numeric_limitsIdE7epsilonEv>:
    1391:	55                   	push   %rbp
    1392:	48 89 e5             	mov    %rsp,%rbp
    1395:	f2 0f 10 05 23 0d 00 	movsd  0xd23(%rip),%xmm0        # 20c0 <_ZZ17ecall_type_doubledE19__PRETTY_FUNCTION__+0x30>
    139c:	00 
    139d:	5d                   	pop    %rbp
    139e:	c3                   	retq   
    139f:	90                   	nop

00000000000013a0 <__libc_csu_init>:
    13a0:	41 57                	push   %r15
    13a2:	41 56                	push   %r14
    13a4:	49 89 d7             	mov    %rdx,%r15
    13a7:	41 55                	push   %r13
    13a9:	41 54                	push   %r12
    13ab:	4c 8d 25 f6 29 00 00 	lea    0x29f6(%rip),%r12        # 3da8 <__frame_dummy_init_array_entry>
    13b2:	55                   	push   %rbp
    13b3:	48 8d 2d f6 29 00 00 	lea    0x29f6(%rip),%rbp        # 3db0 <__init_array_end>
    13ba:	53                   	push   %rbx
    13bb:	41 89 fd             	mov    %edi,%r13d
    13be:	49 89 f6             	mov    %rsi,%r14
    13c1:	4c 29 e5             	sub    %r12,%rbp
    13c4:	48 83 ec 08          	sub    $0x8,%rsp
    13c8:	48 c1 fd 03          	sar    $0x3,%rbp
    13cc:	e8 2f fc ff ff       	callq  1000 <_init>
    13d1:	48 85 ed             	test   %rbp,%rbp
    13d4:	74 20                	je     13f6 <__libc_csu_init+0x56>
    13d6:	31 db                	xor    %ebx,%ebx
    13d8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    13df:	00 
    13e0:	4c 89 fa             	mov    %r15,%rdx
    13e3:	4c 89 f6             	mov    %r14,%rsi
    13e6:	44 89 ef             	mov    %r13d,%edi
    13e9:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
    13ed:	48 83 c3 01          	add    $0x1,%rbx
    13f1:	48 39 dd             	cmp    %rbx,%rbp
    13f4:	75 ea                	jne    13e0 <__libc_csu_init+0x40>
    13f6:	48 83 c4 08          	add    $0x8,%rsp
    13fa:	5b                   	pop    %rbx
    13fb:	5d                   	pop    %rbp
    13fc:	41 5c                	pop    %r12
    13fe:	41 5d                	pop    %r13
    1400:	41 5e                	pop    %r14
    1402:	41 5f                	pop    %r15
    1404:	c3                   	retq   
    1405:	90                   	nop
    1406:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    140d:	00 00 00 

0000000000001410 <__libc_csu_fini>:
    1410:	f3 c3                	repz retq 

Disassembly of section .fini:

0000000000001414 <_fini>:
    1414:	48 83 ec 08          	sub    $0x8,%rsp
    1418:	48 83 c4 08          	add    $0x8,%rsp
    141c:	c3                   	retq   

Disassembly of section .rodata:

0000000000002000 <_IO_stdin_used>:
    2000:	01 00                	add    %eax,(%rax)
    2002:	02 00                	add    (%rax),%al
	...
    2010:	41 72 72             	rex.B jb 2085 <_ZZ14ecall_array_inPiE19__PRETTY_FUNCTION__+0x15>
    2013:	61                   	(bad)  
    2014:	79 20                	jns    2036 <_IO_stdin_used+0x36>
    2016:	69 6e 64 65 78 3a 25 	imul   $0x253a7865,0x64(%rsi),%ebp
    201d:	64 20 76 61          	and    %dh,%fs:0x61(%rsi)
    2021:	6c                   	insb   (%dx),%es:(%rdi)
    2022:	3a 25 64 20 0a 00    	cmp    0xa2064(%rip),%ah        # a408c <_end+0xa0074>
    2028:	2e 2f                	cs (bad) 
    202a:	64 6f                	outsl  %fs:(%rsi),(%dx)
    202c:	75 62                	jne    2090 <_ZZ17ecall_type_doubledE19__PRETTY_FUNCTION__>
    202e:	6c                   	insb   (%dx),%es:(%rdi)
    202f:	65 2e 63 00          	gs movslq %cs:(%rax),%eax
    2033:	61                   	(bad)  
    2034:	72 72                	jb     20a8 <_ZZ17ecall_type_doubledE19__PRETTY_FUNCTION__+0x18>
    2036:	5b                   	pop    %rbx
    2037:	69 5d 20 3d 3d 20 69 	imul   $0x69203d3d,0x20(%rbp),%ebx
    203e:	00 25 64 20 0a 00    	add    %ah,0xa2064(%rip)        # a40a8 <_end+0xa0090>
    2044:	00 00                	add    %al,(%rax)
    2046:	00 00                	add    %al,(%rax)
    2048:	61                   	(bad)  
    2049:	6c                   	insb   (%dx),%es:(%rdi)
    204a:	6d                   	insl   (%dx),%es:(%rdi)
    204b:	6f                   	outsl  %ds:(%rsi),(%dx)
    204c:	73 74                	jae    20c2 <_ZZ17ecall_type_doubledE19__PRETTY_FUNCTION__+0x32>
    204e:	5f                   	pop    %rdi
    204f:	65 71 75             	gs jno 20c7 <_ZZ17ecall_type_doubledE19__PRETTY_FUNCTION__+0x37>
    2052:	61                   	(bad)  
    2053:	6c                   	insb   (%dx),%es:(%rdi)
    2054:	28 76 61             	sub    %dh,0x61(%rsi)
    2057:	6c                   	insb   (%dx),%es:(%rdi)
    2058:	2c 20                	sub    $0x20,%al
    205a:	28 64 6f 75          	sub    %ah,0x75(%rdi,%rbp,2)
    205e:	62                   	(bad)  
    205f:	6c                   	insb   (%dx),%es:(%rdi)
    2060:	65 29 31             	sub    %esi,%gs:(%rcx)
    2063:	32 33                	xor    (%rbx),%dh
    2065:	34 2e                	xor    $0x2e,%al
    2067:	30 29                	xor    %ch,(%rcx)
    2069:	00 00                	add    %al,(%rax)
    206b:	00 00                	add    %al,(%rax)
    206d:	00 00                	add    %al,(%rax)
	...

0000000000002070 <_ZZ14ecall_array_inPiE19__PRETTY_FUNCTION__>:
    2070:	76 6f                	jbe    20e1 <__GNU_EH_FRAME_HDR+0x9>
    2072:	69 64 20 65 63 61 6c 	imul   $0x6c6c6163,0x65(%rax,%riz,1),%esp
    2079:	6c 
    207a:	5f                   	pop    %rdi
    207b:	61                   	(bad)  
    207c:	72 72                	jb     20f0 <__GNU_EH_FRAME_HDR+0x18>
    207e:	61                   	(bad)  
    207f:	79 5f                	jns    20e0 <__GNU_EH_FRAME_HDR+0x8>
    2081:	69 6e 28 69 6e 74 2a 	imul   $0x2a746e69,0x28(%rsi),%ebp
    2088:	29 00                	sub    %eax,(%rax)
    208a:	00 00                	add    %al,(%rax)
    208c:	00 00                	add    %al,(%rax)
	...

0000000000002090 <_ZZ17ecall_type_doubledE19__PRETTY_FUNCTION__>:
    2090:	76 6f                	jbe    2101 <__GNU_EH_FRAME_HDR+0x29>
    2092:	69 64 20 65 63 61 6c 	imul   $0x6c6c6163,0x65(%rax,%riz,1),%esp
    2099:	6c 
    209a:	5f                   	pop    %rdi
    209b:	74 79                	je     2116 <__GNU_EH_FRAME_HDR+0x3e>
    209d:	70 65                	jo     2104 <__GNU_EH_FRAME_HDR+0x2c>
    209f:	5f                   	pop    %rdi
    20a0:	64 6f                	outsl  %fs:(%rsi),(%dx)
    20a2:	75 62                	jne    2106 <__GNU_EH_FRAME_HDR+0x2e>
    20a4:	6c                   	insb   (%dx),%es:(%rdi)
    20a5:	65 28 64 6f 75       	sub    %ah,%gs:0x75(%rdi,%rbp,2)
    20aa:	62                   	(bad)  
    20ab:	6c                   	insb   (%dx),%es:(%rdi)
    20ac:	65 29 00             	sub    %eax,%gs:(%rax)
    20af:	00 ff                	add    %bh,%bh
    20b1:	ff                   	(bad)  
    20b2:	ff                   	(bad)  
    20b3:	ff                   	(bad)  
    20b4:	ff                   	(bad)  
    20b5:	ff                   	(bad)  
    20b6:	ff                   	(bad)  
    20b7:	7f 00                	jg     20b9 <_ZZ17ecall_type_doubledE19__PRETTY_FUNCTION__+0x29>
	...
    20c5:	00 b0 3c 00 00 00    	add    %dh,0x3c(%rax)
    20cb:	00 00                	add    %al,(%rax)
    20cd:	48 93                	xchg   %rax,%rbx
    20cf:	40 00 00             	add    %al,(%rax)
    20d2:	00 00                	add    %al,(%rax)
    20d4:	00 00                	add    %al,(%rax)
    20d6:	5f                   	pop    %rdi
    20d7:	40                   	rex

Disassembly of section .eh_frame_hdr:

00000000000020d8 <__GNU_EH_FRAME_HDR>:
    20d8:	01 1b                	add    %ebx,(%rbx)
    20da:	03 3b                	add    (%rbx),%edi
    20dc:	64 00 00             	add    %al,%fs:(%rax)
    20df:	00 0b                	add    %cl,(%rbx)
    20e1:	00 00                	add    %al,(%rax)
    20e3:	00 48 ef             	add    %cl,-0x11(%rax)
    20e6:	ff                   	(bad)  
    20e7:	ff b0 00 00 00 88    	pushq  -0x78000000(%rax)
    20ed:	ef                   	out    %eax,(%dx)
    20ee:	ff                   	(bad)  
    20ef:	ff                   	(bad)  
    20f0:	d8 00                	fadds  (%rax)
    20f2:	00 00                	add    %al,(%rax)
    20f4:	98                   	cwtl   
    20f5:	ef                   	out    %eax,(%dx)
    20f6:	ff                   	(bad)  
    20f7:	ff 80 00 00 00 a2    	incl   -0x5e000000(%rax)
    20fd:	f0 ff                	lock (bad) 
    20ff:	ff 30                	pushq  (%rax)
    2101:	01 00                	add    %eax,(%rax)
    2103:	00 4f f1             	add    %cl,-0xf(%rdi)
    2106:	ff                   	(bad)  
    2107:	ff 50 01             	callq  *0x1(%rax)
    210a:	00 00                	add    %al,(%rax)
    210c:	a1 f1 ff ff 70 01 00 	movabs 0x2e00000170fffff1,%eax
    2113:	00 2e 
    2115:	f2 ff                	repnz (bad) 
    2117:	ff 90 01 00 00 9d    	callq  *-0x62ffffff(%rax)
    211d:	f2 ff                	repnz (bad) 
    211f:	ff f0                	push   %rax
    2121:	00 00                	add    %al,(%rax)
    2123:	00 b9 f2 ff ff 10    	add    %bh,0x10fffff2(%rcx)
    2129:	01 00                	add    %eax,(%rax)
    212b:	00 c8                	add    %cl,%al
    212d:	f2 ff                	repnz (bad) 
    212f:	ff b0 01 00 00 38    	pushq  0x38000001(%rax)
    2135:	f3 ff                	repz (bad) 
    2137:	ff                   	(bad)  
    2138:	f8                   	clc    
    2139:	01 00                	add    %eax,(%rax)
	...

Disassembly of section .eh_frame:

0000000000002140 <__FRAME_END__-0x1a4>:
    2140:	14 00                	adc    $0x0,%al
    2142:	00 00                	add    %al,(%rax)
    2144:	00 00                	add    %al,(%rax)
    2146:	00 00                	add    %al,(%rax)
    2148:	01 7a 52             	add    %edi,0x52(%rdx)
    214b:	00 01                	add    %al,(%rcx)
    214d:	78 10                	js     215f <__GNU_EH_FRAME_HDR+0x87>
    214f:	01 1b                	add    %ebx,(%rbx)
    2151:	0c 07                	or     $0x7,%al
    2153:	08 90 01 07 10 14    	or     %dl,0x14100701(%rax)
    2159:	00 00                	add    %al,(%rax)
    215b:	00 1c 00             	add    %bl,(%rax,%rax,1)
    215e:	00 00                	add    %al,(%rax)
    2160:	10 ef                	adc    %ch,%bh
    2162:	ff                   	(bad)  
    2163:	ff 2b                	ljmp   *(%rbx)
	...
    216d:	00 00                	add    %al,(%rax)
    216f:	00 14 00             	add    %dl,(%rax,%rax,1)
    2172:	00 00                	add    %al,(%rax)
    2174:	00 00                	add    %al,(%rax)
    2176:	00 00                	add    %al,(%rax)
    2178:	01 7a 52             	add    %edi,0x52(%rdx)
    217b:	00 01                	add    %al,(%rcx)
    217d:	78 10                	js     218f <__GNU_EH_FRAME_HDR+0xb7>
    217f:	01 1b                	add    %ebx,(%rbx)
    2181:	0c 07                	or     $0x7,%al
    2183:	08 90 01 00 00 24    	or     %dl,0x24000001(%rax)
    2189:	00 00                	add    %al,(%rax)
    218b:	00 1c 00             	add    %bl,(%rax,%rax,1)
    218e:	00 00                	add    %al,(%rax)
    2190:	90                   	nop
    2191:	ee                   	out    %al,(%dx)
    2192:	ff                   	(bad)  
    2193:	ff 40 00             	incl   0x0(%rax)
    2196:	00 00                	add    %al,(%rax)
    2198:	00 0e                	add    %cl,(%rsi)
    219a:	10 46 0e             	adc    %al,0xe(%rsi)
    219d:	18 4a 0f             	sbb    %cl,0xf(%rdx)
    21a0:	0b 77 08             	or     0x8(%rdi),%esi
    21a3:	80 00 3f             	addb   $0x3f,(%rax)
    21a6:	1a 3b                	sbb    (%rbx),%bh
    21a8:	2a 33                	sub    (%rbx),%dh
    21aa:	24 22                	and    $0x22,%al
    21ac:	00 00                	add    %al,(%rax)
    21ae:	00 00                	add    %al,(%rax)
    21b0:	14 00                	adc    $0x0,%al
    21b2:	00 00                	add    %al,(%rax)
    21b4:	44 00 00             	add    %r8b,(%rax)
    21b7:	00 a8 ee ff ff 08    	add    %ch,0x8ffffee(%rax)
	...
    21c5:	00 00                	add    %al,(%rax)
    21c7:	00 1c 00             	add    %bl,(%rax,%rax,1)
    21ca:	00 00                	add    %al,(%rax)
    21cc:	5c                   	pop    %rsp
    21cd:	00 00                	add    %al,(%rax)
    21cf:	00 a5 f1 ff ff 1c    	add    %ah,0x1cfffff1(%rbp)
    21d5:	00 00                	add    %al,(%rax)
    21d7:	00 00                	add    %al,(%rax)
    21d9:	41 0e                	rex.B (bad) 
    21db:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
    21e1:	57                   	push   %rdi
    21e2:	0c 07                	or     $0x7,%al
    21e4:	08 00                	or     %al,(%rax)
    21e6:	00 00                	add    %al,(%rax)
    21e8:	1c 00                	sbb    $0x0,%al
    21ea:	00 00                	add    %al,(%rax)
    21ec:	7c 00                	jl     21ee <__GNU_EH_FRAME_HDR+0x116>
    21ee:	00 00                	add    %al,(%rax)
    21f0:	a1 f1 ff ff 0e 00 00 	movabs 0xefffff1,%eax
    21f7:	00 00 
    21f9:	41 0e                	rex.B (bad) 
    21fb:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
    2201:	49 0c 07             	rex.WB or $0x7,%al
    2204:	08 00                	or     %al,(%rax)
    2206:	00 00                	add    %al,(%rax)
    2208:	1c 00                	sbb    $0x0,%al
    220a:	00 00                	add    %al,(%rax)
    220c:	9c                   	pushfq 
    220d:	00 00                	add    %al,(%rax)
    220f:	00 6a ef             	add    %ch,-0x11(%rdx)
    2212:	ff                   	(bad)  
    2213:	ff ad 00 00 00 00    	ljmp   *0x0(%rbp)
    2219:	41 0e                	rex.B (bad) 
    221b:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
    2221:	02 a8 0c 07 08 00    	add    0x8070c(%rax),%ch
    2227:	00 1c 00             	add    %bl,(%rax,%rax,1)
    222a:	00 00                	add    %al,(%rax)
    222c:	bc 00 00 00 f7       	mov    $0xf7000000,%esp
    2231:	ef                   	out    %eax,(%dx)
    2232:	ff                   	(bad)  
    2233:	ff 52 00             	callq  *0x0(%rdx)
    2236:	00 00                	add    %al,(%rax)
    2238:	00 41 0e             	add    %al,0xe(%rcx)
    223b:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
    2241:	02 4d 0c             	add    0xc(%rbp),%cl
    2244:	07                   	(bad)  
    2245:	08 00                	or     %al,(%rax)
    2247:	00 1c 00             	add    %bl,(%rax,%rax,1)
    224a:	00 00                	add    %al,(%rax)
    224c:	dc 00                	faddl  (%rax)
    224e:	00 00                	add    %al,(%rax)
    2250:	29 f0                	sub    %esi,%eax
    2252:	ff                   	(bad)  
    2253:	ff 8d 00 00 00 00    	decl   0x0(%rbp)
    2259:	41 0e                	rex.B (bad) 
    225b:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
    2261:	02 88 0c 07 08 00    	add    0x8070c(%rax),%cl
    2267:	00 1c 00             	add    %bl,(%rax,%rax,1)
    226a:	00 00                	add    %al,(%rax)
    226c:	fc                   	cld    
    226d:	00 00                	add    %al,(%rax)
    226f:	00 96 f0 ff ff 6f    	add    %dl,0x6ffffff0(%rsi)
    2275:	00 00                	add    %al,(%rax)
    2277:	00 00                	add    %al,(%rax)
    2279:	41 0e                	rex.B (bad) 
    227b:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
    2281:	02 6a 0c             	add    0xc(%rdx),%ch
    2284:	07                   	(bad)  
    2285:	08 00                	or     %al,(%rax)
    2287:	00 44 00 00          	add    %al,0x0(%rax,%rax,1)
    228b:	00 1c 01             	add    %bl,(%rcx,%rax,1)
    228e:	00 00                	add    %al,(%rax)
    2290:	10 f1                	adc    %dh,%cl
    2292:	ff                   	(bad)  
    2293:	ff 65 00             	jmpq   *0x0(%rbp)
    2296:	00 00                	add    %al,(%rax)
    2298:	00 42 0e             	add    %al,0xe(%rdx)
    229b:	10 8f 02 42 0e 18    	adc    %cl,0x180e4202(%rdi)
    22a1:	8e 03                	mov    (%rbx),%es
    22a3:	45 0e                	rex.RB (bad) 
    22a5:	20 8d 04 42 0e 28    	and    %cl,0x280e4204(%rbp)
    22ab:	8c 05 48 0e 30 86    	mov    %es,-0x79cff1b8(%rip)        # ffffffff863030f9 <_end+0xffffffff862ff0e1>
    22b1:	06                   	(bad)  
    22b2:	48 0e                	rex.W (bad) 
    22b4:	38 83 07 4d 0e 40    	cmp    %al,0x400e4d07(%rbx)
    22ba:	72 0e                	jb     22ca <__GNU_EH_FRAME_HDR+0x1f2>
    22bc:	38 41 0e             	cmp    %al,0xe(%rcx)
    22bf:	30 41 0e             	xor    %al,0xe(%rcx)
    22c2:	28 42 0e             	sub    %al,0xe(%rdx)
    22c5:	20 42 0e             	and    %al,0xe(%rdx)
    22c8:	18 42 0e             	sbb    %al,0xe(%rdx)
    22cb:	10 42 0e             	adc    %al,0xe(%rdx)
    22ce:	08 00                	or     %al,(%rax)
    22d0:	10 00                	adc    %al,(%rax)
    22d2:	00 00                	add    %al,(%rax)
    22d4:	64 01 00             	add    %eax,%fs:(%rax)
    22d7:	00 38                	add    %bh,(%rax)
    22d9:	f1                   	icebp  
    22da:	ff                   	(bad)  
    22db:	ff 02                	incl   (%rdx)
    22dd:	00 00                	add    %al,(%rax)
    22df:	00 00                	add    %al,(%rax)
    22e1:	00 00                	add    %al,(%rax)
	...

00000000000022e4 <__FRAME_END__>:
    22e4:	00 00                	add    %al,(%rax)
	...

Disassembly of section .init_array:

0000000000003da8 <__frame_dummy_init_array_entry>:
    3da8:	70 11                	jo     3dbb <_DYNAMIC+0x3>
    3daa:	00 00                	add    %al,(%rax)
    3dac:	00 00                	add    %al,(%rax)
	...

Disassembly of section .fini_array:

0000000000003db0 <__do_global_dtors_aux_fini_array_entry>:
    3db0:	30 11                	xor    %dl,(%rcx)
    3db2:	00 00                	add    %al,(%rax)
    3db4:	00 00                	add    %al,(%rax)
	...

Disassembly of section .dynamic:

0000000000003db8 <_DYNAMIC>:
    3db8:	01 00                	add    %eax,(%rax)
    3dba:	00 00                	add    %al,(%rax)
    3dbc:	00 00                	add    %al,(%rax)
    3dbe:	00 00                	add    %al,(%rax)
    3dc0:	01 00                	add    %eax,(%rax)
    3dc2:	00 00                	add    %al,(%rax)
    3dc4:	00 00                	add    %al,(%rax)
    3dc6:	00 00                	add    %al,(%rax)
    3dc8:	0c 00                	or     $0x0,%al
    3dca:	00 00                	add    %al,(%rax)
    3dcc:	00 00                	add    %al,(%rax)
    3dce:	00 00                	add    %al,(%rax)
    3dd0:	00 10                	add    %dl,(%rax)
    3dd2:	00 00                	add    %al,(%rax)
    3dd4:	00 00                	add    %al,(%rax)
    3dd6:	00 00                	add    %al,(%rax)
    3dd8:	0d 00 00 00 00       	or     $0x0,%eax
    3ddd:	00 00                	add    %al,(%rax)
    3ddf:	00 14 14             	add    %dl,(%rsp,%rdx,1)
    3de2:	00 00                	add    %al,(%rax)
    3de4:	00 00                	add    %al,(%rax)
    3de6:	00 00                	add    %al,(%rax)
    3de8:	19 00                	sbb    %eax,(%rax)
    3dea:	00 00                	add    %al,(%rax)
    3dec:	00 00                	add    %al,(%rax)
    3dee:	00 00                	add    %al,(%rax)
    3df0:	a8 3d                	test   $0x3d,%al
    3df2:	00 00                	add    %al,(%rax)
    3df4:	00 00                	add    %al,(%rax)
    3df6:	00 00                	add    %al,(%rax)
    3df8:	1b 00                	sbb    (%rax),%eax
    3dfa:	00 00                	add    %al,(%rax)
    3dfc:	00 00                	add    %al,(%rax)
    3dfe:	00 00                	add    %al,(%rax)
    3e00:	08 00                	or     %al,(%rax)
    3e02:	00 00                	add    %al,(%rax)
    3e04:	00 00                	add    %al,(%rax)
    3e06:	00 00                	add    %al,(%rax)
    3e08:	1a 00                	sbb    (%rax),%al
    3e0a:	00 00                	add    %al,(%rax)
    3e0c:	00 00                	add    %al,(%rax)
    3e0e:	00 00                	add    %al,(%rax)
    3e10:	b0 3d                	mov    $0x3d,%al
    3e12:	00 00                	add    %al,(%rax)
    3e14:	00 00                	add    %al,(%rax)
    3e16:	00 00                	add    %al,(%rax)
    3e18:	1c 00                	sbb    $0x0,%al
    3e1a:	00 00                	add    %al,(%rax)
    3e1c:	00 00                	add    %al,(%rax)
    3e1e:	00 00                	add    %al,(%rax)
    3e20:	08 00                	or     %al,(%rax)
    3e22:	00 00                	add    %al,(%rax)
    3e24:	00 00                	add    %al,(%rax)
    3e26:	00 00                	add    %al,(%rax)
    3e28:	f5                   	cmc    
    3e29:	fe                   	(bad)  
    3e2a:	ff 6f 00             	ljmp   *0x0(%rdi)
    3e2d:	00 00                	add    %al,(%rax)
    3e2f:	00 08                	add    %cl,(%rax)
    3e31:	03 00                	add    (%rax),%eax
    3e33:	00 00                	add    %al,(%rax)
    3e35:	00 00                	add    %al,(%rax)
    3e37:	00 05 00 00 00 00    	add    %al,0x0(%rip)        # 3e3d <_DYNAMIC+0x85>
    3e3d:	00 00                	add    %al,(%rax)
    3e3f:	00 08                	add    %cl,(%rax)
    3e41:	04 00                	add    $0x0,%al
    3e43:	00 00                	add    %al,(%rax)
    3e45:	00 00                	add    %al,(%rax)
    3e47:	00 06                	add    %al,(%rsi)
    3e49:	00 00                	add    %al,(%rax)
    3e4b:	00 00                	add    %al,(%rax)
    3e4d:	00 00                	add    %al,(%rax)
    3e4f:	00 30                	add    %dh,(%rax)
    3e51:	03 00                	add    (%rax),%eax
    3e53:	00 00                	add    %al,(%rax)
    3e55:	00 00                	add    %al,(%rax)
    3e57:	00 0a                	add    %cl,(%rdx)
    3e59:	00 00                	add    %al,(%rax)
    3e5b:	00 00                	add    %al,(%rax)
    3e5d:	00 00                	add    %al,(%rax)
    3e5f:	00 ad 00 00 00 00    	add    %ch,0x0(%rbp)
    3e65:	00 00                	add    %al,(%rax)
    3e67:	00 0b                	add    %cl,(%rbx)
    3e69:	00 00                	add    %al,(%rax)
    3e6b:	00 00                	add    %al,(%rax)
    3e6d:	00 00                	add    %al,(%rax)
    3e6f:	00 18                	add    %bl,(%rax)
    3e71:	00 00                	add    %al,(%rax)
    3e73:	00 00                	add    %al,(%rax)
    3e75:	00 00                	add    %al,(%rax)
    3e77:	00 15 00 00 00 00    	add    %dl,0x0(%rip)        # 3e7d <_DYNAMIC+0xc5>
	...
    3e85:	00 00                	add    %al,(%rax)
    3e87:	00 03                	add    %al,(%rbx)
    3e89:	00 00                	add    %al,(%rax)
    3e8b:	00 00                	add    %al,(%rax)
    3e8d:	00 00                	add    %al,(%rax)
    3e8f:	00 a8 3f 00 00 00    	add    %ch,0x3f(%rax)
    3e95:	00 00                	add    %al,(%rax)
    3e97:	00 02                	add    %al,(%rdx)
    3e99:	00 00                	add    %al,(%rax)
    3e9b:	00 00                	add    %al,(%rax)
    3e9d:	00 00                	add    %al,(%rax)
    3e9f:	00 48 00             	add    %cl,0x0(%rax)
    3ea2:	00 00                	add    %al,(%rax)
    3ea4:	00 00                	add    %al,(%rax)
    3ea6:	00 00                	add    %al,(%rax)
    3ea8:	14 00                	adc    $0x0,%al
    3eaa:	00 00                	add    %al,(%rax)
    3eac:	00 00                	add    %al,(%rax)
    3eae:	00 00                	add    %al,(%rax)
    3eb0:	07                   	(bad)  
    3eb1:	00 00                	add    %al,(%rax)
    3eb3:	00 00                	add    %al,(%rax)
    3eb5:	00 00                	add    %al,(%rax)
    3eb7:	00 17                	add    %dl,(%rdi)
    3eb9:	00 00                	add    %al,(%rax)
    3ebb:	00 00                	add    %al,(%rax)
    3ebd:	00 00                	add    %al,(%rax)
    3ebf:	00 b8 05 00 00 00    	add    %bh,0x5(%rax)
    3ec5:	00 00                	add    %al,(%rax)
    3ec7:	00 07                	add    %al,(%rdi)
    3ec9:	00 00                	add    %al,(%rax)
    3ecb:	00 00                	add    %al,(%rax)
    3ecd:	00 00                	add    %al,(%rax)
    3ecf:	00 f8                	add    %bh,%al
    3ed1:	04 00                	add    $0x0,%al
    3ed3:	00 00                	add    %al,(%rax)
    3ed5:	00 00                	add    %al,(%rax)
    3ed7:	00 08                	add    %cl,(%rax)
    3ed9:	00 00                	add    %al,(%rax)
    3edb:	00 00                	add    %al,(%rax)
    3edd:	00 00                	add    %al,(%rax)
    3edf:	00 c0                	add    %al,%al
    3ee1:	00 00                	add    %al,(%rax)
    3ee3:	00 00                	add    %al,(%rax)
    3ee5:	00 00                	add    %al,(%rax)
    3ee7:	00 09                	add    %cl,(%rcx)
    3ee9:	00 00                	add    %al,(%rax)
    3eeb:	00 00                	add    %al,(%rax)
    3eed:	00 00                	add    %al,(%rax)
    3eef:	00 18                	add    %bl,(%rax)
    3ef1:	00 00                	add    %al,(%rax)
    3ef3:	00 00                	add    %al,(%rax)
    3ef5:	00 00                	add    %al,(%rax)
    3ef7:	00 18                	add    %bl,(%rax)
	...
    3f05:	00 00                	add    %al,(%rax)
    3f07:	00 fb                	add    %bh,%bl
    3f09:	ff                   	(bad)  
    3f0a:	ff 6f 00             	ljmp   *0x0(%rdi)
    3f0d:	00 00                	add    %al,(%rax)
    3f0f:	00 01                	add    %al,(%rcx)
    3f11:	00 00                	add    %al,(%rax)
    3f13:	08 00                	or     %al,(%rax)
    3f15:	00 00                	add    %al,(%rax)
    3f17:	00 fe                	add    %bh,%dh
    3f19:	ff                   	(bad)  
    3f1a:	ff 6f 00             	ljmp   *0x0(%rdi)
    3f1d:	00 00                	add    %al,(%rax)
    3f1f:	00 c8                	add    %cl,%al
    3f21:	04 00                	add    $0x0,%al
    3f23:	00 00                	add    %al,(%rax)
    3f25:	00 00                	add    %al,(%rax)
    3f27:	00 ff                	add    %bh,%bh
    3f29:	ff                   	(bad)  
    3f2a:	ff 6f 00             	ljmp   *0x0(%rdi)
    3f2d:	00 00                	add    %al,(%rax)
    3f2f:	00 01                	add    %al,(%rcx)
    3f31:	00 00                	add    %al,(%rax)
    3f33:	00 00                	add    %al,(%rax)
    3f35:	00 00                	add    %al,(%rax)
    3f37:	00 f0                	add    %dh,%al
    3f39:	ff                   	(bad)  
    3f3a:	ff 6f 00             	ljmp   *0x0(%rdi)
    3f3d:	00 00                	add    %al,(%rax)
    3f3f:	00 b6 04 00 00 00    	add    %dh,0x4(%rsi)
    3f45:	00 00                	add    %al,(%rax)
    3f47:	00 f9                	add    %bh,%cl
    3f49:	ff                   	(bad)  
    3f4a:	ff 6f 00             	ljmp   *0x0(%rdi)
    3f4d:	00 00                	add    %al,(%rax)
    3f4f:	00 03                	add    %al,(%rbx)
	...

Disassembly of section .got:

0000000000003fa8 <_GLOBAL_OFFSET_TABLE_>:
    3fa8:	b8 3d 00 00 00       	mov    $0x3d,%eax
	...
    3fbd:	00 00                	add    %al,(%rax)
    3fbf:	00 36                	add    %dh,(%rsi)
    3fc1:	10 00                	adc    %al,(%rax)
    3fc3:	00 00                	add    %al,(%rax)
    3fc5:	00 00                	add    %al,(%rax)
    3fc7:	00 46 10             	add    %al,0x10(%rsi)
    3fca:	00 00                	add    %al,(%rax)
    3fcc:	00 00                	add    %al,(%rax)
    3fce:	00 00                	add    %al,(%rax)
    3fd0:	56                   	push   %rsi
    3fd1:	10 00                	adc    %al,(%rax)
	...

Disassembly of section .data:

0000000000004000 <__data_start>:
	...

0000000000004008 <__dso_handle>:
    4008:	08 40 00             	or     %al,0x0(%rax)
    400b:	00 00                	add    %al,(%rax)
    400d:	00 00                	add    %al,(%rax)
	...

Disassembly of section .bss:

0000000000004010 <__bss_start>:
	...

Disassembly of section .comment:

0000000000000000 <.comment>:
   0:	47                   	rex.RXB
   1:	43                   	rex.XB
   2:	43 3a 20             	rex.XB cmp (%r8),%spl
   5:	28 55 62             	sub    %dl,0x62(%rbp)
   8:	75 6e                	jne    78 <_init-0xf88>
   a:	74 75                	je     81 <_init-0xf7f>
   c:	20 37                	and    %dh,(%rdi)
   e:	2e 35 2e 30 2d 33    	cs xor $0x332d302e,%eax
  14:	75 62                	jne    78 <_init-0xf88>
  16:	75 6e                	jne    86 <_init-0xf7a>
  18:	74 75                	je     8f <_init-0xf71>
  1a:	31 7e 31             	xor    %edi,0x31(%rsi)
  1d:	38 2e                	cmp    %ch,(%rsi)
  1f:	30 34 29             	xor    %dh,(%rcx,%rbp,1)
  22:	20 37                	and    %dh,(%rdi)
  24:	2e                   	cs
  25:	35                   	.byte 0x35
  26:	2e 30 00             	xor    %al,%cs:(%rax)
