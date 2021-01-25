
./loader:     file format elf64-x86-64


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
 2d3:	00 d2                	add    %dl,%dl
 2d5:	b9 21 72 10 41       	mov    $0x41107221,%ecx
 2da:	81 58 4f d7 06 9b 20 	sbbl   $0x209b06d7,0x4f(%rax)
 2e1:	42 51                	rex.X push %rcx
 2e3:	61                   	(bad)  
 2e4:	e0 52                	loopne 338 <_init-0xcc8>
 2e6:	da 11                	ficoml (%rcx)

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
 30c:	0a 00                	or     (%rax),%al
 30e:	00 00                	add    %al,(%rax)
 310:	01 00                	add    %eax,(%rax)
 312:	00 00                	add    %al,(%rax)
 314:	06                   	(bad)  
 315:	00 00                	add    %al,(%rax)
 317:	00 00                	add    %al,(%rax)
 319:	00 81 00 00 00 00    	add    %al,0x0(%rcx)
 31f:	00 0a                	add    %cl,(%rdx)
 321:	00 00                	add    %al,(%rax)
 323:	00 00                	add    %al,(%rax)
 325:	00 00                	add    %al,(%rax)
 327:	00 d1                	add    %dl,%cl
 329:	65 ce                	gs (bad) 
 32b:	6d                   	insl   (%dx),%es:(%rdi)

Disassembly of section .dynsym:

0000000000000330 <.dynsym>:
	...
 348:	0c 00                	or     $0x0,%al
 34a:	00 00                	add    %al,(%rax)
 34c:	20 00                	and    %al,(%rax)
	...
 35e:	00 00                	add    %al,(%rax)
 360:	68 00 00 00 12       	pushq  $0x12000000
	...
 375:	00 00                	add    %al,(%rax)
 377:	00 76 00             	add    %dh,0x0(%rsi)
 37a:	00 00                	add    %al,(%rax)
 37c:	12 00                	adc    (%rax),%al
	...
 38e:	00 00                	add    %al,(%rax)
 390:	90                   	nop
 391:	00 00                	add    %al,(%rax)
 393:	00 12                	add    %dl,(%rdx)
	...
 3a5:	00 00                	add    %al,(%rax)
 3a7:	00 28                	add    %ch,(%rax)
 3a9:	00 00                	add    %al,(%rax)
 3ab:	00 20                	add    %ah,(%rax)
	...
 3bd:	00 00                	add    %al,(%rax)
 3bf:	00 57 00             	add    %dl,0x0(%rdi)
 3c2:	00 00                	add    %al,(%rax)
 3c4:	12 00                	adc    (%rax),%al
	...
 3d6:	00 00                	add    %al,(%rax)
 3d8:	6f                   	outsl  %ds:(%rsi),(%dx)
 3d9:	00 00                	add    %al,(%rax)
 3db:	00 12                	add    %dl,(%rdx)
	...
 3ed:	00 00                	add    %al,(%rax)
 3ef:	00 37                	add    %dh,(%rdi)
 3f1:	00 00                	add    %al,(%rax)
 3f3:	00 20                	add    %ah,(%rax)
	...
 405:	00 00                	add    %al,(%rax)
 407:	00 51 00             	add    %dl,0x0(%rcx)
 40a:	00 00                	add    %al,(%rax)
 40c:	12 00                	adc    (%rax),%al
	...
 41e:	00 00                	add    %al,(%rax)
 420:	81 00 00 00 22 00    	addl   $0x220000,(%rax)
	...

Disassembly of section .dynstr:

0000000000000438 <.dynstr>:
 438:	00 6c 69 62          	add    %ch,0x62(%rcx,%rbp,2)
 43c:	64 6c                	fs insb (%dx),%es:(%rdi)
 43e:	2e 73 6f             	jae,pn 4b0 <_init-0xb50>
 441:	2e 32 00             	xor    %cs:(%rax),%al
 444:	5f                   	pop    %rdi
 445:	49 54                	rex.WB push %r12
 447:	4d 5f                	rex.WRB pop %r15
 449:	64 65 72 65          	fs gs jb 4b2 <_init-0xb4e>
 44d:	67 69 73 74 65 72 54 	imul   $0x4d547265,0x74(%ebx),%esi
 454:	4d 
 455:	43 6c                	rex.XB insb (%dx),%es:(%rdi)
 457:	6f                   	outsl  %ds:(%rsi),(%dx)
 458:	6e                   	outsb  %ds:(%rsi),(%dx)
 459:	65 54                	gs push %rsp
 45b:	61                   	(bad)  
 45c:	62                   	(bad)  
 45d:	6c                   	insb   (%dx),%es:(%rdi)
 45e:	65 00 5f 5f          	add    %bl,%gs:0x5f(%rdi)
 462:	67 6d                	insl   (%dx),%es:(%edi)
 464:	6f                   	outsl  %ds:(%rsi),(%dx)
 465:	6e                   	outsb  %ds:(%rsi),(%dx)
 466:	5f                   	pop    %rdi
 467:	73 74                	jae    4dd <_init-0xb23>
 469:	61                   	(bad)  
 46a:	72 74                	jb     4e0 <_init-0xb20>
 46c:	5f                   	pop    %rdi
 46d:	5f                   	pop    %rdi
 46e:	00 5f 49             	add    %bl,0x49(%rdi)
 471:	54                   	push   %rsp
 472:	4d 5f                	rex.WRB pop %r15
 474:	72 65                	jb     4db <_init-0xb25>
 476:	67 69 73 74 65 72 54 	imul   $0x4d547265,0x74(%ebx),%esi
 47d:	4d 
 47e:	43 6c                	rex.XB insb (%dx),%es:(%rdi)
 480:	6f                   	outsl  %ds:(%rsi),(%dx)
 481:	6e                   	outsb  %ds:(%rsi),(%dx)
 482:	65 54                	gs push %rsp
 484:	61                   	(bad)  
 485:	62                   	(bad)  
 486:	6c                   	insb   (%dx),%es:(%rdi)
 487:	65 00 64 6c 73       	add    %ah,%gs:0x73(%rsp,%rbp,2)
 48c:	79 6d                	jns    4fb <_init-0xb05>
 48e:	00 64 6c 6f          	add    %ah,0x6f(%rsp,%rbp,2)
 492:	70 65                	jo     4f9 <_init-0xb07>
 494:	6e                   	outsb  %ds:(%rsi),(%dx)
 495:	00 6c 69 62          	add    %ch,0x62(%rcx,%rbp,2)
 499:	63 2e                	movslq (%rsi),%ebp
 49b:	73 6f                	jae    50c <_init-0xaf4>
 49d:	2e 36 00 70 72       	cs add %dh,%ss:0x72(%rax)
 4a2:	69 6e 74 66 00 6d 61 	imul   $0x616d0066,0x74(%rsi),%ebp
 4a9:	6c                   	insb   (%dx),%es:(%rdi)
 4aa:	6c                   	insb   (%dx),%es:(%rdi)
 4ab:	6f                   	outsl  %ds:(%rsi),(%dx)
 4ac:	63 00                	movslq (%rax),%eax
 4ae:	61                   	(bad)  
 4af:	72 63                	jb     514 <_init-0xaec>
 4b1:	68 5f 70 72 63       	pushq  $0x6372705f
 4b6:	74 6c                	je     524 <_init-0xadc>
 4b8:	00 5f 5f             	add    %bl,0x5f(%rdi)
 4bb:	63 78 61             	movslq 0x61(%rax),%edi
 4be:	5f                   	pop    %rdi
 4bf:	66 69 6e 61 6c 69    	imul   $0x696c,0x61(%rsi),%bp
 4c5:	7a 65                	jp     52c <_init-0xad4>
 4c7:	00 5f 5f             	add    %bl,0x5f(%rdi)
 4ca:	6c                   	insb   (%dx),%es:(%rdi)
 4cb:	69 62 63 5f 73 74 61 	imul   $0x6174735f,0x63(%rdx),%esp
 4d2:	72 74                	jb     548 <_init-0xab8>
 4d4:	5f                   	pop    %rdi
 4d5:	6d                   	insl   (%dx),%es:(%rdi)
 4d6:	61                   	(bad)  
 4d7:	69 6e 00 47 4c 49 42 	imul   $0x42494c47,0x0(%rsi),%ebp
 4de:	43 5f                	rex.XB pop %r15
 4e0:	32 2e                	xor    (%rsi),%ch
 4e2:	32 2e                	xor    (%rsi),%ch
 4e4:	35                   	.byte 0x35
	...

Disassembly of section .gnu.version:

00000000000004e6 <.gnu.version>:
 4e6:	00 00                	add    %al,(%rax)
 4e8:	00 00                	add    %al,(%rax)
 4ea:	02 00                	add    (%rax),%al
 4ec:	02 00                	add    (%rax),%al
 4ee:	02 00                	add    (%rax),%al
 4f0:	00 00                	add    %al,(%rax)
 4f2:	03 00                	add    (%rax),%eax
 4f4:	02 00                	add    (%rax),%al
 4f6:	00 00                	add    %al,(%rax)
 4f8:	03 00                	add    (%rax),%eax
 4fa:	02 00                	add    (%rax),%al

Disassembly of section .gnu.version_r:

0000000000000500 <.gnu.version_r>:
 500:	01 00                	add    %eax,(%rax)
 502:	01 00                	add    %eax,(%rax)
 504:	01 00                	add    %eax,(%rax)
 506:	00 00                	add    %al,(%rax)
 508:	10 00                	adc    %al,(%rax)
 50a:	00 00                	add    %al,(%rax)
 50c:	20 00                	and    %al,(%rax)
 50e:	00 00                	add    %al,(%rax)
 510:	75 1a                	jne    52c <_init-0xad4>
 512:	69 09 00 00 03 00    	imul   $0x30000,(%rcx),%ecx
 518:	a2 00 00 00 00 00 00 	movabs %al,0x100000000000000
 51f:	00 01 
 521:	00 01                	add    %al,(%rcx)
 523:	00 5e 00             	add    %bl,0x0(%rsi)
 526:	00 00                	add    %al,(%rax)
 528:	10 00                	adc    %al,(%rax)
 52a:	00 00                	add    %al,(%rax)
 52c:	00 00                	add    %al,(%rax)
 52e:	00 00                	add    %al,(%rax)
 530:	75 1a                	jne    54c <_init-0xab4>
 532:	69 09 00 00 02 00    	imul   $0x20000,(%rcx),%ecx
 538:	a2                   	.byte 0xa2
 539:	00 00                	add    %al,(%rax)
 53b:	00 00                	add    %al,(%rax)
 53d:	00 00                	add    %al,(%rax)
	...

Disassembly of section .rela.dyn:

0000000000000540 <.rela.dyn>:
 540:	88 3d 00 00 00 00    	mov    %bh,0x0(%rip)        # 546 <_init-0xaba>
 546:	00 00                	add    %al,(%rax)
 548:	08 00                	or     %al,(%rax)
 54a:	00 00                	add    %al,(%rax)
 54c:	00 00                	add    %al,(%rax)
 54e:	00 00                	add    %al,(%rax)
 550:	90                   	nop
 551:	11 00                	adc    %eax,(%rax)
 553:	00 00                	add    %al,(%rax)
 555:	00 00                	add    %al,(%rax)
 557:	00 90 3d 00 00 00    	add    %dl,0x3d(%rax)
 55d:	00 00                	add    %al,(%rax)
 55f:	00 08                	add    %cl,(%rax)
 561:	00 00                	add    %al,(%rax)
 563:	00 00                	add    %al,(%rax)
 565:	00 00                	add    %al,(%rax)
 567:	00 50 11             	add    %dl,0x11(%rax)
 56a:	00 00                	add    %al,(%rax)
 56c:	00 00                	add    %al,(%rax)
 56e:	00 00                	add    %al,(%rax)
 570:	08 40 00             	or     %al,0x0(%rax)
 573:	00 00                	add    %al,(%rax)
 575:	00 00                	add    %al,(%rax)
 577:	00 08                	add    %cl,(%rax)
 579:	00 00                	add    %al,(%rax)
 57b:	00 00                	add    %al,(%rax)
 57d:	00 00                	add    %al,(%rax)
 57f:	00 08                	add    %cl,(%rax)
 581:	40 00 00             	add    %al,(%rax)
 584:	00 00                	add    %al,(%rax)
 586:	00 00                	add    %al,(%rax)
 588:	d8 3f                	fdivrs (%rdi)
 58a:	00 00                	add    %al,(%rax)
 58c:	00 00                	add    %al,(%rax)
 58e:	00 00                	add    %al,(%rax)
 590:	06                   	(bad)  
 591:	00 00                	add    %al,(%rax)
 593:	00 01                	add    %al,(%rcx)
	...
 59d:	00 00                	add    %al,(%rax)
 59f:	00 e0                	add    %ah,%al
 5a1:	3f                   	(bad)  
 5a2:	00 00                	add    %al,(%rax)
 5a4:	00 00                	add    %al,(%rax)
 5a6:	00 00                	add    %al,(%rax)
 5a8:	06                   	(bad)  
 5a9:	00 00                	add    %al,(%rax)
 5ab:	00 04 00             	add    %al,(%rax,%rax,1)
	...
 5b6:	00 00                	add    %al,(%rax)
 5b8:	e8 3f 00 00 00       	callq  5fc <_init-0xa04>
 5bd:	00 00                	add    %al,(%rax)
 5bf:	00 06                	add    %al,(%rsi)
 5c1:	00 00                	add    %al,(%rax)
 5c3:	00 05 00 00 00 00    	add    %al,0x0(%rip)        # 5c9 <_init-0xa37>
 5c9:	00 00                	add    %al,(%rax)
 5cb:	00 00                	add    %al,(%rax)
 5cd:	00 00                	add    %al,(%rax)
 5cf:	00 f0                	add    %dh,%al
 5d1:	3f                   	(bad)  
 5d2:	00 00                	add    %al,(%rax)
 5d4:	00 00                	add    %al,(%rax)
 5d6:	00 00                	add    %al,(%rax)
 5d8:	06                   	(bad)  
 5d9:	00 00                	add    %al,(%rax)
 5db:	00 08                	add    %cl,(%rax)
	...
 5e5:	00 00                	add    %al,(%rax)
 5e7:	00 f8                	add    %bh,%al
 5e9:	3f                   	(bad)  
 5ea:	00 00                	add    %al,(%rax)
 5ec:	00 00                	add    %al,(%rax)
 5ee:	00 00                	add    %al,(%rax)
 5f0:	06                   	(bad)  
 5f1:	00 00                	add    %al,(%rax)
 5f3:	00 0a                	add    %cl,(%rdx)
	...

Disassembly of section .rela.plt:

0000000000000600 <.rela.plt>:
 600:	b0 3f                	mov    $0x3f,%al
 602:	00 00                	add    %al,(%rax)
 604:	00 00                	add    %al,(%rax)
 606:	00 00                	add    %al,(%rax)
 608:	07                   	(bad)  
 609:	00 00                	add    %al,(%rax)
 60b:	00 02                	add    %al,(%rdx)
	...
 615:	00 00                	add    %al,(%rax)
 617:	00 b8 3f 00 00 00    	add    %bh,0x3f(%rax)
 61d:	00 00                	add    %al,(%rax)
 61f:	00 07                	add    %al,(%rdi)
 621:	00 00                	add    %al,(%rax)
 623:	00 03                	add    %al,(%rbx)
	...
 62d:	00 00                	add    %al,(%rax)
 62f:	00 c0                	add    %al,%al
 631:	3f                   	(bad)  
 632:	00 00                	add    %al,(%rax)
 634:	00 00                	add    %al,(%rax)
 636:	00 00                	add    %al,(%rax)
 638:	07                   	(bad)  
 639:	00 00                	add    %al,(%rax)
 63b:	00 06                	add    %al,(%rsi)
	...
 645:	00 00                	add    %al,(%rax)
 647:	00 c8                	add    %cl,%al
 649:	3f                   	(bad)  
 64a:	00 00                	add    %al,(%rax)
 64c:	00 00                	add    %al,(%rax)
 64e:	00 00                	add    %al,(%rax)
 650:	07                   	(bad)  
 651:	00 00                	add    %al,(%rax)
 653:	00 07                	add    %al,(%rdi)
	...
 65d:	00 00                	add    %al,(%rax)
 65f:	00 d0                	add    %dl,%al
 661:	3f                   	(bad)  
 662:	00 00                	add    %al,(%rax)
 664:	00 00                	add    %al,(%rax)
 666:	00 00                	add    %al,(%rax)
 668:	07                   	(bad)  
 669:	00 00                	add    %al,(%rax)
 66b:	00 09                	add    %cl,(%rcx)
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
    1020:	ff 35 7a 2f 00 00    	pushq  0x2f7a(%rip)        # 3fa0 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	ff 25 7c 2f 00 00    	jmpq   *0x2f7c(%rip)        # 3fa8 <_GLOBAL_OFFSET_TABLE_+0x10>
    102c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000001030 <printf@plt>:
    1030:	ff 25 7a 2f 00 00    	jmpq   *0x2f7a(%rip)        # 3fb0 <printf@GLIBC_2.2.5>
    1036:	68 00 00 00 00       	pushq  $0x0
    103b:	e9 e0 ff ff ff       	jmpq   1020 <.plt>

0000000000001040 <arch_prctl@plt>:
    1040:	ff 25 72 2f 00 00    	jmpq   *0x2f72(%rip)        # 3fb8 <arch_prctl@GLIBC_2.2.5>
    1046:	68 01 00 00 00       	pushq  $0x1
    104b:	e9 d0 ff ff ff       	jmpq   1020 <.plt>

0000000000001050 <dlopen@plt>:
    1050:	ff 25 6a 2f 00 00    	jmpq   *0x2f6a(%rip)        # 3fc0 <dlopen@GLIBC_2.2.5>
    1056:	68 02 00 00 00       	pushq  $0x2
    105b:	e9 c0 ff ff ff       	jmpq   1020 <.plt>

0000000000001060 <malloc@plt>:
    1060:	ff 25 62 2f 00 00    	jmpq   *0x2f62(%rip)        # 3fc8 <malloc@GLIBC_2.2.5>
    1066:	68 03 00 00 00       	pushq  $0x3
    106b:	e9 b0 ff ff ff       	jmpq   1020 <.plt>

0000000000001070 <dlsym@plt>:
    1070:	ff 25 5a 2f 00 00    	jmpq   *0x2f5a(%rip)        # 3fd0 <dlsym@GLIBC_2.2.5>
    1076:	68 04 00 00 00       	pushq  $0x4
    107b:	e9 a0 ff ff ff       	jmpq   1020 <.plt>

Disassembly of section .plt.got:

0000000000001080 <__cxa_finalize@plt>:
    1080:	ff 25 72 2f 00 00    	jmpq   *0x2f72(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1086:	66 90                	xchg   %ax,%ax

Disassembly of section .text:

0000000000001090 <_start>:
    1090:	31 ed                	xor    %ebp,%ebp
    1092:	49 89 d1             	mov    %rdx,%r9
    1095:	5e                   	pop    %rsi
    1096:	48 89 e2             	mov    %rsp,%rdx
    1099:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    109d:	50                   	push   %rax
    109e:	54                   	push   %rsp
    109f:	4c 8d 05 3a 02 00 00 	lea    0x23a(%rip),%r8        # 12e0 <__libc_csu_fini>
    10a6:	48 8d 0d c3 01 00 00 	lea    0x1c3(%rip),%rcx        # 1270 <__libc_csu_init>
    10ad:	48 8d 3d e6 00 00 00 	lea    0xe6(%rip),%rdi        # 119a <main>
    10b4:	ff 15 26 2f 00 00    	callq  *0x2f26(%rip)        # 3fe0 <__libc_start_main@GLIBC_2.2.5>
    10ba:	f4                   	hlt    
    10bb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000010c0 <deregister_tm_clones>:
    10c0:	48 8d 3d 49 2f 00 00 	lea    0x2f49(%rip),%rdi        # 4010 <__TMC_END__>
    10c7:	55                   	push   %rbp
    10c8:	48 8d 05 41 2f 00 00 	lea    0x2f41(%rip),%rax        # 4010 <__TMC_END__>
    10cf:	48 39 f8             	cmp    %rdi,%rax
    10d2:	48 89 e5             	mov    %rsp,%rbp
    10d5:	74 19                	je     10f0 <deregister_tm_clones+0x30>
    10d7:	48 8b 05 fa 2e 00 00 	mov    0x2efa(%rip),%rax        # 3fd8 <_ITM_deregisterTMCloneTable>
    10de:	48 85 c0             	test   %rax,%rax
    10e1:	74 0d                	je     10f0 <deregister_tm_clones+0x30>
    10e3:	5d                   	pop    %rbp
    10e4:	ff e0                	jmpq   *%rax
    10e6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    10ed:	00 00 00 
    10f0:	5d                   	pop    %rbp
    10f1:	c3                   	retq   
    10f2:	0f 1f 40 00          	nopl   0x0(%rax)
    10f6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    10fd:	00 00 00 

0000000000001100 <register_tm_clones>:
    1100:	48 8d 3d 09 2f 00 00 	lea    0x2f09(%rip),%rdi        # 4010 <__TMC_END__>
    1107:	48 8d 35 02 2f 00 00 	lea    0x2f02(%rip),%rsi        # 4010 <__TMC_END__>
    110e:	55                   	push   %rbp
    110f:	48 29 fe             	sub    %rdi,%rsi
    1112:	48 89 e5             	mov    %rsp,%rbp
    1115:	48 c1 fe 03          	sar    $0x3,%rsi
    1119:	48 89 f0             	mov    %rsi,%rax
    111c:	48 c1 e8 3f          	shr    $0x3f,%rax
    1120:	48 01 c6             	add    %rax,%rsi
    1123:	48 d1 fe             	sar    %rsi
    1126:	74 18                	je     1140 <register_tm_clones+0x40>
    1128:	48 8b 05 c1 2e 00 00 	mov    0x2ec1(%rip),%rax        # 3ff0 <_ITM_registerTMCloneTable>
    112f:	48 85 c0             	test   %rax,%rax
    1132:	74 0c                	je     1140 <register_tm_clones+0x40>
    1134:	5d                   	pop    %rbp
    1135:	ff e0                	jmpq   *%rax
    1137:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    113e:	00 00 
    1140:	5d                   	pop    %rbp
    1141:	c3                   	retq   
    1142:	0f 1f 40 00          	nopl   0x0(%rax)
    1146:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    114d:	00 00 00 

0000000000001150 <__do_global_dtors_aux>:
    1150:	80 3d b9 2e 00 00 00 	cmpb   $0x0,0x2eb9(%rip)        # 4010 <__TMC_END__>
    1157:	75 2f                	jne    1188 <__do_global_dtors_aux+0x38>
    1159:	48 83 3d 97 2e 00 00 	cmpq   $0x0,0x2e97(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1160:	00 
    1161:	55                   	push   %rbp
    1162:	48 89 e5             	mov    %rsp,%rbp
    1165:	74 0c                	je     1173 <__do_global_dtors_aux+0x23>
    1167:	48 8b 3d 9a 2e 00 00 	mov    0x2e9a(%rip),%rdi        # 4008 <__dso_handle>
    116e:	e8 0d ff ff ff       	callq  1080 <__cxa_finalize@plt>
    1173:	e8 48 ff ff ff       	callq  10c0 <deregister_tm_clones>
    1178:	c6 05 91 2e 00 00 01 	movb   $0x1,0x2e91(%rip)        # 4010 <__TMC_END__>
    117f:	5d                   	pop    %rbp
    1180:	c3                   	retq   
    1181:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    1188:	f3 c3                	repz retq 
    118a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000001190 <frame_dummy>:
    1190:	55                   	push   %rbp
    1191:	48 89 e5             	mov    %rsp,%rbp
    1194:	5d                   	pop    %rbp
    1195:	e9 66 ff ff ff       	jmpq   1100 <register_tm_clones>

000000000000119a <main>:
    119a:	55                   	push   %rbp
    119b:	48 89 e5             	mov    %rsp,%rbp
    119e:	48 83 ec 40          	sub    $0x40,%rsp
    11a2:	be 01 00 00 00       	mov    $0x1,%esi
    11a7:	48 8d 3d 56 0e 00 00 	lea    0xe56(%rip),%rdi        # 2004 <_IO_stdin_used+0x4>
    11ae:	e8 9d fe ff ff       	callq  1050 <dlopen@plt>
    11b3:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    11b7:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    11bb:	48 8d 35 56 0e 00 00 	lea    0xe56(%rip),%rsi        # 2018 <_IO_stdin_used+0x18>
    11c2:	48 89 c7             	mov    %rax,%rdi
    11c5:	e8 a6 fe ff ff       	callq  1070 <dlsym@plt>
    11ca:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    11ce:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    11d5:	00 
    11d6:	bf 64 00 00 00       	mov    $0x64,%edi
    11db:	e8 80 fe ff ff       	callq  1060 <malloc@plt>
    11e0:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    11e4:	bf 00 10 02 00       	mov    $0x21000,%edi
    11e9:	e8 72 fe ff ff       	callq  1060 <malloc@plt>
    11ee:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    11f2:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    11f6:	48 05 00 00 02 00    	add    $0x20000,%rax
    11fc:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1200:	c7 45 c8 01 00 00 00 	movl   $0x1,-0x38(%rbp)
    1207:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    120b:	48 89 c6             	mov    %rax,%rsi
    120e:	bf 01 10 00 00       	mov    $0x1001,%edi
    1213:	b8 00 00 00 00       	mov    $0x0,%eax
    1218:	e8 23 fe ff ff       	callq  1040 <arch_prctl@plt>
    121d:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
    1221:	48 8b 75 d8          	mov    -0x28(%rbp),%rsi
    1225:	48 8b 7d f8          	mov    -0x8(%rbp),%rdi
    1229:	44 8b 45 c8          	mov    -0x38(%rbp),%r8d
    122d:	48 89 d0             	mov    %rdx,%rax
    1230:	48 89 fb             	mov    %rdi,%rbx
    1233:	44 89 c7             	mov    %r8d,%edi
    1236:	48 83 c1 02          	add    $0x2,%rcx
    123a:	48 8d 0d 02 00 00 00 	lea    0x2(%rip),%rcx        # 1243 <.RETPOINT>
    1241:	ff d6                	callq  *%rsi

0000000000001243 <.RETPOINT>:
    1243:	90                   	nop
    1244:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1248:	bf 00 00 00 00       	mov    $0x0,%edi
    124d:	ff d0                	callq  *%rax
    124f:	89 45 cc             	mov    %eax,-0x34(%rbp)
    1252:	8b 45 cc             	mov    -0x34(%rbp),%eax
    1255:	89 c6                	mov    %eax,%esi
    1257:	48 8d 3d c8 0d 00 00 	lea    0xdc8(%rip),%rdi        # 2026 <_IO_stdin_used+0x26>
    125e:	b8 00 00 00 00       	mov    $0x0,%eax
    1263:	e8 c8 fd ff ff       	callq  1030 <printf@plt>
    1268:	b8 00 00 00 00       	mov    $0x0,%eax
    126d:	c9                   	leaveq 
    126e:	c3                   	retq   
    126f:	90                   	nop

0000000000001270 <__libc_csu_init>:
    1270:	41 57                	push   %r15
    1272:	41 56                	push   %r14
    1274:	49 89 d7             	mov    %rdx,%r15
    1277:	41 55                	push   %r13
    1279:	41 54                	push   %r12
    127b:	4c 8d 25 06 2b 00 00 	lea    0x2b06(%rip),%r12        # 3d88 <__frame_dummy_init_array_entry>
    1282:	55                   	push   %rbp
    1283:	48 8d 2d 06 2b 00 00 	lea    0x2b06(%rip),%rbp        # 3d90 <__init_array_end>
    128a:	53                   	push   %rbx
    128b:	41 89 fd             	mov    %edi,%r13d
    128e:	49 89 f6             	mov    %rsi,%r14
    1291:	4c 29 e5             	sub    %r12,%rbp
    1294:	48 83 ec 08          	sub    $0x8,%rsp
    1298:	48 c1 fd 03          	sar    $0x3,%rbp
    129c:	e8 5f fd ff ff       	callq  1000 <_init>
    12a1:	48 85 ed             	test   %rbp,%rbp
    12a4:	74 20                	je     12c6 <__libc_csu_init+0x56>
    12a6:	31 db                	xor    %ebx,%ebx
    12a8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    12af:	00 
    12b0:	4c 89 fa             	mov    %r15,%rdx
    12b3:	4c 89 f6             	mov    %r14,%rsi
    12b6:	44 89 ef             	mov    %r13d,%edi
    12b9:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
    12bd:	48 83 c3 01          	add    $0x1,%rbx
    12c1:	48 39 dd             	cmp    %rbx,%rbp
    12c4:	75 ea                	jne    12b0 <__libc_csu_init+0x40>
    12c6:	48 83 c4 08          	add    $0x8,%rsp
    12ca:	5b                   	pop    %rbx
    12cb:	5d                   	pop    %rbp
    12cc:	41 5c                	pop    %r12
    12ce:	41 5d                	pop    %r13
    12d0:	41 5e                	pop    %r14
    12d2:	41 5f                	pop    %r15
    12d4:	c3                   	retq   
    12d5:	90                   	nop
    12d6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    12dd:	00 00 00 

00000000000012e0 <__libc_csu_fini>:
    12e0:	f3 c3                	repz retq 

Disassembly of section .fini:

00000000000012e4 <_fini>:
    12e4:	48 83 ec 08          	sub    $0x8,%rsp
    12e8:	48 83 c4 08          	add    $0x8,%rsp
    12ec:	c3                   	retq   

Disassembly of section .rodata:

0000000000002000 <_IO_stdin_used>:
    2000:	01 00                	add    %eax,(%rax)
    2002:	02 00                	add    (%rax),%al
    2004:	2e 2f                	cs (bad) 
    2006:	65 6e                	outsb  %gs:(%rsi),(%dx)
    2008:	63 6c 61 76          	movslq 0x76(%rcx,%riz,2),%ebp
    200c:	65 2e 73 69          	gs jae,pn 2079 <__GNU_EH_FRAME_HDR+0x4d>
    2010:	67 6e                	outsb  %ds:(%esi),(%dx)
    2012:	65 64 2e 73 6f       	gs fs jae,pn 2086 <__GNU_EH_FRAME_HDR+0x5a>
    2017:	00 65 6e             	add    %ah,0x6e(%rbp)
    201a:	63 6c 61 76          	movslq 0x76(%rcx,%riz,2),%ebp
    201e:	65 5f                	gs pop %rdi
    2020:	65 6e                	outsb  %gs:(%rsi),(%dx)
    2022:	74 72                	je     2096 <__GNU_EH_FRAME_HDR+0x6a>
    2024:	79 00                	jns    2026 <_IO_stdin_used+0x26>
    2026:	25                   	.byte 0x25
    2027:	64                   	fs
	...

Disassembly of section .eh_frame_hdr:

000000000000202c <__GNU_EH_FRAME_HDR>:
    202c:	01 1b                	add    %ebx,(%rbx)
    202e:	03 3b                	add    (%rbx),%edi
    2030:	38 00                	cmp    %al,(%rax)
    2032:	00 00                	add    %al,(%rax)
    2034:	06                   	(bad)  
    2035:	00 00                	add    %al,(%rax)
    2037:	00 f4                	add    %dh,%ah
    2039:	ef                   	out    %eax,(%dx)
    203a:	ff                   	(bad)  
    203b:	ff 84 00 00 00 54 f0 	incl   -0xfac0000(%rax,%rax,1)
    2042:	ff                   	(bad)  
    2043:	ff ac 00 00 00 64 f0 	ljmp   *-0xf9c0000(%rax,%rax,1)
    204a:	ff                   	(bad)  
    204b:	ff 54 00 00          	callq  *0x0(%rax,%rax,1)
    204f:	00 6e f1             	add    %ch,-0xf(%rsi)
    2052:	ff                   	(bad)  
    2053:	ff c4                	inc    %esp
    2055:	00 00                	add    %al,(%rax)
    2057:	00 44 f2 ff          	add    %al,-0x1(%rdx,%rsi,8)
    205b:	ff e4                	jmpq   *%rsp
    205d:	00 00                	add    %al,(%rax)
    205f:	00 b4 f2 ff ff 2c 01 	add    %dh,0x12cffff(%rdx,%rsi,8)
	...

Disassembly of section .eh_frame:

0000000000002068 <__FRAME_END__-0x104>:
    2068:	14 00                	adc    $0x0,%al
    206a:	00 00                	add    %al,(%rax)
    206c:	00 00                	add    %al,(%rax)
    206e:	00 00                	add    %al,(%rax)
    2070:	01 7a 52             	add    %edi,0x52(%rdx)
    2073:	00 01                	add    %al,(%rcx)
    2075:	78 10                	js     2087 <__GNU_EH_FRAME_HDR+0x5b>
    2077:	01 1b                	add    %ebx,(%rbx)
    2079:	0c 07                	or     $0x7,%al
    207b:	08 90 01 07 10 14    	or     %dl,0x14100701(%rax)
    2081:	00 00                	add    %al,(%rax)
    2083:	00 1c 00             	add    %bl,(%rax,%rax,1)
    2086:	00 00                	add    %al,(%rax)
    2088:	08 f0                	or     %dh,%al
    208a:	ff                   	(bad)  
    208b:	ff 2b                	ljmp   *(%rbx)
	...
    2095:	00 00                	add    %al,(%rax)
    2097:	00 14 00             	add    %dl,(%rax,%rax,1)
    209a:	00 00                	add    %al,(%rax)
    209c:	00 00                	add    %al,(%rax)
    209e:	00 00                	add    %al,(%rax)
    20a0:	01 7a 52             	add    %edi,0x52(%rdx)
    20a3:	00 01                	add    %al,(%rcx)
    20a5:	78 10                	js     20b7 <__GNU_EH_FRAME_HDR+0x8b>
    20a7:	01 1b                	add    %ebx,(%rbx)
    20a9:	0c 07                	or     $0x7,%al
    20ab:	08 90 01 00 00 24    	or     %dl,0x24000001(%rax)
    20b1:	00 00                	add    %al,(%rax)
    20b3:	00 1c 00             	add    %bl,(%rax,%rax,1)
    20b6:	00 00                	add    %al,(%rax)
    20b8:	68 ef ff ff 60       	pushq  $0x60ffffef
    20bd:	00 00                	add    %al,(%rax)
    20bf:	00 00                	add    %al,(%rax)
    20c1:	0e                   	(bad)  
    20c2:	10 46 0e             	adc    %al,0xe(%rsi)
    20c5:	18 4a 0f             	sbb    %cl,0xf(%rdx)
    20c8:	0b 77 08             	or     0x8(%rdi),%esi
    20cb:	80 00 3f             	addb   $0x3f,(%rax)
    20ce:	1a 3b                	sbb    (%rbx),%bh
    20d0:	2a 33                	sub    (%rbx),%dh
    20d2:	24 22                	and    $0x22,%al
    20d4:	00 00                	add    %al,(%rax)
    20d6:	00 00                	add    %al,(%rax)
    20d8:	14 00                	adc    $0x0,%al
    20da:	00 00                	add    %al,(%rax)
    20dc:	44 00 00             	add    %r8b,(%rax)
    20df:	00 a0 ef ff ff 08    	add    %ah,0x8ffffef(%rax)
	...
    20ed:	00 00                	add    %al,(%rax)
    20ef:	00 1c 00             	add    %bl,(%rax,%rax,1)
    20f2:	00 00                	add    %al,(%rax)
    20f4:	5c                   	pop    %rsp
    20f5:	00 00                	add    %al,(%rax)
    20f7:	00 a2 f0 ff ff d5    	add    %ah,-0x2a000010(%rdx)
    20fd:	00 00                	add    %al,(%rax)
    20ff:	00 00                	add    %al,(%rax)
    2101:	41 0e                	rex.B (bad) 
    2103:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
    2109:	02 d0                	add    %al,%dl
    210b:	0c 07                	or     $0x7,%al
    210d:	08 00                	or     %al,(%rax)
    210f:	00 44 00 00          	add    %al,0x0(%rax,%rax,1)
    2113:	00 7c 00 00          	add    %bh,0x0(%rax,%rax,1)
    2117:	00 58 f1             	add    %bl,-0xf(%rax)
    211a:	ff                   	(bad)  
    211b:	ff 65 00             	jmpq   *0x0(%rbp)
    211e:	00 00                	add    %al,(%rax)
    2120:	00 42 0e             	add    %al,0xe(%rdx)
    2123:	10 8f 02 42 0e 18    	adc    %cl,0x180e4202(%rdi)
    2129:	8e 03                	mov    (%rbx),%es
    212b:	45 0e                	rex.RB (bad) 
    212d:	20 8d 04 42 0e 28    	and    %cl,0x280e4204(%rbp)
    2133:	8c 05 48 0e 30 86    	mov    %es,-0x79cff1b8(%rip)        # ffffffff86302f81 <_end+0xffffffff862fef69>
    2139:	06                   	(bad)  
    213a:	48 0e                	rex.W (bad) 
    213c:	38 83 07 4d 0e 40    	cmp    %al,0x400e4d07(%rbx)
    2142:	72 0e                	jb     2152 <__GNU_EH_FRAME_HDR+0x126>
    2144:	38 41 0e             	cmp    %al,0xe(%rcx)
    2147:	30 41 0e             	xor    %al,0xe(%rcx)
    214a:	28 42 0e             	sub    %al,0xe(%rdx)
    214d:	20 42 0e             	and    %al,0xe(%rdx)
    2150:	18 42 0e             	sbb    %al,0xe(%rdx)
    2153:	10 42 0e             	adc    %al,0xe(%rdx)
    2156:	08 00                	or     %al,(%rax)
    2158:	10 00                	adc    %al,(%rax)
    215a:	00 00                	add    %al,(%rax)
    215c:	c4                   	(bad)  
    215d:	00 00                	add    %al,(%rax)
    215f:	00 80 f1 ff ff 02    	add    %al,0x2fffff1(%rax)
    2165:	00 00                	add    %al,(%rax)
    2167:	00 00                	add    %al,(%rax)
    2169:	00 00                	add    %al,(%rax)
	...

000000000000216c <__FRAME_END__>:
    216c:	00 00                	add    %al,(%rax)
	...

Disassembly of section .init_array:

0000000000003d88 <__frame_dummy_init_array_entry>:
    3d88:	90                   	nop
    3d89:	11 00                	adc    %eax,(%rax)
    3d8b:	00 00                	add    %al,(%rax)
    3d8d:	00 00                	add    %al,(%rax)
	...

Disassembly of section .fini_array:

0000000000003d90 <__do_global_dtors_aux_fini_array_entry>:
    3d90:	50                   	push   %rax
    3d91:	11 00                	adc    %eax,(%rax)
    3d93:	00 00                	add    %al,(%rax)
    3d95:	00 00                	add    %al,(%rax)
	...

Disassembly of section .dynamic:

0000000000003d98 <_DYNAMIC>:
    3d98:	01 00                	add    %eax,(%rax)
    3d9a:	00 00                	add    %al,(%rax)
    3d9c:	00 00                	add    %al,(%rax)
    3d9e:	00 00                	add    %al,(%rax)
    3da0:	01 00                	add    %eax,(%rax)
    3da2:	00 00                	add    %al,(%rax)
    3da4:	00 00                	add    %al,(%rax)
    3da6:	00 00                	add    %al,(%rax)
    3da8:	01 00                	add    %eax,(%rax)
    3daa:	00 00                	add    %al,(%rax)
    3dac:	00 00                	add    %al,(%rax)
    3dae:	00 00                	add    %al,(%rax)
    3db0:	5e                   	pop    %rsi
    3db1:	00 00                	add    %al,(%rax)
    3db3:	00 00                	add    %al,(%rax)
    3db5:	00 00                	add    %al,(%rax)
    3db7:	00 0c 00             	add    %cl,(%rax,%rax,1)
    3dba:	00 00                	add    %al,(%rax)
    3dbc:	00 00                	add    %al,(%rax)
    3dbe:	00 00                	add    %al,(%rax)
    3dc0:	00 10                	add    %dl,(%rax)
    3dc2:	00 00                	add    %al,(%rax)
    3dc4:	00 00                	add    %al,(%rax)
    3dc6:	00 00                	add    %al,(%rax)
    3dc8:	0d 00 00 00 00       	or     $0x0,%eax
    3dcd:	00 00                	add    %al,(%rax)
    3dcf:	00 e4                	add    %ah,%ah
    3dd1:	12 00                	adc    (%rax),%al
    3dd3:	00 00                	add    %al,(%rax)
    3dd5:	00 00                	add    %al,(%rax)
    3dd7:	00 19                	add    %bl,(%rcx)
    3dd9:	00 00                	add    %al,(%rax)
    3ddb:	00 00                	add    %al,(%rax)
    3ddd:	00 00                	add    %al,(%rax)
    3ddf:	00 88 3d 00 00 00    	add    %cl,0x3d(%rax)
    3de5:	00 00                	add    %al,(%rax)
    3de7:	00 1b                	add    %bl,(%rbx)
    3de9:	00 00                	add    %al,(%rax)
    3deb:	00 00                	add    %al,(%rax)
    3ded:	00 00                	add    %al,(%rax)
    3def:	00 08                	add    %cl,(%rax)
    3df1:	00 00                	add    %al,(%rax)
    3df3:	00 00                	add    %al,(%rax)
    3df5:	00 00                	add    %al,(%rax)
    3df7:	00 1a                	add    %bl,(%rdx)
    3df9:	00 00                	add    %al,(%rax)
    3dfb:	00 00                	add    %al,(%rax)
    3dfd:	00 00                	add    %al,(%rax)
    3dff:	00 90 3d 00 00 00    	add    %dl,0x3d(%rax)
    3e05:	00 00                	add    %al,(%rax)
    3e07:	00 1c 00             	add    %bl,(%rax,%rax,1)
    3e0a:	00 00                	add    %al,(%rax)
    3e0c:	00 00                	add    %al,(%rax)
    3e0e:	00 00                	add    %al,(%rax)
    3e10:	08 00                	or     %al,(%rax)
    3e12:	00 00                	add    %al,(%rax)
    3e14:	00 00                	add    %al,(%rax)
    3e16:	00 00                	add    %al,(%rax)
    3e18:	f5                   	cmc    
    3e19:	fe                   	(bad)  
    3e1a:	ff 6f 00             	ljmp   *0x0(%rdi)
    3e1d:	00 00                	add    %al,(%rax)
    3e1f:	00 08                	add    %cl,(%rax)
    3e21:	03 00                	add    (%rax),%eax
    3e23:	00 00                	add    %al,(%rax)
    3e25:	00 00                	add    %al,(%rax)
    3e27:	00 05 00 00 00 00    	add    %al,0x0(%rip)        # 3e2d <_DYNAMIC+0x95>
    3e2d:	00 00                	add    %al,(%rax)
    3e2f:	00 38                	add    %bh,(%rax)
    3e31:	04 00                	add    $0x0,%al
    3e33:	00 00                	add    %al,(%rax)
    3e35:	00 00                	add    %al,(%rax)
    3e37:	00 06                	add    %al,(%rsi)
    3e39:	00 00                	add    %al,(%rax)
    3e3b:	00 00                	add    %al,(%rax)
    3e3d:	00 00                	add    %al,(%rax)
    3e3f:	00 30                	add    %dh,(%rax)
    3e41:	03 00                	add    (%rax),%eax
    3e43:	00 00                	add    %al,(%rax)
    3e45:	00 00                	add    %al,(%rax)
    3e47:	00 0a                	add    %cl,(%rdx)
    3e49:	00 00                	add    %al,(%rax)
    3e4b:	00 00                	add    %al,(%rax)
    3e4d:	00 00                	add    %al,(%rax)
    3e4f:	00 ae 00 00 00 00    	add    %ch,0x0(%rsi)
    3e55:	00 00                	add    %al,(%rax)
    3e57:	00 0b                	add    %cl,(%rbx)
    3e59:	00 00                	add    %al,(%rax)
    3e5b:	00 00                	add    %al,(%rax)
    3e5d:	00 00                	add    %al,(%rax)
    3e5f:	00 18                	add    %bl,(%rax)
    3e61:	00 00                	add    %al,(%rax)
    3e63:	00 00                	add    %al,(%rax)
    3e65:	00 00                	add    %al,(%rax)
    3e67:	00 15 00 00 00 00    	add    %dl,0x0(%rip)        # 3e6d <_DYNAMIC+0xd5>
	...
    3e75:	00 00                	add    %al,(%rax)
    3e77:	00 03                	add    %al,(%rbx)
    3e79:	00 00                	add    %al,(%rax)
    3e7b:	00 00                	add    %al,(%rax)
    3e7d:	00 00                	add    %al,(%rax)
    3e7f:	00 98 3f 00 00 00    	add    %bl,0x3f(%rax)
    3e85:	00 00                	add    %al,(%rax)
    3e87:	00 02                	add    %al,(%rdx)
    3e89:	00 00                	add    %al,(%rax)
    3e8b:	00 00                	add    %al,(%rax)
    3e8d:	00 00                	add    %al,(%rax)
    3e8f:	00 78 00             	add    %bh,0x0(%rax)
    3e92:	00 00                	add    %al,(%rax)
    3e94:	00 00                	add    %al,(%rax)
    3e96:	00 00                	add    %al,(%rax)
    3e98:	14 00                	adc    $0x0,%al
    3e9a:	00 00                	add    %al,(%rax)
    3e9c:	00 00                	add    %al,(%rax)
    3e9e:	00 00                	add    %al,(%rax)
    3ea0:	07                   	(bad)  
    3ea1:	00 00                	add    %al,(%rax)
    3ea3:	00 00                	add    %al,(%rax)
    3ea5:	00 00                	add    %al,(%rax)
    3ea7:	00 17                	add    %dl,(%rdi)
	...
    3eb1:	06                   	(bad)  
    3eb2:	00 00                	add    %al,(%rax)
    3eb4:	00 00                	add    %al,(%rax)
    3eb6:	00 00                	add    %al,(%rax)
    3eb8:	07                   	(bad)  
    3eb9:	00 00                	add    %al,(%rax)
    3ebb:	00 00                	add    %al,(%rax)
    3ebd:	00 00                	add    %al,(%rax)
    3ebf:	00 40 05             	add    %al,0x5(%rax)
    3ec2:	00 00                	add    %al,(%rax)
    3ec4:	00 00                	add    %al,(%rax)
    3ec6:	00 00                	add    %al,(%rax)
    3ec8:	08 00                	or     %al,(%rax)
    3eca:	00 00                	add    %al,(%rax)
    3ecc:	00 00                	add    %al,(%rax)
    3ece:	00 00                	add    %al,(%rax)
    3ed0:	c0 00 00             	rolb   $0x0,(%rax)
    3ed3:	00 00                	add    %al,(%rax)
    3ed5:	00 00                	add    %al,(%rax)
    3ed7:	00 09                	add    %cl,(%rcx)
    3ed9:	00 00                	add    %al,(%rax)
    3edb:	00 00                	add    %al,(%rax)
    3edd:	00 00                	add    %al,(%rax)
    3edf:	00 18                	add    %bl,(%rax)
    3ee1:	00 00                	add    %al,(%rax)
    3ee3:	00 00                	add    %al,(%rax)
    3ee5:	00 00                	add    %al,(%rax)
    3ee7:	00 18                	add    %bl,(%rax)
	...
    3ef5:	00 00                	add    %al,(%rax)
    3ef7:	00 fb                	add    %bh,%bl
    3ef9:	ff                   	(bad)  
    3efa:	ff 6f 00             	ljmp   *0x0(%rdi)
    3efd:	00 00                	add    %al,(%rax)
    3eff:	00 01                	add    %al,(%rcx)
    3f01:	00 00                	add    %al,(%rax)
    3f03:	08 00                	or     %al,(%rax)
    3f05:	00 00                	add    %al,(%rax)
    3f07:	00 fe                	add    %bh,%dh
    3f09:	ff                   	(bad)  
    3f0a:	ff 6f 00             	ljmp   *0x0(%rdi)
    3f0d:	00 00                	add    %al,(%rax)
    3f0f:	00 00                	add    %al,(%rax)
    3f11:	05 00 00 00 00       	add    $0x0,%eax
    3f16:	00 00                	add    %al,(%rax)
    3f18:	ff                   	(bad)  
    3f19:	ff                   	(bad)  
    3f1a:	ff 6f 00             	ljmp   *0x0(%rdi)
    3f1d:	00 00                	add    %al,(%rax)
    3f1f:	00 02                	add    %al,(%rdx)
    3f21:	00 00                	add    %al,(%rax)
    3f23:	00 00                	add    %al,(%rax)
    3f25:	00 00                	add    %al,(%rax)
    3f27:	00 f0                	add    %dh,%al
    3f29:	ff                   	(bad)  
    3f2a:	ff 6f 00             	ljmp   *0x0(%rdi)
    3f2d:	00 00                	add    %al,(%rax)
    3f2f:	00 e6                	add    %ah,%dh
    3f31:	04 00                	add    $0x0,%al
    3f33:	00 00                	add    %al,(%rax)
    3f35:	00 00                	add    %al,(%rax)
    3f37:	00 f9                	add    %bh,%cl
    3f39:	ff                   	(bad)  
    3f3a:	ff 6f 00             	ljmp   *0x0(%rdi)
    3f3d:	00 00                	add    %al,(%rax)
    3f3f:	00 03                	add    %al,(%rbx)
	...

Disassembly of section .got:

0000000000003f98 <_GLOBAL_OFFSET_TABLE_>:
    3f98:	98                   	cwtl   
    3f99:	3d 00 00 00 00       	cmp    $0x0,%eax
	...
    3fae:	00 00                	add    %al,(%rax)
    3fb0:	36 10 00             	adc    %al,%ss:(%rax)
    3fb3:	00 00                	add    %al,(%rax)
    3fb5:	00 00                	add    %al,(%rax)
    3fb7:	00 46 10             	add    %al,0x10(%rsi)
    3fba:	00 00                	add    %al,(%rax)
    3fbc:	00 00                	add    %al,(%rax)
    3fbe:	00 00                	add    %al,(%rax)
    3fc0:	56                   	push   %rsi
    3fc1:	10 00                	adc    %al,(%rax)
    3fc3:	00 00                	add    %al,(%rax)
    3fc5:	00 00                	add    %al,(%rax)
    3fc7:	00 66 10             	add    %ah,0x10(%rsi)
    3fca:	00 00                	add    %al,(%rax)
    3fcc:	00 00                	add    %al,(%rax)
    3fce:	00 00                	add    %al,(%rax)
    3fd0:	76 10                	jbe    3fe2 <_GLOBAL_OFFSET_TABLE_+0x4a>
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

Disassembly of section .debug_aranges:

0000000000000000 <.debug_aranges>:
   0:	2c 00                	sub    $0x0,%al
   2:	00 00                	add    %al,(%rax)
   4:	02 00                	add    (%rax),%al
   6:	00 00                	add    %al,(%rax)
   8:	00 00                	add    %al,(%rax)
   a:	08 00                	or     %al,(%rax)
   c:	00 00                	add    %al,(%rax)
   e:	00 00                	add    %al,(%rax)
  10:	9a                   	(bad)  
  11:	11 00                	adc    %eax,(%rax)
  13:	00 00                	add    %al,(%rax)
  15:	00 00                	add    %al,(%rax)
  17:	00 d5                	add    %dl,%ch
	...

Disassembly of section .debug_info:

0000000000000000 <.debug_info>:
   0:	cb                   	lret   
   1:	04 00                	add    $0x0,%al
   3:	00 04 00             	add    %al,(%rax,%rax,1)
   6:	00 00                	add    %al,(%rax)
   8:	00 00                	add    %al,(%rax)
   a:	08 01                	or     %al,(%rcx)
   c:	da 01                	fiaddl (%rcx)
   e:	00 00                	add    %al,(%rax)
  10:	0c b6                	or     $0xb6,%al
  12:	02 00                	add    (%rax),%al
  14:	00 6c 00 00          	add    %ch,0x0(%rax,%rax,1)
  18:	00 9a 11 00 00 00    	add    %bl,0x11(%rdx)
  1e:	00 00                	add    %al,(%rax)
  20:	00 d5                	add    %dl,%ch
	...
  2a:	00 00                	add    %al,(%rax)
  2c:	00 02                	add    %al,(%rdx)
  2e:	30 00                	xor    %al,(%rax)
  30:	00 00                	add    %al,(%rax)
  32:	02 d8                	add    %al,%bl
  34:	38 00                	cmp    %al,(%rax)
  36:	00 00                	add    %al,(%rax)
  38:	03 08                	add    (%rax),%ecx
  3a:	07                   	(bad)  
  3b:	58                   	pop    %rax
  3c:	01 00                	add    %eax,(%rax)
  3e:	00 03                	add    %al,(%rbx)
  40:	01 08                	add    %ecx,(%rax)
  42:	28 01                	sub    %al,(%rcx)
  44:	00 00                	add    %al,(%rax)
  46:	03 02                	add    (%rdx),%eax
  48:	07                   	(bad)  
  49:	6c                   	insb   (%dx),%es:(%rdi)
  4a:	02 00                	add    (%rax),%al
  4c:	00 03                	add    %al,(%rbx)
  4e:	04 07                	add    $0x7,%al
  50:	5d                   	pop    %rbp
  51:	01 00                	add    %eax,(%rax)
  53:	00 03                	add    %al,(%rbx)
  55:	01 06                	add    %eax,(%rsi)
  57:	2a 01                	sub    (%rcx),%al
  59:	00 00                	add    %al,(%rax)
  5b:	02 8e 01 00 00 03    	add    0x3000001(%rsi),%cl
  61:	25 3f 00 00 00       	and    $0x3f,%eax
  66:	03 02                	add    (%rdx),%eax
  68:	05 26 00 00 00       	add    $0x26,%eax
  6d:	04 04                	add    $0x4,%al
  6f:	05 69 6e 74 00       	add    $0x746e69,%eax
  74:	02 51 00             	add    0x0(%rcx),%dl
  77:	00 00                	add    %al,(%rax)
  79:	03 29                	add    (%rcx),%ebp
  7b:	4d 00 00             	rex.WRB add %r8b,(%r8)
  7e:	00 03                	add    %al,(%rbx)
  80:	08 05 c3 00 00 00    	or     %al,0xc3(%rip)        # 149 <_init-0xeb7>
  86:	02 50 02             	add    0x2(%rax),%dl
  89:	00 00                	add    %al,(%rax)
  8b:	03 2c 38             	add    (%rax,%rdi,1),%ebp
  8e:	00 00                	add    %al,(%rax)
  90:	00 02                	add    %al,(%rdx)
  92:	c1 02 00             	roll   $0x0,(%rdx)
  95:	00 03                	add    %al,(%rbx)
  97:	8c 7f 00             	mov    %?,0x0(%rdi)
  9a:	00 00                	add    %al,(%rax)
  9c:	02 9d 02 00 00 03    	add    0x3000002(%rbp),%bl
  a2:	8d 7f 00             	lea    0x0(%rdi),%edi
  a5:	00 00                	add    %al,(%rax)
  a7:	05 08 06 08 af       	add    $0xaf080608,%eax
  ac:	00 00                	add    %al,(%rax)
  ae:	00 03                	add    %al,(%rbx)
  b0:	01 06                	add    %eax,(%rsi)
  b2:	31 01                	xor    %eax,(%rcx)
  b4:	00 00                	add    %al,(%rax)
  b6:	07                   	(bad)  
  b7:	af                   	scas   %es:(%rdi),%eax
  b8:	00 00                	add    %al,(%rax)
  ba:	00 08                	add    %cl,(%rax)
  bc:	07                   	(bad)  
  bd:	00 00                	add    %al,(%rax)
  bf:	00 d8                	add    %bl,%al
  c1:	04 f5                	add    $0xf5,%al
  c3:	3b 02                	cmp    (%rdx),%eax
  c5:	00 00                	add    %al,(%rax)
  c7:	09 4a 00             	or     %ecx,0x0(%rdx)
  ca:	00 00                	add    %al,(%rax)
  cc:	04 f6                	add    $0xf6,%al
  ce:	6d                   	insl   (%dx),%es:(%rdi)
  cf:	00 00                	add    %al,(%rax)
  d1:	00 00                	add    %al,(%rax)
  d3:	09 b5 01 00 00 04    	or     %esi,0x4000001(%rbp)
  d9:	fb                   	sti    
  da:	a9 00 00 00 08       	test   $0x8000000,%eax
  df:	09 9f 00 00 00 04    	or     %ebx,0x4000000(%rdi)
  e5:	fc                   	cld    
  e6:	a9 00 00 00 10       	test   $0x10000000,%eax
  eb:	09 f8                	or     %edi,%eax
  ed:	02 00                	add    (%rax),%al
  ef:	00 04 fd a9 00 00 00 	add    %al,0xa9(,%rdi,8)
  f6:	18 09                	sbb    %cl,(%rcx)
  f8:	9d                   	popfq  
  f9:	01 00                	add    %eax,(%rax)
  fb:	00 04 fe             	add    %al,(%rsi,%rdi,8)
  fe:	a9 00 00 00 20       	test   $0x20000000,%eax
 103:	09 3c 00             	or     %edi,(%rax,%rax,1)
 106:	00 00                	add    %al,(%rax)
 108:	04 ff                	add    $0xff,%al
 10a:	a9 00 00 00 28       	test   $0x28000000,%eax
 10f:	0a 8f 02 00 00 04    	or     0x4000002(%rdi),%cl
 115:	00 01                	add    %al,(%rcx)
 117:	a9 00 00 00 30       	test   $0x30000000,%eax
 11c:	0a 36                	or     (%rsi),%dh
 11e:	01 00                	add    %eax,(%rax)
 120:	00 04 01             	add    %al,(%rcx,%rax,1)
 123:	01 a9 00 00 00 38    	add    %ebp,0x38000000(%rcx)
 129:	0a c2                	or     %dl,%al
 12b:	01 00                	add    %eax,(%rax)
 12d:	00 04 02             	add    %al,(%rdx,%rax,1)
 130:	01 a9 00 00 00 40    	add    %ebp,0x40000000(%rcx)
 136:	0a 1d 03 00 00 04    	or     0x4000003(%rip),%bl        # 400013f <_end+0x3ffc127>
 13c:	04 01                	add    $0x1,%al
 13e:	a9 00 00 00 48       	test   $0x48000000,%eax
 143:	0a c9                	or     %cl,%cl
 145:	02 00                	add    (%rax),%al
 147:	00 04 05 01 a9 00 00 	add    %al,0xa901(,%rax,1)
 14e:	00 50 0a             	add    %dl,0xa(%rax)
 151:	19 00                	sbb    %eax,(%rax)
 153:	00 00                	add    %al,(%rax)
 155:	04 06                	add    $0x6,%al
 157:	01 a9 00 00 00 58    	add    %ebp,0x58000000(%rcx)
 15d:	0a 96 00 00 00 04    	or     0x4000000(%rsi),%dl
 163:	08 01                	or     %al,(%rcx)
 165:	73 02                	jae    169 <_init-0xe97>
 167:	00 00                	add    %al,(%rax)
 169:	60                   	(bad)  
 16a:	0a 00                	or     (%rax),%al
 16c:	00 00                	add    %al,(%rax)
 16e:	00 04 0a             	add    %al,(%rdx,%rcx,1)
 171:	01 79 02             	add    %edi,0x2(%rcx)
 174:	00 00                	add    %al,(%rax)
 176:	68 0a a7 02 00       	pushq  $0x2a70a
 17b:	00 04 0c             	add    %al,(%rsp,%rcx,1)
 17e:	01 6d 00             	add    %ebp,0x0(%rbp)
 181:	00 00                	add    %al,(%rax)
 183:	70 0a                	jo     18f <_init-0xe71>
 185:	ea                   	(bad)  
 186:	02 00                	add    (%rax),%al
 188:	00 04 10             	add    %al,(%rax,%rdx,1)
 18b:	01 6d 00             	add    %ebp,0x0(%rbp)
 18e:	00 00                	add    %al,(%rax)
 190:	74 0a                	je     19c <_init-0xe64>
 192:	15 01 00 00 04       	adc    $0x4000001,%eax
 197:	12 01                	adc    (%rcx),%al
 199:	91                   	xchg   %eax,%ecx
 19a:	00 00                	add    %al,(%rax)
 19c:	00 78 0a             	add    %bh,0xa(%rax)
 19f:	e6 00                	out    %al,$0x0
 1a1:	00 00                	add    %al,(%rax)
 1a3:	04 16                	add    $0x16,%al
 1a5:	01 46 00             	add    %eax,0x0(%rsi)
 1a8:	00 00                	add    %al,(%rax)
 1aa:	80 0a 0e             	orb    $0xe,(%rdx)
 1ad:	03 00                	add    (%rax),%eax
 1af:	00 04 17             	add    %al,(%rdi,%rdx,1)
 1b2:	01 54 00 00          	add    %edx,0x0(%rax,%rax,1)
 1b6:	00 82 0a 84 01 00    	add    %al,0x1840a(%rdx)
 1bc:	00 04 18             	add    %al,(%rax,%rbx,1)
 1bf:	01 7f 02             	add    %edi,0x2(%rdi)
 1c2:	00 00                	add    %al,(%rax)
 1c4:	83 0a cc             	orl    $0xffffffcc,(%rdx)
 1c7:	00 00                	add    %al,(%rax)
 1c9:	00 04 1c             	add    %al,(%rsp,%rbx,1)
 1cc:	01 8f 02 00 00 88    	add    %ecx,-0x77fffffe(%rdi)
 1d2:	0a 19                	or     (%rcx),%bl
 1d4:	01 00                	add    %eax,(%rax)
 1d6:	00 04 25 01 9c 00 00 	add    %al,0x9c01
 1dd:	00 90 0a 2d 02 00    	add    %dl,0x22d0a(%rax)
 1e3:	00 04 2d 01 a7 00 00 	add    %al,0xa701(,%rbp,1)
 1ea:	00 98 0a 34 02 00    	add    %bl,0x2340a(%rax)
 1f0:	00 04 2e             	add    %al,(%rsi,%rbp,1)
 1f3:	01 a7 00 00 00 a0    	add    %esp,-0x60000000(%rdi)
 1f9:	0a 3b                	or     (%rbx),%bh
 1fb:	02 00                	add    (%rax),%al
 1fd:	00 04 2f             	add    %al,(%rdi,%rbp,1)
 200:	01 a7 00 00 00 a8    	add    %esp,-0x58000000(%rdi)
 206:	0a 42 02             	or     0x2(%rdx),%al
 209:	00 00                	add    %al,(%rax)
 20b:	04 30                	add    $0x30,%al
 20d:	01 a7 00 00 00 b0    	add    %esp,-0x50000000(%rdi)
 213:	0a 49 02             	or     0x2(%rcx),%cl
 216:	00 00                	add    %al,(%rax)
 218:	04 32                	add    $0x32,%al
 21a:	01 2d 00 00 00 b8    	add    %ebp,-0x48000000(%rip)        # ffffffffb8000220 <_end+0xffffffffb7ffc208>
 220:	0a f2                	or     %dl,%dh
 222:	02 00                	add    (%rax),%al
 224:	00 04 33             	add    %al,(%rbx,%rsi,1)
 227:	01 6d 00             	add    %ebp,0x0(%rbp)
 22a:	00 00                	add    %al,(%rax)
 22c:	c0 0a ac             	rorb   $0xac,(%rdx)
 22f:	01 00                	add    %eax,(%rax)
 231:	00 04 35 01 95 02 00 	add    %al,0x29501(,%rsi,1)
 238:	00 c4                	add    %al,%ah
 23a:	00 0b                	add    %cl,(%rbx)
 23c:	55                   	push   %rbp
 23d:	03 00                	add    (%rax),%eax
 23f:	00 04 9a             	add    %al,(%rdx,%rbx,4)
 242:	08 79 01             	or     %bh,0x1(%rcx)
 245:	00 00                	add    %al,(%rax)
 247:	18 04 a0             	sbb    %al,(%rax,%riz,4)
 24a:	73 02                	jae    24e <_init-0xdb2>
 24c:	00 00                	add    %al,(%rax)
 24e:	09 27                	or     %esp,(%rdi)
 250:	02 00                	add    (%rax),%al
 252:	00 04 a1             	add    %al,(%rcx,%riz,4)
 255:	73 02                	jae    259 <_init-0xda7>
 257:	00 00                	add    %al,(%rax)
 259:	00 09                	add    %cl,(%rcx)
 25b:	0f 01 00             	sgdt   (%rax)
 25e:	00 04 a2             	add    %al,(%rdx,%riz,4)
 261:	79 02                	jns    265 <_init-0xd9b>
 263:	00 00                	add    %al,(%rax)
 265:	08 09                	or     %cl,(%rcx)
 267:	00 01                	add    %al,(%rcx)
 269:	00 00                	add    %al,(%rax)
 26b:	04 a6                	add    $0xa6,%al
 26d:	6d                   	insl   (%dx),%es:(%rdi)
 26e:	00 00                	add    %al,(%rax)
 270:	00 10                	add    %dl,(%rax)
 272:	00 06                	add    %al,(%rsi)
 274:	08 42 02             	or     %al,0x2(%rdx)
 277:	00 00                	add    %al,(%rax)
 279:	06                   	(bad)  
 27a:	08 bb 00 00 00 0c    	or     %bh,0xc000000(%rbx)
 280:	af                   	scas   %es:(%rdi),%eax
 281:	00 00                	add    %al,(%rax)
 283:	00 8f 02 00 00 0d    	add    %cl,0xd000002(%rdi)
 289:	38 00                	cmp    %al,(%rax)
 28b:	00 00                	add    %al,(%rax)
 28d:	00 00                	add    %al,(%rax)
 28f:	06                   	(bad)  
 290:	08 3b                	or     %bh,(%rbx)
 292:	02 00                	add    (%rax),%al
 294:	00 0c af             	add    %cl,(%rdi,%rbp,4)
 297:	00 00                	add    %al,(%rax)
 299:	00 a5 02 00 00 0d    	add    %ah,0xd000002(%rbp)
 29f:	38 00                	cmp    %al,(%rax)
 2a1:	00 00                	add    %al,(%rax)
 2a3:	13 00                	adc    (%rax),%eax
 2a5:	0e                   	(bad)  
 2a6:	f2 00 00             	repnz add %al,(%rax)
 2a9:	00 0f                	add    %cl,(%rdi)
 2ab:	6a 01                	pushq  $0x1
 2ad:	00 00                	add    %al,(%rax)
 2af:	04 3f                	add    $0x3f,%al
 2b1:	01 a5 02 00 00 0f    	add    %esp,0xf000002(%rbp)
 2b7:	5c                   	pop    %rsp
 2b8:	00 00                	add    %al,(%rax)
 2ba:	00 04 40             	add    %al,(%rax,%rax,2)
 2bd:	01 a5 02 00 00 0f    	add    %esp,0xf000002(%rbp)
 2c3:	7f 02                	jg     2c7 <_init-0xd39>
 2c5:	00 00                	add    %al,(%rax)
 2c7:	04 41                	add    $0x41,%al
 2c9:	01 a5 02 00 00 06    	add    %esp,0x6000002(%rbp)
 2cf:	08 b6 00 00 00 07    	or     %dh,0x7000000(%rsi)
 2d5:	ce                   	(bad)  
 2d6:	02 00                	add    (%rax),%al
 2d8:	00 10                	add    %dl,(%rax)
 2da:	d9 02                	flds   (%rdx)
 2dc:	00 00                	add    %al,(%rax)
 2de:	05 87 79 02 00       	add    $0x27987,%eax
 2e3:	00 10                	add    %dl,(%rax)
 2e5:	4e 03 00             	rex.WRX add (%rax),%r8
 2e8:	00 05 88 79 02 00    	add    %al,0x27988(%rip)        # 27c76 <_end+0x23c5e>
 2ee:	00 10                	add    %dl,(%rax)
 2f0:	b7 00                	mov    $0x0,%bh
 2f2:	00 00                	add    %al,(%rax)
 2f4:	05 89 79 02 00       	add    $0x27989,%eax
 2f9:	00 10                	add    %dl,(%rax)
 2fb:	10 00                	adc    %al,(%rax)
 2fd:	00 00                	add    %al,(%rax)
 2ff:	06                   	(bad)  
 300:	1a 6d 00             	sbb    0x0(%rbp),%ch
 303:	00 00                	add    %al,(%rax)
 305:	0c d4                	or     $0xd4,%al
 307:	02 00                	add    (%rax),%al
 309:	00 10                	add    %dl,(%rax)
 30b:	03 00                	add    (%rax),%eax
 30d:	00 11                	add    %dl,(%rcx)
 30f:	00 07                	add    %al,(%rdi)
 311:	05 03 00 00 10       	add    $0x10000003,%eax
 316:	2b 03                	sub    (%rbx),%eax
 318:	00 00                	add    %al,(%rax)
 31a:	06                   	(bad)  
 31b:	1b 10                	sbb    (%rax),%edx
 31d:	03 00                	add    (%rax),%eax
 31f:	00 02                	add    %al,(%rdx)
 321:	90                   	nop
 322:	01 00                	add    %eax,(%rax)
 324:	00 07                	add    %al,(%rdi)
 326:	18 5b 00             	sbb    %bl,0x0(%rbx)
 329:	00 00                	add    %al,(%rax)
 32b:	02 53 00             	add    0x0(%rbx),%dl
 32e:	00 00                	add    %al,(%rax)
 330:	07                   	(bad)  
 331:	1a 74 00 00          	sbb    0x0(%rax,%rax,1),%dh
 335:	00 02                	add    %al,(%rdx)
 337:	52                   	push   %rdx
 338:	02 00                	add    (%rax),%al
 33a:	00 07                	add    %al,(%rdi)
 33c:	1b 86 00 00 00 03    	sbb    0x3000000(%rsi),%eax
 342:	08 05 be 00 00 00    	or     %al,0xbe(%rip)        # 406 <_init-0xbfa>
 348:	03 08                	add    (%rax),%ecx
 34a:	07                   	(bad)  
 34b:	53                   	push   %rbx
 34c:	01 00                	add    %eax,(%rax)
 34e:	00 12                	add    %dl,(%rdx)
 350:	4c 01 00             	add    %r8,(%rax)
 353:	00 00                	add    %al,(%rax)
 355:	10 01                	adc    %al,(%rcx)
 357:	08 ed                	or     %ch,%ch
 359:	03 00                	add    (%rax),%eax
 35b:	00 09                	add    %cl,(%rcx)
 35d:	d2 00                	rolb   %cl,(%rax)
 35f:	00 00                	add    %al,(%rax)
 361:	01 0a                	add    %ecx,(%rdx)
 363:	36 03 00             	add    %ss:(%rax),%eax
 366:	00 00                	add    %al,(%rax)
 368:	09 4b 00             	or     %ecx,0x0(%rbx)
 36b:	00 00                	add    %al,(%rax)
 36d:	01 0b                	add    %ecx,(%rbx)
 36f:	36 03 00             	add    %ss:(%rax),%eax
 372:	00 08                	add    %cl,(%rax)
 374:	09 ac 00 00 00 01 0c 	or     %ebp,0xc010000(%rax,%rax,1)
 37b:	36 03 00             	add    %ss:(%rax),%eax
 37e:	00 10                	add    %dl,(%rax)
 380:	09 37                	or     %esi,(%rdi)
 382:	00 00                	add    %al,(%rax)
 384:	00 01                	add    %al,(%rcx)
 386:	0d 2b 03 00 00       	or     $0x32b,%eax
 38b:	18 09                	sbb    %cl,(%rcx)
 38d:	40 03 00             	rex add (%rax),%eax
 390:	00 01                	add    %al,(%rcx)
 392:	0e                   	(bad)  
 393:	2b 03                	sub    (%rbx),%eax
 395:	00 00                	add    %al,(%rax)
 397:	1c 09                	sbb    $0x9,%al
 399:	21 01                	and    %eax,(%rcx)
 39b:	00 00                	add    %al,(%rax)
 39d:	01 0f                	add    %ecx,(%rdi)
 39f:	36 03 00             	add    %ss:(%rax),%eax
 3a2:	00 20                	add    %ah,(%rax)
 3a4:	09 dc                	or     %ebx,%esp
 3a6:	00 00                	add    %al,(%rax)
 3a8:	00 01                	add    %al,(%rcx)
 3aa:	10 36                	adc    %dh,(%rsi)
 3ac:	03 00                	add    (%rax),%eax
 3ae:	00 28                	add    %ch,(%rax)
 3b0:	09 45 03             	or     %eax,0x3(%rbp)
 3b3:	00 00                	add    %al,(%rax)
 3b5:	01 11                	add    %edx,(%rcx)
 3b7:	36 03 00             	add    %ss:(%rax),%eax
 3ba:	00 30                	add    %dh,(%rax)
 3bc:	09 43 01             	or     %eax,0x1(%rbx)
 3bf:	00 00                	add    %al,(%rax)
 3c1:	01 12                	add    %edx,(%rdx)
 3c3:	36 03 00             	add    %ss:(%rax),%eax
 3c6:	00 38                	add    %bh,(%rax)
 3c8:	09 05 01 00 00 01    	or     %eax,0x1000001(%rip)        # 10003cf <_end+0xffc3b7>
 3ce:	13 2b                	adc    (%rbx),%ebp
 3d0:	03 00                	add    (%rax),%eax
 3d2:	00 40 09             	add    %al,0x9(%rax)
 3d5:	5b                   	pop    %rbx
 3d6:	02 00                	add    (%rax),%al
 3d8:	00 01                	add    %al,(%rcx)
 3da:	14 2b                	adc    $0x2b,%al
 3dc:	03 00                	add    (%rax),%eax
 3de:	00 44 09 37          	add    %al,0x37(%rcx,%rcx,1)
 3e2:	03 00                	add    (%rax),%eax
 3e4:	00 01                	add    %al,(%rcx)
 3e6:	16                   	(bad)  
 3e7:	ed                   	in     (%dx),%eax
 3e8:	03 00                	add    (%rax),%eax
 3ea:	00 48 00             	add    %cl,0x0(%rax)
 3ed:	0c 20                	or     $0x20,%al
 3ef:	03 00                	add    (%rax),%eax
 3f1:	00 fe                	add    %bh,%dh
 3f3:	03 00                	add    (%rax),%eax
 3f5:	00 13                	add    %dl,(%rbx)
 3f7:	38 00                	cmp    %al,(%rax)
 3f9:	00 00                	add    %al,(%rax)
 3fb:	b7 0f                	mov    $0xf,%bh
 3fd:	00 02                	add    %al,(%rdx)
 3ff:	4d 01 00             	add    %r8,(%r8)
 402:	00 01                	add    %al,(%rcx)
 404:	17                   	(bad)  
 405:	4f 03 00             	rex.WRXB add (%r8),%r8
 408:	00 14 d5 01 00 00 01 	add    %dl,0x1000001(,%rdx,8)
 40f:	19 6d 00             	sbb    %ebp,0x0(%rbp)
 412:	00 00                	add    %al,(%rax)
 414:	9a                   	(bad)  
 415:	11 00                	adc    %eax,(%rax)
 417:	00 00                	add    %al,(%rax)
 419:	00 00                	add    %al,(%rax)
 41b:	00 d5                	add    %dl,%ch
 41d:	00 00                	add    %al,(%rax)
 41f:	00 00                	add    %al,(%rax)
 421:	00 00                	add    %al,(%rax)
 423:	00 01                	add    %al,(%rcx)
 425:	9c                   	pushfq 
 426:	b3 04                	mov    $0x4,%bl
 428:	00 00                	add    %al,(%rax)
 42a:	15 af 02 00 00       	adc    $0x2af,%eax
 42f:	01 1b                	add    %ebx,(%rbx)
 431:	a7                   	cmpsl  %es:(%rdi),%ds:(%rsi)
 432:	00 00                	add    %al,(%rax)
 434:	00 02                	add    %al,(%rdx)
 436:	91                   	xchg   %eax,%ecx
 437:	40 02 ce             	add    %sil,%cl
 43a:	01 00                	add    %eax,(%rax)
 43c:	00 01                	add    %al,(%rcx)
 43e:	1c b3                	sbb    $0xb3,%al
 440:	04 00                	add    $0x0,%al
 442:	00 15 98 01 00 00    	add    %dl,0x198(%rip)        # 5e0 <_init-0xa20>
 448:	01 1d 38 04 00 00    	add    %ebx,0x438(%rip)        # 886 <_init-0x77a>
 44e:	02 91 48 16 72 61    	add    0x61721648(%rcx),%dl
 454:	78 00                	js     456 <_init-0xbaa>
 456:	01 1e                	add    %ebx,(%rsi)
 458:	36 03 00             	add    %ss:(%rax),%eax
 45b:	00 02                	add    %al,(%rdx)
 45d:	91                   	xchg   %eax,%ecx
 45e:	50                   	push   %rax
 45f:	16                   	(bad)  
 460:	69 00 01 1f 6d 00    	imul   $0x6d1f01,(%rax),%eax
 466:	00 00                	add    %al,(%rax)
 468:	03 91 bc 7f 15 65    	add    0x65157fbc(%rcx),%edx
 46e:	02 00                	add    (%rax),%al
 470:	00 01                	add    %al,(%rcx)
 472:	20 a7 00 00 00 02    	and    %ah,0x2000000(%rdi)
 478:	91                   	xchg   %eax,%ecx
 479:	58                   	pop    %rax
 47a:	15 06 03 00 00       	adc    $0x306,%eax
 47f:	01 21                	add    %esp,(%rcx)
 481:	a9 00 00 00 02       	test   $0x2000000,%eax
 486:	91                   	xchg   %eax,%ecx
 487:	60                   	(bad)  
 488:	16                   	(bad)  
 489:	74 63                	je     4ee <_init-0xb12>
 48b:	73 00                	jae    48d <_init-0xb73>
 48d:	01 22                	add    %esp,(%rdx)
 48f:	c8 04 00 00          	enterq $0x4,$0x0
 493:	02 91 68 15 b1 00    	add    0xb11568(%rcx),%dl
 499:	00 00                	add    %al,(%rax)
 49b:	01 23                	add    %esp,(%rbx)
 49d:	6d                   	insl   (%dx),%es:(%rdi)
 49e:	00 00                	add    %al,(%rax)
 4a0:	00 03                	add    %al,(%rbx)
 4a2:	91                   	xchg   %eax,%ecx
 4a3:	b8 7f 17 df 02       	mov    $0x2df177f,%eax
 4a8:	00 00                	add    %al,(%rax)
 4aa:	01 25 6d 00 00 00    	add    %esp,0x6d(%rip)        # 51d <_init-0xae3>
 4b0:	18 00                	sbb    %al,(%rax)
 4b2:	00 06                	add    %al,(%rsi)
 4b4:	08 b9 04 00 00 19    	or     %bh,0x19000004(%rcx)
 4ba:	6d                   	insl   (%dx),%es:(%rdi)
 4bb:	00 00                	add    %al,(%rax)
 4bd:	00 c8                	add    %cl,%al
 4bf:	04 00                	add    $0x0,%al
 4c1:	00 1a                	add    %bl,(%rdx)
 4c3:	6d                   	insl   (%dx),%es:(%rdi)
 4c4:	00 00                	add    %al,(%rax)
 4c6:	00 00                	add    %al,(%rax)
 4c8:	06                   	(bad)  
 4c9:	08 fe                	or     %bh,%dh
 4cb:	03 00                	add    (%rax),%eax
	...

Disassembly of section .debug_abbrev:

0000000000000000 <.debug_abbrev>:
   0:	01 11                	add    %edx,(%rcx)
   2:	01 25 0e 13 0b 03    	add    %esp,0x30b130e(%rip)        # 30b1316 <_end+0x30ad2fe>
   8:	0e                   	(bad)  
   9:	1b 0e                	sbb    (%rsi),%ecx
   b:	11 01                	adc    %eax,(%rcx)
   d:	12 07                	adc    (%rdi),%al
   f:	10 17                	adc    %dl,(%rdi)
  11:	00 00                	add    %al,(%rax)
  13:	02 16                	add    (%rsi),%dl
  15:	00 03                	add    %al,(%rbx)
  17:	0e                   	(bad)  
  18:	3a 0b                	cmp    (%rbx),%cl
  1a:	3b 0b                	cmp    (%rbx),%ecx
  1c:	49 13 00             	adc    (%r8),%rax
  1f:	00 03                	add    %al,(%rbx)
  21:	24 00                	and    $0x0,%al
  23:	0b 0b                	or     (%rbx),%ecx
  25:	3e 0b 03             	or     %ds:(%rbx),%eax
  28:	0e                   	(bad)  
  29:	00 00                	add    %al,(%rax)
  2b:	04 24                	add    $0x24,%al
  2d:	00 0b                	add    %cl,(%rbx)
  2f:	0b 3e                	or     (%rsi),%edi
  31:	0b 03                	or     (%rbx),%eax
  33:	08 00                	or     %al,(%rax)
  35:	00 05 0f 00 0b 0b    	add    %al,0xb0b000f(%rip)        # b0b004a <_end+0xb0ac032>
  3b:	00 00                	add    %al,(%rax)
  3d:	06                   	(bad)  
  3e:	0f 00 0b             	str    (%rbx)
  41:	0b 49 13             	or     0x13(%rcx),%ecx
  44:	00 00                	add    %al,(%rax)
  46:	07                   	(bad)  
  47:	26 00 49 13          	add    %cl,%es:0x13(%rcx)
  4b:	00 00                	add    %al,(%rax)
  4d:	08 13                	or     %dl,(%rbx)
  4f:	01 03                	add    %eax,(%rbx)
  51:	0e                   	(bad)  
  52:	0b 0b                	or     (%rbx),%ecx
  54:	3a 0b                	cmp    (%rbx),%cl
  56:	3b 0b                	cmp    (%rbx),%ecx
  58:	01 13                	add    %edx,(%rbx)
  5a:	00 00                	add    %al,(%rax)
  5c:	09 0d 00 03 0e 3a    	or     %ecx,0x3a0e0300(%rip)        # 3a0e0362 <_end+0x3a0dc34a>
  62:	0b 3b                	or     (%rbx),%edi
  64:	0b 49 13             	or     0x13(%rcx),%ecx
  67:	38 0b                	cmp    %cl,(%rbx)
  69:	00 00                	add    %al,(%rax)
  6b:	0a 0d 00 03 0e 3a    	or     0x3a0e0300(%rip),%cl        # 3a0e0371 <_end+0x3a0dc359>
  71:	0b 3b                	or     (%rbx),%edi
  73:	05 49 13 38 0b       	add    $0xb381349,%eax
  78:	00 00                	add    %al,(%rax)
  7a:	0b 16                	or     (%rsi),%edx
  7c:	00 03                	add    %al,(%rbx)
  7e:	0e                   	(bad)  
  7f:	3a 0b                	cmp    (%rbx),%cl
  81:	3b 0b                	cmp    (%rbx),%ecx
  83:	00 00                	add    %al,(%rax)
  85:	0c 01                	or     $0x1,%al
  87:	01 49 13             	add    %ecx,0x13(%rcx)
  8a:	01 13                	add    %edx,(%rbx)
  8c:	00 00                	add    %al,(%rax)
  8e:	0d 21 00 49 13       	or     $0x13490021,%eax
  93:	2f                   	(bad)  
  94:	0b 00                	or     (%rax),%eax
  96:	00 0e                	add    %cl,(%rsi)
  98:	13 00                	adc    (%rax),%eax
  9a:	03 0e                	add    (%rsi),%ecx
  9c:	3c 19                	cmp    $0x19,%al
  9e:	00 00                	add    %al,(%rax)
  a0:	0f 34                	sysenter 
  a2:	00 03                	add    %al,(%rbx)
  a4:	0e                   	(bad)  
  a5:	3a 0b                	cmp    (%rbx),%cl
  a7:	3b 05 49 13 3f 19    	cmp    0x193f1349(%rip),%eax        # 193f13f6 <_end+0x193ed3de>
  ad:	3c 19                	cmp    $0x19,%al
  af:	00 00                	add    %al,(%rax)
  b1:	10 34 00             	adc    %dh,(%rax,%rax,1)
  b4:	03 0e                	add    (%rsi),%ecx
  b6:	3a 0b                	cmp    (%rbx),%cl
  b8:	3b 0b                	cmp    (%rbx),%ecx
  ba:	49 13 3f             	adc    (%r15),%rdi
  bd:	19 3c 19             	sbb    %edi,(%rcx,%rbx,1)
  c0:	00 00                	add    %al,(%rax)
  c2:	11 21                	adc    %esp,(%rcx)
  c4:	00 00                	add    %al,(%rax)
  c6:	00 12                	add    %dl,(%rdx)
  c8:	13 01                	adc    (%rcx),%eax
  ca:	03 0e                	add    (%rsi),%ecx
  cc:	0b 05 3a 0b 3b 0b    	or     0xb3b0b3a(%rip),%eax        # b3b0c0c <_end+0xb3acbf4>
  d2:	01 13                	add    %edx,(%rbx)
  d4:	00 00                	add    %al,(%rax)
  d6:	13 21                	adc    (%rcx),%esp
  d8:	00 49 13             	add    %cl,0x13(%rcx)
  db:	2f                   	(bad)  
  dc:	05 00 00 14 2e       	add    $0x2e140000,%eax
  e1:	01 3f                	add    %edi,(%rdi)
  e3:	19 03                	sbb    %eax,(%rbx)
  e5:	0e                   	(bad)  
  e6:	3a 0b                	cmp    (%rbx),%cl
  e8:	3b 0b                	cmp    (%rbx),%ecx
  ea:	49 13 11             	adc    (%r9),%rdx
  ed:	01 12                	add    %edx,(%rdx)
  ef:	07                   	(bad)  
  f0:	40 18 96 42 19 01 13 	sbb    %dl,0x13011942(%rsi)
  f7:	00 00                	add    %al,(%rax)
  f9:	15 34 00 03 0e       	adc    $0xe030034,%eax
  fe:	3a 0b                	cmp    (%rbx),%cl
 100:	3b 0b                	cmp    (%rbx),%ecx
 102:	49 13 02             	adc    (%r10),%rax
 105:	18 00                	sbb    %al,(%rax)
 107:	00 16                	add    %dl,(%rsi)
 109:	34 00                	xor    $0x0,%al
 10b:	03 08                	add    (%rax),%ecx
 10d:	3a 0b                	cmp    (%rbx),%cl
 10f:	3b 0b                	cmp    (%rbx),%ecx
 111:	49 13 02             	adc    (%r10),%rax
 114:	18 00                	sbb    %al,(%rax)
 116:	00 17                	add    %dl,(%rdi)
 118:	2e 01 3f             	add    %edi,%cs:(%rdi)
 11b:	19 03                	sbb    %eax,(%rbx)
 11d:	0e                   	(bad)  
 11e:	3a 0b                	cmp    (%rbx),%cl
 120:	3b 0b                	cmp    (%rbx),%ecx
 122:	49 13 3c 19          	adc    (%r9,%rbx,1),%rdi
 126:	00 00                	add    %al,(%rax)
 128:	18 18                	sbb    %bl,(%rax)
 12a:	00 00                	add    %al,(%rax)
 12c:	00 19                	add    %bl,(%rcx)
 12e:	15 01 27 19 49       	adc    $0x49192701,%eax
 133:	13 01                	adc    (%rcx),%eax
 135:	13 00                	adc    (%rax),%eax
 137:	00 1a                	add    %bl,(%rdx)
 139:	05 00 49 13 00       	add    $0x134900,%eax
	...

Disassembly of section .debug_line:

0000000000000000 <.debug_line>:
   0:	f6 00 00             	testb  $0x0,(%rax)
   3:	00 03                	add    %al,(%rbx)
   5:	00 c9                	add    %cl,%cl
   7:	00 00                	add    %al,(%rax)
   9:	00 01                	add    %al,(%rcx)
   b:	01 fb                	add    %edi,%ebx
   d:	0e                   	(bad)  
   e:	0d 00 01 01 01       	or     $0x1010100,%eax
  13:	01 00                	add    %eax,(%rax)
  15:	00 00                	add    %al,(%rax)
  17:	01 00                	add    %eax,(%rax)
  19:	00 01                	add    %al,(%rcx)
  1b:	2e 00 2f             	add    %ch,%cs:(%rdi)
  1e:	75 73                	jne    93 <_init-0xf6d>
  20:	72 2f                	jb     51 <_init-0xfaf>
  22:	6c                   	insb   (%dx),%es:(%rdi)
  23:	69 62 2f 67 63 63 2f 	imul   $0x2f636367,0x2f(%rdx),%esp
  2a:	78 38                	js     64 <_init-0xf9c>
  2c:	36 5f                	ss pop %rdi
  2e:	36 34 2d             	ss xor $0x2d,%al
  31:	6c                   	insb   (%dx),%es:(%rdi)
  32:	69 6e 75 78 2d 67 6e 	imul   $0x6e672d78,0x75(%rsi),%ebp
  39:	75 2f                	jne    6a <_init-0xf96>
  3b:	37                   	(bad)  
  3c:	2f                   	(bad)  
  3d:	69 6e 63 6c 75 64 65 	imul   $0x6564756c,0x63(%rsi),%ebp
  44:	00 2f                	add    %ch,(%rdi)
  46:	75 73                	jne    bb <_init-0xf45>
  48:	72 2f                	jb     79 <_init-0xf87>
  4a:	69 6e 63 6c 75 64 65 	imul   $0x6564756c,0x63(%rsi),%ebp
  51:	2f                   	(bad)  
  52:	78 38                	js     8c <_init-0xf74>
  54:	36 5f                	ss pop %rdi
  56:	36 34 2d             	ss xor $0x2d,%al
  59:	6c                   	insb   (%dx),%es:(%rdi)
  5a:	69 6e 75 78 2d 67 6e 	imul   $0x6e672d78,0x75(%rsi),%ebp
  61:	75 2f                	jne    92 <_init-0xf6e>
  63:	62                   	(bad)  
  64:	69 74 73 00 2f 75 73 	imul   $0x7273752f,0x0(%rbx,%rsi,2),%esi
  6b:	72 
  6c:	2f                   	(bad)  
  6d:	69 6e 63 6c 75 64 65 	imul   $0x6564756c,0x63(%rsi),%ebp
  74:	00 00                	add    %al,(%rax)
  76:	6c                   	insb   (%dx),%es:(%rdi)
  77:	6f                   	outsl  %ds:(%rsi),(%dx)
  78:	61                   	(bad)  
  79:	64 65 72 2e          	fs gs jb ab <_init-0xf55>
  7d:	63 00                	movslq (%rax),%eax
  7f:	01 00                	add    %eax,(%rax)
  81:	00 73 74             	add    %dh,0x74(%rbx)
  84:	64 64 65 66 2e 68 00 	fs fs gs cs pushw $0x200
  8b:	02 
  8c:	00 00                	add    %al,(%rax)
  8e:	74 79                	je     109 <_init-0xef7>
  90:	70 65                	jo     f7 <_init-0xf09>
  92:	73 2e                	jae    c2 <_init-0xf3e>
  94:	68 00 03 00 00       	pushq  $0x300
  99:	6c                   	insb   (%dx),%es:(%rdi)
  9a:	69 62 69 6f 2e 68 00 	imul   $0x682e6f,0x69(%rdx),%esp
  a1:	03 00                	add    (%rax),%eax
  a3:	00 73 74             	add    %dh,0x74(%rbx)
  a6:	64 69 6f 2e 68 00 04 	imul   $0x40068,%fs:0x2e(%rdi),%ebp
  ad:	00 
  ae:	00 73 79             	add    %dh,0x79(%rbx)
  b1:	73 5f                	jae    112 <_init-0xeee>
  b3:	65 72 72             	gs jb  128 <_init-0xed8>
  b6:	6c                   	insb   (%dx),%es:(%rdi)
  b7:	69 73 74 2e 68 00 03 	imul   $0x300682e,0x74(%rbx),%esi
  be:	00 00                	add    %al,(%rax)
  c0:	73 74                	jae    136 <_init-0xeca>
  c2:	64 69 6e 74 2d 75 69 	imul   $0x6e69752d,%fs:0x74(%rsi),%ebp
  c9:	6e 
  ca:	74 6e                	je     13a <_init-0xec6>
  cc:	2e 68 00 03 00 00    	cs pushq $0x300
  d2:	00 00                	add    %al,(%rax)
  d4:	09 02                	or     %eax,(%rdx)
  d6:	9a                   	(bad)  
  d7:	11 00                	adc    %eax,(%rax)
  d9:	00 00                	add    %al,(%rax)
  db:	00 00                	add    %al,(%rax)
  dd:	00 03                	add    %al,(%rbx)
  df:	18 01                	sbb    %al,(%rcx)
  e1:	84 08                	test   %cl,(%rax)
  e3:	4c 08 67 84          	rex.WR or %r12b,-0x7c(%rdi)
  e7:	d7                   	xlat   %ds:(%rbx)
  e8:	d7                   	xlat   %ds:(%rbx)
  e9:	d7                   	xlat   %ds:(%rbx)
  ea:	76 08                	jbe    f4 <_init-0xf0c>
  ec:	59                   	pop    %rcx
  ed:	03 0b                	add    (%rbx),%ecx
  ef:	02 27                	add    (%rdi),%ah
  f1:	01 d8                	add    %ebx,%eax
  f3:	08 a0 02 02 00 01    	or     %ah,0x1000202(%rax)
  f9:	01                   	.byte 0x1

Disassembly of section .debug_str:

0000000000000000 <.debug_str>:
   0:	5f                   	pop    %rdi
   1:	63 68 61             	movslq 0x61(%rax),%ebp
   4:	69 6e 00 5f 49 4f 5f 	imul   $0x5f4f495f,0x0(%rsi),%ebp
   b:	46                   	rex.RX
   c:	49                   	rex.WB
   d:	4c                   	rex.WR
   e:	45 00 73 79          	add    %r14b,0x79(%r11)
  12:	73 5f                	jae    73 <_init-0xf8d>
  14:	6e                   	outsb  %ds:(%rsi),(%dx)
  15:	65 72 72             	gs jb  8a <_init-0xf76>
  18:	00 5f 49             	add    %bl,0x49(%rdi)
  1b:	4f 5f                	rex.WRXB pop %r15
  1d:	73 61                	jae    80 <_init-0xf80>
  1f:	76 65                	jbe    86 <_init-0xf7a>
  21:	5f                   	pop    %rdi
  22:	65 6e                	outsb  %gs:(%rsi),(%dx)
  24:	64 00 73 68          	add    %dh,%fs:0x68(%rbx)
  28:	6f                   	outsl  %ds:(%rsi),(%dx)
  29:	72 74                	jb     9f <_init-0xf61>
  2b:	20 69 6e             	and    %ch,0x6e(%rcx)
  2e:	74 00                	je     30 <_init-0xfd0>
  30:	73 69                	jae    9b <_init-0xf65>
  32:	7a 65                	jp     99 <_init-0xf67>
  34:	5f                   	pop    %rdi
  35:	74 00                	je     37 <_init-0xfc9>
  37:	63 73 73             	movslq 0x73(%rbx),%esi
  3a:	61                   	(bad)  
  3b:	00 5f 49             	add    %bl,0x49(%rdi)
  3e:	4f 5f                	rex.WRXB pop %r15
  40:	77 72                	ja     b4 <_init-0xf4c>
  42:	69 74 65 5f 70 74 72 	imul   $0x727470,0x5f(%rbp,%riz,2),%esi
  49:	00 
  4a:	5f                   	pop    %rdi
  4b:	66 6c                	data16 insb (%dx),%es:(%rdi)
  4d:	61                   	(bad)  
  4e:	67 73 00             	addr32 jae 51 <_init-0xfaf>
  51:	5f                   	pop    %rdi
  52:	5f                   	pop    %rdi
  53:	75 69                	jne    be <_init-0xf42>
  55:	6e                   	outsb  %ds:(%rsi),(%dx)
  56:	74 33                	je     8b <_init-0xf75>
  58:	32 5f 74             	xor    0x74(%rdi),%bl
  5b:	00 5f 49             	add    %bl,0x49(%rdi)
  5e:	4f 5f                	rex.WRXB pop %r15
  60:	32 5f 31             	xor    0x31(%rdi),%bl
  63:	5f                   	pop    %rdi
  64:	73 74                	jae    da <_init-0xf26>
  66:	64 6f                	outsl  %fs:(%rsi),(%dx)
  68:	75 74                	jne    de <_init-0xf22>
  6a:	5f                   	pop    %rdi
  6b:	00 2f                	add    %ch,(%rdi)
  6d:	68 6f 6d 65 2f       	pushq  $0x2f656d6f
  72:	61                   	(bad)  
  73:	72 73                	jb     e8 <_init-0xf18>
  75:	6c                   	insb   (%dx),%es:(%rdi)
  76:	61                   	(bad)  
  77:	6e                   	outsb  %ds:(%rsi),(%dx)
  78:	2f                   	(bad)  
  79:	44 6f                	rex.R outsl %ds:(%rsi),(%dx)
  7b:	63 75 6d             	movslq 0x6d(%rbp),%esi
  7e:	65 6e                	outsb  %gs:(%rsi),(%dx)
  80:	74 73                	je     f5 <_init-0xf0b>
  82:	2f                   	(bad)  
  83:	71 65                	jno    ea <_init-0xf16>
  85:	6d                   	insl   (%dx),%es:(%rdi)
  86:	75 73                	jne    fb <_init-0xf05>
  88:	67 78 2f             	addr32 js ba <_init-0xf46>
  8b:	6c                   	insb   (%dx),%es:(%rdi)
  8c:	6f                   	outsl  %ds:(%rsi),(%dx)
  8d:	61                   	(bad)  
  8e:	64 65 72 2d          	fs gs jb bf <_init-0xf41>
  92:	61                   	(bad)  
  93:	70 70                	jo     105 <_init-0xefb>
  95:	00 5f 6d             	add    %bl,0x6d(%rdi)
  98:	61                   	(bad)  
  99:	72 6b                	jb     106 <_init-0xefa>
  9b:	65 72 73             	gs jb  111 <_init-0xeef>
  9e:	00 5f 49             	add    %bl,0x49(%rdi)
  a1:	4f 5f                	rex.WRXB pop %r15
  a3:	72 65                	jb     10a <_init-0xef6>
  a5:	61                   	(bad)  
  a6:	64 5f                	fs pop %rdi
  a8:	65 6e                	outsb  %gs:(%rsi),(%dx)
  aa:	64 00 6f 73          	add    %ch,%fs:0x73(%rdi)
  ae:	73 61                	jae    111 <_init-0xeef>
  b0:	00 69 6e             	add    %ch,0x6e(%rcx)
  b3:	64 65 78 00          	fs gs js b7 <_init-0xf49>
  b7:	73 74                	jae    12d <_init-0xed3>
  b9:	64 65 72 72          	fs gs jb 12f <_init-0xed1>
  bd:	00 6c 6f 6e          	add    %ch,0x6e(%rdi,%rbp,2)
  c1:	67 20 6c 6f 6e       	and    %ch,0x6e(%edi,%ebp,2)
  c6:	67 20 69 6e          	and    %ch,0x6e(%ecx)
  ca:	74 00                	je     cc <_init-0xf34>
  cc:	5f                   	pop    %rdi
  cd:	6c                   	insb   (%dx),%es:(%rdi)
  ce:	6f                   	outsl  %ds:(%rsi),(%dx)
  cf:	63 6b 00             	movslq 0x0(%rbx),%ebp
  d2:	72 65                	jb     139 <_init-0xec7>
  d4:	73 65                	jae    13b <_init-0xec5>
  d6:	72 76                	jb     14e <_init-0xeb2>
  d8:	65 64 30 00          	gs xor %al,%fs:(%rax)
  dc:	72 65                	jb     143 <_init-0xebd>
  de:	73 65                	jae    145 <_init-0xebb>
  e0:	72 76                	jb     158 <_init-0xea8>
  e2:	65 64 31 00          	gs xor %eax,%fs:(%rax)
  e6:	5f                   	pop    %rdi
  e7:	63 75 72             	movslq 0x72(%rbp),%esi
  ea:	5f                   	pop    %rdi
  eb:	63 6f 6c             	movslq 0x6c(%rdi),%ebp
  ee:	75 6d                	jne    15d <_init-0xea3>
  f0:	6e                   	outsb  %ds:(%rsi),(%dx)
  f1:	00 5f 49             	add    %bl,0x49(%rdi)
  f4:	4f 5f                	rex.WRXB pop %r15
  f6:	46                   	rex.RX
  f7:	49                   	rex.WB
  f8:	4c                   	rex.WR
  f9:	45 5f                	rex.RB pop %r15
  fb:	70 6c                	jo     169 <_init-0xe97>
  fd:	75 73                	jne    172 <_init-0xe8e>
  ff:	00 5f 70             	add    %bl,0x70(%rdi)
 102:	6f                   	outsl  %ds:(%rsi),(%dx)
 103:	73 00                	jae    105 <_init-0xefb>
 105:	6f                   	outsl  %ds:(%rsi),(%dx)
 106:	66 73 5f             	data16 jae 168 <_init-0xe98>
 109:	6c                   	insb   (%dx),%es:(%rdi)
 10a:	69 6d 69 74 00 5f 73 	imul   $0x735f0074,0x69(%rbp),%ebp
 111:	62                   	(bad)  
 112:	75 66                	jne    17a <_init-0xe86>
 114:	00 5f 6f             	add    %bl,0x6f(%rdi)
 117:	6c                   	insb   (%dx),%es:(%rdi)
 118:	64 5f                	fs pop %rdi
 11a:	6f                   	outsl  %ds:(%rsi),(%dx)
 11b:	66 66 73 65          	data16 data16 jae 184 <_init-0xe7c>
 11f:	74 00                	je     121 <_init-0xedf>
 121:	6f                   	outsl  %ds:(%rsi),(%dx)
 122:	65 6e                	outsb  %gs:(%rsi),(%dx)
 124:	74 72                	je     198 <_init-0xe68>
 126:	79 00                	jns    128 <_init-0xed8>
 128:	75 6e                	jne    198 <_init-0xe68>
 12a:	73 69                	jae    195 <_init-0xe6b>
 12c:	67 6e                	outsb  %ds:(%esi),(%dx)
 12e:	65 64 20 63 68       	gs and %ah,%fs:0x68(%rbx)
 133:	61                   	(bad)  
 134:	72 00                	jb     136 <_init-0xeca>
 136:	5f                   	pop    %rdi
 137:	49                   	rex.WB
 138:	4f 5f                	rex.WRXB pop %r15
 13a:	62                   	(bad)  
 13b:	75 66                	jne    1a3 <_init-0xe5d>
 13d:	5f                   	pop    %rdi
 13e:	62 61                	(bad)  
 140:	73 65                	jae    1a7 <_init-0xe59>
 142:	00 6f 67             	add    %ch,0x67(%rdi)
 145:	73 5f                	jae    1a6 <_init-0xe5a>
 147:	62 61                	(bad)  
 149:	73 65                	jae    1b0 <_init-0xe50>
 14b:	00 5f 74             	add    %bl,0x74(%rdi)
 14e:	63 73 5f             	movslq 0x5f(%rbx),%esi
 151:	74 00                	je     153 <_init-0xead>
 153:	6c                   	insb   (%dx),%es:(%rdi)
 154:	6f                   	outsl  %ds:(%rsi),(%dx)
 155:	6e                   	outsb  %ds:(%rsi),(%dx)
 156:	67 20 6c 6f 6e       	and    %ch,0x6e(%edi,%ebp,2)
 15b:	67 20 75 6e          	and    %dh,0x6e(%ebp)
 15f:	73 69                	jae    1ca <_init-0xe36>
 161:	67 6e                	outsb  %ds:(%esi),(%dx)
 163:	65 64 20 69 6e       	gs and %ch,%fs:0x6e(%rcx)
 168:	74 00                	je     16a <_init-0xe96>
 16a:	5f                   	pop    %rdi
 16b:	49                   	rex.WB
 16c:	4f 5f                	rex.WRXB pop %r15
 16e:	32 5f 31             	xor    0x31(%rdi),%bl
 171:	5f                   	pop    %rdi
 172:	73 74                	jae    1e8 <_init-0xe18>
 174:	64 69 6e 5f 00 5f 49 	imul   $0x4f495f00,%fs:0x5f(%rsi),%ebp
 17b:	4f 
 17c:	5f                   	pop    %rdi
 17d:	6d                   	insl   (%dx),%es:(%rdi)
 17e:	61                   	(bad)  
 17f:	72 6b                	jb     1ec <_init-0xe14>
 181:	65 72 00             	gs jb  184 <_init-0xe7c>
 184:	5f                   	pop    %rdi
 185:	73 68                	jae    1ef <_init-0xe11>
 187:	6f                   	outsl  %ds:(%rsi),(%dx)
 188:	72 74                	jb     1fe <_init-0xe02>
 18a:	62                   	(bad)  
 18b:	75 66                	jne    1f3 <_init-0xe0d>
 18d:	00 5f 5f             	add    %bl,0x5f(%rdi)
 190:	75 69                	jne    1fb <_init-0xe05>
 192:	6e                   	outsb  %ds:(%rsi),(%dx)
 193:	74 38                	je     1cd <_init-0xe33>
 195:	5f                   	pop    %rdi
 196:	74 00                	je     198 <_init-0xe68>
 198:	74 65                	je     1ff <_init-0xe01>
 19a:	73 74                	jae    210 <_init-0xdf0>
 19c:	00 5f 49             	add    %bl,0x49(%rdi)
 19f:	4f 5f                	rex.WRXB pop %r15
 1a1:	77 72                	ja     215 <_init-0xdeb>
 1a3:	69 74 65 5f 62 61 73 	imul   $0x65736162,0x5f(%rbp,%riz,2),%esi
 1aa:	65 
 1ab:	00 5f 75             	add    %bl,0x75(%rdi)
 1ae:	6e                   	outsb  %ds:(%rsi),(%dx)
 1af:	75 73                	jne    224 <_init-0xddc>
 1b1:	65 64 32 00          	gs xor %fs:(%rax),%al
 1b5:	5f                   	pop    %rdi
 1b6:	49                   	rex.WB
 1b7:	4f 5f                	rex.WRXB pop %r15
 1b9:	72 65                	jb     220 <_init-0xde0>
 1bb:	61                   	(bad)  
 1bc:	64 5f                	fs pop %rdi
 1be:	70 74                	jo     234 <_init-0xdcc>
 1c0:	72 00                	jb     1c2 <_init-0xe3e>
 1c2:	5f                   	pop    %rdi
 1c3:	49                   	rex.WB
 1c4:	4f 5f                	rex.WRXB pop %r15
 1c6:	62                   	(bad)  
 1c7:	75 66                	jne    22f <_init-0xdd1>
 1c9:	5f                   	pop    %rdi
 1ca:	65 6e                	outsb  %gs:(%rsi),(%dx)
 1cc:	64 00 74 65 73       	add    %dh,%fs:0x73(%rbp,%riz,2)
 1d1:	74 5f                	je     232 <_init-0xdce>
 1d3:	74 00                	je     1d5 <_init-0xe2b>
 1d5:	6d                   	insl   (%dx),%es:(%rdi)
 1d6:	61                   	(bad)  
 1d7:	69 6e 00 47 4e 55 20 	imul   $0x20554e47,0x0(%rsi),%ebp
 1de:	43 31 31             	rex.XB xor %esi,(%r9)
 1e1:	20 37                	and    %dh,(%rdi)
 1e3:	2e 35 2e 30 20 2d    	cs xor $0x2d20302e,%eax
 1e9:	6d                   	insl   (%dx),%es:(%rdi)
 1ea:	74 75                	je     261 <_init-0xd9f>
 1ec:	6e                   	outsb  %ds:(%rsi),(%dx)
 1ed:	65 3d 67 65 6e 65    	gs cmp $0x656e6567,%eax
 1f3:	72 69                	jb     25e <_init-0xda2>
 1f5:	63 20                	movslq (%rax),%esp
 1f7:	2d 6d 61 72 63       	sub    $0x6372616d,%eax
 1fc:	68 3d 78 38 36       	pushq  $0x3638783d
 201:	2d 36 34 20 2d       	sub    $0x2d203436,%eax
 206:	67 20 2d 66 50 49 45 	and    %ch,0x45495066(%eip)        # 45495273 <_end+0x4549125b>
 20d:	20 2d 66 73 74 61    	and    %ch,0x61747366(%rip)        # 61747579 <_end+0x61743561>
 213:	63 6b 2d             	movslq 0x2d(%rbx),%ebp
 216:	70 72                	jo     28a <_init-0xd76>
 218:	6f                   	outsl  %ds:(%rsi),(%dx)
 219:	74 65                	je     280 <_init-0xd80>
 21b:	63 74 6f 72          	movslq 0x72(%rdi,%rbp,2),%esi
 21f:	2d 73 74 72 6f       	sub    $0x6f727473,%eax
 224:	6e                   	outsb  %ds:(%rsi),(%dx)
 225:	67 00 5f 6e          	add    %bl,0x6e(%edi)
 229:	65 78 74             	gs js  2a0 <_init-0xd60>
 22c:	00 5f 5f             	add    %bl,0x5f(%rdi)
 22f:	70 61                	jo     292 <_init-0xd6e>
 231:	64 31 00             	xor    %eax,%fs:(%rax)
 234:	5f                   	pop    %rdi
 235:	5f                   	pop    %rdi
 236:	70 61                	jo     299 <_init-0xd67>
 238:	64 32 00             	xor    %fs:(%rax),%al
 23b:	5f                   	pop    %rdi
 23c:	5f                   	pop    %rdi
 23d:	70 61                	jo     2a0 <_init-0xd60>
 23f:	64 33 00             	xor    %fs:(%rax),%eax
 242:	5f                   	pop    %rdi
 243:	5f                   	pop    %rdi
 244:	70 61                	jo     2a7 <_init-0xd59>
 246:	64 34 00             	fs xor $0x0,%al
 249:	5f                   	pop    %rdi
 24a:	5f                   	pop    %rdi
 24b:	70 61                	jo     2ae <_init-0xd52>
 24d:	64 35 00 5f 5f 75    	fs xor $0x755f5f00,%eax
 253:	69 6e 74 36 34 5f 74 	imul   $0x745f3436,0x74(%rsi),%ebp
 25a:	00 6f 67             	add    %ch,0x67(%rdi)
 25d:	73 5f                	jae    2be <_init-0xd42>
 25f:	6c                   	insb   (%dx),%es:(%rdi)
 260:	69 6d 69 74 00 62 75 	imul   $0x75620074,0x69(%rbp),%ebp
 267:	66 66 65 72 00       	data16 data16 gs jb 26c <_init-0xd94>
 26c:	73 68                	jae    2d6 <_init-0xd2a>
 26e:	6f                   	outsl  %ds:(%rsi),(%dx)
 26f:	72 74                	jb     2e5 <_init-0xd1b>
 271:	20 75 6e             	and    %dh,0x6e(%rbp)
 274:	73 69                	jae    2df <_init-0xd21>
 276:	67 6e                	outsb  %ds:(%esi),(%dx)
 278:	65 64 20 69 6e       	gs and %ch,%fs:0x6e(%rcx)
 27d:	74 00                	je     27f <_init-0xd81>
 27f:	5f                   	pop    %rdi
 280:	49                   	rex.WB
 281:	4f 5f                	rex.WRXB pop %r15
 283:	32 5f 31             	xor    0x31(%rdi),%bl
 286:	5f                   	pop    %rdi
 287:	73 74                	jae    2fd <_init-0xd03>
 289:	64 65 72 72          	fs gs jb 2ff <_init-0xd01>
 28d:	5f                   	pop    %rdi
 28e:	00 5f 49             	add    %bl,0x49(%rdi)
 291:	4f 5f                	rex.WRXB pop %r15
 293:	77 72                	ja     307 <_init-0xcf9>
 295:	69 74 65 5f 65 6e 64 	imul   $0x646e65,0x5f(%rbp,%riz,2),%esi
 29c:	00 
 29d:	5f                   	pop    %rdi
 29e:	5f                   	pop    %rdi
 29f:	6f                   	outsl  %ds:(%rsi),(%dx)
 2a0:	66 66 36 34 5f       	data16 data16 ss xor $0x5f,%al
 2a5:	74 00                	je     2a7 <_init-0xd59>
 2a7:	5f                   	pop    %rdi
 2a8:	66 69 6c 65 6e 6f 00 	imul   $0x6f,0x6e(%rbp,%riz,2),%bp
 2af:	68 61 6e 64 6c       	pushq  $0x6c646e61
 2b4:	65 00 2e             	add    %ch,%gs:(%rsi)
 2b7:	2f                   	(bad)  
 2b8:	6c                   	insb   (%dx),%es:(%rdi)
 2b9:	6f                   	outsl  %ds:(%rsi),(%dx)
 2ba:	61                   	(bad)  
 2bb:	64 65 72 2e          	fs gs jb 2ed <_init-0xd13>
 2bf:	63 00                	movslq (%rax),%eax
 2c1:	5f                   	pop    %rdi
 2c2:	5f                   	pop    %rdi
 2c3:	6f                   	outsl  %ds:(%rsi),(%dx)
 2c4:	66 66 5f             	data16 pop %di
 2c7:	74 00                	je     2c9 <_init-0xd37>
 2c9:	5f                   	pop    %rdi
 2ca:	49                   	rex.WB
 2cb:	4f 5f                	rex.WRXB pop %r15
 2cd:	62 61                	(bad)  
 2cf:	63 6b 75             	movslq 0x75(%rbx),%ebp
 2d2:	70 5f                	jo     333 <_init-0xccd>
 2d4:	62 61                	(bad)  
 2d6:	73 65                	jae    33d <_init-0xcc3>
 2d8:	00 73 74             	add    %dh,0x74(%rbx)
 2db:	64 69 6e 00 61 72 63 	imul   $0x68637261,%fs:0x0(%rsi),%ebp
 2e2:	68 
 2e3:	5f                   	pop    %rdi
 2e4:	70 72                	jo     358 <_init-0xca8>
 2e6:	63 74 6c 00          	movslq 0x0(%rsp,%rbp,2),%esi
 2ea:	5f                   	pop    %rdi
 2eb:	66 6c                	data16 insb (%dx),%es:(%rdi)
 2ed:	61                   	(bad)  
 2ee:	67 73 32             	addr32 jae 323 <_init-0xcdd>
 2f1:	00 5f 6d             	add    %bl,0x6d(%rdi)
 2f4:	6f                   	outsl  %ds:(%rsi),(%dx)
 2f5:	64 65 00 5f 49       	fs add %bl,%gs:0x49(%rdi)
 2fa:	4f 5f                	rex.WRXB pop %r15
 2fc:	72 65                	jb     363 <_init-0xc9d>
 2fe:	61                   	(bad)  
 2ff:	64 5f                	fs pop %rdi
 301:	62 61                	(bad)  
 303:	73 65                	jae    36a <_init-0xc96>
 305:	00 70 6f             	add    %dh,0x6f(%rax)
 308:	69 6e 74 65 72 00 5f 	imul   $0x5f007265,0x74(%rsi),%ebp
 30f:	76 74                	jbe    385 <_init-0xc7b>
 311:	61                   	(bad)  
 312:	62                   	(bad)  
 313:	6c                   	insb   (%dx),%es:(%rdi)
 314:	65 5f                	gs pop %rdi
 316:	6f                   	outsl  %ds:(%rsi),(%dx)
 317:	66 66 73 65          	data16 data16 jae 380 <_init-0xc80>
 31b:	74 00                	je     31d <_init-0xce3>
 31d:	5f                   	pop    %rdi
 31e:	49                   	rex.WB
 31f:	4f 5f                	rex.WRXB pop %r15
 321:	73 61                	jae    384 <_init-0xc7c>
 323:	76 65                	jbe    38a <_init-0xc76>
 325:	5f                   	pop    %rdi
 326:	62 61                	(bad)  
 328:	73 65                	jae    38f <_init-0xc71>
 32a:	00 73 79             	add    %dh,0x79(%rbx)
 32d:	73 5f                	jae    38e <_init-0xc72>
 32f:	65 72 72             	gs jb  3a4 <_init-0xc5c>
 332:	6c                   	insb   (%dx),%es:(%rdi)
 333:	69 73 74 00 72 65 73 	imul   $0x73657200,0x74(%rbx),%esi
 33a:	65 72 76             	gs jb  3b3 <_init-0xc4d>
 33d:	65 64 00 6e 73       	gs add %ch,%fs:0x73(%rsi)
 342:	73 61                	jae    3a5 <_init-0xc5b>
 344:	00 6f 66             	add    %ch,0x66(%rdi)
 347:	73 5f                	jae    3a8 <_init-0xc58>
 349:	62 61                	(bad)  
 34b:	73 65                	jae    3b2 <_init-0xc4e>
 34d:	00 73 74             	add    %dh,0x74(%rbx)
 350:	64 6f                	outsl  %fs:(%rsi),(%dx)
 352:	75 74                	jne    3c8 <_init-0xc38>
 354:	00 5f 49             	add    %bl,0x49(%rdi)
 357:	4f 5f                	rex.WRXB pop %r15
 359:	6c                   	insb   (%dx),%es:(%rdi)
 35a:	6f                   	outsl  %ds:(%rsi),(%dx)
 35b:	63 6b 5f             	movslq 0x5f(%rbx),%ebp
 35e:	74 00                	je     360 <_init-0xca0>
