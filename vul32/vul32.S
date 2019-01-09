
vul32:     file format elf32-i386


Disassembly of section .interp:

08048154 <.interp>:
 8048154:	2f                   	das    
 8048155:	6c                   	insb   (%dx),%es:(%edi)
 8048156:	69 62 2f 6c 64 2d 6c 	imul   $0x6c2d646c,0x2f(%edx),%esp
 804815d:	69 6e 75 78 2e 73 6f 	imul   $0x6f732e78,0x75(%esi),%ebp
 8048164:	2e 32 00             	xor    %cs:(%eax),%al

Disassembly of section .note.ABI-tag:

08048168 <.note.ABI-tag>:
 8048168:	04 00                	add    $0x0,%al
 804816a:	00 00                	add    %al,(%eax)
 804816c:	10 00                	adc    %al,(%eax)
 804816e:	00 00                	add    %al,(%eax)
 8048170:	01 00                	add    %eax,(%eax)
 8048172:	00 00                	add    %al,(%eax)
 8048174:	47                   	inc    %edi
 8048175:	4e                   	dec    %esi
 8048176:	55                   	push   %ebp
 8048177:	00 00                	add    %al,(%eax)
 8048179:	00 00                	add    %al,(%eax)
 804817b:	00 02                	add    %al,(%edx)
 804817d:	00 00                	add    %al,(%eax)
 804817f:	00 06                	add    %al,(%esi)
 8048181:	00 00                	add    %al,(%eax)
 8048183:	00 20                	add    %ah,(%eax)
 8048185:	00 00                	add    %al,(%eax)
	...

Disassembly of section .note.gnu.build-id:

08048188 <.note.gnu.build-id>:
 8048188:	04 00                	add    $0x0,%al
 804818a:	00 00                	add    %al,(%eax)
 804818c:	14 00                	adc    $0x0,%al
 804818e:	00 00                	add    %al,(%eax)
 8048190:	03 00                	add    (%eax),%eax
 8048192:	00 00                	add    %al,(%eax)
 8048194:	47                   	inc    %edi
 8048195:	4e                   	dec    %esi
 8048196:	55                   	push   %ebp
 8048197:	00 8f 8a 04 cd b5    	add    %cl,-0x4a32fb76(%edi)
 804819d:	94                   	xchg   %eax,%esp
 804819e:	ac                   	lods   %ds:(%esi),%al
 804819f:	c2 12 78             	ret    $0x7812
 80481a2:	28 25 aa 21 00 41    	sub    %ah,0x410021aa
 80481a8:	7b e4                	jnp    804818e <_init-0x27a>
 80481aa:	b0 91                	mov    $0x91,%al

Disassembly of section .gnu.hash:

080481ac <.gnu.hash>:
 80481ac:	03 00                	add    (%eax),%eax
 80481ae:	00 00                	add    %al,(%eax)
 80481b0:	0a 00                	or     (%eax),%al
 80481b2:	00 00                	add    %al,(%eax)
 80481b4:	01 00                	add    %eax,(%eax)
 80481b6:	00 00                	add    %al,(%eax)
 80481b8:	05 00 00 00 80       	add    $0x80000000,%eax
 80481bd:	2b 02                	sub    (%edx),%eax
 80481bf:	22 0a                	and    (%edx),%cl
 80481c1:	00 00                	add    %al,(%eax)
 80481c3:	00 0b                	add    %cl,(%ebx)
 80481c5:	00 00                	add    %al,(%eax)
 80481c7:	00 00                	add    %al,(%eax)
 80481c9:	00 00                	add    %al,(%eax)
 80481cb:	00 29                	add    %ch,(%ecx)
 80481cd:	1d 8c 1c 38 f2       	sbb    $0xf2381c8c,%eax
 80481d2:	8b 1c ac             	mov    (%esp,%ebp,4),%ebx
 80481d5:	4b                   	dec    %ebx
 80481d6:	e3 c0                	jecxz  8048198 <_init-0x270>
 80481d8:	67 55                	addr16 push %ebp
 80481da:	61                   	popa   
 80481db:	10                   	.byte 0x10

Disassembly of section .dynsym:

080481dc <.dynsym>:
	...
 80481ec:	55                   	push   %ebp
	...
 80481f5:	00 00                	add    %al,(%eax)
 80481f7:	00 12                	add    %dl,(%edx)
 80481f9:	00 00                	add    %al,(%eax)
 80481fb:	00 42 00             	add    %al,0x0(%edx)
	...
 8048206:	00 00                	add    %al,(%eax)
 8048208:	12 00                	adc    (%eax),%al
 804820a:	00 00                	add    %al,(%eax)
 804820c:	24 00                	and    $0x0,%al
	...
 8048216:	00 00                	add    %al,(%eax)
 8048218:	12 00                	adc    (%eax),%al
 804821a:	00 00                	add    %al,(%eax)
 804821c:	1f                   	pop    %ds
	...
 8048225:	00 00                	add    %al,(%eax)
 8048227:	00 12                	add    %dl,(%edx)
 8048229:	00 00                	add    %al,(%eax)
 804822b:	00 74 00 00          	add    %dh,0x0(%eax,%eax,1)
	...
 8048237:	00 20                	add    %ah,(%eax)
 8048239:	00 00                	add    %al,(%eax)
 804823b:	00 1a                	add    %bl,(%edx)
	...
 8048245:	00 00                	add    %al,(%eax)
 8048247:	00 12                	add    %dl,(%edx)
 8048249:	00 00                	add    %al,(%eax)
 804824b:	00 5c 00 00          	add    %bl,0x0(%eax,%eax,1)
	...
 8048257:	00 12                	add    %dl,(%edx)
 8048259:	00 00                	add    %al,(%eax)
 804825b:	00 6e 00             	add    %ch,0x0(%esi)
	...
 8048266:	00 00                	add    %al,(%eax)
 8048268:	12 00                	adc    (%eax),%al
 804826a:	00 00                	add    %al,(%eax)
 804826c:	3b 00                	cmp    (%eax),%eax
	...
 8048276:	00 00                	add    %al,(%eax)
 8048278:	12 00                	adc    (%eax),%al
 804827a:	00 00                	add    %al,(%eax)
 804827c:	47                   	inc    %edi
 804827d:	00 00                	add    %al,(%eax)
 804827f:	00 84 a0 04 08 04 00 	add    %al,0x40804(%eax,%eiz,4)
 8048286:	00 00                	add    %al,(%eax)
 8048288:	11 00                	adc    %eax,(%eax)
 804828a:	19 00                	sbb    %eax,(%eax)
 804828c:	4e                   	dec    %esi
 804828d:	00 00                	add    %al,(%eax)
 804828f:	00 60 a0             	add    %ah,-0x60(%eax)
 8048292:	04 08                	add    $0x8,%al
 8048294:	04 00                	add    $0x0,%al
 8048296:	00 00                	add    %al,(%eax)
 8048298:	11 00                	adc    %eax,(%eax)
 804829a:	19 00                	sbb    %eax,(%eax)
 804829c:	0b 00                	or     (%eax),%eax
 804829e:	00 00                	add    %al,(%eax)
 80482a0:	4c                   	dec    %esp
 80482a1:	87 04 08             	xchg   %eax,(%eax,%ecx,1)
 80482a4:	04 00                	add    $0x0,%al
 80482a6:	00 00                	add    %al,(%eax)
 80482a8:	11 00                	adc    %eax,(%eax)
 80482aa:	0f 00                	(bad)  
 80482ac:	35 00 00 00 80       	xor    $0x80000000,%eax
 80482b1:	a0 04 08 04 00       	mov    0x40804,%al
 80482b6:	00 00                	add    %al,(%eax)
 80482b8:	11 00                	adc    %eax,(%eax)
 80482ba:	19 00                	sbb    %eax,(%eax)

Disassembly of section .dynstr:

080482bc <.dynstr>:
 80482bc:	00 6c 69 62          	add    %ch,0x62(%ecx,%ebp,2)
 80482c0:	63 2e                	arpl   %bp,(%esi)
 80482c2:	73 6f                	jae    8048333 <_init-0xd5>
 80482c4:	2e 36 00 5f 49       	cs add %bl,%ss:0x49(%edi)
 80482c9:	4f                   	dec    %edi
 80482ca:	5f                   	pop    %edi
 80482cb:	73 74                	jae    8048341 <_init-0xc7>
 80482cd:	64 69 6e 5f 75 73 65 	imul   $0x64657375,%fs:0x5f(%esi),%ebp
 80482d4:	64 
 80482d5:	00 65 78             	add    %ah,0x78(%ebp)
 80482d8:	69 74 00 70 75 74 73 	imul   $0x737475,0x70(%eax,%eax,1),%esi
 80482df:	00 
 80482e0:	5f                   	pop    %edi
 80482e1:	5f                   	pop    %edi
 80482e2:	73 74                	jae    8048358 <_init-0xb0>
 80482e4:	61                   	popa   
 80482e5:	63 6b 5f             	arpl   %bp,0x5f(%ebx)
 80482e8:	63 68 6b             	arpl   %bp,0x6b(%eax)
 80482eb:	5f                   	pop    %edi
 80482ec:	66 61                	popaw  
 80482ee:	69 6c 00 73 74 64 69 	imul   $0x6e696474,0x73(%eax,%eax,1),%ebp
 80482f5:	6e 
 80482f6:	00 6d 65             	add    %ch,0x65(%ebp)
 80482f9:	6d                   	insl   (%dx),%es:(%edi)
 80482fa:	73 65                	jae    8048361 <_init-0xa7>
 80482fc:	74 00                	je     80482fe <_init-0x10a>
 80482fe:	72 65                	jb     8048365 <_init-0xa3>
 8048300:	61                   	popa   
 8048301:	64 00 73 74          	add    %dh,%fs:0x74(%ebx)
 8048305:	64 6f                	outsl  %fs:(%esi),(%dx)
 8048307:	75 74                	jne    804837d <_init-0x8b>
 8048309:	00 73 74             	add    %dh,0x74(%ebx)
 804830c:	64 65 72 72          	fs gs jb 8048382 <_init-0x86>
 8048310:	00 73 65             	add    %dh,0x65(%ebx)
 8048313:	74 62                	je     8048377 <_init-0x91>
 8048315:	75 66                	jne    804837d <_init-0x8b>
 8048317:	00 5f 5f             	add    %bl,0x5f(%edi)
 804831a:	6c                   	insb   (%dx),%es:(%edi)
 804831b:	69 62 63 5f 73 74 61 	imul   $0x6174735f,0x63(%edx),%esp
 8048322:	72 74                	jb     8048398 <_init-0x70>
 8048324:	5f                   	pop    %edi
 8048325:	6d                   	insl   (%dx),%es:(%edi)
 8048326:	61                   	popa   
 8048327:	69 6e 00 77 72 69 74 	imul   $0x74697277,0x0(%esi),%ebp
 804832e:	65 00 5f 5f          	add    %bl,%gs:0x5f(%edi)
 8048332:	67 6d                	insl   (%dx),%es:(%di)
 8048334:	6f                   	outsl  %ds:(%esi),(%dx)
 8048335:	6e                   	outsb  %ds:(%esi),(%dx)
 8048336:	5f                   	pop    %edi
 8048337:	73 74                	jae    80483ad <_init-0x5b>
 8048339:	61                   	popa   
 804833a:	72 74                	jb     80483b0 <_init-0x58>
 804833c:	5f                   	pop    %edi
 804833d:	5f                   	pop    %edi
 804833e:	00 47 4c             	add    %al,0x4c(%edi)
 8048341:	49                   	dec    %ecx
 8048342:	42                   	inc    %edx
 8048343:	43                   	inc    %ebx
 8048344:	5f                   	pop    %edi
 8048345:	32 2e                	xor    (%esi),%ch
 8048347:	34 00                	xor    $0x0,%al
 8048349:	47                   	inc    %edi
 804834a:	4c                   	dec    %esp
 804834b:	49                   	dec    %ecx
 804834c:	42                   	inc    %edx
 804834d:	43                   	inc    %ebx
 804834e:	5f                   	pop    %edi
 804834f:	32 2e                	xor    (%esi),%ch
 8048351:	30 00                	xor    %al,(%eax)

Disassembly of section .gnu.version:

08048354 <.gnu.version>:
 8048354:	00 00                	add    %al,(%eax)
 8048356:	02 00                	add    (%eax),%al
 8048358:	02 00                	add    (%eax),%al
 804835a:	03 00                	add    (%eax),%eax
 804835c:	02 00                	add    (%eax),%al
 804835e:	00 00                	add    %al,(%eax)
 8048360:	02 00                	add    (%eax),%al
 8048362:	02 00                	add    (%eax),%al
 8048364:	02 00                	add    (%eax),%al
 8048366:	02 00                	add    (%eax),%al
 8048368:	02 00                	add    (%eax),%al
 804836a:	02 00                	add    (%eax),%al
 804836c:	01 00                	add    %eax,(%eax)
 804836e:	02 00                	add    (%eax),%al

Disassembly of section .gnu.version_r:

08048370 <.gnu.version_r>:
 8048370:	01 00                	add    %eax,(%eax)
 8048372:	02 00                	add    (%eax),%al
 8048374:	01 00                	add    %eax,(%eax)
 8048376:	00 00                	add    %al,(%eax)
 8048378:	10 00                	adc    %al,(%eax)
 804837a:	00 00                	add    %al,(%eax)
 804837c:	00 00                	add    %al,(%eax)
 804837e:	00 00                	add    %al,(%eax)
 8048380:	14 69                	adc    $0x69,%al
 8048382:	69 0d 00 00 03 00 83 	imul   $0x83,0x30000,%ecx
 8048389:	00 00 00 
 804838c:	10 00                	adc    %al,(%eax)
 804838e:	00 00                	add    %al,(%eax)
 8048390:	10 69 69             	adc    %ch,0x69(%ecx)
 8048393:	0d 00 00 02 00       	or     $0x20000,%eax
 8048398:	8d 00                	lea    (%eax),%eax
 804839a:	00 00                	add    %al,(%eax)
 804839c:	00 00                	add    %al,(%eax)
	...

Disassembly of section .rel.dyn:

080483a0 <.rel.dyn>:
 80483a0:	fc                   	cld    
 80483a1:	9f                   	lahf   
 80483a2:	04 08                	add    $0x8,%al
 80483a4:	06                   	push   %es
 80483a5:	05 00 00 60 a0       	add    $0xa0600000,%eax
 80483aa:	04 08                	add    $0x8,%al
 80483ac:	05 0b 00 00 80       	add    $0x8000000b,%eax
 80483b1:	a0 04 08 05 0d       	mov    0xd050804,%al
 80483b6:	00 00                	add    %al,(%eax)
 80483b8:	84 a0 04 08 05 0a    	test   %ah,0xa050804(%eax)
	...

Disassembly of section .rel.plt:

080483c0 <.rel.plt>:
 80483c0:	0c a0                	or     $0xa0,%al
 80483c2:	04 08                	add    $0x8,%al
 80483c4:	07                   	pop    %es
 80483c5:	01 00                	add    %eax,(%eax)
 80483c7:	00 10                	add    %dl,(%eax)
 80483c9:	a0 04 08 07 02       	mov    0x2070804,%al
 80483ce:	00 00                	add    %al,(%eax)
 80483d0:	14 a0                	adc    $0xa0,%al
 80483d2:	04 08                	add    $0x8,%al
 80483d4:	07                   	pop    %es
 80483d5:	03 00                	add    (%eax),%eax
 80483d7:	00 18                	add    %bl,(%eax)
 80483d9:	a0 04 08 07 04       	mov    0x4070804,%al
 80483de:	00 00                	add    %al,(%eax)
 80483e0:	1c a0                	sbb    $0xa0,%al
 80483e2:	04 08                	add    $0x8,%al
 80483e4:	07                   	pop    %es
 80483e5:	05 00 00 20 a0       	add    $0xa0200000,%eax
 80483ea:	04 08                	add    $0x8,%al
 80483ec:	07                   	pop    %es
 80483ed:	06                   	push   %es
 80483ee:	00 00                	add    %al,(%eax)
 80483f0:	24 a0                	and    $0xa0,%al
 80483f2:	04 08                	add    $0x8,%al
 80483f4:	07                   	pop    %es
 80483f5:	07                   	pop    %es
 80483f6:	00 00                	add    %al,(%eax)
 80483f8:	28 a0 04 08 07 08    	sub    %ah,0x8070804(%eax)
 80483fe:	00 00                	add    %al,(%eax)
 8048400:	2c a0                	sub    $0xa0,%al
 8048402:	04 08                	add    $0x8,%al
 8048404:	07                   	pop    %es
 8048405:	09 00                	or     %eax,(%eax)
	...

Disassembly of section .init:

08048408 <_init>:
 8048408:	53                   	push   %ebx
 8048409:	83 ec 08             	sub    $0x8,%esp
 804840c:	e8 ef 00 00 00       	call   8048500 <__x86.get_pc_thunk.bx>
 8048411:	81 c3 ef 1b 00 00    	add    $0x1bef,%ebx
 8048417:	8b 83 fc ff ff ff    	mov    -0x4(%ebx),%eax
 804841d:	85 c0                	test   %eax,%eax
 804841f:	74 05                	je     8048426 <_init+0x1e>
 8048421:	e8 5a 00 00 00       	call   8048480 <__gmon_start__@plt>
 8048426:	83 c4 08             	add    $0x8,%esp
 8048429:	5b                   	pop    %ebx
 804842a:	c3                   	ret    

Disassembly of section .plt:

08048430 <setbuf@plt-0x10>:
 8048430:	ff 35 04 a0 04 08    	pushl  0x804a004
 8048436:	ff 25 08 a0 04 08    	jmp    *0x804a008
 804843c:	00 00                	add    %al,(%eax)
	...

08048440 <setbuf@plt>:
 8048440:	ff 25 0c a0 04 08    	jmp    *0x804a00c
 8048446:	68 00 00 00 00       	push   $0x0
 804844b:	e9 e0 ff ff ff       	jmp    8048430 <_init+0x28>

08048450 <read@plt>:
 8048450:	ff 25 10 a0 04 08    	jmp    *0x804a010
 8048456:	68 08 00 00 00       	push   $0x8
 804845b:	e9 d0 ff ff ff       	jmp    8048430 <_init+0x28>

08048460 <__stack_chk_fail@plt>:
 8048460:	ff 25 14 a0 04 08    	jmp    *0x804a014
 8048466:	68 10 00 00 00       	push   $0x10
 804846b:	e9 c0 ff ff ff       	jmp    8048430 <_init+0x28>

08048470 <puts@plt>:
 8048470:	ff 25 18 a0 04 08    	jmp    *0x804a018
 8048476:	68 18 00 00 00       	push   $0x18
 804847b:	e9 b0 ff ff ff       	jmp    8048430 <_init+0x28>

08048480 <__gmon_start__@plt>:
 8048480:	ff 25 1c a0 04 08    	jmp    *0x804a01c
 8048486:	68 20 00 00 00       	push   $0x20
 804848b:	e9 a0 ff ff ff       	jmp    8048430 <_init+0x28>

08048490 <exit@plt>:
 8048490:	ff 25 20 a0 04 08    	jmp    *0x804a020
 8048496:	68 28 00 00 00       	push   $0x28
 804849b:	e9 90 ff ff ff       	jmp    8048430 <_init+0x28>

080484a0 <__libc_start_main@plt>:
 80484a0:	ff 25 24 a0 04 08    	jmp    *0x804a024
 80484a6:	68 30 00 00 00       	push   $0x30
 80484ab:	e9 80 ff ff ff       	jmp    8048430 <_init+0x28>

080484b0 <write@plt>:
 80484b0:	ff 25 28 a0 04 08    	jmp    *0x804a028
 80484b6:	68 38 00 00 00       	push   $0x38
 80484bb:	e9 70 ff ff ff       	jmp    8048430 <_init+0x28>

080484c0 <memset@plt>:
 80484c0:	ff 25 2c a0 04 08    	jmp    *0x804a02c
 80484c6:	68 40 00 00 00       	push   $0x40
 80484cb:	e9 60 ff ff ff       	jmp    8048430 <_init+0x28>

Disassembly of section .text:

080484d0 <_start>:
 80484d0:	31 ed                	xor    %ebp,%ebp
 80484d2:	5e                   	pop    %esi
 80484d3:	89 e1                	mov    %esp,%ecx
 80484d5:	83 e4 f0             	and    $0xfffffff0,%esp
 80484d8:	50                   	push   %eax
 80484d9:	54                   	push   %esp
 80484da:	52                   	push   %edx
 80484db:	68 30 87 04 08       	push   $0x8048730
 80484e0:	68 d0 86 04 08       	push   $0x80486d0
 80484e5:	51                   	push   %ecx
 80484e6:	56                   	push   %esi
 80484e7:	68 5c 86 04 08       	push   $0x804865c
 80484ec:	e8 af ff ff ff       	call   80484a0 <__libc_start_main@plt>
 80484f1:	f4                   	hlt    
 80484f2:	66 90                	xchg   %ax,%ax
 80484f4:	66 90                	xchg   %ax,%ax
 80484f6:	66 90                	xchg   %ax,%ax
 80484f8:	66 90                	xchg   %ax,%ax
 80484fa:	66 90                	xchg   %ax,%ax
 80484fc:	66 90                	xchg   %ax,%ax
 80484fe:	66 90                	xchg   %ax,%ax

08048500 <__x86.get_pc_thunk.bx>:
 8048500:	8b 1c 24             	mov    (%esp),%ebx
 8048503:	c3                   	ret    
 8048504:	66 90                	xchg   %ax,%ax
 8048506:	66 90                	xchg   %ax,%ax
 8048508:	66 90                	xchg   %ax,%ax
 804850a:	66 90                	xchg   %ax,%ax
 804850c:	66 90                	xchg   %ax,%ax
 804850e:	66 90                	xchg   %ax,%ax

08048510 <deregister_tm_clones>:
 8048510:	b8 5b a0 04 08       	mov    $0x804a05b,%eax
 8048515:	2d 58 a0 04 08       	sub    $0x804a058,%eax
 804851a:	83 f8 06             	cmp    $0x6,%eax
 804851d:	76 1a                	jbe    8048539 <deregister_tm_clones+0x29>
 804851f:	b8 00 00 00 00       	mov    $0x0,%eax
 8048524:	85 c0                	test   %eax,%eax
 8048526:	74 11                	je     8048539 <deregister_tm_clones+0x29>
 8048528:	55                   	push   %ebp
 8048529:	89 e5                	mov    %esp,%ebp
 804852b:	83 ec 14             	sub    $0x14,%esp
 804852e:	68 58 a0 04 08       	push   $0x804a058
 8048533:	ff d0                	call   *%eax
 8048535:	83 c4 10             	add    $0x10,%esp
 8048538:	c9                   	leave  
 8048539:	f3 c3                	repz ret 
 804853b:	90                   	nop
 804853c:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi

08048540 <register_tm_clones>:
 8048540:	b8 58 a0 04 08       	mov    $0x804a058,%eax
 8048545:	2d 58 a0 04 08       	sub    $0x804a058,%eax
 804854a:	c1 f8 02             	sar    $0x2,%eax
 804854d:	89 c2                	mov    %eax,%edx
 804854f:	c1 ea 1f             	shr    $0x1f,%edx
 8048552:	01 d0                	add    %edx,%eax
 8048554:	d1 f8                	sar    %eax
 8048556:	74 1b                	je     8048573 <register_tm_clones+0x33>
 8048558:	ba 00 00 00 00       	mov    $0x0,%edx
 804855d:	85 d2                	test   %edx,%edx
 804855f:	74 12                	je     8048573 <register_tm_clones+0x33>
 8048561:	55                   	push   %ebp
 8048562:	89 e5                	mov    %esp,%ebp
 8048564:	83 ec 10             	sub    $0x10,%esp
 8048567:	50                   	push   %eax
 8048568:	68 58 a0 04 08       	push   $0x804a058
 804856d:	ff d2                	call   *%edx
 804856f:	83 c4 10             	add    $0x10,%esp
 8048572:	c9                   	leave  
 8048573:	f3 c3                	repz ret 
 8048575:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
 8048579:	8d bc 27 00 00 00 00 	lea    0x0(%edi,%eiz,1),%edi

08048580 <__do_global_dtors_aux>:
 8048580:	80 3d 88 a0 04 08 00 	cmpb   $0x0,0x804a088
 8048587:	75 13                	jne    804859c <__do_global_dtors_aux+0x1c>
 8048589:	55                   	push   %ebp
 804858a:	89 e5                	mov    %esp,%ebp
 804858c:	83 ec 08             	sub    $0x8,%esp
 804858f:	e8 7c ff ff ff       	call   8048510 <deregister_tm_clones>
 8048594:	c6 05 88 a0 04 08 01 	movb   $0x1,0x804a088
 804859b:	c9                   	leave  
 804859c:	f3 c3                	repz ret 
 804859e:	66 90                	xchg   %ax,%ax

080485a0 <frame_dummy>:
 80485a0:	b8 10 9f 04 08       	mov    $0x8049f10,%eax
 80485a5:	8b 10                	mov    (%eax),%edx
 80485a7:	85 d2                	test   %edx,%edx
 80485a9:	75 05                	jne    80485b0 <frame_dummy+0x10>
 80485ab:	eb 93                	jmp    8048540 <register_tm_clones>
 80485ad:	8d 76 00             	lea    0x0(%esi),%esi
 80485b0:	ba 00 00 00 00       	mov    $0x0,%edx
 80485b5:	85 d2                	test   %edx,%edx
 80485b7:	74 f2                	je     80485ab <frame_dummy+0xb>
 80485b9:	55                   	push   %ebp
 80485ba:	89 e5                	mov    %esp,%ebp
 80485bc:	83 ec 14             	sub    $0x14,%esp
 80485bf:	50                   	push   %eax
 80485c0:	ff d2                	call   *%edx
 80485c2:	83 c4 10             	add    $0x10,%esp
 80485c5:	c9                   	leave  
 80485c6:	e9 75 ff ff ff       	jmp    8048540 <register_tm_clones>

080485cb <dovuln>:
 80485cb:	55                   	push   %ebp
 80485cc:	89 e5                	mov    %esp,%ebp
 80485ce:	83 ec 48             	sub    $0x48,%esp
 80485d1:	65 a1 14 00 00 00    	mov    %gs:0x14,%eax
 80485d7:	89 45 f4             	mov    %eax,-0xc(%ebp)
 80485da:	31 c0                	xor    %eax,%eax
 80485dc:	83 ec 04             	sub    $0x4,%esp
 80485df:	6a 30                	push   $0x30
 80485e1:	6a 00                	push   $0x0
 80485e3:	8d 45 bc             	lea    -0x44(%ebp),%eax
 80485e6:	83 c0 01             	add    $0x1,%eax
 80485e9:	50                   	push   %eax
 80485ea:	e8 d1 fe ff ff       	call   80484c0 <memset@plt>
 80485ef:	83 c4 10             	add    $0x10,%esp
 80485f2:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
 80485f9:	83 ec 04             	sub    $0x4,%esp
 80485fc:	6a 01                	push   $0x1
 80485fe:	8d 45 bc             	lea    -0x44(%ebp),%eax
 8048601:	50                   	push   %eax
 8048602:	6a 00                	push   $0x0
 8048604:	e8 47 fe ff ff       	call   8048450 <read@plt>
 8048609:	83 c4 10             	add    $0x10,%esp
 804860c:	83 f8 01             	cmp    $0x1,%eax
 804860f:	74 0a                	je     804861b <dovuln+0x50>
 8048611:	83 ec 0c             	sub    $0xc,%esp
 8048614:	6a 00                	push   $0x0
 8048616:	e8 75 fe ff ff       	call   8048490 <exit@plt>
 804861b:	0f b6 45 bc          	movzbl -0x44(%ebp),%eax
 804861f:	3c 0a                	cmp    $0xa,%al
 8048621:	74 13                	je     8048636 <dovuln+0x6b>
 8048623:	8b 45 f0             	mov    -0x10(%ebp),%eax
 8048626:	8d 50 01             	lea    0x1(%eax),%edx
 8048629:	89 55 f0             	mov    %edx,-0x10(%ebp)
 804862c:	0f b6 55 bc          	movzbl -0x44(%ebp),%edx
 8048630:	88 54 05 bd          	mov    %dl,-0x43(%ebp,%eax,1)
 8048634:	eb c3                	jmp    80485f9 <dovuln+0x2e>
 8048636:	90                   	nop
 8048637:	83 ec 0c             	sub    $0xc,%esp
 804863a:	8d 45 bc             	lea    -0x44(%ebp),%eax
 804863d:	83 c0 01             	add    $0x1,%eax
 8048640:	50                   	push   %eax
 8048641:	e8 2a fe ff ff       	call   8048470 <puts@plt>
 8048646:	83 c4 10             	add    $0x10,%esp
 8048649:	8b 4d f4             	mov    -0xc(%ebp),%ecx
 804864c:	65 33 0d 14 00 00 00 	xor    %gs:0x14,%ecx
 8048653:	74 05                	je     804865a <dovuln+0x8f>
 8048655:	e8 06 fe ff ff       	call   8048460 <__stack_chk_fail@plt>
 804865a:	c9                   	leave  
 804865b:	c3                   	ret    

0804865c <main>:
 804865c:	8d 4c 24 04          	lea    0x4(%esp),%ecx
 8048660:	83 e4 f0             	and    $0xfffffff0,%esp
 8048663:	ff 71 fc             	pushl  -0x4(%ecx)
 8048666:	55                   	push   %ebp
 8048667:	89 e5                	mov    %esp,%ebp
 8048669:	51                   	push   %ecx
 804866a:	83 ec 04             	sub    $0x4,%esp
 804866d:	a1 80 a0 04 08       	mov    0x804a080,%eax
 8048672:	83 ec 08             	sub    $0x8,%esp
 8048675:	6a 00                	push   $0x0
 8048677:	50                   	push   %eax
 8048678:	e8 c3 fd ff ff       	call   8048440 <setbuf@plt>
 804867d:	83 c4 10             	add    $0x10,%esp
 8048680:	a1 84 a0 04 08       	mov    0x804a084,%eax
 8048685:	83 ec 08             	sub    $0x8,%esp
 8048688:	6a 00                	push   $0x0
 804868a:	50                   	push   %eax
 804868b:	e8 b0 fd ff ff       	call   8048440 <setbuf@plt>
 8048690:	83 c4 10             	add    $0x10,%esp
 8048693:	a1 60 a0 04 08       	mov    0x804a060,%eax
 8048698:	83 ec 08             	sub    $0x8,%esp
 804869b:	6a 00                	push   $0x0
 804869d:	50                   	push   %eax
 804869e:	e8 9d fd ff ff       	call   8048440 <setbuf@plt>
 80486a3:	83 c4 10             	add    $0x10,%esp
 80486a6:	83 ec 04             	sub    $0x4,%esp
 80486a9:	6a 1e                	push   $0x1e
 80486ab:	68 38 a0 04 08       	push   $0x804a038
 80486b0:	6a 01                	push   $0x1
 80486b2:	e8 f9 fd ff ff       	call   80484b0 <write@plt>
 80486b7:	83 c4 10             	add    $0x10,%esp
 80486ba:	e8 0c ff ff ff       	call   80485cb <dovuln>
 80486bf:	b8 00 00 00 00       	mov    $0x0,%eax
 80486c4:	8b 4d fc             	mov    -0x4(%ebp),%ecx
 80486c7:	c9                   	leave  
 80486c8:	8d 61 fc             	lea    -0x4(%ecx),%esp
 80486cb:	c3                   	ret    
 80486cc:	66 90                	xchg   %ax,%ax
 80486ce:	66 90                	xchg   %ax,%ax

080486d0 <__libc_csu_init>:
 80486d0:	55                   	push   %ebp
 80486d1:	57                   	push   %edi
 80486d2:	31 ff                	xor    %edi,%edi
 80486d4:	56                   	push   %esi
 80486d5:	53                   	push   %ebx
 80486d6:	e8 25 fe ff ff       	call   8048500 <__x86.get_pc_thunk.bx>
 80486db:	81 c3 25 19 00 00    	add    $0x1925,%ebx
 80486e1:	83 ec 0c             	sub    $0xc,%esp
 80486e4:	8b 6c 24 20          	mov    0x20(%esp),%ebp
 80486e8:	8d b3 0c ff ff ff    	lea    -0xf4(%ebx),%esi
 80486ee:	e8 15 fd ff ff       	call   8048408 <_init>
 80486f3:	8d 83 08 ff ff ff    	lea    -0xf8(%ebx),%eax
 80486f9:	29 c6                	sub    %eax,%esi
 80486fb:	c1 fe 02             	sar    $0x2,%esi
 80486fe:	85 f6                	test   %esi,%esi
 8048700:	74 23                	je     8048725 <__libc_csu_init+0x55>
 8048702:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
 8048708:	83 ec 04             	sub    $0x4,%esp
 804870b:	ff 74 24 2c          	pushl  0x2c(%esp)
 804870f:	ff 74 24 2c          	pushl  0x2c(%esp)
 8048713:	55                   	push   %ebp
 8048714:	ff 94 bb 08 ff ff ff 	call   *-0xf8(%ebx,%edi,4)
 804871b:	83 c7 01             	add    $0x1,%edi
 804871e:	83 c4 10             	add    $0x10,%esp
 8048721:	39 f7                	cmp    %esi,%edi
 8048723:	75 e3                	jne    8048708 <__libc_csu_init+0x38>
 8048725:	83 c4 0c             	add    $0xc,%esp
 8048728:	5b                   	pop    %ebx
 8048729:	5e                   	pop    %esi
 804872a:	5f                   	pop    %edi
 804872b:	5d                   	pop    %ebp
 804872c:	c3                   	ret    
 804872d:	8d 76 00             	lea    0x0(%esi),%esi

08048730 <__libc_csu_fini>:
 8048730:	f3 c3                	repz ret 

Disassembly of section .fini:

08048734 <_fini>:
 8048734:	53                   	push   %ebx
 8048735:	83 ec 08             	sub    $0x8,%esp
 8048738:	e8 c3 fd ff ff       	call   8048500 <__x86.get_pc_thunk.bx>
 804873d:	81 c3 c3 18 00 00    	add    $0x18c3,%ebx
 8048743:	83 c4 08             	add    $0x8,%esp
 8048746:	5b                   	pop    %ebx
 8048747:	c3                   	ret    

Disassembly of section .rodata:

08048748 <_fp_hw>:
 8048748:	03 00                	add    (%eax),%eax
	...

0804874c <_IO_stdin_used>:
 804874c:	01 00                	add    %eax,(%eax)
 804874e:	02 00                	add    (%eax),%al

Disassembly of section .eh_frame_hdr:

08048750 <.eh_frame_hdr>:
 8048750:	01 1b                	add    %ebx,(%ebx)
 8048752:	03 3b                	add    (%ebx),%edi
 8048754:	30 00                	xor    %al,(%eax)
 8048756:	00 00                	add    %al,(%eax)
 8048758:	05 00 00 00 e0       	add    $0xe0000000,%eax
 804875d:	fc                   	cld    
 804875e:	ff                   	(bad)  
 804875f:	ff 4c 00 00          	decl   0x0(%eax,%eax,1)
 8048763:	00 7b fe             	add    %bh,-0x2(%ebx)
 8048766:	ff                   	(bad)  
 8048767:	ff 70 00             	pushl  0x0(%eax)
 804876a:	00 00                	add    %al,(%eax)
 804876c:	0c ff                	or     $0xff,%al
 804876e:	ff                   	(bad)  
 804876f:	ff 90 00 00 00 80    	call   *-0x80000000(%eax)
 8048775:	ff                   	(bad)  
 8048776:	ff                   	(bad)  
 8048777:	ff                   	(bad)  
 8048778:	bc 00 00 00 e0       	mov    $0xe0000000,%esp
 804877d:	ff                   	(bad)  
 804877e:	ff                   	(bad)  
 804877f:	ff 08                	decl   (%eax)
 8048781:	01 00                	add    %eax,(%eax)
	...

Disassembly of section .eh_frame:

08048784 <__FRAME_END__-0xe8>:
 8048784:	14 00                	adc    $0x0,%al
 8048786:	00 00                	add    %al,(%eax)
 8048788:	00 00                	add    %al,(%eax)
 804878a:	00 00                	add    %al,(%eax)
 804878c:	01 7a 52             	add    %edi,0x52(%edx)
 804878f:	00 01                	add    %al,(%ecx)
 8048791:	7c 08                	jl     804879b <_IO_stdin_used+0x4f>
 8048793:	01 1b                	add    %ebx,(%ebx)
 8048795:	0c 04                	or     $0x4,%al
 8048797:	04 88                	add    $0x88,%al
 8048799:	01 00                	add    %eax,(%eax)
 804879b:	00 20                	add    %ah,(%eax)
 804879d:	00 00                	add    %al,(%eax)
 804879f:	00 1c 00             	add    %bl,(%eax,%eax,1)
 80487a2:	00 00                	add    %al,(%eax)
 80487a4:	8c fc                	mov    %?,%esp
 80487a6:	ff                   	(bad)  
 80487a7:	ff a0 00 00 00 00    	jmp    *0x0(%eax)
 80487ad:	0e                   	push   %cs
 80487ae:	08 46 0e             	or     %al,0xe(%esi)
 80487b1:	0c 4a                	or     $0x4a,%al
 80487b3:	0f 0b                	ud2    
 80487b5:	74 04                	je     80487bb <_IO_stdin_used+0x6f>
 80487b7:	78 00                	js     80487b9 <_IO_stdin_used+0x6d>
 80487b9:	3f                   	aas    
 80487ba:	1a 3b                	sbb    (%ebx),%bh
 80487bc:	2a 32                	sub    (%edx),%dh
 80487be:	24 22                	and    $0x22,%al
 80487c0:	1c 00                	sbb    $0x0,%al
 80487c2:	00 00                	add    %al,(%eax)
 80487c4:	40                   	inc    %eax
 80487c5:	00 00                	add    %al,(%eax)
 80487c7:	00 03                	add    %al,(%ebx)
 80487c9:	fe                   	(bad)  
 80487ca:	ff                   	(bad)  
 80487cb:	ff 91 00 00 00 00    	call   *0x0(%ecx)
 80487d1:	41                   	inc    %ecx
 80487d2:	0e                   	push   %cs
 80487d3:	08 85 02 42 0d 05    	or     %al,0x50d4202(%ebp)
 80487d9:	02 8d c5 0c 04 04    	add    0x4040cc5(%ebp),%cl
 80487df:	00 28                	add    %ch,(%eax)
 80487e1:	00 00                	add    %al,(%eax)
 80487e3:	00 60 00             	add    %ah,0x0(%eax)
 80487e6:	00 00                	add    %al,(%eax)
 80487e8:	74 fe                	je     80487e8 <_IO_stdin_used+0x9c>
 80487ea:	ff                   	(bad)  
 80487eb:	ff 70 00             	pushl  0x0(%eax)
 80487ee:	00 00                	add    %al,(%eax)
 80487f0:	00 44 0c 01          	add    %al,0x1(%esp,%ecx,1)
 80487f4:	00 47 10             	add    %al,0x10(%edi)
 80487f7:	05 02 75 00 43       	add    $0x43007502,%eax
 80487fc:	0f 03 75 7c          	lsl    0x7c(%ebp),%esi
 8048800:	06                   	push   %es
 8048801:	02 5d 0c             	add    0xc(%ebp),%bl
 8048804:	01 00                	add    %eax,(%eax)
 8048806:	41                   	inc    %ecx
 8048807:	c5 43 0c             	lds    0xc(%ebx),%eax
 804880a:	04 04                	add    $0x4,%al
 804880c:	48                   	dec    %eax
 804880d:	00 00                	add    %al,(%eax)
 804880f:	00 8c 00 00 00 bc fe 	add    %cl,-0x1440000(%eax,%eax,1)
 8048816:	ff                   	(bad)  
 8048817:	ff 5d 00             	lcall  *0x0(%ebp)
 804881a:	00 00                	add    %al,(%eax)
 804881c:	00 41 0e             	add    %al,0xe(%ecx)
 804881f:	08 85 02 41 0e 0c    	or     %al,0xc0e4102(%ebp)
 8048825:	87 03                	xchg   %eax,(%ebx)
 8048827:	43                   	inc    %ebx
 8048828:	0e                   	push   %cs
 8048829:	10 86 04 41 0e 14    	adc    %al,0x140e4104(%esi)
 804882f:	83 05 4e 0e 20 67 0e 	addl   $0xe,0x67200e4e
 8048836:	24 44                	and    $0x44,%al
 8048838:	0e                   	push   %cs
 8048839:	28 44 0e 2c          	sub    %al,0x2c(%esi,%ecx,1)
 804883d:	41                   	inc    %ecx
 804883e:	0e                   	push   %cs
 804883f:	30 4d 0e             	xor    %cl,0xe(%ebp)
 8048842:	20 47 0e             	and    %al,0xe(%edi)
 8048845:	14 41                	adc    $0x41,%al
 8048847:	c3                   	ret    
 8048848:	0e                   	push   %cs
 8048849:	10 41 c6             	adc    %al,-0x3a(%ecx)
 804884c:	0e                   	push   %cs
 804884d:	0c 41                	or     $0x41,%al
 804884f:	c7                   	(bad)  
 8048850:	0e                   	push   %cs
 8048851:	08 41 c5             	or     %al,-0x3b(%ecx)
 8048854:	0e                   	push   %cs
 8048855:	04 00                	add    $0x0,%al
 8048857:	00 10                	add    %dl,(%eax)
 8048859:	00 00                	add    %al,(%eax)
 804885b:	00 d8                	add    %bl,%al
 804885d:	00 00                	add    %al,(%eax)
 804885f:	00 d0                	add    %dl,%al
 8048861:	fe                   	(bad)  
 8048862:	ff                   	(bad)  
 8048863:	ff 02                	incl   (%edx)
 8048865:	00 00                	add    %al,(%eax)
 8048867:	00 00                	add    %al,(%eax)
 8048869:	00 00                	add    %al,(%eax)
	...

0804886c <__FRAME_END__>:
 804886c:	00 00                	add    %al,(%eax)
	...

Disassembly of section .init_array:

08049f08 <__frame_dummy_init_array_entry>:
 8049f08:	a0                   	.byte 0xa0
 8049f09:	85 04 08             	test   %eax,(%eax,%ecx,1)

Disassembly of section .fini_array:

08049f0c <__do_global_dtors_aux_fini_array_entry>:
 8049f0c:	80                   	.byte 0x80
 8049f0d:	85 04 08             	test   %eax,(%eax,%ecx,1)

Disassembly of section .jcr:

08049f10 <__JCR_END__>:
 8049f10:	00 00                	add    %al,(%eax)
	...

Disassembly of section .dynamic:

08049f14 <_DYNAMIC>:
 8049f14:	01 00                	add    %eax,(%eax)
 8049f16:	00 00                	add    %al,(%eax)
 8049f18:	01 00                	add    %eax,(%eax)
 8049f1a:	00 00                	add    %al,(%eax)
 8049f1c:	0c 00                	or     $0x0,%al
 8049f1e:	00 00                	add    %al,(%eax)
 8049f20:	08 84 04 08 0d 00 00 	or     %al,0xd08(%esp,%eax,1)
 8049f27:	00 34 87             	add    %dh,(%edi,%eax,4)
 8049f2a:	04 08                	add    $0x8,%al
 8049f2c:	19 00                	sbb    %eax,(%eax)
 8049f2e:	00 00                	add    %al,(%eax)
 8049f30:	08 9f 04 08 1b 00    	or     %bl,0x1b0804(%edi)
 8049f36:	00 00                	add    %al,(%eax)
 8049f38:	04 00                	add    $0x0,%al
 8049f3a:	00 00                	add    %al,(%eax)
 8049f3c:	1a 00                	sbb    (%eax),%al
 8049f3e:	00 00                	add    %al,(%eax)
 8049f40:	0c 9f                	or     $0x9f,%al
 8049f42:	04 08                	add    $0x8,%al
 8049f44:	1c 00                	sbb    $0x0,%al
 8049f46:	00 00                	add    %al,(%eax)
 8049f48:	04 00                	add    $0x0,%al
 8049f4a:	00 00                	add    %al,(%eax)
 8049f4c:	f5                   	cmc    
 8049f4d:	fe                   	(bad)  
 8049f4e:	ff 6f ac             	ljmp   *-0x54(%edi)
 8049f51:	81 04 08 05 00 00 00 	addl   $0x5,(%eax,%ecx,1)
 8049f58:	bc 82 04 08 06       	mov    $0x6080482,%esp
 8049f5d:	00 00                	add    %al,(%eax)
 8049f5f:	00 dc                	add    %bl,%ah
 8049f61:	81 04 08 0a 00 00 00 	addl   $0xa,(%eax,%ecx,1)
 8049f68:	97                   	xchg   %eax,%edi
 8049f69:	00 00                	add    %al,(%eax)
 8049f6b:	00 0b                	add    %cl,(%ebx)
 8049f6d:	00 00                	add    %al,(%eax)
 8049f6f:	00 10                	add    %dl,(%eax)
 8049f71:	00 00                	add    %al,(%eax)
 8049f73:	00 15 00 00 00 00    	add    %dl,0x0
 8049f79:	00 00                	add    %al,(%eax)
 8049f7b:	00 03                	add    %al,(%ebx)
 8049f7d:	00 00                	add    %al,(%eax)
 8049f7f:	00 00                	add    %al,(%eax)
 8049f81:	a0 04 08 02 00       	mov    0x20804,%al
 8049f86:	00 00                	add    %al,(%eax)
 8049f88:	48                   	dec    %eax
 8049f89:	00 00                	add    %al,(%eax)
 8049f8b:	00 14 00             	add    %dl,(%eax,%eax,1)
 8049f8e:	00 00                	add    %al,(%eax)
 8049f90:	11 00                	adc    %eax,(%eax)
 8049f92:	00 00                	add    %al,(%eax)
 8049f94:	17                   	pop    %ss
 8049f95:	00 00                	add    %al,(%eax)
 8049f97:	00 c0                	add    %al,%al
 8049f99:	83 04 08 11          	addl   $0x11,(%eax,%ecx,1)
 8049f9d:	00 00                	add    %al,(%eax)
 8049f9f:	00 a0 83 04 08 12    	add    %ah,0x12080483(%eax)
 8049fa5:	00 00                	add    %al,(%eax)
 8049fa7:	00 20                	add    %ah,(%eax)
 8049fa9:	00 00                	add    %al,(%eax)
 8049fab:	00 13                	add    %dl,(%ebx)
 8049fad:	00 00                	add    %al,(%eax)
 8049faf:	00 08                	add    %cl,(%eax)
 8049fb1:	00 00                	add    %al,(%eax)
 8049fb3:	00 fe                	add    %bh,%dh
 8049fb5:	ff                   	(bad)  
 8049fb6:	ff 6f 70             	ljmp   *0x70(%edi)
 8049fb9:	83 04 08 ff          	addl   $0xffffffff,(%eax,%ecx,1)
 8049fbd:	ff                   	(bad)  
 8049fbe:	ff 6f 01             	ljmp   *0x1(%edi)
 8049fc1:	00 00                	add    %al,(%eax)
 8049fc3:	00 f0                	add    %dh,%al
 8049fc5:	ff                   	(bad)  
 8049fc6:	ff 6f 54             	ljmp   *0x54(%edi)
 8049fc9:	83 04 08 00          	addl   $0x0,(%eax,%ecx,1)
	...

Disassembly of section .got:

08049ffc <.got>:
 8049ffc:	00 00                	add    %al,(%eax)
	...

Disassembly of section .got.plt:

0804a000 <_GLOBAL_OFFSET_TABLE_>:
 804a000:	14 9f                	adc    $0x9f,%al
 804a002:	04 08                	add    $0x8,%al
	...
 804a00c:	46                   	inc    %esi
 804a00d:	84 04 08             	test   %al,(%eax,%ecx,1)
 804a010:	56                   	push   %esi
 804a011:	84 04 08             	test   %al,(%eax,%ecx,1)
 804a014:	66 84 04 08          	data16 test %al,(%eax,%ecx,1)
 804a018:	76 84                	jbe    8049f9e <_DYNAMIC+0x8a>
 804a01a:	04 08                	add    $0x8,%al
 804a01c:	86 84 04 08 96 84 04 	xchg   %al,0x4849608(%esp,%eax,1)
 804a023:	08 a6 84 04 08 b6    	or     %ah,-0x49f7fb7c(%esi)
 804a029:	84 04 08             	test   %al,(%eax,%ecx,1)
 804a02c:	c6                   	.byte 0xc6
 804a02d:	84 04 08             	test   %al,(%eax,%ecx,1)

Disassembly of section .data:

0804a030 <__data_start>:
 804a030:	00 00                	add    %al,(%eax)
	...

0804a034 <__dso_handle>:
 804a034:	00 00                	add    %al,(%eax)
	...

0804a038 <wel>:
 804a038:	50                   	push   %eax
 804a039:	6c                   	insb   (%dx),%es:(%edi)
 804a03a:	7a 20                	jp     804a05c <__TMC_END__+0x4>
 804a03c:	69 6e 70 75 74 20 73 	imul   $0x73207475,0x70(%esi),%ebp
 804a043:	6f                   	outsl  %ds:(%esi),(%dx)
 804a044:	6d                   	insl   (%dx),%es:(%edi)
 804a045:	65 74 68             	gs je  804a0b0 <_end+0x24>
 804a048:	69 6e 67 3a 0a 00 00 	imul   $0xa3a,0x67(%esi),%ebp
 804a04f:	00 00                	add    %al,(%eax)
 804a051:	00 00                	add    %al,(%eax)
 804a053:	00 00                	add    %al,(%eax)
	...

Disassembly of section .bss:

0804a060 <stderr@@GLIBC_2.0>:
	...

0804a080 <stdin@@GLIBC_2.0>:
 804a080:	00 00                	add    %al,(%eax)
	...

0804a084 <stdout@@GLIBC_2.0>:
 804a084:	00 00                	add    %al,(%eax)
	...

0804a088 <completed.7181>:
 804a088:	00 00                	add    %al,(%eax)
	...

Disassembly of section .comment:

00000000 <.comment>:
   0:	47                   	inc    %edi
   1:	43                   	inc    %ebx
   2:	43                   	inc    %ebx
   3:	3a 20                	cmp    (%eax),%ah
   5:	28 55 62             	sub    %dl,0x62(%ebp)
   8:	75 6e                	jne    78 <_init-0x8048390>
   a:	74 75                	je     81 <_init-0x8048387>
   c:	20 35 2e 32 2e 31    	and    %dh,0x312e322e
  12:	2d 32 32 75 62       	sub    $0x62753232,%eax
  17:	75 6e                	jne    87 <_init-0x8048381>
  19:	74 75                	je     90 <_init-0x8048378>
  1b:	32 29                	xor    (%ecx),%ch
  1d:	20 35 2e 32 2e 31    	and    %dh,0x312e322e
  23:	20 32                	and    %dh,(%edx)
  25:	30 31                	xor    %dh,(%ecx)
  27:	35 31 30 31 30       	xor    $0x30313031,%eax
	...
