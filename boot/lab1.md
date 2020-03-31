# 笔记

###  Exercise 3

Be able to answer the following questions:

- At what point does the processor start executing 32-bit code? What exactly causes the switch from 16- to 32-bit mode?

  `ljmp    $PROT_MODE_CSEG, $protcseg`

- What is the *last* instruction of the boot loader executed, and what is the *first* instruction of the kernel it just loaded?

  `0x7d6b:      call   *0x10018`

  `0x10000c:    movw   $0x1234,0x472`

  ```shell
  ➜  kern git:(lab1) objdump -f kernel
  
  kernel:     file format elf32-i386
  architecture: i386, flags 0x00000112:
  EXEC_P, HAS_SYMS, D_PAGED
  start address 0x0010000c
  ```

- *Where* is the first instruction of the kernel?

  `0x7d6b:      call   *0x10018`

- How does the boot loader decide how many sectors it must read in order to fetch the entire kernel from disk? Where does it find this information?

  ```c
  //bootmain.c
  ph = (struct Proghdr *) ((uint8_t *) ELFHDR + ELFHDR->e_phoff);
  eph = ph + ELFHDR->e_phnum;
  ```

  ```shell
  ➜  kern git:(lab1) readelf -h kernel
  # 程序头表
  ELF Header:
    Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00
    Class:                             ELF32
    Data:                              2's complement, little endian
    Version:                           1 (current)
    OS/ABI:                            UNIX - System V
    ABI Version:                       0
    Type:                              EXEC (Executable file)
    Machine:                           Intel 80386
    Version:                           0x1
    Entry point address:               0x10000c
    Start of program headers:          52 (bytes into file)
    Start of section headers:          86776 (bytes into file)
    Flags:                             0x0
    Size of this header:               52 (bytes)
    Size of program headers:           32 (bytes)
    Number of program headers:         3
    Size of section headers:           40 (bytes)
    Number of section headers:         15
    Section header string table index: 14
  ```

  `e_phoff`:

  `Start of program headers:          52 (bytes into file)`

  此字段指明程序头表(program header table)开始处在文件中的偏移量。如果没有程序头表，该值应设为 0。

  `e_phnum`:

  `Number of program headers:         3`

  此字段表明程序头表中总共有多少个表项。如果一个目标文件中没有程序头表，该值应设为 0。

  `e_entry`:

  `Entry point address:               0x10000c` ==> 刚好是内核的第一条指令地址。

  此字段指明程序入口的虚拟地址。即当文件被加载到进程空间里后，入口程 序在进程地址空间里的地址。对于可执行程序文件来说，当 ELF 文件完成加载之 后，程序将从这里开始运行；而对于其它文件来说，这个值应该是 0。

  ```c
  //bootmain.c
  for (; ph < eph; ph++)
  		// p_pa is the load address of this segment (as well
  		// as the physical address)
  		readseg(ph->p_pa, ph->p_memsz, ph->p_offset);
  ```

  ```shell
  ➜  kern git:(lab1) readelf -l kernel
  
  Elf file type is EXEC (Executable file)
  Entry point 0x10000c
  There are 3 program headers, starting at offset 52
  
  Program Headers:
    Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
    LOAD           0x001000 0xf0100000 0x00100000 0x0759d 0x0759d R E 0x1000
    LOAD           0x009000 0xf0108000 0x00108000 0x0b6a8 0x0b6a8 RW  0x1000
    GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RWE 0x10
  
   Section to Segment mapping:
    Segment Sections...
     00     .text .rodata .stab .stabstr
     01     .data .got .got.plt .data.rel.local .data.rel.ro.local .bss
     02
  ```

  `p_paddr`

  此数据成员给出本段内容的开始位置在进程空间中的物理地址。对于目前大 多数现代操作系统而言，应用程序中段的物理地址事先是不可知的，所以目前这个 成员多数情况下保留不用，或者被操作系统改作它用。

  `p_memsz` 

  此数据成员给出本段内容在内容镜像中的大小，单位是字节，可以是 0。

  **虽然这里p_memsz表示的时候需要占用的内存的大小。实际上也是磁盘上需要读取的数据量的大小。**

  `p_offset` 

  此数据成员给出本段内容在文件中的位置，即段内容的开始位置相对于文件 开头的偏移量。

### Exercise 4

##### 0x1 

```c
// 这里有个少用的方法。
c[1] = 300;
*(c + 2) = 301;
3[c] = 302; // == c[3]
printf("3: a[0] = %d, a[1] = %d, a[2] = %d, a[3] = %d\n",
       a[0], a[1], a[2], a[3]);
```

```assembly
|           0x00000795      488b45d8       mov rax, qword [local_28h]
|           0x00000799      4883c004       add rax, 4
|           0x0000079d      c7002c010000   mov dword [rax], 0x12c      ; [0x12c:4]=0
|           0x000007a3      488b45d8       mov rax, qword [local_28h]
|           0x000007a7      4883c008       add rax, 8
|           0x000007ab      c7002d010000   mov dword [rax], 0x12d      ; [0x12d:4]=0xb8000000
|           0x000007b1      488b45d8       mov rax, qword [local_28h]
|           0x000007b5      4883c00c       add rax, 0xc
|           0x000007b9      c7002e010000   mov dword [rax], 0x12e      ; [0x12e:4]=0xdb80000
|           0x000007bf      8b75ec         mov esi, dword [local_14h]
|           0x000007c2      8b4de8         mov ecx, dword [local_18h]
|           0x000007c5      8b55e4         mov edx, dword [local_1ch]
|           0x000007c8      8b45e0         mov eax, dword [local_20h]
|           0x000007cb      4189f0         mov r8d, esi
|           0x000007ce      89c6           mov esi, eax
|           0x000007d0      488d3db10100.  lea rdi, qword str.3:_a_0_____d__a_1_____d__a_2_____d__a_3_____d ; 0x988 ; "3: a[0] = %d, a[1] = %d, a[2] = %d, a[3] = %d\n"
```

这里会发现`3[c]`等同`c[3]`，即`3[c] = *(c+3) = *(c+3) = c[3]`。

```shell
pwndbg>
3: a[0] = 200, a[1] = 300, a[2] = 301, a[3] = 302
```

##### 0x2

```c
c = (int *) ((char *) c + 1);
*c = 500;
printf("5: a[0] = %d, a[1] = %d, a[2] = %d, a[3] = %d\n",
```

```assembly
|           0x00000812      488345d801     add qword [local_28h], 1
|           0x00000817      488b45d8       mov rax, qword [local_28h]
|           0x0000081b      c700f4010000   mov dword [rax], 0x1f4      ; [0x1f4:4]=0
|           0x00000821      8b75ec         mov esi, dword [local_14h]
|           0x00000824      8b4de8         mov ecx, dword [local_18h]
|           0x00000827      8b55e4         mov edx, dword [local_1ch]
|           0x0000082a      8b45e0         mov eax, dword [local_20h]
|           0x0000082d      4189f0         mov r8d, esi
|           0x00000830      89c6           mov esi, eax
|           0x00000832      488d3daf0100.  lea rdi, qword str.5:_a_0_____d__a_1_____d__a_2_____d__a_3_____d ; 0x9e8 ; "5: a[0] = %d, a[1] = %d, a[2] = %d, a[3] = %d\n"
```

`0x0000081b`之前：

```shell
pwndbg> x/4wx $rax - 1
0x7fffffffe414: 0x00000190      0x0000012d      0x0000012e      0xf7de59a0
```

`0x0000081b`之后：

```shell
pwndbg> x/4wx $rax - 1
0x7fffffffe414: 0x0001f490      0x00000100      0x0000012e      0xf7de59a0
pwndbg> print 0x1f490
$4 = 128144
```

```shell
4: a[0] = 200, a[1] = 400, a[2] = 301, a[3] = 302
5: a[0] = 200, a[1] = 128144, a[2] = 256, a[3] = 302
```

##### 0x3

```c
b = (int *) a + 1;
c = (int *) ((char *) a + 1);
printf("6: a = %p, b = %p, c = %p\n", a, b, c);
```

```shell
//与第五个输出同理
6: a = 0x7ffe7e869b30, b = 0x7ffe7e869b34, c = 0x7ffe7e869b31
```

###  Exercise 6

```shell
(gdb) x/gx 0x00100000
0x100000:       0x0000000000000000
(gdb) b *0x7d6b
Breakpoint 1 at 0x7d6b
(gdb) c
Continuing.
The target architecture is assumed to be i386
=> 0x7d6b:      call   *0x10018

Breakpoint 1, 0x00007d6b in ?? ()
(gdb) x/gx 0x00100000
0x100000:       0x000000001badb002          #<==
(gdb)
```

```c
//Multiboot
#define MULTIBOOT_HEADER_MAGIC (0x1BADB002)
#define MULTIBOOT_HEADER_FLAGS (0)
#define CHECKSUM (-(MULTIBOOT_HEADER_MAGIC + MULTIBOOT_HEADER_FLAGS))
```

```shell
➜  lab git:(lab1) objdump -d obj/kern/kernel | head -n 17

obj/kern/kernel:     file format elf32-i386


Disassembly of section .text:

f0100000 <_start+0xeffffff4>:
f0100000:	02 b0 ad 1b 00 00    	add    0x1bad(%eax),%dh   #<==
f0100006:	00 00                	add    %al,(%eax)
f0100008:	fe 4f 52             	decb   0x52(%edi)
f010000b:	e4                   	.byte 0xe4
```

将其与`boot/kernel.asm`进行比较，这正是内核代码段的开始。 

因为引导加载程序从`LMA`（加载地址）`00100000`开始加载了内核的`.text`。

##### 前导知识

`VMA`表示`VirtualMemory Address`，即虚拟地址；虚拟内存地址是程序运行时候的所对应的地址，代码要运行的时候，此时对应的地址，就是`VMA`。

`LMA`表示`Load Memory Address`，即加载地址。通俗来讲就是这个段被装载到内存的中`LMA`的地址

正常情况下这两个值是一样的，但是在有些嵌入式系统中，特别是在那些程序放在ROM/Flash的系统中时，`LMA`和`VMA`是不相同的。

```shell
➜  lab git:(lab1) objdump -x obj/kern/kernel

obj/kern/kernel:     file format elf32-i386
obj/kern/kernel
architecture: i386, flags 0x00000112:
EXEC_P, HAS_SYMS, D_PAGED
start address 0x0010000c

[···]

Sections:
Idx Name          Size      VMA       LMA       File off  Algn
  0 .text         000019e9  f0100000  00100000  00001000  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
```

### Exercize 7

到了这里，经历了引导boot，到了内核程序。

首先开启分页，即设置`cr0`和`cr3`寄存器，具体内容详见[wiki](https://en.wikipedia.org/wiki/Control_register)

如果注释了`mov    %eax,%cr0`，`cr3`寄存器也无效。`0x00100000`和`0xf0100000`两个地址的内容就会不同的。

注释掉`kern/entry.S`中的`movl %eax, %cr0`，这样就无法开启分页，虚拟地址无法映射到物理地址。

执行这条语句，二者就变成相同的了。

原因就是在执行这条指令之前，还没有建立分页机制，高地址的内核区域还没有映射到内核的物理地址，只有低地址是有效的；执行完这条指令之后，开启了分页，由于有静态映射表（`kern/entrypgdir`）的存在，两块虚拟地址区域都映射到同一块物理地址区域。

如果注释掉，第一条执行失败的命令是` 0x100031: mov $0xf0110000,%esp`，因为`0xf0110000`是高的虚拟地址，由于没有分页，CPU不知道访问哪一个物理地址。