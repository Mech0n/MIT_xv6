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
  
  
