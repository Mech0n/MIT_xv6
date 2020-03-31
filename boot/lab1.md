# Lab1-Excercise

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

### Exercise 8

仿照`%u`来改写：

```c
// unsigned decimal
case 'u':
  num = getuint(&ap, lflag);
  base = 10;
  goto number;

// (unsigned) octal
case 'o':
  // Replace this with your code.
  // putch('X', putdat);
  // putch('X', putdat);
  // putch('X', putdat);
  num = getuint(&ap, lflag);
  base = 8;
  goto number;
  // break;
```

效果

```shell
#before
➜  lab git:(lab1) make qemu-nox
***
*** Use Ctrl-a x to exit qemu
***
qemu-system-i386 -nographic -drive file=obj/kern/kernel.img,index=0,media=disk,format=raw -serial mon:stdio -gdb tcp::25000 -D qemu.log
6828 decimal is XXX octal!		#<===
entering test_backtrace 5
entering test_backtrace 4
[···]

#after
➜  lab git:(lab1) ✗ make qemu-nox
***
*** Use Ctrl-a x to exit qemu
***
qemu-system-i386 -nographic -drive file=obj/kern/kernel.img,index=0,media=disk,format=raw -serial mon:stdio -gdb tcp::25000 -D qemu.log
6828 decimal is 15254 octal!		#<===
entering test_backtrace 5
entering test_backtrace 4
[···]
```

1. Explain the interface between `printf.c` and `console.c`. Specifically, what function does `console.c` export? How is this function used by `printf.c`?

   `putch()/printf.c` ->`cputchar()/console.c`->`cons_putc()/console.c`->`[···]`

2. Explain the following from `console.c`:

   ```c
   //console.h
   #define CRT_SIZE	(CRT_ROWS * CRT_COLS) // 屏幕大小
   #define CRT_ROWS	25
   #define CRT_COLS	80
   
   //console.c
   //如果输出位置crt_pos已经超出屏幕范围
   if (crt_pos >= CRT_SIZE) {
                 int i;
     						//crt_buf存放屏幕指定位置的字符
   					    // 通过这一行代码完成了整个屏幕向上移动一行的操作。
                 memmove(crt_buf, crt_buf + CRT_COLS, (CRT_SIZE - CRT_COLS) * sizeof(uint16_t));
     						//清空最后一行
                 for (i = CRT_SIZE - CRT_COLS; i < CRT_SIZE; i++)
                         crt_buf[i] = 0x0700 | ' ';
                 crt_pos -= CRT_COLS;
         }
   ```

3. For the following questions you might wish to consult the notes for Lecture 2. These notes cover GCC's calling convention on the x86.

   Trace the execution of the following code step-by-step:

   ```
   int x = 1, y = 3, z = 4;
   cprintf("x %d, y %x, z %d\n", x, y, z);
   ```

```c
//va_arg
typedef __builtin_va_list va_list;
#define va_start(ap, last) __builtin_va_start(ap, last)
#define va_arg(ap, type) __builtin_va_arg(ap, type)
#define va_end(ap) __builtin_va_end(ap)
```

```c
// 指针定义为char *可以指向任意一个内存地址。
typedef char *va_list;
// 类型大小，注意这里是与CPU位数对齐 ＝ sizeof(long)的作用。
#define    __va_size(type) \
    (((sizeof(type) + sizeof(long) - 1) / sizeof(long)) * sizeof(long))
// 这里个宏并不是取得参数的起始地址。而是说参数将从什么地址开始放。
#define    va_start(ap, last) \
    ((ap) = (va_list)&(last) + __va_size(last))
// va_arg就是用来取参数的起始地址的。然后返回type类型。
// 从整个表达式的意义来说没有什么好用的。
// 其实等价于(*(type*)ap)
// 但是实际上使ap指针移动一个参数大小。
#define    va_arg(ap, type) \
    (*(type *)((ap) += __va_size(type), (ap) - __va_size(type)))
// 空指令，没有什么用
#define    va_end(ap)    ((void)0)
```



- In the call to `cprintf()`, to what does `fmt` point? To what does `ap` point?

`fmt = "x %d, y %x, z %d\n"`，`ap = （x, y, z)`

`ap`第一次是`x`，然后是`y`，然后是`z`。直到`fmt`打印完毕。涉及到以上三个头文件的调用栈。

- List (in order of execution) each call to `cons_putc`, `va_arg`, and `vcprintf`. For `cons_putc`, list its argument as well. For `va_arg`, list what `ap` points to before and after the call. For `vcprintf` list the values of its two arguments.

`[···]`

- Run the following code.

```
    unsigned int i = 0x00646c72;
    cprintf("H%x Wo%s", 57616, &i);
```

```shell
➜  ~ ./a.out
He110 World
```

`%x`输出16进制数，而且`57616 = 0xe110`，

`%s`输出`i`内的字符，按小端读取输出，即`0x72, 0x6c, 0x64 ==> r, l, d`

大端读取`57616`不用修改，但是`i`需要按字节反序。

- In the following code, what is going to be printed after `'y='`? (note: the answer is not a specific value.) Why does this happen?

  `cprintf("x=%d y=%d", 3);`

  `y`会打印栈上“第三个参数“位置的值，很有可能是个地址什么的。

- Let's say that GCC changed its calling convention so that it pushed arguments on the stack in declaration order, so that the last argument is pushed last. How would you have to change `cprintf` or its interface so that it would still be possible to pass it a variable number of arguments?

  引用这个解释吧：[reference](https://jiyou.github.io/blog/2018/04/15/mit.6.828/jos-lab1/)

  之前认为GCC调用规则更改我们是不用多操作的。但是忘记了这里需要我们自己实现`cprintf()`，那就修改`va_arg`即相关宏定义呗。

  ```c
  / 指针定义为char *可以指向任意一个内存地址。
  typedef char *va_list;
  // 类型大小，注意这里是与CPU位数对齐 ＝ sizeof(long)的作用。
  #define    __va_size(type) \
      (((sizeof(type) + sizeof(long) - 1) / sizeof(long)) * sizeof(long))
  // 这里个宏并不是取得参数的起始地址。而是说参数将从什么地址开始放。
  #define    va_start(ap, last) \
      ((ap) = (va_list)&(last) + __va_size(last))
  // va_arg就是用来取参数的起始地址的。然后返回type类型。
  // 从整个表达式的意义来说没有什么好用的。
  // 其实等价于(*(type*)ap)
  // 但是实际上使ap指针移动一个参数大小。
  #define    va_arg(ap, type) \
      (*(type *)((ap) += __va_size(type), (ap) - __va_size(type)))
  // 空指令，没有什么用
  #define    va_end(ap)    ((void)0)
  ```


### Exercise 9

Determine where the kernel initializes its stack, and exactly where in memory its stack is located. How does the kernel reserve space for its stack? And at which "end" of this reserved area is the stack pointer initialized to point to?

##### First

```assembly
# boot.S
调用到内核时，设置了寄存器和栈指针。
protcseg:
  # Set up the protected-mode data segment registers
  movw    $PROT_MODE_DSEG, %ax    # Our data segment selector
  movw    %ax, %ds                # -> DS: Data Segment
  movw    %ax, %es                # -> ES: Extra Segment
  movw    %ax, %fs                # -> FS
  movw    %ax, %gs                # -> GS
  movw    %ax, %ss                # -> SS: Stack Segment
  
  # Set up the stack pointer and call into C.
  movl    $start, %esp
  call bootmain
```

##### Second

```assembly
# entry.S
relocated:

	# Clear the frame pointer register (EBP)
	# so that once we get into debugging C code,
	# stack backtraces will be terminated properly.
	# 清空帧指针(EBP)，以便运行c程序（待考证）
	movl	$0x0,%ebp			# nuke frame pointer

	# Set the stack pointer
	# 设置栈指针 
	movl	$(bootstacktop),%esp	# => 0xf0100034:    mov    $0xf0110000,%esp

	# now to C code
	call	i386_init	# => 0xf0100039:   call   0xf01000a6 <i386_init>
```

```assembly
.data
###################################################################
# boot stack
###################################################################
	.p2align	PGSHIFT		# force page alignment # log(PGSIZE) PGSIZE == 4K
	.globl		bootstack
bootstack:
	.space		KSTKSIZE	 # 申请KSTKSIZE字节的空间作为栈 # 8 * 4K(PGSIZE)
	.globl		bootstacktop   # 定义变量 bootstacktop
bootstacktop:
```

### Exercise 10

To become familiar with the C calling conventions on the x86, find the address of the `test_backtrace` function in `obj/kern/kernel.asm`, set a breakpoint there, and examine what happens each time it gets called after the kernel starts. How many 32-bit words does each recursive nesting level of `test_backtrace` push on the stack, and what are those words?

Note that, for this exercise to work properly, you should be using the patched version of QEMU available on the [tools](https://pdos.csail.mit.edu/6.828/2017/tools.html) page or on Athena. Otherwise, you'll have to manually translate all breakpoint and memory addresses to linear addresses.

仔细看`test_backtrace`函数，观察调用函数调整栈空间，除去内部函数压栈弹栈。占用`0x14`字节，这些字分别是`0xc`预留、`eax`、`eip`。

```assembly
		test_backtrace(x-1);
f0100095:	83 ec 0c             	sub    $0xc,%esp
f0100098:	8d 46 ff             	lea    -0x1(%esi),%eax
f010009b:	50                   	push   %eax
f010009c:	e8 9f ff ff ff       	call   f0100040 <test_backtrace>
f01000a1:	83 c4 10             	add    $0x10,%esp
f01000a4:	eb d5                	jmp    f010007b <test_backtrace+0x3b>
```

内部，占用`0x8`字节：`ebp`、`esi`、`ebx`。

```assembly
// Test the stack backtrace function (lab 1 only)
void
test_backtrace(int x)
{
f0100040:	55                   	push   %ebp
f0100041:	89 e5                	mov    %esp,%ebp
f0100043:	56                   	push   %esi
f0100044:	53                   	push   %ebx
f0100045:	e8 72 01 00 00       	call   f01001bc <__x86.get_pc_thunk.bx>
f010004a:	81 c3 be 12 01 00    	add    $0x112be,%ebx
f0100050:	8b 75 08             	mov    0x8(%ebp),%esi
	cprintf("entering test_backtrace %d\n", x);
f0100053:	83 ec 08             	sub    $0x8,%esp
f0100056:	56                   	push   %esi
f0100057:	8d 83 f8 06 ff ff    	lea    -0xf908(%ebx),%eax
f010005d:	50                   	push   %eax
f010005e:	e8 e6 09 00 00       	call   f0100a49 <cprintf>
	if (x > 0)
f0100063:	83 c4 10             	add    $0x10,%esp
f0100066:	85 f6                	test   %esi,%esi
f0100068:	7f 2b                	jg     f0100095 <test_backtrace+0x55>
		test_backtrace(x-1);
	else
		mon_backtrace(0, 0, 0);
f010006a:	83 ec 04             	sub    $0x4,%esp
f010006d:	6a 00                	push   $0x0
f010006f:	6a 00                	push   $0x0
f0100071:	6a 00                	push   $0x0
f0100073:	e8 0b 08 00 00       	call   f0100883 <mon_backtrace>
f0100078:	83 c4 10             	add    $0x10,%esp
	cprintf("leaving test_backtrace %d\n", x);
f010007b:	83 ec 08             	sub    $0x8,%esp
f010007e:	56                   	push   %esi
f010007f:	8d 83 14 07 ff ff    	lea    -0xf8ec(%ebx),%eax
f0100085:	50                   	push   %eax
f0100086:	e8 be 09 00 00       	call   f0100a49 <cprintf>
}
f010008b:	83 c4 10             	add    $0x10,%esp
f010008e:	8d 65 f8             	lea    -0x8(%ebp),%esp
f0100091:	5b                   	pop    %ebx
f0100092:	5e                   	pop    %esi
f0100093:	5d                   	pop    %ebp
f0100094:	c3                   	ret    
```

```shell
entering test_backtrace 5
(gdb) x/8wx $esp - 0x20
0xf010ffb0:     0x00000000      0xf0111308      0xf010ffd8   0xf0100a5b
0xf010ffc0:     0xf0101a57      0xf010ffe4      0x00000000   0xf0111308
```

```shell
entering test_backtrace 4
(gdb) x/8wx $esp - 0x20
0xf010ff90:     0xf01009f0      0xf0111308      0xf010ffb8      0xf0100a5b
0xf010ffa0:     0xf0101a20      0xf010ffc4      0x00000000      0x00000000
```

```shell
entering test_backtrace 3
(gdb) x/8wx $esp - 0x20
0xf010ff70:     0xf01009f0      0xf0111308      0xf010ff98      0xf0100a5b
0xf010ff80:     0xf0101a20      0xf010ffa4      0xf010ffb8      0x00000000
```

```shell
entering test_backtrace 2
(gdb) x/8wx $esp - 0x20
0xf010ff50:     0xf01009f0      0xf0111308      0xf010ff78      0xf0100a5b
0xf010ff60:     0xf0101a20      0xf010ff84      0xf010ff98      0x00000000
```

```shell
entering test_backtrace 1
(gdb) x/8wx $esp - 0x20
0xf010ff30:     0xf01009f0      0xf0111308      0xf010ff58      0xf0100a5b
0xf010ff40:     0xf0101a20      0xf010ff64      0xf010ff78      0x00000000
```

```shell
entering test_backtrace 0
(gdb) x/8wx $esp - 0x20
0xf010ff10:     0xf01009f0      0xf0111308      0xf010ff38      0xf0100a5b
0xf010ff20:     0xf0101a20      0xf010ff44      0xf010ff58      0x00000000
```

### Exercise 11

Implement the backtrace function as specified above. Use the same format as in the example, since otherwise the grading script will be confused. When you think you have it working right, run make grade to see if its output conforms to what our grading script expects, and fix it if it doesn't. *After* you have handed in your Lab 1 code, you are welcome to change the output format of the backtrace function any way you like.

让我们打印信息（如下格式）：

```c
int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Your code here.
	uint32_t *ebp = (uint32_t *)read_ebp();	//地址形式。
	uint32_t eip = ebp[1];
	uint32_t arg1= ebp[2];
	uint32_t arg2 = ebp[3];
	uint32_t arg3 = ebp[4];
	uint32_t arg4 = ebp[5];
	uint32_t arg5 = ebp[6];
	cprintf("Stack backtrace:\n");
	while(ebp)
	{
			cprintf("ebp %08x eip %08x args %08x %08x %08x %08x %08x\n",ebp,eip,arg1,arg2,arg3,arg4,arg5);
			ebp = (uint32_t *)ebp[0];
			eip = ebp[1];
			arg1 = ebp[2];
			arg2 = ebp[3];
			arg3 = ebp[4];
			arg4 = ebp[5];
			arg5 = ebp[6];
	}
	return 0;
}
```

### Exercise 12

