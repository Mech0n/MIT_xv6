/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>

# Shift Right Logical 
#define SRL(val, shamt)		(((val) >> (shamt)) & ~(-1 << (32 - (shamt))))


###################################################################
# The kernel (this code) is linked at address ~(KERNBASE + 1 Meg), 
# but the bootloader loads it at address ~1 Meg.
#	
# RELOC(x) maps a symbol x from its link address to its actual
# location in physical memory (its load address).	 
###################################################################

#define	RELOC(x) ((x) - KERNBASE)

#define MULTIBOOT_HEADER_MAGIC (0x1BADB002)
#define MULTIBOOT_HEADER_FLAGS (0)
#define CHECKSUM (-(MULTIBOOT_HEADER_MAGIC + MULTIBOOT_HEADER_FLAGS))

###################################################################
# entry point
###################################################################

.text

# The Multiboot header
.align 4
.long MULTIBOOT_HEADER_MAGIC	# .long指示声明一组数，每个数占32位，相当于C语言中的数组 # .bytes .ascii etc.
.long MULTIBOOT_HEADER_FLAGS
.long CHECKSUM

# '_start' specifies the ELF entry point.  Since we haven't set up
# virtual memory when the bootloader enters this code, we need the
# bootloader to jump to the *physical* address of the entry point.
.globl		_start
_start = RELOC(entry)

.globl entry
entry:
	movw	$0x1234,0x472			# warm boot

# ; /*
# ;  * Virtual memory map:                                Permissions
# ;  *                                                    kernel/user
# ;  *
# ;  *    4 Gig -------->  +------------------------------+
# ;  *                     |                              | RW/--
# ;  *                     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# ;  *                     :              .               :
# ;  *                     :              .               :
# ;  *                     :              .               :
# ;  *                     |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~| RW/--
# ;  *                     |                              | RW/--
# ;  *                     |   Remapped Physical Memory   | RW/--
# ;  *                     |                              | RW/--
# ;  *    KERNBASE, ---->  +------------------------------+ 0xf0000000      --+
# ;  *    KSTACKTOP        |     CPU0's Kernel Stack      | RW/--  KSTKSIZE   |
# ;  *                     | - - - - - - - - - - - - - - -|                   |
# ;  *                     |      Invalid Memory (*)      | --/--  KSTKGAP    |
# ;  *                     +------------------------------+                   |
# ;  *                     |     CPU1's Kernel Stack      | RW/--  KSTKSIZE   |
# ;  *                     | - - - - - - - - - - - - - - -|                 PTSIZE
# ;  *                     |      Invalid Memory (*)      | --/--  KSTKGAP    |
# ;  *                     +------------------------------+                   |
# ;  *                     :              .               :                   |
# ;  *                     :              .               :                   |
# ;  *    MMIOLIM ------>  +------------------------------+ 0xefc00000      --+
# ;  *                     |       Memory-mapped I/O      | RW/--  PTSIZE
# ;  * ULIM, MMIOBASE -->  +------------------------------+ 0xef800000
# ;  *                     |  Cur. Page Table (User R-)   | R-/R-  PTSIZE
# ;  *    UVPT      ---->  +------------------------------+ 0xef400000
# ;  *                     |          RO PAGES            | R-/R-  PTSIZE
# ;  *    UPAGES    ---->  +------------------------------+ 0xef000000
# ;  *                     |           RO ENVS            | R-/R-  PTSIZE
# ;  * UTOP,UENVS ------>  +------------------------------+ 0xeec00000
# ;  * UXSTACKTOP -/       |     User Exception Stack     | RW/RW  PGSIZE
# ;  *                     +------------------------------+ 0xeebff000
# ;  *                     |       Empty Memory (*)       | --/--  PGSIZE
# ;  *    USTACKTOP  --->  +------------------------------+ 0xeebfe000
# ;  *                     |      Normal User Stack       | RW/RW  PGSIZE
# ;  *                     +------------------------------+ 0xeebfd000
# ;  *                     |                              |
# ;  *                     |                              |
# ;  *                     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# ;  *                     .                              .
# ;  *                     .                              .
# ;  *                     .                              .
# ;  *                     |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
# ;  *                     |     Program Data & Heap      |
# ;  *    UTEXT -------->  +------------------------------+ 0x00800000
# ;  *    PFTEMP ------->  |       Empty Memory (*)       |        PTSIZE
# ;  *                     |                              |
# ;  *    UTEMP -------->  +------------------------------+ 0x00400000      --+
# ;  *                     |       Empty Memory (*)       |                   |
# ;  *                     | - - - - - - - - - - - - - - -|                   |
# ;  *                     |  User STAB Data (optional)   |                 PTSIZE
# ;  *    USTABDATA ---->  +------------------------------+ 0x00200000        |
# ;  *                     |       Empty Memory (*)       |                   |
# ;  *    0 ------------>  +------------------------------+                 --+
# ;  *
# ;  * (*) Note: The kernel ensures that "Invalid Memory" is *never* mapped.
# ;  *     "Empty Memory" is normally unmapped, but user programs may map pages
# ;  *     there if desired.  JOS user programs map pages temporarily at UTEMP.
# ;  */


	# We haven't set up virtual memory yet, so we're running from
	# the physical address the boot loader loaded the kernel at: 1MB
	# (plus a few bytes).  However, the C code is linked to run at
	# KERNBASE+1MB.  Hence, we set up a trivial page directory that
	# translates virtual addresses [KERNBASE, KERNBASE+4MB) to
	# physical addresses [0, 4MB).  This 4MB region will be
	# sufficient until we set up our real page table in mem_init
	# in lab 2.
	# 我们尚未设置虚拟内存
	# 但是，C代码被链接为在以下位置运行KERNBASE+1MB
	# 我们建立了一个简单的页面目录，将虚拟地址[KERNBASE，KERNBASE + 4MB）转换为物理地址[0，4MB）

	# Load the physical address of entry_pgdir into cr3.  entry_pgdir
	# is defined in entrypgdir.c.
	# 将entry_pgdir的物理地址加载到cr3中（entrypgdir.c）。

	# CR3通过定位当前任务的页面目录和页面表，使处理器能够将线性地址转换为物理地址。 
	# 通常，CR3的高20位将成为页面目录基址寄存器（PDBR），该寄存器存储第一个页面目录项的物理地址。 
	# 如果CR4中的PCIDE位置1，则最低12位用于进程上下文标识符（PCID）
	movl	$(RELOC(entry_pgdir)), %eax # => 0x100015:    mov    $0x112000,%eax
	movl	%eax, %cr3
	# Turn on paging.
	movl	%cr0, %eax
	orl	$(CR0_PE|CR0_PG|CR0_WP), %eax	# 开启 PE PG WP
	movl	%eax, %cr0			# PE	32位保护模式 Protected Mode Enable
						# WP	写保护 Write protect
						# PG	开启分页 $cr3寄存器启用 Paging
	# Now paging is enabled, but we're still running at a low EIP
	# (why is this okay?).  Jump up above KERNBASE before entering
	# C code.
	# 现在进入高位地址
	mov	$relocated, %eax	# => 0x100028:    mov    $0xf010002f,%eax 
	jmp	*%eax
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

	# Should never get here, but in case we do, just spin.
spin:	jmp	spin


.data
###################################################################
# boot stack
###################################################################
	.p2align	PGSHIFT		# force page alignment # log(PGSIZE) PGSIZE == 4K
	.globl		bootstack
bootstack:
	.space		KSTKSIZE	# 8 * 4K(PGSIZE)
	.globl		bootstacktop   
bootstacktop:

