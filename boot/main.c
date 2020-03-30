#include <inc/x86.h>
#include <inc/elf.h>

/**********************************************************************
 * This a dirt simple boot loader, whose sole job is to boot
 * an ELF kernel image from the first IDE hard disk.
 *
 * DISK LAYOUT
 *  * This program(boot.S and main.c) is the bootloader.  It should
 *    be stored in the first sector of the disk. 512bytes
 *		引导加载程序 被加载到 第一扇区 
 *  * The 2nd sector onward holds the kernel image.
 *		第二个扇区加载内核镜像(ELF)
 *  * The kernel image must be in ELF format.
 *
 * BOOT UP STEPS
 *  * when the CPU boots it loads the BIOS into memory and executes it
 *
 *  * the BIOS intializes devices, sets of the interrupt routines, and
 *    reads the first sector of the boot device(e.g., hard-drive)
 *    into memory and jumps to it.
 *
 *  * Assuming this boot loader is stored in the first sector of the
 *    hard-drive, this code takes over...
 *
 *  * control starts in boot.S -- which sets up protected mode,
 *    and a stack so C code then run, then calls bootmain()
 *
 *  * bootmain() in this file takes over, reads in the kernel and jumps to it.
 *  	bootmain() 读取内核，然后跳转执行内核
 **********************************************************************/

#define SECTSIZE	512		// 硬盘扇区大小 512 字节
#define ELFHDR		((struct Elf *) 0x10000) // scratch space
/*

+------------------+  <- 0xFFFFFFFF (4GB)
|      32-bit      |
|  memory mapped   |
|     devices      |
|                  |
/\/\/\/\/\/\/\/\/\/\

/\/\/\/\/\/\/\/\/\/\
|                  |
|      Unused      |
|                  |
+------------------+  <- depends on amount of RAM
|                  |
|                  |
| Extended Memory  |
|                  |
|                  |
+------------------+  <- 0x00100000 (1MB) 	<= ELFHDR
|     BIOS ROM     |
+------------------+  <- 0x000F0000 (960KB)
|  16-bit devices, |
|  expansion ROMs  |
+------------------+  <- 0x000C0000 (768KB)
|   VGA Display    |
+------------------+  <- 0x000A0000 (640KB)
|                  |
|    Low Memory    |
|                  |
+------------------+  <- 0x00000000

*/

void readsect(void*, uint32_t);
void readseg(uint32_t, uint32_t, uint32_t);

void
bootmain(void)
{
	struct Proghdr *ph, *eph;

	// read 1st page off disk
	// 从内核所在硬盘位置读取一内存页 4kb 数据
	readseg((uint32_t) ELFHDR, SECTSIZE*8, 0);

	// is this a valid ELF?
	// 判断是否内核镜像是否ELF文件
	if (ELFHDR->e_magic != ELF_MAGIC)
		goto bad;

	// load each program segment (ignores ph flags)
	ph = (struct Proghdr *) ((uint8_t *) ELFHDR + ELFHDR->e_phoff);
	eph = ph + ELFHDR->e_phnum;
	for (; ph < eph; ph++)
		// p_pa is the load address of this segment (as well
		// as the physical address)
		readseg(ph->p_pa, ph->p_memsz, ph->p_offset);

	// call the entry point from the ELF header
	// note: does not return!
	((void (*)(void)) (ELFHDR->e_entry))();

bad:
	outw(0x8A00, 0x8A00);
	outw(0x8A00, 0x8E00);
	while (1)
		/* do nothing */;
}

// Read 'count' bytes at 'offset' from kernel into physical address 'pa'.
// Might copy more than asked
void
readseg(uint32_t pa, uint32_t count, uint32_t offset)
{
	uint32_t end_pa;

	end_pa = pa + count;

	// round down to sector boundary
	// 向下舍入取扇区边界
	pa &= ~(SECTSIZE - 1);

	// translate from bytes to sectors, and kernel starts at sector 1
	// 将字节偏移转换为扇区偏移，内核从扇区1开始
	offset = (offset / SECTSIZE) + 1;

	// If this is too slow, we could read lots of sectors at a time.
	// We'd write more to memory than asked, but it doesn't matter --
	// we load in increasing order.
	// 以递增顺序装载
	while (pa < end_pa) {
		// Since we haven't enabled paging yet and we're using
		// an identity segment mapping (see boot.S), we can
		// use physical addresses directly.  This won't be the
		// case once JOS enables the MMU.
		// 一次读取一个扇区 512 字节的数据
		readsect((uint8_t*) pa, offset);
		pa += SECTSIZE;
		offset++;
	}
}

void
waitdisk(void)
{
	// wait for disk reaady
  // xxxxxxxx & 11000000 != 01000000
  // 0x1F7 状态位
  //     bit 7 = 1  控制器忙
  //     bit 6 = 1  驱动器就绪
  //     bit 5 = 1  设备错误
  //     bit 4        N/A
  //     bit 3 = 1  扇区缓冲区错误
  //     bit 2 = 1  磁盘已被读校验
  //     bit 1        N/A
  //     bit 0 = 1  上一次命令执行失败
	while ((inb(0x1F7) & 0xC0) != 0x40)
		/* do nothing */;
}

// 这里使用的是 LBA 磁盘寻址模式
// LBA是非常单纯的一种寻址模式﹔从0开始编号来定位区块，
// 第一区块LBA=0，第二区块LBA=1，依此类推
void
readsect(void *dst, uint32_t offset)
{
	// wait for disk to be ready
	waitdisk();

	// void outb(int port, uint8_t data);
	outb(0x1F2, 1);				// 要读取的扇区数量 count = 1
	outb(0x1F3, offset);			// 扇区 LBA 地址的 0-7 位		// 扇区号W
	outb(0x1F4, offset >> 8);		// 扇区 LBA 地址的 8-15 位		// 柱面的低8位 
	outb(0x1F5, offset >> 16);		// 扇区 LBA 地址的 16-23 位		// 柱面的高8位
	outb(0x1F6, (offset >> 24) | 0xE0);	// offset | 11100000 保证高三位恒为 1
																				//         第7位     恒为1
                                      	//         第6位     LBA模式的开关，置1为LBA模式
                                      	//         第5位     恒为1
                                      	//         第4位     为0代表主硬盘、为1代表从硬盘
                                      	//         第3~0位   扇区 LBA 地址的 24-27 位
	outb(0x1F7, 0x20);	// cmd 0x20 - read sectors	 // 20h为读，30h为写

	// wait for disk to be ready
	waitdisk();

	// read a sector
	insl(0x1F0, dst, SECTSIZE/4);				//copies 512 bytes (128 words of 32bit each)to
                              				 	//the location pointed by a
	//no error checking
}

