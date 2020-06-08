# lab2 - Exercise

#### 【2020-04-01】 

建立分支，准备环境，

#### 【2020-04-07】

学习`pmap.c`、`memlayout.h`、`pmap.h`，~~根据自己的理解做了详细注释~~

#### 【2020-04-10】

 [Intel 80386 Reference Manual](https://pdos.csail.mit.edu/6.828/2017/readings/i386/toc.htm) : 5-2 、6-4

### 练习前梳理

引用一张图，图像化展示内存布局(复习一下lab1)：

![](./img/mem_after_boot.png)

对比lab1给的布局(做了一下补充)：

```shell

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
+------------------+  <- 0x00100000 (1MB) // kern code
|     BIOS ROM     |
+------------------+  <- 0x000F0000 (960KB)
|  16-bit devices, |
|  expansion ROMs  |
+------------------+  <- 0x000C0000 (768KB)
|   VGA Display    |
+------------------+  <- 0x000A0000 (640KB)
|                  |
|    Low Memory    |  <- 0x10000 (ELF header)
|                  |
+------------------+  <- 0x00000000

```

在进行实验之前，我们通过`boot.S`的`call bootmain`转移到了`bootmain(boot/main.c)`的`((void (*)(void)) (ELFHDR->e_entry))();`然后进入内核`entry.S`的`call i386_init`来到了目前的练习。

在`entry.S`之前，首先，内核使分页能够使用虚拟内存并解决位置依赖性。 用`kern/entrypgdir.c`中的实现映射，静态初始化的页面目录和页面表。 仅映射物理内存的前4M。这样，`entry.S`可以在高地址操作。即：

```c
// Map VA's [0, 4MB) to PA's [0, 4MB)
// Map VA's [KERNBASE, KERNBASE+4MB) to PA's [0, 4MB)
```

- virtual addresses `0xf0000000` through `0xf0400000` to physical addresses` 0x00000000` through `0x00400000`
- virtual addresses `0x00000000` through `0x00400000` to physical addresses `0x00000000` through `0x00400000`

`Init.c`的预操作：

```c
// kern/init.c
void
i386_init(void)
{
	extern char edata[], end[];

	// Before doing anything else, complete the ELF loading process.
	// Clear the uninitialized global data (BSS) section of our program.
	// This ensures that all static/global variables start out zero.
	memset(edata, 0, end - edata);

	// Initialize the console.
	// Can't call cprintf until after we do this!
	cons_init();

	cprintf("6828 decimal is %o octal!\n", 6828);

	// Lab 2 memory management initialization functions
	mem_init();

	// Drop into the kernel monitor.
	while (1)
		monitor(NULL);
}
```

这里初始化了`bss`段，众所周知不初始化的全局变量在`bss`里声明，并置为`0`。

**到目前为止，我们仅使用`entry_pgdir`和`entry_pgtable`手动映射了`KERNBASE`开始的4M内存。** 

### Ecercise 1

调用`mem_init();`来到需要我们完善的地方`pmap.c`

这里只设置内核部分，即`addresses >= UTOP`。

首先确定有多少可用内存，更新`npages`，`npages_basemem`。然后使用一个页面来作为页面目录`page directory`，来到`boot_alloc()`。

```c
// nextfree是空闲内存下一个字节的虚拟地址，被初始化到.bss的end。
[...]
if(n > 0) {
  result = nextfree;
  nextfree = ROUNDUP((char*)(nextfree + n), PGSIZE);
  if((uint32_t)nextfree - KERNBASE > (npages * PGSIZE))	//检测是否超出分配范围。
    panic("Out Of Memory!\n");
  return result;
}
else if(n == 0)
  return nextfree;
return NULL;
[···]
```

然后（先跳过在虚拟地址UVPT处形成虚拟页表部分），分配`npages`个`struct PageInfo`元素组成数组，并将其存储在`pages`中。内核使用此数组来跟踪物理页面。

```c
struct PageInfo {
	// Next page on the free list.
	struct PageInfo *pp_link;

	// pp_ref is the count of pointers (usually in page table entries)
	// to this page, for pages allocated using page_alloc.
	// Pages allocated at boot time using pmap.c's
	// boot_alloc do not have valid reference count fields.

	uint16_t pp_ref;
};	//memlayout.h
pages = (struct PageInfo *) boot_alloc(npages * sizeof(struct PageInfo));
memset(pages, 0, npages * sizeof(struct PageInfo));
```

随后需要进入并完成`page_init()`函数：

根据要求把这几项提示完成即可：

```c
	size_t i;
	page_free_list = NULL;

	// 已分配使用部分(extmem)
	int num_alloc = ((uint32_t)boot_alloc(0) - KERNBASE) / PGSIZE;
	//IO部分 384K
	int num_IOhole = (EXTPHYSMEM - IOPHYSMEM) / PGSIZE;

	// page 0
	pages[0].pp_ref = 1;
	// last base memory 
	for(i = 1; i < npages_basemem; i++)
	{
		pages[i].pp_ref = 0;
		pages[i].pp_link = page_free_list;
		page_free_list = &pages[i];
	}
	// alloc / IO hole 
	for(i = npages_basemem; i < npages_basemem + num_IOhole + num_alloc; i++)
  	pages[i].pp_ref = 1;
	// last
	for(; i < npages; i++)
	{
		pages[i].pp_ref = 0;
		pages[i].pp_link = page_free_list;
		page_free_list = &pages[i];
	}
```

此时，`page_free_list`链表指向地址最高的`free page`

最后进入`check_page_free_list()`函数来测试。~~参数`1`指定了包含`entry_pgdir`的`Page Dictionary`。~~

然后是`page_alloc()`、`page_free()`

```c
struct PageInfo *
page_alloc(int alloc_flags)
{
	// Fill this function in
	if(!page_free_list)
		return NULL;
	struct PageInfo *pp = page_free_list;
	if(alloc_flags & ALLOC_ZERO) {
		memset(page2kva(pp), 0, PGSIZE);
	}
	page_free_list = pp->pp_link;
	pp->pp_link = NULL;
	return pp;	
}

void
page_free(struct PageInfo *pp)
{
	// Fill this function in
	// Hint: You may want to panic if pp->pp_ref is nonzero or
	// pp->pp_link is not NULL.
	if(pp->pp_ref != 0)
		panic("pp->pp_ref is nonzero\n");
	if(pp->pp_link)
		panic("pp->pp_link is not NULL\n");

	pp->pp_link = page_free_list;
	page_free_list = pp;
}
```

### Exercise 2

详见[sources](./sources/)

在x86术语中，**虚拟地址**由 段选择器 `segment selector` 和段内的偏移量 `offset` 组成。 **线性地址**是您在分段翻译 `segment translation` 之后, 页面翻译 ` page translation` 之前获得的。 **物理地址**是在段和页面翻译之后最终得到的，最终在硬件总线上抵达RAM的内容。

```shell

           Selector  +--------------+         +-----------+
          ---------->|              |         |           |
                     | Segmentation |         |  Paging   |
Software             |              |-------->|           |---------->  RAM
            Offset   |  Mechanism   |         | Mechanism |
          ---------->|              |         |           |
                     +--------------+         +-----------+
            Virtual                   Linear                Physical

```

虚拟地址 -> 线性地址 -> 物理地址:

![虚拟地址 -> 线性地址](./img/fig5-12.gif)

C指针是虚拟地址的`offset`部分。 **在`boot / boot.S`中，我们设置了全局描述符表（`GDT`），该表通过将所有段基址设置为`0`并将限制设置为`0xffffffff`，有效地禁用了段转换。 因此，`selector`无效，线性地址始终等于虚拟地址的偏移量。** 在lab3中，我们将需要与分段进行更多交互才能设置特权级别，但是对于内存转换，我们可以在整个JOS实验中忽略分段，而只专注于页面转换。

回想一下，在lab1 Part 3中，我们设置了一个简单的`page table`，以便内核可以实际上以其链接地址`0xf0100000`运行，即使该内核实际上已加载到ROM BIOS上方的物理内存中，即`0x00100000`。 该`page table`仅映射了`4MB`的内存。 在本lab中，您将在虚拟地址空间布局中为JOS进行设置，**我们将对其进行扩展以映射从虚拟地址`0xf0000000`开始的前256MB物理内存，并映射虚拟地址空间的许多其他区域。**

从在CPU上执行的代码开始，一旦进入保护模式（我们在`boot / boot.S`中输入了第一件事），就无法直接使用线性或物理地址。 **所有内存引用都被解释为虚拟地址，并由`MMU`转换，这意味着C中的所有指针都是虚拟地址。**

JOS内核通常需要将地址作为不透明值或整数进行操作，而无需在例如物理内存分配器中对其进行反引用。 有时这些是虚拟地址，有时是物理地址。

 为了帮助记录代码，JOS源代码区分了两种情况：`uintptr_t`类型代表不透明的虚拟地址，而`physaddr_t`类型代表物理地址。 这两种类型实际上只是32位整数（`uint32_t`）的同义词，因此编译器不会阻止您将一种类型分配给另一种类型！ 由于它们是整数类型（不是指针），因此，如果您尝试取消引用它们，则编译器将complain。

JOS内核可以通过首先将`uintptr_t`强制转换为指针类型来取消引用。 相反，内核无法明智地取消对物理地址的引用，因为`MMU`会转换所有内存引用。 如果将`physaddr_t`强制转换为指针并取消引用，则可以加载并存储到结果地址（硬件会将其解释为虚拟地址），但可能无法获得所需的内存位置。

| C type       | Address type |
| ------------ | ------------ |
| `T*`         | Virtual      |
| `uintptr_t`  | Virtual      |
| `physaddr_t` | Physical     |

为了将物理地址转换为内核可以实际读写的虚拟地址，内核必须在物理地址上添加`0xf0000000`才能在重映射区域中找到其对应的虚拟地址。 应该使用`KADDR(pa)`进行添加。

**引用计数**

在之后的lab中，通常会同时在多个虚拟地址（或多个环境的地址空间）中映射相同的物理页面。 您将在与物理页面对应的`struct PageInfo`的`pp_ref`字段中保留对每个物理页面的引用数量的计数。 当物理页面的此计数变为`0`时，可以释放该页面，因为它不再使用。 一般来说，这个计数应该等于物理页面在所有页面表中出现在`UTOP`下面的次数（`UTOP`上面的映射主要是在内核启动时设置的，不应该被释放，因此不需要引用他们）。 我们还将使用它来跟踪我们保留到页面目录页面的指针数量，进而跟踪页面目录对页面表页面的引用数量。

使用`page_alloc`时要注意，它返回的页面的引用计数始终为`0`，因此只要您对返回的页面执行某些操作（例如将其插入页面表），`pp_ref`就应该递增。 有时这是由其他函数处理的（例如，`page_insert`），有时调用`page_alloc`的函数必须直接执行。

### Exercise 4

现在，您将编写一组例程来管理页表：插入和删除线性到物理的映射，以及在需要时创建页表页面。

 In the file `kern/pmap.c`, you must implement code for the following functions.

在文件`kern/pmap.c`中，您必须实现以下功能的代码

```c
        pgdir_walk()
        boot_map_region()
        page_lookup()
        page_remove()
        page_insert()
```

`check_page()`, called from `mem_init()`, tests your page table management routines. You should make sure it reports success before proceeding.