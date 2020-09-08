// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/trap.h>
#include <kern/pmap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line

int showmappings(int argc, char **argv, struct Trapframe *tf);
int setm(int argc, char **argv, struct Trapframe *tf);
int showvm(int argc, char **argv, struct Trapframe *tf);


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Display information about the eip debug info", mon_backtrace},
	{ "showmappings", "Usage: showmappings 0xbegin_addr 0xend_addr", showmappings},
	{ "setm", "setm", setm},
	{ "showvm", "showvm", showvm}
};

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Your code here.
	struct Eipdebuginfo info;
	uint32_t *ebp = (uint32_t *)read_ebp();
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
			if(!debuginfo_eip(eip,&info)) {
				cprintf("%s:%d: %.*s+%d\n",
				info.eip_file,
				info.eip_line,
				info.eip_fn_namelen,
				info.eip_fn_name,
				eip - info.eip_fn_addr);
			}
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



/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");

	if (tf != NULL)
		print_trapframe(tf);

	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}

uint32_t strtoi(char* buf) {
	uint32_t res = 0;
	buf += 2; //0x...
	while (*buf) { 
		if (*buf >= 'a') *buf = *buf-'a'+'0'+10;//aha
		res = res*16 + *buf - '0';
		++buf;
	}
	return res;
}

void pprint(pte_t *pte) {
	cprintf("PTE_P: %x, PTE_W: %x, PTE_U: %x\n", 
		*pte&PTE_P, *pte&PTE_W, *pte&PTE_U);
}

int
showmappings(int argc, char **argv, struct Trapframe *tf)
{
	if (argc == 1) {
		cprintf("Usage: showmappings 0xbegin_addr 0xend_addr\n");
		return 0;
	}
	uint32_t begin = strtoi(argv[1]), end = strtoi(argv[2]);
	cprintf("begin: %x, end: %x\n", begin, end);
	for (; begin <= end; begin += PGSIZE) {
		pte_t *pte = pgdir_walk(kern_pgdir, (void *) begin, 1);	//create
		if (!pte) panic("boot_map_region panic, out of memory");
		if (*pte & PTE_P) {
			cprintf("page %x with ", begin);
			pprint(pte);
		} else cprintf("page not exist: %x\n", begin);
	}
	return 0;
}

int setm(int argc, char **argv, struct Trapframe *tf) 
{
	if (argc == 1) {
		cprintf("Usage: setm 0xaddr [0|1 :clear or set] [P|W|U]\n");
		return 0;
	}
	uint32_t addr = strtoi(argv[1]);
	pte_t *pte = pgdir_walk(kern_pgdir, (void *)addr, 1);
	cprintf("%x before setm: ", addr);
	pprint(pte);
	uint32_t perm = 0;
	if (argv[3][0] == 'P') perm = PTE_P;
	if (argv[3][0] == 'W') perm = PTE_W;
	if (argv[3][0] == 'U') perm = PTE_U;
	if (argv[2][0] == '0') 	//clear
		*pte = *pte & ~perm;
	else 	//set
		*pte = *pte | perm;
	cprintf("%x after  setm: ", addr);
	pprint(pte);
	return 0;
}

int showvm(int argc, char **argv, struct Trapframe *tf) 
{
	if (argc == 1) {
		cprintf("Usage: showvm 0xaddr 0xn\n");
		return 0;
	}
	void** addr = (void**) strtoi(argv[1]);
	uint32_t n = strtoi(argv[2]);
	int i;
	for (i = 0; i < n; ++i)
		cprintf("VM at %x is %x\n", addr+i, addr[i]);
	return 0;
}