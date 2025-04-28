#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <dis-asm.h>
#include <sched.h>
#include <sys/syscall.h>

extern void asmSyscallHook();
extern void syscallAddr(void);

extern long enterSyscall(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);

void (*asmSyscallHookPtr)() = asmSyscallHook;

void setupTrampoline() {
    const int TRAMPOLINE_SIZE = getpagesize();
    unsigned char* addr = mmap(0x0, TRAMPOLINE_SIZE, 
        PROT_READ | PROT_WRITE, 
        MAP_PRIVATE | MAP_ANON | MAP_FIXED, 
        -1, 0);
    if(addr == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    const int NR_syscalls = 512;
    // Set nop
    for (int i = 0; i < NR_syscalls; i++)
        addr[i] = 0x90;

	/* 
	 * put code for jumping to asm_syscall_hook.
	 *
	 * here we embed the following code.
	 *
	 * sub    $0x80,%rsp    
	 * movabs [asm_syscall_hook],%r11
	 * jmpq   *%r11
	 *
    */

    // sub $0x80, %rsp      /* preserve redzone */
	// 48 81 ec 80 00 00 00    
	addr[NR_syscalls + 0x00] = 0x48;
	addr[NR_syscalls + 0x01] = 0x81;
	addr[NR_syscalls + 0x02] = 0xec;
	addr[NR_syscalls + 0x03] = 0x80;
	addr[NR_syscalls + 0x04] = 0x00;
	addr[NR_syscalls + 0x05] = 0x00;
	addr[NR_syscalls + 0x06] = 0x00;

    // mov [syscallHook], %r11
	// 49 bb [64-bit addr]
	addr[NR_syscalls + 0x07] = 0x49;
	addr[NR_syscalls + 0x08] = 0xbb;
	addr[NR_syscalls + 0x09] = ((uint64_t) asmSyscallHookPtr >> (8 * 0)) & 0xff;
	addr[NR_syscalls + 0x0a] = ((uint64_t) asmSyscallHookPtr >> (8 * 1)) & 0xff;
	addr[NR_syscalls + 0x0b] = ((uint64_t) asmSyscallHookPtr >> (8 * 2)) & 0xff;
	addr[NR_syscalls + 0x0c] = ((uint64_t) asmSyscallHookPtr >> (8 * 3)) & 0xff;
	addr[NR_syscalls + 0x0d] = ((uint64_t) asmSyscallHookPtr >> (8 * 4)) & 0xff;
	addr[NR_syscalls + 0x0e] = ((uint64_t) asmSyscallHookPtr >> (8 * 5)) & 0xff;
	addr[NR_syscalls + 0x0f] = ((uint64_t) asmSyscallHookPtr >> (8 * 6)) & 0xff;
	addr[NR_syscalls + 0x10] = ((uint64_t) asmSyscallHookPtr >> (8 * 7)) & 0xff;

    // jmp *%r11
	// 41 ff e3                    
	addr[NR_syscalls + 0x11] = 0x41;
	addr[NR_syscalls + 0x12] = 0xff;
	addr[NR_syscalls + 0x13] = 0xe3;

	if(mprotect(0, TRAMPOLINE_SIZE, PROT_READ | PROT_EXEC) < 0) {
        perror("mprotect");
        exit(1);
    }
}

static long (*hook_fn)(int64_t a1, int64_t a2, int64_t a3,
		       int64_t a4, int64_t a5, int64_t a6,
		       int64_t a7) = enterSyscall;

long syscallHook(int64_t rdi, int64_t rsi,
		  int64_t rdx, int64_t __rcx __attribute__((unused)),
		  int64_t r8, int64_t r9,
		  int64_t r10_on_stack /* 4th arg for syscall */,
		  int64_t rax_on_stack,
		  int64_t retptr) {
		
	if(rax_on_stack == 1) {
		char* buffer = (char*)rsi;
		for(size_t i = 0; i < (size_t)rdx; i++) {
			switch (buffer[i]) {
			case '0':
				buffer[i] = 'o';
				break;
			case '1':
				buffer[i] = 'i';
				break;
			case '2':
				buffer[i] = 'z';
				break;
			case '3':
				buffer[i] = 'e';
				break;
			case '4':
				buffer[i] = 'a';
				break;
			case '5':
				buffer[i] = 's';
				break;
			case '6':
				buffer[i] = 'g';
				break;
			case '7':
				buffer[i] = 't';
				break;
			
			default:
				break;
			}
		}
	}

	return hook_fn(rax_on_stack, rdi, rsi, rdx, r10_on_stack, r8, r9);
}

void ____asm_impl(void) {
	/*
	 * enter_syscall triggers a kernel-space system call
	 */
	asm volatile (
	".globl enterSyscall \n\t"
	"enterSyscall: \n\t"
	"movq %rdi, %rax \n\t"
	"movq %rsi, %rdi \n\t"
	"movq %rdx, %rsi \n\t"
	"movq %rcx, %rdx \n\t"
	"movq %r8, %r10 \n\t"
	"movq %r9, %r8 \n\t"
	"movq 8(%rsp),%r9 \n\t"
	".globl syscallAddr \n\t"
	"syscallAddr: \n\t"
	"syscall \n\t"
	"ret \n\t"
	);

	/*
	 * asm_syscall_hook is the address where the
	 * trampoline code first lands.
	 *
	 * the procedure below calls the C function
	 * named syscall_hook.
	 *
	 * at the entry point of this,
	 * the register values follow the calling convention
	 * of the system calls.
	 *
	 * this part is a bit complicated.
	 * commit e5afaba has a bit simpler versoin.
	 *
	 */
	asm volatile (
	".globl asmSyscallHook \n\t"
	"asmSyscallHook: \n\t"

	"cmpq $15, %rax \n\t" // rt_sigreturn
	"je do_rt_sigreturn \n\t"
	"pushq %rbp \n\t"
	"movq %rsp, %rbp \n\t"

	/*
	 * NOTE: for xmm register operations such as movaps
	 * stack is expected to be aligned to a 16 byte boundary.
	 */

	"andq $-16, %rsp \n\t" // 16 byte stack alignment

	/* assuming callee preserves r12-r15 and rbx  */

	"pushq %r11 \n\t"
	"pushq %r9 \n\t"
	"pushq %r8 \n\t"
	"pushq %rdi \n\t"
	"pushq %rsi \n\t"
	"pushq %rdx \n\t"
	"pushq %rcx \n\t"

	/* arguments for syscall_hook */

	"pushq 136(%rbp) \n\t"	// return address
	"pushq %rax \n\t"
	"pushq %r10 \n\t"

	/* up to here, stack has to be 16 byte aligned */

	"callq syscallHook@plt \n\t"

	"popq %r10 \n\t"
	"addq $16, %rsp \n\t"	// discard arg7 and arg8

	"popq %rcx \n\t"
	"popq %rdx \n\t"
	"popq %rsi \n\t"
	"popq %rdi \n\t"
	"popq %r8 \n\t"
	"popq %r9 \n\t"
	"popq %r11 \n\t"

	"leaveq \n\t"

	"addq $128, %rsp \n\t"

	"retq \n\t"

	"do_rt_sigreturn:"
	"addq $136, %rsp \n\t"
	"jmp syscallAddr \n\t"
	);
}

struct disassembly_state {
	char *code;
	size_t off;
};

static int do_rewrite(void *data, const char *fmt, ...) {
	struct disassembly_state *s = (struct disassembly_state *) data;
	char buf[4096];
	va_list arg;
	va_start(arg, fmt);
	vsprintf(buf, fmt, arg);
	if (strstr(buf, "(%rsp)") && !strncmp(buf, "-", 1)) {
		int32_t off;
		sscanf(buf, "%x(%%rsp)", &off);
		if (-0x78 > off && off >= -0x80) {
			printf("\x1b[41mthis cannot be handled: %s\x1b[39m\n", buf);
			assert(0);
		} else if (off < -0x80) {
			/* this is skipped */
		} else {
			off &= 0xff;
			{
				uint8_t *ptr = (uint8_t *)(((uintptr_t) s->code) + s->off);
				{
					int i;
					for (i = 0; i < 16; i++) {
						if (ptr[i] == 0x24 && ptr[i + 1] == off) {
							ptr[i + 1] -= 8;
							break;
						}
					}
				}
			}
		}
	} else
	/* replace syscall and sysenter with callq *%rax */
	if (!strncmp(buf, "syscall", 7) || !strncmp(buf, "sysenter", 8)) {
		uint8_t *ptr = (uint8_t *)(((uintptr_t) s->code) + s->off);
		if ((uintptr_t) ptr == (uintptr_t) syscallAddr) {
			/*
			 * skip the syscall replacement for
			 * our system call hook (enter_syscall)
			 * so that it can issue system calls.
			 */
			goto skip;
		}
		ptr[0] = 0xff; // callq
		ptr[1] = 0xd0; // *%rax
    }
skip:
	va_end(arg);
	return 0;
}
static void disassemble_and_rewrite(char *code, size_t code_size, int mem_prot) {
	struct disassembly_state s = { 0 };
	/* add PROT_WRITE to rewrite the code */
	assert(!mprotect(code, code_size, PROT_WRITE | PROT_READ | PROT_EXEC));
	disassemble_info disasm_info = { 0 };
	init_disassemble_info(&disasm_info, &s, do_rewrite);

	disasm_info.arch = bfd_arch_i386;
	disasm_info.mach = bfd_mach_x86_64;
	disasm_info.buffer = (bfd_byte *) code;
	disasm_info.buffer_length = code_size;
	disassemble_init_for_target(&disasm_info);
	disassembler_ftype disasm;
	disasm = disassembler(bfd_arch_i386, false, bfd_mach_x86_64, NULL);
	s.code = code;
	while (s.off < code_size)
		s.off += disasm(s.off, &disasm_info);
	/* restore the memory protection */
	assert(!mprotect(code, code_size, mem_prot));
}

/* entry point for binary rewriting */
static void rewriteCode(void) {
	FILE *fp;
	/* get memory mapping information from procfs */
	assert((fp = fopen("/proc/self/maps", "r")) != NULL);
    char buf[4096];
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        if(strstr(buf, "[stack]\n") != NULL || 
           strstr(buf, "[vsyscall]\n") != NULL || 
           strstr(buf, "[vdso]\n") != NULL) {
            continue; //we do not touch stack and vsyscall memory
        }

        int i = 0;
        char addr[65] = { 0 };
        char *c = strtok(buf, " ");
        while (c != NULL) {
            switch (i) {
            case 0:
                strncpy(addr, c, sizeof(addr) - 1);
                break;
            case 1:
                {
                    int mem_prot = 0;
                    for (size_t j = 0; j < strlen(c); j++) {
                        if (c[j] == 'r')
                            mem_prot |= PROT_READ;
                        if (c[j] == 'w')
                            mem_prot |= PROT_WRITE;
                        if (c[j] == 'x')
                            mem_prot |= PROT_EXEC;
                    }

                    /* rewrite code if the memory is executable */
                    if (mem_prot & PROT_EXEC) {
						size_t j;
                        for (j = 0; j < strlen(addr); j++) {
                            if (addr[j] == '-') {
                                addr[j] = '\0';
                                break;
                            }
                        }
                        int64_t from, to;
                        from = strtol(&addr[0], NULL, 16);
                        if (from == 0) {
                            /*
                                * this is trampoline code.
                                * so skip it.
                                */
                            break;
                        }
                        to = strtol(&addr[j + 1], NULL, 16);
                        disassemble_and_rewrite((char *) from,
                                (size_t) to - from,
                                mem_prot);
                    }
                }
                break;
            }
            
            if (i == 1) break;
            c = strtok(NULL, " ");
            i++;
        }
    }
	fclose(fp);
}

void __attribute__((constructor)) init() {
    setupTrampoline();
	rewriteCode();
}