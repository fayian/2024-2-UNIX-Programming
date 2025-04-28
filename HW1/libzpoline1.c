#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>

extern void asmSyscallHook();
extern void syscallAddr(void);
extern long enterSyscall(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);

void (*asmSyscallHookPtr)() = asmSyscallHook;

void __attribute__((constructor)) setup_trampoline() {
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
    printf("Hello from trampoline!\n");
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

void syscallHook() {
    printf("Hello from trampoline!\n");
}

void ____asm_impl(void)
{
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