#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>

void syscallHook();

void (*syscallHookPtr)() = syscallHook;

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
	addr[NR_syscalls + 0x09] = ((uint64_t) syscallHookPtr >> (8 * 0)) & 0xff;
	addr[NR_syscalls + 0x0a] = ((uint64_t) syscallHookPtr >> (8 * 1)) & 0xff;
	addr[NR_syscalls + 0x0b] = ((uint64_t) syscallHookPtr >> (8 * 2)) & 0xff;
	addr[NR_syscalls + 0x0c] = ((uint64_t) syscallHookPtr >> (8 * 3)) & 0xff;
	addr[NR_syscalls + 0x0d] = ((uint64_t) syscallHookPtr >> (8 * 4)) & 0xff;
	addr[NR_syscalls + 0x0e] = ((uint64_t) syscallHookPtr >> (8 * 5)) & 0xff;
	addr[NR_syscalls + 0x0f] = ((uint64_t) syscallHookPtr >> (8 * 6)) & 0xff;
	addr[NR_syscalls + 0x10] = ((uint64_t) syscallHookPtr >> (8 * 7)) & 0xff;

    // jmp *%r11
	// 41 ff e3                    
	addr[NR_syscalls + 0x11] = 0x41;
	addr[NR_syscalls + 0x12] = 0xff;
	addr[NR_syscalls + 0x13] = 0xe3;

	/*
	 * mprotect(PROT_EXEC without PROT_READ), executed
	 * on CPUs supporting Memory Protection Keys for Userspace (PKU),
	 * configures this memory region as eXecute-Only-Memory (XOM).
	 * this enables to cause a segmentation fault for a NULL pointer access.
	 */
	if(mprotect(0, TRAMPOLINE_SIZE, PROT_EXEC) < 0) {
        perror("mprotect");
        exit(1);
    }
}