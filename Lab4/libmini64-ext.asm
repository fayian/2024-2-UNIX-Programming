%macro gensys 2
	global sys_%2:function
sys_%2:
	push	r10
	mov	r10, rcx
	mov	rax, %1
	syscall
	pop	r10
	ret
%endmacro

extern write_hex

section .data
    seed dq 0

section .text

gensys 13, rt_sigaction
gensys 14, rt_sigprocmask
gensys 127, rt_sigpending
gensys 130, rt_sigsuspend

global time:function
time:
    mov rax, 201
	syscall
    mov rdi, rax
    ret

global srand:function
srand:
    sub rdi, 1
    mov [rel seed], rdi
    ret

global grand:function
grand:
    mov rax, [rel seed]
    ret

global rand:function
rand:
    mov rax, [rel seed]
    mov rbx, 6364136223846793005
    mul rbx
    add rax, 1
    mov [rel seed], rax
    shr rax, 33
    ret

global sigemptyset:function
sigemptyset:
    mov QWORD[rdi], 0
    ret

global sigfillset:function
sigfillset:
    mov rdx, 0xffffffffffffffff
    mov [rdi], rdx
    ret

global sigaddset:function
sigaddset:
    mov rdx, 1
    mov rcx, rsi
    sub rcx, 1
    shl edx, cl
    or [rdi], rdx
    ret

global sigdelset:function
sigdelset:
    mov rdx, 1
    mov rcx, rsi
    sub rcx, 1
    shl edx, cl
    not rdx
    and [rdi], rdx
    ret

global sigismember:function
sigismember:
    mov edx, 1
    mov rcx, rsi
    sub rcx, 1
    shl edx, cl
    mov rbx, [rdi]
    and ebx, edx
    cmp ebx, 0
    jne sigismember_isset
    mov rax, 0
    ret
sigismember_isset:
    mov rax, 1
    ret

global sigprocmask:function
sigprocmask:
    mov rcx, 8
    call sys_rt_sigprocmask
    ret

global setjmp:function
setjmp:
    mov [rdi], rbx
    mov [rdi + 8], r12
    mov [rdi + 16], r13
    mov [rdi + 24], r14
    mov [rdi + 32], r15
    mov [rdi + 40], rsp
    mov [rdi + 48], rbp
    mov rcx, [rsp] ; return address
    mov [rdi + 56], rcx

    push rdi
    sub rsp, 8
    mov rsi, 0
    mov rdx, rsp
    call sigprocmask
    mov rcx, [rsp]
    add rsp, 8
    pop rdi
    
    mov [rdi + 64], rcx
    mov rax, 0
    ret

global longjmp:function
longjmp:
    mov rcx, [rdi + 64]

    push rdi
    push rsi
    sub rsp, 8
    mov [rsp], rcx
    mov rdi, 2
    mov rsi, rsp
    mov rdx, 0
    call sigprocmask
    add rsp, 8
    pop rsi
    pop rdi

    mov rbx, [rdi]
    mov r12, [rdi + 8]
    mov r13, [rdi + 16]
    mov r14, [rdi + 24]
    mov r15, [rdi + 32]
    mov rsp, [rdi + 40]
    mov rbp, [rdi + 48]    

    mov rax, rsi
    pop rcx
    mov rcx, [rdi + 56]
    jmp rcx