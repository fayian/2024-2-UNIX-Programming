section .data
    seed dq 0

section .text

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
    mov QWORD[rdi], 0xffffffffffffffff
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
    xor rdx, 0xffffffffffffffff
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