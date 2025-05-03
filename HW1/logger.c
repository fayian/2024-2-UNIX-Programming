#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>

typedef int64_t (*syscall_hook_fn_t)(int64_t, int64_t, int64_t, int64_t,
                                     int64_t, int64_t, int64_t);

static syscall_hook_fn_t original_syscall = NULL;

void setEscapeContent(char* dst, const char* src, size_t len) {
    int index = 0;
    if(len > 32) len = 32;
    for(size_t i = 0; i < len; i++) {
        if(isprint(src[i])) dst[index++] = src[i];
        else if(src[i] == '\n') {
            dst[index++] = '\\';
            dst[index++] = 'n';
        } else if(src[i] == '\t') {
            dst[index++] = '\\';
            dst[index++] = 't';
        } else if(src[i] == '\r') {
            dst[index++] = '\\';
            dst[index++] = 'r';
        } else {
            sprintf(dst + index, "\\x%x", src[i]);
            index += 4;
        }
    }
    dst[index] = '\0';
}

static int64_t syscall_hook_fn(int64_t rdi, int64_t rsi, int64_t rdx,
                               int64_t r10, int64_t r8, int64_t r9,
                               int64_t rax) {
    char log[4096];
    bool doLog = true;    

    switch(rax) {
    case 257: //openat
        if((int)rdi == -100) {
            sprintf(log, "[logger] openat(AT_FDCWD, \"%s\", 0x%x, %#o) = %%lu\n", 
                (char*)rsi, 
                (int)rdx, 
                (int)r10);
        } else {
            sprintf(log, "[logger] openat(%d, \"%s\", 0x%x, %#o) = %%lu\n", 
                (int)rdi,
                (char*)rsi, 
                (int)rdx, 
                (int)r10
            );
        }
        break;
    case 0:
        {
            char buf[256] = ""; 
            setEscapeContent(buf, (char*)rsi, (size_t)rdx);

            sprintf(log, "[logger] read(%u, \"%s\"%s, %lu) = %%lu\n", 
                (unsigned int)rdi,
                buf,
                (size_t)rdx > 32 ? "..." : "",
                (size_t)rdx
            );
        }
        break;

    case 1:
        {
            char buf[256]; 
            setEscapeContent(buf, (char*)rsi, (size_t)rdx);

            sprintf(log, "[logger] write(%u, \"%s\"%s, %lu) = %%lu\n", 
                (unsigned int)rdi,
                buf,
                (size_t)rdx > 32 ? "..." : "",
                (size_t)rdx
            );
        }
        break;

    case 42:
        sa_family_t sockType = ((struct sockaddr*)rsi)->sa_family;
        if(sockType == AF_INET) {
            sprintf(log, "[logger] connect(%d, \"%s:%u\", %d) = %%lu\n", 
                (int)rdi,
                inet_ntoa(((struct sockaddr_in*)rsi)->sin_addr),
                htons(((struct sockaddr_in*)rsi)->sin_port),
                (int)rdx
            );
        } else if(sockType == AF_INET6) {
            char addr[64];
            inet_ntop(AF_INET6, &((struct sockaddr_in6*)rsi)->sin6_addr, addr, (int)rdx);
            sprintf(log, "[logger] connect(%d, \"%s:%u\", %d) = %%lu\n", 
                (int)rdi,
                addr,
                htons(((struct sockaddr_in6*)rsi)->sin6_port),
                (int)rdx
            );
        } else if(sockType == AF_UNIX) {
            sprintf(log, "[logger] connect(%d, \"UNIX:%s\", %d) = %%lu\n", 
                (int)rdi,
                ((struct sockaddr_un*)rsi)->sun_path,
                (int)rdx
            );
        }        
        break;
    
    case 59:
        fprintf(stderr, "[logger] execve(\"%s\", %p, %p)\n",
            (char*)rdi,
            (void*)rsi,
            (void*)rdx
        );
        break;
    
    default:
        doLog = false;
        break;
    }
    int64_t result = original_syscall(rdi, rsi, rdx, r10, r8, r9, rax);

    if(doLog) fprintf(stderr, log, result);
    return result;
}

void __hook_init(const syscall_hook_fn_t trigger_syscall,
                 syscall_hook_fn_t *hooked_syscall) {
    original_syscall = trigger_syscall;
    *hooked_syscall = syscall_hook_fn;
}