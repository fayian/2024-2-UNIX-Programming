#include <dlfcn.h>
#include <assert.h>
#include <stdio.h>

void (*initPtr)();

int main() {
    void* hdl = dlopen("libzpoline.so.2", RTLD_LAZY);
    return 0;
}