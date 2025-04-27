CFLAGS = -std=gnu11 -Wall

all: libzpoline.so.1

libzpoline.so.1: libzpoline1.c
	gcc -shared -fPIC $(CFLAGS) $< -o $@