CFLAGS = -std=gnu11 -Wall

all: libzpoline.so.1 libzpoline.so.2

libzpoline.so.1: libzpoline1.c
	gcc -shared -fPIC $(CFLAGS) $< -o $@

libzpoline.so.2: libzpoline2.c
	gcc -shared -fPIC -g $(CFLAGS) $< -lopcodes -lbfd -ldl -o $@

test: libzpoline1.c
	gcc $(CFLAGS) $< -o $@