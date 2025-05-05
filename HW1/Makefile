CFLAGS = -std=gnu11 -Wall

all: libzpoline.so.1 libzpoline.so.2 libzpoline.so logger.so

libzpoline.so.1: libzpoline1.c
	gcc -shared -fPIC $(CFLAGS) $< -o $@

libzpoline.so.2: libzpoline2.c
	gcc -shared -fPIC $(CFLAGS) $< -lopcodes -lbfd -ldl -o $@

libzpoline.so: libzpoline3.c
	gcc -shared -fPIC $(CFLAGS) $< -lopcodes -lbfd -ldl -o $@

logger.so: logger.c
	gcc -shared -fPIC $(CFLAGS) $< -ldl -o $@