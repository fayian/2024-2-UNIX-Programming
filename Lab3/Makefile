all: libgotoku libsolver libsolver_local gotoku

libgotoku: libgotoku_dummy.c
	gcc -fPIC -shared libgotoku_dummy.c -o libgotoku.so -ldl

libsolver: libsolver.c
	gcc -fPIC -shared libsolver.c -o libsolver.so -ldl

libsolver_local: libsolver.local.c
	gcc -fPIC -shared libsolver.local.c -o libsolver.local.so -ldl

gotoku: gotoku.c
	gcc -L. -Wl,-rpath=. -Wall gotoku.c -o gotoku.local -lgotoku

clean:
	rm libgotoku.so
	rm gotoku.local
