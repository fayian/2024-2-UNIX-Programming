#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include "libgotoku.h"
#include "got_table.h"

gotoku_t* sol_board;
int idx;
void* main_addr;

void* handle;
void (*sol_up)();
void (*sol_down)();
void (*sol_left)();
void (*sol_right)();
void (*sol_fill[10])();
void *(*sol_game_get_ptr)();
int (*sol_game_init)();
void (*actions[1200])();

gotoku_t *sol_game_load(const char *fn) {
	gotoku_t *gt = NULL;
	FILE *fp = NULL;
	int i, j, k;
	if((fp = fopen(fn, "rt")) == NULL) {
		fprintf(stderr, "SOLVER: fopen failed - %s.\n", strerror(errno));
		return NULL;
	}
	if((gt = sol_board = (gotoku_t*) malloc(sizeof(gotoku_t))) == NULL) {
		fprintf(stderr, "SOLVER: alloc failed - %s.\n", strerror(errno));
		goto err_quit;
	}
	gt->x = gt->y = 0;
	for(i = 0; i < 9; i++) {
		for(j = 0; j < 9; j++) {
			if(fscanf(fp, "%d", &k) != 1) {
				fprintf(stderr, "SOLVER: load number (%d, %d) failed - %s.\n", j, i, strerror(errno));
				goto err_quit;
			}
			gt->board[i][j] = k;
		}
	}
	fclose(fp);
	return gt;
err_quit:
	if(gt) free(gt);
	if(fp) fclose(fp);
	sol_board = NULL;
	return NULL;
}

bool check(int x, int y) {
    bool appeared[9];
    int num;

    //check row
    memset(appeared, 0, 9);
    for(int i = 0; i < 9; i++) {
        num = sol_board->board[i][y];
        if(!num) continue;
        if(appeared[num - 1])
            return false;

        appeared[num - 1] = true;
    }

    //check column
    memset(appeared, 0, 9);
    for(int i = 0; i < 9; i++) {
        num = sol_board->board[x][i];
        if(!num) continue;
        if(appeared[num - 1])
            return false;

        appeared[num - 1] = true;
    }

    //check block
    memset(appeared, 0, 9);
    int blockX = x / 3;
    int blockY = y / 3;
    for(int i = 0; i < 3; i++) {
        for(int j = 0; j < 3; j++) {
            num = sol_board->board[blockX * 3 + i][blockY * 3 + j];
            if(!num) continue;
            if(appeared[num - 1])
                return false;

            appeared[num - 1] = true;
        }
    }

    return true;
}

bool solve_board(int x, int y) {
    if(x >= 9 || y >= 9) return true;

    int nextX = x + 1;
    int nextY = y + (nextX / 9);
    nextX %= 9;
    if(sol_board->board[x][y]) return solve_board(nextX, nextY);

    for(int i = 1; i <= 9; i++) {
        sol_board->board[x][y] = i;
        if(!check(x, y)) {
            continue;
        }
        if(solve_board(nextX, nextY)) return true;
    }
    sol_board->board[x][y] = 0;
    return false;
}

//hijack game_init()
int game_init() {
    printf("UP113_GOT_PUZZLE_CHALLENGE\n");
    // Getting functions from libgotoku.so
    handle = dlopen("libgotoku.so", RTLD_NOW);
    if(handle == NULL) fprintf(stderr, "%s\n", dlerror());

    sol_up = dlsym(handle, "gop_up");
    sol_down = dlsym(handle, "gop_down");
    sol_left = dlsym(handle, "gop_left");
    sol_right = dlsym(handle, "gop_right");
    sol_fill[0] = dlsym(handle, "gop_fill_0");
    sol_fill[1] = dlsym(handle, "gop_fill_1");
    sol_fill[2] = dlsym(handle, "gop_fill_2");
    sol_fill[3] = dlsym(handle, "gop_fill_3");
    sol_fill[4] = dlsym(handle, "gop_fill_4");
    sol_fill[5] = dlsym(handle, "gop_fill_5");
    sol_fill[6] = dlsym(handle, "gop_fill_6");
    sol_fill[7] = dlsym(handle, "gop_fill_7");
    sol_fill[8] = dlsym(handle, "gop_fill_8");
    sol_fill[9] = dlsym(handle, "gop_fill_9");
    sol_game_init = dlsym(handle, "game_init");
    sol_game_get_ptr = dlsym(handle, "game_get_ptr");    
    
    // Solve the gotoku
    sol_board = sol_game_load("/gotoku.txt");
    solve_board(0, 0);

    idx = 0;
    for(int x = 0; x < 9; x++) {
        for(int y = 0; y < 9; y++) {
            actions[idx++] = sol_fill[sol_board->board[x][y]];
            actions[idx++] = sol_right;
        }
        actions[idx++] = sol_down;
    }

    free(sol_board);	

    // Get pointer to main
    sol_game_init();
    main_addr = sol_game_get_ptr();
    printf("SOLVER: _main = %p\n", main_addr);    
    
    //hijack gop_NNN
    int pagesize = sysconf(_SC_PAGE_SIZE);
    void *main_relative_addr = (void*)0x16c89;
    void **target_got_addr;
    uintptr_t ptr;
    for(int i = 0; i < idx; i++) {        
        target_got_addr = main_addr - main_relative_addr + got_table[i];
        ptr = (uintptr_t)target_got_addr / pagesize * pagesize;
        int err = mprotect((void*)ptr, sizeof(void*), PROT_READ | PROT_WRITE);
        if(err < 0) perror("mprotect");
        *target_got_addr = actions[i];
        mprotect((void*)ptr, sizeof(void*), PROT_READ);
    }

    return 0;
}