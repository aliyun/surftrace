#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "clcc.h"

int main(int argc,char *argv[]) {
    struct clcc_struct* pclcc = clcc_init("./"SO_NAME);

    if (pclcc == NULL) {
        printf("open so file failed.\n");
        exit(-1);
    }
    pclcc->init(-1, 0);
    pclcc->attach_kprobe("j_wake_up_new_task2", "wake_up_new_task");
    pause();
    pclcc->exit();
    clcc_deinit(pclcc);
    return 0;
}