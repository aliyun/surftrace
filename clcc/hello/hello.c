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
    pclcc->init(-1);
    pause();
    pclcc->exit();
    clcc_deinit(pclcc);
    return 0;
}
