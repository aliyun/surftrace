#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int func(int v) {
    printf("show %d\n", v);
}

int main(void) {
    int i;

    printf("hello, uprobe. %d\n", getpid());
    sleep(1);
    for (i = 0; i < 800; i ++){
        func(i);
        sleep(1);
    }
    return 0;
}