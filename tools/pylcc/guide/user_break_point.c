#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void test(int loop) {
    int i;
    for (i = 0; i < loop * 100; i ++);
    printf("end.\n");
}

int main()
{
    int i;
    printf("%d %p\n", getpid(), test);
    for (i = 1; i < 1000; i ++) {
        test(i);
        sleep(1);
    }
    return 0;
}
