#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

struct uprobe_def{
    int a;
    int b;
};

int func(int v, struct uprobe_def* ud) {
    printf("show %d, a: %d, b:%d\n", v, ud->a, ud->b);
    return v;
}

int main(void) {
    int i;
    struct uprobe_def ud = {1, 1};
    printf("hello, uprobe. %d\n", getpid());
    sleep(1);
    for (i = 1; i < 1000; i ++){
        ud.a = i * 2;
        ud.b = i * 3;
        func(i, &ud);
        sleep(1);
    }
    return 0;
}
