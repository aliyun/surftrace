#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct user_struct{
    int user_a;
    int user_b;
};

void test_struct(struct user_struct *p_user) {
    p_user->user_b = p_user->user_a + 3;
    p_user->user_a ++;
}

void test(int loop) {
    int i;
    for (i = 0; i < loop * 100; i ++);
    printf("end.\n");
}

int main()
{
    int i;
    struct user_struct t_s = {0, 0};

    printf("%d %p\n", getpid(), test);
    for (i = 1; i < 1000; i ++) {
        test(i);
        test_struct(&t_s);
        printf("use: %d\n", t_s.user_a);
        sleep(1);
    }
    return 0;
}
