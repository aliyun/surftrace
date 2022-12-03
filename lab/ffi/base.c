#include <stdio.h>
#include <string.h>

struct struct_user{
    int a;
    int b;
    char s[16];
    int c[4];
    void *p;
    double d;
    float f;
};

int user_test(int (*func)(struct struct_user* p), int v) {
    struct struct_user user = {};
    user.a = v;
    user.b = v * 2;
    strcpy(user.s, "hello.");
    user.c[0] = 0;
    user.c[1] = 1;
    user.c[2] = 2;
    user.c[3] = 3;
    user.p = NULL;
    user.d = 1.1;
    user.f = 1.2;
    return func(&user);
}

void user_add(int a, int b) {
    printf("%d + %d = %d\n", a, b, a + b);
}
