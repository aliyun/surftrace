//
// Created by 廖肇燕 on 2022/11/3.
//

#include <stdio.h>
#include <stdlib.h>
#include "second.h"

enum DAY {
    MON=1, TUE, WED, THU, FRI, SAT, SUN
};

void get_iemployee(struct iEmployee* e) {
    e->date.dd = 10;
    printf("e:%d", e->date.dd );
}

void get_employee(struct Employee* e) {
    e->doj.dd = 10;
    printf("e:%d", e->doj.dd );
}

void print_type(second_p p) {
    enum DAY day;
    day = WED;
    printf("%d",day);

    printf("out %ld", p->a);
}

int union_test(union second_union* u) {
    printf("out: %ld", u->a);
    return 0;
}

static int const_test(const int i, volatile int b) {
    printf("%d, %d\n", i, b);
    return 0;
}

int second(void) {
    second_t t = {15L, 14, 13};
    union second_union ut;
    struct Employee ee;
    struct iEmployee ie;
    ut.c = 3;
    print_type(&t);
    union_test(&ut);
    get_employee(&ee);
    get_iemployee(&ie);
    printf("send.\n");
    return 0;
}
