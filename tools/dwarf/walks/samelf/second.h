//
// Created by 廖肇燕 on 2022/11/3.
//

#ifndef WALKS_SECOND_H
#define WALKS_SECOND_H

typedef unsigned long u64;

struct second_struct {
    u64 a;
    int b;
    char c;
    int d[16];
    short e[8];
    char f[8][8];
    char *name;
    void (*func)(int);
    int (*func2)(void);
    int (*func3)(char, int);
};

union second_union {
    u64 a;
    int b;
    char c;
};

typedef struct second_struct second_t;
typedef struct second_struct * second_p;

struct Date
{
    int dd;
    int mm;
    int yyyy;
};

struct Employee
{
    int bit1:2;
    int bit2:3;
    int bit3:1;
    int id;
    char name[20];
    struct Date doj;
};

struct iEmployee
{
    int id;
    char name[20];
    struct {
        int dd;
        int mm;
        int yyyy;
    } date;
};

int second(void);

#endif //WALKS_SECOND_H
