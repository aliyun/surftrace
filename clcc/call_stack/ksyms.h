#ifndef KSYMS_H_
#define KSYMS_H_

#include "clcc.h"

typedef unsigned long addr_t;

struct ksym {
    addr_t addr;
    char *name;
};

int ksym_load(void);
struct ksym *ksym_search(addr_t key);
addr_t ksym_addr(const char *name);
void ksym_shows(struct clcc_call_stack *pstack);
void ksym_deinit(void);

#endif