#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "ksyms.h"

#define FUNC_LEN_MAX 256

static struct ksym* syms = NULL;
static int sym_cnt;

static int sym_cmp(const void *p1, const void *p2)
{
    return ((struct ksym *)p1)->addr > ((struct ksym *)p2)->addr;
}

static int load_kallsyms(int lines)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    int ret;
    char func[FUNC_LEN_MAX], buf[FUNC_LEN_MAX], ko[FUNC_LEN_MAX];
    char symbol;
    void *addr;
    int i = 0;

    if (!f)
        return -ENOENT;

    while (!feof(f)) {
        if (!fgets(buf, sizeof(buf), f))
            break;
        ret = sscanf(buf, "%p %c %s %s", &addr, &symbol, func, ko);
        if (ret == 4) {
            strncat(func, " ", FUNC_LEN_MAX -1);
            strncat(func, ko, FUNC_LEN_MAX -1);
            func[FUNC_LEN_MAX -1] = '\0';
        }
        else if (ret != 3) {
            break;
        }
        if (!addr)
            continue;
        syms[i].addr = (addr_t) addr;
        syms[i].name = strdup(func);
        i ++;
        if (i > lines) {
            fprintf(stderr, "warning: /proc/kallsyms symbol overflow.");
            break;
        }
    }
    fclose(f);
    sym_cnt = i;
    qsort(syms, sym_cnt, sizeof(struct ksym), sym_cmp);
    return 0;
}

static int line_kallsyms(void) {
    int count;

    FILE *f = fopen("/proc/kallsyms", "r");

    if (!f)
        return -ENOENT;

    while (!feof(f)) {
        if (fgetc(f) == '\n')
            count ++;
    }
    return count + 1;
}

int ksym_load(void) {
    int lines;

    if (syms == NULL) {
        lines = line_kallsyms();
        if (lines <= 0) {
            return -ENOENT;
        }

        syms = malloc(sizeof(struct ksym) * lines);
        if (syms == NULL)
            return -ENOMEM;
        memset(syms, 0, sizeof(struct ksym) * lines);

        if (load_kallsyms(lines)) {
            free(syms);
            return -ENOENT;
        }
    }
    return 0;
}

struct ksym *ksym_search(addr_t key)
{
    int start = 0, end = sym_cnt;

    /* kallsyms not loaded. return NULL */
    if (sym_cnt <= 0)
        return NULL;

    while (start < end) {
        size_t mid = start + (end - start) / 2;

        if (key < syms[mid].addr)
            end = mid;
        else if (key > syms[mid].addr)
            start = mid + 1;
        else
            return &syms[mid];
    }

    if (start >= 1 && syms[start - 1].addr < key &&
        key < syms[start].addr)
        /* valid ksym */
        return &syms[start - 1];

    /* out of range. return _stext */
    return &syms[0];
}

void ksym_shows(struct clcc_call_stack *pstack)
{
    int i;
    struct ksym* sym;

    for (i = 0; i < pstack->depth; i ++) {
        sym = ksym_search(pstack->stack[i]);
        printf("\t0x%lx: %s+0x%lx\n", pstack->stack[i], sym->name, pstack->stack[i] - sym->addr);
    }
}

addr_t ksym_addr(const char *name)
{
    int i;

    for (i = 0; i < sym_cnt; i++) {
        if (strcmp(syms[i].name, name) == 0)
            return syms[i].addr;
    }
    return 0;
}

void ksym_deinit(void) {
    if (syms != NULL) {
        int i;
        for (i = 0; i < sym_cnt; i ++) {
            free(syms[i].name);
        }
        free(syms);

        syms = NULL;
    }
}