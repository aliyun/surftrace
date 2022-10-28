//
// Created by 廖肇燕 on 2022/10/22.
//
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <bfd.h>
#include <linux/elf.h>
#include "elf_local.h"

#define FUNC_LEN_MAX 256

typedef unsigned long addr_t;

struct ksym {
    addr_t addr;
    char *name;
};

struct elf_manager {
    long local;
    long dynamic;
    long counts;
    long index;
    long load_offset;
    struct ksym *psym;
};

static struct ksym* syms = NULL;
static int sym_cnt;
static int elf_init = 1;

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

static int walk_symbol(asymbol **symbol_table,
                       long number_of_symbols,
                       struct elf_manager *p_mana) {
    long i;
    int ret = 0;
    long index = p_mana->index;
    symbol_info symbolinfo;

    for (i = 0; i < number_of_symbols; i++) {
        struct ksym *psym = &(p_mana->psym[index]);

        if (symbol_table[i]->section == NULL)
            continue;

        bfd_symbol_info(symbol_table[i], &symbolinfo);
        psym->name = strdup(symbolinfo.name);
        psym->addr = (addr_t)symbolinfo.value;
        index ++;

    }
    p_mana->index = index;
    return ret;
}

static int count_local_symbol(bfd *ibfd) {
    long storage_needed;
    asymbol **symbol_table;
    long number_of_symbols = 0;

    storage_needed = bfd_get_symtab_upper_bound(ibfd);
    if (storage_needed < 0) {
        fprintf(stderr, "bfd_get_symtab_upper_bound failed.\n");
        return -EINVAL;
    }

    if (storage_needed > 0) {
        symbol_table = (asymbol **)(long)malloc(storage_needed);
        if (symbol_table == NULL) {
            fprintf(stderr, "malloc for local_symbol failed.\n");
            return -ENOMEM;
        }

        number_of_symbols = bfd_canonicalize_symtab(ibfd, symbol_table);
        free(symbol_table);
        if (number_of_symbols < 0) {
            fprintf(stderr, "bfd_canonicalize_symtab failed.\n");
            return -EINVAL;
        }

    }
    return number_of_symbols;
}

static int dump_local_symbol(bfd *ibfd, struct elf_manager *p_mana) {
    int ret = 0;
    long storage_needed;
    asymbol **symbol_table;
    long number_of_symbols;

    storage_needed = bfd_get_symtab_upper_bound(ibfd);
    if (storage_needed < 0) {
        fprintf(stderr, "bfd_get_symtab_upper_bound failed.\n");
        return -EINVAL;
    }

    if (storage_needed > 0) {
        symbol_table = (asymbol **)(long)malloc(storage_needed);
        if (symbol_table == NULL) {
            fprintf(stderr, "malloc for local_symbol failed.\n");
            return -ENOMEM;
        }

        number_of_symbols = bfd_canonicalize_symtab(ibfd, symbol_table);
        if (number_of_symbols < 0) {
            fprintf(stderr, "bfd_canonicalize_symtab failed.\n");
            free(symbol_table);
            return -EINVAL;
        }

        ret = walk_symbol(symbol_table, number_of_symbols, p_mana);
        if (ret < 0) {
            ret = -EINVAL;
        }
        free(symbol_table);
    }
    return ret;
}

static int count_dynamic_symbol(bfd *ibfd) {
    long storage_needed;
    asymbol **symbol_table;
    long number_of_symbols = 0;

    storage_needed = bfd_get_dynamic_symtab_upper_bound(ibfd);
    if (storage_needed < 0) {
        fprintf(stderr, "bfd_get_dynamic_symtab_upper_bound failed.\n");
        return -EINVAL;
    }

    if (storage_needed > 0) {
        symbol_table = (asymbol **)(long)malloc(storage_needed);
        if (symbol_table == NULL) {
            fprintf(stderr, "malloc for local_symbol failed.\n");
            return -ENOMEM;
        }

        number_of_symbols = bfd_canonicalize_dynamic_symtab(ibfd, symbol_table);
        free(symbol_table);
        if (number_of_symbols < 0) {
            fprintf(stderr, "bfd_canonicalize_dynamic_symtab failed.\n");
            return -EINVAL;
        }
    }
    return number_of_symbols;
}

static int dump_dynamic_symbol(bfd *ibfd, struct elf_manager *p_mana) {
    int ret = 0;
    long storage_needed;
    asymbol **symbol_table;
    long number_of_symbols;

    storage_needed = bfd_get_dynamic_symtab_upper_bound(ibfd);
    if (storage_needed < 0) {
        fprintf(stderr, "bfd_get_dynamic_symtab_upper_bound failed.\n");
        return -EINVAL;
    }

    if (storage_needed > 0) {
        symbol_table = (asymbol **)(long)malloc(storage_needed);
        if (symbol_table == NULL) {
            fprintf(stderr, "malloc for local_symbol failed.\n");
            return -ENOMEM;
        }

        number_of_symbols = bfd_canonicalize_dynamic_symtab(ibfd, symbol_table);
        if (number_of_symbols < 0) {
            fprintf(stderr, "bfd_canonicalize_dynamic_symtab failed.\n");
            free(symbol_table);
            return -EINVAL;
        }

        ret = walk_symbol(symbol_table, number_of_symbols, p_mana);
        if (ret < 0) {
            ret = -EINVAL;
        }
        free(symbol_table);
    }
    return ret;
}

static int symbol_count(bfd *ibfd, struct elf_manager *p_mana) {
    long res;

    res = count_local_symbol(ibfd);
    if (res < 0) {
        return (int)res;
    }
    p_mana->local = res;

    res = count_dynamic_symbol(ibfd);
    if (res < 0) {
        return (int)res;
    }
    p_mana->dynamic = res;
    p_mana->counts = p_mana->local + p_mana->dynamic;
    return 0;
}

addr_t sym_addr(struct elf_manager *p_mana, char* func) {
    long i;

    for (i = 0; i < p_mana->index; i ++) {
        if (strcmp(func, p_mana->psym[i].name) == 0) {
            return p_mana->psym[i].addr;
        }
    }
    return 0;
}

struct ksym *sym_search(struct elf_manager *p_mana, addr_t key) {
    long start = 0, end = p_mana->index;
    struct ksym *syms = p_mana->psym;

    while (start < end) {
        int mid = start + (end - start) / 2;

        if (key < syms[mid].addr)
            end = mid;
        else if (key > syms[mid].addr)
            start = mid + 1;
        else
            return &syms[mid];
    }

    if (start >= 1 && syms[start - 1].addr < key && key < syms[start].addr)
        /* valid ksym */
        return &syms[start - 1];

    /* out of range. return _stext */
    return NULL;
}

void de_mana(struct elf_manager *p_mana) {
    int i;

    for (i = 0; i < p_mana->index; i ++) {
        free(p_mana->psym[i].name);
    }
    free(p_mana->psym);
    free(p_mana);
}

static long _elf_load_offset(bfd *ibfd) {
    long ret = -1;
    struct elf_obj_tdata* tdata;
    struct elf_internal_phdr* p;

    tdata = elf_tdata(ibfd);
    p = tdata->phdr;
    if (p != NULL) {
        unsigned int i, c;
        c = elf_elfheader(ibfd)->e_phnum;
        for (i = 0; i < c; i++, p++) {
            if ((p->p_type == PT_LOAD)&&(p->p_flags & PF_X)) {
                ret = p->p_vaddr;
                break;
            }
        }
    }
    return ret;
}

struct elf_manager *sym_load(char *path) {
    int res = 0;
    bfd *ibfd;
    char **matching;
    struct elf_manager *p_mana;
    long offset;

    if (elf_init) {
        bfd_init();
        elf_init = 0;
    }

    p_mana = (struct elf_manager *)malloc(sizeof(struct elf_manager));
    if (p_mana == NULL) {
        fprintf(stderr, "malloc manager struct failed.\n");
        return NULL;
    }

    ibfd = bfd_openr(path, NULL);
    if (ibfd == NULL) {
        fprintf(stderr, "bfd_openr %s failed.\n", path);
        return NULL;
    }

    if (bfd_check_format_matches(ibfd, bfd_object, &matching)) {
        res = symbol_count(ibfd, p_mana);
        if (res < 0) {
            goto end_syms;
        }

        p_mana->index = 0;
        p_mana->psym = (struct ksym*)malloc(sizeof(struct ksym) * p_mana->counts);
        if (p_mana->psym == NULL) {
            res = -ENOMEM;
            goto end_syms;
        }

        res = dump_local_symbol(ibfd, p_mana);
        if (res < 0) {
            goto load_failed;
        }
        res = dump_dynamic_symbol(ibfd, p_mana);
        if (res < 0) {
            goto load_failed;
        }
        qsort(p_mana->psym, p_mana->index, sizeof(struct ksym), sym_cmp);
    } else {
        fprintf(stderr, "bfd_check_format_matches %s failed.\n", path);
        goto end_syms;
    }

    offset = _elf_load_offset(ibfd);
    if (offset < 0) {
        fprintf(stderr, "elf_load_offset get %s load offset failed.\n", path);
        goto end_offset;
    }
    p_mana->load_offset = offset;

    bfd_close(ibfd);
    return p_mana;

    end_syms:
    free(p_mana);
    goto close_bfd;
    end_offset:
    load_failed:
    de_mana(p_mana);
    close_bfd:
    bfd_close(ibfd);
    return NULL;
}

long elf_code_offset(struct elf_manager *p_mana) {
    return p_mana->load_offset;
}