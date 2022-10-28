#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

typedef unsigned long addr_t;

struct ksym {
    addr_t addr;
    char *name;
};

int (*ksym_load)(void);
struct ksym* (*ksym_search)(addr_t key);
addr_t (*ksym_addr)(char *name);
void (*ksym_deinit)(void);

void* (*sym_load)(char *path);
long (*elf_code_offset)(void* );
void (*de_mana)(void* );
addr_t (*sym_addr)(void*, char*);
struct ksym* (*sym_search)(void*, addr_t);


int main(int argc, char *argv[]) {
    void* handle = dlopen("./syms.so", RTLD_LAZY);
    void* p_mana = NULL;
    struct ksym* psym;
    addr_t addr;

    printf("dl: %p, %s\n", handle, dlerror());

    ksym_load = dlsym(handle, "ksym_load");
    ksym_search = dlsym(handle, "ksym_search");
    ksym_addr = dlsym(handle, "ksym_addr");
    ksym_deinit = dlsym(handle, "ksym_deinit");

    sym_load = dlsym(handle, "sym_load");
    elf_code_offset = dlsym(handle, "elf_code_offset");
    sym_addr = dlsym(handle, "sym_addr");
    sym_search = dlsym(handle, "sym_search");
    de_mana = dlsym(handle, "de_mana");

    p_mana = sym_load("/usr/bin/bash");
    printf("offset: %lx\n", elf_code_offset(p_mana));

    addr = sym_addr(p_mana, "readline");
    printf("addr: %lx\n", addr);
    psym = sym_search(p_mana, addr + 0x00);
    printf("sym: %s\n", psym->name);
    psym = sym_search(p_mana, addr + 0x100);
    printf("sym: %s\n", psym->name);
    psym = sym_search(p_mana, addr + 0x200);
    printf("sym: %s\n", psym->name);
    psym = sym_search(p_mana, addr + 0x500);
    printf("sym: %s\n", psym->name);

    de_mana(p_mana);

    ksym_load();
    addr = ksym_addr("_do_fork");
    printf("addr: 0x%lx\n", addr);
    psym = ksym_search(addr + 0x0);
    printf("sym: %s\n", psym->name);
    psym = ksym_search(addr + 0x200);
    printf("sym: %s\n", psym->name);
    psym = ksym_search(addr + 0x500);
    printf("sym: %s\n", psym->name);

    ksym_deinit();

    dlclose(handle);

}