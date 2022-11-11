#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>

void* (*dwarf_load)(char* path);
void (*dwarf_close)(void *handler);
int (*dwarf_show)(void *handler);
int (*dwarf_walk_compile_unit)(void *handler, void* cb);
int (*dwarf_walk2json)(void *handler, void* cb);
int (*dwarf_filter2json)(void *handler, void* cb, void* filter);

static int show(char* s) {
    printf("%s\n", s);
    return 0;
}

static int filter(char* s) {
    return strcmp("second.c", s);
}

int main(int argc, char **argv) {
    void* pso = dlopen("./dwarf_walk.so", RTLD_LAZY);
    void* handler = NULL;

    dwarf_load = dlsym(pso, "dwarf_load");
    dwarf_close = dlsym(pso, "dwarf_close");
    dwarf_show = dlsym(pso, "dwarf_show");
    dwarf_walk_compile_unit = dlsym(pso, "dwarf_walk_compile_unit");
    dwarf_walk2json = dlsym(pso, "dwarf_walk2json");
    dwarf_filter2json = dlsym(pso, "dwarf_filter2json");

    handler = dwarf_load(argv[1]);
    if (handler == NULL) {
        exit(1);
    }

    dwarf_show(handler);
    dwarf_walk_compile_unit(handler, show);
    dwarf_walk2json(handler, show);
    printf("\n\nuse filter.\n\n");
    dwarf_filter2json(handler, show, filter);
    dwarf_close(handler);

    dlclose(pso);
}