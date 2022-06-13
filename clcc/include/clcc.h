#ifndef CLCC_H
#define CLCC_H

#include <dlfcn.h>
#include <errno.h>

#define PERF_MAX_STACK_DEPTH 127

struct clcc_call_stack{
    unsigned long stack[PERF_MAX_STACK_DEPTH];
    int depth;
};

struct ksym {
    long addr;
    char *name;
};

static const char * clcc_funcs[] = {
    "lbc_bpf_init",
    "lbc_bpf_exit",
    "lbc_bpf_get_maps_id",
    "lbc_set_event_cb",
    "lbc_event_loop",
    "lbc_map_lookup_elem",
    "lbc_map_lookup_and_delete_elem",
    "lbc_map_delete_elem",
    "lbc_map_get_next_key",
    "lbc_get_map_types",
    "ksym_search",
};

struct clcc_struct{
    /*
     * member: handle
     * description: so file file handle pointer, it should not be modified or accessed.
     */
    void* handle;
    /*
     * member: status
     * description: reserved.
     */
    int status;
    /*
     * member: init
     * description: install libbpf programme,
     * arg1: print level, 0~3. -1:do not print any thing.
     * return: 0 if success.
     */
    int  (*init)(int);
     /*
     * member: exit
     * description: uninstall libbpf programme,
     * return: None.
     */
    void (*exit)(void);
    /*
     * member: get_maps_id
     * description: get map id from map name which quote in LBC_XXX().
     * arg1: event: map name which quote in LBC_XXX(), eg: LBC_PERF_OUTPUT(e_out, struct data_t, 128),  then arg is e_out.
     * return: >=0, failed when < 0
     */
    int  (*get_maps_id)(char* event);
    /*
     * member: set_event_cb
     * description: set call back function for perf out event.
     * arg1: event id, get from get_maps_id.
     * arg2: callback function when event polled.
     * arg3: lost callback function when event polled.
     * return: 0 if success.
     */
    int  (*set_event_cb)(int id,
                       void (*cb)(void *ctx, int cpu, void *data, unsigned int size),
                       void (*lost)(void *ctx, int cpu, unsigned long long cnt));
    /*
     * member: event_loop
     * description: poll perf out put event, usually used in pairs with set_event_cb function.
     * arg1: event id, get from get_maps_id.
     * arg2: timeout， unit seconds. -1 nevet timeout.
     * return: 0 if success.
     */
    int  (*event_loop)(int id, int timeout);
    /*
     * member: map_lookup_elem
     * description: lookup element by key.
     * arg1: event id, get from get_maps_id.
     * arg2: key point.
     * arg3: value point.
     * return: 0 if success.
     */
    int  (*map_lookup_elem)(int id, const void *key, void *value);
    /*
     * member: map_lookup_and_delete_elem
     * description: lookup element by key then delete key.
     * arg1: event id, get from get_maps_id.
     * arg2: key point.
     * arg3: value point.
     * return: 0 if success.
     */
    int  (* map_lookup_and_delete_elem)(int id, const void *key, void *value);
    /*
     * member: map_lookup_and_delete_elem
     * description: lookup element by key then delete key.
     * arg1: event id, get from get_maps_id.
     * arg2: key point.
     * return: 0 if success.
     */
    int  (*map_delete_elem)(int id, const void *key);
    /*
     * member: map_get_next_key
     * description: walk keys from maps.
     * arg1: event id, get from get_maps_id.
     * arg2: key point.
     * arg3: next key point.
     * return: 0 if success.
     */
    int  (*map_get_next_key)(int id, const void *key, void *next_key);
    const char* (*get_map_types)(void);
    /*
     * member: ksym_search
     * description: get symbol from kernel addr.
     * arg1: kernnel addr.
     * return: symbol name and address information.
     */
    struct ksym* (*ksym_search)(unsigned long addr);
};


inline int clcc_setup_syms(void* handle, struct clcc_struct *pclcc)
{
    void** head = (void** )&(pclcc->init);
    void* func = NULL;
    int nums = sizeof(clcc_funcs) / sizeof(const char *);
    int i = 0;

    for (i = 0; i < nums; i ++) {
        func = dlsym(handle, clcc_funcs[i]);
        if (func == NULL) {
            printf("can not find %s on so.", clcc_funcs[i]);
            return -1;
        }
        *(head ++) = func;
    }
    return 0;
}

/*
 * function name: clcc_init
 * description: load an so
 * arg1: so path to load
 * return: struct clcc_struct *
 */
inline struct clcc_struct* clcc_init(const char* so_path)
{
    void *handle = NULL;
    struct clcc_struct *pclcc = NULL;

    if ((handle = dlopen(so_path, RTLD_NOW)) == NULL) {
        printf("dlopen - %sn", dlerror());
        errno = -EPERM;
        goto open_failed;
    }

    pclcc = (struct clcc_struct *)malloc(sizeof(struct clcc_struct));
    if (pclcc == NULL) {
        errno = -ENOMEM;
        goto malloc_failed;
    }

    pclcc->handle = handle;
    if (clcc_setup_syms(handle, pclcc)) {
        errno = -ESRCH;
        goto setup_failed;
    }
    return pclcc;

setup_failed:
    free(pclcc);
malloc_failed:
    dlclose(handle);
open_failed:
    return NULL;
}

/*
 * function name: clcc_deinit
 * description: release an so
 * arg1:  struct clcc_struct *p; setup from clcc_init function, mem will be free in this function.
 * return: None
 */
inline void clcc_deinit(struct clcc_struct* pclcc)
{
    void *handle = pclcc->handle;

    free(pclcc);
    dlclose(handle);
}

/*
 * function name: clcc_get_call_stack
 * description:  get call stack from table and stack id
 * arg1:  table id: from struct clcc_struct get_maps_id function.
 * arg2: stack_id: from bpf kernel bpf_get_stackid function.
 * arg3: pstack:  struct clcc_call_stack, should be alloced at first, use in clcc_print_stack
 * arg4: pclcc: setup from clcc_init function
 * return: 0 if success.
 */
inline int clcc_get_call_stack(int table_id,
                               int stack_id,
                               struct clcc_call_stack *pstack,
                               struct clcc_struct *pclcc) {
    int i;
    int ret;

    ret = pclcc->map_lookup_elem(table_id, &stack_id, &(pstack->stack[0]));
    if (ret != 0) {
        printf("get stack id %d return %d\n", stack_id, ret);
        return 1;
    }

    pstack->depth = PERF_MAX_STACK_DEPTH;
    for (i = 0; i < PERF_MAX_STACK_DEPTH; i ++) {
        if (pstack->stack[i] == 0) {
            pstack->depth = i;
            break;
        }
    }
    return 0;
}

/*
 * function name: clcc_print_stack
 * description:  print call stack
 * arg1: pstack:  struct clcc_call_stack, stack to print, setup from clcc_get_call_stack.
 * arg2: pclcc: setup from clcc_init function
 * return: None.
 */
inline void clcc_print_stack(struct clcc_call_stack *pstack,
                             struct clcc_struct *pclcc){
    int i;
    struct ksym* sym;

    for (i = 0; i < pstack->depth; i ++) {
        sym = pclcc->ksym_search(pstack->stack[i]);
        printf("\t0x%lx: %s+0x%lx\n", pstack->stack[i], sym->name, pstack->stack[i] - sym->addr);
    }
}

#endif
