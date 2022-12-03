#ifndef CLCC_H
#define CLCC_H

#include <dlfcn.h>
#include <errno.h>

#define PERF_MAX_STACK_DEPTH 127

struct clcc_call_stack{
    unsigned long stack[PERF_MAX_STACK_DEPTH];
    int depth;
};

static const char * clcc_funcs[] = {
    "lbc_bpf_init",
    "lbc_bpf_exit",
    "lbc_bpf_get_maps_id",
    "lbc_set_event_cb",
    "lbc_event_loop",
    "lbc_map_lookup_elem",
    "lbc_map_lookup_elem_flags",
    "lbc_map_lookup_and_delete_elem",
    "lbc_map_delete_elem",
    "lbc_map_update_elem",
    "lbc_map_get_next_key",
    "lbc_attach_perf_event",
    "lbc_attach_kprobe",
    "lbc_attach_kretprobe",
    "lbc_attach_uprobe",
    "lbc_attach_uretprobe",
    "lbc_attach_tracepoint",
    "lbc_attach_raw_tracepoint",
    "lbc_attach_cgroup",
    "lbc_attach_netns",
    "lbc_attach_xdp",
    "lbc_get_map_types",
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
     * arg2: attach, 0: do not attach, !0: attach
     * return: 0 if success.
     */
    int  (*init)(int log_level, int attach);
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
     * member: map_lookup_elem_flags
     * description: lookup element by key.
     * arg1: event id, get from get_maps_id.
     * arg2: key point.
     * arg3: value point.
     * return: 0 if success.
     */
    int  (*map_lookup_elem_flags)(int id, const void *key, void *value, unsigned long int);
    /*
     * member: map_lookup_and_delete_elem
     * description: lookup element by key then delete key.
     * arg1: event id, get from get_maps_id.
     * arg2: key point.
     * arg3: value point.
     * return: 0 if success.
     */
    int  (*map_lookup_and_delete_elem)(int id, const void *key, void *value);
    /*
     * member: map_delete_elem
     * description: lookup element by key then delete key.
     * arg1: event id, get from get_maps_id.
     * arg2: key point.
     * return: 0 if success.
     */
    int  (*map_delete_elem)(int id, const void *key);
    /*
     * member: map_update_elem
     * description: update element by key.
     * arg1: event id, get from get_maps_id.
     * arg2: key point.
     * arg3: value point.
     * return: 0 if success.
     */
    int  (*map_update_elem)(int id, const void *key, void *value);
    /*
     * member: map_get_next_key
     * description: walk keys from maps.
     * arg1: event id, get from get_maps_id.
     * arg2: key point.
     * arg3: next key point.
     * return: 0 if success.
     */
    int  (*map_get_next_key)(int id, const void *key, void *next_key);
    /*
     * member: attach_perf_event
     * description: attach perf event.
     * arg1: function name in bpf.c.
     * arg2: perf event id.
     * return: 0 if success.
     */
    int  (*attach_perf_event)(const char* func, int pfd);
    /*
     * member: attach_kprobe
     * description: attach kprobe.
     * arg1: function name in bpf.c.
     * arg2: kprobe symbol.
     * return: 0 if success.
     */
    int  (*attach_kprobe)(const char* func, const char* sym);
    /*
     * member: attach_kretprobe
     * description: attach kprobe.
     * arg1: function name in bpf.c.
     * arg2: kprobe symbol.
     * return: 0 if success.
     */
    int  (*attach_kretprobe)(const char* func, const char* sym);
    /*
     * member: attach_uprobe
     * description: attach uprobe.
     * arg1: function name in bpf.c.
     * arg2: task pid
     * arg3: binary_path.
     * arg4: offset.
     * return: 0 if success.
     */
    int  (*attach_uprobe)(const char* func, int pid, const char *binary_path, unsigned long func_offset);
    /*
     * member: attach_uretprobe
     * description: attach uretprobe.
     * arg1: function name in bpf.c.
     * arg2: task pid
     * arg3: binary_path.
     * arg4: offset.
     * return: 0 if success.
     */
    int  (*attach_uretprobe)(const char* func, int pid, const char *binary_path, unsigned long func_offset);
    /*
     * member: attach_tracepoint
     * description: attach kprobe.
     * arg1: function name in bpf.c.
     * arg2: tp_category.
     * arg3: tp_name.
     * return: 0 if success.
     */
    int  (*attach_tracepoint)(const char* func, const char *tp_category, const char *tp_name);
    /*
     * member: attach_raw_tracepoint
     * description: attach kprobe.
     * arg1: function name in bpf.c.
     * arg2: tp_name.
     * return: 0 if success.
     */
    int  (*attach_raw_tracepoint)(const char* func, const char *tp_name);
    /*
     * member: attach_cgroup
     * description: attach cgroup.
     * arg1: function name in bpf.c.
     * arg2: cgroup_fd.
     * return: 0 if success.
     */
    int  (*attach_cgroup)(const char* func, int cgroup_fd);
    /*
     * member: attach_netns
     * description: attach netns.
     * arg1: function name in bpf.c.
     * arg2: netns.
     * return: 0 if success.
     */
    int  (*attach_netns)(const char* func, int netns);
    /*
     * member: attach_xdp
     * description: attach xdp.
     * arg1: function name in bpf.c.
     * arg2: ifindex.
     * return: 0 if success.
     */
    int  (*attach_xdp)(const char* func, int ifindex);
    const char* (*get_map_types)(void);
};


static inline int clcc_setup_syms(void* handle, struct clcc_struct *pclcc)
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
static inline struct clcc_struct* clcc_init(const char* so_path)
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
static inline void clcc_deinit(struct clcc_struct* pclcc)
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
static inline int clcc_get_call_stack(int table_id,
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

#endif
