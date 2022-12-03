#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "clcc.h"
#include "ksyms.h"

#define TASK_COMM_LEN 16
struct data_t {
    unsigned int c_pid;
    unsigned int p_pid;
    char c_comm[TASK_COMM_LEN];
    char p_comm[TASK_COMM_LEN];
    unsigned int stack_id;
};
struct clcc_struct* gclcc = NULL;

void event_cb(void *ctx, int cpu, void *data, unsigned int size){
    struct data_t *e = (struct data_t *)data;
    struct clcc_call_stack stack;
    int table_id = gclcc->get_maps_id("call_stack");

    printf("poll message: c_pid:%d, p_pid:%d, stack_id:%d\n", e->c_pid, e->p_pid, e->stack_id);
    printf("c_comm:%s, p_comm:%s\n", e->c_comm, e->p_comm);

    if (table_id >= 0 && !clcc_get_call_stack(table_id, e->stack_id, &stack, gclcc)) {
        printf("call stack:\n");
        ksym_shows(&stack);
    }
}

void event_run(struct clcc_struct* pclcc) {
    int event_id;

    event_id = pclcc->get_maps_id("e_out");
    if (event_id < 0) {
        return;
    }

    pclcc->set_event_cb(event_id, event_cb, NULL);
    pclcc->event_loop(event_id, -1);
}

int main(int argc,char *argv[]) {
    int res;
    struct clcc_struct* pclcc = clcc_init("./"SO_NAME);

    if (pclcc == NULL) {
        printf("open so file failed.\n");
        exit(-1);
    }

    res = ksym_load();
    if (res != 0) {
        printf("setup kallsyms failed.\n");
        exit(-1);
    }

    pclcc->init(-1, 1);
    gclcc = pclcc;
    event_run(pclcc);

    pclcc->exit();
    ksym_deinit();
    clcc_deinit(pclcc);
    return 0;
}
