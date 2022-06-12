#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "clcc.h"

#define TASK_COMM_LEN 16
struct data_t {
    unsigned int c_pid;
    unsigned int p_pid;
    char c_comm[TASK_COMM_LEN];
    char p_comm[TASK_COMM_LEN];
};

void event_cb(void *ctx, int cpu, void *data, unsigned int size){
    struct data_t *e = (struct data_t *)data;
    printf("poll message: c_pid:%d, p_pid:%d\n", e->c_pid, e->p_pid);
    printf("c_comm:%s, p_comm:%s\n", e->c_comm, e->p_comm);
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
    struct clcc_struct* pclcc = clcc_init("./event_out.so");

    if (pclcc == NULL) {
        printf("open so file failed.\n");
        exit(-1);
    }
    pclcc->init(-1);
    event_run(pclcc);

    pclcc->exit();
    clcc_deinit(pclcc);
    return 0;
}
