#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
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
        printf("get %s map id failed.\n", "e_out");
        return;
    }

    pclcc->set_event_cb(event_id, event_cb, NULL);
    pclcc->event_loop(event_id, 10);
}

static void report(struct clcc_struct* pclcc) {
    int hash_id;
    unsigned int pid = 0, pid_next;
    unsigned int cnt;

    hash_id = pclcc->get_maps_id("pid_cnt");
    if (hash_id < 0) {
        printf("get %s map id failed.\n", "pid_cnt");
        return;
    }

    while (!pclcc->map_get_next_key(hash_id, &pid, &pid_next)) {
        pclcc->map_lookup_elem(hash_id, &pid_next, &cnt);
        printf("pid: %d, count: %d\n", pid, cnt);
        pid = pid_next;
    }
}

static void stop(int signo){
    printf("signal.\n");
}

int main(int argc,char *argv[]) {
    struct clcc_struct* pclcc = clcc_init("./hash_map.so");

    if (pclcc == NULL) {
        printf("open so file failed.\n");
        exit(-1);
    }

    signal(SIGINT, stop);
    pclcc->init(-1);
    printf("The program starts executing and will exit after 10 seconds.\n");
    event_run(pclcc);

    printf("report:\n");
    report(pclcc);

    pclcc->exit();
    clcc_deinit(pclcc);
    return 0;
}
