#ifndef __DOWNLOAD_H
#define __DOWNLOAD_H 1

#include <stdint.h>

enum download_task_status {
    DT_STATUS_NONE,
    DT_STATUS_INIT,
    DT_STATUS_DOWNLOADING,
    DT_STATUS_COMPLETE,
    DT_STATUS_REMOTE_ERROR,
    DT_STATUS_LOCAL_ERROR,
    DT_STATUS_NETWORK_ERROR
};



typedef struct download_task {
    char *lname;
    char *lpath;
    char *rpath;
    char *rmd5;
    char *rcid;

    uint64_t total_size;
    uint64_t download_size;
    enum download_task_status status;

    time_t start_ts;
    time_t complete_ts;
    time_t used_ts;

    unsigned int tid;

    void *http_context;
} download_task_t;

typedef struct download_entry {
    struct download_entry *prev;
    struct download_entry *next;    
    struct download_task *task;
} download_entry_t;

typedef struct download_list {
    void *mutex;
    struct download_entry head;
    unsigned int task_cnt;
} download_list_t;


int download_list_init();

int download_list_exit();

int download_task_add(void *context, char *rpath, char *rmd5, uint64_t total_size, char *lpath, char *lname);

int download_task_del(char *lpath);



#endif
