#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <pthread.h>

#include "pcs_mem.h"
#include "pcs_utils.h"
#include "pcs_fileinfo.h"
#include "error_code.h"
#include "download.h"


static struct download_list *g_download_list = NULL;
static int g_download_exit = 0;


#define DOWNLOAD_LOCK_SURE()    \
    do { \
        int _ret = pthread_mutex_lock((pthread_mutex_t *)(g_download_list->mutex)); \
        if (_ret != 0) { \
            printf("mutex lock failed, %s\n", strerror(_ret)); \
            return ERRCODE_SYSTEM; \
        } \
    } while(0)


#define DOWNLOAD_UNLOCK_SURE()  \
    do { \
        int _ret = pthread_mutex_unlock((pthread_mutex_t *)(g_download_list->mutex)); \
        if (_ret != 0) { \
            printf("mutex unlock failed, %s\n", strerror(_ret)); \
            return ERRCODE_SYSTEM; \
        } \
    } while(0)


int download_list_init()
{
    struct download_list *list = NULL;
    int ret;

    list = (struct download_list *)pcs_malloc(sizeof(struct download_list));
    if (!list) {
        return ERRCODE_MEMORY;
    }
    memset(list, 0, sizeof(struct download_list));

    list->head.prev = &(list->head);
    list->head.next = &(list->head);

    list->mutex = (pthread_mutex_t *)pcs_malloc(sizeof(pthread_mutex_t));
    if (list->mutex == NULL) {
        pcs_free(list);
        return ERRCODE_MEMORY;
    }

    if ((ret = pthread_mutex_init(list->mutex, NULL)) != 0) {
        printf("mutex init failed, %s\n", strerror(ret));
        pcs_free(list->mutex);
        pcs_free(list);
        return ERRCODE_SYSTEM;
    }

    g_download_list = list;

    return 0;    
}

int download_list_exit()
{
    if (!g_download_list) {
        return 0;
    }

    struct download_entry *entry = g_download_list->head.next;
    struct download_entry *next_entry = NULL;
    struct download_task *task = NULL;

    while (entry != &(g_download_list->head)) {
        task = entry->task;

        if (task->lname) pcs_free(task->lname);
        if (task->lpath) pcs_free(task->lpath);
        if (task->rpath) pcs_free(task->rpath);
        if (task->rmd5) pcs_free(task->rmd5);
        if (task->rcid) pcs_free(task->rcid);

        pcs_free(task);

        next_entry = entry->next;
        pcs_free(entry);
        entry = next_entry;
    }

    pthread_mutex_destroy((pthread_mutex_t *)(g_download_list->mutex));

    pcs_free(g_download_list->mutex);

    pcs_free(g_download_list);

    g_download_list = NULL;

    return 0;
}



static void *download_thread(void *param)
{
    struct download_task *task = (struct download_task *)param;
    struct HttpContext *context = (struct HttpContext *)(task->http_context);

    return NULL;
}


static int download_thread_start(struct download_task *task)
{
    pthread_t tid;
    pthread_attr_t attr;
    int ret;
    
    ret = pthread_attr_init(&attr);
    if (ret != 0) {
        printf("pthread_attr_init failed, %s\n", strerror(ret));
        return ERRCODE_SYSTEM;
    }

    ret = pthread_create(&tid, &attr, download_thread, task);

    pthread_attr_destroy(&attr);

    if (ret != 0) {
        printf("pthread_create failed, %s\n", strerror(ret));
        return ERRCODE_SYSTEM;
    }

    return 0;
}




int download_task_add(void *context, char *rpath, char *rmd5, 
    uint64_t total_size, char *lpath, char *lname)
{
    int ret = 0;

    DOWNLOAD_LOCK_SURE();

    /* look whether task exist ? */
    struct download_entry *entry = g_download_list->head.next;
    struct download_task *task = NULL;

    while (entry != &(g_download_list->head)) {
        task = entry->task;

        if (strcmp(task->lpath, lpath) == 0 ||
            strcmp(task->rpath, rpath) == 0) {
            /* duplicate task */
            printf("duplicate task, %s %s\n", rpath, lpath);
            DOWNLOAD_UNLOCK_SURE();
            return ERRCODE_TASK_EXIST;
        }

        entry = entry->next;
    }

    entry = (struct download_entry *)pcs_malloc(sizeof(struct download_entry));
    if (!entry) {
        DOWNLOAD_UNLOCK_SURE();
        return ERRCODE_MEMORY;
    }

    memset(entry, 0, sizeof(struct download_entry));

    task = (struct download_task *)pcs_malloc(sizeof(struct download_task));
    if (!task) {
        pcs_free(entry);
        DOWNLOAD_UNLOCK_SURE();
        return ERRCODE_MEMORY;       
    }

    task->lname = pcs_utils_strdup(lname);
    task->lpath = pcs_utils_strdup(lpath);
    task->rpath = pcs_utils_strdup(rpath);
    task->rmd5 = pcs_utils_strdup(rmd5);
    task->total_size = total_size;
    task->status = DT_STATUS_INIT;
    time(&(task->start_ts));
    task->http_context = context;

    entry->task = task;

    entry->prev = g_download_list->head.prev;
    entry->next = &(g_download_list->head);
    g_download_list->head.prev->next = entry;
    g_download_list->head.prev = entry;

    g_download_list->task_cnt++;

    DOWNLOAD_UNLOCK_SURE();

    /* start a thread to download */
    download_thread_start(task);

    return 0;
}

int download_task_del(char *lpath);
