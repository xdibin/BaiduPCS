#ifndef __TASK_H
#define __TASK_H 1 

#include <stdint.h>

#include <curl/curl.h>
#include <curl/multi.h>

typedef enum task_status {
    TASK_STATUS_NONE,
    TASK_STATUS_INIT,
    TASK_STATUS_DOWNLOADING,
    TASK_STATUS_COMPLETE,
    TASK_STATUS_REMOTE_ERROR,
    TASK_STATUS_LOCAL_ERROR,
    TASK_STATUS_NETWORK_ERROR
} task_status_t;


#ifndef TASK_BUFFER_SIZE
/* 缓冲块的默认大小，单位：字节 */
#define TASK_BUFFER_SIZE    (512 * 1024)
#endif

#ifndef TASK_BUFFER_CNT
/* 缓冲块总个数，所以总共缓冲区大小为 (TASK_BUFFER_SIZE * TASK_BUFFER_CNT) Bytes */
#define TASK_BUFFER_CNT     (16)
#endif


typedef struct task_buffer {
    void *base;         /**< 缓冲基地址 */
    void *start;        /**< 缓冲开始地址（start >= base） */
    unsigned int length;    /**< 缓冲区目前保存的数据长度 */

    void *file_slice;   /**< 属于哪个文件分片 */
} task_buffer_t;

typedef struct task_file_slice {
    uint64_t offset_base;      /**< 文件分片基偏移位置 */
    uint64_t slice_size;       /**< 文件分片大小 */
    uint64_t offset_current;    /**< 文件分片当前偏移位置 */
} task_file_slice_t;

typedef struct task_file {
    int fd;             /**< 文件描述符，用于读写文件 */
    int slice_cnt;          /**< 文件分片个数 */
    task_file_slice_t *slices;  /**< 文件分片数组 */
} task_file_t;

struct task;

typedef struct task_sub {
    struct task *task;  /**< 回指向task的指针 */
    int task_id;        /**< 任务ID */
    CURL *curl;         /**< CURL句柄 */
    task_file_slice_t *file_slice;   /**< 该HTTP子任务操作哪个文件分片 */
    uint64_t download_size;
} task_sub_t;


enum task_subtask_type {
    SUBTASK_TYPE_NONE = 0,          /**< 错误类型 */
    SUBTASK_TYPE_ONE_LESS = 1,      /**< 有且仅有一片 */
    SUBTASK_TYPE_MID_LESS = 2,      /**< 有1-max片，且每片都小于min size */
    SUBTASK_TYPE_MAX_LARGE = 3     /**< 有max片，且每片都大于min size */
};

typedef struct task {
    struct task *prev;      /**< 指向前一个任务 */
    struct task *next;      /**< 指向下一个任务 */

    char *url;              /**< 任务的URL地址 */
    char *rpath;            /**< 文件的远端地址 */
    char *lpath;            /**< 文件的本端地址 */
    char *rmd5;             /**< 文件的远端MD5 */
    char *rcid;             /**< 文件的远端CID */

    uint64_t total_size;        /**< 文件总大小 */
    uint64_t download_size;     /**< 文件已下载大小 */
    task_status_t status;       /**< 任务的当前状态 */

    time_t start_ts;            /**< 任务开始时间 */
    time_t download_ts;         /**< 任务下载总时间 */
    time_t complete_ts;         /**< 任务完成时间 */
    time_t used_ts;             /**< 任务下载总用时 */

    unsigned int tid;           /**<  */

    void *http_context;         /**< HttpContext上下文句柄 */
    
    CURLM *cm;              /*< CURLM句柄 */
    int subtask_cnt;        /**< CURL子任务个数 */
    task_sub_t *subtask;    /**< CURL子任务列表 */
    enum task_subtask_type subtask_type;
    task_file_t *file;      /**< 任务的文件句柄 */

    int buffer_cnt;         /**< 任务使用的缓冲区块数 */
    task_buffer_t *buffer;  /**< 任务使用的缓冲区列表 */
} task_t;

typedef struct task_list {
    task_t run;
    int run_cnt;

    task_t done;
    int done_cnt;
    
    void *mutex;
} task_list_t;



int task_list_init();

int task_list_exit();

int task_add(void *context, char *rpath, char *rmd5, 
    uint64_t total_size, char *lpath);


#endif

