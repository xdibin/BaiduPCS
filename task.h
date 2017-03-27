#ifndef __TASK_H
#define __TASK_H 1 

#include <stdint.h>

#include <curl/curl.h>
#include <curl/multi.h>

#include "task_db.h"

#ifndef TASK_BUFFER_SIZE
/* 缓冲块的默认大小，单位：字节 */
#define TASK_BUFFER_SIZE    (512 * 1024)
#endif

#ifndef TASK_BUFFER_CNT
/* 缓冲块总个数，所以总共缓冲区大小为 (TASK_BUFFER_SIZE * TASK_BUFFER_CNT) Bytes */
#define TASK_BUFFER_CNT     (16)
#endif

/* CFG文件的刷新时间间隔，单位秒 */
#define TASK_CFG_FLUSH_INTERVAL     (10)
/* CFG文件的刷新周期，下载的文件没增大这么多刷新，单位字节 */
#define TASK_CFG_FLUSH_INCR         (1 << 20)


#define TASK_FILE_TMP_EXT_NAME      ".tmp"

#define TASK_FILE_TMP_EXT_NAME_SIZE  (sizeof(TASK_FILE_TMP_EXT_NAME))


typedef enum task_status {
    TASK_STATUS_NONE = 0,
    TASK_STATUS_INIT = 1,
    TASK_STATUS_DOWNLOADING = 2,
    TASK_STATUS_COMPLETE =3 ,
    TASK_STATUS_PAUSE = 4,
    TASK_STATUS_STOP = 5,
    TASK_STATUS_REMOTE_ERROR = 6,
    TASK_STATUS_LOCAL_ERROR = 7,
    TASK_STATUS_NETWORK_ERROR = 8,    
} task_status_t;


enum task_subtask_type {
    SUBTASK_TYPE_NONE = 0,          /**< 错误类型 */
    SUBTASK_TYPE_ONE_LESS = 1,      /**< 有且仅有一片 */
    SUBTASK_TYPE_MID_LESS = 2,      /**< 有1-max片，且每片都小于min size */
    SUBTASK_TYPE_MAX_LARGE = 3     /**< 有max片，且每片都大于min size */
};


enum task_info_list_sort_order {
    TASK_INFO_LIST_SORT_ORDER_NONE = -1,
    TASK_INFO_LIST_SORT_ORDER_TIME,

    TASK_INFO_LIST_SORT_ORDER_MAX
};

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
    unsigned int subtask_id;        /**< 任务ID */
    CURL *curl;         /**< CURL句柄 */
    task_file_slice_t *file_slice;   /**< 该HTTP子任务操作哪个文件分片 */
    uint64_t download_size;
    task_status_t status;
    int http_code;
} task_sub_t;


#define SLICE_TABLE_START       0x80




struct task_cfg_head {
    char magic[4];                      /**< 魔数，必须为 XPCS */
    unsigned char version;              /**< 版本号，目前固定为 1 */
    unsigned char slice_cnt;            /**< 文件分片个数 */
    unsigned short slice_table_start;   /**< 文件分片表开始位置，分片结构为 task_file_slice_t 类型 */
    uint64_t total_size;                /**< 文件的总长度 */
    unsigned char md5[16];              /**< cfg文件的MD5，计算范围：文件头+分片表 */
} __attribute__((packed));

typedef struct task_cfg_head task_cfg_head_t;

typedef struct task {
    struct task *prev;      /**< 指向前一个任务 */
    struct task *next;      /**< 指向下一个任务 */

    unsigned int task_id;   /**< 任务的ID */
    char *url;              /**< 任务的URL地址 */
    char *rpath;            /**< 文件的远端地址 */
    char *lpath;            /**< 文件的本端地址 */
    char *lpath_tmp;        /**< 本地文件的临时文件名 */
    char *rmd5;             /**< 文件的远端MD5 */
    char *rcid;             /**< 文件的远端CID */

    uint64_t total_size;        /**< 文件总大小 */
    volatile uint64_t download_size;     /**< 文件已下载大小 */
    volatile task_status_t status;       /**< 任务的当前状态 */

    time_t start_ts;            /**< 任务开始时间 */
    volatile time_t download_ts;         /**< 任务下载总时间 */
    time_t complete_ts;         /**< 任务完成时间 */

    unsigned int tpid;          /**< Linux thread pid */
    void *tid;                  /**< pthread_t id */

    void *http_context;         /**< HttpContext上下文句柄 */
    
    CURLM *cm;              /*< CURLM句柄 */
    int subtask_cnt;        /**< CURL子任务个数 */
    task_sub_t *subtask;    /**< CURL子任务列表 */
    enum task_subtask_type subtask_type;
    task_file_t *file;      /**< 任务的文件句柄 */

    int buffer_cnt;         /**< 任务使用的缓冲区块数 */
    task_buffer_t *buffer;  /**< 任务使用的缓冲区列表 */

    char *cfg_name;         /**< 任务配置文件名 */
    task_mnt_t *mnt;        /**< 任务所在的磁盘分区引用 */

} task_t;

typedef struct task_list {
    task_t run;
    volatile int run_cnt;

    task_t done;
    int done_cnt;

    void *http_context;
    task_dev_t *dev;
    
    void *mutex;
} task_list_t;


typedef struct task_info_list {
    struct task_info_list *next;

    char *lpath;                /**< 任务的本地路径 */
    char *rpath;                /**< 任务的远程路径 */
    char *rmd5;                 /**< 任务的远程MD5 */

    uint64_t total_size;        /**< 文件总大小 */
    uint64_t download_size;     /**< 文件已下载大小 */
    task_status_t status;       /**< 任务的当前状态 */

    time_t start_ts;            /**< 任务开始时间 */
    time_t download_ts;         /**< 任务下载总时间 */
    time_t complete_ts;         /**< 任务完成时间 */  
} task_info_list_t;


int task_list_init(void *http_context);

int task_list_exit();

int task_add(void *context, char *rpath, char *rmd5, 
    uint64_t total_size, char *lpath);

int task_restore(void *context, char *rpath, char *rmd5, 
    uint64_t total_size, char *lpath, task_status_t status, unsigned int download_ts);

int task_info_run_list_get(task_info_list_t **list);

int task_info_list_free(task_info_list_t *list);

int task_info_list_sort(task_info_list_t **list, enum task_info_list_sort_order order, int ascending);

#endif

