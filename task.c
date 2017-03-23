#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/select.h>

#include <pthread.h>

#include <syscall.h> //for syscall(SYS_gettid)

#include <curl/curl.h>
#include <curl/multi.h>

#include "pcs/pcs_mem.h"
#include "pcs/pcs_utils.h"
#include "task.h"
#include "error_code.h"
#include "http.h"
#include "pcs_log.h"

static task_list_t *g_task_list = NULL;



#define TASK_LOCK_SURE()    \
    do { \
        int _ret = pthread_mutex_lock((pthread_mutex_t *)(g_task_list->mutex)); \
        if (_ret != 0) { \
            printf("mutex lock failed, %s\n", strerror(_ret)); \
            return ERRCODE_SYSTEM; \
        } \
    } while(0)


#define TASK_UNLOCK_SURE()  \
    do { \
        int _ret = pthread_mutex_unlock((pthread_mutex_t *)(g_task_list->mutex)); \
        if (_ret != 0) { \
            printf("mutex unlock failed, %s\n", strerror(_ret)); \
            return ERRCODE_SYSTEM; \
        } \
    } while(0)



/**
 * @brief 初始化TASK子模块
 *
 */
int task_list_init()
{
    int ret = 0;

    pcs_log("task list init ...\n");

    task_list_t *list = (task_list_t *)pcs_malloc(sizeof(task_list_t));
    assert(list != NULL);

    memset(list, 0, sizeof(task_list_t));

    list->mutex = (pthread_mutex_t *)pcs_malloc(sizeof(pthread_mutex_t));
    assert(list->mutex != NULL);

    list->run.prev = &(list->run);
    list->run.next = &(list->run);
    list->run_cnt = 0;

    list->done.prev = &(list->done);
    list->done.next = &(list->done);
    list->done_cnt = 0;    

    ret = pthread_mutex_init(list->mutex, NULL);
    if (ret != 0) {
        printf("pthread mutex init failed, %s\n", strerror(ret));
        pcs_free(list->mutex);
        pcs_free(list);
        return ERRCODE_SYSTEM;
    }

    g_task_list = list;

    return 0;
}

/**
 * @brief 去初始化TASK子模块
 *
 */
int task_list_exit()
{
    //TODO: 
    pcs_log("task list exit ...\n");

     return 0;
}

static int task_subtask_slice(task_t *task)
{
    struct HttpContext *context = (struct HttpContext *)(task->http_context);

    if (task->total_size <= context->file_slice_size_min) {
        task->subtask_cnt = 1;
        task->subtask_type = SUBTASK_TYPE_ONE_LESS;     
    } else if ( task->total_size >= (context->file_slice_size_min * context->subtask_max) ) {
        /* 最多分 subtask_max 片，且每片大于 file_slice_size_min */
        task->subtask_cnt = context->subtask_max;
        task->subtask_type = SUBTASK_TYPE_MAX_LARGE;
    } else {
        /* 每片小于  file_slice_size_min */
        task->subtask_cnt = task->total_size / context->file_slice_size_min;
        if (task->total_size % context->file_slice_size_min) {
            task->subtask_cnt++;
        }
        task->subtask_type = SUBTASK_TYPE_MID_LESS;
    }

    return task->subtask_cnt;
}


static int task_url_build(task_t *task)
{
    struct HttpContext *context = (struct HttpContext *)task->http_context;

    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        pcs_log("init curl failed\n");
        return -1;
    }

    char *url = (char *)pcs_malloc(URL_SIZE_MAX);
    if (!url) {
        pcs_log("malloc for url failed\n");
        curl_easy_cleanup(curl);
        return -1;
    }

    memset(url, 0, URL_SIZE_MAX);

    snprintf(url, URL_SIZE_MAX - 1,
        "http://c.pcs.baidu.com/rest/2.0/pcs/file?method=download&app_id=250528&gid=%s&path=", context->gid);

    int len = strlen(url);
    char *str = curl_easy_escape(curl, task->rpath, strlen(task->rpath));
    
    if (!str) {
        pcs_log("curl_easy_escape failed, %s\n", task->rpath);
        pcs_free(url);
        curl_easy_cleanup(curl);
        return -1;
    }

    strncpy(url + len, str, URL_SIZE_MAX - len - 1);

    curl_free(str);
    
    task->url = url;
    
    curl_easy_cleanup(curl);

    return 0;
}


static int task_init_memory(task_t *task)
{
    int subtask_cnt = task->subtask_cnt;

    pcs_log("init task memory\n");

    task->subtask = (task_sub_t *)pcs_malloc(sizeof(task_sub_t) * subtask_cnt);
    if (task->subtask == NULL) {
        return -1;        
    }
    memset(task->subtask, 0, sizeof(task_sub_t) * subtask_cnt);   

    /* 初始化文件和文件分片 */
    task->file = (task_file_t *)pcs_malloc(sizeof(task_file_t));
    if (task->file == NULL) {
        return -1;  
    }
    memset(task->file, 0, sizeof(task_file_t));
    task->file->slice_cnt = subtask_cnt;

    task->file->slices = (task_file_slice_t *)pcs_malloc(sizeof(task_file_slice_t) * subtask_cnt);
    if (task->file->slices == NULL) {
        return -1;         
    }
    memset(task->file->slices, 0, sizeof(task_file_slice_t) * subtask_cnt);

    return 0;
}

static int task_init_file(task_t *task)
{
    int subtask_cnt = task->subtask_cnt;
    task_file_t *file = task->file;
    int i = 0;
    uint64_t offset = 0;
    int err = 0;
    int ret = 0;

    pcs_log("init task file structure\n");

    if (task->subtask_type == SUBTASK_TYPE_ONE_LESS) {
        /* 有且仅有一片 */
        file->slices[0].offset_base = 0;
        file->slices[0].slice_size = task->total_size;
        file->slices[0].offset_current = 0;
    } else if (task->subtask_type == SUBTASK_TYPE_MID_LESS || SUBTASK_TYPE_MAX_LARGE) {
        offset = 0;
        i = 0;
        uint64_t size = task->total_size / subtask_cnt;
        /* 前 subtask_cnt - 1 个，每个大小为 total_size / subtask_cnt */
        for (i = 0; i < subtask_cnt - 1; i++) {
            file->slices[i].offset_base = offset;
            file->slices[i].slice_size = size;
            file->slices[i].offset_current = offset;
            offset += size;
        }
        /* 最后一片 */                   
        file->slices[i].offset_base = offset;
        file->slices[i].slice_size = task->total_size - offset;
        file->slices[i].offset_current = offset;        
    }

    printf("%4s %16s %16s\n", "task", "offset", "size");
    printf("%4s %16s %16s\n", "----", "---------------", "---------------");
    for (i = 0; i < subtask_cnt; i++) {
        printf("%4d %16llu %16llu\n", 
            i, 
            (unsigned long long)(file->slices[i].offset_base), 
            (unsigned long long)(file->slices[i].slice_size));
    }
    printf("%4s %16s %16s\n", "----", "---------------", "---------------");

    /* open the file for writing */
    /**
     * 是否有必要将普通文件设置为非阻塞模式？
     * 网上的说法是没必要，因为普通文件任何时候都是可读可写的
     * https://www.remlab.net/op/nonblock.shtml
     */
    task->file->fd = open(task->lpath, 
        O_RDWR | O_CLOEXEC | O_CREAT /*| O_NONBLOCK*/, 
        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    if (task->file->fd == -1) {
        err = errno;
        printf("open file failed, %s, %s\n", task->lpath, strerror(err));
        return -1;
    }

    /* allocate the disk space */
    ret = posix_fallocate(task->file->fd, 0, task->total_size);
    if (ret != 0) {
        pcs_log("posix_fallocate failed, %s\n", strerror(ret));
    }

    printf("create file fd = %d\n", task->file->fd);

    return 0;
}

static size_t task_head_recv_callback(char *buffer, size_t size, size_t nmemb, void *userp)
{
    size_t recv_size = size * nmemb;
    task_sub_t *subtask = (task_sub_t *)userp;

    //pcs_log("recv http head\n");

    assert(subtask != NULL);

    if (subtask->status == TASK_STATUS_DOWNLOADING) {
        return recv_size;
    }

    /* 分析HTTP响应头 
     * HTTP状态码必须是 2xx，如：
     * 200 OK
     * 206 Partial Content
     */
     char line[128];
     char *ptr = line;
     char *end = line + sizeof(line) - 2;
     char *start = NULL;
     int http_code = 0;

     memset(line, 0, sizeof(line));

     memcpy(line, buffer, sizeof(line) - 2);

     if (memcmp(line, "HTTP/1.1", 8) != 0) {
         pcs_log("not HTTP/1.1 protocol, %s\n", line);
         return 0;
     }
     ptr += 8;

     /* 忽略空格 */
     while (ptr < end && *ptr == ' ') ptr++;
     if (ptr >= end) return 0;

     start = ptr;

     /* 找HTTP状态码 */
     while (ptr < end && *ptr != ' ') ptr++;     
     if (ptr >= end) return 0;

     if (ptr == start) {
         /* 没有找到任何状态码 */
         return 0;
     }

     *ptr = '\0';
     ptr++;

     /* 转换状态码 */
     http_code = atoi(start);

     if (http_code < 200 || http_code >= 300) {
         /* 服务器返回出错了，为了得到服务器返回的数据，还是要让curl继续收数据，然后在write callback中处理错误 */
         pcs_log("server response error, http code %d\n", http_code);
         subtask->status = TASK_STATUS_REMOTE_ERROR;         
     } else {
         subtask->status = TASK_STATUS_DOWNLOADING;
     }

     subtask->http_code = http_code;

     pcs_log("http code is %d\n", http_code);

    return recv_size;
}

static size_t task_file_write_callback(char *buffer, size_t size, size_t nmemb, void *userp)
{
    //pcs_log("task_file_write_callback called, buffer %p, size = %u, nmemb = %u\n", buffer, (unsigned int)size, (unsigned int)nmemb);

    assert(userp != NULL);

    int err = 0;
    ssize_t ret;
    task_sub_t *subtask = (task_sub_t *)userp;
    
    assert(subtask != NULL);

    task_t *task = subtask->task;
    
    assert(task != NULL);    

    task_file_t *file = task->file;
    task_file_slice_t *slice = subtask->file_slice;

    size_t recv_size = size * nmemb;

    if (subtask->status != TASK_STATUS_DOWNLOADING) {
        char err_msg[1024];
        memset(err_msg, 0, sizeof(err_msg));
        strncpy(err_msg, buffer, (recv_size < sizeof(err_msg) - 2 ? recv_size : sizeof(err_msg) - 2));
        pcs_log("server response error message is : %s\n", err_msg);
        return 0;
    }

    subtask->download_size += recv_size;
    
    //pcs_log("file fd = %d, offset = %llu, recv size = %u\n", 
    //    file->fd, (unsigned long long)(slice->offset_current), (unsigned int)recv_size);

    /* 修改文件指针位置 */
    if (lseek(file->fd, slice->offset_current, SEEK_SET) == -1) {
        err = errno;
        pcs_log("lseek failed, %s %s\n", task->lpath, strerror(err));
        return 0; // return 0 to terminate the curl transform
    }

    /* 写入数据到文件 */
    ret = write(file->fd, buffer, recv_size);
    if (ret == -1) {
        err = errno;
        pcs_log("write to file failed, %s, fd %d, %s\n", task->lpath, file->fd, strerror(err));
        return 0;
    }

    if (ret != recv_size) {
        pcs_log("write truncated, expect %u, but only %u\n", (unsigned int)recv_size, (unsigned int)ret);
        return 0;
    }

    slice->offset_current += recv_size;
    task->download_size += recv_size;

    return recv_size;
}

#if 0
static int task_cookie_clone(task_t *task, CURL *curl)
{
    CURL *curl_ref = NULL;
    struct HttpContext *context = (struct HttpContext *)(task->http_context);
    CURLcode rc;
    struct curl_slist *cookies;
    struct curl_slist *nc;

    curl_ref = (CURL *)pcs_curl_ref_get(context->pcs);

    if (!curl_ref) {
        return -1;
    }
    
    rc = curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies);
    if(rc != CURLE_OK || cookies == NULL) {
        return -1;
    }

    for (nc = cookies; nc; nc = nc->next) {
        rc = curl_easy_setopt(curl, CURLOPT_COOKIELIST, nc->data);
        if (rc != CURLE_OK) {
            pcs_log("add cookie failed, [%s]\n", nc->data);
        }
    }

    curl_slist_free_all(cookies);

    return 0;
}
#endif

static int task_init_curl(task_t *task)
{
    int subtask_cnt = task->subtask_cnt;
    struct HttpContext *context = (struct HttpContext *)(task->http_context);   

    uint64_t offset = 0;
    CURL *curl = NULL;
    int i = 0;
    char range[128];

    CURLcode rc;
    CURL *curl_ref = NULL;
    struct curl_slist *cookies;
    struct curl_slist *nc;   

    pcs_log("init task curls\n");

    /* 计算请求url */
    if ( task_url_build(task) != 0) {
        return -1;
    }

    pcs_log("task url is %s\n", task->url);
    pcs_log("cookie file is '%s'\n", context->cookiefile);    

    curl_ref = (CURL *)pcs_curl_ref_get(context->pcs);

    if (!curl_ref) {
        pcs_log("get curl handle failed\n");
        assert(0);
    }
    
    rc = curl_easy_getinfo(curl_ref, CURLINFO_COOKIELIST, &cookies);
    if(rc != CURLE_OK || cookies == NULL) {
        pcs_log("get cookie failed\n");
    } 

    task->cm = curl_multi_init();
    if (task->cm == NULL) {
        pcs_log("curl_multi_init failed\n");
        return -1;
    }

    //curl_multi_setopt(cm, CURLMOPT_MAXCONNECTS, (long)subtask_cnt);

    offset = 0;
    for (i = 0; i < subtask_cnt; i++) {
        task->subtask[i].task = task;
        task->subtask[i].task_id = i;
        task->subtask[i].file_slice = task->file->slices + i;

        curl = curl_easy_init();
        if (curl == NULL) {
            pcs_log("init curl %d failed\n", i);
            return -1;
        }
        
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, task_head_recv_callback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, task->subtask + i);
        
        curl_easy_setopt(curl, CURLOPT_HEADER, 0L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, task_file_write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, task->subtask + i);
        
        curl_easy_setopt(curl, CURLOPT_URL, task->url);
        //curl_easy_setopt(curl, CURLOPT_PRIVATE, NULL);
                        
        snprintf(range, sizeof(range) - 1, "%llu-%llu", 
            (unsigned long long)offset, (unsigned long long)(offset + task->subtask[i].file_slice->slice_size - 1));
        
        printf("set subtask %d range, %s\n", i, range);

        offset += task->subtask[i].file_slice->slice_size;
        curl_easy_setopt(curl, CURLOPT_RANGE, range);

        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        //curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1024L);
        //curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 60L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, context->user_agent);        
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_REFERER, "https://pan.baidu.com/");
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, HTTP_CONNECT_TIMEOUT);
	    //curl_easy_setopt(curl, CURLOPT_TIMEOUT, HTTP_TIMEOUT);

        //curl_easy_setopt(curl, CURLOPT_COOKIEFILE, context->cookiefile);
        //curl_easy_setopt(curl, CURLOPT_COOKIEJAR, context->cookiefile);

        /* add cookies */
        for (nc = cookies; nc; nc = nc->next) {
            rc = curl_easy_setopt(curl, CURLOPT_COOKIELIST, nc->data);
            if (rc != CURLE_OK) {
                pcs_log("add cookie failed, [%s]\n", nc->data);
            }
        }
               
        task->subtask[i].curl = curl;
        curl_multi_add_handle(task->cm, task->subtask[i].curl);
    }

    curl_slist_free_all(cookies);

    return 0;
}


static int task_init(task_t *task)
{
    int ret = 0;
    int i = 0;
    int subtask_cnt = 0;

    pcs_log("init task\n");

    task->tpid = syscall(SYS_gettid);

    /* get the subtask count */   
    subtask_cnt = task_subtask_slice(task);
    
    if (task_init_memory(task) != 0) {
        ret = ERRCODE_MEMORY;
        goto init_failed;
    }

    if ((ret = task_init_file(task)) != 0) {
        goto init_failed;
    }    

    if ((ret = task_init_curl(task)) != 0) {
        goto init_failed;
    }

    return 0;

init_failed:
    if (task->url) {
        pcs_free(task->url);
        task->url = NULL;
    }

    if (task->file) {
        if (task->file->slices) {
            pcs_free(task->file->slices);
            task->file->slices = NULL;
        }
        pcs_free(task->file);
        task->file = NULL;
    }

    if (task->subtask) {
        for (i = 0; i < subtask_cnt; i++) {
            if (task->subtask[i].curl) {
                if (task->cm) {
                    curl_multi_remove_handle(task->cm, task->subtask[i].curl);
                }
                curl_easy_cleanup(task->subtask[i].curl);
                task->subtask[i].curl = NULL;
            }
        }
        pcs_free(task->subtask);
        task->subtask = NULL;
    }

    if (task->cm) {
        curl_multi_cleanup(task->cm);
        task->cm = NULL;
    }

    return ret;
}


static void task_summary_show(task_t *task)
{
    char time_str[128];

    unsigned int speed = task->download_size / task->download_ts;

    printf("\ntask summary:\n");
    printf("pthread pid      : %u\n", task->tpid);
    printf("file name        : %s\n", task->lpath);
    printf("total size       : %llu\n", (unsigned long long)(task->total_size));
    printf("download size    : %llu\n", (unsigned long long)(task->download_size));
    printf("server file md5  : %s\n", task->rmd5);
    printf("start time       : %s", ctime_r(&(task->start_ts), time_str));
    printf("stop time        : %s", ctime_r(&(task->complete_ts), time_str));
    printf("download time    : %u\n", (unsigned int)(task->download_ts));
    printf("download speed   : %u Bytes/s, %.3f KB/s, %.3f MB/s\n", 
        speed, ((double)speed) / 1024, ((double)speed) / (1024 * 1024));

    int i;
    printf("\n%4s  %16s\n", "task", "download size");
    printf("----  ----------------\n");
    for (i = 0; i < task->subtask_cnt; i++) {
        printf("%4d  %16llu\n", i, (unsigned long long)(task->subtask[i].download_size));
    }
    printf("----  ----------------\n");    
}


static int task_exit(task_t *task)
{
    pcs_log("task exit\n");

    if (!task) {
        return -1;
    }

    task_summary_show(task);    

    if (task->url) {
        pcs_free(task->url);
        task->url = NULL;
    }

    if (task->rpath) {
        pcs_free(task->rpath);
        task->rpath = NULL;
    }

    if (task->lpath) {
        pcs_free(task->lpath);
        task->lpath = NULL;
    }

    if (task->rmd5) {
        pcs_free(task->rmd5);
        task->rmd5 = NULL;
    }

    if (task->rcid) {
        pcs_free(task->rcid);
        task->rcid = NULL;
    }

    if (task->file) {
        if (task->file->slices) {
            pcs_free(task->file->slices);
            task->file->slices = NULL;
        }
        pcs_free(task->file);
        task->file = NULL;
    }

    if (task->subtask) {
        int i = 0;
        for (i = 0; i < task->subtask_cnt; i++) {
            if (task->subtask[i].curl) {
                if (task->cm) {
                    curl_multi_remove_handle(task->cm, task->subtask[i].curl);
                }
                curl_easy_setopt(task->subtask[i].curl, CURLOPT_COOKIELIST, "ALL"); //清除下载子任务的cookie，以免多线程写cookie文件
                curl_easy_cleanup(task->subtask[i].curl);
                task->subtask[i].curl = NULL;
            }
        }
        pcs_free(task->subtask);
        task->subtask = NULL;
    }

    if (task->cm) {
        curl_multi_cleanup(task->cm);
        task->cm = NULL;
    }

    if (task->buffer) {
        pcs_free(task->buffer);
        task->buffer = NULL;
    }

    TASK_LOCK_SURE();

    task->prev->next = task->next;
    task->next->prev = task->prev;

    g_task_list->run_cnt--;

    TASK_UNLOCK_SURE();

    return 0;
}

static void task_result_check(task_t *task)
{
#if 0    
    struct CURLMsg *m = NULL;
    CURL *e = NULL;
    int msgq = 0;
    int i = 0;

    do {        
        m = curl_multi_info_read(task->cm, &msgq);
        if(m && (m->msg == CURLMSG_DONE)) {
            e = m->easy_handle;
            
            for (i = 0; i < task->subtask_cnt; i++) {
                if (e == task->subtask[i].curl) {
                    /* get curl info, see https://curl.haxx.se/libcurl/c/curl_easy_getinfo.html */              
                    //curl_easy_getinfo(e, CURLINFO_XXX, );
                    break;
                }
            }

        }
    } while(m);
#endif
}

static int task_loop(task_t *task)
{
    int still_running = 0;
    struct timeval timeout;
    int rc;
    CURLMcode mc;
 
    fd_set fdread;
    fd_set fdwrite;
    fd_set fdexcep;
    int maxfd = -1;

    long curl_timeout = -1;

    time_t ts_1;
    time_t ts_2;

    time(&ts_1);

    pcs_log("task loop ...\n");

    do {

        /* we start some action by calling perform right away */ 
        curl_multi_perform(task->cm, &still_running);

        curl_timeout = -1;

        FD_ZERO(&fdread);
        FD_ZERO(&fdwrite);
        FD_ZERO(&fdexcep);
        
        /* default timeout value */
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        curl_multi_timeout(task->cm, &curl_timeout);
        if(curl_timeout > 0) {
            timeout.tv_sec = curl_timeout / 1000;
            if(timeout.tv_sec > 1) {
                timeout.tv_sec = 1;
            } else {
                timeout.tv_usec = (curl_timeout % 1000) * 1000;
            }
        }
    
        /* get file descriptors from the transfers */ 
        mc = curl_multi_fdset(task->cm, &fdread, &fdwrite, &fdexcep, &maxfd);
    
        if(mc != CURLM_OK) {
            pcs_log("curl_multi_fdset() failed, code %d.\n", mc);
            break;
        }

        if(maxfd == -1) {
            struct timeval wait = { 0, 100 * 1000 }; /* 100ms */ 
            rc = select(0, NULL, NULL, NULL, &wait);
        } else {
            rc = select(maxfd + 1, &fdread, &fdwrite, &fdexcep, &timeout);
        }

        switch(rc) {
        case -1:
            /* select error */ 
            break;
        case 0: /* timeout */ 
        default: /* action */ 
            curl_multi_perform(task->cm, &still_running);
            break;
        }
    } while (still_running);

    time(&ts_2);
    
    task->complete_ts = ts_2;

    task->download_ts += (ts_2 - ts_1);
    
    task_result_check(task);

    return 0;
}


static void *task_thread(void *param)
{
    task_t *task = (task_t *)param;
    int ret = 0;

    printf("task thread running: rpath = %s, lpath = %s\n", task->rpath, task->lpath);
    
    ret = task_init(task);
    if (ret != 0) {
        printf("init task failed, error code = %d\n", ret);
        return NULL;
    }

    task_loop(task);

    task_exit(task);

    return NULL;
}


static int task_thread_start(task_t *task)
{
    pthread_t tid;
    pthread_attr_t attr;
    int ret;
    
    ret = pthread_attr_init(&attr);
    if (ret != 0) {
        printf("pthread_attr_init failed, %s\n", strerror(ret));
        return ERRCODE_SYSTEM;
    }

    ret = pthread_create(&tid, &attr, task_thread, task);

    pthread_attr_destroy(&attr);

    if (ret != 0) {
        printf("pthread_create failed, %s\n", strerror(ret));
        return ERRCODE_SYSTEM;
    }

    return 0;
}



/**
 * @brief 添加一个任务
 *
 */
int task_add(void *context, char *rpath, char *rmd5, 
    uint64_t total_size, char *lpath)
{

    printf("%s %d %s : add task rpath %s, rmd5 %s, size %llu, lpath %s\n", __FILE__, __LINE__, __FUNCTION__,
        rpath, rmd5, (unsigned long long)total_size, lpath);

    TASK_LOCK_SURE();

    /* look whether task exist ? */
    task_t *task = g_task_list->run.next;

    while (task != &(g_task_list->run)) {
        if (strcmp(task->lpath, lpath) == 0 ||
            strcmp(task->rpath, rpath) == 0) {
            /* duplicate task */
            printf("duplicate task, %s %s\n", rpath, lpath);
            TASK_UNLOCK_SURE();
            return ERRCODE_TASK_EXIST;
        }

        task = task->next;
    }

    task = (task_t *)pcs_malloc(sizeof(task_t));
    if (!task) {
        TASK_UNLOCK_SURE();
        return ERRCODE_MEMORY;
    }

    memset(task, 0, sizeof(task_t));

    task->lpath = pcs_utils_strdup(lpath);
    task->rpath = pcs_utils_strdup(rpath);
    task->rmd5 = pcs_utils_strdup(rmd5);
    task->total_size = total_size;
    task->status = TASK_STATUS_INIT;
    time(&(task->start_ts));
    task->http_context = context;

    task->prev = g_task_list->run.prev;
    task->next = &(g_task_list->run);
    g_task_list->run.prev->next = task;
    g_task_list->run.prev = task;

    g_task_list->run_cnt++;

    TASK_UNLOCK_SURE();

    /* start a thread to download */
    return task_thread_start(task);
}






/**
 * @brief 删除一个任务
 *
 */
int task_del()
{

     return 0;
}

/**
 * @brief 暂停一个任务
 *
 */
int task_pause()
{
  
     return 0;
}

/**
 * @brief 恢复一个任务
 *
 */
int task_resume()
{

     return 0;
}

/**
 * @brief 查看任务列表
 *
 */
task_t *task_list()
{
    task_t *list = NULL;

    return list;
}



