#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "sqlite3.h"

#include "pcs/pcs_mem.h"
#include "pcs/pcs_utils.h"
#include "pcs_log.h"
#include "task.h"
#include "task_db.h"



#define TASK_DB_CREATE_SQL  \
    "CREATE TABLE IF NOT EXISTS task (" \
    "lpath TEXT NOT NULL UNIQUE," \
    "rpath TEXT NOT NULL," \
    "size INTEGER NOT NULL," \
    "rmd5 TEXT NOT NULL," \
    "rcid TEXT," \
    "start_ts INTEGER DEFAULT 0," \
    "complete_ts INTEGER DEFAULT 0," \
    "download_ts INTEGER DEFAULT 0," \
    "download_size INTEGER DEFAULT 0," \
    "status INTEGER NOT NULL" \
    ")"




struct volume_dev_node {
    char *node_name;
    unsigned int node_len;
};


//TODO: 修改为系统挂载硬盘节点
const struct volume_dev_node g_dev_nodes[] = {
    { "/dev/", 5 },
    { NULL, 0 } /* make sure this is the last */
};


static char *next_line(char *str)
{
	char *ptr = str;
	
	while (*ptr && *ptr != '\n') ptr++;

	ptr++;

	if (*ptr == '\0') {
		return NULL;
	} else {
		return ptr;
	}
}

static int task_mnt_init(task_mnt_t **mnt)
{
    FILE *fp = NULL;
	char *buff = NULL;
	int ret = -1;
	char *ptr;
	char *start;
	int i;
	int volume_cnt = 0;
    int buff_size = 1 << 20;
    const struct volume_dev_node *node = NULL;

    task_mnt_t volumes[TASK_MNT_MAX];

    pcs_log("init mnt point ...\n");

    buff = pcs_malloc(buff_size); 
    if (!buff) {
        pcs_log("malloc failed\n");
        return -1;
    }

    memset(buff, 0, buff_size);

	if ((fp = fopen("/proc/mounts", "r")) == NULL) {
        pcs_free(buff);
		return -1;
	}

	if ((ret = fread(buff, 1, buff_size - 1, fp)) <= 0) {
		fclose(fp);
        pcs_free(buff);
		return -1;
	}
	fclose(fp);

	//pcs_log("/proc/mounts = [%s]\n", buff);

	ptr = buff;
	/* parse the data, get all "/dev/sda sdb sdc etc." */
	for(i = 0; i < TASK_MNT_MAX; ) {
        for (node = g_dev_nodes; node->node_name; node++ ) {
            if (strncmp(ptr, node->node_name, node->node_len) == 0) {
                /* get the full device name */
                start = ptr;
                while (*ptr && *ptr != ' ') ptr++;
                *ptr = '\0';
                volumes[i].dev = pcs_utils_strdup(start);
                *ptr = ' ';

                /* get the mount point */
                start = ++ptr;
                while (*ptr && *ptr != ' ') ptr++;
                *ptr = '\0';
                volumes[i].mnt = pcs_malloc(ptr - start + 2);

                assert(volumes[i].mnt != NULL);

                snprintf(volumes[i].mnt, ptr - start + 2, "%s/", start);                

                *ptr = ' ';

                i++;
                volume_cnt++;
            }
        }
        
		ptr = next_line(ptr);
		if (ptr == NULL) {
			break;
		}
	}

    pcs_free(buff);

    if (i >= TASK_MNT_MAX) {
        pcs_log("Warning: mnt cnt may overflow, max %d\n", TASK_MNT_MAX);
    }

    if (volume_cnt == 0) {
        pcs_log("not found any mount point\n");
        return 0;
    }

#if 1
    // just for debug on pc
    for (i = 0; i < volume_cnt; i++) {
        pcs_free(volumes[i].mnt);
        pcs_free(volumes[i].dev);
    }

    volume_cnt = 1;
    volumes[0].mnt = pcs_utils_strdup("/home/michael/");
    volumes[0].dev = pcs_utils_strdup("/dev/xxxx");
#endif    

    task_mnt_t *mnt_new = NULL;
    mnt_new = (task_mnt_t *)pcs_malloc(sizeof(task_mnt_t) * volume_cnt);
    if (mnt_new == NULL) {
        pcs_log("malloc failed\n");
        assert(0);
    }

    memset(mnt_new, 0, sizeof(task_mnt_t) * volume_cnt);

    for (i = 0; i < volume_cnt; i++) {
        mnt_new[i].mnt = volumes[i].mnt;
        mnt_new[i].mnt_len = strlen(mnt_new[i].mnt);
        mnt_new[i].dev = volumes[i].dev;
        pcs_log("index %d, mnt %s, dev %s\n", i, mnt_new[i].mnt, mnt_new[i].dev);
    }

    *mnt = mnt_new;

    return volume_cnt;
}

static int task_db_open(task_mnt_t *mnt)
{
    //try to open db
    char path[4096];
    int err;
    sqlite3 *db_ptr = NULL;
    int ret;
    
    snprintf(path, sizeof(path), "%s%s", mnt->mnt, ".pcs/pcs.db");
    
    pcs_log("try to open db %s\n", path);

    if (access(path, R_OK | W_OK) == -1) {
        err = errno;
        pcs_log("access file failed, %s %s\n", path, strerror(err));
        return -1;
    }

    if ((ret = sqlite3_open(path, &db_ptr)) != SQLITE_OK) {
        pcs_log("open sqlite db failed, %s\n", path);
        return -1;
    }

    mnt->db = db_ptr;

    return 0; 
}

static int task_db_restore(struct task_list *task_list, task_mnt_t *mnt)
{
    sqlite3 *db = NULL;
    int ret;
    sqlite3_stmt *stmt = NULL;

    char *lpath = NULL;
    char *rpath = NULL;
    char *rmd5 = NULL;
    uint64_t size;
    int status = 0;
    char *str = NULL;
    int len;
    unsigned int download_ts = 0;

    pcs_log("try to restore tasks on: %s\n", mnt->mnt);

    if ((ret = task_db_open(mnt)) != 0) {
        pcs_log("open sqlite db failed, %s\n", mnt->mnt);
        return -1;
    }

    db = mnt->db;

    char *sql = "SELECT lpath, rpath, rmd5, size, status, download_ts FROM task WHERE status == ? OR status == ?";

    ret = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (ret != SQLITE_OK) {
        pcs_log("sqlite3_prepare failed, ret = %d, %s\n", ret, sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, TASK_STATUS_DOWNLOADING);

    sqlite3_bind_int(stmt, 2, TASK_STATUS_INIT);

    while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {

        str = (char *)sqlite3_column_text(stmt, 0);
        if (!str) {
            pcs_log("get lpath failed\n");
            continue;
        }
        len = strlen(str) + mnt->mnt_len + 2;
        lpath = (char *)pcs_malloc(len);
        if (!lpath) {
            pcs_log("malloc failed\n");
            assert(0);
        }
        snprintf(lpath, len, "%s%s", mnt->mnt, str);

        str = (char *)sqlite3_column_text(stmt, 1);
        if (!str) {
            pcs_log("get lpath failed\n");
            continue;
        }
        rpath = pcs_utils_strdup(str);

        str = (char *)sqlite3_column_text(stmt, 2);
        if (!str) {
            pcs_log("get lpath failed\n");
            continue;
        }
        rmd5 = pcs_utils_strdup(str);

        size = sqlite3_column_int64(stmt, 3);

        status = sqlite3_column_int(stmt, 4);

        download_ts = (unsigned int)sqlite3_column_int(stmt, 5);

        if (!rpath || !rmd5) {
            pcs_log("malloc failed\n");
            assert(0);
        }

        pcs_log("got a task, lpath %s, rpath %s, rmd5 %s, size %llu, status %d, download_ts %u\n", lpath, rpath, rmd5, (unsigned long long)size, status, download_ts);

        task_restore(task_list->http_context, rpath, rmd5, size, lpath, status, download_ts);
    }

    sqlite3_finalize(stmt);

    return 0;
}

/**
 * 初始化数据库
 * 扫描所有挂载节点
 * 扫描所有挂载节点下面是否存在数据库，如果存在则尝试打开 
 */
int task_db_init(struct task_list *task_list)
{
    task_dev_t *dv = NULL;
    int i;

    pcs_log("init task db ...\n");

    dv = (task_dev_t *)pcs_malloc(sizeof(task_dev_t));
    if (!dv) {
        pcs_log("malloc failed\n");
        assert(0);
    }

    memset(dv, 0, sizeof(task_dev_t));

    task_list->dev = dv;

    dv->mnt_cnt = task_mnt_init(&(dv->mnts));
    if (dv->mnt_cnt == -1) {
        pcs_log("task mnt init failed\n");
        return -1;
    }

    if (dv->mnt_cnt == 0) {
        pcs_log("no disk mnted\n");
        return -1;
    }

    for (i = 0; i < dv->mnt_cnt; i++) {
        task_db_restore(task_list, dv->mnts + i);
    }

    return 0;
}


/**
 * 退出DB
 */
int task_db_exit(struct task_list *task_list)
{
    
    if (!task_list) {
        return -1;
    }

    pcs_log("task db exit...\n");

    if (task_list->dev) {
        if (task_list->dev->mnts) {
            task_mnt_t *mnt = task_list->dev->mnts;
            int i;
            for (i = 0; i < task_list->dev->mnt_cnt; i++) {
                if (mnt[i].mnt) pcs_free(mnt[i].mnt);
                if (mnt[i].dev) pcs_free(mnt[i].dev);

                if (mnt[i].db) {
                    sqlite3_close((sqlite3 *)(mnt[i].db));
                    mnt[i].db = NULL;
                }            
            }
            pcs_free(task_list->dev->mnts);
        }
        pcs_free(task_list->dev);
        task_list->dev = NULL;
    }

    return 0;
}

int task_db_create(task_mnt_t *mnt)
{
    char path[4096];
    sqlite3 *db = NULL;
    int ret = 0;
    char *errmsg = NULL;

    snprintf(path, sizeof(path), "%s%s", mnt->mnt, ".pcs/pcs.db");

    pcs_log("try to create db %s\n", path);

    if ((ret = sqlite3_open(path, &db)) != SQLITE_OK) {
        pcs_log("open sqlite db failed, %s\n", path);
        return -1;
    }

    ret = sqlite3_exec(db, TASK_DB_CREATE_SQL, NULL, NULL, &errmsg);
    if (ret != SQLITE_OK) {
        pcs_log("create table failed, sql = [%s], %s\n", TASK_DB_CREATE_SQL, errmsg);
        sqlite3_free(errmsg);
        sqlite3_close(db);
        return -1;
    }

    mnt->db = db;

    return 0;
}


static int task_db_record_add(struct task *task)
{
    sqlite3 *db = task->mnt->db;
    sqlite3_stmt *stmt = NULL;
    int ret = 0;

    int rc = 0;

    pcs_log("add a record, %s\n", task->lpath);

    char *sql = "INSERT INTO task (lpath, rpath, size, rmd5, start_ts, status) VALUES (?, ?, ?, ?, ?, ?)";

    ret = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (ret != SQLITE_OK) {
        pcs_log("sqlite3_prepare failed, ret = %d, %s\n", ret, sqlite3_errmsg(db));
        return -1;
    }

    //去除掉挂载点前缀
    sqlite3_bind_text(stmt, 1, task->lpath + task->mnt->mnt_len, -1, SQLITE_TRANSIENT);

    sqlite3_bind_text(stmt, 2, task->rpath, -1, SQLITE_TRANSIENT);

    sqlite3_bind_int64(stmt, 3, task->total_size);

    sqlite3_bind_text(stmt, 4, task->rmd5, -1, SQLITE_TRANSIENT);

    sqlite3_bind_int(stmt, 5, task->start_ts);

    sqlite3_bind_int(stmt, 6, task->status);

    ret = sqlite3_step(stmt);
    if (ret != SQLITE_DONE) {
        pcs_log("sqlite3_step failed, %s\n", sqlite3_errmsg(db));
        rc = -1;
    }

    sqlite3_finalize(stmt);

    return rc;        
}


int task_db_mnt_set(struct task_list *task_list, struct task *task)
{
    //找到对应的分区
    int i;
    task_dev_t *dev = task_list->dev;
    task_mnt_t *mnt;
    int found = 0;

    pcs_log("try to set task mnt, %s\n", task->lpath);

    for (i = 0; i < dev->mnt_cnt; i++) {
        mnt = dev->mnts + i;
        if (strncmp(task->lpath, mnt->mnt, mnt->mnt_len) == 0){
            found = 1;
            break;
        } 
    }

    if (found == 0) {
        pcs_log("not found the mount point %s\n", task->lpath);
        return -1;
    }

    //add record to db
    task->mnt = mnt;  

    return 0;  
}

/**
 *添加一条任务信息到数据中
 * 首先检查数据库是否存在，如果不存在，则先尝试创建数据
 * 在相应表格内插入数据
 * 
 */
int task_db_add(struct task_list *task_list, struct task *task)
{
    pcs_log("try to add task to db, %s\n", task->lpath);

    if (task_db_mnt_set(task_list, task) == -1) {
        pcs_log("set task mnt failed\n");
        return -1;
    }


    /* FIXME: 可能由于竞争导致db被多次打开 */
    if (task->mnt->db == NULL) {
        //try to create db
        if (task_db_create(task->mnt) == -1) {
            pcs_log("task_db_create failed\n");
            return -1;
        }
    }

    if (task_db_record_add(task) == -1) {
        pcs_log("add record to db failed\n");
        return -1;
    }

    return 0;
}

/**
 * 保存任务到数据库
 */
int task_db_update(struct task_list *task_list, struct task *task)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int ret = 0;

    int rc = 0;

    if (!task) {
        pcs_log("task is null\n");
        return -1;
    }

    if (task->mnt == NULL) {
        if (task_db_mnt_set(task_list, task) == -1) {
            pcs_log("set the task mnt failed\n");
            return -1;
        }
    }

    if (task->mnt->db == NULL) {
        //try to open db

        if ((ret = task_db_open(task->mnt)) != 0) {
            pcs_log("open sqlite db failed, %s\n", task->mnt->mnt);
            return -1;
        } 
    }

    db = task->mnt->db;

    pcs_log("update a record, %s\n", task->lpath);

    char *sql = "UPDATE task SET complete_ts = ?, download_ts = ?, download_size = ?, status = ? WHERE lpath = ?";

    ret = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (ret != SQLITE_OK) {
        pcs_log("sqlite3_prepare failed, ret = %d, %s\n", ret, sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, task->complete_ts);

    sqlite3_bind_int(stmt, 2, task->download_ts);

    sqlite3_bind_int(stmt, 3, task->download_size);

    sqlite3_bind_int(stmt, 4, task->status);

    //去除掉挂载点前缀
    sqlite3_bind_text(stmt, 5, task->lpath + task->mnt->mnt_len, -1, SQLITE_STATIC);

    ret = sqlite3_step(stmt);
    if (ret != SQLITE_DONE) {
        pcs_log("sqlite3_step failed, %s\n", sqlite3_errmsg(db));
        rc = -1;
    }

    sqlite3_finalize(stmt);

    return rc;
}


static int task_db_complete_task_get_from_mnt(task_mnt_t *mnt, task_info_list_t **head, task_info_list_t **tail, int *cnt)
{
    sqlite3 *db = NULL;
    int ret;
    sqlite3_stmt *stmt = NULL;
    char *str = NULL;
    task_info_list_t *list = NULL;
    int len = 0;

    char *sql = "SELECT rpath, lpath, rmd5, size, download_size, start_ts, download_ts, complete_ts FROM task WHERE status == ?";

    db = mnt->db;

    ret = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (ret != SQLITE_OK) {
        pcs_log("sqlite3_prepare failed, ret = %d, %s\n", ret, sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, TASK_STATUS_COMPLETE);

    while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
        list = pcs_malloc(sizeof(task_info_list_t));
        if (!list) {
            pcs_log("malloc failed\n");
            assert(0);
        }
        memset(list, 0, sizeof(task_info_list_t));

        str = (char *)sqlite3_column_text(stmt, 0);
        if (str) {
            list->rpath = pcs_utils_strdup(str);
        }

        str = (char *)sqlite3_column_text(stmt, 1);
        if (str) {
            len = strlen(str) + mnt->mnt_len + 2;
            list->lpath = (char *)pcs_malloc(len);
            if (!list->lpath) {
                pcs_log("malloc failed\n");
                assert(0);
            }
            snprintf(list->lpath, len, "%s%s", mnt->mnt, str);
        }

        str = (char *)sqlite3_column_text(stmt, 2);
        if (str) {
            list->rmd5 = pcs_utils_strdup(str);
        }    

        list->total_size = sqlite3_column_int64(stmt, 3);

        list->download_size = sqlite3_column_int64(stmt, 4);

        list->start_ts = sqlite3_column_int(stmt, 5);

        list->download_ts = sqlite3_column_int(stmt, 6);

        list->complete_ts = sqlite3_column_int(stmt, 7);

        list->status = TASK_STATUS_COMPLETE;

        if (*head) {
            (*tail)->next = list;
            *tail = list;
        } else {
            *head = list;
            *tail = list;
        }

        *cnt = *cnt + 1;
    }

    sqlite3_finalize(stmt);

    return 0;
}

int task_db_complete_task_get(struct task_list *task_list, struct task_info_list **info_list)
{
    if (!task_list || !info_list) {
        return -1;
    }

    if (!task_list->dev || !task_list->dev->mnts) {
        //没有挂载任何磁盘设备
        pcs_log("no disk mnted\n");
        *info_list = NULL;
        return 0;
    }

    task_mnt_t *mnt = task_list->dev->mnts;
    int mnt_cnt = task_list->dev->mnt_cnt;
    int i;

    struct task_info_list *head = NULL;
    struct task_info_list *tail = NULL;
    int cnt = 0;
    
    for (i = 0; i < mnt_cnt; i++) {
        if (!mnt->db) {
            pcs_log("mnt not found or opened db %s\n", mnt->mnt);
            continue;
        }

        task_db_complete_task_get_from_mnt(mnt + i, &head, &tail, &cnt);
    }

    *info_list = head;

    return cnt;
}

int task_db_check_exist(task_mnt_t *mnt, const char *lpath)
{
    sqlite3 *db = NULL;
    int ret;
    sqlite3_stmt *stmt = NULL;
    int rc = 0;

    pcs_log("try to check task in db %s\n", lpath);

    char *sql = "SELECT status FROM task WHERE lpath == ?";

    if (strncmp(lpath, mnt->mnt, mnt->mnt_len) != 0) {
        return 0;
    }

    if (mnt->db == NULL) {
        //try to open db
        if ((ret = task_db_open(mnt)) != 0) {
            //open db faild
            return 0;
        }
    }

    db = mnt->db;

    ret = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (ret != SQLITE_OK) {
        pcs_log("sqlite3_prepare failed, ret = %d, %s\n", ret, sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, lpath + mnt->mnt_len, -1, SQLITE_STATIC);

    rc = 0;
    if ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
        rc = 1;
    }

    sqlite3_finalize(stmt);

    return rc;
}

int task_db_del_by_lpath(task_mnt_t *mnt, const char *lpath)
{
    sqlite3 *db = NULL;
    int ret;
    sqlite3_stmt *stmt = NULL;
    int rc = 0;

    char *sql = "DELETE FROM task WHERE lpath == ?";

    pcs_log("try to del task, %s\n", lpath);

    if (strncmp(lpath, mnt->mnt, mnt->mnt_len) != 0) {
        return 0;
    }    

    if (mnt->db == NULL) {
        //try to open db
        if ((ret = task_db_open(mnt)) != 0) {
            //open db faild
            return 0;
        }
    }

    db = mnt->db;

    ret = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (ret != SQLITE_OK) {
        pcs_log("sqlite3_prepare failed, ret = %d, %s\n", ret, sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, lpath + mnt->mnt_len, -1, SQLITE_STATIC);

    rc = -1;
    if ((ret = sqlite3_step(stmt)) == SQLITE_DONE) {
        pcs_log();
        rc = 0;
    }

    sqlite3_finalize(stmt);

    return rc;
}


/**
 * 递归创建目录
 * @param dir 目录名称，所有路径都认为是目录
 */
int create_dir_r(const char *dir)
{
	char path[4096];
	char *ptr = NULL;
	char old = 0;
	int err = 0;

	if (!dir || *dir != '/') {
		return -1;
	}

	memset(path, 0, sizeof(path));

	strncpy(path, dir, sizeof(path) - 1);

	ptr = path + 1;

    while (*ptr) {
        while (*ptr && *ptr != '/') ptr++;
        if (*ptr == '/' || *ptr == '\0') {
            old = *ptr;
            *ptr = '\0';
            //printf("check path [%s]\n", path);
            if (access(path, F_OK) == -1) {
                /* do not exist, attemp to create it */
                printf("create dir [%s]\n", path);
                if (mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO ) == -1) {
                    err = errno;
                    if (err != EEXIST) {
                        printf("mkdir: mkdir failed, %s, %s\n", path, strerror(err));
                        return -1;
                    }
                }
            }

            if(old == '/') {
                *ptr++ = '/';  /* restore */
            } else {
                return 0;
            }
        }
	}

	return 0;
}

