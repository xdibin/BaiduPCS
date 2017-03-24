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
    "task_id INTEGER PRIMARY KEY," \
    "lpath TEXT NOT NULL UNIQUE," \
    "rpath TEXT NOT NULL," \
    "url TEXT NOT NULL," \
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


const struct volume_dev_node g_dev_nodes[] = {
    { "/dev/sd",                    7  },
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

	//printf("buff = [%s]\n", buff);

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
                volumes[i].mnt = pcs_utils_strdup(start);
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
        return 0;
    }

    task_mnt_t *mnt_new = NULL;
    mnt_new = (task_mnt_t *)pcs_malloc(sizeof(task_mnt_t) * volume_cnt);
    if (mnt_new == NULL) {
        pcs_log("malloc failed\n");
        return -1;
    }

    for (i = 0; i < volume_cnt; i++) {
        mnt_new[i].mnt = volumes[i].mnt;
        mnt_new[i].mnt_len = strlen(mnt_new[i].mnt);
        mnt_new[i].dev = volumes[i].dev;
    }

    return volume_cnt;
}

static int task_db_restore(struct task_list *task_list, task_mnt_t *mnt)
{
    char path[4096];
    int err;
    sqlite3 *db = NULL;
    int ret;
    sqlite3_stmt *stmt = NULL;

    unsigned int task_id;
    char *lpath = NULL;
    char *rpath = NULL;
    char *rmd5 = NULL;
    uint64_t size;
    int status = 0;
    char *str = NULL;
    int len;

    snprintf(path, sizeof(path), "%s/%s", mnt->mnt, ".pcs/pcs.db");

    if (access(path, R_OK | W_OK) == -1) {
        err = errno;
        pcs_log("access file failed, %s %s\n", path, strerror(err));
        return -1;
    }

    if ((ret = sqlite3_open(path, &db)) != SQLITE_OK) {
        pcs_log("open sqlite db failed, %s\n", path);
        return -1;
    }    

    char *sql = "SELECT task_id, lpath, rpath, rmd5, size, status FROM task";

    ret = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (ret != SQLITE_OK) {
        pcs_log("sqlite3_prepare failed, ret = %d\n", ret);
        return -1;
    }

    while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
        task_id = sqlite3_column_int(stmt, 0);

        str = (char *)sqlite3_column_text(stmt, 1);
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

        str = (char *)sqlite3_column_text(stmt, 2);
        if (!str) {
            pcs_log("get lpath failed\n");
            continue;
        }
        rpath = pcs_utils_strdup(str);

        str = (char *)sqlite3_column_text(stmt, 3);
        if (!str) {
            pcs_log("get lpath failed\n");
            continue;
        }
        rmd5 = pcs_utils_strdup(str);

        size = sqlite3_column_int64(stmt, 4);

        status = sqlite3_column_int(stmt, 5);

        if (!rpath || !rmd5) {
            pcs_log("malloc failed\n");
            assert(0);
        }

        pcs_log("lpath %s\n", lpath);

        task_restore(task_list->http_context, task_id, rpath, rmd5, size, lpath, status);
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

    dv = (task_dev_t *)pcs_malloc(sizeof(task_dev_t));
    if (!dv) {
        pcs_log("malloc failed\n");
        assert(0);
    }

    memset(dv, 0, sizeof(task_dev_t));

    dv->mnt_cnt = task_mnt_init(&(dv->mnts));
    if (dv->mnt_cnt == -1) {
        pcs_log("task_mnt_init failed\n");
        pcs_free(dv);
        return -1;
    }

    if (dv->mnt_cnt == 0) {
        pcs_log("no disk mnted\n");
        return -1;
    }

    for (i = 0; i < dv->mnt_cnt; i++) {
        task_db_restore(task_list, dv->mnts + i);
    }

    task_list->dev = dv;

    return 0;
}



int task_db_create(task_mnt_t *mnt)
{
    char path[4096];
    sqlite3 *db = NULL;
    int ret = 0;
    char *errmsg = NULL;

    snprintf(path, sizeof(path), "%s/%s", mnt->mnt, ".pcs/pcs.db");

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

    char *sql = "INSERT INTO task(task_id, lpath, rpath, url, size, md5, start_ts) VALUES (?, ?, ?, ?, ?, ?, ?)";

    ret = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (ret != SQLITE_OK) {
        pcs_log("sqlite3_prepare failed, ret = %d\n", ret);
        return -1;
    }


    sqlite3_bind_int(stmt, 1, task->task_id);

    //去除掉挂载点前缀
    sqlite3_bind_text(stmt, 2, task->lpath + task->mnt->mnt_len, -1, SQLITE_TRANSIENT);

    sqlite3_bind_text(stmt, 3, task->rpath, -1, SQLITE_TRANSIENT);

    sqlite3_bind_text(stmt, 4, task->url, -1, SQLITE_TRANSIENT);

    sqlite3_bind_int(stmt, 5, task->total_size);

    sqlite3_bind_text(stmt, 6, task->rmd5, -1, SQLITE_TRANSIENT);

    sqlite3_bind_int(stmt, 7, task->start_ts);

    ret = sqlite3_step(stmt);
    if (ret != SQLITE_DONE) {
        pcs_log("sqlite3_step failed, %s\n", sqlite3_errmsg(db));
        rc = -1;
    }

    sqlite3_finalize(stmt);

    return rc;        
}

/**
 *添加一条任务信息到数据中
 * 首先检查数据库是否存在，如果不存在，则先尝试创建数据
 * 在相应表格内插入数据
 * 
 */
int task_db_add(struct task_list *task_list, struct task *task)
{
    //找到对应的分区
    int i;
    task_dev_t *dev = task_list->dev;
    task_mnt_t *mnt;
    int found = 0;

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

    if (mnt->db == NULL) {
        //try to create db
        if (task_db_create(mnt) == -1) {
            pcs_log("task_db_create failed\n");
            return -1;
        }
    }

    //add record to db
    task->mnt = mnt;

    if (task_db_record_add(task) == -1) {
        pcs_log("add record to db failed\n");
        return -1;
    }

    return 0;
}
