#ifndef __TASK_DB_H
#define __TASK_DB_H 1


#define TASK_MNT_MAX        64



typedef struct task_mnt {
    char *mnt;          /**< 磁盘分区挂载点, e.g. /mnt/sda1/ 注意：必须包含最后一个斜杠，便于字符串比较 */
    int mnt_len;        /**< mnt字段的长度 */
    char *dev;          /**< 设备分区节点, e.g. /dev/sda1 */

    void *db;           /**< 数据库句柄 */
} task_mnt_t;

typedef struct task_dev {
    int mnt_cnt;        /**< 挂载节点总数 */
    task_mnt_t *mnts;   /**< 挂载节点列表 */
} task_dev_t;

struct task;

struct task_list;

struct task_info_list;

int task_db_init(struct task_list *task_list);

int task_db_exit(struct task_list *task_list);

int task_db_add(struct task_list *task_list, struct task *task);

int task_db_mnt_set(struct task_list *task_list, struct task *task);

int task_db_del(struct task_list *task_list, struct task *task);

int task_db_update(struct task_list *task_list, struct task *task);

int task_db_info_list_get_by_status(
    struct task_list *task_list, 
    struct task_info_list **info_list_head,
    struct task_info_list **info_list_tail,
    int status);

int task_db_check_exist(task_mnt_t *mnt, const char *lpath);

int task_db_del_by_lpath(task_mnt_t *mnt, const char *lpath);

int create_dir_r(const char *dir);

int task_db_get_by_lpath(struct task_list *task_list, const char *lpath, struct task **task);

#endif
