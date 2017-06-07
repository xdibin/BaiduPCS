#ifndef _HTTP_H
#define _HTTP_H

#include <time.h>
#include "pcs/pcs.h"

#define SORT_DIRECTION_ASC	0 /*正序*/
#define SORT_DIRECTION_DESC 1 /*倒序*/

#define USAGE "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36"

/**
 * @brief context文件的默认路径
 */
#define CONTEXT_FILE_DEFAULT	"/tmp/.pcs/pcs.context"

/**
 * @brief cookie文件的默认路径
 */
#define COOKIE_FILE_DEFAULT		"/tmp/.pcs/pcs.cookie"

/**
 * @brief 验证码文件的默认路径
 */
#define CAPTCH_FILE_DEFAULT		"/tmp/.pcs/captch.png"


/**
 * @brief list接口的默认分页大小
 */
#define LIST_PAGE_SIZE_DEFAULT	20	


#ifndef HTTP_TIMEOUT
#define HTTP_TIMEOUT	6
#endif

#ifndef HTTP_CONNECT_TIMEOUT
#define HTTP_CONNECT_TIMEOUT	4
#endif

#define URL_SIZE_MAX			8192

#define SUBTASK_MAX				8

#define FILE_SLICE_MIN			(1 << 20)

typedef void (*signal_handle_t)(int signo);


/**
 * @brief HTTP上下文定义
 *
 */
typedef struct HttpContext {
	char		*contextfile; /**<上下文文件的路径 */
	char		*cookiefile; /**< Cookie文件路径 */
	char		*captchafile; /**< 验证码图片路径 */
	char		*workdir; /**< 当前工作目录 */
	char		*gid;
	Pcs			pcs; /**< PCS上下文 */

	int			list_page_size; /*执行list命令时，每页大小*/
	char		*list_sort_name; /**< 执行list命令时，排序字段，可选值：name|time|size */
	char		*list_sort_direction; /**< 执行list命令时，排序字段，可选值：asc|desc */

	char		*secure_method; /**< 加密方法，可选值：plaintext|aes-cbc-128|aes-cbc-192|aes-cbc-256 */
	char		*secure_key;    /**< 加密时的KEY */
	int			secure_enable;  /**< 是否启用加密 */

	int			timeout_retry;  /**< 是否启用超时后重试 */
	int			max_thread; /**< 指定最大线程数量 */
	int			max_speed_per_thread; /**< 指定单个线程的最多下载速度 */
	int			max_upload_speed_per_thread; /**< 指定单个线程的最大上传速度 */

	char		*user_agent;    /**< 浏览器代理 */

	void		*http;			/**< xhttp协议相关的参数 */

	int			subtask_max;	/**< 每个HTTP文件下载任务的最大子任务个数 */
	int			file_slice_size_min;	/**< 每个HTTP文件下载任务的最小文件分片尺寸 */

	signal_handle_t	sig_handle;

	int			is_login;
} HttpContext;

extern volatile int g_pcs_running;

#endif
