#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dispatch.h"
#include "utils_print.h"
#include "error_code.h"

#include "xhttpd.h"

/**
 * @brief HTTP分发回调函数原型
 *
 */
typedef int (*DispatchCallbackFunction)(HttpContext *context);


/**
 * @brief HTTP分发表原型定义
 *
 */
typedef struct DispatchTable {
    char *method;                       /**< the HTTP method string, end with nil, should not be duplicate */
    DispatchCallbackFunction callback;  /**< the callback function */
} DispatchTable;



#define PARAM_GET(c, k)	((char *)(xhttpd_parameter_get((xhttpd_http_t *)(c->http), (k))))

static int http_response_by_xhttpd(HttpContext *http, const char *body, int bodylen);

/**
 * @brief 将C语言的字符串编码成JSON字符串，对需要转义的控制字符进行转义替换
 *
 * @param src 原字符串，C语言形式，已0结束
 * @param dst 目标字符串，传递一个buf
 * @param dst_len 目标字符串缓冲区的长度指针，函数会将最终目标目标字符串的长度写入到该参数
 *
 * @return 返回编码后的字符串
 */
static char *json_encode_string(const char *src, char *dst, int *dst_len)
{
	memset(dst, 0, sizeof(*dst_len));

	//TODO: need replace to real json encode function
	strncpy(dst, src, *dst_len - 1);

	return dst;
}



/**
 * @brief 检查是否已经登录
 *
 * @param context HTTP上下文
 *
 * @return 已经登陆返回PcsTrue，没有登陆返回PcsFalse
 */
static PcsBool is_http_login(HttpContext *context)
{
	PcsRes pcsres;
	time_t now;
	time(&now);
	pcsres = pcs_islogin(context->pcs);
	if (pcsres == PCS_LOGIN)
		return PcsTrue;

	if (pcsres == PCS_NOT_LOGIN) {
		printf("You are not logon or your session is time out. You can login by 'login' command.\n");
	}
	else {
		printf("Error: %s\n", pcs_strerror(context->pcs));
	}
	return PcsFalse;
}




static int callback_login(HttpContext *context)
{
	int pcsres = 0;
	char *username = NULL;
	char *password = NULL;	

	/* get username and password */
	username = PARAM_GET(context, "username");
	password = PARAM_GET(context, "password");

	if (!username || !*username || !password || !*password) {
		return ERRCODE_ARG;
	}

	printf("username = '%s'\n", username);
	printf("password = '%s'\n", password);

	/* save the username and password */
	pcs_setopt(context->pcs, PCS_OPTION_USERNAME, username);
	pcs_setopt(context->pcs, PCS_OPTION_PASSWORD, password);

	pcsres = pcs_login(context->pcs);
	if (pcsres != PCS_OK) {
		printf("Login Failed: %s\n", pcs_strerror(context->pcs));
		return ERRCODE_UNKNOWN;
	}
	printf("Login Success. UID: %s\n", pcs_sysUID(context->pcs));

	char buf[512];
	int len = 0;

	len = snprintf(buf, sizeof(buf), "{\"errno\":0}");

	printf("json response is '%s', len = %d\n", buf, len);

	http_response_by_xhttpd(context, buf, len);

	return 0;
}

static int callback_who(HttpContext *context)
{
	char buf[512];
	int len = 0;

	memset(buf, 0, sizeof(buf));

	char name[256];
	int name_len = sizeof(name);

	json_encode_string(pcs_sysUID(context->pcs), name, &name_len);

	len = snprintf(buf, sizeof(buf), "{\"errno\":0,\"username\":\"%s\"}", name);

	printf("response is '%s', len = %d\n", buf, len);

	http_response_by_xhttpd(context, buf, len);

	return 0;
}

static int callback_logout(HttpContext *context)
{
	PcsRes pcsres = 0;
	
	pcsres = pcs_logout(context->pcs);
	if (pcsres != PCS_OK) {
		printf("Logout Fail: %s\n", pcs_strerror(context->pcs));

		return ERRCODE_UNKNOWN;
	}

	printf("Logout Success.\n");

	char buf[512];
	int len = 0;

	len = snprintf(buf, sizeof(buf), "{\"errno\":0}");

	printf("json response is '%s', len = %d\n", buf, len);

	http_response_by_xhttpd(context, buf, len);

	return 0;	
}


static int json_list_file_init(char **json, int *capacity, int *remain)
{
	char *buf = NULL;

	printf("init the list file json\n");

	buf = malloc(sizeof(char) * 512 * 1024);
	if (!buf) {
		return ERRCODE_MEMORY;
	}
	*capacity = sizeof(char) * 512 * 1024;
	*remain = *capacity;
	*json = buf;

	int len = 0;

	len = snprintf(buf, *remain, "{\"errno\":0,\"list\":[");

	*remain -= len;

	return len;
}

static int json_list_file_end(char **json, int *capacity, int *remain, int has_more)
{
	int len = *capacity - *remain;
	int inc = 0;

	printf("end the list file json\n");

	if ((*json)[len - 1] == ',') {
		(*json)[len - 1] = '\0';
		*remain = *remain + 1;
		len--;
	}

	if (*remain <= 15) {
		printf("remain too small\n");
		free(*json);
		*json = NULL;
		return ERRCODE_MEMORY;
	}

	inc = snprintf(*json + len, *remain, "],\"has_more\":%d}", has_more);

	return len + inc; // the total length of json string
}

static void json_list_file_free(char **json)
{
	printf("free the list file json\n");
	if (*json) {
		free(*json);
		*json = NULL;
	}
}

/**
 * @brief 将PcsFileInfo类型的变量转换成json格式并添加到json字符串里面
 *
 * @param json 输入/输出参数，用于保存转换后的json串
 * @param capacity 输入/输出参数，当前json缓冲区的总长度
 * @param remain 输入/输出参数，json缓冲区目前剩余的空间，返回时，会将剩余的空间通过这个参数返回
 * @param fi PcsFileInfo文件对象
 *
 * @return json字符串里面的字符总数
 */
static int json_list_file_add(char **json, int *capacity, int *remain, PcsFileInfo *fi)
{
	char *buf = NULL;
	int len = 0;
	int offset = *capacity - *remain;
	char path[1024];
	int path_len = sizeof(path);
	char filename[1024];
	int filename_len = sizeof(filename);

	printf("add a list file json\n");

	if (*remain < (8192)) {
		/* realloc a new large buffer */
		printf("realloc a new large buffer\n");
		
		int len_inc = (sizeof(char) * 512 * 1024);
		buf = realloc(*json, (*capacity) + len_inc);
		if (!buf) {
			free(*json);
			*json = NULL;
			return ERRCODE_MEMORY;
		}
		memset(buf + (*capacity), 0, len_inc);

		*capacity += len_inc;
		*remain += len_inc;
		*json = buf;
	} else {
		buf = *json;
	}

	len = snprintf(buf + offset, *remain, "{"
		"\"fs_id\":%llu,"
		"\"path\":\"%s\","
		"\"server_filename\":\"%s\","
		"\"size\":%lld,"
		"\"server_mtime\":%llu,"
		"\"server_ctime\":%llu,"
		"\"isdir\":%d,"
		"\"md5\":\"%s\""
		"},",
		fi->fs_id,
		json_encode_string(fi->path, path, &path_len),
		json_encode_string(fi->server_filename, filename, &filename_len),
		fi->size,
		fi->server_mtime,
		fi->server_ctime,
		fi->isdir,
		(fi->md5 ? fi->md5 : "")	
	);

	*remain = *remain - len;

	return *capacity - *remain;
}

/**
 * @brief callback function for list method
 *
 * @return 
 */
static int callback_list(HttpContext *context)
{
    char *dir = PARAM_GET(context, "dir");
    char *page = PARAM_GET(context, "page");
    char *num = PARAM_GET(context, "num");

    /* set the default value */
    int i4_page = 1;
    int i4_num = context->list_page_size;

	if (page) {
		i4_page = atoi(page);
	}

	if (num) {
		i4_num = atoi(num);
	}

	if (!dir || !*dir || i4_page <= 0 || i4_num <= 0) {
		return ERRCODE_ARG;
	}

	PcsFileInfoList *list = NULL;

	int fileCount = 0, dirCount = 0;
	int64_t totalSize = 0;
    int md5 = 0, thumb = 0; 

	PcsFileInfoListIterater iterater;
	PcsFileInfo *file = NULL;	

	char *json = NULL;
	int json_capacity = 0;
	int json_remain = 0;
	int rc = 0;
	int total = 0;	

	printf("try to list %s\n", dir);

	/* get the file list from server */
	list = pcs_list(context->pcs, dir,
		i4_page, i4_num,
		context->list_sort_name,
		streq(context->list_sort_direction, "desc", -1) ? PcsTrue: PcsFalse);

	if (!list) {
		if (pcs_strerror(context->pcs)) {
			fprintf(stderr, "Error: %s\n", pcs_strerror(context->pcs));
			return ERRCODE_UNKNOWN;
		}
	}

	print_http_filelist(list, &fileCount, &dirCount, &totalSize, md5, thumb);

	/* convert the list to json string */
	rc = json_list_file_init(&json, &json_capacity, &json_remain);
	if (rc < 0) {
		pcs_filist_destroy(list);
		return rc;
	}

	pcs_filist_iterater_init(list, &iterater, PcsFalse);
	while (pcs_filist_iterater_next(&iterater)) {
		file = iterater.current;
		total++;
		if (!file) {
			json_list_file_free(&json);
			pcs_filist_destroy(list);
			return ERRCODE_UNKNOWN;
		}
		rc = json_list_file_add(&json, &json_capacity, &json_remain, file);

		if (rc < 0) {
			pcs_filist_destroy(list);
			return rc;
		}
	}

	rc = json_list_file_end(&json, &json_capacity, &json_remain, (total < i4_num ? 0 : 1));
	if (rc < 0) {
		pcs_filist_destroy(list);
		return rc;
	}

	printf("json response is '%s', len = %d\n", json, rc);

	http_response_by_xhttpd(context, json, rc);

	json_list_file_free(&json);

	pcs_filist_destroy(list);

	return 0;
}




/**
 * @brief 
 *
 * @return 
 */
static int callback_meta(HttpContext *context)
{
	PcsFileInfo *fi = NULL;
	char *path = NULL;
	char buf[4096];
	int len = 0;
	char jpath[1024];
	int jpath_len = sizeof(jpath);
	char filename[1024];
	int filename_len =  sizeof(filename);

	path = PARAM_GET(context, "path");

	if (!path || strcmp(path, "/") == 0) {
		/* the root dir is not allowed to meta */
		return ERRCODE_ARG;
	}

	fi = pcs_meta(context->pcs, path);
	if (!fi) {
		fprintf(stderr, "Error: The target not exist, or have error: %s\n", pcs_strerror(context->pcs));
		return ERRCODE_UNKNOWN;
	}
	
	print_http_fileinfo(fi, " ");

	memset(buf, 0, sizeof(buf));

	len = snprintf(buf, sizeof(buf), "{\"errno\":0,\"list\":[{"
		"\"fs_id\":%llu,"
		"\"path\":\"%s\","
		"\"server_filename\":\"%s\","
		"\"size\":%lld,"
		"\"server_mtime\":%llu,"
		"\"server_ctime\":%llu,"
		"\"isdir\":%d,"
		"\"md5\":\"%s\""
		"}]}",
		fi->fs_id,
		json_encode_string(fi->path, jpath, &jpath_len),
		json_encode_string(fi->server_filename, filename, &filename_len),
		fi->size,
		fi->server_mtime,
		fi->server_ctime,
		fi->isdir,
		(fi->md5 ? fi->md5 : "")	
	);

	pcs_fileinfo_destroy(fi);

	printf("response is '%s', len = %d\n", buf, len);

	http_response_by_xhttpd(context, buf, len);

	return 0;
}


/**
 * @brief 
 *
 * @return 
 */
static int callback_quota(HttpContext *context)
{
	PcsRes pcsres = 0;
	int64_t quota = 0;
	int64_t used = 0;

	char buf[512];
	int len = 0;

	pcsres = pcs_quota(context->pcs, &quota, &used);
	if (pcsres != PCS_OK) {
		fprintf(stderr, "Error: %s\n", pcs_strerror(context->pcs));
		return ERRCODE_UNKNOWN;
	}

	memset(buf, 0, sizeof(buf));
	len = snprintf(buf, sizeof(buf), "{\"errno\":0,\"total\":%lld,\"used\":%lld}",
		quota, used);

	printf("response is '%s', len = %d\n", buf, len);

	http_response_by_xhttpd(context, buf, len);

	return 0;
}

/**
 * @brief 下载单个文件
 *
 * @return 
 */
static int callback_download(HttpContext *context)
{
	char *rpath = NULL;
	char *ldir = NULL;
	char *lname = NULL;
	char *offset = NULL;
	char *length = NULL;
	char *force = NULL;

	char lpath_real[4096];
	char rpath_real[4096];
	char lname_real[2048];
	int lpath_real_len = 0;
	int err;
	int rc;

	int64_t i8_length = 0;
	int64_t i8_offset = 0;
	int i4_force = 0;

	rpath = PARAM_GET(context, "rpath");
	ldir = PARAM_GET(context, "ldir");
	lname = PARAM_GET(context, "lname");
	offset = PARAM_GET(context, "offset");
	length = PARAM_GET(context, "length");
	force = PARAM_GET(context, "force");

	if (offset) {
		i8_offset = atoll(offset);
	}

	if (length) {
		i8_length = atoll(length);
	}

	if (force) {
		i4_force = atoi(force);
	}

	if (!rpath || !*rpath || 
		!ldir || !*ldir ||
		i8_offset < 0 ||
		i8_length < 0 ||
		(i4_force != 0 && i4_force != 1)
	) {
		return ERRCODE_ARG;
	}

	if (!lname || !*lname) {
		memset(rpath_real, 0, sizeof(rpath_real));
		xhttpd_url_decode(rpath, strlen(rpath), rpath_real, sizeof(rpath_real) - 1, 0);
		char *rr = strrchr(rpath_real, '/');
		
	}

	/* check local file */


	memset(lpath_real, 0, sizeof(lpath_real));
	lpath_real_len = xhttpd_url_decode(ldir, strlen(ldir), lpath_real, sizeof(lpath_real) - 1, 0);
	
	printf("local path is '%s'\n", lpath_real);

	struct stat st;
	if (stat(lpath_real, &st) == -1) {
		err = errno;
		if (err != ENOENT) {
			printf("stat file failed, %s, %s\n", lpath_real, strerror(err));
			return ERRCODE_LOCAL_FILE;
		} else {
			/* create the dir */
			printf("dir not exist\n");
			return ERRCODE_LOCAL_FILE;
		}
	} else {
		if (!S_ISDIR(st.st_mode)) {
			/* not a dir */
			return ERRCODE_LOCAL_FILE;
		}
	}

	if (lpath_real[lpath_real_len - 1] != '/') {
		lpath_real[lpath_real_len] = '/';
		lpath_real_len++;
	}
	assert(lpath_real_len >= sizeof(lpath_real));

	xhttpd_url_decode(lname_real, strlen(lname_real), lpath_real + lpath_real_len, sizeof(lpath_real) - 1 - lpath_real_len, 0);

	if (stat(lpath_real, &st) == 0) {
		if (!S_ISREG(st.st_mode)) {
			/* not a file */
			return ERRCODE_LOCAL_FILE;
		} else {
			/* check force overwrite flag is set or not ? */
			if (i4_force == 0) {
				printf("file exist not force overwrite is not set!\n");
				return ERRCODE_LOCAL_FILE;
			}
		}
	}




}

static void http_response_error(HttpContext *context, int error_code)
{
	char buf[1024];
	int len = 0;

	memset(buf, 0, sizeof(buf));

	len = snprintf(buf, sizeof(buf), "{\"errno\":%d}", error_code);

	printf("error code = %d, response = %s\n", error_code, buf);

	http_response_by_xhttpd(context, buf, len);

	return;
}

/**
 * @brief the http dispatch callback function table
 */
static const DispatchTable dispatch_table[] = {
    { "list",   	callback_list 		},
	{ "login",		callback_login 		},
	{ "who",		callback_who	 	},
	{ "logout",		callback_logout		},
	{ "meta",		callback_meta 		},
	{ "quota",		callback_quota	 	},
	{ "download",	callback_download	}
};

/**
 * @brief the dispatch table size (total elements count)
 */
static const int dispatch_table_size = sizeof(dispatch_table)/sizeof(dispatch_table[0]);


/**
 * @brief HTTP请求处理分发处理函数
 *
 * @detailed 
 *
 * @param context HTTP上下文
 *
 * @return 0 成功，其他失败
 */
static int http_dispatch(HttpContext *context)
{
	int i;
	int rc = 0;
	int is_login = 0;
	char *method = NULL;

	xhttpd_http_t *http = (xhttpd_http_t *)(context->http);
	assert(http != NULL);
	printf("uri = '%s'\n", http->uri);

	method = strrchr(http->uri, '/');
	assert(method != NULL);

	if (method[1] == '\0') {
		http_response_error(context, ERRCODE_PROTOCOL);
		return 0;
	}

	method++;

	if (!is_http_login(context)) {
		printf("not login the server\n");
		is_login = 0;
	}
	else {
		printf("have logined\n");
		is_login = 1;
	}

	/* need check it every time */
	if ((is_login == 0) && strcmp(method, "login") != 0) {
		/* not logined and not a login request */
		//printf("not logined and not a login request\n");
		http_response_error(context, ERRCODE_NOT_LOGIN);

		return 0;
	}

	for (i = 0; i < dispatch_table_size; i++) {
		if (strcmp(method, dispatch_table[i].method) == 0) {
			rc = dispatch_table[i].callback(context);

			if (rc < 0) {
				/* some error */				
				http_response_error(context, rc);		
			}

			break;
		}
	}

	if (i == dispatch_table_size) {
		http_response_error(context, ERRCODE_PROTOCOL);
	}

	return 0;
}



static void http_callback_by_xhttpd(xhttpd_http_t *http)
{
	HttpContext *context = (HttpContext *)(http->user_data);

	assert(context != NULL);

	context->http = http;

	http_dispatch(context);

	close(http->socket);

	free(http->req.buf);

	free(http);
}

static xhttpd_t *http_int_by_xhttpd(HttpContext *context)
{
	xhttpd_t *xhttpd = NULL;
	int rc = 0;
	struct sockaddr_in addr;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(8888);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	rc = xhttpd_init(&xhttpd, context, 
		http_callback_by_xhttpd,
		(struct sockaddr *)&addr, sizeof(addr));
	if (rc != 0) {
		printf("init xhttpd server failed\n");
		return NULL;
	}

	return xhttpd;
}


static void http_exit_by_xhttpd(xhttpd_t *xhttp)
{
	xhttpd_exit(xhttp);
}

static int http_response_by_xhttpd(HttpContext *http, const char *body, int bodylen)
{
	char head[1024] = {0};
	int ret;
	xhttpd_http_t *xhttp = (xhttpd_http_t *)(http->http);
	int socket = xhttp->socket;

	ret = snprintf(head, sizeof(head),
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: application/json;charset=utf-8\r\n"
		"Content-Length: %d\r\n"
		"Connection: close\r\n"
		"\r\n",
		bodylen
	);

	send(socket, head, ret, MSG_NOSIGNAL);

	if (body || bodylen > 0) {
		send(socket, body, bodylen, MSG_NOSIGNAL);
	}
}

/**
 * @brief HTTP主循环
 *
 * @param context HTTP上下文
 *
 * @return 0 成功，其他失败
 */
int http_loop(HttpContext *context)
{
	xhttpd_t *xhttpd = NULL;
	xhttpd = http_int_by_xhttpd(context);

	if (xhttpd == NULL) {
		printf("init http server failed\n");
		return -1;
	}

	xhttpd_loop(xhttpd);

	http_exit_by_xhttpd(xhttpd);
	xhttpd = NULL;

	return 0;
}

