#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cJSON.h"

#include "dispatch.h"
#include "utils_print.h"
#include "error_code.h"
#include "task.h"
#include "pcs_log.h"
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

	pcs_log("enter\n");

	xhttpd_http_t *xhttp = (xhttpd_http_t *)(context->http);
	if (!xhttp || xhttp->method != XHTTPD_METHOD_POST || !(xhttp->content)) {
		pcs_log("must post and json context\n");
		return ERRCODE_ARG;
	}

	/* get username and password */
	cJSON *item = NULL;
	cJSON *root = cJSON_Parse(xhttp->content);
	if (!root) {
		pcs_log("parse json failed, %s\n", xhttp->content);
		return ERRCODE_ARG;
	}

	item = cJSON_GetObjectItem(root, "username");
	if (item && item->type == cJSON_String && item->valuestring && *(item->valuestring)) {
		username = pcs_utils_strdup(item->valuestring);
	}

	item = cJSON_GetObjectItem(root, "password");
	if (item && item->type == cJSON_String && item->valuestring && *(item->valuestring)) {
		password = pcs_utils_strdup(item->valuestring);
	}	

	cJSON_Delete(root);

	if (!username || !*username || !password || !*password) {
		pcs_log("need username and password parameters\n");
		return ERRCODE_ARG;
	}

	pcs_log("username = '%s'\n", username);
	pcs_log("password = '%s'\n", password);

	/* save the username and password */
	pcs_setopt(context->pcs, PCS_OPTION_USERNAME, username);
	pcs_setopt(context->pcs, PCS_OPTION_PASSWORD, password);

	pcsres = pcs_login(context->pcs);
	if (pcsres != PCS_OK) {
		pcs_log("Login Failed: %s\n", pcs_strerror(context->pcs));
		return ERRCODE_UNKNOWN;
	}
	pcs_log("Login Success. UID: %s\n", pcs_sysUID(context->pcs));

	pcs_cookie_flush(context->pcs);

	char buf[512];
	int len = 0;

	len = snprintf(buf, sizeof(buf), "{\"errno\":0}");

	pcs_log("json response is '%s', len = %d\n", buf, len);

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

	pcs_log("response is '%s', len = %d\n", buf, len);

	http_response_by_xhttpd(context, buf, len);

	return 0;
}

static int callback_logout(HttpContext *context)
{
	PcsRes pcsres = 0;
	
	pcsres = pcs_logout(context->pcs);
	if (pcsres != PCS_OK) {
		pcs_log("Logout Fail: %s\n", pcs_strerror(context->pcs));

		return ERRCODE_UNKNOWN;
	}

	pcs_log("Logout Success.\n");

	pcs_cookie_flush(context->pcs);

	char buf[512];
	int len = 0;

	len = snprintf(buf, sizeof(buf), "{\"errno\":0}");

	pcs_log("json response is '%s', len = %d\n", buf, len);

	http_response_by_xhttpd(context, buf, len);

	return 0;	
}


static int json_list_file_init(char **json, int *capacity, int *remain)
{
	char *buf = NULL;

	pcs_log("init the list file json\n");

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

	pcs_log("end the list file json\n");

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
	pcs_log("free the list file json\n");
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

	pcs_log("add a list file json\n");

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

	pcs_log("try to list %s\n", dir);

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

	pcs_log("json response is '%s', len = %d\n", json, rc);

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
		pcs_log("Error: The target not exist, or have error: %s\n", pcs_strerror(context->pcs));
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

	pcs_log("response is '%s', len = %d\n", buf, len);

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
		pcs_log("Error: %s\n", pcs_strerror(context->pcs));
		return ERRCODE_UNKNOWN;
	}

	memset(buf, 0, sizeof(buf));
	len = snprintf(buf, sizeof(buf), "{\"errno\":0,\"total\":%lld,\"used\":%lld}",
		quota, used);

	pcs_log("response is '%s', len = %d\n", buf, len);

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
	char *lpath = NULL;

	int err = 0;
	int ret = ERRCODE_UNKNOWN;

	int64_t length = 0;
	int64_t offset = 0;
	int force = 0;

	xhttpd_http_t *xhttp = (xhttpd_http_t *)(context->http);
	if (!xhttp || xhttp->method != XHTTPD_METHOD_POST || !(xhttp->content)) {
		pcs_log("must post and json context\n");
		return ERRCODE_ARG;
	}

	cJSON *root = NULL;
	cJSON *array = NULL;
	cJSON *list = NULL;
	cJSON *item = NULL;
	int array_size = 0;

	root = cJSON_Parse(xhttp->content);
	if (!root) {
		pcs_log("parse json failed, %s\n", xhttp->content);
		return ERRCODE_ARG;
	}

	array = cJSON_GetObjectItem(root, "list");
	if (!array && array->type != cJSON_Array) {
		cJSON_Delete(root);
		return ERRCODE_ARG;
	}

	array_size = cJSON_GetArraySize(array);

	if (array_size <= 0) {
		cJSON_Delete(root);
		return ERRCODE_ARG;
	} else if (array_size > 1) {
		pcs_log("only support one task to download now\n");
	}

	list = array->child;

	item = cJSON_GetObjectItem(list, "rpath");
	if (item && item->type == cJSON_String && item->valuestring && *(item->valuestring)) {
		rpath = pcs_utils_strdup(item->valuestring);
	}

	item = cJSON_GetObjectItem(list, "ldir");
	if (item && item->type == cJSON_String && item->valuestring && *(item->valuestring)) {
		ldir = pcs_utils_strdup(item->valuestring);
	}

	item = cJSON_GetObjectItem(list, "lname");
	if (item && item->type == cJSON_String && item->valuestring && *(item->valuestring)) {
		lname = pcs_utils_strdup(item->valuestring);
	}

	item = cJSON_GetObjectItem(list, "offset");
	if (item && item->type == cJSON_Number) {
		offset = item->valueint;
	}

	item = cJSON_GetObjectItem(list, "length");
	if (item && item->type == cJSON_Number) {
		length = item->valueint;
	}

	item = cJSON_GetObjectItem(list, "force");
	if (item && item->type == cJSON_Number) {
		force = item->valueint;
	}

	cJSON_Delete(root);

	/* check arguments */
	if (!rpath || (rpath[0] != '/') || ( rpath[1] == '\0') ||
		!ldir || (ldir[0] != '/') || (ldir[1] == '\0') ||
		offset < 0 ||
		length < 0 ||
		(force != 0 && force != 1)
	) {
		ret = ERRCODE_ARG;
		goto download_out;
	}

	if (!lname || !*lname) {
		char *rr = strrchr(rpath, '/');
		if (!rr) {
			ret = ERRCODE_ARG;
			goto download_out;
		}
		lname = pcs_utils_strdup(rr + 1);
	}

	int lpath_len = strlen(ldir) + strlen(lname) + 2;
	
	lpath = (char *)pcs_malloc(lpath_len);
	if (!lpath) {
		ret = ERRCODE_MEMORY;
		goto download_out;
	}

	snprintf(lpath, lpath_len, "%s/%s", ldir, lname);

	struct stat st;
	if (stat(ldir, &st) == -1) {
		err = errno;
		if (err != ENOENT) {
			pcs_log("stat ldir failed, %s, %s\n", ldir, strerror(err));
			ret = ERRCODE_LOCAL_FILE;
			goto download_out;
		} else {
			/* create the dir */
			pcs_log("dir not exist\n");
			ret = ERRCODE_LOCAL_FILE;
			goto download_out;
		}
	} else {
		if (!S_ISDIR(st.st_mode)) {
			/* not a dir */
			ret = ERRCODE_LOCAL_FILE;
			goto download_out;
		}
	}

	pcs_free(ldir);
	ldir = NULL;

	if (stat(lpath, &st) == 0) {
		if (!S_ISREG(st.st_mode)) {
			/* not a file */
			ret = ERRCODE_LOCAL_FILE;
			goto download_out;
		} else {
			/* check force overwrite flag is set or not ? */
			if (force == 0) {
				pcs_log("file exist not force overwrite is not set!\n");
				ret =  ERRCODE_LOCAL_FILE;
				goto download_out;
			} else {
				/* remove the local file */
				unlink(lpath);
				if (access(lpath, F_OK) == 0) {
					ret =  ERRCODE_LOCAL_FILE;
					goto download_out;
				}
			}
		}
	}

	pcs_log("rpath = %s, lpath = %s\n", rpath, lpath);

	/* check remote file */
	PcsFileInfo *meta = pcs_meta(context->pcs, rpath);
	if (!meta) {
		ret = ERRCODE_REMOTE_FILE;
		goto download_out;
	}

	if (meta->isdir) {
		pcs_log("not support of dir download\n");
		ret = ERRCODE_REMOTE_FILE;
		goto download_out;
	}

	ret = task_add(context, rpath, meta->md5, (uint64_t)(meta->size), lpath);

	char buf[512];
	int len = 0;

	memset(buf, 0, sizeof(buf));
	len = snprintf(buf, sizeof(buf), "{\"errno\":%d}", ret);

	pcs_log("response is '%s', len = %d\n", buf, len);

	http_response_by_xhttpd(context, buf, len);	

download_out:
	if (rpath) pcs_free(rpath);
	if (lpath) pcs_free(lpath);
	if (lname) pcs_free(lname);
	if (ldir) pcs_free(ldir);
	if (meta) pcs_fileinfo_destroy(meta);

	return ret;
}

static void http_response_error(HttpContext *context, int error_code)
{
	char buf[1024];
	int len = 0;

	memset(buf, 0, sizeof(buf));

	len = snprintf(buf, sizeof(buf), "{\"errno\":%d}", error_code);

	pcs_log("error code = %d, response = %s\n", error_code, buf);

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
	pcs_log("uri = '%s'\n", http->uri);

	method = strrchr(http->uri, '/');
	assert(method != NULL);

	if (method[1] == '\0') {
		http_response_error(context, ERRCODE_PROTOCOL);
		return 0;
	}

	method++;

	if (!is_http_login(context)) {
		pcs_log("not login the server\n");
		is_login = 0;
	}
	else {
		pcs_log("have logined\n");
		is_login = 1;
	}

	/* need check it every time */
	if ((is_login == 0) && strcmp(method, "login") != 0) {
		/* not logined and not a login request */
		pcs_log("not logined and not a login request\n");
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

	pcs_log("init http by xhttpd backend\n");

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(8888);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	rc = xhttpd_init(&xhttpd, context, 
		http_callback_by_xhttpd,
		(struct sockaddr *)&addr, sizeof(addr));
	if (rc != 0) {
		pcs_log("init xhttpd server failed\n");
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

	pcs_log("xhttpd looping ...\n");
	xhttpd_loop(xhttpd);

	http_exit_by_xhttpd(xhttpd);
	xhttpd = NULL;

	return 0;
}

