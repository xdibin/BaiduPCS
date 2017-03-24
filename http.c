#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <locale.h>
#include <time.h>

#include <signal.h>

#include "cJSON.h"
#include "utils.h"

#include "http.h"
#include "dispatch.h"
#include "pcs_log.h"
#include "task.h"

/** 整个进程是否运行的标志，运行:1，收到退出信号置为0 */
volatile int g_pcs_running = 1;


static void signal_handle(int signo)
{
	fprintf(stderr, "%s %d signal handle called, signal = %d\n", __FILE__, __LINE__, signo);

	if (signo == SIGINT || signo == SIGTERM) {
		g_pcs_running = 0;
	}
}



/*把上下文转换为字符串*/
static char *httpcontext2str(HttpContext *context)
{
	char *json;
	cJSON *root, *item;

	root = cJSON_CreateObject();
	assert(root);

	item = cJSON_CreateString(context->cookiefile);
	assert(item);
	cJSON_AddItemToObject(root, "cookiefile", item);

	item = cJSON_CreateString(context->captchafile);
	assert(item);
	cJSON_AddItemToObject(root, "captchafile", item);

	item = cJSON_CreateString(context->workdir);
	assert(item);
	cJSON_AddItemToObject(root, "workdir", item);

	item = cJSON_CreateNumber((double)context->list_page_size);
	assert(item);
	cJSON_AddItemToObject(root, "list_page_size", item);

	item = cJSON_CreateString(context->list_sort_name);
	assert(item);
	cJSON_AddItemToObject(root, "list_sort_name", item);

	item = cJSON_CreateString(context->list_sort_direction);
	assert(item);
	cJSON_AddItemToObject(root, "list_sort_direction", item);

	item = cJSON_CreateString(context->secure_method);
	assert(item);
	cJSON_AddItemToObject(root, "secure_method", item);

	item = cJSON_CreateString(context->secure_key);
	assert(item);
	cJSON_AddItemToObject(root, "secure_key", item);

	item = cJSON_CreateBool(context->secure_enable);
	assert(item);
	cJSON_AddItemToObject(root, "secure_enable", item);

	item = cJSON_CreateBool(context->timeout_retry);
	assert(item);
	cJSON_AddItemToObject(root, "timeout_retry", item);

	item = cJSON_CreateNumber(context->max_thread);
	assert(item);
	cJSON_AddItemToObject(root, "max_thread", item);

	item = cJSON_CreateNumber(context->max_speed_per_thread);
	assert(item);
	cJSON_AddItemToObject(root, "max_speed_per_thread", item);

	item = cJSON_CreateNumber(context->max_upload_speed_per_thread);
	assert(item);
	cJSON_AddItemToObject(root, "max_upload_speed_per_thread", item);

	item = cJSON_CreateString(context->user_agent);
	assert(item);
	cJSON_AddItemToObject(root, "user_agent", item);

	json = cJSON_Print(root);
	assert(json);

	cJSON_Delete(root);
	return json;
}

/*保存上下文*/
static void save_http_context(HttpContext *context)
{
	const char *filename;
	char *json;
	FILE *pf;

	json = httpcontext2str(context);
	assert(json);

	filename = context->contextfile;
	pf = fopen(filename, "wb");
	if (!pf) {
		pcs_log("Error: Can't open the file: %s\n", filename);
		pcs_free(json);
		return;
	}
	fwrite(json, 1, strlen(json), pf);
	fclose(pf);
	pcs_free(json);
}

/*还原保存的上下文。
成功返回0，失败返回非0值。*/
static int restore_http_context(HttpContext *context, const char *filename)
{
	char *filecontent = NULL;
	int filesize = 0;
	cJSON *root, *item;

	if (!filename) {
		filename = context->contextfile;
	}
	else {
		if (context->contextfile) pcs_free(context->contextfile);
#ifdef WIN32
		context->contextfile = pcs_utils_strdup(filename);
#else
		/* Can't open the path that start with '~/'. why? It's not good, but work. */
		if (filename[0] == '~' && filename[1] == '/') {
			static char tmp[1024] = { 0 };
			strcpy(tmp, getenv("HOME"));
			strcat(tmp, filename + 1);
			context->contextfile = pcs_utils_strdup(tmp);
		}
		else {
			context->contextfile = pcs_utils_strdup(filename);
		}
#endif
	}
	pcs_log("context file is %s\n", context->contextfile);
	filesize = read_file(context->contextfile, &filecontent);
	if (filesize <= 0) {
		pcs_log("Error: Can't read the context file (%s).\n", context->contextfile);
		if (filecontent) pcs_free(filecontent);
		return -1;
	}
	root = cJSON_Parse(filecontent);
	if (!root) {
		pcs_log("Error: Broken context file (%s).\n", context->contextfile);
		pcs_free(filecontent);
		return -1;
	}

	item = cJSON_GetObjectItem(root, "cookiefile");
	if (item && item->valuestring && item->valuestring[0]) {
		if (!is_absolute_path(item->valuestring)) {
			pcs_log("warning: Invalid context.cookiefile, the value should be absolute path, use default value: %s.\n", context->cookiefile);
		}
		else {
			if (context->cookiefile) pcs_free(context->cookiefile);
			context->cookiefile = pcs_utils_strdup(item->valuestring);
		}
	}
	pcs_log("cookie file is '%s'\n", context->cookiefile);

	item = cJSON_GetObjectItem(root, "captchafile");
	if (item && item->valuestring && item->valuestring[0]) {
		if (!is_absolute_path(item->valuestring)) {
			pcs_log("warning: Invalid context.captchafile, the value should be absolute path, use default value: %s.\n", context->captchafile);
		}
		else {
			if (context->captchafile) pcs_free(context->captchafile);
			context->captchafile = pcs_utils_strdup(item->valuestring);
		}
	}

	item = cJSON_GetObjectItem(root, "workdir");
	if (item && item->valuestring && item->valuestring[0]) {
		if (item->valuestring[0] != '/') {
			pcs_log("warning: Invalid context.workdir, the value should be absolute path, use default value: %s.\n", context->workdir);
		}
		else {
			if (context->workdir) pcs_free(context->workdir);
			context->workdir = pcs_utils_strdup(item->valuestring);
		}
	}

	item = cJSON_GetObjectItem(root, "list_page_size");
	if (item) {
		if (((int)item->valueint) < 1) {
			pcs_log("warning: Invalid context.list_page_size, the value should be great than 0, use default value: %d.\n", context->list_page_size);
		}
		else {
			context->list_page_size = (int)item->valueint;
		}
	}

	item = cJSON_GetObjectItem(root, "list_sort_name");
	if (item && item->valuestring && item->valuestring[0]) {
		if (strcmp(item->valuestring, "name") && strcmp(item->valuestring, "time") && strcmp(item->valuestring, "size")) {
			pcs_log("warning: Invalid context.list_sort_name, the value should be one of [name|time|size], use default value: %s.\n", context->list_sort_name);
		}
		else {
			if (context->list_sort_name) pcs_free(context->list_sort_name);
			context->list_sort_name = pcs_utils_strdup(item->valuestring);
		}
	}

	item = cJSON_GetObjectItem(root, "list_sort_direction");
	if (item && item->valuestring && item->valuestring[0]) {
		if (strcmp(item->valuestring, "asc") && strcmp(item->valuestring, "desc")) {
			pcs_log("warning: Invalid context.list_sort_direction, the value should be one of [asc|desc], use default value: %s.\n", context->list_sort_direction);
		}
		else {
			if (context->list_sort_direction) pcs_free(context->list_sort_direction);
			context->list_sort_direction = pcs_utils_strdup(item->valuestring);
		}
	}

	item = cJSON_GetObjectItem(root, "secure_method");
	if (item && item->valuestring && item->valuestring[0]) {
		if (strcmp(item->valuestring, "plaintext") && strcmp(item->valuestring, "aes-cbc-128") && strcmp(item->valuestring, "aes-cbc-192") && strcmp(item->valuestring, "aes-cbc-256")) {
			pcs_log("warning: Invalid context.secure_method, the value should be one of [plaintext|aes-cbc-128|aes-cbc-192|aes-cbc-256], use default value: %s.\n", context->secure_method);
		}
		else {
			if (context->secure_method) pcs_free(context->secure_method);
			context->secure_method = pcs_utils_strdup(item->valuestring);
		}
	}

	item = cJSON_GetObjectItem(root, "secure_key");
	if (item && item->valuestring && item->valuestring[0]) {
		if (context->secure_key) pcs_free(context->secure_key);
		context->secure_key = pcs_utils_strdup(item->valuestring);
	}

	item = cJSON_GetObjectItem(root, "secure_enable");
	if (item) {
		context->secure_enable = item->valueint ? 1 : 0;
	}

	item = cJSON_GetObjectItem(root, "timeout_retry");
	if (item) {
		context->timeout_retry = item->valueint ? 1 : 0;
	}

	item = cJSON_GetObjectItem(root, "max_thread");
	if (item) {
		if (((int)item->valueint) < 1) {
			pcs_log("warning: Invalid context.max_thread, the value should be great than 0, use default value: %d.\n", context->max_thread);
		}
		else {
			context->max_thread = (int)item->valueint;
		}
	}

	item = cJSON_GetObjectItem(root, "max_speed_per_thread");
	if (item) {
		if (((int)item->valueint) < 0) {
			pcs_log("warning: Invalid context.max_speed_per_thread, the value should be >= 0, use default value: %d.\n", context->max_speed_per_thread);
		}
		else {
			context->max_speed_per_thread = (int)item->valueint;
		}
	}

	item = cJSON_GetObjectItem(root, "max_upload_speed_per_thread");
	if (item) {
		if (((int)item->valueint) < 0) {
			pcs_log("warning: Invalid context.max_upload_speed_per_thread, the value should be >= 0, use default value: %d.\n", context->max_upload_speed_per_thread);
		}
		else {
			context->max_upload_speed_per_thread = (int)item->valueint;
		}
	}

	item = cJSON_GetObjectItem(root, "user_agent");
	if (item && item->valuestring && item->valuestring[0]) {
		if (context->user_agent) pcs_free(context->user_agent);
		context->user_agent = pcs_utils_strdup(item->valuestring);
	}

	cJSON_Delete(root);
	pcs_free(filecontent);
	return 0;
}

/*初始化上下文*/
static void init_http_context(HttpContext *context)
{
	memset(context, 0, sizeof(HttpContext));
	context->contextfile = pcs_utils_strdup(CONTEXT_FILE_DEFAULT);
	context->cookiefile = pcs_utils_strdup(COOKIE_FILE_DEFAULT);
	context->captchafile = pcs_utils_strdup(CAPTCH_FILE_DEFAULT);
	context->workdir = pcs_utils_strdup("/");
	context->list_page_size = LIST_PAGE_SIZE_DEFAULT;
	context->list_sort_name = pcs_utils_strdup("name");
	context->list_sort_direction = pcs_utils_strdup("asc");
	
	context->secure_method = pcs_utils_strdup("plaintext");
	context->secure_key = pcs_utils_strdup("");
	context->secure_enable = 0;

	context->timeout_retry = 1;
	context->max_thread = 1;
	context->max_speed_per_thread = 0;
	context->max_upload_speed_per_thread = 0;

	context->subtask_max = SUBTASK_MAX;
	context->file_slice_size_min = FILE_SLICE_MIN;

	context->user_agent = pcs_utils_strdup(USAGE);

	context->sig_handle = signal_handle;
}

/*释放上下文*/
static void free_http_context(HttpContext *context)
{
	if (context->cookiefile) pcs_free(context->cookiefile);
	if (context->captchafile) pcs_free(context->captchafile);
	if (context->workdir) pcs_free(context->workdir);
	if (context->list_sort_name) pcs_free(context->list_sort_name);
	if (context->list_sort_direction) pcs_free(context->list_sort_direction);
	if (context->secure_method) pcs_free(context->secure_method);
	if (context->secure_key) pcs_free(context->secure_key);
	if (context->contextfile) pcs_free(context->contextfile);
	if (context->user_agent) pcs_free(context->user_agent);
	if (context->gid) pcs_free(context->gid);
	memset(context, 0, sizeof(HttpContext));
}

/*初始化PCS*/
static Pcs *create_http_pcs(HttpContext *context)
{
	Pcs *pcs = pcs_create(context->cookiefile);
	if (!pcs) return NULL;
	char *gid = pcs_utils_gid();
	pcs_setopt(pcs, PCS_OPTION_GID, gid);
	context->gid = gid;
	pcs_setopt(pcs, PCS_OPTION_TIMEOUT, (void *)((long)HTTP_TIMEOUT));
	pcs_setopt(pcs, PCS_OPTION_CONNECTTIMEOUT, (void *)((long)HTTP_CONNECT_TIMEOUT));
	//pcs_setopt(pcs, PCS_OPTION_CAPTCHA_FUNCTION, (void *)&verifycode);
	//pcs_setopt(pcs, PCS_OPTION_CAPTCHA_FUNCTION_DATA, (void *)context);
    //pcs_setopt(pcs, PCS_OPTION_INPUT_FUNCTION, (void *)&input_str);
    //pcs_setopt(pcs, PCS_OPTION_INPUT_FUNCTION_DATA, (void *)context);
	// pcs_setopts(pcs,
	// 	PCS_OPTION_PROGRESS_FUNCTION, (void *)&upload_progress,
	// 	PCS_OPTION_PROGRESS, (void *)((long)PcsFalse),
	// 	PCS_OPTION_USAGE, (void*)context->user_agent,
	// 	//PCS_OPTION_TIMEOUT, (void *)((long)TIMEOUT),
	// 	PCS_OPTION_CONNECTTIMEOUT, (void *)((long)CONNECTTIMEOUT),
	// 	PCS_OPTION_END);
	return pcs;
}

static void destroy_http_pcs(Pcs *pcs)
{
	pcs_destroy(pcs);
}

/*hood cJSON 库中分配内存的方法，用于检查内存泄漏*/
static void hook_cjson()
{
	cJSON_Hooks hooks = { 0 };
#if defined(DEBUG) || defined(_DEBUG)
	hooks.malloc_fn = &pcs_mem_malloc_arg1;
	hooks.free_fn = &pcs_mem_free;
#else

#endif
	cJSON_InitHooks(&hooks);
}


/**
 * make -f Makefile.http clean; make -f Makefile.http ver=debug
 */
int main(int argc, char *argv[])
{
	HttpContext context;
	int rc = 0;

	setlocale(LC_ALL, "");

	pcs_log("main start\n");

	srandom((unsigned int)(time(NULL)));

	signal(SIGTERM, signal_handle);
	signal(SIGPIPE, SIG_IGN);

	/* Must initialize libcurl before any threads are started */ 
	curl_global_init(CURL_GLOBAL_ALL);

	hook_cjson();
	
	init_http_context(&context);

	pcs_log("restore http context\n");
	rc = restore_http_context(&context, NULL);
	
	if (rc != 0) {
		pcs_log("restore http context failed, use default\n");
		free_http_context(&context);
		init_http_context(&context);
	}

	pcs_log("create pcs\n");
	context.pcs = create_http_pcs(&context);
	if (!context.pcs) {
		pcs_log("Can't create pcs context.\n");
		return -1;
	}
	
	task_list_init();
	
	http_loop(&context);

	pcs_log("pcs exiting\n");

	task_list_exit();

	destroy_http_pcs(context.pcs);

	save_http_context(&context);

	free_http_context(&context);

	curl_global_cleanup();

	pcs_print_leak();

	pcs_log("pcs exited\n");

	return 0;
}


