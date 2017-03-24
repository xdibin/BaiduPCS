#ifndef XHTTPD_H_
#define XHTTPD_H_ 1

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define XHTTPD_PARAMETER_MAX	        32

#define XHTTPD_PARAMETER_LEN_MAX	    4096

#define XHTTPD_REQUEST_SIZE_DEFAULT     (4096)

#define XHTTPD_REQUEST_SIZE_LIMIT       (2 * 1024 * 1024 - 1)         
#define XHTTP_REQUEST_MORE_DATA         (0x7fffffff)

#define XHTTPD_RESPONSE_PRE_PADDING     (LWS_PRE + 1024)

#define XHTTPD_RESPONSE_HEAD_SIZE       (XHTTPD_RESPONSE_PRE_PADDING)

#define XHTTPD_MIME_TYPE_JSON           "application/json; charset=utf-8"

#define XHTTPD_CONNECTOR_SIZE           (64)

typedef enum {
    XHTTPD_METHOD_NONE = 0,
    XHTTPD_METHOD_GET,
    XHTTPD_METHOD_POST,
    XHTTPD_METHOD_PUT
} xhttp_request_method_t;


typedef enum 
{
    XHTTPD_SOCKET_TYPE_TCP = 0,
    XHTTPD_SOCKET_TYPE_WEBSOCKET,

    XHTTPD_SOCKET_TYPE_MAX
} xhttpd_socket_type_t;


#include "ev.h"

#define XHTTPD_LOOP_FORVER		0
#define XHTTPD_LOOP_NOWAIT		EVRUN_NOWAIT 
#define XHTTPD_LOOP_ONCE		EVRUN_ONCE

typedef struct xhttpd_parameter {
	char *key;
	int key_len;
	char *value;
	int value_len;
} xhttpd_parameter_t;

typedef struct xhttpd_buf_s {
    char *buf;      /* the buffer base */
    int capacity;   /* the total bytes of buf memory alloced */
    int size;       /* current used bytes in buffer */
} xhttpd_buf_t;

typedef struct xhttpd_http {
    int socket;	
	int state;      

    xhttp_request_method_t method;
	xhttpd_buf_t req;

	xhttpd_parameter_t parameters[XHTTPD_PARAMETER_MAX];
	int para_cnt;

	char *uri;
	char *content;
	int content_len;
    int more_size; 
	void *user_data;
} xhttpd_http_t;

typedef struct xhttpd_s {
	void *loop;
	void *watcher;
	void *user_data;
	ev_signal sigint_watcher;
	void (*sighandle_callback)(int signo);
	void (*get_requst_callback)(xhttpd_http_t *http);
} xhttpd_t;

int xhttpd_url_decode(const char *src, int src_len, char *dst, int dst_len, int is_form_url_encoded);

const char *xhttpd_status_code_to_str(int status_code);

int xhttpd_send(int socket, int status_code, 
    const char *mime_type, const char *body, int body_len);

int xhttpd_send_error(int socket, int status_code);

int xhttpd_send_error_msg(int socket, int status_code, char *msg);

const char *xhttpd_parameter_get(xhttpd_http_t *http, const char *key);

int xhttpd_init(xhttpd_t **xhttp, void *user_data,
	void (*get_requst_callback)(xhttpd_http_t *http),
	const struct sockaddr *addr, int addr_len,
	void (*sighandle_callback)(int signo));

int xhttpd_loop(xhttpd_t *xhttp);

void xhttpd_exit(xhttpd_t *xhttp);

#endif
