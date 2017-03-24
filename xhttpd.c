#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <assert.h>


#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>


#include "ev.h"

#include "xhttpd.h"






int xhttpd_url_decode(const char *src, int src_len, char *dst, int dst_len, int is_form_url_encoded)
{
    int i, j, a, b;
   
    #ifdef HEXTOI
        #undef HEXTOI
    #endif
    #define HEXTOI(x) (isdigit(x) ? x - '0' : x - 'W')

    for (i = j = 0; i < src_len && j < dst_len - 1; i++, j++) {
        if (src[i] == '%') {
            if (i < src_len - 2 && isxdigit(*(const unsigned char *) (src + i + 1)) &&
                isxdigit(*(const unsigned char *) (src + i + 2))) {
                a = tolower(*(const unsigned char *) (src + i + 1));
                b = tolower(*(const unsigned char *) (src + i + 2));
                dst[j] = (char) ((HEXTOI(a) << 4) | HEXTOI(b));
                i += 2;
            } else {
                return -1;
            }
        } else if (is_form_url_encoded && src[i] == '+') {
            dst[j] = ' ';
        } else {
            dst[j] = src[i];
        }
    }

    dst[j] = '\0'; /* Null-terminate the destination */

    #undef HEXTOI
    
    return i >= src_len ? j : -1;
}

const char *xhttpd_status_code_to_str(int status_code)
{
    
    const char *status_message = NULL;
    
    switch (status_code) {
    case 200:
        status_message = "OK";
        break;
    case 206:
        status_message = "Partial Content";
        break;
    case 301:
        status_message = "Moved";
        break;
    case 302:
        status_message = "Found";
        break;
    case 401:
        status_message = "Unauthorized";
        break;
    case 403:
        status_message = "Forbidden";
        break;
    case 404:
        status_message = "Not Found";
        break;
    case 405:
        status_message = "Method not allowed";
        break;
    case 414:
        status_message = "414 Request-URI Too Long";
        break;        
    case 416:
        status_message = "Requested range not satisfiable";
        break;
    case 418:
        status_message = "I'm a teapot";
        break;
    case 500:
        status_message = "Internal Server Error";
        break;
    default:
        status_message = "Internal Server Error";
        break;
    }
    
    return status_message;
}

void xhttpd_setnonblock(int fd)
{
  int flags;
  
  flags = fcntl(fd, F_GETFL);
  flags |= O_NONBLOCK;
  fcntl(fd, F_SETFL, flags);
}

int xhttpd_sendn(int sock, const void *buff, int size, int timeout_ms)
{
    int ret;
    int err;
	const char *base = (const char *)buff;
	int send_cnt = 0;
    int tritimes = 1000;

    if (sock < 0 || buff == NULL || size <= 0 || timeout_ms <= 0) {
        printf("http: invalid arguments\n");
        return -1;
    }

    fd_set wrset;

    struct timeval time_val;

    time_val.tv_sec = timeout_ms / 1000;
    time_val.tv_usec = timeout_ms % 1000;    
	
	for (send_cnt = 0; send_cnt < size && tritimes > 0 
        && (time_val.tv_sec + time_val.tv_usec) > 0; tritimes--) {
		/* send the file to remote server
		 * NOTE: the remote socket may unblocked, so the tcp socket buffer may full when write too much data
		 */
	    FD_ZERO(&wrset);
    	FD_SET(sock, &wrset);

		if ((ret = select(sock + 1, NULL, &wrset, NULL, &time_val)) == -1) {
			err = errno;
            printf("http: select return error, %s\n", strerror(err));
			return send_cnt;
		}
  
		if (ret == 0) {
			/* timeouted */
            printf("http: select timeout\n");
			return send_cnt;
		}

		if (FD_ISSET(sock, &wrset)) {
			/* socket writeable, send the data now */
			if ((ret = send(sock, base + send_cnt, size - send_cnt, MSG_DONTWAIT | MSG_NOSIGNAL)) == -1) {
				err = errno;
				if (err == EAGAIN || err == EWOULDBLOCK) {
					continue;
				}
               	printf("http: send return error, %s\n", strerror(err));
				return send_cnt;
			}
			
			/* check send truncate  */
			send_cnt += ret;
		}
		
	}	

    return send_cnt;
}


int xhttpd_send(int socket, int status_code, 
    const char *mime_type, const char *body, int body_len)
{
    if (socket <= -1 || status_code <= 0) {
        printf("http: xhttpd_send invalid argument\n");
        return -1;
    }
    
    int ret;
    
    char head[1024] = {0};
    
    if (mime_type == NULL) {
        mime_type = "application/octet-stream";
    }
    
    if (body == NULL) {
        body_len = 0;
    }
    
    const char *status_str = xhttpd_status_code_to_str(status_code);
    
    ret = snprintf(head, sizeof(head), 
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
  		"access-control-allow-origin: http://pan.xzb.xunlei.com\r\n"
		"access-control-allow-credentials: true\r\n"
		"access-control-allow-methods: GET,POST,OPTIONS\r\n"
		"access-control-allow-headers: X-Requested-With, Content-Type\r\n"
		"Cache-Control: max-age=604800\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n",
        status_code, status_str,
        mime_type,
        body_len
    );
    
    xhttpd_sendn(socket, head, ret, 1000);
    
    if (body) {
        xhttpd_sendn(socket, body, body_len, (body_len << 4));
    }
    
    return 0;
}

int xhttpd_send_error(int socket, int status_code)
{
    const char *status_str = xhttpd_status_code_to_str(status_code);
    
    return xhttpd_send(socket, status_code, "text/plain", status_str, strlen(status_str));
}

int xhttpd_send_error_msg(int socket, int status_code, char *msg)
{
	int len = 0;

	if (msg) {
		len = strlen(msg);
	}
	
    return xhttpd_send(socket, status_code, "text/plain", msg, len);
}

#if 0
static void xhttpd_free_watch(struct ev_loop *loop, ev_io *watcher)
{
    xhttpd_http_t *http = (xhttpd_http_t *)(watcher->data);
    if (http) {
        free(http);
    }
	
    ev_io_stop(loop, watcher);
    
    free(watcher);
}
#endif

static int xhttpd_parameter_parse(xhttpd_http_t *http, char *para, char *end)
{
	char *ptr = para;
	char *base = para;
	int i = 0;

	if (!http || !para || !end) {
		return -1;
	}

	//printf("parameter is [%s]\n", para);

	char buf[XHTTPD_PARAMETER_LEN_MAX];
	int ret;

	while (ptr < end && i < XHTTPD_PARAMETER_MAX) {
		for (base = ptr; ptr < end && *ptr != '=' && *ptr != ' '; ptr++)
			;

		if (*ptr != '=') {
			// illegal parameter key
			printf("illegal parameter key, base = %s\n", base);
			ptr++;
			continue;
		}

		*ptr = '\0';
		/* now ptr point the key end */
		http->parameters[i].key_len = ptr - base;
		if (http->parameters[i].key_len >= XHTTPD_PARAMETER_LEN_MAX) {
			return -1;
		}
		
		ret = xhttpd_url_decode(base, http->parameters[i].key_len, buf, XHTTPD_PARAMETER_LEN_MAX, 1);
		if (ret == -1 || ret > http->parameters[i].key_len) {
			return -1;
		}
		strncpy(base, buf, http->parameters[i].key_len);
		http->parameters[i].key = base;
		
		//printf("key = [%s]\n", base);

		/* get the value */
		ptr++;
		for (base = ptr; ptr < end && *ptr != '&' && *ptr != ' '; ptr++)
			;
		
		if (ptr > end) {
			return 0;
		}

		*ptr = '\0';
		/* now ptr point the value end */
		http->parameters[i].value_len = ptr - base;
		if (http->parameters[i].value_len >= XHTTPD_PARAMETER_LEN_MAX) {
			return -1;
		}		
		ret = xhttpd_url_decode(base, http->parameters[i].value_len, buf, XHTTPD_PARAMETER_LEN_MAX, 1);
		if (ret == -1 || ret > http->parameters[i].value_len) {
			return -1;
		}
		strncpy(base, buf, http->parameters[i].value_len);
		http->parameters[i].value = base;
		
		//printf("value = [%s]\n", base);

		i++;

		ptr++;
	}

	http->para_cnt = i;

	//printf("parameters cnt : %d\n", http->para_cnt);
	//for (i = 0; i < http->para_cnt; i++) printf("%s=%s\n", http->parameters[i].key, http->parameters[i].value);

	return 0;
}



/**
 * parse the http request message, assume that the http head in a mbuf
 *
 * Validate the protocol type
 * Validate the HTTP version 1.1
 * Validate the HTTP URL
 * Validate the HTTP content(if any)
 *
 *
 * return, less than zero the http error code
 *           zero all http recved
 *           greater than zero, need more bytes
 */
static int xhttpd_http_parse(xhttpd_http_t *http)
{
    char *base = http->req.buf;
    int size = http->req.size;
	char *ptr = base;
	char *end = ptr + size;
	int any_para = 0;
	char *uri = NULL;
	char *para = NULL;	
	char *para_end = NULL;
	char *http_ver = NULL;
    
	/* allow HTTP GET POST */	
	if (strncmp(ptr, "GET ", 4) == 0) {
		http->method = XHTTPD_METHOD_GET;
	} else if ( strncmp(ptr, "POST ", 5) == 0) {
        http->method = XHTTPD_METHOD_POST;
	} else if ( strncmp(ptr, "PUT ", 4) == 0) {
        http->method = XHTTPD_METHOD_PUT;
	} else {
		printf("http: HTTP method not support");

		return -405;
	}

	/* parse HTTP head */
	while (ptr < end && *ptr != ' ') ptr++;
	uri = ++ptr;

	if (*uri != '/') {
		return -400;
	}

	/* find the uri end : space or '?' */
	while (ptr < end && (*ptr != ' ' && *ptr != '?')) ptr++;
	if (*ptr == '?') {
		any_para = 1;
		para = ptr + 1;
	}
	/* now terminate the uri */
	*ptr++ = '\0';

	//printf("uri is [%s]\n", uri);

	if (any_para == 1) {
		/* find the protocol para end */
		while (ptr < end && *ptr != ' ') ptr++;
		para_end = ptr;
		*ptr++ = '\0';
		http_ver = ptr;
	} else {
		http_ver = ptr;
	}

	if (strncmp(http_ver, "HTTP/", 5) != 0) {
		return -505;				
	}

	if (strncmp(http_ver + 5, "1.1", 3) != 0 &&
		strncmp(http_ver + 5, "1.0", 3) != 0) {
		/* only support HTTP/1.1 and HTTP/1.0 */
		return -505;
	}

	ptr += 8;
	if (strncmp(ptr, "\r\n", 2) != 0) {
		return -400;			
	}
	
	/* parse parameters, if any */
	if (any_para == 1) {
		//parse parameter
		//printf("parse parameters\n");
		if (xhttpd_parameter_parse(http, para, para_end) == -1) {
			return -400;
		}
	}

	http->uri = uri;
	
    /* check if contain content-length */
    if (http->method == XHTTPD_METHOD_POST || http->method == XHTTPD_METHOD_PUT) {
        if ( ptr < end) {
            char *content_length_ptr = NULL;
            int content_length = 0;
            content_length_ptr = strstr(ptr, "Content-Length:");
            if (content_length_ptr == NULL) {
                /* not find content length ? */
                printf("http: POST request but not contains Content-Length\n");
                return -400;
            } else {
                /* get the content length */
                ptr = content_length_ptr + 15;
                while (ptr < end && *ptr != ' ') ptr++;
                content_length = atoi(ptr);
                if (content_length < 0 || content_length > XHTTPD_REQUEST_SIZE_LIMIT) {
                    printf("http: POST Content-Length is invalid, %d\n", content_length);
                    return -400;
                }

                http->content_len = content_length;

                printf("http: POST http content-length is %d\n", http->content_len);

                /* find the HEAD '\r\n\r\n' */
                char *head_end = NULL;
                int head_size = 0;
                int more_size = 0;
                head_end = strstr(ptr, "\r\n\r\n");
                if (head_end == NULL) {
                    printf("http: POST http head imcomplete\n");
                    return -400;
                } else {         
                    head_end += 4;
                    http->content = head_end;
                    head_size = head_end - base;
                    more_size = content_length + head_size - (http->req.size);
                    if (more_size < 0) {
                        /* error */
                        printf("http: POST error, head size %d, content-length %d, recv size %d\n", 
                            head_size, content_length, http->req.size);
                        return -400;
                    } else {
                        http->more_size = more_size;
                        if (more_size > 0) {
                            printf("http: POST need more bytes %d\n", more_size);
                        }
                        return more_size;
                    }
                }
                
            }
        } else {
            return XHTTP_REQUEST_MORE_DATA;
        }
    }



    
	return 0;
}



static void xhttpd_read_callback(struct ev_loop *loop, ev_io *watcher, int revents)
{
    int ret;
    int err;
    int fd = watcher->fd;
    int buf_size = 0;
    xhttpd_http_t *http = NULL;
    
    //printf("some data arrive\n");
    
    if (watcher->data == NULL) {
        //printf("malloc a new http\n");
        
        http = (xhttpd_http_t *)malloc(sizeof(xhttpd_http_t));
        //printf("http %p\n", http);
        if (!http) {
            /* FIXME:  */
            printf("http: malloc failed");
            xhttpd_send_error(fd, 500);

			close(fd);
			ev_io_stop(loop, watcher);			
			free(watcher);

            return;
        }
       
        memset(http, 0, sizeof(xhttpd_http_t));
        
        http->req.buf = malloc(XHTTPD_REQUEST_SIZE_DEFAULT);
		//printf("http->req.buf %p\n", http->req.buf);
        if (http->req.buf == NULL) {
            printf("http: malloc failed\n");
 
            xhttpd_send_error(fd, 500);
 
			close(fd);
			ev_io_stop(loop, watcher); 		 
			free(watcher);
			free(http);
            
            return;
        }
        memset(http->req.buf, 0, XHTTPD_REQUEST_SIZE_DEFAULT);
        http->req.capacity = XHTTPD_REQUEST_SIZE_DEFAULT;
        http->req.size = 0;
        buf_size = XHTTPD_REQUEST_SIZE_DEFAULT - 1;
        
        http->socket = watcher->fd;
		
		xhttpd_t *xhttpd = ev_userdata(loop);
		http->user_data = xhttpd ? xhttpd->user_data : NULL;
        
        watcher->data = http;
    } else {
                
        http = (xhttpd_http_t *)(watcher->data);

       	printf("http: exist a http, %p\n", http);
        
        // FIXME: 
        if (http->req.size >= XHTTPD_REQUEST_SIZE_LIMIT) {
            // overflow
            printf("http: http request overflow\n");
            
            xhttpd_send_error(fd, 500);
            close(http->socket);
			ev_io_stop(loop, watcher);
			free(watcher);
			free(http->req.buf);
			free(http);			
            
            return;
        }
        
        buf_size = http->req.capacity - http->req.size;
        
        if (buf_size <= 16) { /* FIXME: why 16, just test */
            
            // relloc a large buffer
            buf_size = http->more_size;
            int resize = (http->req.size + buf_size + 1);
			if (resize >= XHTTPD_REQUEST_SIZE_LIMIT) {
				resize = XHTTPD_REQUEST_SIZE_LIMIT + 1;
			}
			printf("http: realloc http size to %d\n", resize);
            char *buf_new = realloc(http->req.buf, resize);
            if (buf_new == NULL) {
                printf("http: malloc failed\n");
                xhttpd_send_error(fd, 500);
                close(http->socket);
				ev_io_stop(loop, watcher);
				free(watcher);
				free(http->req.buf);
				free(http); 
                
                return;
            }
            http->req.buf = buf_new;
            memset(buf_new + http->req.size, 0, resize - http->req.size);
            http->req.capacity = resize;
            
        } else {
            //use the pre-alloc buffer
            
            printf("http: use pre-alloc  remain buffer len %d, expect to recv %d\n", buf_size, http->more_size);
        }
    }

    assert(buf_size > 0);

    ret = recv(http->socket, 
        http->req.buf + http->req.size, 
        buf_size, 
        0
    );
    
    if (ret == -1) {
        err = errno;
        printf("http: recv failed, %s\n", strerror(err));
        //xhttpd_send_error(fd, 500); 
        close(http->socket);
		ev_io_stop(loop, watcher);
		free(watcher);
		free(http->req.buf);
		free(http); 

        return;
    } else if (ret == 0) {
        /* client closed */
        printf("http: client closed, http %p\n", http);
        close(http->socket);
		ev_io_stop(loop, watcher);
		free(watcher);
		free(http->req.buf);
		free(http); 

        return;
    }

    //printf("http: recv %d bytes, http %p\n", ret, http);
    
    http->req.size += ret;

    if (http->method == XHTTPD_METHOD_NONE) {
        /* parse the http head */
        ret = xhttpd_http_parse(http);
    } else {
        /* check if we have recv all data */
        if (ret < http->more_size) {
            /* recv more  */
            printf("http: recv a segment %d, more %d\n", ret, http->more_size - ret);
            http->more_size -= ret;
            return;
        } else {
            printf("http: all haved recved\n");

            ret = 0; // set to zero
        }
    }

    if (ret < 0)
    {
        /* parse error */
        
        xhttpd_send_error(http->socket, ret);

        close(http->socket);
        
     	ev_io_stop(loop, watcher);
    	
    	free(watcher); 

		free(http->req.buf);
        
		free(http);        

        return;
    } else if (ret == 0) {
        /* all data have recved, call the user callback now */

        printf("http: all data recved, call user calback\n");
        
        xhttpd_t *xhttp = (xhttpd_t *)ev_userdata(loop);
        
        assert(xhttp != NULL);
        
        assert(xhttp->get_requst_callback != NULL);
        
        xhttp->get_requst_callback(http);

    	ev_io_stop(loop, watcher);
    	
    	free(watcher);
        
        return;
    } else {
        /* wait more data arriave */
        printf("http: wait more data %d, http %p\n", ret, http);
    }
}

/**
 *
 * return -2 port in use, -1 other error
 */
static int xhttpd_init_internal(const struct sockaddr *addr, int addr_len)
{
    int socketlisten;
    int err;
    int reuse;

    socketlisten = socket(addr->sa_family, SOCK_STREAM, 0);
    if (socketlisten == -1) {
        err = errno;
        printf("http: failed to create listen socket, %s\n", strerror(err));
        return -1;
    }

    reuse = 1;
    setsockopt(socketlisten, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));    
    
    if (bind(socketlisten,
        (struct sockaddr *)addr,
        addr_len) == -1) {
        err = errno;
        close(socketlisten);
        printf("http: Failed to bind%s\n", strerror(err));
		if (err == EADDRINUSE) {
			return -2;
		}
        return -1;
    }

    if (listen(socketlisten, 5) == -1) {
        err = errno;
        close(socketlisten);
        printf("http: Failed to listen to socket, %s\n", strerror(err));
        return -1;
    }

    xhttpd_setnonblock(socketlisten);
    
    return socketlisten;
}

static void xhttpd_accept_callback(struct ev_loop *loop, ev_io *watcher, int revents)
{
    int client_fd;
    int err;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    struct ev_io *watcher_client = NULL;

    //printf("new client connecting ...\n");
    
    client_fd = accept(watcher->fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd == -1) {
        err = errno;
        printf("http: Client: accept() failed, %s\n", strerror(err));
        return;
    }

    xhttpd_setnonblock(client_fd);

    watcher_client = (struct ev_io *)malloc(sizeof(struct ev_io));
	//printf("new watcher: %p\n", watcher_client);
    if (watcher_client == NULL) {
        printf("http: malloc failed\n");
        close(client_fd);
        return;
    }
	memset(watcher_client, 0, sizeof(struct ev_io));

    ev_io_init(watcher_client, xhttpd_read_callback, client_fd, EV_READ);
    
    ev_io_start(loop, watcher_client);
}

static void
sigint_cb (struct ev_loop *loop, ev_signal *w, int revents)
{
    xhttpd_t *xhttpd = ev_userdata(loop);

    fprintf(stderr, "%s %d libev signal int calback\n", __FILE__, __LINE__);

    if (xhttpd->sighandle_callback) {
        fprintf(stderr, "call user defined signal handle\n");
        xhttpd->sighandle_callback(SIGINT);
    }

    ev_break (loop, EVBREAK_ALL);  
}

int xhttpd_init(xhttpd_t **xhttp, void *user_data,
	void (*get_requst_callback)(xhttpd_http_t *http),
	const struct sockaddr *addr, int addr_len,
    void (*sighandle_callback)(int signo))
{   
    int xhttpd_listen_socket = -1;
    
	if (!xhttp || !addr || (addr->sa_family != AF_INET && addr->sa_family != AF_UNIX) || addr_len <= 0) {
		printf("http: invalid argument\n");
		return -1;
	}

	xhttpd_t *xhttp_new = malloc(sizeof(xhttpd_t));

	if (!(xhttp_new)) {
		printf("http: malloc failed\n");
		return -1;
	}

	memset(xhttp_new, 0, sizeof(xhttpd_t));
	
	xhttp_new->get_requst_callback = get_requst_callback;

	assert ("libev version mismatch" &&
		(ev_version_major () == EV_VERSION_MAJOR
		&& ev_version_minor () >= EV_VERSION_MINOR));

	assert ("sorry, no epoll support" &&
		(ev_supported_backends () & EVBACKEND_EPOLL));

    ev_io *watcher = malloc(sizeof(ev_io));
	if (!watcher) {	
		printf("malloc failed\n");
		free(xhttp_new);
		return -1;
	}

    struct ev_loop *loop = ev_loop_new(EVBACKEND_EPOLL | EVFLAG_NOENV);

	if (!loop) {
		//printf("http: new loop failed\n");
		free(watcher);
		free(xhttp_new);
		return -1;
	}
	ev_set_userdata(loop, xhttp_new);

    xhttpd_listen_socket = xhttpd_init_internal(addr, addr_len);

    if (xhttpd_listen_socket < 0) {
        //printf("http: xhttpd init failed\n");
		ev_loop_destroy(loop);
		free(watcher);
		free(xhttp_new);
        return xhttpd_listen_socket;
    }

    ev_init(watcher, xhttpd_accept_callback);
    
    ev_io_set(watcher, xhttpd_listen_socket, EV_READ);
    
    ev_io_start(loop, watcher);

	xhttp_new->loop = loop;
	
	xhttp_new->watcher = watcher;
	
	xhttp_new->user_data = user_data;

    xhttp_new->sighandle_callback = sighandle_callback;

	*xhttp = xhttp_new;

    ev_signal_init (&(xhttp_new->sigint_watcher), sigint_cb, SIGINT);
    ev_signal_start (loop, &(xhttp_new->sigint_watcher));    
    
	return 0;
}


int xhttpd_loop(xhttpd_t *xhttp)
{
	if (!xhttp || xhttp->loop == NULL || xhttp->watcher == NULL) {
		return -1;
	}
	
	struct ev_loop *loop = (struct ev_loop *)(xhttp->loop);
	ev_io *watcher = xhttp->watcher;
	
    ev_run(loop, 0);
    
    ev_io_stop(loop, watcher);
    
    // call ev_break(loop, how) how = EVBREAK_ALL or EVBREAK_ONE to stop ev_run loop
    ev_loop_destroy(loop);

	free(watcher);

	xhttp->loop = NULL;
	xhttp->watcher = NULL;

	return 0;
}

void xhttpd_exit(xhttpd_t *xhttp)
{
	if (xhttp) {
		ev_break(xhttp->loop, EVBREAK_ALL);
	}
}

const char *xhttpd_parameter_get(xhttpd_http_t *http, const char *key)
{
    int i;
    for (i = 0; i < http->para_cnt; i++) {
        if (strcmp(key, http->parameters[i].key) == 0) {
            return (const char *)(http->parameters[i].value);
        }     
    }

    return NULL; 
}
