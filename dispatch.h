#ifndef _DISPATCH_H
#define _DISPATCH_H 1


#include "pcs/pcs.h"

#include "http.h"



int http_loop(HttpContext *context);

int is_http_login(HttpContext *context);

#endif /* _DISPATCH_H */