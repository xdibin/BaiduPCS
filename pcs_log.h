#ifndef __PCS__LOG_H_
#define __PCS__LOG_H_   1

#include <stdarg.h>

#define pcs_log(fmt, ...)   \
    do { fprintf(stderr, "%s %d %s: " fmt, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); } while (0)


#endif
