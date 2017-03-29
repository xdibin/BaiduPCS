#ifndef __PCS_UTILS_PRINT_H
#define __PCS_UTILS_PRINT_H 1

void print_http_filelist(PcsFileInfoList *list, int *pFileCount, int *pDirCount, int64_t *pTotalSize,
	int md5, int thumb);
void print_http_fileinfo(PcsFileInfo *f, const char *prex);
#endif