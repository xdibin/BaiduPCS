#include <stdio.h>
#include <string.h>

#include "pcs/pcs.h"
#include "pcs_fileinfo.h"
#include "utils_print.h"



/*找到str第一次出现ch的位置*/
static inline char *findchar(char *str, int ch)
{
	char *p = str;
	while (*p && ((int)((unsigned int)(*p))) != ch) p++;
	return p;
}

/*回到上一行*/
static inline void clear_current_print_line()
{
#ifdef _WIN32
	printf("\r");  //清除该行
#else
	//printf("\033[1A"); //先回到上一行
	printf("\033[K");  //清除该行
#endif
}

/*回到上一行*/
static inline void back_prev_print_line()
{
#ifdef _WIN32
	printf("\r"); //先回到上一行
	printf("                                        ");  //清除该行
	printf("\r"); //先回到上一行
#else
	printf("\033[1A"); //先回到上一行
	printf("\033[K");  //清除该行
#endif
}

/*把文件大小转换成字符串*/
static const char *size_tostr(size_t size, int *fix_width, char ch)
{
	static char str[128], *p;
	int i;
	int j, cn, mod;
	size_t sz;

	if (size == 0) {
		i = 0;
		if (*fix_width > 0) {
			for (; i < *fix_width - 1; i++) {
				str[i] = ch;
			}
		}
		str[i] = '0';
		str[i + 1] = '\0';
		if (*fix_width < 0)
			*fix_width = 1;
		return str;
	}

	sz = size;
	j = 127;
	str[j] = '\0';
	cn = 0;
	while (sz != 0) {
		mod = sz % 10;
		sz = sz / 10;
		str[--j] = (char)('0' + mod);
		cn++;
	}

	i = 0;
	if (*fix_width > 0) {
		for (; i < *fix_width - cn; i++) {
			str[i] = ch;
		}
	}
	p = &str[j];
	while (*p){
		str[i++] = *p++;
	}
	str[i] = '\0';
	if (*fix_width < 0)
		*fix_width = (int)i;
	return str;
}

static const char *uint64_tostr(int64_t size, int *fix_width, char ch)
{
	static char str[128], *p;
	int i;
	int j, cn, mod;
	int64_t sz;

	if (size == 0) {
		i = 0;
		if (*fix_width > 0) {
			for (; i < *fix_width - 1; i++) {
				str[i] = ch;
			}
		}
		str[i] = '0';
		str[i + 1] = '\0';
		if (*fix_width < 0)
			*fix_width = 1;
		return str;
	}

	sz = size;
	j = 127;
	str[j] = '\0';
	cn = 0;
	while (sz != 0) {
		mod = sz % 10;
		sz = sz / 10;
		str[--j] = (char)('0' + mod);
		cn++;
	}

	i = 0;
	if (*fix_width > 0) {
		for (; i < *fix_width - cn; i++) {
			str[i] = ch;
		}
	}
	p = &str[j];
	while (*p){
		str[i++] = *p++;
	}
	str[i] = '\0';
	if (*fix_width < 0)
		*fix_width = (int)i;
	return str;
}

/*打印文件时间*/
static void print_time(const char *format, time_t time)
{
	struct tm *tm = NULL;
	time_t t = time;
	char tmp[64];

	if (time)
		tm = localtime(&t);

	if (tm) {
		sprintf(tmp, "%d-%02d-%02d %02d:%02d:%02d",
			1900 + tm->tm_year,
			tm->tm_mon + 1,
			tm->tm_mday,
			tm->tm_hour,
			tm->tm_min,
			tm->tm_sec);
		printf(format, tmp);
	}
	else {
		printf(format, "0000-00-00 00:00:00");
	}
}

/*打印可读的文件大小*/
static void print_size(const char *format, size_t size)
{
	char tmp[64];
	tmp[63] = '\0';
	pcs_utils_readable_size((double)size, tmp, 63, NULL);
	printf(format, tmp);
}

static void print_uint64(const char *format, int64_t size)
{
	char tmp[64];
	tmp[63] = '\0';
	pcs_utils_readable_size((double)size, tmp, 63, NULL);
	printf(format, tmp);
}

/*打印文件列表的头*/
static void print_filelist_head(int size_width, int md5, int thumb)
{
	int i;
	putchar('D');
	putchar(' ');
	for (i = 0; i < size_width - 4; i++)
		putchar(' ');
	printf("Size");
	putchar(' ');
	putchar(' ');
	printf("Modify Date Time");
	if (md5) {
		putchar(' ');
		putchar(' ');
		printf("MD5");
	}
	putchar(' ');
	putchar(' ');
	printf("File Name");
    if (thumb) {
        putchar(' ');
        putchar(' ');
        printf("Thumb Url");
    }
    putchar('\n');
}

/*打印文件列表的数据行*/
static void print_filelist_row(PcsFileInfo *f, int size_width, int md5, int thumb)
{
	const char *p;

	if (f->isdir)
		putchar('d');
	else
		putchar('-');
	putchar(' ');

	p = uint64_tostr(f->size, &size_width, ' ');
	while (*p) {
		putchar(*p++);
	}
	putchar(' ');
	putchar(' ');
	print_time("%s", f->server_mtime);
	if (md5) {
		putchar(' ');
		putchar(' ');
		printf("%s", f->md5);
	}
	putchar(' ');
	putchar(' ');
	printf("%s", f->path);
    if (thumb && f->thumbs) {
        printf("  %s", f->thumbs->string2);
    }
    putchar('\n');
}

/*打印文件列表*/
void print_http_filelist(PcsFileInfoList *list, int *pFileCount, int *pDirCount, int64_t *pTotalSize,
	int md5, int thumb)
{
	char tmp[64] = { 0 };
	int cnt_file = 0,
		cnt_dir = 0,
		size_width = 1,
		w;
	PcsFileInfo *file = NULL;
	int64_t total = 0;
	PcsFileInfoListIterater iterater;

	pcs_filist_iterater_init(list, &iterater, PcsFalse);
	while (pcs_filist_iterater_next(&iterater)) {
		file = iterater.current;
		w = -1;
		uint64_tostr(file->size, &w, ' ');
		if (size_width < w)
			size_width = w;
		total += file->size;
		if (file->isdir)
			cnt_dir++;
		else
			cnt_file++;
	}

	if (size_width < 4)
		size_width = 4;
	print_filelist_head(size_width, md5, thumb);
	puts("------------------------------------------------------------------------------");
	pcs_filist_iterater_init(list, &iterater, PcsFalse);
	while (pcs_filist_iterater_next(&iterater)) {
		file = iterater.current;
		print_filelist_row(file, size_width, md5, thumb);
	}
	puts("------------------------------------------------------------------------------");
	pcs_utils_readable_size((double)total, tmp, 63, NULL);
	tmp[63] = '\0';
	printf("Total: %s, File Count: %d, Directory Count: %d\n", tmp, cnt_file, cnt_dir);
	putchar('\n');
	if (pFileCount) *pFileCount += cnt_file;
	if (pDirCount) *pDirCount += cnt_dir;
	if (pTotalSize) *pTotalSize += total;
}

/*打印文件或目录的元数据*/
void print_http_fileinfo(PcsFileInfo *f, const char *prex)
{
	if (!prex) prex = "";
	printf("%sfs_id:\t%"PRIu64"\n", prex, f->fs_id);
	printf("%sCategory:\t%d\n", prex, f->category);
	printf("%sPath:\t\t%s\n", prex, f->path);
	printf("%sFilename:\t%s\n", prex, f->server_filename);
	printf("%s", prex);
	print_time("Create time:\t%s\n", f->server_ctime);
	printf("%s", prex);
	print_time("Modify time:\t%s\n", f->server_mtime);
	printf("%sIs Dir:\t%s\n", prex, f->isdir ? "Yes" : "No");
	if (!f->isdir) {
		printf("%s", prex);
		print_uint64("Size:\t\t%s\n", f->size);
		printf("%smd5:\t\t%s\n", prex, f->md5);
		printf("%sdlink:\t\t%s\n", prex, f->dlink);
	}
    if (f->thumbs) {
        PcsSList2 *list = f->thumbs;
        printf("%sthumbs:\n", prex);
        while (list) {
            printf("%s  %s: %s\n", prex, list->string1, list->string2);
            list = list->next;
        }
    }
}

