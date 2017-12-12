/*
 *  util.c
 *
 *  Copyright (C) 2017-, Chia-Che Tsai, Bhushan Jain and Donald Porter
 *
 */

#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/version.h>

size_t norm_path (const char * path, char * buf, size_t size)
{
    off_t head = 0, offset = 0;
    char c, c1;
    const char * p = path;

    for (c = '/' ; c ; c = c1, p++) {
        c1 = *p;
        if (c == '/') {     /* find a slash, or the beginning of the path */
            if (c1 == 0)    /* no more path */
                break;
            if (c1 == '/')  /* consequential slashes */
                continue;
            if (c1 == '.') {    /* find a dot, can be dot-dot or a file */
                c1 = *(++p);
                if (c1 == 0)    /* no more path */
                    break;
                if (c1 == '/')  /* a dot, skip it */
                    continue;
                if (c1 == '.') {    /* must be dot-dot */
                    c1 = *(++p);
                    if (c1 != 0 && c1 != '/') { /* Paths can start with a dot
                                                 * dot: ..xyz is ok */
                        if (offset >= size - 2)
                            return -ENAMETOOLONG;
                        buf[offset++] = '.';
                        buf[offset++] = '.';
                        continue;
                    }
                    if (offset > head) {    /* remove the last token */
                        while (offset > head && buf[--offset] != '/');
                    } else {
                        if (offset) {   /* add a slash */
                            if (offset >= size - 1)
                                return -ENAMETOOLONG;
                            buf[offset++] = '/';
                        }               /* add a dot-dot */
                        if (offset >= size - 2)
                            return -ENAMETOOLONG;
                        buf[offset++] = '.';
                        buf[offset++] = '.';
                        head = offset;
                    }
                } else { /* it's a file */
                    if (offset) {   /* add a slash */
                        if (offset >= size - 1)
                            return -ENAMETOOLONG;
                        buf[offset++] = '/';
                    }
                    if (offset >= size - 1)
                        return -ENAMETOOLONG;
                    buf[offset++] = '.';
                }
                continue;
            }
        }
        if (offset || c != '/' || *path == '/') {
            if (offset >= size - 1)
                return -ENAMETOOLONG;
            buf[offset++] = c;
        }
    }

    buf[offset] = 0;
    return offset;
}
