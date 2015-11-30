#ifndef PAL_FREEBSD_ERROR_H
#define PAL_FREEBSD_ERROR_H

#ifdef IN_PAL

# include <pal_error.h>
# include <errno.h>

static inline __attribute__((unused))
int unix_to_pal_error (int unix_errno)
{
    switch(unix_errno) {
        case ENOENT:
            return -PAL_ERROR_STREAMNOTEXIST;
        case EINTR:
            return -PAL_ERROR_INTERRUPTED;
        case EBADF:
            return -PAL_ERROR_BADHANDLE;
        case ETIMEDOUT:
        case EAGAIN:
            return -PAL_ERROR_TRYAGAIN;
        case ENOMEM:
            return -PAL_ERROR_NOMEM;
        case EFAULT:
            return -PAL_ERROR_BADADDR;
        case EEXIST:
            return -PAL_ERROR_STREAMEXIST;
        case ENOTDIR:
            return -PAL_ERROR_STREAMISFILE;
        case EINVAL:
            return -PAL_ERROR_INVAL;
        case ENAMETOOLONG:
            return -PAL_ERROR_TOOLONG;
        case EISDIR:
            return -PAL_ERROR_STREAMISDIR;
        default:
            return -PAL_ERROR_DENIED;
    }
}

#define ERESTART        (-1)            /* restart syscall */

#endif /* IN_PAL */

#endif /* PAL_FREEBSD_ERROR_H */
