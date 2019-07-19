#include <sys/endian.h>

#ifndef __BYTE_ORDER
# define __BYTE_ORDER _BYTE_ORDER
#endif
#ifndef __LITTLE_ENDIAN
# define __LITTLE_ENDIAN _LITTLE_ENDIAN
#endif
#ifndef __BIG_ENDIAN
# define __BIG_ENDIAN _BIG_ENDIAN
#endif

#undef __htonl
#undef __ntohl
#undef __htons
#undef __ntohs
