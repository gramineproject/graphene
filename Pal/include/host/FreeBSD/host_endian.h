#include <sys/endian.h>
#undef __htonl
#undef __ntohl
#undef __htons
#undef __ntohs
#define __bswap_16 __bswap16
#define __bswap_32 __bswap32
#define __bswap_64 __bswap64
