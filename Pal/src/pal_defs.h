#ifndef PAL_DEFS_H
#define PAL_DEFS_H

/* (Linux-only) enable caching loaded binaries for optimizing process creation
 */
#define CACHE_LOADED_BINARIES 0 /* default: disabled */

/* statically allocate slab manager */
#define STATIC_SLAB 1

/* maximum length of URIs */
#define URI_MAX 4096

/* allow binding sockets to ANY addresses (e.g., 0.0.0.0:0) */
#define ALLOW_BIND_ANY 1

#endif /* PAL_DEFS_H */
