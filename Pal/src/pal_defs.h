/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#ifndef PAL_DEFS_H
#define PAL_DEFS_H

/* (Linux-only) enable caching loaded binaries for optimizing process creation */
#define CACHE_LOADED_BINARIES    0      /* default: disabled */

/* statically allocate slab manager */
#define STATIC_SLAB              1

/* maximum length of URIs */
#define URI_MAX                  256

/* allow binding sockets to ANY addresses (e.g., 0.0.0.0:0) */
#define ALLOW_BIND_ANY           1

/* turn on the following option to trace heap memory leak */
#define TRACE_HEAP_LEAK          0

#endif /* PAL_DEFS_H */
