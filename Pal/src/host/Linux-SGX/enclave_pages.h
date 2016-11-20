/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

extern void * heap_base;
void init_pages (void);
void * get_reserved_pages (void * addr, uint64_t size);
void free_pages (void * addr, uint64_t size);
