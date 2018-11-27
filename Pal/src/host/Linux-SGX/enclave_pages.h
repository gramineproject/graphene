extern void * heap_base;
void init_pages (void);
void * get_reserved_pages (void * addr, size_t size);
void free_pages (void * addr, size_t size);
