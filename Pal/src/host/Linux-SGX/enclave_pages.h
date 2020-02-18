extern void* heap_base;
void init_pages(void);
int get_reserved_pages(void** addr, size_t size, bool internal);
int free_pages(void* addr, size_t size);
bool _DkCheckMemoryMappable(const void* addr, size_t size);
