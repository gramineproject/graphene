#ifndef _MY_MMAP_H
#define _MY_MMAP_H

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)

typedef unsigned long (* do_mmap_pgoff_t)(struct file *file, unsigned long addr,
					  unsigned long len, unsigned long prot,
					  unsigned long flags, 
					  unsigned long pgoff, unsigned long *populate);

static do_mmap_pgoff_t my_do_mmap_pgoff = NULL;


#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)

typedef unsigned long (* do_mmap_pgoff_t)(struct file *file, unsigned long addr,
					  unsigned long len, unsigned long prot,
					  unsigned long flags, 
					  unsigned long pgoff);

static do_mmap_pgoff_t my_do_mmap_pgoff = NULL;

#endif //kernel version >=3.4

#endif //_MY_MMAP_H
