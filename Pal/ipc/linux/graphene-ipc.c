#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/bitmap.h>
#include <asm/mman.h>

#ifdef CONFIG_GRAPHENE_BULK_IPC
# include "graphene.h"
#else
# include "my_tlb.h"
# include "my_mmap.h"
#endif

#include "graphene-ipc.h"

MODULE_LICENSE("Dual BSD/GPL");

#define FILE_POISON LIST_POISON1

struct kmem_cache *gipc_queue_cachep;
struct kmem_cache *gipc_buf_cachep;

#define GIPC_DEBUG	0

#if defined(GIPC_DEBUG) && GIPC_DEBUG == 1
# define DEBUG(...)		printk(KERN_INFO __VA_ARGS__)
# define GIPC_BUG_ON(cond)      BUG_ON(cond)
#else
# define DEBUG(...)
# define GIPC_BUG_ON(cond)
#endif

#ifndef gipc_get_session
u32 (*my_gipc_get_session) (struct task_struct *) = NULL;
#endif

/* The page bufs going one direction */
struct gipc_pages {
	struct file *file; // indicates if the struct is taken or not
	volatile int next, last;

	struct gipc_page_buf {
		struct page *page;
		struct file *file;
		u64 pgoff;
	} page_buf[PAGE_BUFS];

	struct mutex sender_lock;
	struct mutex receiver_lock;
	wait_queue_head_t send, recv;
	struct gipc_sender_buf {
		unsigned long bitmap[PAGE_BITS];
		struct page *pages[PAGE_BUFS];
		struct vm_area_struct *vmas[PAGE_BUFS];
		struct file *files[PAGE_BUFS];
		u64 pgoffs[PAGE_BUFS];
	} *sender_buf;
};

#define GIPC_PAGES(queue) \
	((struct gipc_pages *) ((void *) (queue) + sizeof(struct gipc_queue)))

struct {
	spinlock_t lock;
        /*
	 * For now, just make them monotonically increasing.  XXX: At
	 * some point, do something smarter for security.
	 */
	int64_t max_token;
	struct list_head channels; // gipc_queue structs
} gdev;

static inline struct gipc_queue * create_gipc_queue(struct file *creator)
{
	struct gipc_queue *gq = kmem_cache_alloc(gipc_queue_cachep, GFP_KERNEL);
	struct gipc_pages *gp = GIPC_PAGES(gq);

	if (!gq)
		return gq;

	INIT_LIST_HEAD(&gq->list);

	memset(gp, 0, sizeof(struct gipc_pages) * 2);
	mutex_init(&gp[0].sender_lock);
	mutex_init(&gp[1].sender_lock);
	mutex_init(&gp[0].receiver_lock);
	mutex_init(&gp[1].receiver_lock);

	init_waitqueue_head(&gp[0].send);
	init_waitqueue_head(&gp[0].recv);
	init_waitqueue_head(&gp[1].send);
	init_waitqueue_head(&gp[1].recv);

	gp[0].file = creator;
	creator->private_data = gq;
	gp[1].file = NULL;

	spin_lock(&gdev.lock);
	list_add(&gq->list, &gdev.channels);
	gq->token = gdev.max_token++;
#ifdef gipc_get_session
	gq->owner = gipc_get_session(current);
#else
	gq->owner = my_gipc_get_session ? my_gipc_get_session(current) : 0;
#endif
	spin_unlock(&gdev.lock);
	return gq;
}

static inline void release_gipc_pages(struct gipc_pages *gps) {
	int idx;
	while (gps->next != gps->last) {
		idx = gps->next;
		if (gps->page_buf[idx].page) {
			page_cache_release(gps->page_buf[idx].page);
			gps->page_buf[idx].page = NULL;
		}
		if (gps->page_buf[idx].file) {
			fput_atomic(gps->page_buf[idx].file);
			gps->page_buf[idx].file = NULL;
			gps->page_buf[idx].pgoff = 0;
		}
		gps->next++;
		gps->next &= (PAGE_BUFS-1);
	}
}

#if defined(SPLIT_RSS_COUNTING)
static void add_mm_counter_fast(struct mm_struct *mm, int member, int val)
{
        struct task_struct *task = current;

        if (likely(task->mm == mm))
                task->rss_stat.count[member] += val;
        else
                add_mm_counter(mm, member, val);
}
#else
#define add_mm_counter_fast(mm, member, val) add_mm_counter(mm, member, val)
#endif

#define inc_mm_counter_fast(mm, member) add_mm_counter_fast(mm, member, 1)
#define dec_mm_counter_fast(mm, member) add_mm_counter_fast(mm, member, -1)

inline int make_pages_cow(struct mm_struct *mm, struct vm_area_struct *vma,
			  unsigned long addr, int count)
{
	int i = 0;
	pgd_t *pgd;
	unsigned long pgd_next;
	pud_t *pud;
	unsigned long pud_next;
	pmd_t *pmd;
	unsigned long pmd_next;
	pte_t *pte;
	spinlock_t *ptl;
	unsigned long end = addr + (PAGE_SIZE * count);

	/* Mark source COW */
	do {
		if ((vma->vm_flags & (VM_SHARED|VM_MAYWRITE)) != VM_MAYWRITE)
			return VM_FAULT_OOM;

		pgd = pgd_offset(mm, addr);

		do {
			pgd_next = pgd_addr_end(addr, end);

			if (pgd_none(*pgd) || pgd_bad(*pgd))
				return VM_FAULT_OOM;

			pud = pud_offset(pgd, addr);
			do {
				pud_next = pud_addr_end(addr, pgd_next);
				if (pud_none(*pud) || pud_bad(*pud))
					return VM_FAULT_OOM;
		
				pmd = pmd_offset(pud, addr);
				do {
					pte_t *pte_base;
					pmd_next = pmd_addr_end(addr, pud_next);
					if (pmd_none(*pmd) || pmd_bad(*pmd))
						return VM_FAULT_OOM;

					pte_base = pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
					if (!pte)
						return VM_FAULT_OOM;

					do {
						if ((!pte_none(*pte)) && pte_present(*pte)) {
							ptep_set_wrprotect(mm, addr, pte);
							pte_wrprotect(*pte);
						} else {
							pte_unmap_unlock(pte, ptl);
							return VM_FAULT_OOM;
						}
					} while (pte++, addr += PAGE_SIZE, i++,
						 addr != pmd_next);

					pte_unmap_unlock(pte_base, ptl);
				} while (pmd++,
					 addr < pud_next);
			} while (pud++,
				 addr < pgd_next);
		} while (pgd++,
			 addr < vma->vm_end && addr < end);

		if (i < count) {
			/* Find the next vma.  Leverage the fact that
			 * addresses are increasing.
			 */
			while (vma && addr < vma->vm_end)
				vma = vma->vm_next;
		}
	} while (addr < end && vma);

	return 0;
}

static void fill_page_bitmap(struct mm_struct *mm, unsigned long addr,
			     unsigned long * page_bit_map, int count)
{
	int i = 0;
	spinlock_t *ptl;

	pgd_t *pgd;
	unsigned long pgd_next;
	
	pud_t *pud;
	unsigned long pud_next;

	pmd_t *pmd;
	unsigned long pmd_next;

	pte_t *pte;
	
	unsigned long end = addr + (PAGE_SIZE * count);

	pgd = pgd_offset(mm, addr);

	do {
		pgd_next = pgd_addr_end(addr, end);

		if (pgd_none(*pgd) || pgd_bad(*pgd)) {
			while (addr < pgd_next) {
				clear_bit(i, page_bit_map);
				i++;
				addr += PAGE_SIZE;
			}
			continue;
		} 
		
		pud = pud_offset(pgd, addr);
		do {
			pud_next = pud_addr_end(addr, pgd_next);
			if (pud_none(*pud) || pud_bad(*pud)) {
				while (addr < pud_next) {
					clear_bit(i, page_bit_map);
					i++;
					addr += PAGE_SIZE;
				}
				continue;
			} 

			pmd = pmd_offset(pud, addr);
			do {
				pmd_next = pmd_addr_end(addr, pud_next);
				if(pmd_none(*pmd) || pmd_bad(*pmd)) {
					while (addr < pmd_next) {
						clear_bit(i, page_bit_map);
						i++;
						addr += PAGE_SIZE;
					}
					continue;
				}

				pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
				do {
					if ((!pte) || pte_none(*pte) || (!pte_present(*pte)))
						clear_bit(i, page_bit_map);
					else
						set_bit(i, page_bit_map);

				} while (pte++, addr += PAGE_SIZE, i++,
					 addr != pmd_next);

				pte_unmap_unlock(pte - 1, ptl);
				
			} while (pmd++,
				 addr < pud_next);
			
		} while (pud++,
			 addr < pgd_next);
	} while (pgd++, 
		 addr < end);
}

static int get_pages (struct task_struct *current_tsk,
		      unsigned long address, unsigned long * page_bit_map,
		      struct page *pages[PAGE_BUFS],
		      struct vm_area_struct *vmas[PAGE_BUFS], int count)
{
	int num_contiguous_bits= 0;
	int index = 0;
	int i = 0, start, rv, page_count = 0;
	unsigned long addr = address;
	struct vm_area_struct *last_vma = NULL;

	while ( index < count ) {
		start = index;

		if ( test_bit(start, page_bit_map) ) {

			index = find_next_zero_bit(page_bit_map, PAGE_BUFS, start+1);
			if (index > count)
				index = count;
			num_contiguous_bits = index - start;

			rv = get_user_pages(current_tsk,
					    current_tsk->mm,
					    addr,
					    num_contiguous_bits,
					    1,
					    1,
					    &pages[start],
					    &vmas[start]);

			if (rv <= 0) {
				printk(KERN_ERR "Graphene error: "
				       "get_user_pages at 0x%016lx-0x%016lx\n",
				       addr,
				       addr + PAGE_SIZE * num_contiguous_bits);
				return rv;
			}

			if (rv != num_contiguous_bits) {
				printk(KERN_ERR "Graphene error: "
				       "get_user_pages at 0x%016lx\n",
				       addr + PAGE_SIZE * rv);
				return -EACCES;
			}

			page_count += rv;

			/* Mark source COW */
			rv = make_pages_cow(current_tsk->mm,
					    vmas[start], addr, num_contiguous_bits);
			if (rv) 
				return rv;

			/* Fix up the counters */
			add_mm_counter_fast(current_tsk->mm, MM_FILEPAGES, num_contiguous_bits);
			add_mm_counter_fast(current_tsk->mm, MM_ANONPAGES, -num_contiguous_bits);

			for (i = 0; i < num_contiguous_bits; i++) {
				pages[start + i]->mapping = NULL;
				addr += PAGE_SIZE;
			}

			last_vma = vmas[start + num_contiguous_bits - 1];
		} else {
			/* This is the case where a page (or pages) are not currently mapped.
			 * Handle the hole appropriately.
			 */
			index = find_next_bit(page_bit_map, PAGE_BUFS, start+1);
			if (index > count)
				index = count;
			num_contiguous_bits = index - start;

			for (i = 0; i < num_contiguous_bits; i++) {
				struct vm_area_struct *my_vma;
				pages[start + i] = NULL;

				if ( !last_vma ) {
					last_vma = find_vma(current_tsk->mm,
							    addr);
					my_vma = last_vma;
				} else {
					/* DEP 6/17/13 - these addresses should be
					 * monotonically increasing.
					 */
					while (last_vma && addr >= last_vma->vm_end )
						last_vma = last_vma->vm_next;

					/* Leverage monotonic increasing vmas
					 * to more quickly detect holes in the address space.
					 */
					if (addr < last_vma->vm_start)
						my_vma = NULL;
					else 
						my_vma = last_vma;
				}

				vmas[start + i] = my_vma;
				page_count++;
				addr += PAGE_SIZE;
			}
		}
	}

	return page_count;
}

static inline
int recv_next (struct task_struct *current_tsk,
	       struct gipc_pages *pending)
{
	if (pending->next == pending->last) {
		/* The blocking condition for send
		 * and recv can't both be true! */
		wake_up_all(&pending->send);
		wait_event_interruptible(pending->recv, (pending->next != pending->last));
		if (signal_pending(current_tsk))
			return -ERESTARTSYS;
	}
	
	return pending->next;
}

static
int recv_helper (unsigned long *addr, unsigned long len, int prot,
		 struct task_struct *current_tsk, struct gipc_pages *pending,
		 struct file *file, int *physical_pages)
{
	int page_count = len >> PAGE_SHIFT;
	int i, found;
	long rv = 0;
	struct page *page;
	struct file *vm_file;
	u64 vm_pgoff;
	int flags = MAP_PRIVATE;
	struct vm_area_struct *vma;
	unsigned long my_addr = *addr;

	if (len & ~PAGE_MASK)
		page_count++;

	for (i = 0; i < page_count; ) {
		unsigned long start_addr;

		found = recv_next(current_tsk, pending);
		if (found < 0)
			return -ERESTARTSYS;
			
		page = pending->page_buf[found].page;
		vm_file = pending->page_buf[found].file;
		vm_pgoff = pending->page_buf[found].pgoff;

		pending->next = ((pending->next + 1) & (PAGE_BUFS-1));
		wake_up_all(&pending->send);

		if (my_addr)
			flags |= MAP_FIXED;

		if (file)
			flags = (flags & ~MAP_ANONYMOUS) | MAP_FILE;
		else
			flags = (flags & ~MAP_FILE) | MAP_ANONYMOUS;

		/* Speculate that we will want the entire region under one 
		 * vma.  Correct if not. 
		 */
#if defined(CONFIG_GRAPHENE_BULK_IPC) || LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)
		my_addr = do_mmap_pgoff(vm_file, my_addr, PAGE_SIZE * (page_count - i),
				      prot,
				      flags, vm_pgoff);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
		my_addr = my_do_mmap_pgoff(vm_file, my_addr, PAGE_SIZE * (page_count - i),
					 prot,
					 flags, vm_pgoff);
#else
		{
			unsigned long populate;
			my_addr = my_do_mmap_pgoff(vm_file, my_addr, PAGE_SIZE * (page_count - i),
						 prot,
						 flags, vm_pgoff, &populate);
		}
#endif /* kernel_version >= 3.9.0 */

		if (!my_addr) {
			printk(KERN_ERR
			       "Graphene error: failed to mmap %p\n",
			       (void *) rv);
			rv = -EINVAL;
			goto finish_recv;
		}

		/* Save our staring addr for COW-ing later */
		*addr = start_addr = my_addr;

		vma = find_vma(current_tsk->mm, my_addr);
		if (!vma) {
			printk(KERN_ERR
			       "Graphene error: can't find vma at %p\n",
			       (void *) my_addr);
			rv = -ENOENT;
			goto finish_recv;
		}

		while (i < page_count) {
			int last_time = ((i+1) == page_count);
			int page_true = (page != NULL);
				
			/* Fill the vma with this page */
			if (page) {
				rv = vm_insert_page(vma, my_addr, page);
				if (rv) {
					printk(KERN_ERR
					       "Graphene error: fail to insert page %p\n",
					       (void *) rv);
					goto finish_recv;
				}
				(*physical_pages)++;
				page_cache_release(page);
					
				/* Avoid double-putting the page */
				page = NULL;
			}

			/* Check out the next page, maybe it can go in the same VMA */
			if (!last_time) {
				found = recv_next(current_tsk, pending);
				if (found < 0)
					return -ERESTARTSYS;
			}

			if (page_true) {
				/* If the next page will break the vma, isn't there,
				 * or we are at the end of the VMA, go ahead
				 * and mark the range we've mapped as COW.
				 */
				if ((i+1) == page_count
				    || (!pending->page_buf[found].page)
				    || pending->page_buf[found].file != vm_file) {
					int sz = ((my_addr - start_addr) / PAGE_SIZE) + 1;
					rv = make_pages_cow(current_tsk->mm, vma, 
							    start_addr,
							    sz);

					start_addr = my_addr + PAGE_SIZE;
					if (rv) {
						printk(KERN_ERR
						       "Graphene error: can't make vma copy-on-write at %p-%p\n",
						       (void *) start_addr,
						       (void *) my_addr);
						goto finish_recv;
					}
				}
			}

			/* See if we can continue in the inner loop*/
			if ((!last_time) && pending->page_buf[found].file == vm_file) {
				page = pending->page_buf[found].page;
				pending->next = ((pending->next + 1) & (PAGE_BUFS-1));
				wake_up_all(&pending->send);
				i++;
				my_addr += PAGE_SIZE;
				/* Handle the case where we had a run of missing pages
				 * and then one shows up
				 */
				if (page && !page_true)
					start_addr = my_addr;
			} else 
				break;

		}

finish_recv:
		/* Drop the kernel's reference to this page */
		if (page)
			page_cache_release(page);
		if (vm_file)
			fput_atomic(vm_file);
		if (rv)
			return rv;

		i++;
		my_addr += PAGE_SIZE;
	}
	return page_count;
}

static long gipc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct task_struct *current_tsk = current;
	long rv = 0;

	switch (cmd) {
	case GIPC_SEND: {
		unsigned long addrs[ADDR_ENTS], lens[ADDR_ENTS];
		unsigned long *page_bitmap;
		struct page **pages;
		struct vm_area_struct **vmas;
		struct file **files;
		u64 *pgoffs;
		struct gipc_send gs;
		unsigned long page_count, total_page_count;
		int page_copied = 0, physical_pages = 0;
		int i, j;
		struct gipc_queue *queue = NULL;
		struct gipc_pages *pending = NULL;

		rv = copy_from_user(&gs, (void *) arg, sizeof(gs));
		if (rv) {
			printk(KERN_ALERT "Graphene SEND: bad buffer %p\n",
			       (void *) arg);
			return -EFAULT;
		}

		if (gs.entries > ADDR_ENTS) {
			printk(KERN_ALERT "Graphene SEND: too many entries\n");
			return -EINVAL;
		}

		rv = copy_from_user(&addrs, gs.addr,
				    sizeof(unsigned long) * gs.entries);
		if (rv) {
			printk(KERN_ALERT "Graphene SEND: bad buffer %p\n",
			       gs.addr);
			return -EFAULT;
		}

		rv = copy_from_user(&lens, gs.len,
				    sizeof(unsigned long) * gs.entries);
		if (rv) {
			printk(KERN_ALERT "Graphene SEND: bad buffer %p\n",
			       gs.len);
			return -EFAULT;
		}

		for (j = 0; j < gs.entries; j++) {
			unsigned long addr = addrs[j]; //user pointers
			unsigned long len = lens[j];   //user supplied lens

			if (addr > addr + len) {
				printk(KERN_ALERT "Graphene SEND:"
				       " attempt to send %p - %p "
				       " by thread %d FAIL: bad length\n",
				       (void *) addr, (void *) (addr + len),
				       current_tsk->pid);
				return -EINVAL;
			}
		}

		/* Find/allocate the gipc_pages struct for our recipient */
		queue = (struct gipc_queue *) file->private_data;
		if (!queue)
			return -EFAULT;
		/* We want to put pages in the partner buf */
		if (file == GIPC_PAGES(queue)[0].file) {
			pending = &GIPC_PAGES(queue)[1];
		} else {
			pending = &GIPC_PAGES(queue)[0];
			BUG_ON(pending->file != file);
		}


		DEBUG("GIPC_SEND %ld entries to token %lld by thread %d\n",
		      gs.entries, queue->token, current_tsk->pid);

		for (j = 0; j < gs.entries; j++) {
			unsigned long addr = addrs[j]; //user pointers
			unsigned long len = lens[j];   //user supplied lens
			int get_page_failed = 0;

			total_page_count = len >> PAGE_SHIFT;
			if (len & ~PAGE_MASK)
				total_page_count++;

			if (!access_ok(VERIFY_READ, addr,
				       total_page_count << PAGE_SHIFT)) {
				printk(KERN_ALERT "Graphene SEND:"
				       " attempt to send %p - %p (%ld pages) "
				       " by thread %d FAIL: bad permission\n",
				       (void *) addr, (void *) (addr + len),
				       total_page_count, current_tsk->pid);
				return -EFAULT;
			}

			DEBUG("    %p - %p (%ld pages) sent by thread %d\n",
			      (void *) addr, (void *) (addr + len),
			      len >> PAGE_SHIFT, current_tsk->pid);

			while (total_page_count) {
				page_count = total_page_count <= PAGE_BUFS
					? total_page_count : PAGE_BUFS;
	
				total_page_count -= page_count;
				/* for each of these addresses - check if
				 * demand faulting will be triggered
				 * if vma is present, but there is no page
				 * present(pmd/pud not present or PTE_PRESENT
				 * is off) then get_user_pages will trigger
				 * the creation of those */

				mutex_lock(&pending->sender_lock);

				if (!pending->sender_buf)
					pending->sender_buf =
						kmem_cache_alloc(gipc_buf_cachep,
								 GFP_KERNEL);

				page_bitmap = pending->sender_buf->bitmap;
				pages = pending->sender_buf->pages;
				vmas = pending->sender_buf->vmas;
				files = pending->sender_buf->files;
				pgoffs = pending->sender_buf->pgoffs;

				down_write(&current_tsk->mm->mmap_sem);
				fill_page_bitmap(current_tsk->mm,
						 addr,
						 page_bitmap,
						 page_count);
				rv = get_pages(current_tsk,
					       addr,
					       page_bitmap,
					       pages,
					       vmas,
					       page_count);
				if (rv < 0) {
					up_write(&current_tsk->mm->mmap_sem);
					mutex_unlock(&pending->sender_lock);
					goto out;
				}

				for (i = 0; i < page_count; i++) {
					BUG_ON((!vmas[i]) && (pages[i]));
					if (vmas[i]) {
						files[i] = vmas[i]->vm_file;
						if (files[i]) {
							get_file(files[i]);
							pgoffs[i] = ((addr - vmas[i]->vm_start) >> PAGE_SHIFT)
								+ vmas[i]->vm_pgoff;
						} else {
							pgoffs[i] = 0;
						}
					} else {
						files[i] = NULL;
						pgoffs[i] = 0;
					}
					if (pages[i])
						physical_pages++;

					addr += PAGE_SIZE;
				}
				up_write(&current_tsk->mm->mmap_sem);

				for (i = 0; i < page_count ; i++) {
					/* Put in the pending buffer*/
					if ( ((pending->last + 1)
					      & (PAGE_BUFS-1) )
					     == pending->next) {
						
						/* The blocking condition for send
						 * and recv can't both be true! */
						wake_up_all(&pending->recv);
						wait_event_interruptible(pending->send,
									 ( ((pending->last + 1)
									    & (PAGE_BUFS-1) )
									  != pending->next));
										 
						if (signal_pending(current_tsk)) {
							mutex_unlock(&pending->sender_lock);
							return -ERESTARTSYS;
						}
					}
					pending->page_buf[pending->last].page = pages[i];
					pending->page_buf[pending->last].file = files[i];
					pending->page_buf[pending->last].pgoff = pgoffs[i];
					pending->last = ((pending->last + 1) & (PAGE_BUFS-1));
				}
				mutex_unlock(&pending->sender_lock);
				wake_up_all(&pending->recv);
				page_copied += page_count;
				if (get_page_failed)
					goto out;
	        	}

			if (get_page_failed)
				goto out;
		}

out:
		DEBUG("GIPC_SEND return to thread %d, %d pages "
`		      "(%d physical pages) are sent\n",
		      current_tsk->pid, page_copied, physical_pages);

		rv = page_copied;
		break;
	}
	case GIPC_RECV:
	{
		unsigned long addrs[ADDR_ENTS], lens[ADDR_ENTS];
		int prots[ADDR_ENTS];
		struct gipc_recv gr;
		int page_copied = 0;
		int j;
		struct gipc_pages *pending = NULL;
		struct gipc_queue *queue = (struct gipc_queue *) file->private_data;
		int physical_pages = 0;

		if (!queue)
			return -EFAULT;

		if (file == GIPC_PAGES(queue)[0].file)
			pending = &GIPC_PAGES(queue)[0];
		else {
			pending = &GIPC_PAGES(queue)[1];
			BUG_ON(pending->file != file);
		}

		rv = copy_from_user(&gr, (void *) arg, sizeof(gr));
		if (rv) {
			printk(KERN_ERR "Graphene error: bad buffer %p\n",
			       (void *) arg);
			return -EFAULT;
		}

		if (gr.entries > ADDR_ENTS) {
			printk(KERN_ALERT "Graphene RECV: too many entries\n");
			return -EINVAL;
		}

		rv = copy_from_user(&addrs, gr.addr,
				    sizeof(unsigned long) * gr.entries);
		if (rv) {
			printk(KERN_ALERT "Graphene RECV: bad buffer %p\n",
			       gr.addr);
			return -EFAULT;
		}

		rv = copy_from_user(&lens, gr.len,
				    sizeof(unsigned long) * gr.entries);
		if (rv) {
			printk(KERN_ALERT "Graphene RECV: bad buffer %p\n",
			       gr.len);
			return -EFAULT;
		}

		rv = copy_from_user(&prots, gr.prot,
				    sizeof(int) * gr.entries);
		if (rv) {
			printk(KERN_ALERT "Graphene RECV: bad buffer %p\n",
			       gr.prot);
			return -EFAULT;
		}

		down_write(&current_tsk->mm->mmap_sem);
		mutex_lock(&pending->receiver_lock);

		DEBUG("GIPC_RECV %ld entries to token %lld by thread %d\n",
		      gr.entries, queue->token, current_tsk->pid);

		for (j = 0; j < gr.entries; j++) {
			rv = recv_helper(&addrs[j], lens[j], prots[j],
					 current_tsk, pending, file,
					 &physical_pages);
			if (rv < 0) {
				mutex_unlock(&pending->receiver_lock);
				up_write(&current_tsk->mm->mmap_sem);
				return rv;
			}

			DEBUG("    %p - %p (%ld pages) received by thread %d\n",
			      (void *) addrs[j],
			      (void *) addrs[j] + (rv << PAGE_SHIFT),
			      rv, current_tsk->pid);

			page_copied += rv;
		}
		
		mutex_unlock(&pending->receiver_lock);
		up_write(&current_tsk->mm->mmap_sem);

		rv = copy_to_user(((struct gipc_recv *)arg)->addr, addrs,
				  sizeof(unsigned long) * gr.entries);
		if (rv) {
			printk(KERN_ERR "Graphene error: bad buffer %p\n",
			       (void *) arg);
			return -EFAULT;
		}

		DEBUG("GIPC_RECV return to thread %d, %d pages "
		      "(%d physical pages) are received\n",
		      current_tsk->pid, page_copied, physical_pages);

		rv = page_copied;
		break;
	}
	case GIPC_CREATE:
	{
		struct gipc_queue *gq = create_gipc_queue(file);
		if (gq == NULL)
			return -ENOMEM;
		DEBUG("GIPC_CREATE token %lld by thread %d\n", gq->token,
		      current_tsk->pid);
		rv = gq->token;
		break;
	}
	case GIPC_JOIN:
	{
		struct gipc_queue *gq;
		s64 token = arg;
#ifdef gipc_get_session
		u32 session = gipc_get_session(current);
#else
		u32 session = my_gipc_get_session ? my_gipc_get_session(current_tsk) : 0;
#endif

		if (file->private_data != NULL)
			return -EBUSY;

		/* Search for this token */
		spin_lock(&gdev.lock);
		list_for_each_entry(gq, &gdev.channels, list) {
			if (gq->token == token)
				break;
		}

		/* Fail if we didn't find it */
		if (gq == NULL || &gq->list == &gdev.channels) {
			spin_unlock(&gdev.lock);
			return -ENOENT;
		}

		if (gq->owner != session) {
			spin_unlock(&gdev.lock);
			return -EPERM;
		}

		if (GIPC_PAGES(gq)[1].file == NULL) {
			GIPC_PAGES(gq)[1].file = file;
			file->private_data = gq;
		} else {
			spin_unlock(&gdev.lock);
			return -EBUSY;
		}

		/* Hold the lock until we allocate so only one process
		 * gets the queue */
		spin_unlock(&gdev.lock);
		DEBUG("GIPC_JOIN token %lld by thread %d\n", token,
		      current_tsk->pid);
		rv = 0;
		break;
	}
	default:
		printk(KERN_ALERT "Graphene unknown ioctl %u %lu\n", cmd, arg);
		rv = -ENOSYS;
		break;
	}

	return rv;
}

static int gipc_release(struct inode *inode, struct file *file)
{
	int free = 0;
	struct gipc_queue *gq = (struct gipc_queue *) file->private_data;
	struct gipc_pages *gp = GIPC_PAGES(gq);

	if (gq) {
		struct gipc_pages *local, *other;
		spin_lock(&gdev.lock);
		if (gp[0].file == file) {
			local = &gp[0];
			other = &gp[1];
		} else {
			local = &gp[1];
			other = &gp[0];
			BUG_ON(local->file != file);
		}
		release_gipc_pages(local);
		/* Detect whether we are the last one out by poisoning the file field */
		local->file = FILE_POISON;
		if (other->file == FILE_POISON) {
			free = 1;
			list_del(&gq->list);
		}
		spin_unlock(&gdev.lock);
	}

	if (free) {
		if (gp[0].sender_buf)
			kmem_cache_free(gipc_buf_cachep, gp[0].sender_buf);
		if (gp[1].sender_buf)
			kmem_cache_free(gipc_buf_cachep, gp[1].sender_buf);

		kmem_cache_free(gipc_queue_cachep, gq);
	}

	file->private_data = NULL;
	return 0;
}

static int gipc_open(struct inode *inode, struct file *file)
{
	file->private_data = NULL;
	return 0;
}

static struct file_operations gipc_fops = {
	.owner		= THIS_MODULE,
	.release	= gipc_release,
	.open		= gipc_open,
	.unlocked_ioctl	= gipc_ioctl,
	.compat_ioctl	= gipc_ioctl,
	.llseek		= noop_llseek,
};

static struct miscdevice gipc_dev = {
	.minor		= GIPC_MINOR,
	.name		= "gipc",
	.fops		= &gipc_fops,
	.mode		= 0666,
};

static int __init gipc_init(void)
{
	int rv = 0;

#if !defined(CONFIG_GRAPHENE_BULK_IPC) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
	my_do_mmap_pgoff = (do_mmap_pgoff_t)
		kallsyms_lookup_name("do_mmap_pgoff");
	printk(KERN_ERR "resolved symbol do_mmap_pgoff %p\n", my_do_mmap_pgoff);
	if (!my_do_mmap_pgoff) {
		printk(KERN_ERR "Graphene error: "
		       "can't find kernel function do_mmap_pgoff\n");
		return -ENOENT;
	}
#endif

#ifndef gipc_get_session
	my_gipc_get_session = (void *) kallsyms_lookup_name("gipc_get_session");
#endif

#if 0 /* these functions are no longer used, keep here for future use. */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
	my_tlb_gather_mmu = (tlb_gather_mmu_t)
		kallsyms_lookup_name("tlb_gather_mmu");
	printk(KERN_ERR "resolved symbol tlb_gather_mmu %p\n", my_tlb_gather_mmu);
	if (!my_tlb_gather_mmu) {
		printk(KERN_ERR "Graphene error: "
		       "can't find kernel function my_tlb_gather_mmu\n");
		return -ENOENT;
	}

	my_tlb_flush_mmu = (tlb_flush_mmu_t)
		kallsyms_lookup_name("tlb_flush_mmu");
	if (!my_tlb_flush_mmu) {
		printk(KERN_ERR "Graphene error: "
		       "can't find kernel function my_tlb_flush_mmu\n");
		return -ENOENT;
	}

	my_tlb_finish_mmu = (tlb_finish_mmu_t)
		kallsyms_lookup_name("tlb_finish_mmu");
	if (!my_tlb_finish_mmu) {
		printk(KERN_ERR "Graphene error: "
		       "can't find kernel function my_tlb_finish_mmu\n");
		return -ENOENT;
	}
#else
	pmmu_gathers = (struct mmu_gather *)
		kallsyms_lookup_name("mmu_gathers");
	if (!pmmu_gathers) {
		printk(KERN_ERR "Graphene error: "
		       "can't find kernel function mmu_gathers\n");
		return -ENOENT;
	}
#endif /* kernel_version < 3.2 */

	kern_free_pages_and_swap_cachep = (free_pages_and_swap_cache_t)
		kallsyms_lookup_name("free_pages_and_swap_cache");
	if (!kern_free_pages_and_swap_cachep) {
		printk(KERN_ERR "Graphene error: "
		       "can't find kernel function free_pages_and_swap_cache\n");
		return -ENOENT;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 6, 0)
	kern_flush_tlb_mm = (flush_tlb_mm_t)
		kallsyms_lookup_name("flush_tlb_mm");
	if (!kern_flush_tlb_mm) {
		printk(KERN_ERR "Graphene error: "
		       "can't find kernel function flush_tlb_mm\n");
		return -ENOENT;
	}
#endif

	kern_free_pgtables = (free_pgtables_t)
		kallsyms_lookup_name("free_pgtables");
	if (!kern_free_pgtables) {
		printk(KERN_ERR "Graphene error: "
		       "can't find kernel function free_pgtables\n");
		return -ENOENT;
	}

#endif

	/* Register the kmem cache */
	gipc_queue_cachep = kmem_cache_create("gipc_queues",
					      sizeof(struct gipc_queue) +
					      sizeof(struct gipc_pages) * 2,
					      0,
					      SLAB_HWCACHE_ALIGN|
					      SLAB_DESTROY_BY_RCU,
					      NULL);
	if (!gipc_queue_cachep) {
		printk(KERN_ERR "Graphene error: "
		       "failed to create a gipc queues cache\n");
		return -ENOMEM;
	}

	gipc_buf_cachep = kmem_cache_create("gipc_bufs",
					    sizeof(struct gipc_sender_buf),
					    0,
					    SLAB_HWCACHE_ALIGN|
					    SLAB_DESTROY_BY_RCU,
					    NULL);
	if (!gipc_buf_cachep) {
		printk(KERN_ERR "Graphene error: "
		       "failed to create a gipc buffers cache\n");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&gdev.channels);
	spin_lock_init(&gdev.lock);
	gdev.max_token = 1;

	rv = misc_register(&gipc_dev);
	if (rv) {
		printk(KERN_ERR "Graphene error: "
		       "failed to add a char device (rv=%d)\n", rv);
		return rv;
	}

	printk(KERN_ALERT "Graphene IPC: Hello, world\n");
	return 0;
}

static void __exit gipc_exit(void)
{
	struct gipc_queue *gq, *n;
	spin_lock(&gdev.lock);
	list_for_each_entry_safe(gq, n, &gdev.channels, list) {
		release_gipc_pages(&GIPC_PAGES(gq)[0]);
		release_gipc_pages(&GIPC_PAGES(gq)[1]);
		list_del(&gq->list);
		kmem_cache_free(gipc_queue_cachep, gq);
	}
	spin_unlock(&gdev.lock);

	misc_deregister(&gipc_dev);
	kmem_cache_destroy(gipc_queue_cachep);

	printk(KERN_ALERT "Graphene IPC: Goodbye, cruel world\n");
}

module_init(gipc_init);
module_exit(gipc_exit);
