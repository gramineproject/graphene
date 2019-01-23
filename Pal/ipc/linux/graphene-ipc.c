#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/mmu_notifier.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/miscdevice.h>
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/bitmap.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
# include <linux/sched/signal.h>
#endif
#include <asm/mman.h>
#include <asm/tlb.h>

#include "graphene-ipc.h"
#include "ksyms.h"

MODULE_LICENSE("Dual BSD/GPL");

#define FILE_POISON LIST_POISON1

struct kmem_cache *gipc_queue_cachep;
struct kmem_cache *gipc_send_buffer_cachep;

#define GIPC_DEBUG	0

#if defined(GIPC_DEBUG) && GIPC_DEBUG == 1
# define DEBUG(...)		printk(KERN_INFO __VA_ARGS__)
# define GIPC_BUG_ON(cond)      BUG_ON(cond)
#else
# define DEBUG(...)
# define GIPC_BUG_ON(cond)
#endif

#if defined(CONFIG_GRAPHENE_BULK_IPC) || LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)
# if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
#  define DO_MMAP_PGOFF(file, addr, len, prot, flags, pgoff)		\
	({								\
		unsigned long populate;					\
		unsigned long rv = do_mmap_pgoff((file), (addr), (len), \
						 (prot), (flags),	\
			 			 (pgoff), &populate);	\
	rv; })
# else
#  define DO_MMAP_PGOFF(file, addr, len, prot, flags, pgoff)		\
	do_mmap_pgoff((file), (addr), (len), (prot), (flags), (pgoff))
# endif /* kernel_version < 3.9.0 */
#else
# if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#  define MY_DO_MMAP
#  define DO_MMAP_PGOFF(file, addr, len, prot, flags, pgoff)		\
	({								\
		unsigned long populate;					\
		unsigned long rv;					\
	 	rv = KSYM(do_mmap)((file), (addr), (len),		\
				   (prot), (flags), 0, (pgoff),		\
				   &populate, NULL);			\
	rv; })

# elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
#  define MY_DO_MMAP
#  define DO_MMAP_PGOFF(file, addr, len, prot, flags, pgoff)		\
	({								\
		unsigned long populate;					\
		unsigned long rv;					\
	 	rv = KSYM(do_mmap)((file), (addr), (len),		\
				   (prot), (flags), 0, (pgoff),		\
				   &populate);				\
	rv; })
# elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
#  define MY_DO_MMAP_PGOFF
#  define DO_MMAP_PGOFF(file, addr, len, prot, flags, pgoff)		\
	({								\
		unsigned long populate;					\
		unsigned long rv;					\
	 	rv = KSYM(do_mmap_pgoff)((file), (addr), (len),		\
					 (prot), (flags), (pgoff),	\
					 &populate);			\
	rv; })
# else
#  define MY_DO_MMAP_PGOFF
#  define DO_MMAP_PGOFF(file, addr, len, prot, flags, pgoff)		\
	KSYM(do_mmap_pgoff)((file), (addr), (len), (prot), (flags), (pgoff))
# endif /* kernel version < 3.9 */
#endif /* !CONFIG_GRAPHENE_BULK_IPC && kernel version > 3.4.0 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
# ifdef CONFIG_GRAPHENE_BULK_IPC
#  define FLUSH_TLB_MM_RANGE flush_tlb_mm_range
# else
#  define MY_FLUSH_TLB_MM_RANGE
#  define FLUSH_TLB_MM_RANGE KSYM(flush_tlb_mm_range)
# endif
#else /* LINUX_VERSION_CODE < 3.7.0 */
# if defined(CONFIG_GRAPHENE_BULK_IPC) || LINUX_VERSION_CODE < KERNEL_VERSION(3, 2, 0)
#  define FLUSH_TLB_PAGE flush_tlb_page
# else
#  define MY_FLUSH_TLB_PAGE
#  define FLUSH_TLB_PAGE KSYM(flush_tlb_page)
# endif
#endif

#ifdef MY_DO_MMAP
	IMPORT_KSYM(do_mmap);
#endif
#ifdef MY_DO_MMAP_PGOFF
	IMPORT_KSYM(do_mmap_pgoff);
#endif
#ifdef MY_FLUSH_TLB_MM_RANGE
	IMPORT_KSYM(flush_tlb_mm_range);
#endif
#ifdef MY_FLUSH_TLB_PAGE
	IMPORT_KSYM(flush_tlb_page);
#endif

#ifndef gipc_get_session
u64 (*my_gipc_get_session) (struct task_struct *) = NULL;
#endif

struct gipc_queue {
	struct list_head list;
	s64 token;
	u64 owner;
	atomic_t count;

	struct mutex send_lock, recv_lock;
	wait_queue_head_t send, recv;
	volatile int next, last;

	struct {
		struct page *page;
		struct file *file;
		u64 pgoff;
	} pages[PAGE_QUEUE];
};

struct gipc_send_buffer {
	unsigned long page_bit_map[PAGE_BITS];
	struct page *pages[PAGE_QUEUE];
	struct vm_area_struct *vmas[PAGE_QUEUE];
	struct file *files[PAGE_QUEUE];
	unsigned long pgoffs[PAGE_QUEUE];
};

struct {
	spinlock_t lock;
        /*
	 * For now, just make them monotonically increasing.  XXX: At
	 * some point, do something smarter for security.
	 */
	u64 max_token;
	struct list_head channels; // gipc_queue structs
} gdev;

#ifdef gipc_get_session
#define GIPC_OWNER gipc_get_session(current)
#else
#define GIPC_OWNER (my_gipc_get_session ? my_gipc_get_session(current) : 0)
#endif

static inline struct gipc_queue * create_gipc_queue(struct file *creator)
{
	struct gipc_queue *gq = kmem_cache_alloc(gipc_queue_cachep, GFP_KERNEL);

	if (!gq)
		return gq;

	memset(gq, 0, sizeof(*gq));
	INIT_LIST_HEAD(&gq->list);
	mutex_init(&gq->send_lock);
	mutex_init(&gq->recv_lock);
	init_waitqueue_head(&gq->send);
	init_waitqueue_head(&gq->recv);
	gq->owner = GIPC_OWNER;
	creator->private_data = gq;
	atomic_set(&gq->count, 1);

	spin_lock(&gdev.lock);
	list_add(&gq->list, &gdev.channels);
	gq->token = gdev.max_token++;
	spin_unlock(&gdev.lock);

	return gq;
}

static inline void release_gipc_queue(struct gipc_queue *gq, bool locked)
{
	int idx;

	if (!atomic_dec_and_test(&gq->count))
		return;

	if (!locked)
		spin_lock(&gdev.lock);

	while (gq->next != gq->last) {
		idx = gq->next;
		if (gq->pages[idx].page) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
			put_page(gq->pages[idx].page);
#else
			page_cache_release(gq->pages[idx].page);
#endif
			gq->pages[idx].page = NULL;
		}
		if (gq->pages[idx].file) {
			fput_atomic(gq->pages[idx].file);
			gq->pages[idx].file = NULL;
			gq->pages[idx].pgoff = 0;
		}
		gq->next++;
		gq->next &= (PAGE_QUEUE - 1);
	}

	list_del(&gq->list);

	if (!locked)
		spin_unlock(&gdev.lock);

	kmem_cache_free(gipc_queue_cachep, gq);
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

inline int make_page_cow(struct mm_struct *mm, struct vm_area_struct *vma,
			 unsigned long addr)
{
	pgd_t *pgd;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	p4d_t *p4d;
#endif
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		goto no_page;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d)))
		goto no_page;

	pud = pud_offset(p4d, addr);
#else
	pud = pud_offset(pgd, addr);
#endif
	if (pud_none(*pud) || unlikely(pud_bad(*pud)))
		goto no_page;

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
		goto no_page;

	BUG_ON(pmd_trans_huge(*pmd));

	pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
	if (!pte_present(*pte)) {
		spin_unlock(ptl);
		goto no_page;
	}

	ptep_set_wrprotect(mm, addr, pte);
	spin_unlock(ptl);
	DEBUG("make page COW at %lx\n", addr);
	return 0;
no_page:
	return -EFAULT;
}

static void fill_page_bit_map(struct mm_struct *mm,
			      unsigned long addr, unsigned long nr_pages,
			      unsigned long page_bit_map[PAGE_BITS])
{
	int i = 0;

	DEBUG("GIPC_SEND fill_page_bit_map %lx - %lx\n",
	      addr, addr + (nr_pages << PAGE_SHIFT));

	do {
		struct vm_area_struct *vma;
		pgd_t *pgd;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
		p4d_t *p4d;
#endif
		pud_t *pud;
		pmd_t *pmd;
		pte_t *pte;
		spinlock_t *ptl;
		bool has_page = false;

		vma = find_vma(mm, addr);
		if (!vma)
			goto next;

		BUG_ON(vma->vm_flags & VM_HUGETLB);

		pgd = pgd_offset(mm, addr);
		if (pgd_none(*pgd) || pgd_bad(*pgd))
			goto next;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
		p4d = p4d_offset(pgd, addr);
		if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d)))
			goto next;

		pud = pud_offset(p4d, addr);
#else
		pud = pud_offset(pgd, addr);
#endif
		if (pud_none(*pud) || pud_bad(*pud))
			goto next;

		pmd = pmd_offset(pud, addr);
		if (pmd_none(*pmd))
			goto next;

		if (unlikely(pmd_trans_huge(*pmd))) {
			has_page = true;
			goto next;
		}

		if (pmd_bad(*pmd))
			goto next;

		pte = pte_offset_map_lock(mm, pmd, addr, &ptl);

		if (pte_none(*pte))
			goto next_locked;
/*
		if (unlikely(!pte_present(*pte)) && pte_file(*pte))
			goto next_locked;
*/
		has_page = true;
next_locked:
		spin_unlock(ptl);
next:
		if (has_page) {
			DEBUG("found a page at %lx\n", addr);
			set_bit(i, page_bit_map);
		} else {
			clear_bit(i, page_bit_map);
		}
	} while (i++, addr += PAGE_SIZE, i < nr_pages);
}

static int get_pages (struct task_struct *task, unsigned long start,
		      unsigned long nr_pages,
		      unsigned long page_bit_map[PAGE_BITS],
		      struct page *pages[PAGE_QUEUE],
		      struct vm_area_struct *vmas[PAGE_QUEUE])
{
	struct mm_struct *mm = task->mm;
	struct vm_area_struct *vma = NULL;
	unsigned long addr = start, nr;
	int i = 0, j, rv;

	while (i < nr_pages) {
		unsigned long flushed, vmflags;
		int last = i;

		if (test_bit(last, page_bit_map)) {
			i = find_next_zero_bit(page_bit_map, PAGE_QUEUE,
					       last + 1);
			if (i > nr_pages)
				i = nr_pages;
			nr = i - last;

			DEBUG("GIPC_SEND get_user_pages %ld pages at %lx\n",
			      addr, nr);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
			rv = get_user_pages(addr, nr,
					    FOLL_GET|FOLL_FORCE|FOLL_SPLIT,
					    pages + last, vmas + last);
#else
			rv = __get_user_pages(task, mm, addr, nr,
					      FOLL_GET|FOLL_FORCE|FOLL_SPLIT,
					      pages + last, vmas + last, NULL);
#endif
			if (rv <= 0) {
				printk(KERN_ERR "Graphene error: "
				       "get_user_pages at 0x%016lx-0x%016lx\n",
				       addr, addr + (nr << PAGE_SHIFT));
				return rv;
			}

			if (rv != nr) {
				printk(KERN_ERR "Graphene error: "
				       "get_user_pages at 0x%016lx\n",
				       addr + (rv << PAGE_SHIFT));
				return -EACCES;
			}

			flushed = addr;
			vmflags = 0;
			for (j = 0; j < nr; j++) {
				unsigned long target = addr + (j << PAGE_SHIFT);

				/* Mark source COW */
				rv = make_page_cow(mm, vmas[last + j],
						   target);
				if (rv)
					return rv;

				if (PageAnon(pages[last + j])) {
					/* Fix up the counters */
					inc_mm_counter_fast(mm, MM_FILEPAGES);
					dec_mm_counter_fast(mm, MM_ANONPAGES);
					pages[last + j]->mapping = NULL;
				}

#ifdef FLUSH_TLB_MM_RANGE
				if (vmflags == vmas[last + j]->vm_flags)
					continue;
				if (flushed < target)
					FLUSH_TLB_MM_RANGE(mm, flushed, target,
							   vmflags);
				flushed = target;
				vmflags = vmas[last + j]->vm_flags;
#else
				FLUSH_TLB_PAGE(vmas[last + j], target);
#endif
			}

#ifdef FLUSH_TLB_MM_RANGE
			if (flushed < addr + (nr << PAGE_SHIFT))
				FLUSH_TLB_MM_RANGE(mm, flushed,
						   addr + (nr << PAGE_SHIFT),
						   vmflags);
#endif
			vma = vmas[i - 1];
			addr += nr << PAGE_SHIFT;
		} else {
			/* This is the case where a page (or pages) are not
			 * currently mapped.
			 * Handle the hole appropriately. */
			i = find_next_bit(page_bit_map, PAGE_QUEUE, last + 1);
			if (i > nr_pages)
				i = nr_pages;
			nr = i - last;

			DEBUG("GIPC_SEND skip %ld pages at %lx\n", addr, nr);

			for (j = 0; j < nr; j++) {
				if (!vma) {
					vma = find_vma(mm, addr);
				} else {
					/* DEP 6/17/13 - these addresses should
					 * be monotonically increasing. */
					for (; vma && addr >= vma->vm_end;
					     vma = vma->vm_next);

					/* Leverage monotonic increasing vmas
					 * to more quickly detect holes in the
					 * address space. */
					if (vma && addr < vma->vm_start)
						vma = NULL;
				}

				pages[last + j] = NULL;
				vmas[last + j] = vma;
				addr += PAGE_SIZE;
			}
		}
	}

	return i;
}

static int do_gipc_send(struct task_struct *task, struct gipc_queue *gq,
			struct gipc_send_buffer *gbuf,
			unsigned long __user *uaddr, unsigned long __user *ulen,
			unsigned long *copied_pages)
{
	struct mm_struct *mm = task->mm;
	unsigned long addr, len, nr_pages;
	int rv, i;

	DEBUG("GIPC_SEND uaddr = %p, ulen = %p\n", uaddr, ulen);

	rv = copy_from_user(&addr, uaddr, sizeof(unsigned long));
	if (rv) {
		printk(KERN_ALERT "Graphene SEND: bad buffer %p\n", uaddr);
		return -EFAULT;
	}

	rv = copy_from_user(&len, ulen, sizeof(unsigned long));
	if (rv) {
		printk(KERN_ALERT "Graphene SEND: bad buffer %p\n", ulen);
		return -EFAULT;
	}

	if (addr > addr + len) {
		printk(KERN_ALERT "Graphene SEND: attempt to send %p - %p "
		       " by thread %d FAIL: bad argument\n",
		       (void *) addr, (void *) (addr + len), task->pid);
		return -EINVAL;
	}

	DEBUG("GIPC_SEND addr = %lx, len = %ld\n", addr, len);

	nr_pages = len >> PAGE_SHIFT;

	if (!access_ok(VERIFY_READ, addr, len)) {
		printk(KERN_ALERT "Graphene SEND:"
		       " attempt to send %p - %p (%ld pages) "
		       " by thread %d FAIL: bad permission\n",
		       (void *) addr, (void *) (addr + len), nr_pages,
		       task->pid);
		return -EFAULT;
	}

	DEBUG("    %p - %p (%ld pages) sent by thread %d\n",
	      (void *) addr, (void *) (addr + len), nr_pages, task->pid);

	while (nr_pages) {
		unsigned long nr =
			(nr_pages <= PAGE_QUEUE) ? nr_pages : PAGE_QUEUE;

		/* for each of these addresses - check if
		 * demand faulting will be triggered
		 * if vma is present, but there is no page
		 * present(pmd/pud not present or PTE_PRESENT
		 * is off) then get_user_pages will trigger
		 * the creation of those */

		down_write(&mm->mmap_sem);

		fill_page_bit_map(mm, addr, nr, gbuf->page_bit_map);

		rv = get_pages(task, addr, nr,
			       gbuf->page_bit_map,
			       gbuf->pages,
			       gbuf->vmas);
		if (rv < 0) {
			up_write(&mm->mmap_sem);
			break;
		}

		for (i = 0; i < nr; i++) {
			BUG_ON((!gbuf->vmas[i]) && (!!gbuf->pages[i]));
			if (gbuf->vmas[i] && gbuf->vmas[i]->vm_file) {
				gbuf->files[i] = get_file(gbuf->vmas[i]->vm_file);
				gbuf->pgoffs[i] =
					((addr - gbuf->vmas[i]->vm_start) >> PAGE_SHIFT)
					+ gbuf->vmas[i]->vm_pgoff;
			} else {
				gbuf->files[i] = NULL;
				gbuf->pgoffs[i] = 0;
			}
			addr += PAGE_SIZE;
		}

		up_write(&mm->mmap_sem);

		for (i = 0; i < nr ; i++) {
			/* Put in the pending buffer*/
			if (((gq->last + 1) & (PAGE_QUEUE - 1)) == gq->next) {
				/* The blocking condition for send
				 * and recv can't both be true! */
				wake_up_all(&gq->recv);
				wait_event_interruptible(gq->send,
					((gq->last + 1) & (PAGE_QUEUE - 1)) != gq->next);
				if (signal_pending(task)) {
					rv = -ERESTARTSYS;
					goto out;
				}
			}
			gq->pages[gq->last].page = gbuf->pages[i];
			gq->pages[gq->last].file = gbuf->files[i];
			gq->pages[gq->last].pgoff = gbuf->pgoffs[i];
			gq->last++;
			gq->last &= PAGE_QUEUE - 1;
			(*copied_pages)++;
		}

		wake_up_all(&gq->recv);
		nr_pages -= nr;
	}

out:
	return rv;
}

static inline
int recv_next (struct task_struct *task, struct gipc_queue *gq)
{
	if (gq->next == gq->last) {
		/* The blocking condition for send & recv can't both be true */
		wake_up_all(&gq->send);
		wait_event_interruptible(gq->recv, gq->next != gq->last);
		if (signal_pending(task))
			return -ERESTARTSYS;
	}
	
	return gq->next;
}

static int do_gipc_recv(struct task_struct *task, struct gipc_queue *gq,
			unsigned long __user *uaddr, unsigned long __user *ulen,
			unsigned long __user *uprot,
			unsigned long *copied_pages)
{
	struct mm_struct *mm = task->mm;
	struct vm_area_struct *vma = NULL;
	unsigned long start, addr, len, nr_pages, prot, pgoff;
	struct page *page = NULL;
	struct file *file = NULL;
	int i = 0, rv;

	rv = copy_from_user(&addr, uaddr, sizeof(unsigned long));
	if (rv) {
		printk(KERN_ALERT "Graphene RECV: bad buffer %p\n", uaddr);
		return -EFAULT;
	}

	rv = copy_from_user(&len, ulen, sizeof(unsigned long));
	if (rv) {
		printk(KERN_ALERT "Graphene RECV: bad buffer %p\n", ulen);
		return -EFAULT;
	}

	rv = copy_from_user(&prot, uprot, sizeof(unsigned long));
	if (rv) {
		printk(KERN_ALERT "Graphene RECV: bad buffer %p\n", uprot);
		return -EFAULT;
	}

	nr_pages = len >> PAGE_SHIFT;
	start = addr;
	down_write(&mm->mmap_sem);

	while (i < nr_pages) {
		int found = recv_next(task, gq);
		int need_map = 1;

		if (found < 0) {
			rv = found;
			goto finish;
		}

		page = gq->pages[found].page;
		file = gq->pages[found].file;
		pgoff = gq->pages[found].pgoff;
		gq->next++;
		gq->next &= PAGE_QUEUE - 1;
		wake_up_all(&gq->send);

		if (vma) {
			need_map = 0;
			if (vma->vm_file != file)
				need_map = 1;
			if (file && vma->vm_start +
				    ((pgoff - vma->vm_pgoff) << PAGE_SHIFT)
				    != addr)
				need_map = 1;
			if (prot != (vma->vm_flags & (VM_READ|VM_WRITE|VM_EXEC)))
				need_map = 1;
		}

		if (need_map) {
			unsigned long flags = MAP_PRIVATE;

			if (addr)
				flags |= MAP_FIXED;
			if (file)
				flags |= MAP_FILE;
			else
				flags |= MAP_ANONYMOUS;

			addr = DO_MMAP_PGOFF(file, addr,
					     (nr_pages - i) << PAGE_SHIFT,
					     prot, flags, pgoff);

			if (IS_ERR_VALUE(addr)) {
				rv = PTR_ERR((void *) addr);
				printk(KERN_ERR
				       "Graphene error: failed to mmap (%d)\n",
				       -rv);
				goto finish;
			}

			if (file)
				DEBUG("map %08lx-%08lx file %p\n", addr,
				      addr + ((nr_pages - i) << PAGE_SHIFT),
				      file);
			else
				DEBUG("map %08lx-%08lx\n", addr,
				      addr + ((nr_pages - i) << PAGE_SHIFT));

			if (!start)
				start = addr;

			vma = find_vma(mm, addr);
			if (!vma) {
				printk(KERN_ERR
				       "Graphene error: can't find vma at %p\n",
				       (void *) addr);
				rv = -ENOENT;
				goto finish;
			}
		} else {
			BUG_ON(!vma);
		}

		if (page) {
			rv = vm_insert_page(vma, addr, page);
			if (rv) {
				printk(KERN_ERR "Graphene error: "
				       "fail to insert page %d\n", rv);
				goto finish;
			}
			rv = make_page_cow(mm, vma, addr);
			if (rv) {
				printk(KERN_ERR "Graphene error: "
				       "can't make vma copy-on-write at %p\n",
				       (void *) addr);
				goto finish;
			}
		}

finish:
		/* Drop the kernel's reference to this page */
		if (page)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
			put_page(page);
#else
			page_cache_release(page);
#endif
		if (file)
			fput_atomic(file);
		if (rv)
			break;
		i++;
		addr += PAGE_SIZE;
		(*copied_pages)++;
	}

	up_write(&mm->mmap_sem);

	if (i)
		DEBUG("    %p - %p (%d pages) received by thread %d\n",
		      (void *) start, (void *) start + (i << PAGE_SHIFT), i,
		      task->pid);

	if (start) {
		rv = copy_to_user(uaddr, &start, sizeof(unsigned long));
		if (rv) {
			printk(KERN_ERR "Graphene error: bad buffer %p\n",
			       uaddr);
			return -EFAULT;
		}
	}

	return rv;
}

static long gipc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct task_struct *task = current;
	struct gipc_queue *gq = NULL;
	long rv = 0;

	switch (cmd) {

	case GIPC_SEND: {
		struct gipc_send gs;
		struct gipc_send_buffer *gbuf;
		int i;
		unsigned long nr_pages = 0;

		rv = copy_from_user(&gs, (void *) arg, sizeof(gs));
		if (rv) {
			printk(KERN_ALERT "Graphene SEND: bad buffer %p\n",
			       (void *) arg);
			return -EFAULT;
		}

		/* Find/allocate the gipc_pages struct for our recipient */
		gq = (struct gipc_queue *) file->private_data;
		if (!gq)
			return -EFAULT;

		gbuf = kmem_cache_alloc(gipc_send_buffer_cachep, GFP_KERNEL);
		if (!gbuf)
			return -ENOMEM;

		DEBUG("GIPC_SEND %ld entries to token %lld by thread %d\n",
		      gs.entries, gq->token, task->pid);

		mutex_lock(&gq->send_lock);

		for (i = 0; i < gs.entries; i++) {
			rv = do_gipc_send(task, gq, gbuf, gs.addr + i,
					  gs.len + i, &nr_pages);
			if (rv < 0)
				break;
		}

		mutex_unlock(&gq->send_lock);
		DEBUG("GIPC_SEND return to thread %d, %ld pages are sent\n",
		      task->pid, nr_pages);
		kmem_cache_free(gipc_send_buffer_cachep, gbuf);
		rv = nr_pages ? : rv;
		break;
	}

	case GIPC_RECV: {
		struct gipc_recv gr;
		int i;
		unsigned long nr_pages = 0;

		rv = copy_from_user(&gr, (void *) arg, sizeof(gr));
		if (rv) {
			printk(KERN_ERR "Graphene error: bad buffer %p\n",
			       (void *) arg);
			return -EFAULT;
		}

		gq = (struct gipc_queue *) file->private_data;
		if (!gq)
			return -EBADF;

		DEBUG("GIPC_RECV %ld entries to token %lld by thread %d\n",
		      gr.entries, gq->token, task->pid);
		mutex_lock(&gq->recv_lock);

		for (i = 0; i < gr.entries; i++) {
			rv = do_gipc_recv(task, gq, gr.addr + i, gr.len + i,
					  gr.prot + i, &nr_pages);
			if (rv < 0)
				break;
		}

		mutex_unlock(&gq->recv_lock);
		DEBUG("GIPC_RECV return to thread %d, %ld pages are received\n",
		      task->pid, nr_pages);
		rv = nr_pages ? : rv;
		break;
	}

	case GIPC_CREATE: {
		gq = create_gipc_queue(file);
		if (!gq) {
			rv = -ENOMEM;
			break;
		}

		DEBUG("GIPC_CREATE token %lld by thread %d\n", gq->token,
		      task->pid);
		rv = gq->token;
		break;
	}

	case GIPC_JOIN: {
		struct gipc_queue *q;
		u64 token = arg;
		u64 session = GIPC_OWNER;

		if (file->private_data != NULL)
			return -EBUSY;

		/* Search for this token */
		spin_lock(&gdev.lock);
		list_for_each_entry(q, &gdev.channels, list) {
			if (q->token == token) {
				gq = q;
				break;
			}
		}

		/* Fail if we didn't find it */
		if (!gq) {
			spin_unlock(&gdev.lock);
			return -ENOENT;
		}

		if (gq->owner != session) {
			spin_unlock(&gdev.lock);
			return -EPERM;
		}

		atomic_inc(&gq->count);
		file->private_data = gq;

		/* Hold the lock until we allocate so only one process
		 * gets the queue */
		spin_unlock(&gdev.lock);
		DEBUG("GIPC_JOIN token %lld by thread %d\n", token, task->pid);
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
	struct gipc_queue *gq = (struct gipc_queue *) file->private_data;

	if (!gq)
		return 0;

	file->private_data = NULL;
	release_gipc_queue(gq, false);
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

#ifdef MY_DO_MMAP
	LOOKUP_KSYM(do_mmap);
#endif
#ifdef MY_DO_MMAP_PGOFF
	LOOKUP_KSYM(do_mmap_pgoff);
#endif
#ifdef MY_FLUSH_TLB_MM_RANGE
	LOOKUP_KSYM(flush_tlb_mm_range);
#endif
#ifdef MY_FLUSH_TLB_PAGE
	LOOKUP_KSYM(flush_tlb_page);
#endif

#ifndef gipc_get_session
	my_gipc_get_session = (void *) kallsyms_lookup_name("gipc_get_session");
#endif

	/* Register the kmem cache */
	gipc_queue_cachep = kmem_cache_create("gipc_queue",
					      sizeof(struct gipc_queue),
					      0,
					      SLAB_HWCACHE_ALIGN|
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
					      SLAB_TYPESAFE_BY_RCU,
#else
					      SLAB_DESTROY_BY_RCU,
#endif
					      NULL);
	if (!gipc_queue_cachep) {
		printk(KERN_ERR "Graphene error: "
		       "failed to create a gipc queues cache\n");
		return -ENOMEM;
	}

	gipc_send_buffer_cachep = kmem_cache_create("gipc_send_buffer",
					    sizeof(struct gipc_send_buffer),
					    0,
					    SLAB_HWCACHE_ALIGN|
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
					    SLAB_TYPESAFE_BY_RCU,
#else
					    SLAB_DESTROY_BY_RCU,
#endif
					    NULL);
	if (!gipc_send_buffer_cachep) {
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
	list_for_each_entry_safe(gq, n, &gdev.channels, list)
		release_gipc_queue(gq, true);
	spin_unlock(&gdev.lock);

	misc_deregister(&gipc_dev);
	kmem_cache_destroy(gipc_queue_cachep);

	printk(KERN_ALERT "Graphene IPC: Goodbye, cruel world\n");
}

module_init(gipc_init);
module_exit(gipc_exit);
