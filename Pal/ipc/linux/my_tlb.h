#ifndef _MY_TLB_H
#define _MY_TLB_H

#include <linux/version.h>

typedef void (* free_pages_and_swap_cache_t )(struct page **, int);

free_pages_and_swap_cache_t kern_free_pages_and_swap_cachep = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 6, 0)
typedef void (* flush_tlb_mm_t) (struct mm_struct *mm);

flush_tlb_mm_t kern_flush_tlb_mm = NULL;
#endif

typedef void (*free_pgtables_t)(struct mmu_gather *tlb, struct vm_area_struct *vma,
			      unsigned long floor, unsigned long ceiling);

free_pgtables_t kern_free_pgtables = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)

/*
 * If we can't allocate a page to make a big batch of page pointers
 * to work on, then just handle a few from the on-stack structure.
 */
#define MMU_GATHER_BUNDLE	8

struct mmu_gather_batch {
	struct mmu_gather_batch	*next;
	unsigned int		nr;
	unsigned int		max;
	struct page		*pages[0];
};

/* struct mmu_gather is an opaque type used by the mm code for passing around
 * any data needed by arch specific code for tlb_remove_page.
 */
struct mmu_gather {
	struct mm_struct	*mm;
#ifdef CONFIG_HAVE_RCU_TABLE_FREE
	struct mmu_table_batch	*batch;
#endif
	unsigned int		need_flush : 1,	/* Did free PTEs */
				fast_mode  : 1; /* No batching   */

	unsigned int		fullmm;

	struct mmu_gather_batch *active;
	struct mmu_gather_batch	local;
	struct page		*__pages[MMU_GATHER_BUNDLE];
};

typedef void (*tlb_gather_mmu_t)(struct mmu_gather *tlb, struct mm_struct *mm, bool fullmm);
tlb_gather_mmu_t my_tlb_gather_mmu = NULL;

typedef void (*tlb_flush_mmu_t)(struct mmu_gather *tlb);
tlb_flush_mmu_t my_tlb_flush_mmu = NULL;

typedef void (*tlb_finish_mmu_t)(struct mmu_gather *tlb, unsigned long start, unsigned long end);
tlb_finish_mmu_t my_tlb_finish_mmu = NULL;

#else

#ifdef CONFIG_X86
#ifdef CONFIG_SMP
  #ifdef ARCH_FREE_PTR_NR
    #define FREE_PTR_NR   ARCH_FREE_PTR_NR
  #else
    #define FREE_PTE_NR	506
  #endif
  #define tlb_fast_mode(tlb) ((tlb)->nr == ~0U)
#else
  #define FREE_PTE_NR	1
  #define tlb_fast_mode(tlb) 1
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
#include <asm/tlbflush.h>
#define tlb_flush(tlb) flush_tlb_mm((tlb)->mm)
#else
#define tlb_flush(tlb) kern_flush_tlb_mm((tlb)->mm)
#endif

/* struct mmu_gather is an opaque type used by the mm code for passing around
 * any data needed by arch specific code for tlb_remove_page.
 */
struct mmu_gather {
	struct mm_struct	*mm;
	unsigned int		nr;	/* set to ~0U means fast mode */
	unsigned int		need_flush;/* Really unmapped some ptes? */
	unsigned int		fullmm; /* non-zero means full mm flush */
	struct page *		pages[FREE_PTE_NR];
};
#else 
#error Need mmu_gather def
#endif

struct mmu_gather *pmmu_gathers = NULL;

/* tlb_gather_mmu
 *	Return a pointer to an initialized struct mmu_gather.
 */
static inline struct mmu_gather *
my_tlb_gather_mmu(struct mm_struct *mm, unsigned int full_mm_flush)
{
	struct mmu_gather *tlb = &get_cpu_var(*pmmu_gathers);

	tlb->mm = mm;

	/* Use fast mode if only one CPU is online */
	tlb->nr = num_online_cpus() > 1 ? 0U : ~0U;

	tlb->fullmm = full_mm_flush;

	return tlb;
}

static inline void
my_tlb_flush_mmu(struct mmu_gather *tlb, unsigned long start, unsigned long end)
{
	if (!tlb->need_flush)
		return;
	tlb->need_flush = 0;
	tlb_flush(tlb);
	if (!tlb_fast_mode(tlb)) {
		kern_free_pages_and_swap_cachep(tlb->pages, tlb->nr);
		tlb->nr = 0;
	}
}


/* tlb_finish_mmu
 *	Called at the end of the shootdown operation to free up any resources
 *	that were required.
 */
static inline void
my_tlb_finish_mmu(struct mmu_gather *tlb, unsigned long start, unsigned long end)
{
	my_tlb_flush_mmu(tlb, start, end);

	/* keep the page table cache within bounds */
	check_pgt_cache();

	put_cpu_var(*pmmu_gathers);
}
#endif // Pre 3.2 kernel


#endif


