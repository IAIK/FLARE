#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/page-flags.h>
#include <linux/version.h>
#include <asm/pgtable.h>
#include <asm/pgtable_types.h>
#include <asm/page.h>
#include <linux/kprobes.h>

MODULE_LICENSE("GPL");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include <linux/mmap_lock.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#define KPROBE_KALLSYMS_LOOKUP 1
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kallsyms_lookup_name_func;
#define kallsyms_lookup_name kallsyms_lookup_name_func

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

#if CONFIG_PGTABLE_LEVELS != 4 && CONFIG_PGTABLE_LEVELS != 5
#error This module only supports 4 or 5 PT levels
#endif

#define PROMPT KERN_INFO "[FLARE]: "

#define KB(x) (x * 1024ul)
#define MB(x) (x * KB(1024))
#define GB(x) (x * MB(1024))
#define TB(x) (x * GB(1024))

#define KERNEL_RANGE_START  (0xffffffff80000000)
#define MODULE_RANGE_START  (KERNEL_RANGE_START + GB(1))

#define PT_ENTRIES (PAGE_SIZE / sizeof(long))
#define PT_DEFAULT_FLAGS (_PAGE_PRESENT | _PAGE_ACCESSED | _PAGE_DIRTY)

#define ALLOC_ERROR_FMT "ERROR! Could not allocate %s!\n"

MODULE_AUTHOR("FLARE");
MODULE_DESCRIPTION("FLARE: Mitigation for microarchitectural KASLR breaks");

static int entry_ldfr_module(struct kretprobe_instance *ri, struct pt_regs *regs);
static int ret_ldfr_module(struct kretprobe_instance *ri, struct pt_regs *regs);

static struct mm_struct *im = 0;
void (*flush_tlb_all)(void) = 0;

static const int HUGE_PAGE_ORDER = ilog2((MB(2)) / PAGE_SIZE);
static const int modules_order_pte = 0;
static const int PAGE_ORDER = 0;

static struct page *data_page = 0;
static struct page *data_page_nx = 0;
static struct page *pmd_page = 0;
static struct page *pmd_page_nx = 0;
static struct page *pte_page = 0;
static struct page *pte_page_nx = 0;

static pmd_t pmd_line = {0};
static pmd_t pmd_line_nx = {0};
static pte_t pte_line = {0};
static pte_t pte_line_nx = {0};

static pud_t *kernel_pud = 0;
static pud_t *modules_pud = 0;

static const char *LOAD_MODULE_SYMBOL = "load_module";
static const char *FREE_MODULE_SYMBOL = "free_module";

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#define LOCK_MM mmap_write_lock(im);
#define UNLOCK_MM mmap_write_unlock(im);
#else
#define LOCK_MM down_write(&im->mmap_sem);
#define UNLOCK_MM up_write(&im->mmap_sem);
#endif

static struct kretprobe load_module_krp = {
  .entry_handler = entry_ldfr_module,
  .handler = ret_ldfr_module,
  .maxactive = 25
};

static struct kretprobe free_module_krp = {
  .entry_handler = 0,
  .handler = ret_ldfr_module,
  .maxactive = 25
};

static pgd_t *resolve_pgd(unsigned long address) {
  pgd_t *pgd;

  pgd = pgd_offset(im, address);

  if (static_cpu_has(X86_FEATURE_PTI)) {
    return kernel_to_user_pgdp(pgd);
  }

  return pgd;
}

static p4d_t *resolve_p4d(unsigned long address) {
  pgd_t *pgd;
  p4d_t *p4d;

  pgd = resolve_pgd(address);

  if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd))) {
    goto fail;
  }

  p4d = p4d_offset(pgd, address);
  if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d))) {
    goto fail;
  }

  return p4d;
fail:
  return 0;
}

static int mitigate_range(pud_t **pud, size_t RANGE_START, char *message) {
  unsigned long pmd_ctr;
  unsigned long pte_ctr;
  pmd_t *pmd;
  pte_t *pte;
  spinlock_t *pte_lock;
  int was_writable = 0;
  int is_nx = 0;

  *pud = pud_offset(resolve_p4d(RANGE_START), RANGE_START);
  if (pud_none(*(*pud)) || unlikely(pud_bad(*(*pud))))
    goto fail;

  for (pmd_ctr = 0; pmd_ctr < PT_ENTRIES; pmd_ctr++) {
    pmd = pmd_offset(*pud, RANGE_START + MB(2) * pmd_ctr);

    if (!pmd_val(*pmd)) {
      // set PMD based on whether we are in X or NX region
      if(is_nx) {
        set_pmd(pmd, pmd_line_nx);
      } else
        set_pmd(pmd, pmd_line);
      continue;
    }
    // check if we switch now to NX pages
    if(pmd_flags(*pmd) & _PAGE_NX) {
      is_nx = 1;
    } else {
      is_nx = 0;
    }
    // skip if it is a huge page, otherwise we access PTEs that don't exist
    if(pmd_large(*pmd))
      continue;
    // PMD might not have RW permission, fix it temporarily othterwise we crash. Needs tlb flush to take effect
    if(!pmd_write(*pmd)) {
      was_writable = 1;
      *pmd = pmd_mkwrite(*pmd);
      flush_tlb_all();
    }

    for (pte_ctr = 0; pte_ctr < PT_ENTRIES; pte_ctr++) {
      pte = pte_offset_map_lock(im, pmd, RANGE_START + MB(2) * pmd_ctr + PAGE_SIZE * pte_ctr, &pte_lock);
      // check if we switch now to NX pages in case that permissions are switched within PMD
      // this shouldn't occur, but just to be sure
      if(pte_exec(*pte)) {
        is_nx = 1;
      } else {
        is_nx = 0;
      }

      if (!pte_val(*pte)) {
        // set PTE based on whether we are in X or NX region
        if(is_nx) {
          set_pte(pte, pte_line_nx);
        } else
          set_pte(pte, pte_line);
      }

      pte_unmap_unlock(pte, pte_lock);
    }
    // if PMD was previously RO, we revert the changes as we don't modify it until cleanup
    if(was_writable) {
      was_writable = 0;
      *pmd = pmd_wrprotect(*pmd);
      flush_tlb_all();
    }
  }
  flush_tlb_all();
  printk(PROMPT "%s mitigated\n", message);
  return 0;
fail:
  printk(PROMPT "ERROR on %s mitigation!\n", message);
  return -ECANCELED;
}

static void cleanup_mitigation_range(pud_t **pud, size_t RANGE_START, char *message) {
  unsigned long long addr;
  pmd_t *pmd;
  pte_t *pte;
  int pmd_ctr;
  int pte_ctr;
  spinlock_t *pte_lock;
  int was_writable = 0;

  if(!(*pud))
    return;
  for (pmd_ctr = 0; pmd_ctr < PT_ENTRIES; pmd_ctr++) {
    addr = RANGE_START + MB(2) * pmd_ctr;
    pmd = pmd_offset(*pud, addr);
    // check if it is one of our PMDs
    if (page_to_pfn(pte_page) == pmd_pfn(*pmd) || page_to_pfn(pte_page_nx) == pmd_pfn(*pmd)) {
      pmd_clear(pmd);
      continue;
    }

    // skip if it is a huge page, otherwise we access PTEs that don't exist
    if(pmd_large(*pmd))
      continue;

    // check whether page is RO, set to RW if so otherwise we crash. TLB flush required to take effect
    if(!pmd_write(*pmd)) {
      was_writable = 1;
      *pmd = pmd_mkwrite(*pmd);
      flush_tlb_all();
    }

    for (pte_ctr = 0; pte_ctr < PT_ENTRIES; pte_ctr++) {
      pte = pte_offset_map_lock(im, pmd, addr + PAGE_SIZE * pte_ctr, &pte_lock);
      // check if it is one of our PTEs, set to zero if that is the case
      if (page_to_pfn(data_page) == pte_pfn(*pte) || page_to_pfn(data_page_nx) == pte_pfn(*pte)) {
        set_pte(pte, native_make_pte(0));
      }
      pte_unmap_unlock(pte, pte_lock);
    }
    // if page was previously RO, we revert the change. TLB flush required to take effect
    if(was_writable) {
      was_writable = 0;
      *pmd = pmd_wrprotect(*pmd);
      flush_tlb_all();
    }
  }
  flush_tlb_all();
  printk(PROMPT "Removed %s mitigation\n", message);
}

static int entry_ldfr_module(struct kretprobe_instance *ri, struct pt_regs *regs) {
  LOCK_MM
  cleanup_mitigation_range(&modules_pud, MODULE_RANGE_START, "Modules");
  UNLOCK_MM
  return 0;
}

static int ret_ldfr_module(struct kretprobe_instance *ri, struct pt_regs *regs) {
  LOCK_MM
  mitigate_range(&modules_pud, MODULE_RANGE_START, "Modules");
  UNLOCK_MM
  return 0;
}

static void fill_pt(struct page *pt, unsigned long line) {
  int x;
  unsigned long *ptr;

  ptr = page_address(pt);

  for (x = 0; x < PT_ENTRIES; x++) {
    *(ptr+x) = line;
  }
}

static bool alloc_pt_pages(void) {
  data_page = alloc_pages(GFP_KERNEL | __GFP_ZERO, PAGE_ORDER);
  if (data_page == 0) {
    printk(PROMPT ALLOC_ERROR_FMT, "data page");
    goto fail;
  }

  data_page_nx = alloc_pages(GFP_KERNEL | __GFP_ZERO, PAGE_ORDER);
  if (data_page_nx == 0) {
    printk(PROMPT ALLOC_ERROR_FMT, "data page nx");
    goto fail;
  }

  pte_page = alloc_pages(GFP_KERNEL | __GFP_ZERO, PAGE_ORDER);
  if (pte_page == 0) {
    printk(PROMPT ALLOC_ERROR_FMT, "pte page");
    goto fail;
  }

  pte_page_nx = alloc_pages(GFP_KERNEL | __GFP_ZERO, PAGE_ORDER);
  if (pte_page_nx == 0) {
    printk(PROMPT ALLOC_ERROR_FMT, "pte page nx");
    goto fail;
  }

  pmd_page = alloc_pages(GFP_KERNEL | __GFP_ZERO, PAGE_ORDER);
  if (pmd_page == 0) {
    printk(PROMPT ALLOC_ERROR_FMT, "pmd page");
    goto fail;
  }

  pmd_page_nx = alloc_pages(GFP_KERNEL | __GFP_ZERO, PAGE_ORDER);
  if (pmd_page_nx == 0) {
    printk(PROMPT ALLOC_ERROR_FMT, "pmd page nx");
    goto fail;
  }

  return true;
fail:
  return false;
}

static void setup_pt_lines(void) {
  //4KB
  pte_line = native_make_pte((page_to_pfn(data_page) << PAGE_SHIFT) | PT_DEFAULT_FLAGS);
  pte_line_nx = native_make_pte((page_to_pfn(data_page_nx) << PAGE_SHIFT) | PT_DEFAULT_FLAGS | _PAGE_NX);
  pmd_line = native_make_pmd((page_to_pfn(pte_page) << PAGE_SHIFT) | PT_DEFAULT_FLAGS);
  pmd_line_nx = native_make_pmd((page_to_pfn(pte_page_nx) << PAGE_SHIFT) | PT_DEFAULT_FLAGS | _PAGE_NX);

  //4KB
  fill_pt(pte_page, pte_val(pte_line));
  fill_pt(pte_page_nx, pte_val(pte_line_nx));
  fill_pt(pmd_page, pmd_val(pmd_line));
  fill_pt(pmd_page_nx, pmd_val(pmd_line_nx));
}

static bool setup_probes(void) {
  load_module_krp.kp.symbol_name = LOAD_MODULE_SYMBOL;
  free_module_krp.kp.symbol_name = FREE_MODULE_SYMBOL;

  if (register_kretprobe(&load_module_krp) < 0) {
    printk(PROMPT "Failed to register the load_module probe!\n");
    goto fail;
  }

  if (register_kretprobe(&free_module_krp) < 0) {
    printk(PROMPT "Failed to register the free_module probe!\n");
    unregister_kretprobe(&load_module_krp);
    goto fail;
  }

  return true;
fail:
  return false;
}

static void free_allocated_pages(void) {
  if(data_page) {
    free_pages((unsigned long) page_address(data_page), PAGE_ORDER);
  }
  if(data_page_nx) {
    free_pages((unsigned long) page_address(data_page_nx), PAGE_ORDER);
  }
  if(pmd_page) {
    free_pages((unsigned long) page_address(pmd_page), PAGE_ORDER);
  }
  if(pmd_page_nx) {
    free_pages((unsigned long) page_address(pmd_page_nx), PAGE_ORDER);
  }
  if(pte_page) {
    free_pages((unsigned long) page_address(pte_page), PAGE_ORDER);
  }
  if(pte_page_nx) {
    free_pages((unsigned long) page_address(pte_page_nx), PAGE_ORDER);
  }
}

static int __init mitigation_init(void){
  printk(PROMPT "Loading module\n");

#ifdef KPROBE_KALLSYMS_LOOKUP
  /* register the kprobe */
  register_kprobe(&kp);

  /* assign kallsyms_lookup_name symbol to kp.addr */
  kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;

  /* done with the kprobe, so unregister it */
  unregister_kprobe(&kp);

  if(unlikely(!kallsyms_lookup_name)) {
    printk(PROMPT "Could not retrieve kallsyms_lookup_name\n");
    return -ENXIO;
  }
#endif

  im = (void *) kallsyms_lookup_name("init_mm");
  flush_tlb_all = (void *) kallsyms_lookup_name("flush_tlb_all");

  if (!alloc_pt_pages()) {
    goto fail;
  }

  setup_pt_lines();

  // Lock im
  LOCK_MM

  // setup kret probes
  if (!setup_probes()) {
    goto fail_unlock;
  }

  mitigate_range(&kernel_pud, KERNEL_RANGE_START, "Kernel");
  mitigate_range(&modules_pud, MODULE_RANGE_START, "Modules");

  // Unlock mm
  UNLOCK_MM


  return 0;
fail_unlock:
  UNLOCK_MM
fail:
  free_allocated_pages();
  return -ENOMEM;
}

static void __exit mitigation_exit(void){
  printk(KERN_INFO PROMPT "Unloading module\n");

  unregister_kretprobe(&load_module_krp);
  unregister_kretprobe(&free_module_krp);

  // Lock mm
  LOCK_MM

  cleanup_mitigation_range(&kernel_pud, KERNEL_RANGE_START, "Kernel");
  cleanup_mitigation_range(&modules_pud, MODULE_RANGE_START, "Modules");

  // Unlock mm
  UNLOCK_MM

  free_allocated_pages();

  flush_tlb_all();
  printk(PROMPT "Mitigations removed\n");
}

module_init(mitigation_init);
module_exit(mitigation_exit);
