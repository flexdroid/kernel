#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/gfp.h>
#include <linux/mm.h>

#include <asm/elf.h>
#include <asm/unistd.h>

#include <asm/domain.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/bug.h>
#include <asm/tlbflush.h>

#include <linux/slab.h>

#define cond_printk(...) printk(__VA_ARGS__)

/*
 * RBTree for managing registers of each thread
 */

static DEFINE_MUTEX(reg_lock);
static struct rb_root reg_tree = RB_ROOT;
struct reg_node {
    pid_t tid;                  /* key */
    struct pt_regs regs;
    struct rb_node elem;
};

static inline struct reg_node * rb_search_reg_node(pid_t key)
{
    struct rb_node * n = reg_tree.rb_node;
    struct reg_node * node;

    while (n)
    {
        node = rb_entry(n, struct reg_node, elem);

        if (key < node->tid)
            n = n->rb_left;
        else if (key > node->tid)
            n = n->rb_right;
        else
            return node;
    }
    return NULL;
}

static inline struct reg_node * __rb_insert_reg_node(
        pid_t key,
        struct rb_node * node)
{
    struct rb_node ** p = &(reg_tree.rb_node);
    struct rb_node * parent = NULL;
    struct reg_node * ret;

    while (*p)
    {
        parent = *p;
        ret = rb_entry(parent, struct reg_node, elem);

        if (key < ret->tid)
            p = &(*p)->rb_left;
        else if (key > ret->tid)
            p = &(*p)->rb_right;
        else
            return ret;
    }

    rb_link_node(node, parent, p);

    return NULL;
}

static inline struct reg_node * rb_insert_reg_node(
        pid_t key,
        struct rb_node * node)
{
    struct reg_node * ret;
    if ((ret = __rb_insert_reg_node(key, node)))
        goto out;
    rb_insert_color(node, &reg_tree);
out:
    return ret;
}

/*
 * system calls
 */

#define DOM_MAX 16
#define ENTRY_EXIT_GAP 20
#define UNTRUSTED_SECTIONS 127
#define LIB_STACK_SIZE (1<<20)

static void set_domain_client(unsigned int domain, unsigned int type)
{
    do {
        struct thread_info *thread = current_thread_info();
        unsigned int dom_ = thread->cpu_domain;
        dom_ &= ~domain_val(domain, DOMAIN_MANAGER);
        thread->cpu_domain = dom_ | domain_val(domain, type);
        do {
            __asm__ __volatile__(
                    "mcr	p15, 0, %0, c3, c0	@ set domain"
                    : : "r" (thread->cpu_domain));
            isb();
        } while (0);
    } while (0);
}

asmlinkage unsigned long sys_jump_out(struct pt_regs *regs)
{
    set_domain_client(DOMAIN_USER, DOMAIN_CLIENT);
    return ((unsigned long*)regs)[0];
}

asmlinkage unsigned long sys_jump_in(struct pt_regs *regs)
{
    set_domain_client(DOMAIN_USER, DOMAIN_NOACCESS);
    return ((unsigned long*)regs)[0];
}

asmlinkage unsigned long sys_enter_sandbox(unsigned long addr,
        unsigned long stack, struct pt_regs *regs)
{
    unsigned long dacr = 0;
    struct reg_node* rnode = NULL;
    pid_t tid = task_pid_vnr(current);
    unsigned int i;

    cond_printk("----> sys_enter_sandbox\n");
    for (i = 0; i < 16; i++) {
        cond_printk("%08lx ", ((unsigned long*)regs)[i]);
        if (i == 7)
            cond_printk("\n");
    }
    cond_printk("\n");

    /* backup thread's state */
    mutex_lock(&reg_lock);
    rnode = rb_search_reg_node(tid);
    if (rnode == NULL) {
        // register only one thread for a process
        rnode = kzalloc(sizeof(*rnode), GFP_KERNEL);
        if (rnode == NULL) {
            cond_printk("[sandbox] alloc fail %d\n", __LINE__);
            mutex_unlock(&reg_lock);
            return 0;
        }
        rnode->tid = tid;
        memcpy(&rnode->regs, regs, sizeof(struct pt_regs));
        rb_insert_reg_node(tid, &(rnode->elem));
    } else {
        cond_printk("[sandbox] tid=%d already exists in reg_tree %d\n", tid, __LINE__);
        mutex_unlock(&reg_lock);
        return 0;
    }
    mutex_unlock(&reg_lock);

    /* set jump_to_jni as pc and sp */
    ((unsigned long*)regs)[1] = stack;
    ((unsigned long*)regs)[13] = stack + LIB_STACK_SIZE - PAGE_SIZE;
    ((unsigned long*)regs)[15] = addr + (1<<11) + 1;

    cond_printk("pid = %d, tid = %d\n", task_tgid_vnr(current), task_pid_vnr(current));

    /* Read from DACR */
    __asm__ __volatile__(
            "mrc p15, 0, %[result], c3, c0, 0\n"
            : [result] "=r" (dacr) : );
    cond_printk("[0x%lx] dacr=0x%lx\n", addr, dacr);

    /* Write to DACR */
    // set_domain_client(DOMAIN_UNTRUSTED, DOMAIN_CLIENT);
    set_domain_client(DOMAIN_USER, DOMAIN_NOACCESS);

    /* Read from DACR */
    __asm__ __volatile__(
            "mrc p15, 0, %[result], c3, c0, 0\n"
            : [result] "=r" (dacr) : );
    cond_printk("[0x%lx] dacr=0x%lx\n", addr, dacr);
    cond_printk("----< sys_enter_sandbox\n");

    return addr;
}

asmlinkage void sys_exit_sandbox(struct pt_regs *regs)
{
    unsigned long dacr = 0;
    struct reg_node* rnode = NULL;
    pid_t tid = task_pid_vnr(current);
    unsigned int i;

    cond_printk("----> sys_exit_sandbox\n");
    /* restore thread's state */
    mutex_lock(&reg_lock);
    rnode = rb_search_reg_node(tid);
    if (rnode == NULL) {
        cond_printk("[sandbox] tid=%d does not exist in reg_tree %d\n", tid, __LINE__);
        mutex_unlock(&reg_lock);
        return;
    } else {
        memcpy(regs, &rnode->regs, sizeof(struct pt_regs));
        rb_erase(&(rnode->elem), &reg_tree);
        kfree(rnode);
    }
    mutex_unlock(&reg_lock);

    cond_printk("pid = %d, tid = %d\n", task_tgid_vnr(current), task_pid_vnr(current));

    /* Write to DACR */
    set_domain_client(DOMAIN_USER, DOMAIN_CLIENT);
    // set_domain_client(DOMAIN_UNTRUSTED, DOMAIN_NOACCESS);

    /* Read from DACR */
    __asm__ __volatile__(
            "mrc p15, 0, %[result], c3, c0, 0\n"
            : [result] "=r" (dacr) : );
    cond_printk("dacr=0x%lx\n", dacr);

    for (i = 0; i < 16; i++) {
        cond_printk("%08lx ", ((unsigned long*)regs)[i]);
        if (i == 7)
            cond_printk("\n");
    }
    cond_printk("\n");
    cond_printk("----< sys_exit_sandbox\n");
}

asmlinkage void sys_mark_sandbox(unsigned long addr, unsigned long sects)
{
    struct mm_struct *mm = current->mm;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    unsigned int i;

    spin_lock(&mm->page_table_lock);
    pgd = pgd_offset(mm, addr);
    pud = pud_offset(pgd, addr);
    pmd = pmd_offset(pud, addr);
    if (addr & SECTION_SIZE)
        pmd++;

    for (i = 0; i < sects; ++i) {
        *pmd = (*pmd & 0xfffffe1f) | (DOMAIN_UNTRUSTED << 5);
        flush_pmd_entry(pmd);
        pmd++;
    }
    spin_unlock(&mm->page_table_lock);
    cond_printk("[sys_mark_sandbox] addr=0x%lx, sects=%ld\n", addr, sects);
}
