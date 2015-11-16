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

/*
 * RBTree for managing registers of each thread
 */

static DEFINE_MUTEX(reg_lock);
static struct rb_root reg_tree = RB_ROOT;
struct reg_node {
    pid_t tid;                  /* key */
    //unsigned long pc;
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
 * RBTree for managing JNIEnv caller
 */

static DEFINE_MUTEX(jni_caller_lock);
static struct rb_root jni_caller_tree = RB_ROOT;
struct jni_caller_node {
    pid_t pid;                  /* key */
    unsigned long jni_caller;
    struct rb_node elem;
};

static inline struct jni_caller_node * rb_search_jni_caller_node(pid_t key)
{
    struct rb_node * n = jni_caller_tree.rb_node;
    struct jni_caller_node * node;

    while (n)
    {
        node = rb_entry(n, struct jni_caller_node, elem);

        if (key < node->pid)
            n = n->rb_left;
        else if (key > node->pid)
            n = n->rb_right;
        else
            return node;
    }
    return NULL;
}

static inline struct jni_caller_node * __rb_insert_jni_caller_node(
        pid_t key,
        struct rb_node * node)
{
    struct rb_node ** p = &(jni_caller_tree.rb_node);
    struct rb_node * parent = NULL;
    struct jni_caller_node * ret;

    while (*p)
    {
        parent = *p;
        ret = rb_entry(parent, struct jni_caller_node, elem);

        if (key < ret->pid)
            p = &(*p)->rb_left;
        else if (key > ret->pid)
            p = &(*p)->rb_right;
        else
            return ret;
    }

    rb_link_node(node, parent, p);

    return NULL;
}

static inline struct jni_caller_node * rb_insert_jni_caller_node(
        pid_t key,
        struct rb_node * node)
{
    struct jni_caller_node * ret;
    if ((ret = __rb_insert_jni_caller_node(key, node)))
        goto out;
    rb_insert_color(node, &jni_caller_tree);
out:
    return ret;
}

/*
 * system calls
 */

#define DOM_MAX 16
#define ENTRY_EXIT_GAP 20
#define UNTRUSTED_SECTIONS 127
#define LIB_STACK_SIZE (1<<22)

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

asmlinkage void sys_set_javaapicaller(unsigned long addr)
{
    struct jni_caller_node* node = NULL;
    pid_t pid = task_tgid_vnr(current);
    mutex_lock(&jni_caller_lock);
    node = rb_search_jni_caller_node(pid);
    if (node == NULL) {
        node = kzalloc(sizeof(*node), GFP_KERNEL);
        if (node == NULL) {
            printk("[sandbox_jnienv] alloc fail %d\n", __LINE__);
            mutex_unlock(&jni_caller_lock);
            return;
        }
        node->pid = pid;
        node->jni_caller = addr;
        printk("[sandbox_jnienv] jni_caller = %lx (%d)\n", addr, pid);
        rb_insert_jni_caller_node(pid, &(node->elem));
    } else {
        printk("[sandbox_jnienv] pid=%d already exists in jni_caller_tree %d\n", pid, __LINE__);
        mutex_unlock(&jni_caller_lock);
        return;
    }
    mutex_unlock(&jni_caller_lock);
}

/*
 * Do not use PC (jump addr) as 1st arg here.
 * It overlaps the real argument (r0).
 * This function must not have any argument (except regs).
 */
asmlinkage void sys_jnienv_enter(struct pt_regs *regs)
{
    struct reg_node* rnode = NULL;
    struct jni_caller_node* node = NULL;
    pid_t tid = task_pid_vnr(current);
    pid_t pid = task_tgid_vnr(current);

    printk("[sandbox_jnienv] ----> sys_jnienv_enter\n");
    mutex_lock(&jni_caller_lock);
    node = rb_search_jni_caller_node(pid);
    if (node == NULL) {
        printk("[sandbox_jnienv] no jni caller at %d\n", __LINE__);
        mutex_unlock(&jni_caller_lock);
        return;
    }
    mutex_unlock(&jni_caller_lock);

    /* backup thread's state */
    mutex_lock(&reg_lock);
    rnode = rb_search_reg_node(tid);
    if (rnode == NULL) {
        rnode = kzalloc(sizeof(*rnode), GFP_KERNEL);
        if (rnode == NULL) {
            printk("[sandbox_jnienv] alloc fail %d\n", __LINE__);
            mutex_unlock(&reg_lock);
            return;
        }
        rnode->tid = tid;
        //rnode->pc = ((unsigned long*)regs)[15];
        memcpy(&rnode->regs, regs, sizeof(struct pt_regs));
        rb_insert_reg_node(tid, &(rnode->elem));
    } else {
        printk("[sandbox_jnienv] tid=%d already exists in reg_tree %d\n", tid, __LINE__);
        mutex_unlock(&reg_lock);
        return;
    }
    mutex_unlock(&reg_lock);

    /*
     * Find jump address i.e. jni caller.
     * And set PC as jump addr.
     */
    printk("[sandbox_jnienv] jni_caller = %lx (%d/%d)\n", node->jni_caller, tid, pid);
    ((unsigned long*)regs)[15] = node->jni_caller;

    /* set domain permission */
    set_domain_client(DOMAIN_USER, DOMAIN_CLIENT);
    printk("[sandbox_jnienv] ----< sys_jnienv_enter\n");
}

asmlinkage unsigned long sys_jnienv_exit(struct pt_regs *regs)
{
    unsigned long ret = 0;
    struct reg_node* rnode = NULL;
    pid_t tid = task_pid_vnr(current);

    printk("[sandbox_jnienv] ----> sys_jnienv_exit\n");
    /* restore thread's state */
    mutex_lock(&reg_lock);
    rnode = rb_search_reg_node(tid);
    if (rnode == NULL) {
        printk("[sandbox_jnienv] tid=%d does not exist in reg_tree %d\n", tid, __LINE__);
        mutex_unlock(&reg_lock);
        return ret;
    } else {
        printk("[sandbox_jnienv] pc = %lx (%d)\n", ((unsigned long*)&rnode->regs)[15], tid);
        ret = ((unsigned long*)regs)[0];
        printk("[sandbox_jnienv] ret = %lx (%d)\n", ret, tid);
        memcpy(regs, &rnode->regs, sizeof(struct pt_regs));
        ((unsigned long*)regs)[0] = ret;
        //((unsigned long*)regs)[15] = rnode->pc;
        rb_erase(&(rnode->elem), &reg_tree);
        kfree(rnode);
    }
    mutex_unlock(&reg_lock);

    /* set domain permission */
    set_domain_client(DOMAIN_USER, DOMAIN_NOACCESS);
    printk("[sandbox_jnienv] ----< sys_jnienv_exit\n");

    return ret;
}
