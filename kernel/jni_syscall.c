#include <asm/unistd.h>
#include <asm/mman.h>
#include <asm/page.h>
#include <linux/syscalls.h>
#include <linux/rbtree.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>
#include <linux/mempool.h>
#include <linux/slab.h>

//----> jni tree interface
static DEFINE_MUTEX(jni_tree_lock);

static struct rb_root jni_tree = RB_ROOT;
struct jni_node {
    struct rb_node elem;
    pid_t tid;              /* key: thread id */
    void __user *page;      /* value: page address */
    unsigned int pc;        /* value: pc */
};

static inline struct jni_node * rb_search_jni_node(pid_t key)
{
    struct rb_node * n = jni_tree.rb_node;
    struct jni_node * node;

    while (n)
    {
        node = rb_entry(n, struct jni_node, elem);

        if (key < node->tid)
            n = n->rb_left;
        else if (key > node->tid)
            n = n->rb_right;
        else
            return node;
    }
    return NULL;
}

static inline struct jni_node * __rb_insert_jni_node(
        pid_t key,
        struct rb_node * node)
{
    struct rb_node ** p = &(jni_tree.rb_node);
    struct rb_node * parent = NULL;
    struct jni_node * ret;

    while (*p)
    {
        parent = *p;
        ret = rb_entry(parent, struct jni_node, elem);

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

static inline struct jni_node * rb_insert_jni_node(
        pid_t key,
        struct rb_node * node)
{
    struct jni_node * ret;
    if ((ret = __rb_insert_jni_node(key, node)))
        goto out;
    rb_insert_color(node, &jni_tree);
out:
    return ret;
}
//----< jni tree interface

static inline pid_t current_tid(void)
{
    pid_t tid = task_pid_vnr(current);
    return (tid > 0) ? tid : task_tgid_vnr(current);
}

int check_jni_block(unsigned long pg)
{
    struct jni_node* node;
    void* p;
    pid_t tid = current_tid();

    mutex_lock(&jni_tree_lock);
    node = rb_search_jni_node(tid);
    if (node == NULL) {
        mutex_unlock(&jni_tree_lock);
        return 0;
    }

    p = node->page;
    while (*((void**)p)) {
        if (*((unsigned long*)p) == pg) {
            mutex_unlock(&jni_tree_lock);
            return 1;
        }
        ++p;
    }
    mutex_unlock(&jni_tree_lock);
    return 0;
}

#define STACK_AREA_SIZE 20

asmlinkage long sys_enter_JNI(void __user *ubuf)
{
    pid_t tid = current_tid(); /* XXX:this must be the first variable in this function */
    unsigned int pc = (unsigned int)((int*)&tid)[28];
    struct jni_node* node;
    size_t size;
    void* ptr;
    void* p1;
    void* p2;
    unsigned long pg;

    static bool tf = true;
    if (tf) {
        for (size = 0;size < 30;++size)
            printk("[SYS_ENTER_JNI] %x\n", (unsigned int)((int*)&tid)[size]);
        printk("[SYS_ENTER_JNI] pc = %x\n", pc);
        tf = false;
    }

    mutex_lock(&jni_tree_lock);

    node = rb_search_jni_node(tid);
    if (node == NULL)
    {
        size = 0;
        p1 = ubuf;
        while (*((void**)p1++))
            ++size;
        ++size;

        ptr = kzalloc(sizeof(void*)*size, GFP_KERNEL);
        if (ptr == NULL) {
            printk("[SYS_ENTER_JNI] alloc fail %d\n", __LINE__);
        }

        p1 = ubuf;
        p2 = ptr;
        while (*((void**)p1)) {
            pg = (unsigned int)*((void**)p1);
            pg = (pg >> PAGE_SHIFT) << PAGE_SHIFT;
            *((unsigned int*)p2) = pg;
            ++p1;
            ++p2;
        }
        *((void**)p2) = NULL;

        node = kzalloc(sizeof(*node), GFP_KERNEL);
        if (node == NULL) {
            printk("[SYS_ENTER_JNI] alloc fail %d\n", __LINE__);
        }

        node->tid = tid;
        node->page = ptr;
        node->pc = pc;
        rb_insert_jni_node(tid, &(node->elem));

        p2 = ptr;
        while (*((void**)p2)) {
            //real_sys_mprotect(*((unsigned int*)p2), PAGE_SIZE, PROT_READ);
            ++p2;
        }
    }

    mutex_unlock(&jni_tree_lock);
    return 0;
}

asmlinkage long sys_exit_JNI(void)
{
    pid_t tid = current_tid(); /* XXX:this must be the first variable in this function */
    unsigned int pc = (unsigned int)((int*)&tid)[28];
    struct jni_node* node;
    size_t size;
    void* p;
    unsigned long pg;

    static bool tf = true;
    if (tf) {
        for (size = 0;size < 30;++size)
            printk("[SYS_EXIT_JNI] %x\n", (unsigned int)((int*)&tid)[size]);
        printk("[SYS_EXIT_JNI] pc = %x\n", pc);
        tf = false;
    }

    mutex_lock(&jni_tree_lock);

    node = rb_search_jni_node(tid);
    if (node != NULL)
    {
        if (pc == (node->pc+0x50))
        {
            p = node->page;
            while (*((void**)p)) {
                pg = (unsigned int)*((void**)p);
                pg = (pg >> PAGE_SHIFT) << PAGE_SHIFT;
                // real_sys_mprotect(pg, PAGE_SIZE, PROT_READ | PROT_EXEC | PROT_WRITE);
                ++p;
            }

            rb_erase(&(node->elem), &jni_tree);
            kfree( node->page );
            kfree( node );
        }
    }

    mutex_unlock(&jni_tree_lock);
    return 0;
}
