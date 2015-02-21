#include <asm/unistd.h>
#include <asm/mman.h>
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
    size_t size;
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

int check_jni_block(void)
{
    struct jni_node* node;
    pid_t tid = current_tid();
    mutex_lock(&jni_tree_lock);
    node = rb_search_jni_node(tid);
    mutex_unlock(&jni_tree_lock);
    return node != NULL;
}

#define STACK_AREA_SIZE 20

asmlinkage long sys_enter_JNI(void __user *ubuf)
{
    pid_t tid = current_tid(); /* XXX:this must be the first variable in this function */
    unsigned int pc = (unsigned int)((int*)&tid)[26];
    struct jni_node* node;
    size_t size;
    void* ptr;
    void* p;

    mutex_lock(&jni_tree_lock);

    node = rb_search_jni_node(tid);
    if (node == NULL)
    {
        size = 0;
        while (*((int*)ubuf++))
            ++size;
        ++size;

        ptr = kzalloc(sizeof(int*)*size, GFP_KERNEL);
        p = ptr;
        while (*((int*)ubuf))
            *((unsigned int*)p++) = *((unsigned int*)ubuf++);
        *((unsigned int*)p) = NULL;

        node = kzalloc(sizeof(*node), GFP_KERNEL);
        if (node == NULL) {
            printk("[SYS_ENTER_JNI] alloc fail %d\n", __LINE__);
        }
        node->tid = tid;
        node->page = ptr;
        node->size = size;
        node->pc = pc;
        rb_insert_jni_node(tid, &(node->elem));

        while (*((int*)p)) {
            real_sys_mprotect((unsigned long)_ALIGN_DOWN(*((int*)p),PAGE_SIZE),
                    PAGE_SIZE, PROT_READ);
            ++p;
        }
    }

    mutex_unlock(&jni_tree_lock);
    return 0;
}

asmlinkage long sys_exit_JNI(void)
{
    pid_t tid = current_tid(); /* XXX:this must be the first variable in this function */
    unsigned int pc = (unsigned int)((int*)&tid)[24];
    struct jni_node* node;
    void *p;

    mutex_lock(&jni_tree_lock);

    node = rb_search_jni_node(tid);
    if (node != NULL)
    {
        if (pc == (node->pc+0x20))
        {
            p = node->page;
            while (*((int*)p)) {
                real_sys_mprotect((unsigned long)_ALIGN_DOWN(*((int*)p),PAGE_SIZE),
                        PAGE_SIZE, PROT_READ);
                ++p;
            }
            real_sys_mprotect((unsigned long)node->page, PAGE_SIZE,
                    PROT_READ | PROT_EXEC | PROT_WRITE);

            rb_erase(&(node->elem), &jni_tree);
            kfree( node );
        }
    }

    mutex_unlock(&jni_tree_lock);
    return 0;
}
