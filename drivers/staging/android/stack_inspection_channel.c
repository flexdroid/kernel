#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/slab.h>

#include <linux/miscdevice.h>
#include <linux/workqueue.h>
#include <linux/device-mapper.h>
#include <linux/pagemap.h>
#include <linux/mempool.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>

#define  BUFF_SIZE      (16 * 1024)
#define  NAME_SIZE      128
#define  MAJOR_NUMBER   250

static char *global_buffer  = NULL;
static char current_task_name[NAME_SIZE];

static DEFINE_MUTEX(channel_lock);
static DECLARE_WAIT_QUEUE_HEAD(wq);
static pid_t pm_pid = 0;
static pid_t wakeup_tid = 0;
static bool in_stack_inspection = false;

inline pid_t current_tid(void) {
    pid_t tid = task_pid_vnr(current);
    return (tid > 0) ? tid : task_tgid_vnr(current);
}

inline pid_t current_pid(void) {
    return task_tgid_vnr(current);
}

inline char* get_task_name(void) {
    get_task_comm(current_task_name, current);
    current_task_name[sizeof(current->comm)] = '\0';
    return current_task_name;
}

//----> red black tree interface
static struct rb_root channel_tree = RB_ROOT;
struct channel_node {
    struct rb_node elem;
    pid_t key_pid;
    pid_t value_tid;
};

static inline struct channel_node * rb_search_channel_node(pid_t key)
{
    struct rb_node * n = channel_tree.rb_node;
    struct channel_node * node;

    while (n)
    {
        node = rb_entry(n, struct channel_node, elem);

        if (key < node->key_pid)
            n = n->rb_left;
        else if (key > node->key_pid)
            n = n->rb_right;
        else
            return node;
    }
    return NULL;
}

static inline struct channel_node * __rb_insert_channel_node(
        pid_t key,
        struct rb_node * node)
{
    struct rb_node ** p = &(channel_tree.rb_node);
    struct rb_node * parent = NULL;
    struct channel_node * ret;

    while (*p)
    {
        parent = *p;
        ret = rb_entry(parent, struct channel_node, elem);

        if (key < ret->key_pid)
            p = &(*p)->rb_left;
        else if (key > ret->key_pid)
            p = &(*p)->rb_right;
        else
            return ret;
    }

    rb_link_node(node, parent, p);

    return NULL;
}

static inline struct channel_node * rb_insert_channel_node(
        pid_t key,
        struct rb_node * node)
{
    struct channel_node * ret;
    if ((ret = __rb_insert_channel_node(key, node)))
        goto out;
    rb_insert_color(node, &channel_tree);
out:
    return ret;
}
//----< red black tree interface

static int channel_open( struct inode *inode, struct file *filp )
{
    printk( "[CHANNEL] opened (%s, %d)\n", get_task_name(), current_pid() );
    return 0;
}

static int channel_release( struct inode *inode, struct file *filp )
{
    struct channel_node* node;
    pid_t cur_pid;

    cur_pid = current_pid();

    mutex_lock(&channel_lock);
    if (cur_pid == pm_pid)
    {
        // if it is pm, clear pm_pid
        pm_pid = 0;
    }

    node = rb_search_channel_node(cur_pid);
    if (node)
    {
        // remove from rbtree
        rb_erase(&(node->elem), &channel_tree);
        kfree( node );
        printk( "[CHANNEL] remove from rbtree: %d (%s, %d)\n",
                cur_pid, get_task_name(), cur_pid );
    }
    mutex_unlock(&channel_lock);

    printk( "[CHANNEL] released: %d (%s, %d)\n",
            cur_pid, get_task_name(), cur_pid );
    return 0;
}

static ssize_t channel_write( struct file *filp, const char *buf, size_t count, loff_t *f_pos )
{
    int sz_data;
    pid_t cur_pid;
    struct channel_node* node;

    sz_data = 0;
    cur_pid = current_pid();

    if (cur_pid == pm_pid)
    {
        // call from pm
        // It means stack inspection begins.
        mutex_lock(&channel_lock);
        in_stack_inspection = true;

        // PM gives (pid, tid) in buf.
        node = rb_search_channel_node(((pid_t *)buf)[0]);
        mutex_unlock(&channel_lock);
        if (node != NULL)
        {
            // wake up target stack inspector
            // NOTE: right after releasing wq, it is possible
            // that stack inspector wake up and do not wait writing target tid.
            // Thus holding lock until writing target tid is required.
            mutex_lock(&channel_lock);
            wakeup_tid = node->value_tid;
            wake_up_all(&wq);

            // write target tid
            sz_data = copy_from_user( global_buffer, buf+sizeof(pid_t), count - sizeof(pid_t));
            mutex_unlock(&channel_lock);
        }
    }
    else
    {
        mutex_lock(&channel_lock);
        node = rb_search_channel_node(cur_pid);
        mutex_unlock(&channel_lock);
        if (node != NULL)
        {
            if (current_tid() == node->value_tid)
            {
                // call from stack inspector
                mutex_lock(&channel_lock);
                sz_data = copy_from_user( global_buffer, buf, count);
                mutex_unlock(&channel_lock);

                // Stack inspection ends
                in_stack_inspection = false;
            }
        }
    }

    printk( "[CHANNEL] write to global_buffer %d (%s, %d)\n",
            sz_data, get_task_name(), cur_pid);
    return sz_data;
}

static ssize_t channel_read( struct file *filp, char *buf, size_t count, loff_t *f_pos )
{
    int sz_data;
    pid_t cur_pid;
    pid_t cur_tid;
    struct channel_node* node;

    sz_data = 0;
    cur_pid = current_pid();

    if (cur_pid == pm_pid)
    {
        // call from pm
        // It means stack inspection begins before.
        // Now this thread should wait until stack inspector finshes it.
        wait_event(wq, !in_stack_inspection);

        // Make sure that reading stack trace waits writing stack trace.
        mutex_lock(&channel_lock);
        sz_data = copy_to_user( buf, global_buffer, count);
        mutex_unlock(&channel_lock);
    }
    else
    {
        mutex_lock(&channel_lock);
        node = rb_search_channel_node(cur_pid);
        mutex_unlock(&channel_lock);
        if (node != NULL)
        {
            // call from stack inspector
            // wait until a stack inspection request arrives
            // NOTE: if wait_event() is in critical section(= CS),
            // Only one thread will be in CS and
            // Only the thread can be waked up.
            // It cause dead-lock, thereby staying wait_event() out of CS.
            cur_tid = current_tid();
            wait_event(wq, (wakeup_tid == cur_tid) && in_stack_inspection);

            // read target tid
            // NOTE: It must wait writing target tid.
            // Therefore, it waits lock until writing target tid has done.
            mutex_lock(&channel_lock);
            sz_data = copy_to_user( buf, global_buffer, count);

            // clear wakeup_tid
            wakeup_tid = 0;
            mutex_unlock(&channel_lock);
        }
    }

    printk( "[CHANNEL] read from global_buffer %d (%s, %d)\n",
            sz_data, get_task_name(), cur_pid );
    return 0;
}

static long channel_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct channel_node* node;
    pid_t cur_pid;

    cur_pid = current_pid();

    mutex_lock(&channel_lock);
    if ((pm_pid == 0) && (cmd == 0))
    {
        pm_pid = cur_pid;
        node = rb_search_channel_node(pm_pid);
        if (node)
        {
            rb_erase(&(node->elem), &channel_tree);
            kfree( node );
            printk( "[CHANNEL] remove from rbtree (because it's pm): %d (%s, %d)\n",
                    pm_pid, get_task_name(), cur_pid );
        }
    }
    if (cmd == 1)
    {
        node = rb_search_channel_node(cur_pid);
        if (node == NULL)
        {
            node = (struct channel_node*) kmalloc(
                    sizeof(struct channel_node),
                    GFP_KERNEL );
            node->key_pid = cur_pid;
            node->value_tid = current_tid();
            rb_insert_channel_node(cur_pid, &(node->elem));
        }
    }
    mutex_unlock(&channel_lock);

    printk( "[CHANNEL] ioctl (%s, %d)\n", get_task_name(), cur_pid );
    return 0;
}

static struct file_operations channel_fops = {
    .owner = THIS_MODULE,
    .read = channel_read,
    .write = channel_write,
    .open = channel_open,
    .unlocked_ioctl = channel_ioctl,
    .release = channel_release
};

static struct miscdevice channel_miscdev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "stack_inspection_channel",
    .fops = &channel_fops
};

int __init channel_init( void )
{
    int ret = 0;
    ret = misc_register(&channel_miscdev);
    global_buffer = (char*) kmalloc( BUFF_SIZE, GFP_KERNEL );
    memset( global_buffer, 0, BUFF_SIZE);

    printk( "[CHANNEL] initialized (%s, %d)\n", get_task_name(), current_pid());

    return ret;
}

device_initcall( channel_init );

MODULE_LICENSE( "GPL" );
