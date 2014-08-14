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
static struct task_struct *wakeup_task = NULL;
static bool in_stack_inspection = false;

enum {
    CHANNEL_REGISTER_PM = 0,
    CHANNEL_REGISTER_INSPECTOR,
    CHANNEL_UNREGISTER,
};

inline pid_t current_tid(void)
{
    pid_t tid = task_pid_vnr(current);
    return (tid > 0) ? tid : task_tgid_vnr(current);
}

inline pid_t current_pid(void)
{
    return task_tgid_vnr(current);
}

inline char* get_task_name(void)
{
    get_task_comm(current_task_name, current);
    current_task_name[sizeof(current->comm)] = '\0';
    return current_task_name;
}

//----> red black tree interface
static struct rb_root channel_tree = RB_ROOT;
struct channel_node {
    struct rb_node elem;
    pid_t key_pid;
    struct task_struct *value_task;
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
    printk( "[CHANNEL] released (%s, %d)\n", get_task_name(), current_pid() );
    return 0;
}

static ssize_t channel_write( struct file *filp, const char *buf, size_t count, loff_t *f_pos )
{
    long missed_bytes;
    long written_bytes;
    pid_t cur_pid;
    struct channel_node* node;

    written_bytes = 0;
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
            if (!task_is_dead(node->value_task))
            {
                // wake up target stack inspector
                // NOTE: right after releasing wq, it is possible
                // that stack inspector wake up and do not wait writing target tid.
                // Thus holding lock until writing target tid is required.
                mutex_lock(&channel_lock);
                wakeup_task = node->value_task;
                wake_up_all(&wq);

                // write target tid
                missed_bytes = copy_from_user( global_buffer, buf+sizeof(pid_t),
                        count - sizeof(pid_t));
                written_bytes = count - sizeof(pid_t) - missed_bytes;
                printk( "[CHANNEL] write: %d as %ld of %ld (%s, %d)\n",
                        ((pid_t *)buf)[1], written_bytes, count - sizeof(pid_t),
                        get_task_name(), cur_pid );
                mutex_unlock(&channel_lock);
            }
            else
            {
                // Target app is dead.
                // remove from rbtree
                mutex_lock(&channel_lock);
                rb_erase(&(node->elem), &channel_tree);
                kfree( node );
                printk( "[CHANNEL] remove from rbtree: %d (%s, %d)\n",
                        ((pid_t *)buf)[0], get_task_name(), cur_pid );
                mutex_unlock(&channel_lock);
            }
        }
    }
    else
    {
        mutex_lock(&channel_lock);
        node = rb_search_channel_node(cur_pid);
        mutex_unlock(&channel_lock);
        if (node != NULL)
        {
            if (current == node->value_task)
            {
                // call from stack inspector
                mutex_lock(&channel_lock);
                missed_bytes = copy_from_user( global_buffer, buf, count);
                written_bytes = count - missed_bytes;
                printk( "[CHANNEL] write: %s as %ld of %ld (%s, %d)\n",
                        buf, written_bytes, count, get_task_name(), cur_pid );
                mutex_unlock(&channel_lock);

                // Stack inspection ends
                in_stack_inspection = false;
                wake_up_all(&wq);
            }
        }
    }

    printk( "[CHANNEL] write to global_buffer %ld (%s, %d)\n",
            written_bytes, get_task_name(), cur_pid);
    return written_bytes;
}

static ssize_t channel_read( struct file *filp, char *buf, size_t count, loff_t *f_pos )
{
    long missed_bytes;
    long read_bytes;
    pid_t cur_pid;
    struct channel_node* node;

    read_bytes = 0;
    cur_pid = current_pid();

    if (cur_pid == pm_pid)
    {
        // call from pm
        // It means stack inspection begins before.
        // Now this thread should wait until stack inspector finshes it.
        wait_event_interruptible(wq, !in_stack_inspection || task_is_dead(wakeup_task));

        if (task_is_dead(wakeup_task))
        {
            mutex_lock(&channel_lock);
            node = rb_search_channel_node(task_tgid_vnr(wakeup_task));
            if (node)
            {
                // Target app is dead.
                // remove from rbtree
                rb_erase(&(node->elem), &channel_tree);
                kfree( node );
                printk( "[CHANNEL] remove from rbtree: %d (%s, %d)\n",
                        task_tgid_vnr(wakeup_task), get_task_name(), cur_pid );
            }
            mutex_unlock(&channel_lock);
        }

        // Make sure that reading stack trace waits writing stack trace.
        mutex_lock(&channel_lock);
        missed_bytes = copy_to_user( buf, global_buffer, count);
        read_bytes = count - missed_bytes;
        printk( "[CHANNEL] read: %s as %ld of %ld (%s, %d)\n",
                buf, read_bytes, count, get_task_name(), cur_pid );

        // clear wakeup_task
        wakeup_task = NULL;
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
            // NOTE: if wait_event_interruptible() is in critical section(= CS),
            // Only one thread will be in CS and
            // Only the thread can be waked up.
            // It cause dead-lock,
            // thereby staying wait_event_interruptible() out of CS.
            wait_event_interruptible(wq,
                    (wakeup_task == current) && in_stack_inspection);

            // read target tid
            // NOTE: It must wait writing target tid.
            // Therefore, it waits lock until writing target tid has done.
            mutex_lock(&channel_lock);
            missed_bytes = copy_to_user( buf, global_buffer, count);
            read_bytes = count - missed_bytes;
            printk( "[CHANNEL] read: %d as %ld of %ld (%s, %d)\n",
                    ((int*)buf)[0], read_bytes, count, get_task_name(), cur_pid );
            mutex_unlock(&channel_lock);
        }
    }

    printk( "[CHANNEL] read from global_buffer %ld (%s, %d)\n",
            read_bytes, get_task_name(), cur_pid );
    return read_bytes;
}

static long channel_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct channel_node* node;
    pid_t cur_pid;

    cur_pid = current_pid();

    mutex_lock(&channel_lock);
    if ((pm_pid == 0) && (cmd == CHANNEL_REGISTER_PM))
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
        printk( "[CHANNEL] pm_pid=%d (%s, %d)\n", pm_pid, get_task_name(), cur_pid );
    }
    if (cmd == CHANNEL_REGISTER_INSPECTOR)
    {
        node = rb_search_channel_node(cur_pid);
        if (node == NULL)
        {
            // register only one thread for a process
            node = (struct channel_node*) kmalloc(
                    sizeof(struct channel_node),
                    GFP_KERNEL );
            node->key_pid = cur_pid;
            node->value_task = current;
            rb_insert_channel_node(cur_pid, &(node->elem));
        }
        printk( "[CHANNEL] registered %d (%s, %d)\n", cur_pid, get_task_name(), cur_pid );
    }
    if (cmd == CHANNEL_UNREGISTER)
    {
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
