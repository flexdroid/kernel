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
#define  RESPONSE_COUNT 1000000

static char *global_buffer  = NULL;
static char current_task_name[NAME_SIZE];

static DEFINE_MUTEX(channel_lock);
static DECLARE_WAIT_QUEUE_HEAD(wq);
static pid_t target_tid = 0;
static pid_t caller_tid = 0;
static pid_t waiting_tid = 0;
static pid_t waiting_pid = 0;
static pid_t pm_pid = 0;

static int response_count = RESPONSE_COUNT;

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
    printk( "[CHANNEL] released: %d (%s, %d)\n", current_pid(), get_task_name(), current_pid() );
    mutex_lock(&channel_lock);
    node = rb_search_channel_node(current_pid());
    if (node)
    {
        rb_erase(&(node->elem), &channel_tree);
        kfree( node );
        printk( "[CHANNEL] remove: %d (%s, %d)\n", current_pid(), get_task_name(), current_pid() );
    }
    mutex_unlock(&channel_lock);
    return 0;
}

static ssize_t channel_write( struct file *filp, const char *buf, size_t count, loff_t *f_pos )
{
    int sz_data;
    pid_t key;
    pid_t cur_tid;
    struct channel_node* node;

    mutex_lock(&channel_lock);
    cur_tid = current_tid();
    key = current_pid();
    // only pm and registered threads can write
    node = rb_search_channel_node(key);
    if (key != pm_pid)
    {
        // call from registered dvm threads
        if (node == NULL)
        {
            mutex_unlock(&channel_lock);
            return 0;
        }
        else if (node->value_tid != cur_tid)
        {
            mutex_unlock(&channel_lock);
            return 0;
        }
        key = 0;
        caller_tid = cur_tid;
    }
    else
    {
        // call from pm
        caller_tid = key;
        key = ((pid_t *)buf)[0];
    }

    if (key == 0)
        target_tid = pm_pid;
    else
    {
        node = rb_search_channel_node(key);
        if (node != NULL)
            target_tid = node->value_tid;
        else
        {
            target_tid = pm_pid;
            waiting_pid = 0;
            wake_up_all(&wq);
            mutex_unlock(&channel_lock);
            return 0;
        }
    }

    if (caller_tid == pm_pid)
    {
        waiting_pid = key;
        waiting_tid = target_tid;
    }

    wake_up_all(&wq);

    if (BUFF_SIZE < count)
        sz_data  = BUFF_SIZE;
    else
        sz_data  = count;

    if (target_tid == pm_pid)
        strncpy( global_buffer, buf, sz_data);
    else
    {
        strncpy( global_buffer, buf+sizeof(pid_t), sz_data - sizeof(pid_t));
        sz_data -= sizeof(pid_t);
    }

    mutex_unlock(&channel_lock);

    printk( "[CHANNEL] write to global_buffer %d (%s, %d)\n", sz_data, get_task_name(), current_pid());
    return sz_data;
}

inline bool should_continue_to_sleep(void)
{
    pid_t cur_tid = current_tid();
    pid_t cur_pid = current_pid();
    bool ret;

    mutex_lock(&channel_lock);
    ret = (target_tid == cur_tid && caller_tid == pm_pid)
        || (cur_pid == pm_pid && target_tid == pm_pid
                && (caller_tid == waiting_tid
                    || rb_search_channel_node(waiting_pid) == NULL));
    //ret = ret || (cur_pid == pm_pid && --response_count > 0);
    mutex_unlock(&channel_lock);
    return ret;
}

static ssize_t channel_read( struct file *filp, char *buf, size_t count, loff_t *f_pos )
{
    int sz_data;
    pid_t key;
    pid_t cur_tid;
    struct channel_node* node;

    mutex_lock(&channel_lock);
    cur_tid = current_tid();
    key = current_pid();
    // only pm and registered threads can write
    node = rb_search_channel_node(key);
    if (key != pm_pid)
    {
        if (node == NULL)
        {
            mutex_unlock(&channel_lock);
            return 0;
        }
        else if (node->value_tid != cur_tid)
        {
            mutex_unlock(&channel_lock);
            return 0;
        }
    }
    else
    {
        if (response_count <= 0)
        {
            response_count = RESPONSE_COUNT;
            // remove waiting_pid
            node = rb_search_channel_node(waiting_pid);
            if (node)
            {
                rb_erase(&(node->elem), &channel_tree);
                kfree( node );
                printk( "[CHANNEL] remove: %d (%s, %d)\n", waiting_pid, get_task_name(), current_pid() );
            }
            mutex_unlock(&channel_lock);
            return 0;
        }
    }
    mutex_unlock(&channel_lock);

    wait_event(wq, should_continue_to_sleep());

    mutex_lock(&channel_lock);
    sz_data = copy_to_user( buf, global_buffer, count);
    target_tid = 0;
    mutex_unlock(&channel_lock);
    printk( "[CHANNEL] read from global_buffer %d (%s, %d)\n", sz_data, get_task_name(), current_pid() );
    return sz_data;
}

static long channel_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct channel_node* new;
    struct channel_node* node;
    pid_t key;
    mutex_lock(&channel_lock);
    if ((pm_pid == 0) && (cmd == 0))
    {
        pm_pid = current_pid();
        node = rb_search_channel_node(pm_pid);
        if (node)
        {
            rb_erase(&(node->elem), &channel_tree);
            kfree( node );
            printk( "[CHANNEL] remove pm_pid: %d (%s, %d)\n", pm_pid, get_task_name(), current_pid() );
        }
    }
    if (cmd == 1)
    {
        key = current_pid();
        new = rb_search_channel_node(key);
        if (new == NULL)
        {
            new = (struct channel_node*) kmalloc(
                    sizeof(struct channel_node),
                    GFP_KERNEL );
            new->key_pid = key;
            new->value_tid = current_tid();
            rb_insert_channel_node(key, &(new->elem));
        }
    }
    mutex_unlock(&channel_lock);
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
    int ret;
    ret = misc_register(&channel_miscdev);
    global_buffer = (char*) kmalloc( BUFF_SIZE, GFP_KERNEL );
    memset( global_buffer, 0, BUFF_SIZE);

    printk( "[CHANNEL] initialized (%s, %d)\n", get_task_name(), current_pid());

    return ret;
}

device_initcall( channel_init );

MODULE_LICENSE( "GPL" );
