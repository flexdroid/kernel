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
#include <linux/cred.h>

#include <linux/sched.h>
#include <linux/semaphore.h>

#define  BUFF_SIZE      (16 * 1024)
#define  BIG_BUFF_SIZE  (16 * 1024)
#define  NAME_SIZE      128
#define  MAJOR_NUMBER   250

#define cond_printk(fmt, ...) \
    if (do_prtk) {\
        mutex_lock(&tname_lock);\
        printk(fmt, __VA_ARGS__);\
        mutex_unlock(&tname_lock);\
    }

#define mutex_deferred_lock(lock) \
  if (pm_pid != 0) mutex_lock(lock);
#define mutex_deferred_unlock(lock) \
  if (pm_pid != 0) mutex_unlock(lock);

/* for logging */
static const bool do_prtk = false;
static char current_task_name[NAME_SIZE];
static DEFINE_MUTEX(tname_lock);

/* for stack inspection */
static char *global_buffer  = NULL;
static long input_size = 0;
static DEFINE_MUTEX(channel_lock);
static DEFINE_MUTEX(pm_lock);
static DECLARE_WAIT_QUEUE_HEAD(wq);
static pid_t pm_pid = 0;
static pid_t wakeup_pid = 0;
static bool in_stack_inspection = false;

/* for data transfer */
struct semaphore req_sema;
struct semaphore res_sema;
static int req_uid = 0;
static int req_code = 0;
static char *data_trans_buffer  = NULL;
static DEFINE_MUTEX(data_lock);

enum {
    CHANNEL_REGISTER_PM = 0,
    CHANNEL_REGISTER_INSPECTOR,
    CHANNEL_UNREGISTER,
    CHANNEL_PM_WAIT,
    CHANNEL_REQUEST_PM,
    CHANNEL_PM_RESPONSE,
};

enum {
    GET_SANDBOXNAMES = 0,
    GET_GIDS,
};

struct sdb_packet {
    int size;
    void* addr;
};

static long __channel_ioctl(unsigned int, unsigned long);

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

//----> gids tree interface
static struct rb_root gids_tree = RB_ROOT;
struct gids_node {
    struct rb_node elem;
    int key_uid;
    int **value_gids;
};

static inline struct gids_node * rb_search_gids_node(int key)
{
    struct rb_node * n = gids_tree.rb_node;
    struct gids_node * node;

    while (n)
    {
        node = rb_entry(n, struct gids_node, elem);

        if (key < node->key_uid)
            n = n->rb_left;
        else if (key > node->key_uid)
            n = n->rb_right;
        else
            return node;
    }
    return NULL;
}

static inline struct gids_node * __rb_insert_gids_node(
        int key,
        struct rb_node * node)
{
    struct rb_node ** p = &(gids_tree.rb_node);
    struct rb_node * parent = NULL;
    struct gids_node * ret;

    while (*p)
    {
        parent = *p;
        ret = rb_entry(parent, struct gids_node, elem);

        if (key < ret->key_uid)
            p = &(*p)->rb_left;
        else if (key > ret->key_uid)
            p = &(*p)->rb_right;
        else
            return ret;
    }

    rb_link_node(node, parent, p);

    return NULL;
}

static inline struct gids_node * rb_insert_gids_node(
        int key,
        struct rb_node * node)
{
    struct gids_node * ret;
    if ((ret = __rb_insert_gids_node(key, node)))
        goto out;
    rb_insert_color(node, &gids_tree);
out:
    return ret;
}
//----< gids tree interface

const static int GID_DELIMITER = -1;
static int** create_gids(int* buf, int size)
{
    int** gids = (int**) kmalloc( size*sizeof(int*), GFP_KERNEL );
    int* gid_arr;
    int offset = 0, i, j;
    for (i = 0; i < size; ++i) {
        for (j = 0; buf[j+offset] != GID_DELIMITER; ++j);
        gid_arr = (int*) kmalloc( j*sizeof(int), GFP_KERNEL );
        for (j = 0; buf[j+offset] != GID_DELIMITER; ++j)
            gid_arr[j] = buf[j+offset];
        offset += (j + 1);
        gids[i] = gid_arr;
    }
    return gids;
}

//----> channel tree interface
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
//----< channel tree interface

inline long start_inspection(pid_t target_pid, pid_t target_tid)
{
    long written_bytes;
    struct channel_node* node;
    pid_t cur_pid;

    written_bytes = 0;
    cur_pid = current_pid();

    // wait until the previous stack inspection will finish
    mutex_lock(&pm_lock);

    mutex_lock(&channel_lock);
    node = rb_search_channel_node(target_pid);
    mutex_unlock(&channel_lock);
    if (node != NULL)
    {
        mutex_lock(&channel_lock);

        // stack inspection begins.
        in_stack_inspection = true;

        // write target tid
        memcpy((void*)global_buffer, (void*)&target_tid, sizeof(pid_t));
        written_bytes = sizeof(pid_t);

        input_size = written_bytes;
        cond_printk( "[CHANNEL] write: %d as %ld (%s, %d)\n",
                target_tid, written_bytes, get_task_name(), cur_pid );

        // wake up target stack inspector
        set_user_nice(node->value_task, 19);
        wakeup_pid = target_pid;
        wake_up_all(&wq);
        mutex_unlock(&channel_lock);
    }
    else
    {
        // Target app is dead.
        // Do not inspect stack
        mutex_unlock(&pm_lock);
    }
    return written_bytes;
}

inline long request_data(int code, void __user * ubuf)
{
    long size = 0;
    mutex_lock(&data_lock);
    req_uid = current_uid();
    req_code = code;
    up(&req_sema);
    down(&res_sema);
    if (code == GET_SANDBOXNAMES && ubuf)
    {
        size = ((int*)data_trans_buffer)[0];
        memcpy(ubuf, (void*)&((int*)data_trans_buffer)[1], size);
    }
    req_uid = 0;
    req_code = 0;
    mutex_unlock(&data_lock);
    return size;
}

static int channel_open( struct inode *inode, struct file *filp )
{
    printk( "[CHANNEL] opened (%s, %d)\n", get_task_name(), current_pid() );
    return 0;
}

static int channel_release( struct inode *inode, struct file *filp )
{
    // Stack Inspector is dead, so we clear the node of rbtree.
    // NOTE: In usual, release is independent with the life of proc. (release = close)
    //       However, in Stack Inspector, release only called at the end of proc.
    struct channel_node* node;
    pid_t cur_pid = current_pid();

    mutex_lock(&channel_lock);
    node = rb_search_channel_node(cur_pid);
    if (node)
    {
        // remove from rbtree
        rb_erase(&(node->elem), &channel_tree);
        kfree( node );
        cond_printk( "[CHANNEL] remove from rbtree: %d (%s, %d)\n",
                cur_pid, get_task_name(), cur_pid );
    }
    if (cur_pid == wakeup_pid && in_stack_inspection)
    {
        wakeup_pid = 0;
        in_stack_inspection = false;
    }
    mutex_unlock(&channel_lock);

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
        written_bytes = start_inspection(((pid_t *)buf)[0], ((pid_t *)buf)[1]);
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
                input_size = written_bytes;
                cond_printk( "[CHANNEL] write: %ld of %u (%s, %d)\n",
                        written_bytes, count, get_task_name(), cur_pid );
                mutex_unlock(&channel_lock);

                // The end of Stack Inspection
                in_stack_inspection = false;
                wake_up_all(&wq);
            }
        }
    }

    cond_printk( "[CHANNEL] write to global_buffer %ld (%s, %d)\n",
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
        wait_event_interruptible(wq, !in_stack_inspection);
        mutex_lock(&channel_lock);
        if (wakeup_pid)
        {
            // Make sure that reading stack trace waits writing stack trace.
            missed_bytes = copy_to_user( buf, global_buffer, input_size );
            read_bytes = input_size - missed_bytes;
            cond_printk( "[CHANNEL] read: %ld of %ld (%s, %d)\n",
                    read_bytes, input_size, get_task_name(), cur_pid );
        }
        mutex_unlock(&channel_lock);

        // clear global variables
        mutex_lock(&channel_lock);
        wakeup_pid = 0;
        input_size = 0;
        in_stack_inspection = false;
        mutex_unlock(&channel_lock);

        // allow the next pm to inspect stack trace
        mutex_unlock(&pm_lock);
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
                    (wakeup_pid == cur_pid) && in_stack_inspection);

            // read target tid
            // NOTE: It must wait writing target tid.
            // Therefore, it waits lock until writing target tid has done.
            mutex_lock(&channel_lock);
            missed_bytes = copy_to_user( buf, global_buffer, input_size );
            read_bytes = input_size - missed_bytes;
            cond_printk( "[CHANNEL] read: %d as %ld of %ld (%s, %d)\n",
                    ((int*)buf)[0], read_bytes, input_size, get_task_name(), cur_pid );
            mutex_unlock(&channel_lock);
        }
    }

    cond_printk( "[CHANNEL] read from global_buffer %ld (%s, %d)\n",
            read_bytes, get_task_name(), cur_pid );
    return read_bytes;
}

static long channel_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
  return __channel_ioctl(cmd, arg);
}

static long __channel_ioctl(unsigned int cmd, unsigned long arg)
{
    struct channel_node* node;
    struct gids_node* __gids_node;
    pid_t cur_pid;
    void __user *ubuf;
    long size = 0;
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
            cond_printk( "[CHANNEL] remove from rbtree (because it's pm): %d (%s, %d)\n",
                    pm_pid, get_task_name(), cur_pid );
        }
        cond_printk( "[CHANNEL] pm_pid=%d (%s, %d)\n", pm_pid, get_task_name(), cur_pid );
    }
    if ((cmd == CHANNEL_REGISTER_INSPECTOR) && (cur_pid != pm_pid))
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
        cond_printk( "[CHANNEL] registered %d (%s, %d)\n", cur_pid, get_task_name(), cur_pid );
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
            cond_printk( "[CHANNEL] remove from rbtree: %d (%s, %d)\n",
                    cur_pid, get_task_name(), cur_pid );
        }
    }
    mutex_unlock(&channel_lock);

    if (cmd == CHANNEL_PM_WAIT)
    {
        if (cur_pid == pm_pid)
        {
            down(&req_sema);
            ubuf = (void __user *)arg;
            ((int *)ubuf)[0] = req_uid;
            ((int *)ubuf)[1] = req_code;
        }
    }

    if (cmd == CHANNEL_REQUEST_PM)
    {
        mutex_lock(&channel_lock);
        node = rb_search_channel_node(cur_pid);
        mutex_unlock(&channel_lock);
        // stack inspector cannot request gids
        if (node)
            size = request_data(GET_SANDBOXNAMES, (void __user *)arg);
    }

    if (cmd == CHANNEL_PM_RESPONSE)
    {
        if (cur_pid == pm_pid)
        {
            ubuf = (void __user *)arg;
            if (ubuf == NULL)
                up(&res_sema);
            else
            {
                if (req_code == GET_GIDS)
                {
                    // get gids
                    memcpy(&size, ubuf, sizeof(int));

                    // construct gids tree
                    __gids_node = (struct gids_node*) kmalloc(
                            sizeof(struct gids_node), GFP_KERNEL );
                    __gids_node->key_uid = req_uid;
                    __gids_node->value_gids = create_gids(&((int*)ubuf)[1], size);
                    rb_insert_gids_node(req_uid, &(__gids_node->elem));

                    up(&res_sema);
                }
                else if (req_code == GET_SANDBOXNAMES)
                {
                    // get string size
                    memcpy((void*)data_trans_buffer,
                            &(((struct sdb_packet*)ubuf)->size), sizeof(int));
                    size = ((int*)data_trans_buffer)[0];

                    // get sandbox names
                    memcpy((void*)&((int*)data_trans_buffer)[1],
                            ((struct sdb_packet*)ubuf)->addr, size);

                    up(&res_sema);
                }
                else
                    up(&res_sema);
            }
        }
    }

    cond_printk( "[CHANNEL] ioctl (%s, %d, %d)\n", get_task_name(), cmd, cur_pid );
    return size;
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
    data_trans_buffer = (char*) kmalloc( BIG_BUFF_SIZE, GFP_KERNEL );
    memset( global_buffer, 0, BUFF_SIZE);
    memset( data_trans_buffer, 0, BIG_BUFF_SIZE);

    sema_init(&req_sema, 0);
    sema_init(&res_sema, 0);
    printk( "[CHANNEL] initialized (%s, %d)\n", get_task_name(), current_pid());

    return ret;
}


bool request_inspect_gids(int *gids)
{
    //int ids[4] = {current_uid(), current_pid(), current_tid()};
    if (gids == NULL) return false;
    if (pm_pid == 0) return false;
    if (in_atomic() || in_interrupt()) return false;
    if (!start_inspection(current_pid(), current_tid())) return false;
    wait_event_interruptible(wq, !in_stack_inspection);
    mutex_lock(&channel_lock);
    if (wakeup_pid)
    {
        // do gids inspection using stack trace

        // clear global variables
        wakeup_pid = 0;
        input_size = 0;
        in_stack_inspection = false;

        // allow the next pm to inspect stack trace
        mutex_unlock(&pm_lock);
    }
    mutex_unlock(&channel_lock);
    return true;
}

device_initcall( channel_init );

MODULE_LICENSE( "GPL" );
