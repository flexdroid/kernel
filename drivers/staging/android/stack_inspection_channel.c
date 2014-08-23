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

#define  BUFF_SIZE      (16 * 1024)
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

static const bool do_prtk = false;

static char *global_buffer  = NULL;
static long input_size = 0;
static char current_task_name[NAME_SIZE];
static DEFINE_MUTEX(tname_lock);

static DEFINE_MUTEX(channel_lock);
static DEFINE_MUTEX(pm_lock);
static DEFINE_MUTEX(gids_lock);
static DECLARE_WAIT_QUEUE_HEAD(wq);
static pid_t pm_pid = 0;
static struct task_struct *wakeup_task = NULL;
static bool in_stack_inspection = false;

static int *inspect_gids_buffer  = NULL;
static bool is_requested = false;
static bool is_responded = false;


enum {
    CHANNEL_REGISTER_PM = 0,
    CHANNEL_REGISTER_INSPECTOR,
    CHANNEL_UNREGISTER,
    CHANNEL_READ_INSPECT_GIDS,
    CHANNEL_WRITE_INSPECT_GIDS,
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
        // wait until the previous stack inspection will finish
        mutex_lock(&pm_lock);

        // stack inspection begins.
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
                input_size = written_bytes;
                cond_printk( "[CHANNEL] write: %d as %ld of %u (%s, %d)\n",
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
                cond_printk( "[CHANNEL] remove from rbtree: %d (%s, %d)\n",
                        ((pid_t *)buf)[0], get_task_name(), cur_pid );
                mutex_unlock(&channel_lock);

                // do not inspect stack
                mutex_unlock(&pm_lock);
            }
        }
        else
        {
            // do not inspect stack
            mutex_unlock(&pm_lock);
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
                input_size = written_bytes;
                cond_printk( "[CHANNEL] write: %s as %ld of %u (%s, %d)\n",
                        buf, written_bytes, count, get_task_name(), cur_pid );
                mutex_unlock(&channel_lock);

                // Stack inspection ends
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
                cond_printk( "[CHANNEL] remove from rbtree: %d (%s, %d)\n",
                        task_tgid_vnr(wakeup_task), get_task_name(), cur_pid );
            }
            mutex_unlock(&channel_lock);
        }

        // Make sure that reading stack trace waits writing stack trace.
        mutex_lock(&channel_lock);
        missed_bytes = copy_to_user( buf, global_buffer, input_size );
        read_bytes = input_size - missed_bytes;
        cond_printk( "[CHANNEL] read: %s as %ld of %ld (%s, %d)\n",
                buf, read_bytes, input_size, get_task_name(), cur_pid );

        // clear wakeup_task
        wakeup_task = NULL;
        input_size = 0;
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
                    (wakeup_task == current) && in_stack_inspection);

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
    pid_t cur_pid;
    void __user *ubuf;
    void __kernel *kbuf;
    int i;
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

    if (cur_pid != pm_pid) {
        // called from requester
        kbuf = (void __kernel *) arg;
        if (cmd == CHANNEL_READ_INSPECT_GIDS) {
            /* while(!is_responded); */
            wait_event_interruptible(wq, is_responded);
            is_responded = false;
            printk("[CHANNEL] INSPECT_GIDS :: [4-] RES by INSPECTOR (%d)\n", cur_pid);
            printk("[CHANNEL] INSPECT_GIDS :: [4+] REQ by INSPECTOR :: %d, %d, %d (%d)\n",
                    ((int*)inspect_gids_buffer)[0], ((int*)inspect_gids_buffer)[1], ((int*)inspect_gids_buffer)[2], cur_pid);
            mutex_unlock(&gids_lock);
            memcpy((void*)arg, (void*)inspect_gids_buffer, 3 * sizeof(int));
            return 3 * sizeof(int);
        } else if (cmd == CHANNEL_WRITE_INSPECT_GIDS) {
            mutex_lock(&gids_lock);
            inspect_gids_buffer[0] = ((int*)kbuf)[0];
            inspect_gids_buffer[1] = ((int*)kbuf)[1];
            inspect_gids_buffer[2] = ((int*)kbuf)[2];
            printk("[CHANNEL] INSPECT_GIDS :: [1] REQ by INSPECTOR :: %d, %d, %d (%d)\n",
                    ((int*)kbuf)[0], ((int*)kbuf)[1], ((int*)kbuf)[2], cur_pid);
            is_requested = true;
            wake_up_all(&wq);
        }
    } else {
        // called from pm
        ubuf = (void __user *) arg;
        if (cmd == CHANNEL_READ_INSPECT_GIDS) {
            printk("[CHANNEL] INSPECT_GIDS :: [2-] READ by PM (%d)\n", cur_pid);
            /* while(!is_requested); */
            wait_event_interruptible(wq, is_requested);
            is_requested = false;
            printk("[CHANNEL] INSPECT_GIDS :: [2+] READ by PM (%d)\n", cur_pid);
            return 3 * sizeof(int)
                - copy_to_user(ubuf, inspect_gids_buffer, 3 * sizeof(int));
        } else if (cmd == CHANNEL_WRITE_INSPECT_GIDS) {
            printk("[CHANNEL] INSPECT_GIDS :: [3] WRITE by PM (%d)\n", cur_pid);
            inspect_gids_buffer[0] = ((int*)ubuf)[0];
            for (i = 1; i <= inspect_gids_buffer[0]; ++i)
                inspect_gids_buffer[i] = ((int*)ubuf)[i];
            is_responded = true;
            wake_up_all(&wq);
        }
    }

    cond_printk( "[CHANNEL] ioctl (%s, %d, %d)\n", get_task_name(), cmd, cur_pid );
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
    inspect_gids_buffer = (int*) kmalloc( BUFF_SIZE, GFP_KERNEL );
    memset( global_buffer, 0, BUFF_SIZE);
    memset( inspect_gids_buffer, 0, BUFF_SIZE);

    printk( "[CHANNEL] initialized (%s, %d)\n", get_task_name(), current_pid());

    return ret;
}


bool request_inspect_gids(int *gids)
{
    size_t size;
    struct channel_node * node;
    int ids[4] = {current_uid(), current_pid(), current_tid()};
    if (gids == NULL) return false;
    if (pm_pid == 0) return false;
    /* printk("[CHANNEL] in_atomic?\n"); */
    if (in_atomic() || in_interrupt()) return false;
    mutex_lock(&channel_lock);
    node = rb_search_channel_node(current_pid());
    mutex_unlock(&channel_lock);
    if (node != NULL && !task_is_dead(node->value_task)
        && task_tgid_vnr(node->value_task) != current_tid())
    {
      printk("[CHANNEL] __channel_ioctl(CHANNEL_WRITE_INSPECT_GIDS, {%d, %d, %d}\n", ids[0], ids[1], ids[2]);
      size = __channel_ioctl(CHANNEL_WRITE_INSPECT_GIDS, (long) ids);
      printk("[CHANNEL] __channel_ioctl(CHANNEL_READ_INSPECT_GIDS, int *)\n");
      size = __channel_ioctl(CHANNEL_READ_INSPECT_GIDS, (long) gids);
      printk("[CHANNEL] __channel_ioctl(CHANNEL_READ_INSPECT_GIDS, int *) :: gids[={%d, %d, %d, ...}\n", gids[0], gids[1], gids[2]);
      return true;
    }
    return false;
}

device_initcall( channel_init );

MODULE_LICENSE( "GPL" );
