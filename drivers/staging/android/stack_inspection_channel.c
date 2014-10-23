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

/* for logging */
static const bool do_prtk = false;
static char current_task_name[NAME_SIZE];
static DEFINE_MUTEX(tname_lock);

/* for stack inspection */
static void *global_buffer  = NULL;
static long input_size = 0;
static DEFINE_MUTEX(channel_lock);
static DEFINE_MUTEX(pm_lock);
static DECLARE_WAIT_QUEUE_HEAD(wq);
static pid_t pm_pid = 0;
static struct task_struct *wakeup_tsk = NULL;
static bool in_stack_inspection = false;

/* for data transfer */
struct semaphore req_sema;
struct semaphore res_sema;
static int req_uid = 0;
static void *data_trans_buffer  = NULL;
static DEFINE_MUTEX(data_lock);

/* measure stack inspection time */
#define PERIODIC_LOG 0
static int num_insp[2] = {0};
static struct timeval time_insp[2];
static struct timeval start = {0};
enum {
    ANDRO_RES,
    NATIVE_RES,
};

/* count thread resource access */
static int count_tid = -1;

enum {
    CHANNEL_REGISTER_PM = 0,
    CHANNEL_REGISTER_INSPECTOR,
    CHANNEL_UNREGISTER,
    CHANNEL_PM_WAIT,
    CHANNEL_REQUEST_PM,
    CHANNEL_PM_RESPONSE,
    CHANNEL_REGISTER_GIDS,
    CHANNEL_COUNT_SETTID,
    CHANNEL_COUNT_LOG,
};

struct sdb_packet {
    int size;
    void* addr;
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

//----> to check suspended thread
static DEFINE_MUTEX(stat_lock);
static pid_t target_tsk_tid = 0;

static struct rb_root stat_tree = RB_ROOT;
struct stat_node {
    struct rb_node elem;
    pid_t key_tid;
};

static inline struct stat_node * rb_search_stat_node(pid_t key)
{
    struct rb_node * n = stat_tree.rb_node;
    struct stat_node * node;

    while (n)
    {
        node = rb_entry(n, struct stat_node, elem);

        if (key < node->key_tid)
            n = n->rb_left;
        else if (key > node->key_tid)
            n = n->rb_right;
        else
            return node;
    }
    return NULL;
}

static inline struct stat_node * __rb_insert_stat_node(
        pid_t key,
        struct rb_node * node)
{
    struct rb_node ** p = &(stat_tree.rb_node);
    struct rb_node * parent = NULL;
    struct stat_node * ret;

    while (*p)
    {
        parent = *p;
        ret = rb_entry(parent, struct stat_node, elem);

        if (key < ret->key_tid)
            p = &(*p)->rb_left;
        else if (key > ret->key_tid)
            p = &(*p)->rb_right;
        else
            return ret;
    }

    rb_link_node(node, parent, p);

    return NULL;
}

static inline struct stat_node * rb_insert_stat_node(
        pid_t key,
        struct rb_node * node)
{
    struct stat_node * ret;
    if ((ret = __rb_insert_stat_node(key, node)))
        goto out;
    rb_insert_color(node, &stat_tree);
out:
    return ret;
}
//----< stat tree interface

/* uid - sbx - gids map */
static bool is_gids_set = false;
static int uid_size = 0;
struct gids_elem {
    int uid;
    int sbx_size;
    int* gids_size;
    int** sbx_gids;
};
static struct gids_elem* gids_map = NULL;

static struct gids_elem* search_gids(int uid)
{
    int mid, lh, rh;
    if (!gids_map)
        return NULL;
    lh = 0;
    rh = uid_size - 1;
    while (lh < rh) {
        mid = (lh+rh) / 2;
        if (gids_map[mid].uid < uid)
            lh = mid + 1;
        else
            rh = mid;
    }
    return gids_map[lh].uid == uid ? &gids_map[lh] : NULL;
}

static void create_gids_map(void __user *ubuf)
{
    int i, j, k, min;
    struct gids_elem tmp;
    int ofs = 0;

    /* set # of uid */
    uid_size = ((int*)ubuf)[ofs++];

    /* alloc gids_elem array */
    gids_map = kzalloc(sizeof(struct gids_elem)*uid_size, GFP_KERNEL);
    if (gids_map == NULL) {
        cond_printk("[CHANNEL] alloc fail %d\n", __LINE__);
    }

    /* for each uid */
    for (i = 0; i < uid_size; ++i) {
        /* set uid */
        gids_map[i].uid = ((int*)ubuf)[ofs++];

        /* set # of sandbox */
        gids_map[i].sbx_size = ((int*)ubuf)[ofs++];

        if (!gids_map[i].sbx_size) continue;

        /* alloc gids size array */
        gids_map[i].gids_size = kzalloc(
                sizeof(int)*gids_map[i].sbx_size,
                GFP_KERNEL);
        if (gids_map[i].gids_size == NULL) {
            cond_printk("[CHANNEL] alloc fail %d\n", __LINE__);
        }

        /* alloc sandbox-to-gids pointers */
        gids_map[i].sbx_gids = kzalloc(
                sizeof(int*)*gids_map[i].sbx_size,
                GFP_KERNEL);
        if (gids_map[i].sbx_gids == NULL) {
            cond_printk("[CHANNEL] alloc fail %d\n", __LINE__);
        }

        /* for each sandbox */
        for (j = 0; j < gids_map[i].sbx_size; ++j) {
            /* set # of gids */
            gids_map[i].gids_size[j] = ((int*)ubuf)[ofs++];

            if (!gids_map[i].gids_size[j]) continue;

            /* alloc gids array */
            gids_map[i].sbx_gids[j] = kzalloc(
                    sizeof(int)*gids_map[i].gids_size[j],
                    GFP_KERNEL);
            if (gids_map[i].sbx_gids[j] == NULL) {
                cond_printk("[CHANNEL] alloc fail %d\n", __LINE__);
            }

            for (k = 0; k < gids_map[i].gids_size[j]; ++k) {
                gids_map[i].sbx_gids[j][k] = ((int*)ubuf)[ofs++];
            }
        }
    }

    for (i = 0; i < uid_size; ++i) {
        min = i;
        for (j = i+1; j < uid_size; ++j) {
            if (gids_map[min].uid > gids_map[j].uid)
                min = j;
        }
        tmp = gids_map[min];
        gids_map[min] = gids_map[i];
        gids_map[i] = tmp;
        cond_printk("[CHANNEL]create_gids_map uid=%d\n", gids_map[i].uid);
    }

    is_gids_set = true;
}

inline void time_stamp_end(unsigned int res)
{
    struct timeval now;
    struct timeval diff;
#if !(PERIODIC_LOG)
    if (count_tid != current_tid())
        return;
#endif
    do_gettimeofday(&now);
    if (now.tv_usec < start.tv_usec) {
        diff.tv_usec = 1000000L + now.tv_usec - start.tv_usec;
        diff.tv_sec = now.tv_sec - start.tv_sec - 1L;
    } else {
        diff.tv_usec = now.tv_usec - start.tv_usec;
        diff.tv_sec = now.tv_sec - start.tv_sec;
    }
    time_insp[res].tv_sec += diff.tv_sec;
    time_insp[res].tv_usec += diff.tv_usec;
    ++num_insp[res];

#if PERIODIC_LOG
    if (num_insp[res] == 1000) {
        printk("%s: %lu.%lu\n", res==ANDRO_RES?"ANDRO_RES":"NATIVE_RES",
                time_insp[res].tv_sec/1000L, time_insp[res].tv_usec/1000L);
        num_insp[res] = 0;
        time_insp[res].tv_sec = 0;
        time_insp[res].tv_usec = 0;
    }
#endif
}

inline long start_inspection(pid_t target_pid, pid_t target_tid,
        int is_target_thd_suspended)
{
    long written_bytes;
    struct channel_node* node;
    pid_t cur_pid;

    written_bytes = 0;
    cur_pid = current_pid();

    /* skip gid inspection for the task in stack inspection. */
    if (target_tsk_tid == target_tid) return 0;

    // wait until the previous stack inspection will finish
    mutex_lock(&pm_lock);
    do_gettimeofday(&start);
    target_tsk_tid = target_tid;

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
        memcpy(&((pid_t*)global_buffer)[1], (void*)&is_target_thd_suspended, sizeof(int));
        written_bytes = sizeof(pid_t) + sizeof(int);

        input_size = written_bytes;
        cond_printk( "[CHANNEL] write: %d as %ld (%s, %d)\n",
                target_tid, written_bytes, get_task_name(), cur_pid );

        // wake up target stack inspector
        set_user_nice(node->value_task, 19);

        wakeup_tsk = node->value_task;
        wake_up_all(&wq);
        mutex_unlock(&channel_lock);
    }
    else
    {
        // Target app is dead.
        // Do not inspect stack
        target_tsk_tid = 0;
        time_stamp_end(is_target_thd_suspended);
        mutex_unlock(&pm_lock);
    }
    return written_bytes;
}

inline long request_data(void __user * ubuf)
{
    long size = 0;
    mutex_lock(&data_lock);
    req_uid = current_uid();
    up(&req_sema);
    down(&res_sema);

    size = ((int*)data_trans_buffer)[0];
    if (copy_to_user(ubuf, (void*)&((int*)data_trans_buffer)[1], size)) {
        cond_printk( "[CHANNEL] copy fail %d\n", __LINE__);
        size = -EFAULT;
    }

    req_uid = 0;
    mutex_unlock(&data_lock);
    return size;
}

static int channel_open( struct inode *inode, struct file *filp )
{
    cond_printk( "[CHANNEL] opened (%s, %d)\n", get_task_name(), current_pid() );
    return 0;
}

static int channel_release( struct inode *inode, struct file *filp )
{
    // Stack Inspector is dead, so we clear the node of rbtree.
    // NOTE: In usual, release is independent with the life of proc. (release = close)
    //       However, in Stack Inspector, release only called at the end of proc.
    struct channel_node* node;
    pid_t cur_pid = current_pid();

    cond_printk( "[CHANNEL] %s: %d---->\n", __func__, current_tid());
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
    if (current == wakeup_tsk && in_stack_inspection)
    {
        wakeup_tsk = NULL;
        input_size = 0;
        in_stack_inspection = false;
    }
    mutex_unlock(&channel_lock);

    cond_printk( "[CHANNEL] released (%s, %d)\n", get_task_name(), current_pid() );
    cond_printk( "[CHANNEL] %s: %d----<\n", __func__, current_tid());
    return 0;
}

static ssize_t channel_write( struct file *filp, const char *buf, size_t count, loff_t *f_pos )
{
    long missed_bytes;
    long written_bytes;
    pid_t cur_pid;
    struct channel_node* node;
    void __user *ubuf = (void __user *)buf;
    pid_t target_id[2];

    written_bytes = 0;
    cur_pid = current_pid();

    cond_printk( "[CHANNEL] %s: %d---->\n", __func__, current_tid());
    if (cur_pid == pm_pid)
    {
        // call from pm
        if (copy_from_user(target_id, ubuf, 2*sizeof(pid_t))) {
            cond_printk( "[CHANNEL] copy fail %d\n", __LINE__);
            return -EFAULT;
        }

        written_bytes = start_inspection(target_id[0], target_id[1], 0);
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
                missed_bytes = copy_from_user( global_buffer, ubuf, count);
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
    cond_printk( "[CHANNEL] %s: %d----<\n", __func__, current_tid());
    return written_bytes;
}

static ssize_t channel_read( struct file *filp, char *buf, size_t count, loff_t *f_pos )
{
    long missed_bytes;
    long read_bytes;
    pid_t cur_pid;
    struct channel_node* node;
    void __user *ubuf = (void __user *)buf;

    read_bytes = 0;
    cur_pid = current_pid();

    cond_printk( "[CHANNEL] %s: %d---->\n", __func__, current_tid());

    if (cur_pid == pm_pid)
    {
        // call from pm
        wait_event_interruptible(wq, !in_stack_inspection);
        mutex_lock(&channel_lock);
        if (wakeup_tsk)
        {
            // Make sure that reading stack trace waits writing stack trace.
            missed_bytes = copy_to_user( ubuf, global_buffer, input_size );
            read_bytes = input_size - missed_bytes;
            cond_printk( "[CHANNEL] read: %ld of %ld (%s, %d)\n",
                    read_bytes, input_size, get_task_name(), cur_pid );
        }
        mutex_unlock(&channel_lock);

        // clear global variables
        mutex_lock(&channel_lock);
        wakeup_tsk = NULL;
        input_size = 0;
        in_stack_inspection = false;
        mutex_unlock(&channel_lock);

        // allow the next pm to inspect stack trace
        target_tsk_tid = 0;
        time_stamp_end(ANDRO_RES);
        mutex_unlock(&pm_lock);
    }
    else
    {
        mutex_lock(&channel_lock);
        node = rb_search_channel_node(cur_pid);
        mutex_unlock(&channel_lock);
        if (node != NULL)
        {
            if (node->value_task == current)
            {
                // call from stack inspector
                // wait until a stack inspection request arrives
                // NOTE: if wait_event_interruptible() is in critical section(= CS),
                // Only one thread will be in CS and
                // Only the thread can be waked up.
                // It cause dead-lock,
                // thereby staying wait_event_interruptible() out of CS.
                wait_event_interruptible(wq,
                        (wakeup_tsk == current) && in_stack_inspection);

                // read target tid
                // NOTE: It must wait writing target tid.
                // Therefore, it waits lock until writing target tid has done.
                mutex_lock(&channel_lock);
                missed_bytes = copy_to_user( ubuf, global_buffer, input_size );
                read_bytes = input_size - missed_bytes;
                cond_printk( "[CHANNEL] read: %d as %ld of %ld (%s, %d)\n",
                        ((int*)ubuf)[0], read_bytes, input_size, get_task_name(), cur_pid );
                mutex_unlock(&channel_lock);
            }
        }
    }

    cond_printk( "[CHANNEL] read from global_buffer %ld (%s, %d)\n",
            read_bytes, get_task_name(), cur_pid );
    cond_printk( "[CHANNEL] %s: %d----<\n", __func__, current_tid());
    return read_bytes;
}

static long channel_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct channel_node* node;
    pid_t cur_pid;
    void __user *ubuf;
    long size = 0;
    long err = 0;
    cur_pid = current_pid();

    cond_printk( "[CHANNEL] %s: %d---->\n", __func__, current_tid());
    cond_printk( "[CHANNEL] ioctl (%s, %d, %d)\n", get_task_name(), cmd, cur_pid );

    if ((pm_pid == 0) && (cmd == CHANNEL_REGISTER_PM))
    {
        mutex_lock(&channel_lock);
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
        mutex_unlock(&channel_lock);
    }
    if ((cmd == CHANNEL_REGISTER_INSPECTOR) && (cur_pid != pm_pid))
    {
        mutex_lock(&channel_lock);
        node = rb_search_channel_node(cur_pid);
        if (node == NULL)
        {
            // register only one thread for a process
            node = kzalloc(sizeof(*node), GFP_KERNEL);
            if (node == NULL) {
                cond_printk("[CHANNEL] alloc fail %d\n", __LINE__);
            }
            node->key_pid = cur_pid;
            node->value_task = current;
            rb_insert_channel_node(cur_pid, &(node->elem));
        }
        cond_printk( "[CHANNEL] registered %d (%s, %d)\n", cur_pid, get_task_name(), cur_pid );
        mutex_unlock(&channel_lock);
    }
    if (cmd == CHANNEL_UNREGISTER)
    {
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
            cond_printk( "[CHANNEL] remove from rbtree: %d (%s, %d)\n",
                    cur_pid, get_task_name(), cur_pid );
        }
        mutex_unlock(&channel_lock);
    }

    if (cmd == CHANNEL_PM_WAIT)
    {
        if (cur_pid == pm_pid)
        {
            down(&req_sema);
            ubuf = (void __user *)arg;
            ((int *)ubuf)[0] = req_uid;
        }
    }

    if (cmd == CHANNEL_REQUEST_PM)
    {
        mutex_lock(&channel_lock);
        node = rb_search_channel_node(cur_pid);
        mutex_unlock(&channel_lock);
        if (node)
            size = request_data((void __user *)arg);
    }

    if (cmd == CHANNEL_PM_RESPONSE)
    {
        if (cur_pid == pm_pid)
        {
            ubuf = (void __user *)arg;
            if (ubuf)
            {
                if (copy_from_user((void*)data_trans_buffer,
                            &(((struct sdb_packet*)ubuf)->size),
                            sizeof(int))) {
                    cond_printk( "[CHANNEL] copy fail %d\n", __LINE__);
                    size = 0;
                } else {
                    size = ((int*)data_trans_buffer)[0];

                    // get sandbox names
                    err = copy_from_user((void*)&((int*)data_trans_buffer)[1],
                            (void __user *)((struct sdb_packet*)ubuf)->addr,
                            size);
                    if (err) {
                        cond_printk( "[CHANNEL] copy fail %d\n", __LINE__);
                        size = 0;
                    }
                }
            }
            up(&res_sema);
        }
    }

    if (cmd == CHANNEL_REGISTER_GIDS)
    {
        if (cur_pid == pm_pid && !is_gids_set)
        {
            ubuf = (void __user *)arg;
            if (!access_ok(VERIFY_READ, ubuf, sizeof(*ubuf)))
                return 0;

            mutex_lock(&channel_lock);
            create_gids_map(ubuf);
            mutex_unlock(&channel_lock);
        }
    }

#if PERIODIC_LOG
    if (cmd == CHANNEL_COUNT_SETTID || cmd == CHANNEL_COUNT_LOG)
    {
        printk("count_tid log is turned off\n");
    }
#else
    if (cmd == CHANNEL_COUNT_SETTID)
    {
        if (cur_pid == pm_pid)
        {
            ubuf = (void __user *)arg;
            if (ubuf)
            {
                if (copy_from_user(&count_tid, ubuf, sizeof(int)))
                {
                    printk("copy fail in setuid\n");
                }
            }
        }
    }

    if (cmd == CHANNEL_COUNT_LOG)
    {
        if (cur_pid == pm_pid)
        {
            printk("ANDRO_RES (%d): %lu sec %lu usec for %d\n", count_tid,
                    time_insp[ANDRO_RES].tv_sec, time_insp[ANDRO_RES].tv_usec,
                    num_insp[ANDRO_RES]);
            num_insp[ANDRO_RES] = 0;
            time_insp[ANDRO_RES].tv_sec = 0;
            time_insp[ANDRO_RES].tv_usec = 0;
            printk("NATIVE_RES (%d): %lu sec %lu usec for %d\n", count_tid,
                    time_insp[NATIVE_RES].tv_sec, time_insp[NATIVE_RES].tv_usec,
                    num_insp[NATIVE_RES]);
            num_insp[NATIVE_RES] = 0;
            time_insp[NATIVE_RES].tv_sec = 0;
            time_insp[NATIVE_RES].tv_usec = 0;
        }
    }
#endif

    cond_printk( "[CHANNEL] %s: %d----<\n", __func__, current_tid());
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
    global_buffer = kzalloc(BUFF_SIZE, GFP_KERNEL);
    data_trans_buffer = kzalloc(BUFF_SIZE, GFP_KERNEL);

    sema_init(&req_sema, 0);
    sema_init(&res_sema, 0);
    memset(time_insp, 0, 2*sizeof(struct timeval));
    cond_printk( "[CHANNEL] initialized (%s, %d)\n", get_task_name(), current_pid());

    return ret;
}

/* lock should be surrounded */
static int gids_inspection(struct gids_elem* gelem, int gid)
{
    int i, sbx_idx, j, size;
    size = input_size / sizeof(int);
    for (i = 0; i < size; ++i) {
        sbx_idx = ((int*)global_buffer)[i];
        if (sbx_idx >= gelem->sbx_size)
            continue;
        for (j = 0; j < gelem->gids_size[sbx_idx]; ++j) {
            if (gid == gelem->sbx_gids[sbx_idx][j])
                return 1;
        }
    }
    return -1;
}

/* returns 0 if gids inspection is not available (skip)
 * returns -1 if current proc does not have GID (reject)
 * returns 1 if current proc has GID (allow)
 */
int request_inspect_gids(int gid)
{
    int cur_uid;
    int cur_pid = current_pid();
    int cur_tid = current_tid();
    struct channel_node* cnode;
    struct gids_elem* gelem;
    int ret = 0;
    struct stat_node snode, *psnode;

    /* do it only after initialization */
    if (pm_pid == 0) goto done;

    /* Skip PM */
    if (pm_pid == cur_pid) goto done;

    /* Skip non-system call like interrupt
     * to prevent deadlock.
     * For example, timer interrupt
     * while remote stack inspection.
     */
    if (in_atomic() || in_interrupt()) goto done;

    /* do gids inspection for only necessary threads */
    cur_uid = current_uid();
    gelem = search_gids(cur_uid);
    if (!gelem) goto done;

    /* Prevent recursive remote stack inspection.
     * For example, remote stack inspector calls syscall.
     */
    if (wakeup_tsk == current) goto done;
    mutex_lock(&channel_lock);
    cnode = rb_search_channel_node(cur_pid);
    mutex_unlock(&channel_lock);
    if (!cnode) goto done; /* don't have sandbox */
    if (cnode->value_task == current) goto done;

    /* check if this thread is already suspended */
    mutex_lock(&stat_lock);
    psnode = rb_search_stat_node(cur_tid);
    mutex_unlock(&stat_lock);
    if (psnode) goto done;

    /* mark status as suspended to prevent deadlock */
    snode.key_tid = cur_tid;
    mutex_lock(&stat_lock);
    rb_insert_stat_node(cur_tid, &(snode.elem));
    mutex_unlock(&stat_lock);

    if (!start_inspection(cur_pid, cur_tid, 1)) goto unlock_suspended;

    wait_event_interruptible(wq, !in_stack_inspection);

    /* do gids inspection using stack trace */
    mutex_lock(&channel_lock);
    ret = -1;
    /* If input_size is zero, it has default GIDS.
     * Thus skip it.
     */
    if (!input_size)
        ret = 0;
    else if (wakeup_tsk) {
        ret = gids_inspection(gelem, gid);
    }
    mutex_unlock(&channel_lock);

    // clear global variables
    mutex_lock(&channel_lock);
    wakeup_tsk = NULL;
    input_size = 0;
    in_stack_inspection = false;
    mutex_unlock(&channel_lock);

    // allow the next pm to inspect stack trace
    target_tsk_tid = 0;
    time_stamp_end(NATIVE_RES);
    mutex_unlock(&pm_lock);

unlock_suspended:
    mutex_lock(&stat_lock);
    rb_erase(&(snode.elem), &stat_tree);
    mutex_unlock(&stat_lock);

done:
    return ret;
}

device_initcall( channel_init );

MODULE_LICENSE( "GPL" );
