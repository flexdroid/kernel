#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/slab.h>

#include <linux/miscdevice.h>
#include <linux/device-mapper.h>
#include <linux/pagemap.h>
#include <linux/mempool.h>

const int CHANNEL_COUNT_SETTID = 9;

inline pid_t current_pid(void)
{
    return task_tgid_vnr(current);
}

static int count_pid;
void print_time(int mode)
{
    struct timeval now;
    if (count_pid != current_pid())
        return;
    do_gettimeofday(&now);
    printk("%d: %lu %lu\n", mode, now.tv_sec, now.tv_usec);
}

static int channel_open( struct inode *inode, struct file *filp )
{
    return 0;
}

static int channel_release( struct inode *inode, struct file *filp )
{
    return 0;
}

static ssize_t channel_write( struct file *filp, const char *buf, size_t count, loff_t *f_pos )
{
    return 0;
}

static ssize_t channel_read( struct file *filp, char *buf, size_t count, loff_t *f_pos )
{
    return 0;
}

static long channel_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    void __user *ubuf;

    if (cmd == CHANNEL_COUNT_SETTID)
    {
        ubuf = (void __user *)arg;
        if (ubuf)
        {
            if (copy_from_user(&count_pid, ubuf, sizeof(int)))
            {
                printk("copy fail in setuid\n");
            }
        }
    }

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

    return ret;
}

device_initcall( channel_init );

MODULE_LICENSE( "GPL" );
