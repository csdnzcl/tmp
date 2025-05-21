#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/kfifo.h>
#include <linux/wait.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/device.h>

#define DEVICE_NAME "mychardev"
#define FIFO_SIZE 64

static dev_t devno;
static struct cdev my_cdev;
static struct class *my_class;
static DEFINE_KFIFO(myfifo, char, FIFO_SIZE);
static DECLARE_WAIT_QUEUE_HEAD(read_queue);
static DECLARE_WAIT_QUEUE_HEAD(write_queue);

static ssize_t my_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    unsigned int copied;
    int ret;

    if (kfifo_is_empty(&myfifo)) {
        if (file->f_flags & O_NONBLOCK)
            return -EAGAIN;
        if (wait_event_interruptible(read_queue, !kfifo_is_empty(&myfifo)))
            return -ERESTARTSYS;
    }

    ret = kfifo_to_user(&myfifo, buf, count, &copied);
    if (ret)
        return -EFAULT;

    wake_up_interruptible(&write_queue);
    return copied;
}

static ssize_t my_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    unsigned int copied;
    int ret;

    if (kfifo_avail(&myfifo) == 0) {
        if (file->f_flags & O_NONBLOCK)
            return -EAGAIN;
        if (wait_event_interruptible(write_queue, kfifo_avail(&myfifo) > 0))
            return -ERESTARTSYS;
    }

    ret = kfifo_from_user(&myfifo, buf, count, &copied);
    if (ret)
        return -EFAULT;

    wake_up_interruptible(&read_queue);
    return copied;
}

static int my_open(struct inode *inode, struct file *file) { return 0; }
static int my_release(struct inode *inode, struct file *file) { return 0; }

static struct file_operations my_fops = {
    .owner = THIS_MODULE,
    .read = my_read,
    .write = my_write,
    .open = my_open,
    .release = my_release,
};

static int my_proc_show(struct seq_file *m, void *v)
{
    seq_printf(m, "kfifo size: %u\n", kfifo_size(&myfifo));
    seq_printf(m, "kfifo len: %u\n", kfifo_len(&myfifo));
    return 0;
}

static int my_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, my_proc_show, NULL);
}

static const struct proc_ops my_proc_ops = {
    .proc_open = my_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init my_init(void)
{
    int ret;
    ret = alloc_chrdev_region(&devno, 0, 1, DEVICE_NAME);
    if (ret < 0) return ret;

    cdev_init(&my_cdev, &my_fops);
    my_cdev.owner = THIS_MODULE;
    ret = cdev_add(&my_cdev, devno, 1);
    if (ret < 0) goto unregister;

    my_class = class_create(THIS_MODULE, DEVICE_NAME);
    if (IS_ERR(my_class)) {
        ret = PTR_ERR(my_class);
        goto del_cdev;
    }
    device_create(my_class, NULL, devno, NULL, DEVICE_NAME);

    proc_create("mychardev_info", 0, NULL, &my_proc_ops);

    printk(KERN_INFO "mychardev loaded\n");
    return 0;

del_cdev:
    cdev_del(&my_cdev);
unregister:
    unregister_chrdev_region(devno, 1);
    return ret;
}

static void __exit my_exit(void)
{
    remove_proc_entry("mychardev_info", NULL);
    device_destroy(my_class, devno);
    class_destroy(my_class);
    cdev_del(&my_cdev);
    unregister_chrdev_region(devno, 1);
    printk(KERN_INFO "mychardev unloaded\n");
}

module_init(my_init);
module_exit(my_exit);
MODULE_LICENSE("GPL");