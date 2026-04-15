/*
 * monitor.c - Multi-Container Memory Monitor (Linux Kernel Module)
 *
 * Implements:
 *   - /dev/container_monitor character device
 *   - ioctl: MONITOR_REGISTER / MONITOR_UNREGISTER
 *   - Kernel linked list of monitored containers (spinlock-protected)
 *   - Periodic timer callback for RSS checking, soft-limit warnings, hard-limit kills
 *   - Clean teardown on module unload
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/timer.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/version.h>
#include <linux/spinlock.h>

#include "monitor_ioctl.h"

#define DEVICE_NAME "container_monitor"
#define CHECK_INTERVAL_SEC 1

/* ================================================================
 * Per-container tracking node
 *
 * Each registered container gets one heap-allocated node stored
 * in the global container_list. Uses the standard kernel intrusive
 * linked-list via struct list_head.
 *
 * soft_warned is set to 1 after the first soft-limit warning is
 * emitted, so we don't spam dmesg on every timer tick.
 * ================================================================ */
struct monitored_entry {
    pid_t         pid;
    char          container_id[MONITOR_NAME_LEN];
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int           soft_warned;
    struct list_head list;
};

/* ================================================================
 * Global monitored list and lock
 *
 * A spinlock is used instead of a mutex because the timer callback
 * runs in softirq (atomic) context where sleeping is not allowed.
 * spin_lock_irqsave also disables local interrupts, preventing a
 * deadlock if the timer fires on the same CPU as an ioctl call.
 * ================================================================ */
static LIST_HEAD(container_list);
static DEFINE_SPINLOCK(list_lock);

/* Internal device and timer state */
static struct timer_list monitor_timer;
static dev_t             dev_num;
static struct cdev       c_dev;
static struct class     *cl;

/* ================================================================
 * get_rss_bytes — Returns RSS in bytes for the given PID
 *
 * Returns -1 if the task no longer exists. Uses RCU read lock
 * and get_task_mm, safe to call from atomic context.
 * ================================================================ */
static long get_rss_bytes(pid_t pid)
{
    struct task_struct *task;
    struct mm_struct   *mm;
    long rss_pages = 0;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return -1;
    }
    get_task_struct(task);
    rcu_read_unlock();

    mm = get_task_mm(task);
    if (mm) {
        rss_pages = get_mm_rss(mm);
        mmput(mm);
    }
    put_task_struct(task);

    return rss_pages * PAGE_SIZE;
}

/* ================================================================
 * log_soft_limit_event — Emit a kernel warning when soft limit
 * is exceeded for the first time.
 * ================================================================ */
static void log_soft_limit_event(const char *container_id, pid_t pid,
                                  unsigned long limit_bytes, long rss_bytes)
{
    printk(KERN_WARNING
           "[container_monitor] SOFT LIMIT container=%s pid=%d "
           "rss=%ld bytes limit=%lu bytes\n",
           container_id, pid, rss_bytes, limit_bytes);
}

/* ================================================================
 * kill_process — Send SIGKILL when hard limit is exceeded
 * ================================================================ */
static void kill_process(const char *container_id, pid_t pid,
                          unsigned long limit_bytes, long rss_bytes)
{
    struct task_struct *task;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task)
        send_sig(SIGKILL, task, 1);
    rcu_read_unlock();

    printk(KERN_WARNING
           "[container_monitor] HARD LIMIT container=%s pid=%d "
           "rss=%ld bytes limit=%lu bytes — SIGKILL sent\n",
           container_id, pid, rss_bytes, limit_bytes);
}

/* ================================================================
 * timer_callback — Periodic RSS enforcement
 *
 * Fires every CHECK_INTERVAL_SEC seconds. For each tracked entry:
 *   - If process is gone (rss < 0): remove stale entry
 *   - If rss > hard_limit: kill process, remove entry
 *   - If rss > soft_limit (first time): log warning
 *
 * list_for_each_entry_safe is used because we may delete entries
 * during iteration. It saves the next pointer before entering
 * the loop body so deletion is safe.
 * ================================================================ */
static void timer_callback(struct timer_list *t)
{
    struct monitored_entry *entry, *tmp;
    unsigned long flags;

    (void)t;

    spin_lock_irqsave(&list_lock, flags);

    list_for_each_entry_safe(entry, tmp, &container_list, list) {
        long rss = get_rss_bytes(entry->pid);

        if (rss < 0) {
            /* Process exited — clean up stale tracking entry */
            printk(KERN_INFO
                   "[container_monitor] PID %d gone, removing entry '%s'\n",
                   entry->pid, entry->container_id);
            list_del(&entry->list);
            kfree(entry);
            continue;
        }

        if ((unsigned long)rss > entry->hard_limit_bytes) {
            /* Hard limit exceeded — kill and remove */
            kill_process(entry->container_id, entry->pid,
                         entry->hard_limit_bytes, rss);
            list_del(&entry->list);
            kfree(entry);

        } else if ((unsigned long)rss > entry->soft_limit_bytes
                   && !entry->soft_warned) {
            /* Soft limit exceeded for the first time — warn only */
            log_soft_limit_event(entry->container_id, entry->pid,
                                 entry->soft_limit_bytes, rss);
            entry->soft_warned = 1;
        }
    }

    spin_unlock_irqrestore(&list_lock, flags);

    /* Re-arm the timer for the next check interval */
    mod_timer(&monitor_timer, jiffies + CHECK_INTERVAL_SEC * HZ);
}

/* ================================================================
 * monitor_ioctl — Handles REGISTER and UNREGISTER commands
 *
 * REGISTER:
 *   Allocates a new monitored_entry from the user-space request,
 *   validates limits, and inserts into the list under the spinlock.
 *
 * UNREGISTER:
 *   Finds matching entry by PID + container_id, removes and frees
 *   it. Returns -ENOENT if no match.
 * ================================================================ */
static long monitor_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct monitor_request req;
    unsigned long flags;

    (void)f;

    if (cmd != MONITOR_REGISTER && cmd != MONITOR_UNREGISTER)
        return -EINVAL;

    if (copy_from_user(&req, (struct monitor_request __user *)arg, sizeof(req)))
        return -EFAULT;

    /* ---- REGISTER ---- */
    if (cmd == MONITOR_REGISTER) {
        struct monitored_entry *entry;

        printk(KERN_INFO
               "[container_monitor] Register container=%s pid=%d "
               "soft=%lu hard=%lu\n",
               req.container_id, req.pid,
               req.soft_limit_bytes, req.hard_limit_bytes);

        /* Sanity: soft limit must not exceed hard limit */
        if (req.soft_limit_bytes > req.hard_limit_bytes) {
            printk(KERN_WARNING
                   "[container_monitor] Rejected: soft > hard for '%s'\n",
                   req.container_id);
            return -EINVAL;
        }

        /* GFP_KERNEL is OK here — ioctl runs in process context */
        entry = kmalloc(sizeof(*entry), GFP_KERNEL);
        if (!entry)
            return -ENOMEM;

        entry->pid              = req.pid;
        entry->soft_limit_bytes = req.soft_limit_bytes;
        entry->hard_limit_bytes = req.hard_limit_bytes;
        entry->soft_warned      = 0;
        strncpy(entry->container_id, req.container_id, MONITOR_NAME_LEN - 1);
        entry->container_id[MONITOR_NAME_LEN - 1] = '\0';
        INIT_LIST_HEAD(&entry->list);

        spin_lock_irqsave(&list_lock, flags);
        list_add(&entry->list, &container_list);
        spin_unlock_irqrestore(&list_lock, flags);

        return 0;
    }

    /* ---- UNREGISTER ---- */
    printk(KERN_INFO
           "[container_monitor] Unregister container=%s pid=%d\n",
           req.container_id, req.pid);

    {
        struct monitored_entry *entry, *tmp;
        int found = 0;

        spin_lock_irqsave(&list_lock, flags);
        list_for_each_entry_safe(entry, tmp, &container_list, list) {
            if (entry->pid == req.pid &&
                strncmp(entry->container_id, req.container_id,
                        MONITOR_NAME_LEN) == 0) {
                list_del(&entry->list);
                kfree(entry);
                found = 1;
                break;
            }
        }
        spin_unlock_irqrestore(&list_lock, flags);

        return found ? 0 : -ENOENT;
    }
}

/* File operations */
static struct file_operations fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = monitor_ioctl,
};

/* ================================================================
 * Module init — register char device and start timer
 * ================================================================ */
static int __init monitor_init(void)
{
    if (alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME) < 0)
        return -1;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    cl = class_create(DEVICE_NAME);
#else
    cl = class_create(THIS_MODULE, DEVICE_NAME);
#endif
    if (IS_ERR(cl)) {
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(cl);
    }

    if (IS_ERR(device_create(cl, NULL, dev_num, NULL, DEVICE_NAME))) {
        class_destroy(cl);
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    cdev_init(&c_dev, &fops);
    if (cdev_add(&c_dev, dev_num, 1) < 0) {
        device_destroy(cl, dev_num);
        class_destroy(cl);
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    timer_setup(&monitor_timer, timer_callback, 0);
    mod_timer(&monitor_timer, jiffies + CHECK_INTERVAL_SEC * HZ);

    printk(KERN_INFO "[container_monitor] Module loaded. /dev/%s ready.\n",
           DEVICE_NAME);
    return 0;
}

/* ================================================================
 * Module exit — stop timer, free all entries, tear down device
 *
 * del_timer_sync waits for any running timer callback to finish
 * before returning, so the list is not being accessed when we free.
 * ================================================================ */
static void __exit monitor_exit(void)
{
    struct monitored_entry *entry, *tmp;
    unsigned long flags;

    /* Stop the periodic timer first */
    del_timer_sync(&monitor_timer);

    /* Free every remaining tracked entry */
    spin_lock_irqsave(&list_lock, flags);
    list_for_each_entry_safe(entry, tmp, &container_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    spin_unlock_irqrestore(&list_lock, flags);

    /* Tear down char device */
    cdev_del(&c_dev);
    device_destroy(cl, dev_num);
    class_destroy(cl);
    unregister_chrdev_region(dev_num, 1);

    printk(KERN_INFO "[container_monitor] Module unloaded.\n");
}

module_init(monitor_init);
module_exit(monitor_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Supervised multi-container memory monitor");
