#include <linux/init.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>

MODULE_AUTHOR("B1TC0R3");
MODULE_DESCRIPTION("Example LKM");
MODULE_LICENSE("GPL");

static int __init ophicordys_init(void) {
    printk(KERN_INFO "Ophicordys loaded.");
    return 0;
}

static void __exit ophicordys_exit(void) {
    printk(KERN_INFO "Ophicordys unloaded.");
}

module_init(ophicordys_init);
module_exit(ophicordys_exit);
