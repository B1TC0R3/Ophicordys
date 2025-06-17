# Ophicordys

A single file Linux rootkit.

This is a study project in the form of a proof of concept and does not contain
any actual exploits. In order to install it into any system you need root access
to this system. In addition, it will taint the kernel when loaded and raise an
according error, preventing stealthy usage of the kit entirely.

## Installation

1. Build the module.

```bash
make
```

2. Load the module into the kernel.

> **Warning:** This will taint your kernel.

```bash
sudo insmod ophicordys.ko
```

3. Unload the module.

```bash
sudo rmmod ophicordys
```

## Usage

The kit can elevate any PID to root level through a block device.
It is possible to send such a request using `echo`.

```bash
# Get PID of current shell
ps

# Elevate shell to root
echo "elevate <pid>" > /dev/ophicordys_driver

# Execute shell command as root. Can be a maximum of 512 bytes long.
echo "execute <command> > /dev/ophicordys_driver
```

## Indicators of compromise / How to detect

1. Loading this module will **always** taint the kernel of a system. This cannot be avoided
   and should be monitored on any system.
   If the content of the file `/proc/sys/kernel/tainted` is **NOT** the number `0`,
   an external, non-approved module has been loaded.

2. This kit will **always** create an out of place block device in `/dev`.
   By default, this block device is called `/dev/ophicordys_driver`.
   While a malicious actor could potentially change the name of this block device, it cannot be
   one of the common ones such as `ttyS`, ... as these namespaces are reserved by other
   kernel features.
