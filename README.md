# isn_sync

Linux kernel module and agent for TCP protection with ISN synchronization.

## Kernel Support

### Supported kernels

* 4.13+

### Custom kernels

These options are required for module to work:

```
CONFIG_KPROBES=y
CONFIG_LIVEPATCH=y
CONFIG_FTRACE=y
CONFIG_DYNAMIC_FTRACE=y
CONFIG_DYNAMIC_FTRACE_WITH_REGS=y
CONFIG_FTRACE_MCOUNT_RECORD=y
```

## Installation

This module is a part of the MITIGATOR product. To install, follow
the documentation at https://docs.mitigator.ru/integrate/syncookie/

### Required packages

* dkms
* linux-headers-amd64
* openssh-server
* systemd-sysv
