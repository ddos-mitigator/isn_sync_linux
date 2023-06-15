# isn_sync

Linux kernel module to provide access to TCP secret keys via `/proc/isn_sync_*`.

## Kernel Support

### Tested kernels

* 4.19.0-12-amd64 (Debian 10)
* 5.7.0-0.bpo.2-amd64 (Debian 10)
* 5.9.0-0.bpo.5-amd64 (Debian 10)
* 5.10.0-5-amd64 (Debian 11)

### Unsupported kernels

* < 4.13 (cookie algorithm changed)

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

## Install via DKMS

This module is a part of the DDoS MITIGATOR product. To install, follow
the documentation at https://docs.mitigator.ru/integrate/syncookie/
