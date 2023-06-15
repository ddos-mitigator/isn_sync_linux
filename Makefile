obj-m := isn_sync.o

KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/${KVER}/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

clean: 
	@rm -f *.o .*.cmd .*.*.cmd .*.flags *.mod.c *.order

distclean: clean 
	@rm -f *.ko *.mod *.symvers
