ifneq ($(KERNELRELEASE),)
	dummy-y := main.o
	obj-m += dummy.o
else
KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

.PHONY: default
default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) CFLAGS_MODULE="-DDEBUG -g -O0" modules

endif

.PHONY: clean
clean:
	rm -vrf *.o *.ko *.order *.symvers *.mod.c .tmp_versions .*o.cmd
