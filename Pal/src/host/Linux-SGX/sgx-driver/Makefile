ifneq ($(KERNELRELEASE),)
	graphene-sgx-y := \
		gsgx_ioctl_1_6.o \
		gsgx_ioctl_1_7.o \
		gsgx_fsgsbase.o \
		gsgx_main.o
	obj-m += graphene-sgx.o
else
KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

default: isgx_version.h linux-sgx-driver
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) CFLAGS_MODULE="-DDEBUG -g -O0" modules

.INTERMEDIATE: link-sgx-driver
link-sgx-driver:
	@./link-intel-driver.py

isgx_version.h linux-sgx-driver: link-sgx-driver

endif

clean:
	rm -vrf linux-sgx-driver isgx_version.h
	rm -vrf *.o *.ko *.order *.symvers *.mod.c .tmp_versions .*o.cmd
