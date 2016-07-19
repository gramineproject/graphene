ifneq ($(KERNELRELEASE),)
	ccflags-y += -I$(PWD)/linux-sgx-driver
	graphene-sgx-y := \
		gsgx_main.o
	obj-m += graphene-sgx.o
else
KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

default: linux-sgx-driver/isgx.h
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) CFLAGS_MODULE="-DDEBUG -g -O0" modules

linux-sgx-driver/isgx.h:
	@./link-intel-driver.py
endif

clean:
	rm -vrf *.o *.ko *.order *.symvers *.mod.c .tmp_versions .*o.cmd
