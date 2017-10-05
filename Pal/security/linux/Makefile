# If KERNELRELEASE is defined, we've been invoked from the
# kernel build system and can use its language.
ifneq ($(KERNELRELEASE),)
	obj-m := graphene-rm.o graphene-sandbox.o
# Otherwise we were called directly from the command
# line; invoke the kernel build system.
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

graphene-rm.i: graphene-rm.c
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $@

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

endif
