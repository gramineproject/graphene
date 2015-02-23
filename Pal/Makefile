OS ?= $(shell uname -s)
ifeq ($(OS),Linux)
	NPROCS ?= $(shell grep -c ^processor /proc/cpuinfo)
else
	NPROCS ?= 1
endif

ifeq ($(OS),Linux)
	LINUX_GEN := 3.x
	LINUX_SRC := linux-3.14
	LINUX_KERNEL := $(LINUX_SRC)/arch/x86/boot/bzImage
endif

DIRS = src test

all debug:
	for d in $(DIRS); \
	do \
		make -C $$d $@; \
	done

.PHONY: kernel
kernel: $(LINUX_KERNEL)

ifneq ($(LINUX_KERNEL),)
$(LINUX_KERNEL): $(LINUX_SRC)/Makefile $(LINUX_SRC)/.config
	make -C $(LINUX_SRC) -j$(NPROCS)

$(LINUX_SRC)/Makefile:
	[ -f $(LINUX_SRC).tar.gz ] || \
	wget https://www.kernel.org/pub/linux/kernel/v$(LINUX_GEN)/$(LINUX_SRC).tar.gz
	tar -xzf $(LINUX_SRC).tar.gz
	[ ! -f $(LINUX_SRC).patch ] || git apply $(LINUX_SRC).patch

$(LINUX_SRC)/.config:
	cd $(LINUX_SRC) && make menuconfig

install: $(LINUX_KERNEL)
	make -C $(LINUX_SRC) install modules_install headers_install

linux-deb:
	if [ -f $(LINUX_SRC)/.config ]; then \
		cp /boot/config-$(shell uname -r) $(LINUX_SRC)/.config && \
		cd $(LINUX_SRC) && make menuconfig; fi
	cd $(LINUX_SRC) && \
	CONCURRENCY_LEVEL=$(NPROCS) make-kpkg --rootcmd fakeroot \
		--append-to-version -graphene --initrd \
		kernel-image kernel-headers
else
install:
endif

.PHONY: test
test:
	make -C test test

clean:
	for d in $(DIRS) $(LINUX_KERNEL); \
	do \
		make -C $$d clean; \
	done
