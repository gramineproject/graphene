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

DIRS = src test regression

all debug clean:
	for d in $(DIRS); \
	do \
		$(MAKE) -C $$d $@; \
	done

.PHONY: kernel
kernel: $(LINUX_KERNEL)

ifneq ($(LINUX_KERNEL),)
$(LINUX_KERNEL): $(LINUX_SRC)/Makefile $(LINUX_SRC)/graphene $(LINUX_SRC)/.config
	$(MAKE) -C $(LINUX_SRC) -j$(NPROCS)

$(LINUX_SRC)/Makefile:
	[ -f $(LINUX_SRC).tar.gz ] || \
	wget https://www.kernel.org/pub/linux/kernel/v$(LINUX_GEN)/$(LINUX_SRC).tar.gz
	tar -xzf $(LINUX_SRC).tar.gz
	cd $(LINUX_SRC) && patch -p1 < ../$(LINUX_SRC).patch

$(LINUX_SRC)/graphene: linux-kernel/graphene
	cd $(LINUX_SRC) && ln -s ../linux-kernel/graphene graphene

$(LINUX_SRC)/.config: $(LINUX_SRC)/Makefile
	cd $(LINUX_SRC) && make menuconfig

kernel_install: $(LINUX_KERNEL)
	$(MAKE) -C $(LINUX_SRC) install modules_install headers_install

install:
	[ -d ../Runtime ] || mkdir -p ../Runtime
	[ -f ../Runtime/libpal.so ] || ln -sf ../Pal/src/libpal.so ../Runtime/libpal.so
	[ -f ../Runtime/pal ] || ln -sf ../Pal/src/pal ../Runtime/pal
	[ -f ../Runtime/pal_sec ] || ln -sf ../Pal/src/pal_sec ../Runtime/pal_sec

linux-deb:
	if [ ! -f $(LINUX_SRC)/.config ]; then \
		cp /boot/config-$(shell uname -r) $(LINUX_SRC)/.config && \
		cd $(LINUX_SRC) && $(MAKE) menuconfig; fi
	cd $(LINUX_SRC) && \
	CONCURRENCY_LEVEL=$(NPROCS) make-kpkg --rootcmd fakeroot \
		--append-to-version -graphene --initrd \
		kernel_image kernel_debug kernel_headers
else
install:
endif

.PHONY: test
test:
	$(MAKE) -C test test

.PHONY: pack
pack:
	$(MAKE) -C test pack
	$(MAKE) -C regression pack
