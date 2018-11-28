include src/Makefile.Host

ifeq ($(OS),Linux)
	NPROCS ?= $(shell grep -c ^processor /proc/cpuinfo)
else
	NPROCS ?= 1
endif

ifeq ($(OS),Linux)
	LINUX_GEN := 3.x
	LINUX_SRC := linux-3.19
	LINUX_KERNEL := $(LINUX_SRC)/arch/x86/boot/bzImage
endif

DIRS = src test regression

.PHONY: all clean
all clean:
	for d in $(DIRS); \
	do \
		$(MAKE) -C $$d $@ || exit $?; \
	done

.PHONY: linux-kernel
linux-kernel: $(LINUX_KERNEL)

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

kernel_install: kernel
	$(MAKE) -C $(LINUX_SRC) install modules_install headers_install

linux-deb:
	if [ ! -f $(LINUX_SRC)/.config ]; then \
		cp /boot/config-$(shell uname -r) $(LINUX_SRC)/.config && \
		cd $(LINUX_SRC) && $(MAKE) menuconfig; fi
	cd $(LINUX_SRC) && \
	CONCURRENCY_LEVEL=$(NPROCS) make-kpkg --rootcmd fakeroot \
		--append-to-version -graphene --initrd \
		kernel_image kernel_headers $(if $(DEBUG),kernel_debug,)
else
kernel_install:
endif

.PHONY: test
test:
	$(MAKE) -C test test

.PHONY: format
format:
	clang-format -i $(shell find . -path ./linux-kernel -prune -o \
	                               -path ./lib/crypto/mbedtls -prune -o \
	                               -path ./lib/crypto/udivmodti4.c -prune -o \
	                               -path ./src/host/Linux-SGX/sgx-driver -prune -o \
	                               -path ./src/security/Linux/bpf-helper.h -prune -o \
	                               -path ./src/security/Linux/bpf_helper.c -prune -o \
	                               \( -name '*.h' -o -name '*.c' \) -print)

.PHONY: pack
pack:
	$(MAKE) -C test pack
	$(MAKE) -C regression pack
