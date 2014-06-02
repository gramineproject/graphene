LINUX_GEN = 3.x
LINUX_SRC = linux-3.5
SRC_DIR = src
TEST_DIR = test
DIRS = ${SRC_DIR} ${TEST_DIR} $(LINUX_SRC)

NPROCS := 1
OS := $(shell uname -s)
ifeq ($(OS),Linux)
	NPROCS := $(shell grep -c ^processor /proc/cpuinfo)
endif

all debug:
	for d in ${SRC_DIR} $(TEST_DIR); \
	do \
		make -C $$d $@; \
	done
	make $(LINUX_SRC)/arch/x86/boot/bzImage

$(LINUX_SRC)/arch/x86/boot/bzImage: $(LINUX_SRC)/Makefile $(LINUX_SRC)/.config
	make -C $(LINUX_SRC) -j$(NPROCS)

install: $(LINUX_SRC)/arch/x86/boot/bzImage
	make -C $(LINUX_SRC) install modules_install headers_install

.PHONY: test

test:
	make -C test test

$(LINUX_SRC)/Makefile:
	[ -f $(LINUX_SRC).tar.gz ] || \
	wget https://www.kernel.org/pub/linux/kernel/v$(LINUX_GEN)/$(LINUX_SRC).tar.gz
	tar -xzf $(LINUX_SRC).tar.gz
	[ ! -f $(LINUX_SRC).patch ] || git apply $(LINUX_SRC).patch

$(LINUX_SRC)/.config:
	$(error "Configure the kernel source and rerun the make command")

clean:
	for d in ${SRC_DIR} $(TEST_DIR) $(LINUX_SRC); \
	do \
		make -C $$d clean; \
	done
