SYS ?= $(shell gcc -dumpmachine)
export SYS

export DEBUG

GLIBC_SRC = glibc-2.19
SHIM_DIR = shim
BUILD_DIR = glibc-build
GLIBC_TARGET = $(addprefix $(BUILD_DIR)/,libc.so.6 ld-linux-x86-64.so.2 libpthread.so.0 libm.so.6 libdl.so.2 libutil.so.1 crt1.o crti.o crtn.o liblibos.so.1)

all: $(GLIBC_TARGET)
	$(MAKE) -C $(SHIM_DIR) all

install:
	[ -d ../Runtime ] || mkdir -p ../Runtime
	[ -f ../Runtime/libsysdb.so ] || ln -sf ../LibOS/shim/src/libsysdb.so ../Runtime/libsysdb.so
	./buildglibc.py install --quiet

ifeq ($(SYS),x86_64-linux-gnu)
$(GLIBC_TARGET): $(BUILD_DIR)/Makefile
	cd $(BUILD_DIR) && $(MAKE)

$(BUILD_DIR)/Makefile: $(GLIBC_SRC)/configure
ifeq ($(DEBUG),1)
	./buildglibc.py --quiet --debug
else
	./buildglibc.py --quiet
endif

$(GLIBC_SRC)/configure:
	[ -f $(GLIBC_SRC).tar.gz ] || \
	wget http://ftp.gnu.org/gnu/glibc/$(GLIBC_SRC).tar.gz
	tar -xzf $(GLIBC_SRC).tar.gz
	cd $(GLIBC_SRC) && patch -p1 < ../$(GLIBC_SRC).patch

.PHONY: pack
pack: $(GLIBC_TARGET)
	@../Scripts/pack_binaries.sh glibc $^
	$(MAKE) -C $(SHIM_DIR) pack

clean:
	$(MAKE) -C $(SHIM_DIR) clean
	rm -rf $(BUILD_DIR)
else
$(GLIBC_TARGET): .packed/glibc.tar.gz
	tar -xmozf $< $@

clean:
	rm -rf $(BUILD_DIR)
endif
