include ../../Scripts/Makefile.configs
include ../../Scripts/Makefile.rules

CFLAGS += \
	-I../include \
	-I../include/arch/$(ARCH) \
	-Icrypto/mbedtls/include

CFLAGS += -fPIC -fno-builtin -Wextra

# FIXME: currently disable GCC's stack protector in the common lib because it is linked with
#        different libraries/executables including those that do not provide __stack_chk_fail(),
#        e.g. PAL regression tests (in particular, avl_tree_test.c)
CFLAGS += -fno-stack-protector

CFLAGS += $(CFLAGS_SANITIZERS)

CRYPTO_PROVIDER ?= mbedtls

# Select which crypto adapter you want to use here. This has to match the #define in crypto.h.
ifeq ($(CRYPTO_PROVIDER),mbedtls)
crypto_mbedtls_library_objs = \
	crypto/mbedtls/library/aes.o \
	crypto/mbedtls/library/base64.o \
	crypto/mbedtls/library/bignum.o \
	crypto/mbedtls/library/cipher.o \
	crypto/mbedtls/library/cipher_wrap.o \
	crypto/mbedtls/library/cmac.o \
	crypto/mbedtls/library/ctr_drbg.o \
	crypto/mbedtls/library/dhm.o \
	crypto/mbedtls/library/entropy.o \
	crypto/mbedtls/library/gcm.o \
	crypto/mbedtls/library/hkdf.o \
	crypto/mbedtls/library/md.o \
	crypto/mbedtls/library/oid.o \
	crypto/mbedtls/library/platform_util.o \
	crypto/mbedtls/library/rsa.o \
	crypto/mbedtls/library/rsa_internal.o \
	crypto/mbedtls/library/sha256.o \
	crypto/mbedtls/library/ssl_ciphersuites.o \
	crypto/mbedtls/library/ssl_cli.o \
	crypto/mbedtls/library/ssl_msg.o \
	crypto/mbedtls/library/ssl_srv.o \
	crypto/mbedtls/library/ssl_tls.o
ifeq ($(ARCH),x86_64)
crypto_mbedtls_library_objs += \
	crypto/mbedtls/library/aesni.o
endif

objs += $(crypto_mbedtls_library_objs)

# Compile mbedtls without UBSan. UBSan makes the code much slower, and consumes a lot of stack:
# `mbedtls_internal_sha256_process` (as compiled by clang) takes up over 20 KB, overflowing LibOS
# stack.
ifeq ($(UBSAN),1)
$(crypto_mbedtls_library_objs): CFLAGS += -fno-sanitize=undefined
$(addprefix $(target),$(crypto_mbedtls_library_objs)): CFLAGS += -fno-sanitize=undefined
endif

endif

MBEDTLS_VERSION ?= 2.26.0
MBEDTLS_SRC ?= mbedtls-$(MBEDTLS_VERSION).tar.gz
MBEDTLS_URI ?= \
	https://github.com/ARMmbed/mbedtls/archive \
	https://packages.grapheneproject.io/distfiles
MBEDTLS_CHECKSUM ?= 35d8d87509cd0d002bddbd5508b9d2b931c5e83747d087234cc7ad551d53fe05

crypto/$(MBEDTLS_SRC):
	../../Scripts/download --output $@ $(foreach mirror,$(MBEDTLS_URI),--url $(mirror)/$(MBEDTLS_SRC)) --sha256 $(MBEDTLS_CHECKSUM)

ifeq ($(DEBUG),1)
MBED_BUILD_TYPE=Debug
else
MBED_BUILD_TYPE=Release
endif

# First, build mbedtls library against system's glibc and install in ../install. This library is
# used by, for example, LibOS test cases. Second, prepare mbedtls directory to be used during PAL
# build. A custom config.h header replaces libc dependencies with PAL-specific alternatives.
crypto/mbedtls/CMakeLists.txt: crypto/$(MBEDTLS_SRC) crypto/mbedtls-$(MBEDTLS_VERSION).diff
	$(RM) -r crypto/mbedtls
	cd crypto && tar -mxzf $(MBEDTLS_SRC)
	mv crypto/mbedtls-mbedtls-$(MBEDTLS_VERSION) crypto/mbedtls
	cd crypto/mbedtls && patch -p1 < ../mbedtls-$(MBEDTLS_VERSION).diff || exit 255
	mkdir crypto/mbedtls/install
	cd crypto/mbedtls && perl ./scripts/config.pl set MBEDTLS_CMAC_C && $(MAKE) CFLAGS="" SHARED=1 DESTDIR=install install .
	$(RM) crypto/mbedtls/include/mbedtls/config.h

crypto/mbedtls/include/mbedtls/config.h: crypto/config.h crypto/mbedtls/CMakeLists.txt
	cp crypto/config.h crypto/mbedtls/include/mbedtls

crypto/mbedtls/library/aes.c: crypto/mbedtls/CMakeLists.txt crypto/mbedtls/include/mbedtls/config.h
$(filter-out crypto/mbedtls/library/aes.c,$(patsubst %.o,%.c,$(crypto_mbedtls_library_objs))): crypto/mbedtls/library/aes.c

objs += \
	avl_tree.o \
	network/hton.o \
	network/inet_pton.o \
	path.o \
	stack_protector.o \
	stdlib/printfmt.o \
	string/atoi.o \
	string/ctype.o \
	string/memcmp.o \
	string/memcpy.o \
	string/memset.o \
	string/strchr.o \
	string/strcmp.o \
	string/strlen.o \
	string/strspn.o \
	string/strstr.o \
	string/toml_utils.o \
	string/utils.o \
	toml.o

ifeq ($(UBSAN),1)
objs += ubsan.o
endif

$(addprefix $(target),crypto/adapters/mbedtls_adapter.o): crypto/mbedtls/library/aes.c

ifeq ($(CRYPTO_PROVIDER),mbedtls)
CFLAGS += -DCRYPTO_USE_MBEDTLS
objs += crypto/adapters/mbedtls_adapter.o
endif

.PHONY: all
all: uthash.patched $(target)graphene-lib.a

$(target)graphene-lib.a: $(addprefix $(target),$(objs))
	@mkdir -p $(dir $@)
	$(call cmd,ar_a_o)

$(target)%.o: %.c toml.patched
	@mkdir -p $(dir $@)
	$(call cmd,cc_o_c)

ifeq ($(filter %clean,$(MAKECMDGOALS)),)
-include $(patsubst %.o,%.d,$(addprefix $(target),$(objs)))
endif

UTHASH_URI ?= \
	https://raw.githubusercontent.com/troydhanson/uthash/8b214aefcb81df86a7e5e0d4fa20e59a6c18bc02/src/uthash.h \
	https://packages.grapheneproject.io/distfiles/uthash-2.1.0/src/uthash.h
UTHASH_CHECKSUM ?= ba9af0e8c902108cc40be8e742ff4fcbb0e93062d91aefd6070b70d4e067c2ac

uthash.h:
	../../Scripts/download --output $@ --sha256 $(UTHASH_CHECKSUM) $(foreach mirror,$(UTHASH_URI),--url $(mirror))

uthash.patched: uthash.h
	patch -p1 < uthash.patch || exit 255
	cp uthash.h ../include/uthash.h
	touch $@

TOML_COMMIT ?= 208203af46bdbdb29ba199660ed78d09c220b6c5
TOML_H_URI ?= \
	https://raw.githubusercontent.com/cktan/tomlc99/$(TOML_COMMIT)/toml.h \
	https://packages.grapheneproject.io/distfiles/tomlc99-$(TOML_COMMIT)/toml.h
TOML_H_CHECKSUM ?= 2156347bb23ac717aaa1260eef34daeb87565fc2c647e2bc92fa691787fc210c
TOML_C_URI ?= \
	https://raw.githubusercontent.com/cktan/tomlc99/$(TOML_COMMIT)/toml.c \
	https://packages.grapheneproject.io/distfiles/tomlc99-$(TOML_COMMIT)/toml.c
TOML_C_CHECKSUM ?= 98115b4483f4c23f6f22b19f1fb86e2a0e3855c02aa1eed21d8a19f9afbc6c35

toml.h:
	../../Scripts/download --output $@ --sha256 $(TOML_H_CHECKSUM) $(foreach mirror,$(TOML_H_URI),--url $(mirror))

toml.c:
	../../Scripts/download --output $@ --sha256 $(TOML_C_CHECKSUM) $(foreach mirror,$(TOML_C_URI),--url $(mirror))

toml.patched: toml.h toml.c
	patch -p1 -l < toml.patch || exit 255
	cp toml.h ../include/toml.h
	touch $@

.PHONY: clean
clean:
	$(RM) $(objs) $(patsubst %.o,%.d,$(objs)) graphene-lib.a

.PHONY: distclean
distclean: clean
	$(RM) -r crypto/$(MBEDTLS_SRC) crypto/mbedtls
	$(RM) ../include/uthash.h uthash.h uthash.patched
	$(RM) ../include/toml.h toml.h toml.c toml.patched
