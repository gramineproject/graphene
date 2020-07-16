# Build Redis as follows:
#
# - make               -- create non-SGX no-debug-log manifest
# - make SGX=1         -- create SGX no-debug-log manifest
# - make SGX=1 DEBUG=1 -- create SGX debug-log manifest
#
# Any of these invocations clones Redis' git repository and builds Redis in
# default configuration and in the latest-to-date (5.0.5) version.
#
# By default, Redis uses poll/epoll mechanism of Linux. To build Redis with
# select, use `make USE_SELECT=1`. For correct re-builds, always clean up
# Redis source code beforehand via `make distclean`.
#
# Use `make clean` to remove Graphene-generated files and `make distclean` to
# additionally remove the cloned Redis git repository.

################################# CONSTANTS ###################################

# Relative path to Graphene root
GRAPHENEDIR = ../..
SGX_SIGNER_KEY ?= $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

SRCDIR = src
COMMIT = 6.0.5
TAR_SHA256 = f7ded6c27d48c20bc78e797046c79b6bc411121f0c2d7eead9fea50d6b0b6290

ifeq ($(DEBUG),1)
GRAPHENEDEBUG = inline
else
GRAPHENEDEBUG = none
endif

.PHONY: all
all: redis-server redis-server.manifest pal_loader
ifeq ($(SGX),1)
all: redis-server.manifest.sgx
endif

include ../../Scripts/Makefile.configs

############################## REDIS EXECUTABLE ###############################

# Redis is built as usual, without any changes to the build process (except to
# test select syscall instead of poll/epoll). The source is downloaded from the
# GitHub repo (5.0.5 tag) and built via `make`. The result of this build process
# is the final executable "src/redis-server".

$(SRCDIR)/Makefile:
	$(GRAPHENEDIR)/Scripts/download --output redis.tar.gz \
		--sha256 $(TAR_SHA256) \
		--url https://github.com/antirez/redis/archive/$(COMMIT).tar.gz
	mkdir $(SRCDIR)
	tar -C $(SRCDIR) --strip-components=1 -xf redis.tar.gz

ifeq ($(USE_SELECT),1)
$(SRCDIR)/src/redis-server: $(SRCDIR)/Makefile
	sed -i 's|#define HAVE_EPOLL 1|/* no HAVE_EPOLL */|g' src/src/config.h
	$(MAKE) -C $(SRCDIR)
else
$(SRCDIR)/src/redis-server: $(SRCDIR)/Makefile
	$(MAKE) -C $(SRCDIR)
endif

################################ REDIS MANIFEST ###############################

# The template file contains almost all necessary information to run Redis
# under Graphene / Graphene-SGX. We create redis.manifest (to be run under
# non-SGX Graphene) by simply replacing variables in the template file via sed.

redis-server.manifest: redis-server.manifest.template
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
		-e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
		-e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
		$< > $@

# Manifest for Graphene-SGX requires special "pal-sgx-sign" procedure. This
# procedure measures all Redis dependencies (shared libraries and trusted
# files), measures Redis code/data pages, and adds measurements in the
# resulting manifest.sgx file (among other, less important SGX options).
#
# Additionally, Graphene-SGX requires EINITTOKEN and SIGSTRUCT objects (see
# SGX hardware ABI, in particular EINIT instruction). The "pal-sgx-get-token"
# script generates these objects and puts them in files .token and .sig
# respectively. Note that filenames must be the same as the executable/manifest
# name (i.e., "redis-server").

redis-server.manifest.sgx: redis-server.manifest $(SRCDIR)/src/redis-server
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest $< -output $@ \
		-exec $(SRCDIR)/src/redis-server
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token \
		-output redis-server.token -sig redis-server.sig

########################### COPIES OF EXECUTABLES #############################

# Redis build process creates the final executable as src/redis-server. For
# simplicity, copy it into our root directory.
# Also, create a link to pal_loader for simplicity.

redis-server: $(SRCDIR)/src/redis-server
	cp $< $@

pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/pal_loader $@

############################## RUNNING TESTS ##################################
.PHONY: start-native-server
start-native-server: all
	./redis-server --save '' --protected-mode no

.PHONY: start-graphene-server
start-graphene-server: all
	./pal_loader redis-server --save '' --protected-mode no

################################## CLEANUP ####################################

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest pal_loader redis-server *.rdb

.PHONY: distclean
distclean: clean
	$(RM) -r $(SRCDIR) redis.tar.gz
