# Build Redis as follows:
#
# - make               -- create non-SGX no-debug-log manifest
# - make SGX=1         -- create SGX no-debug-log manifest
# - make SGX=1 DEBUG=1 -- create SGX debug-log manifest
#
# Any of these invocations clones Redis' git repository and builds Redis in
# default configuration and in the latest-to-date (6.0.5) version.
#
# By default, Redis uses poll/epoll mechanism of Linux. To build Redis with
# select, use `make USE_SELECT=1`. For correct re-builds, always clean up
# Redis source code beforehand via `make distclean`.
#
# Use `make clean` to remove Graphene-generated files and `make distclean` to
# additionally remove the cloned Redis git repository.

################################# CONSTANTS ###################################

# In production env, SGX_SIGNER_KEY must point to production signing key
SGX_SIGNER_KEY ?= ../../Pal/src/host/Linux-SGX/signer/enclave-key.pem

# directory with arch-specific libraries, used by Redis
# the below path works for Debian/Ubuntu; for CentOS/RHEL/Fedora, you should
# overwrite this default like this: `ARCH_LIBDIR=/lib64 make`
ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

SRCDIR = src
COMMIT = 6.0.5
TAR_SHA256 = f7ded6c27d48c20bc78e797046c79b6bc411121f0c2d7eead9fea50d6b0b6290

ifeq ($(DEBUG),1)
GRAPHENE_LOG_LEVEL = debug
else
GRAPHENE_LOG_LEVEL = error
endif

.PHONY: all
all: redis-server redis-server.manifest
ifeq ($(SGX),1)
all: redis-server.manifest.sgx redis-server.sig redis-server.token
endif

############################## REDIS EXECUTABLE ###############################

# Redis is built as usual, without any changes to the build process (except to
# test select syscall instead of poll/epoll). The source is downloaded from the
# GitHub repo (6.0.5 tag) and built via `make`. The result of this build process
# is the final executable "src/redis-server".

$(SRCDIR)/Makefile:
	../common_tools/download --output redis.tar.gz \
		--sha256 $(TAR_SHA256) \
		--url https://github.com/antirez/redis/archive/$(COMMIT).tar.gz \
		--url https://packages.grapheneproject.io/distfiles/redis-$(COMMIT).tar.gz
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

# The template file contains almost all necessary information to run Redis under
# Graphene / Graphene-SGX. We create redis-server.manifest (to be run under
# non-SGX Graphene) by replacing variables in the template file using the
# "graphene-manifest" script.

redis-server.manifest: redis-server.manifest.template
	graphene-manifest \
		-Dlog_level=$(GRAPHENE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		$< > $@

# Manifest for Graphene-SGX requires special "graphene-sgx-sign" procedure. This
# procedure measures all Redis trusted files, adds the measurement to the
# resulting manifest.sgx file (among other, less important SGX options) and
# creates redis-server.sig (SIGSTRUCT object).
#
# Graphene-SGX requires EINITTOKEN and SIGSTRUCT objects (see SGX hardware ABI,
# in particular EINIT instruction). The "graphene-sgx-get-token" script
# generates EINITTOKEN based on a SIGSTRUCT and puts it in .token file. Note
# that filenames must be the same as the manifest name (i.e., "redis-server").
# EINITTOKEN must be generated on the machine where the application will run,
# not where it was built.

# Make on Ubuntu <= 20.04 doesn't support "Rules with Grouped Targets" (`&:`),
# we need to hack around.
redis-server.sig redis-server.manifest.sgx: sgx_outputs
	@:

.INTERMEDIATE: sgx_outputs
sgx_outputs: redis-server.manifest $(SRCDIR)/src/redis-server
	@test -s $(SGX_SIGNER_KEY) || \
	    { echo "SGX signer private key was not found, please specify SGX_SIGNER_KEY!"; exit 1; }
	graphene-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest redis-server.manifest \
		--output redis-server.manifest.sgx

redis-server.token: redis-server.sig
	graphene-sgx-get-token --output $@ --sig $<

########################### COPIES OF EXECUTABLES #############################

# Redis build process creates the final executable as src/redis-server. For
# simplicity, copy it into our root directory.

redis-server: $(SRCDIR)/src/redis-server
	cp $< $@

############################## RUNNING TESTS ##################################
.PHONY: start-native-server
start-native-server: all
	./redis-server --save '' --protected-mode no

ifeq ($(SGX),)
GRAPHENE = graphene-direct
else
GRAPHENE = graphene-sgx
endif

.PHONY: start-graphene-server
start-graphene-server: all
	$(GRAPHENE) redis-server --save '' --protected-mode no

################################## CLEANUP ####################################

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest redis-server *.rdb

.PHONY: distclean
distclean: clean
	$(RM) -r $(SRCDIR) redis.tar.gz
