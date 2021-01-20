# Build Memcached as follows:
#
# - make               -- create non-SGX no-debug-log manifest
# - make SGX=1         -- create SGX no-debug-log manifest
# - make SGX=1 DEBUG=1 -- create SGX debug-log manifest
#
# Any of these invocations downloads Memcached and builds Memcached in default configuration.
#
# Use `make clean` to remove Graphene-generated files and `make distclean` to additionally remove
# the Memcached source.

############################################ CONSTANTS ############################################

# Relative path to Graphene root
GRAPHENEDIR = ../..
SGX_SIGNER_KEY ?= $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

SRCDIR = src
MEMCACHED_URL ?= https://memcached.org/files/memcached-1.5.21.tar.gz
MEMCACHED_SHA256 ?= e3d10c06db755b220f43d26d3b68d15ebf737a69c7663529b504ab047efe92f4

UBUNTU_VER = $(shell lsb_release --short --id)$(shell lsb_release --short --release)

ifeq ($(UBUNTU_VER), Ubuntu18.04)
else ifeq ($(UBUNTU_VER), Ubuntu16.04)
else
$(error This example requires Ubuntu 16.04 or 18.04)
endif

ifeq ($(DEBUG),1)
GRAPHENE_LOG_LEVEL = debug
else
GRAPHENE_LOG_LEVEL = error
endif

.PHONY: all
all: memcached memcached.manifest pal_loader
ifeq ($(SGX),1)
all: memcached.manifest.sgx memcached.sig memcached.token
endif

include ../../Scripts/Makefile.configs

####################################### MEMCACHED EXECUTABLE #######################################

# Memcached is built as usual, without any changes to the build process. The source is downloaded
# from memcached.org and built via classic ./configure && make. The result of this build process is
# the final executable "src/memcached".

$(SRCDIR)/configure:
	$(GRAPHENEDIR)/Scripts/download --output memcached.tar.gz \
		--sha256 $(MEMCACHED_SHA256) --url $(MEMCACHED_URL)
	mkdir $(SRCDIR)
	tar -C $(SRCDIR) --strip-components=1 -xf memcached.tar.gz

$(SRCDIR)/memcached: $(SRCDIR)/configure
	cd $(SRCDIR) && ./configure
	$(MAKE) -C $(SRCDIR)

######################################## MEMCACHED MANIFEST ########################################

# The template file contains almost all necessary information to run Memcached under Graphene /
# Graphene-SGX. We create memcached.manifest (to be run under non-SGX Graphene) by simply replacing
# variables in the template file via sed.

memcached.manifest: memcached.manifest.template
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
		-e 's|$$(GRAPHENE_LOG_LEVEL)|'"$(GRAPHENE_LOG_LEVEL)"'|g' \
		-e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
		-e 's|# \['"$(UBUNTU_VER)"'\] ||g' \
		$< > $@

# Manifest for Graphene-SGX requires special "pal-sgx-sign" procedure. This procedure measures all
# Memcached trusted files, adds the measurement to the resulting manifest.sgx file (among other,
# less important SGX options) and creates memcached.sig (SIGSTRUCT object).
#
# Graphene-SGX requires EINITTOKEN and SIGSTRUCT objects (see SGX hardware ABI, in particular EINIT
# instruction). The "pal-sgx-get-token" script generates EINITTOKEN based on a SIGSTRUCT and puts it
# in .token file. Note that filenames must be the same as the manifest name (i.e., "memcached").
# EINITTOKEN must be generated on the machine where the application will run, not where it was
# built.

memcached.manifest.sgx: memcached.manifest memcached
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest $< -output $@

memcached.sig: memcached.manifest.sgx

memcached.token: memcached.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token \
		-output memcached.token -sig memcached.sig

########################### COPIES OF EXECUTABLES #############################

# Memcached build process creates the final executable as src/memcached. For
# simplicity, copy it into our root directory.
# Also, create a link to pal_loader for simplicity.

memcached: $(SRCDIR)/memcached
	cp $< $@

pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/pal_loader $@

############################## RUNNING TESTS ##################################
.PHONY: start-native-server
start-native-server: all
	./memcached

.PHONY: start-graphene-server
start-graphene-server: all
	./pal_loader memcached -u nobody

################################## CLEANUP ####################################

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest pal_loader memcached .lck

.PHONY: distclean
distclean: clean
	$(RM) -r $(SRCDIR) memcached.tar.gz
