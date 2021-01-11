# Build Busybox as follows:
#
# - make               -- create non-SGX no-debug-log manifest
# - make DEBUG=1       -- create non-SGX debug-log manifest
# - make SGX=1         -- create SGX no-debug-log manifest
# - make SGX=1 DEBUG=1 -- create SGX debug-log manifest
#
# Any of these invocations downloads Busybox and builds it.
#
# Use `make clean` to remove Graphene-generated files and `make distclean` to
# additionally remove the Busybox source.

################################# CONSTANTS ###################################

# Relative path to Graphene root
GRAPHENEDIR = ../..
SGX_SIGNER_KEY ?= $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

SRCDIR = src
BUSYBOX_URL ?= https://busybox.net/downloads/busybox-1.32.0.tar.bz2
BUSYBOX_SHA256 ?= c35d87f1d04b2b153d33c275c2632e40d388a88f19a9e71727e0bbbff51fe689

ifeq ($(DEBUG),1)
GRAPHENE_LOG_LEVEL = debug
else
GRAPHENE_LOG_LEVEL = error
endif


.PHONY: all
all: busybox busybox.manifest pal_loader
ifeq ($(SGX),1)
all: busybox.manifest.sgx busybox.sig busybox.token
endif

include ../../Scripts/Makefile.configs

############################ BUSYBOX EXECUTABLE ###############################

# Busybox is built as usual, without any changes to the build process. The
# source is downloaded and then built via classic make. The result of this
# build process is the final executable "src/busybox".

$(SRCDIR)/Makefile:
	$(GRAPHENEDIR)/Scripts/download --output busybox.tar.bz2 \
		--sha256 $(BUSYBOX_SHA256) --url $(BUSYBOX_URL)
	mkdir $(SRCDIR)
	tar -C $(SRCDIR) --strip-components=1 -xf busybox.tar.bz2

$(SRCDIR)/.config: $(SRCDIR)/Makefile
	$(MAKE) -C $(SRCDIR) clean
	$(MAKE) -C $(SRCDIR) defconfig
	# Enable usage of Busybox's built-in applets
	sed -e 's/.*CONFIG_FEATURE_SH_STANDALONE.*/CONFIG_FEATURE_SH_STANDALONE=y/' \
		-i $(SRCDIR)/.config
	# Currently '/proc/self/exe' is bugged in graphene, so manually set path
	# to the Busybox binary
	sed -e 's/.*CONFIG_BUSYBOX_EXEC_PATH.*/CONFIG_BUSYBOX_EXEC_PATH="\/busybox"/' \
		-i $(SRCDIR)/.config

$(SRCDIR)/busybox: $(SRCDIR)/.config
	$(MAKE) -C $(SRCDIR)

############################## BUSYBOX MANIFEST ###############################

# The template file contains almost all necessary information to run Busybox
# under Graphene / Graphene-SGX. We create busybox.manifest (to be run under
# non-SGX Graphene) by simply replacing variables in the template file via sed.

busybox.manifest: busybox.manifest.template
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
		-e 's|$$(GRAPHENE_LOG_LEVEL)|'"$(GRAPHENE_LOG_LEVEL)"'|g' \
		-e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
		$< > $@

# Manifest for Graphene-SGX requires special "pal-sgx-sign" procedure. This procedure measures all
# Busybox trusted files, adds the measurement to the resulting manifest.sgx file (among other,
# less important SGX options) and creates busybox.sig (SIGSTRUCT object).
#
# Graphene-SGX requires EINITTOKEN and SIGSTRUCT objects (see SGX hardware ABI, in particular EINIT
# instruction). The "pal-sgx-get-token" script generates EINITTOKEN based on a SIGSTRUCT and puts it
# in .token file. Note that filenames must be the same as the manifest name (i.e., "busybox").
# EINITTOKEN must be generated on the machine where the application will run, not where it was
# built.


busybox.manifest.sgx: busybox.manifest busybox
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest $< -output $@
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token \
		-output busybox.token -sig busybox.sig

########################### COPIES OF EXECUTABLES #############################

# Busybox build process creates the final executable as "src/busybox".
# Copy Busybox binary to our root directory and create a link to pal_loader for
# simplicity.

busybox: $(SRCDIR)/busybox
	cp $(SRCDIR)/busybox busybox

pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/pal_loader $@

################################## CLEANUP ####################################

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest pal_loader busybox

.PHONY: distclean
distclean: clean
	$(RM) -r $(SRCDIR) busybox.tar.bz2

