# Build Java Blockchain demo as follows:
#
# - make               -- create non-SGX no-debug-log manifest
# - make SGX=1         -- create SGX no-debug-log manifest
# - make SGX=1 DEBUG=1 -- create SGX debug-log manifest
#
# Additional Prerequisites:
#   1) An OpenJDK installed in folder /opt (default: /opt/jdk)
#   2) Gradle installed on system
#   3) Gradle proxy configured in ~/.gradle/gradle.properties if behind firewall
#
# Use `make run-native` to run workload with native JDK, (default JDK_HOME: /opt/jdk)
# Use `make run-gr` to run workload with Graphene
# Use `make SGX=1 run-gr` to run workload with Graphene SGX
#
# Use `make clean` to remove Graphene-generated files and `make distclean` to
# additionally remove workload artifacts.

################################# CONSTANTS ###################################

# Relative path to Graphene root
GRAPHENEDIR ?= ../..
SGX_SIGNER_KEY ?= $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

# Global tunable parameters
G_JAVA_XMX ?= 2G
G_SGX_SIZE ?= 8G
G_SGX_THREAD_NUM ?= 256

# default OpenJDK path
JDK_HOME ?= /opt/jdk

# Java block chain demo info
WL_DIR = blockchain_demo

# Java blockchain info
WL_PKG_VERSION = 1.0
WL_PKG_SHA256 = d8d133db8e8f4b3b15a0691e7a3f6e5d61213040cc9298e161bf70f33f386bbb
WL_PKG_NAME = blockchain_v$(WL_PKG_VERSION).tar.gz
WL_TARGET = $(WL_DIR)/block-chain-all-$(WL_PKG_VERSION).jar

ifeq ($(DEBUG),1)
GRAPHENEDEBUG = inline
else
GRAPHENEDEBUG = none
endif

.PHONY: all
all: java.manifest pal_loader
ifeq ($(SGX),1)
all: java.manifest.sgx
endif

include $(GRAPHENEDIR)/Scripts/Makefile.configs

######### PREPARING JAVA BLOCK CHAIN DEMO WORKLOAD ###############################

# Building blockchain demo using Gradle, the proxy needs to be configured properly
# on Gradle if behind firewall.

$(WL_TARGET):
	$(GRAPHENEDIR)/Scripts/download --output $(WL_PKG_NAME) \
		--sha256 $(WL_PKG_SHA256) \
		--url https://github.com/bigdata-memory/java-examples/tarball/v$(WL_PKG_VERSION)
	mkdir $(WL_DIR) && tar -C $(WL_DIR) --strip-components=1 -xf $(WL_PKG_NAME) && \
		cd $(WL_DIR)/block-chain && gradle fatjar && \
		cp build/libs/block-chain-all-$(WL_PKG_VERSION).jar .. && cd -

################### JAVA BLOCK CHAIN DEMO MANIFEST ###############################

# The template file contains almost all necessary information to run Java block chain demo
# under Graphene / Graphene-SGX. We create java.manifest (to be run under
# non-SGX Graphene) by simply replacing variables in the template file via sed.

java.manifest: java.manifest.template $(WL_TARGET)
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
		-e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
		-e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
		-e 's|$$(JDK_HOME)|'"$(JDK_HOME)"'|g' \
		-e 's|$$(WL_TARGET)|'"$(WL_TARGET)"'|g' \
		-e 's|$$(G_SGX_SIZE)|'"$(G_SGX_SIZE)"'|g' \
		-e 's|$$(G_SGX_THREAD_NUM)|'"$(G_SGX_THREAD_NUM)"'|g' \
		$< > $@

# Manifest for Graphene-SGX requires special "pal-sgx-sign" procedure. This
# procedure measures all JVM dependencies (shared libraries and trusted
# files), measures JVM code/data pages, and adds measurements in the
# resulting manifest.sgx file (among other, less important SGX options).
#
# Additionally, Graphene-SGX requires EINITTOKEN and SIGSTRUCT objects (see
# SGX hardware ABI, in particular EINIT instruction). The "pal-sgx-get-token"
# script generates these objects and puts them in files .token and .sig
# respectively. Note that filenames must be the same as the executable/manifest
# name (i.e., "java").

java.manifest.sgx: java.manifest $(WL_TARGET)
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest $< -output $@ \
		-exec $(JDK_HOME)/bin/java
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token \
		-output java.token -sig java.sig

########################### COPIES OF PAL EXECUTABLE #############################

pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/pal_loader $@

############################## RUNNING TESTS ##################################
.PHONY: run-native
run-native: all
	$(JDK_HOME)/bin/java -jar $(WL_TARGET)

.PHONY: run-gr
run-gr: all
	./pal_loader java.manifest -Xmx$(G_JAVA_XMX) -jar $(WL_TARGET)

################################## CLEANUP ####################################

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest pal_loader

.PHONY: distclean
distclean: clean
	$(RM) -r $(WL_DIR) *.tar.gz
