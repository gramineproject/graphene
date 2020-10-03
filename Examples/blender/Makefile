# assumes this makefile lies in cwd
PWD := $(shell pwd)

GRAPHENE_DIR = $(PWD)/../..
SGX_SIGNER_KEY ?= $(GRAPHENE_DIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

BLENDER_DIR = $(PWD)/blender_dir
BLENDER_URL ?= https://ftp.nluug.nl/pub/graphics/blender/release/Blender2.82/blender-2.82-linux64.tar.xz
BLENDER_SHA256 ?= b13600fa2ca23ea1bba511e3a6599b6792acde80b180707c3ea75db592a9b916
BLENDER_VER = 2.82

DATA_DIR = $(PWD)/data
RUN_DIR = $(PWD)/run_dir

UBUNTU_VER = $(shell lsb_release --short --id)$(shell lsb_release --short --release)

ifeq ($(UBUNTU_VER), Ubuntu18.04)
else ifeq ($(UBUNTU_VER), Ubuntu16.04)
else
$(error This example requires Ubuntu 16.04 or 18.04)
endif

ifeq ($(DEBUG),1)
GRAPHENE_DEBUG = inline
else
GRAPHENE_DEBUG = none
endif


.PHONY: all
all: $(BLENDER_DIR)/blender $(BLENDER_DIR)/blender.manifest | $(RUN_DIR)/pal_loader $(DATA_DIR)/images
ifeq ($(SGX),1)
all: $(BLENDER_DIR)/blender.token
endif

include ../../Scripts/Makefile.configs

$(BLENDER_DIR)/blender:
	$(GRAPHENE_DIR)/Scripts/download --output blender.tar.xz \
		--sha256 $(BLENDER_SHA256) --url $(BLENDER_URL)
	mkdir $(BLENDER_DIR)
	tar -C $(BLENDER_DIR) --strip-components=1 -xf blender.tar.xz

$(RUN_DIR):
	mkdir -p $@

$(BLENDER_DIR)/blender.manifest: blender.manifest.template $(BLENDER_DIR)/blender | $(RUN_DIR)
	sed -e 's|$$(GRAPHENE_DIR)|'"$(GRAPHENE_DIR)"'|g' \
		-e 's|$$(GRAPHENE_DEBUG)|'"$(GRAPHENE_DEBUG)"'|g' \
		-e 's|$$(DATA_DIR)|'"$(DATA_DIR)"'|g' \
		-e 's|$$(BLENDER_DIR)|'"$(BLENDER_DIR)"'|g' \
		-e 's|$$(BLENDER_VER)|'"$(BLENDER_VER)"'|g' \
		-e 's|# \['"$(UBUNTU_VER)"'\] ||g' \
		-e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
		$< > $@

$(BLENDER_DIR)/blender.manifest.sgx: $(BLENDER_DIR)/blender $(BLENDER_DIR)/blender.manifest \
        $(GRAPHENE_DIR)/Runtime/libpal-Linux-SGX.so | $(RUN_DIR)
	$(GRAPHENE_DIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-output $@ \
		-libpal $(GRAPHENE_DIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest $(BLENDER_DIR)/blender.manifest \
		-exec $<

$(BLENDER_DIR)/blender.token: $(BLENDER_DIR)/blender.manifest.sgx
	$(GRAPHENE_DIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token \
		-output $@ \
		-sig $(BLENDER_DIR)/blender.sig

$(RUN_DIR)/pal_loader: | $(RUN_DIR)
	ln -s $(GRAPHENE_DIR)/Runtime/pal_loader $@

$(DATA_DIR)/images:
	mkdir -p $@

.PHONY: check
check: all
	cd $(RUN_DIR) && BLENDER_DIR=$(BLENDER_DIR) DATA_DIR=$(DATA_DIR) \
	    sh $(PWD)/test_all_scenes.sh

.PHONY: clean
clean:
	$(RM) -r $(RUN_DIR) $(DATA_DIR)/images $(BLENDER_DIR)/blender.manifest \
	      $(BLENDER_DIR)/blender.manifest.sgx $(BLENDER_DIR)/blender.sig \
	      $(BLENDER_DIR)/blender.token

.PHONY: distclean
distclean: clean
	$(RM) -r $(BLENDER_DIR) blender.tar.xz

