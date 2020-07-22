# Building the manifest for OpenVINO:
#
# - make                Build for Linux, OpenVINO with Release build
# - make DEBUG=1        Build for Linux, OpenVINO with Debug build, Graphene with debug output
# - make SGX=1          Build for SGX, OpenVINO with Release build
# - make SGX=1 DEBUG=1  Build for SGX, OpenVINO with Debug build, Graphene with debug output
#
# Use `make clean` to remove Graphene-generated files.
#
# Use `make distclean` to further remove the OpenVINO source and installation.

THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

MODEL_DIR ?= $(THIS_DIR)model
MODEL_COMMIT ?= acf297c73db8cb3f68791ae1fad4a7cc4a6039e5     # corresponds to tag "2019_R3"
MODEL_NAME ?= VGG_VOC0712Plus_SSD_300x300_ft_iter_160000

OPENVINO_DIR ?= $(THIS_DIR)openvino
OPENVINO_COMMIT ?= ba6e22b1b5ee4cbefcc30e8d9493cddb0bb3dfdf  # corresponds to tag "2019_R2"

# Relative path to Graphene root and key for enclave signing
GRAPHENE_DIR ?= ../..
SGX_SIGNER_KEY ?= $(GRAPHENE_DIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENE_DEBUG = inline
OPENVINO_BUILD = Debug
LIBTBB_DEBUG   = "sgx.trusted_files.libtbb_debug = file:$(OPENVINO_DIR)/inference-engine/temp/tbb/lib/libtbb_debug.so.2"
else
GRAPHENE_DEBUG = none
OPENVINO_BUILD = Release
LIBTBB_DEBUG   = ""
endif

.PHONY: all
all: $(OPENVINO_DIR)/inference-engine/bin/intel64/$(OPENVINO_BUILD)/object_detection_sample_ssd $(MODEL_DIR)/$(MODEL_NAME).bin openvino.manifest pal_loader
ifeq ($(SGX),1)
all: openvino.manifest.sgx openvino.sig openvino.token
endif

include ../../Scripts/Makefile.configs

$(MODEL_DIR)/README.md:
	git clone https://github.com/opencv/open_model_zoo.git $(MODEL_DIR)
	git -C $(MODEL_DIR) checkout $(MODEL_COMMIT)

$(MODEL_DIR)/$(MODEL_NAME).bin: $(MODEL_DIR)/README.md
	cd $(MODEL_DIR)/tools/downloader && python3 ./downloader.py \
		--name ssd300 -o $(abspath $(MODEL_DIR))
	cd $(OPENVINO_DIR)/model-optimizer && python3 ./mo.py \
		--input_model $(abspath $(MODEL_DIR))/public/ssd300/models/VGGNet/VOC0712Plus/SSD_300x300_ft/$(MODEL_NAME).caffemodel \
		--input_proto $(abspath $(MODEL_DIR))/public/ssd300/models/VGGNet/VOC0712Plus/SSD_300x300_ft/deploy.prototxt \
		--output_dir $(abspath $(MODEL_DIR))

$(OPENVINO_DIR)/README.md:
	git clone https://github.com/opencv/dldt.git $(OPENVINO_DIR)
	git -C $(OPENVINO_DIR) checkout $(OPENVINO_COMMIT)
	git -C $(OPENVINO_DIR)/inference-engine submodule init
	git -C $(OPENVINO_DIR)/inference-engine submodule update --recursive

$(OPENVINO_DIR)/inference-engine/bin/intel64/$(OPENVINO_BUILD)/object_detection_sample_ssd: $(OPENVINO_DIR)/README.md
	cd $(OPENVINO_DIR)/inference-engine && mkdir -p build
	cd $(OPENVINO_DIR)/inference-engine/build && cmake -DCMAKE_BUILD_TYPE=$(OPENVINO_BUILD) ..
	$(MAKE) -C $(OPENVINO_DIR)/inference-engine/build

openvino.manifest: openvino.manifest.template
	sed -e 's|$$(GRAPHENE_DIR)|'"$(GRAPHENE_DIR)"'|g' \
	    -e 's|$$(GRAPHENE_DEBUG)|'"$(GRAPHENE_DEBUG)"'|g' \
	    -e 's|$$(OPENVINO_DIR)|'"$(OPENVINO_DIR)"'|g' \
	    -e 's|$$(OPENVINO_DIR_ABSPATH)|'"$(abspath $(OPENVINO_DIR))"'|g' \
	    -e 's|$$(MODEL_DIR)|'"$(MODEL_DIR)"'|g' \
	    -e 's|$$(OPENVINO_BUILD)|'"$(OPENVINO_BUILD)"'|g' \
	    -e 's|$$(LIBTBB_DEBUG)|'$(LIBTBB_DEBUG)'|g' \
	    -e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
	    $< > $@

# Generating the SGX-specific manifest (openvino.manifest.sgx), the enclave signature,
# and the token for enclave initialization.
openvino.manifest.sgx: openvino.manifest $(OPENVINO_DIR)/inference-engine/bin/intel64/$(OPENVINO_BUILD)/object_detection_sample_ssd
	$(GRAPHENE_DIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENE_DIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest $< -output $@

openvino.sig: openvino.manifest.sgx

openvino.token: openvino.sig
	$(GRAPHENE_DIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -sig $< -output $@

# Extra executables
pal_loader:
	ln -s $(GRAPHENE_DIR)/Runtime/pal_loader $@

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig pal_loader *.bmp

.PHONY: distclean
distclean: clean
	$(RM) -r $(OPENVINO_DIR) $(MODEL_DIR)
