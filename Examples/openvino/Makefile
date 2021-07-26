THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

MODEL_DIR ?= $(THIS_DIR)model
MODEL_COMMIT ?= acf297c73db8cb3f68791ae1fad4a7cc4a6039e5     # corresponds to tag "2019_R3"
MODEL_NAME ?= VGG_VOC0712Plus_SSD_300x300_ft_iter_160000

OPENVINO_DIR ?= $(THIS_DIR)openvino
OPENVINO_COMMIT ?= 023e7c2c3f8a8ac83564db09799d2049115d9cf6  # corresponds to tag "2020.4"

SGX_SIGNER_KEY ?= ../../Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENE_LOG_LEVEL = debug
OPENVINO_BUILD = Debug
else
GRAPHENE_LOG_LEVEL = error
OPENVINO_BUILD = Release
endif

.PHONY: all
all: $(OPENVINO_DIR)/inference-engine/bin/intel64/$(OPENVINO_BUILD)/object_detection_sample_ssd \
     $(MODEL_DIR)/$(MODEL_NAME).bin object_detection_sample_ssd.manifest
ifeq ($(SGX),1)
all: object_detection_sample_ssd.manifest.sgx object_detection_sample_ssd.sig \
     object_detection_sample_ssd.token
endif

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
	git clone https://github.com/openvinotoolkit/openvino.git $(OPENVINO_DIR)
	git -C $(OPENVINO_DIR) checkout $(OPENVINO_COMMIT)
	git -C $(OPENVINO_DIR)/inference-engine submodule update --init --recursive

$(OPENVINO_DIR)/inference-engine/bin/intel64/$(OPENVINO_BUILD)/object_detection_sample_ssd: $(OPENVINO_DIR)/README.md
	cd $(OPENVINO_DIR)/inference-engine && mkdir -p build
	cd $(OPENVINO_DIR)/inference-engine/build && cmake -DCMAKE_BUILD_TYPE=$(OPENVINO_BUILD) ../..
	$(MAKE) -C $(OPENVINO_DIR)/inference-engine/build

object_detection_sample_ssd.manifest: object_detection_sample_ssd.manifest.template
	graphene-manifest \
		-Dlog_level=$(GRAPHENE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dopenvino_dir=$(abspath $(OPENVINO_DIR)) \
		-Dmodel_dir=$(MODEL_DIR) \
		-Dopenvino_build=$(OPENVINO_BUILD) \
		$< > $@

object_detection_sample_ssd.manifest.sgx: object_detection_sample_ssd.manifest \
		$(OPENVINO_DIR)/inference-engine/bin/intel64/$(OPENVINO_BUILD)/object_detection_sample_ssd
	@test -s $(SGX_SIGNER_KEY) || \
	    { echo "SGX signer private key was not found, please specify SGX_SIGNER_KEY!"; exit 1; }
	graphene-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest $< \
		--output $@

object_detection_sample_ssd.sig: object_detection_sample_ssd.manifest.sgx

object_detection_sample_ssd.token: object_detection_sample_ssd.sig
	graphene-sgx-get-token --sig $< --output $@

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig *.bmp

.PHONY: distclean
distclean: clean
	$(RM) -r $(OPENVINO_DIR) $(MODEL_DIR)
