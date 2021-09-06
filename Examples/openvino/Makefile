SHELL := /bin/bash #Use bash syntax to activate virtual environment and to download models

OPENVINO_DIR ?= $(INTEL_OPENVINO_DIR)

THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

INFERENCE_ENGINE_CPP_SAMPLES_BUILD ?=  $(THIS_DIR)inference_engine_cpp_samples_build

MODEL_DIR ?= $(THIS_DIR)model

INTEL_MODELS = \
	bert-large-uncased-whole-word-masking-squad-0001 \
	bert-large-uncased-whole-word-masking-squad-int8-0001

PUBLIC_MODELS = \
	resnet-50-tf \
	brain-tumor-segmentation-0001 \
	brain-tumor-segmentation-0002 \
	ssd_mobilenet_v1_coco

VENV_DIR ?= $(THIS_DIR)/openvino

SGX_SIGNER_KEY ?= ../../Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENE_LOG_LEVEL = debug
else
GRAPHENE_LOG_LEVEL = error
endif

.PHONY: all
all: benchmark_app benchmark_app.manifest $(VENV_DIR) intel_models public_models
ifeq ($(SGX),1)
all: benchmark_app.manifest.sgx benchmark_app.sig benchmark_app.token
endif

.PHONY: intel_models
intel_models: $(VENV_DIR)
	@source $(VENV_DIR)/bin/activate \
	&& cd $(OPENVINO_DIR)/deployment_tools/open_model_zoo/tools/downloader \
	&& for model in $(INTEL_MODELS); do \
		if [ ! -d $(abspath $(MODEL_DIR))/intel/$$model ]; then \
			python3 ./downloader.py --name $$model -o $(abspath $(MODEL_DIR)); \
			python3 ./converter.py --name $$model -d $(abspath $(MODEL_DIR)) -o $(abspath $(MODEL_DIR)); \
		fi; \
	done \
	&& deactivate

.PHONY: public_models
public_models: $(VENV_DIR)
	@source $(VENV_DIR)/bin/activate \
	&& cd $(OPENVINO_DIR)/deployment_tools/open_model_zoo/tools/downloader \
	&& for model in $(PUBLIC_MODELS); do \
		if [ ! -d $(abspath $(MODEL_DIR))/public/$$model ]; then \
			python3 ./downloader.py --name $$model -o $(abspath $(MODEL_DIR)); \
			python3 ./converter.py --name $$model -d $(abspath $(MODEL_DIR)) -o $(abspath $(MODEL_DIR)); \
		fi; \
	done \
	&& deactivate

$(VENV_DIR):
	mkdir -p model
	python3 -m venv $(VENV_DIR) \
	&& source $(VENV_DIR)/bin/activate \
	&& pip install --upgrade pip \
	&& cd $(OPENVINO_DIR)/deployment_tools/open_model_zoo/tools/downloader \
	&& python3 -mpip install -r ./requirements.in \
	&& cd $(OPENVINO_DIR)/deployment_tools/model_optimizer \
	&& pip3 install -r requirements.txt \
	&& deactivate

benchmark_app.manifest: benchmark_app.manifest.template
	graphene-manifest \
	-Dlog_level=$(GRAPHENE_LOG_LEVEL) \
	-Darch_libdir=$(ARCH_LIBDIR) \
	-Dopenvino_dir=$(abspath $(OPENVINO_DIR)) \
	-Dinference_engine_cpp_samples_build=$(abspath $(INFERENCE_ENGINE_CPP_SAMPLES_BUILD)) \
	$< > $@

benchmark_app.manifest.sgx: benchmark_app.manifest | benchmark_app
	@test -s $(SGX_SIGNER_KEY) || \
		{ echo "SGX signer private key was not found, please specify SGX_SIGNER_KEY!"; exit 1; }
	graphene-sgx-sign \
	-key $(SGX_SIGNER_KEY) \
	-manifest $< -output $@

benchmark_app.sig: benchmark_app.manifest.sgx

benchmark_app.token: benchmark_app.sig
	graphene-sgx-get-token --sig $< --output $@

benchmark_app: $(OPENVINO_DIR)
	mkdir -p $(INFERENCE_ENGINE_CPP_SAMPLES_BUILD)
	cd $(INFERENCE_ENGINE_CPP_SAMPLES_BUILD) && cmake -DCMAKE_BUILD_TYPE=Release $(OPENVINO_DIR)/inference_engine/samples/cpp && make
	ln -s $(INFERENCE_ENGINE_CPP_SAMPLES_BUILD)/intel64/Release/benchmark_app $@

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig benchmark_app

.PHONY: distclean
distclean: clean
	$(RM) -r $(MODEL_DIR) $(VENV_DIR) $(INFERENCE_ENGINE_CPP_SAMPLES_BUILD)
