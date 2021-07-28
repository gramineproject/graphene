SHELL := /bin/bash
OPENVINO_DIR ?= $(INTEL_OPENVINO_DIR)

THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

MODEL_DIR ?= $(THIS_DIR)model
MODEL_RESNET ?= resnet-50-tf
MODEL_BERT ?= bert-large-uncased-whole-word-masking-squad-0001
MODEL_BERT_INT8 ?= bert-large-uncased-whole-word-masking-squad-int8-0001
MODEL_BRATS0001 ?= brain-tumor-segmentation-0001
MODEL_BRATS0002 ?= brain-tumor-segmentation-0002
MODEL_SSD_COCO ?= ssd_mobilenet_v1_coco

VENV_DIR ?= $(THIS_DIR)/openvino

SGX_SIGNER_KEY ?= ../../Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENE_LOG_LEVEL = debug
else
GRAPHENE_LOG_LEVEL = error
endif

.PHONY: all
all: benchmark_app benchmark_app.manifest $(VENV_DIR) \
	$(MODEL_DIR)/public/$(MODEL_RESNET) \
	$(MODEL_DIR)/intel/$(MODEL_BERT) \
	$(MODEL_DIR)/intel/$(MODEL_BERT_INT8) \
	$(MODEL_DIR)/public/$(MODEL_BRATS0001) \
	$(MODEL_DIR)/public/$(MODEL_BRATS0002) \
	$(MODEL_DIR)/public/$(MODEL_SSD_COCO)
ifeq ($(SGX),1)
all: benchmark_app.manifest.sgx benchmark_app.sig \
     benchmark_app.token
endif

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

$(MODEL_DIR)/public/$(MODEL_RESNET): $(VENV_DIR)
	source $(VENV_DIR)/bin/activate \
	&& cd $(OPENVINO_DIR)/deployment_tools/open_model_zoo/tools/downloader \
	&& python3 ./downloader.py --name $(MODEL_RESNET) -o $(abspath $(MODEL_DIR)) \
	&& python3 ./converter.py --name $(MODEL_RESNET) -d $(abspath $(MODEL_DIR)) -o $(abspath $(MODEL_DIR)) \
	&& deactivate

$(MODEL_DIR)/intel/$(MODEL_BERT): $(VENV_DIR)
	source $(VENV_DIR)/bin/activate \
	&& cd $(OPENVINO_DIR)/deployment_tools/open_model_zoo/tools/downloader \
	&& python3 ./downloader.py --name $(MODEL_BERT) -o $(abspath $(MODEL_DIR)) \
	&& python3 ./converter.py --name $(MODEL_BERT) -d $(abspath $(MODEL_DIR)) -o $(abspath $(MODEL_DIR)) \
	&& deactivate

$(MODEL_DIR)/intel/$(MODEL_BERT_INT8): $(VENV_DIR)
	source $(VENV_DIR)/bin/activate \
	&& cd $(OPENVINO_DIR)/deployment_tools/open_model_zoo/tools/downloader \
	&& python3 ./downloader.py --name $(MODEL_BERT_INT8) -o $(abspath $(MODEL_DIR)) \
	&& python3 ./converter.py --name $(MODEL_BERT_INT8) -d $(abspath $(MODEL_DIR)) -o $(abspath $(MODEL_DIR)) \
	&& deactivate

$(MODEL_DIR)/public/$(MODEL_BRATS0001): $(VENV_DIR)
	source $(VENV_DIR)/bin/activate \
	&& cd $(OPENVINO_DIR)/deployment_tools/open_model_zoo/tools/downloader \
	&& python3 ./downloader.py --name $(MODEL_BRATS0001) -o $(abspath $(MODEL_DIR)) \
	&& python3 ./converter.py --name $(MODEL_BRATS0001) -d $(abspath $(MODEL_DIR)) -o $(abspath $(MODEL_DIR)) \
	&& deactivate

$(MODEL_DIR)/public/$(MODEL_BRATS0002): $(VENV_DIR)
	source $(VENV_DIR)/bin/activate \
	&& cd $(OPENVINO_DIR)/deployment_tools/open_model_zoo/tools/downloader \
	&& python3 ./downloader.py --name $(MODEL_BRATS0002) -o $(abspath $(MODEL_DIR)) \
	&& python3 ./converter.py --name $(MODEL_BRATS0002) -d $(abspath $(MODEL_DIR)) -o $(abspath $(MODEL_DIR)) \
	&& deactivate

$(MODEL_DIR)/public/$(MODEL_SSD_COCO): $(VENV_DIR)
	source $(VENV_DIR)/bin/activate \
	&& cd $(OPENVINO_DIR)/deployment_tools/open_model_zoo/tools/downloader \
	&& python3 ./downloader.py --name $(MODEL_SSD_COCO) -o $(abspath $(MODEL_DIR)) \
	&& python3 ./converter.py --name $(MODEL_SSD_COCO) -d $(abspath $(MODEL_DIR)) -o $(abspath $(MODEL_DIR)) \
	&& deactivate

benchmark_app.manifest: benchmark_app.manifest.template
	graphene-manifest \
	-Dlog_level=$(GRAPHENE_LOG_LEVEL) \
	-Darch_libdir=$(ARCH_LIBDIR) \
	-Dopenvino_dir=$(abspath $(OPENVINO_DIR)) \
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

# OpenVINO's build_samples.sh always installs samples in HOME directory
benchmark_app:
	cd $(OPENVINO_DIR)/deployment_tools/inference_engine/samples/cpp && ./build_samples.sh
	ln -s $(HOME)/inference_engine_cpp_samples_build/intel64/Release/benchmark_app $@

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig benchmark_app

.PHONY: distclean
distclean: clean
	$(RM) -r $(MODEL_DIR) $(VENV_DIR)
