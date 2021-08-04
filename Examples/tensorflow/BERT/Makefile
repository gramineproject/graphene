# BERT sample for Tensorflow

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)
SGX_SIGNER_KEY ?= ../../../Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENE_LOG_LEVEL = debug
else
GRAPHENE_LOG_LEVEL = error
endif

.PHONY: all
all: python.manifest
ifeq ($(SGX),1)
all: python.manifest.sgx python.sig python.token
endif

BERT_DATASET = https://storage.googleapis.com/bert_models/2019_05_30/wwm_uncased_L-24_H-1024_A-16.zip
SQUAAD_DATASET = https://rajpurkar.github.io/SQuAD-explorer/dataset/dev-v1.1.json
CHECKPOINTS = https://storage.googleapis.com/intel-optimized-tensorflow/models/v1_8/bert_large_checkpoints.zip
BERT_INT8_MODEL = https://storage.googleapis.com/intel-optimized-tensorflow/models/r2.5-icx-b631821f/asymmetric_per_channel_bert_int8.pb

collateral:
	apt install unzip
	test -d models || git clone https://github.com/IntelAI/models.git
	mkdir -p data
	test -f data/wwm_uncased_L-24_H-1024_A-16.zip || wget $(BERT_DATASET) -P data/
	test -d data/wwm_uncased_L-24_H-1024_A-16 || unzip data/wwm_uncased_L-24_H-1024_A-16.zip -d data
	test -f data/wwm_uncased_L-24_H-1024_A-16/dev-v1.1.json || wget $(SQUAAD_DATASET) -P data/wwm_uncased_L-24_H-1024_A-16
	test -f data/bert_large_checkpoints.zip || wget $(CHECKPOINTS) -P data/
	test -d data/bert_large_checkpoints || unzip data/bert_large_checkpoints.zip -d data
	test -f data/asymmetric_per_channel_bert_int8.pb || wget $(BERT_INT8_MODEL) -P data/

python.manifest: python.manifest.template collateral
	graphene-manifest \
		-Dlog_level=$(GRAPHENE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dentrypoint=$(realpath $(shell sh -c "command -v python3")) \
		-Dpythondistpath=$(PYTHONDISTPATH) \
		$< >$@

python.manifest.sgx: python.manifest
	@test -s $(SGX_SIGNER_KEY) || \
		{ echo "SGX signer private key was not found, please specify SGX_SIGNER_KEY!"; exit 1; }
	graphene-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest $< -output $@

python.sig: python.manifest.sgx

python.token: python.sig
	graphene-sgx-get-token -output $@ -sig $<

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig

.PHONY: distclean
distclean: clean
	$(RM) -r models/ data/
