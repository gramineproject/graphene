SGX_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
RUNTIME_DIR = $(SGX_DIR)/../../../../Runtime

LIBPAL = $(RUNTIME_DIR)/libpal-Linux-SGX.so
SGX_SIGNER_KEY ?= $(SGX_DIR)/signer/enclave-key.pem

# sgx manifest.sgx/sig/token
drop_manifest_suffix = $(filter-out manifest,$(sort $(patsubst %.manifest,%,$(1))))
expand_target_to_token = $(addsuffix .token,$(call drop_manifest_suffix,$(1)))
expand_target_to_sig = $(addsuffix .sig,$(call drop_manifest_suffix,$(1)))
expand_target_to_sgx = $(addsuffix .manifest.sgx,$(call drop_manifest_suffix,$(1)))

$(SGX_SIGNER_KEY):
	$(error "Cannot find any enclave key. Generate $(abspath $(SGX_SIGNER_KEY)) or specify 'SGX_SIGNER_KEY=' with make")

%.token: %.sig
	$(call cmd,sgx_get_token)

%.sig %.manifest.sgx: %.manifest %.manifest.sgx.d
	$(call cmd,sgx_sign)

.PRECIOUS: %.manifest.sgx.d
%.manifest.sgx.d: %.manifest
	$(call cmd,sgx_sign_depend)

ifeq ($(filter %clean,$(MAKECMDGOALS)),)
ifeq ($(target),)
$(error define "target" variable for manifest.sgx dependency calculation)
endif
include $(addsuffix .manifest.sgx.d,$(call drop_manifest_suffix,$(target)))
endif
