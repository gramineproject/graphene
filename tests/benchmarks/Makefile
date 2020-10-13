BENCHMARKS = \
	 helloworld \
	 write_1e4 \
	 write_1e5 \
	 write_1e6 \
	 write_1e7
GRAPHENEDIR = $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
signer = $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer


all: $(BENCHMARKS) $(patsubst %,%.token,$(BENCHMARKS))

$(filter write_%,$(BENCHMARKS)): %: write_pages.c
	$(CC) $(CFLAGS) $< -o $@
write_1e4 : CFLAGS += -DPAGECOUNT=10000
write_1e5 : CFLAGS += -DPAGECOUNT=100000
write_1e6 : CFLAGS += -DPAGECOUNT=1000000
write_1e7 : CFLAGS += -DPAGECOUNT=10000000

%.manifest: manifest.template
	sed \
		-e 's:@GRAPHENEDIR@:$(GRAPHENEDIR):g' $< \
	> $@

.PRECIOUS: %.manifest.sgx
%.manifest.sgx: % %.manifest
	$(signer)/pal-sgx-sign \
		--exec $< \
		--manifest $<.manifest \
		--output $@ \
		--key $(signer)/enclave-key.pem \
		--libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so

%.token: %.manifest.sgx
	$(signer)/pal-sgx-get-token \
		--sig $*.sig \
		--output $@

.PHONY: clean
clean:
	$(RM) \
		$(BENCHMARKS) \
		$(patsubst %,%.manifest,$(BENCHMARKS)) \
		$(patsubst %,%.manifest.sgx,$(BENCHMARKS)) \
		$(patsubst %,%.sig,$(BENCHMARKS)) \
		$(patsubst %,%.token,$(BENCHMARKS))
