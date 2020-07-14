include buildenv.mk

include $(TOPDIR)/../../Scripts/Makefile.configs

all: readpipe writepipe testpipe pal_loader readpipe.manifest writepipe.manifest 
ifeq ($(SGX), 1)
all: $(TARGET_MANIFEST_SGX) readpipe.manifest.sgx writepipe.manifest.sgx 
endif

writepipe : writepipe.c
	gcc writepipe.c -o $@

readpipe : readpipe.c
	gcc readpipe.c -o $@

readpipe.manifest: readpipe.manifest.template
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
        -e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
        -e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
        $< > $@

readpipe.manifest.sgx: readpipe.manifest readpipe
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
        -libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
        -key $(SGX_SIGNER_KEY) \
        -manifest $< -output $@ \
        -exec readpipe 
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token \
        -output readpipe.token -sig readpipe.sig

writepipe.manifest: writepipe.manifest.template
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
        -e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
        -e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
        $< > $@

writepipe.manifest.sgx: writepipe.manifest writepipe
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
        -libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
        -key $(SGX_SIGNER_KEY) \
		-manifest $< -output $@ \
        -exec writepipe 
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token \
        -output writepipe.token -sig writepipe.sig

openpipe: openpipe.c
	@gcc $^ -o $@

testpipe:
	mknod $@ p

pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/pal_loader $@

clean:
	rm -rf *.o readpipe.manifest writepipe.manifest
	rm -rf readpipe.manifest.sgx writepipe.manifest.sgx pal_loader testpipe writepipe readpipe readpipe.sig readpipe.token writepipe.sig writepipe.token 

.PHONY: all clean
