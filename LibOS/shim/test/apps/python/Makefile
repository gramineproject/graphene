manifests = python.manifest

all debug: $(manifests)

test_targets =  testsamplebash

test: all $(test_targets)

%.manifest: %.manifest.template
	make -C .. python/$@ appdir=python/

clean: clean-manifests
distclean: clean-manifests

clean-manifests:
	rm -rf $(manifests)
