bash_src = bash-4.1

manifests = bash.manifest bash-local.manifest

all debug: $(manifests)

test_targets =  testsamplebash

bash-local: $(bash_src)/bash
	cp $< bash-local

$(bash_src): $(bash_src).tar.gz
	tar -xzf $<

$(bash_src)/bash: $(bash_src)
	cd $(bash_src) && ./configure --without-gnu-malloc
	cd $(bash_src) && make CC="gcc -g"

test: all $(test_targets)

testsamplebash:
	bash bash_test.sh

%.manifest: %.manifest.template
	make -C .. bash/$@ appdir=bash/

clean: clean-manifests

distclean: clean-manifests
	rm -rf $(bash_src)
	rm -rf bash result $(test_targets)

clean-manifests:
	rm -rf $(manifests)
