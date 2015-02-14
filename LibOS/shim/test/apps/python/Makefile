manifests = python.manifest python-local.manifest

all debug: $(manifests)

PYTHON_SRC = Python-2.7.9
PYTHON_INSTALL = $(PYTHON_SRC)/build
local: python-local

python-local: $(PYTHON_INSTALL)/bin/python
	cp -f $< $@

$(PYTHON_INSTALL)/bin/python: $(PYTHON_SRC)/Makefile
	cd $(PYTHON_SRC) && make
	cd $(PYTHON_SRC) && make install

$(PYTHON_SRC)/Makefile: $(PYTHON_SRC)/configure
	cd $(PYTHON_SRC) && \
		./configure --prefix=$(shell readlink -f $(PYTHON_INSTALL))

$(PYTHON_SRC)/configure: $(PYTHON_SRC).tgz
	tar -xzf $<

test_targets =  testsamplebash

test: all $(test_targets)

python.manifest: python.manifest.template
	make -C .. python/$@ appdir=python/

python-local.manifest: python-local.manifest.template
	make -C .. python/$@ appdir=python/ \
		extra_rules="-e 's:\\\$$\$$(PYTHONDIR):$(shell readlink -f $(PYTHON_INSTALL)):g'"

distclean: clean
	rm -rf $(PYTHON_SRC) python-local

clean: clean-manifests

clean-manifests:
	rm -rf $(manifests)
