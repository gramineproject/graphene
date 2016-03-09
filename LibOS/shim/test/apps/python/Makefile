manifest = python$(if $(LOCAL),-local,).manifest

target = benchmarks
exec_target = $(manifest)
clean-extra = clean-local

level = ../../
include ../../Makefile

local:
	make LOCAL=1

PYTHON_SRC = Python-2.7.9
PYTHON_INSTALL = $(PYTHON_SRC)/build

$(PYTHON_INSTALL)/bin/python: $(PYTHON_SRC)/Makefile
	cd $(PYTHON_SRC) && $(MAKE)
	cd $(PYTHON_SRC) && $(MAKE) install

$(PYTHON_SRC)/Makefile: $(PYTHON_SRC)/configure
	cd $(PYTHON_SRC) && \
		./configure --prefix=$(shell readlink -f $(PYTHON_INSTALL))

$(PYTHON_SRC)/configure: $(PYTHON_SRC).tgz
	tar -xzf $<

test_targets =  testsamplebash

test: all $(test_targets)

python.manifest: python.manifest.template
	$(MAKE) -C .. python/$@ appdir=python/

python-local.manifest: python-local.manifest.template $(PYTHON_INSTALL)/bin/python
	$(MAKE) -C .. python/$@ appdir=python/ \
		extra_rules="-e 's:\\\$$\$$(PYTHONDIR):$(shell readlink -f $(PYTHON_INSTALL))/:g'"

benchmarks: benchmarks.tar.gz
	tar -xzf $<

BENCHMARK = all,-rietveld,-spitfire,-tornado_http

test-graphene: benchmarks
	cd benchmarks && ./perf.py -b $(BENCHMARK) --csv ../results.csv /usr/bin/python $(PWD)/python.manifest

distclean: clean
	rm -rf $(PYTHON_SRC) benchmarks

clean-local:
ifneq ($(LOCAL),1)
	make clean LOCAL=1
endif
