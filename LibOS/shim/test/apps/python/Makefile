PYTHON_SRC = Python-2.7.9
PYTHON_INSTALL = $(PYTHON_SRC)/build

manifests = python.manifest

target = benchmarks
exec_target = $(manifests)

extra_rules = -e 's:\$$(PYTHONDIR):$(PYTHON_INSTALL)/:g'

level = ../../
include ../../Makefile

$(PYTHON_INSTALL)/bin/python: $(PYTHON_SRC)/Makefile
	cd $(PYTHON_SRC) && $(MAKE)
	cd $(PYTHON_SRC) && $(MAKE) install

$(PYTHON_SRC)/Makefile: $(PYTHON_SRC)/configure
	cd $(PYTHON_SRC) && \
		./configure --prefix=$(shell readlink -f $(PYTHON_INSTALL))

$(PYTHON_SRC)/configure: $(PYTHON_SRC).tgz
	tar -xzf $<

benchmarks: benchmarks.tar.gz
	tar -xzf $<

BENCHMARK = all,-rietveld,-spitfire,-tornado_http

distclean: clean
	rm -rf $(PYTHON_SRC) benchmarks
