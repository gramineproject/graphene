PYTHON_SRC = Python-2.7.9
PYTHON_INSTALL = $(PYTHON_SRC)/build

manifests = python.manifest

target = benchmarks
exec_target = $(manifests)

extra_rules = -e 's:\$$(PYTHONDIR):$(PYTHON_INSTALL)/:g'
clean-extra += clean-tmp

level = ../../
include ../../Makefile

$(PYTHON_INSTALL)/bin/python: $(PYTHON_SRC)/Makefile
	cd $(PYTHON_SRC) && $(MAKE)
	cd $(PYTHON_SRC) && $(MAKE) install

$(PYTHON_SRC)/Makefile: $(PYTHON_SRC)/configure
	cd $(PYTHON_SRC) && \
		./configure --prefix=$(shell readlink -f $(PYTHON_INSTALL))

$(PYTHON_SRC)/configure: $(PYTHON_SRC).tgz
	tar -xmzf $<

benchmarks: benchmarks.tar.gz
	tar -xmzf $<

regression: 
	@echo "\n\nBuilding Python..."
	@$(MAKE) >> /dev/null 2>&1

	@echo "\n\nRun helloworld.py:"
	-./python.manifest scripts/helloworld.py > OUTPUT
	-grep -q "Hello World" OUTPUT
	@rm OUTPUT

	@echo "\n\nRun fibonacci.py:"
	-./python.manifest scripts/fibonacci.py  > OUTPUT
	-grep -q "fib2              55" OUTPUT
	@rm -f OUTPUT

	./web-test.sh


BENCHMARK = all,-rietveld,-spitfire,-tornado_http

clean-tmp:
	rm -f python.manifest.sgx

distclean: clean
	rm -rf $(PYTHON_SRC) benchmarks
