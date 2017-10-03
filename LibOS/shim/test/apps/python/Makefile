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
	tar -xzf $<

benchmarks: benchmarks.tar.gz
	tar -xzf $<

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

	@echo "\n\nRun a HTTP server in the background"
	python scripts/dummy-web-server.py 8000 & echo $$! > server.PID
	sleep 1
	@echo "\n\nRun test-http.py:"
	-./python.manifest scripts/test-http.py 127.0.0.1 8000 > OUTPUT1
	-wget -q http://127.0.0.1:8000/ -O OUTPUT2
	diff -q OUTPUT1 OUTPUT2
	@kill `cat server.PID`
	@rm -f OUTPUT1 OUTPUT2 server.PID


BENCHMARK = all,-rietveld,-spitfire,-tornado_http

clean-tmp:
	rm -f python.manifest.sgx

distclean: clean
	rm -rf $(PYTHON_SRC) benchmarks
