c_executables = $(patsubst %.c,%,$(wildcard *.c))
cxx_executables = $(patsubst %.cpp,%,$(wildcard *.cpp))
manifests = $(patsubst %.manifest.template,%.manifest,$(wildcard *.manifest.template)) manifest

exec_target = $(c_executables) $(cxx_executables)
target = $(exec_target) $(manifests)

clean-extra += clean-tmp

include ../../../../Makefile.configs
include ../../../../Makefile.rules
include ../../../../Makefile.manifest
include ../../../../Makefile.Test

CFLAGS-bootstrap_static = -static
CFLAGS-bootstrap_pie = -fPIC -pie
CFLAGS-shared_object = -fPIC -pie
CFLAGS-syscall += -I$(PALDIR)/../include -I$(PALDIR)/host/$(PAL_HOST)
CFLAGS-openmp = -fopenmp
CFLAGS-multi_pthread = -pthread

%: %.c
	$(call cmd,csingle)

%: %.cpp
	$(call cmd,cxxsingle)

export PAL_LOADER = $(RUNTIME)/pal-$(PAL_HOST)
export PYTHONPATH=../../../../Scripts

.PHONY: regression
regression: $(target)
	$(RM) libos-regression.xml
	$(MAKE) libos-regression.xml

libos-regression.xml:
	python3 -m pytest --junit-xml $@ -v test_libos.py

.PHONY: clean-tmp
clean-tmp:
	rm -rf *.tmp *.cached *.manifest.sgx *~ *.sig *.token .cache __pycache__ libos-regression.xml testfile tmp/*
