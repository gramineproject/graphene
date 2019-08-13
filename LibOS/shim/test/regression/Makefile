c_executables = $(patsubst %.c,%,$(wildcard *.c))
cxx_executables = $(patsubst %.cpp,%,$(wildcard *.cpp))
manifests = $(patsubst %.manifest.template,%.manifest,$(wildcard *.manifest.template)) manifest

exec_target = $(c_executables) $(cxx_executables)
target = $(exec_target) $(manifests)

clean-extra += clean-tmp

.PHONY: default
default: all

level = ../
include ../../../../Makefile.configs
include ../../../../Makefile.rules
include ../Makefile

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)

CFLAGS-bootstrap_static = -static
CFLAGS-bootstrap_pie = -fPIC -pie
CFLAGS-shared_object = -fPIC -pie
CFLAGS-syscall += -I$(PALDIR)/../include -I$(PALDIR)/host/$(PAL_HOST)
CFLAGS-openmp = -fopenmp

$(c_executables): %: %.c
	$(call cmd,csingle)

$(cxx_executables): %: %.cpp
	$(call cmd,cxxsingle)

else
.IGNORE: $(c_executables) $(cxx_executables)
$(c_executables) $(cxx_executables):
endif

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
	rm -rf *.tmp ../apps/ltp/*.csv *.cached *.manifest.sgx *~ *.sig *.token
