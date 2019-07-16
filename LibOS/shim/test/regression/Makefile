special_executables = bootstrap_static bootstrap_pie shared_object openmp
c_executables = $(filter-out $(special_executables),$(patsubst %.c,%,$(wildcard *.c)))
cxx_executables = $(patsubst %.cpp,%,$(wildcard *.cpp))
manifests = $(patsubst %.manifest.template,%.manifest,$(wildcard *.manifest.template)) manifest

exec_target = $(special_executables) $(c_executables) $(cxx_executables)
target = $(exec_target) $(manifests)

clean-extra += clean-tmp

.PHONY: default
default: all

level = ../
include ../Makefile

CFLAGS-libos = -L../../../build/libos -I../../include

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)
$(c_executables): %: %.c
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $(if $(findstring .libos,$@),$(CFLAGS-libos),) -o $@ $< \
	$(shell echo $@ | sed 's/^[^\.]*//g' | sed 's/\./ -l/g')

$(cxx_executables): %: %.cpp
	@echo [ $@ ]
	@$(CXX) $(CXXFLAGS) -o $@ $< \
	$(shell echo $@ | sed 's/^[^\.]*//g' | sed 's/\./ -l/g')

bootstrap_static: %: %.c
	@echo [ $@ ]
	@$(CC) $(CFLAGS) -o $@ -static $< \
	$(shell echo $@ | sed 's/^[^\.]*//g' | sed 's/\./ -l/g')

bootstrap_pie: %: %.c
	@echo [ $@ ]
	@$(CC) $(CFLAGS) -fPIC --pie -o $@ $< \
	$(shell echo $@ | sed 's/^[^\.]*//g' | sed 's/\./ -l/g')

shared_object: %: %.c
	@echo [ $@ ]
	@$(CC) $(CFLAGS) -o $@ -fPIC -pie $< \
	$(shell echo $@ | sed 's/^[^\.]*//g' | sed 's/\./ -l/g')

syscall: CFLAGS += -I$(PALDIR)/../include -I$(PALDIR)/host/$(PAL_HOST)

openmp: %: %.c
	@echo [ $@ ]
	@$(CC) $(CFLAGS) -o $@ -fopenmp $< \
	$(shell echo $@ | sed 's/^[^\.]*//g' | sed 's/\./ -l/g')

else
.IGNORE: $(special_executables) $(c_executables) $(cxx_executables)
$(special_executables) $(c_executables) $(cxx_executables):
endif

export PAL_LOADER = $(RUNTIME)/pal-$(PAL_HOST)
export PAL_SEC = $(RUNTIME)/pal_sec-$(PAL_HOST)
export PYTHONPATH=../../../../Scripts

.PHONY: regression
regression: $(target)
	$(RM) libos-regression.xml
	$(MAKE) libos-regression.xml

libos-regression.xml:
	python3 -m pytest --junit-xml $@ -v test.py

.PHONY: clean-tmp
clean-tmp:
	rm -rf *.tmp ../apps/ltp/*.csv *.cached *.manifest.sgx *~ *.sig *.token
