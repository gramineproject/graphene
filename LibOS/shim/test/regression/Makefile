special_executables = bootstrap_static bootstrap_pie shared_object
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

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)
$(c_executables): %: %.c
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $(if $(findstring .libos,$@),$(CFLAGS-libos),) -o $@ $< \
	$(shell echo $@ | sed 's/^[^\.]*//g' | sed 's/\./ -l/g')

$(cxx_executables): %: %.cpp
	@echo [ $@ ]
	@$(CC) $(CFLAGS) -o $@ $< \
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
else
.IGNORE: $(special_executables) $(c_executables) $(cxx_executables)
$(special_executables) $(c_executables) $(cxx_executables):
endif

PYTHONENV="PYTHONPATH=../../../../Scripts"

ifeq ($(SGX_RUN),1)
	PYTHONENV += "TIMEOUT=5000"
endif

.PHONY: regression
regression: $(target)
	@echo "\n\nBasic Bootstrapping:"
	@for f in $(wildcard 00_*.py); do env $(PYTHONENV) python $$f $(RUNTIME)/pal-$(PAL_HOST) || exit $$?; done
	@echo "\n\nSyscall Support:"
	@for f in $(wildcard 30_*.py); do env $(PYTHONENV) python $$f $(RUNTIME)/pal-$(PAL_HOST) || exit $$?; done
	@echo "\n\nSocket Support:"
	@for f in $(wildcard 80_*.py); do env $(PYTHONENV) python $$f $(RUNTIME)/pal-$(PAL_HOST) || exit $$?; done
	@echo "\n\nLarge File Support:"
	@for f in $(wildcard 90_*.py); do env $(PYTHONENV) python $$f $(RUNTIME)/pal-$(PAL_HOST) || exit $$?; done

.PHONY: clean-tmp
clean-tmp:
	rm -rf *.tmp ../apps/ltp/*.csv *.cached *.manifest.sgx *~ *.sig *.token
