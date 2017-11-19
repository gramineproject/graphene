CFLAGS-libos = -L../../../build/libos -I../../include

special_executables = bootstrap_static bootstrap_pie
c_executables = $(filter-out $(special_executables),$(patsubst %.c,%,$(wildcard *.c)))
cxx_executables = $(patsubst %.cpp,%,$(wildcard *.cpp))

exec_target = $(special_executables) $(c_executables) $(cxx_executables)
target = $(exec_target) manifest

clean-extra += clean-tmp

default: all
level = ../
include ../Makefile

ifeq ($(SYS),x86_64-linux-gnu)
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

.PHONY: pack
pack: $(special_executables) $(c_executables) $(cxx_executables)
	@../../../../Scripts/pack_binaries.sh test $^
else
$(special_executables) $(c_executables) $(cxx_executables): .packed/test.tar.gz
	tar -xmozf $< $@
endif

PYTHONENV="PYTHONPATH=../../../../Scripts"

ifeq ($(SGX_RUN),1)
	PYTHONENV += "TIMEOUT=5000"
endif

regression: $(target)
	@echo "\n\nBasic Bootstrapping:"
	@for f in $(wildcard 00_*.py); do env $(PYTHONENV) python $$f $(RUNTIME)/pal-$(PAL_HOST) || exit $?; done
	@echo "\n\nFutex Support:"
	@for f in $(wildcard 30_*.py); do env $(PYTHONENV) python $$f $(RUNTIME)/pal-$(PAL_HOST) || exit $?; done
	@echo "\n\nSocket Support:"
	@for f in $(wildcard 80_*.py); do env $(PYTHONENV) python $$f $(RUNTIME)/pal-$(PAL_HOST) || exit $?; done
	@echo "\n\nLarge File Support:"
	@for f in $(wildcard 90_*.py); do env $(PYTHONENV) python $$f $(RUNTIME)/pal-$(PAL_HOST) || exit $?; done

clean-tmp:
	rm -rf *.tmp ../apps/ltp/*.csv *.cached *.manifest.sgx *~ *.sig *.token
