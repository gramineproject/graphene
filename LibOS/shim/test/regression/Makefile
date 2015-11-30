CFLAGS-libos = -L../../../build/libos -I../../include

special_executables = bootstrap_static bootstrap_pie
c_executables = $(filter-out $(special_executables),$(patsubst %.c,%,$(wildcard *.c)))
cxx_executables = $(patsubst %.cpp,%,$(wildcard *.cpp))

target = $(special_executables) $(c_executables) $(cxx_executables) \
	  manifest pal pal_sec

clean-extra += clean-tmp

level = ../
include ../Makefile

%.manifest: %.manifest.template
	rm -rf $@
	cp $@.template $@

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

regression: $(target)
	@echo "\n\nBasic Bootstrapping:"
	@for f in $(wildcard 00_*.py); do env $(PYTHONENV) python $$f; done
	@echo "\n\n"

clean-tmp:
	rm -rf *.tmp
