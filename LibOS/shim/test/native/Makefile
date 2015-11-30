CFLAGS-libos = -L../../../build/libos -I../../include

special_executables = static pie
c_executables = $(filter-out $(special_executables),$(patsubst %.c,%,$(wildcard *.c)))
cxx_executables = $(patsubst %.cpp,%,$(wildcard *.cpp))

target = $(special_executables) $(c_executables) $(cxx_executables) \
	  manifest static.manifest pal pal_sec

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

static: %: %.c
	@echo [ $@ ]
	@$(CC) $(CFLAGS) -o $@ -static $< \
	$(shell echo $@ | sed 's/^[^\.]*//g' | sed 's/\./ -l/g')

pie: %: %.c
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
