CFLAGS-libos = -L../../../build/libos -I../../include

c_executables = $(patsubst %.c,%,$(wildcard *.c))
cxx_executables = $(patsubst %.cpp,%,$(wildcard *.cpp))

target = $(c_executables) $(cxx_executables) \
	  manifest pal pal_sec

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

.PHONY: pack
pack: $(c_executables) $(cxx_executables)
	tar -czf .packed/test.tar.gz $^
else
$(c_executables) $(cxx_executables): .packed/test.tar.gz
	tar -xmozf $<
endif
