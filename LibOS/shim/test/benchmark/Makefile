c_executables = $(patsubst %.c,%,$(wildcard *.c))
cxx_executables = $(patsubst %.cpp,%,$(wildcard *.cpp))

target = $(c_executables) $(cxx_executables) \
	  manifest

level = ../
include ../Makefile

%.manifest: %.manifest.template
	rm -rf $@
	cp $@.template $@

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)
$(c_executables): %: %.c
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $(if $(findstring .libos,$@),$(CFLAGS-libos),) -o $@ $< \
	$(shell echo $@ | sed 's/^[^\.]*//g' | sed 's/\./ -l/g')

$(cxx_executables): %: %.cpp
	@echo [ $@ ]
	@$(CC) $(CFLAGS) -o $@ $< \
	$(shell echo $@ | sed 's/^[^\.]*//g' | sed 's/\./ -l/g')
else
.IGNORE: $(c_executables) $(cxx_executables)
$(c_executables) $(cxx_executables):
endif
