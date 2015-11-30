c_executables = $(patsubst %.c,%,$(wildcard *.c))
cxx_executables = $(patsubst %.cpp,%,$(wildcard *.cpp))

target = $(c_executables) $(cxx_executables) manifest pal pal_sec

level = ../
include ../Makefile

CFLAGS-debug += -fno-builtin -nostdlib

ifeq ($(SYS),x86_64-linux-gnu)
$(c_executables): %: %.c $(libs) $(level)../../../Pal/src/user_start.o
	@echo [ $@ ]
	@$(CC) $(CFLAGS-debug) $(LDFLAGS-debug) -o $@ $^

$(cxx_executables): %: %.cpp $(libs) $(level)../../../Pal/src/user_start.o
	@echo [ $@ ]
	@$(CXX) $(CFLAGS-debug) $(LDFLAGS-debug) -o $@ $^

.PHONY: pack
pack: $(c_executables) $(cxx_executables)
	@../../../../Scripts/pack_binaries.sh test $^
else
$(c_executables) $(cxx_executables): .packed/test.tar.gz
	tar -xmozf $< $@
endif
