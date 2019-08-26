c_executables = $(patsubst %.c,%,$(wildcard *.c))
cxx_executables = $(patsubst %.cpp,%,$(wildcard *.cpp))

target = $(c_executables) $(cxx_executables) \
	  manifest

include ../../../../Makefile.configs
include ../../../../Makefile.rules
include ../Makefile.Test

%.manifest: %.manifest.template
	rm -rf $@
	cp $@.template $@

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)

CFLAGS-rpc_latency.libos += $(CFLAGS-libos)
CFLAGS-rpc_latency2.libos += $(CFLAGS-libos)

LDLIBS-rpc_latency.libos += -llibos
LDLIBS-rpc_latency2.libos += -llibos
LDLIBS-test_start.m += -lm

$(c_executables): %: %.c
	$(call cmd,csingle)

$(cxx_executables): %: %.cpp
	$(call cmd,cxxsingle)
else
.IGNORE: $(c_executables) $(cxx_executables)
$(c_executables) $(cxx_executables):
endif
