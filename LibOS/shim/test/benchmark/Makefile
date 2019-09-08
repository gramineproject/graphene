c_executables = $(patsubst %.c,%,$(wildcard *.c))
cxx_executables = $(patsubst %.cpp,%,$(wildcard *.cpp))

exec_target = $(c_executables) $(cxx_executables)
target = $(exec_target) manifest

include ../../../../Makefile.configs
include ../../../../Makefile.rules
include ../../../../Makefile.manifest
include ../../../../Makefile.Test

CFLAGS-rpc_latency += $(CFLAGS-libos)
CFLAGS-rpc_latency2 += $(CFLAGS-libos)

LDLIBS-rpc_latency += -llibos
LDLIBS-rpc_latency2 += -llibos
LDLIBS-test_start += -lm

%: %.c
	$(call cmd,csingle)

%: %.cpp
	$(call cmd,cxxsingle)
