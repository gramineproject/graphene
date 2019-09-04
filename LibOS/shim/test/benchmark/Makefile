c_executables = $(patsubst %.c,%,$(wildcard *.c))
cxx_executables = $(patsubst %.cpp,%,$(wildcard *.cpp))

exec_target = $(c_executables) $(cxx_executables)
target = $(exec_target) manifest

include ../Makefile.Test

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)

CFLAGS-rpc_latency += $(CFLAGS-libos)
CFLAGS-rpc_latency2 += $(CFLAGS-libos)

LDLIBS-rpc_latency += -llibos
LDLIBS-rpc_latency2 += -llibos
LDLIBS-test_start += -lm

%: %.c
	$(call cmd,csingle)

%: %.cpp
	$(call cmd,cxxsingle)
else
.IGNORE: $(c_executables) $(cxx_executables)
$(c_executables) $(cxx_executables):
endif
