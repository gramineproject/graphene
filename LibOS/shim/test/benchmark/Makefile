c_executables = \
	fork_latency \
	rpc_latency \
	rpc_latency2 \
	sig_latency \
	start \
	test_start

cxx_executables =

exec_target = \
	$(c_executables) \
	$(cxx_executables)

target = \
	$(exec_target) \
	manifest

include ../../../../Scripts/Makefile.configs
include ../../../../Scripts/Makefile.manifest
include ../../../../Scripts/Makefile.Test

CFLAGS-rpc_latency += $(CFLAGS-libos)
CFLAGS-rpc_latency2 += $(CFLAGS-libos)

LDLIBS-rpc_latency += -llibos
LDLIBS-rpc_latency2 += -llibos
LDLIBS-test_start += -lm

%: %.c
	$(call cmd,csingle)

%: %.cpp
	$(call cmd,cxxsingle)
