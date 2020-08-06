c_executables = \
	fork_latency \
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

LDLIBS-test_start += -lm

%: %.c
	$(call cmd,csingle)

%: %.cpp
	$(call cmd,cxxsingle)
