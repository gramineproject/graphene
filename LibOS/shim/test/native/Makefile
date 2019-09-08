c_executables = $(patsubst %.c,%,$(wildcard *.c))
cxx_executables = $(patsubst %.cpp,%,$(wildcard *.cpp))
manifests = $(patsubst %.template,%,$(wildcard *.manifest.template)) manifest

exec_target = $(c_executables) $(cxx_executables) ls.manifest
target = $(exec_target) $(manifests)

include ../../../../Makefile.configs
include ../../../../Makefile.rules
include ../../../../Makefile.manifest
include ../../../../Makefile.Test

CFLAGS-msg_create_libos += $(CFLAGS-libos)
CFLAGS-msg_send_libos += $(CFLAGS-libos)

LDLIBS-condvar += -lpthread
LDLIBS-futextest += -lpthread
LDLIBS-get_time += -lm
LDLIBS-helloworld_pthread += -lpthread
LDLIBS-msg_create_libos += -llibos
LDLIBS-msg_send_libos += -llibos
LDLIBS-sqrt += -lm
LDLIBS-start += -lpthread -lm
LDLIBS-sync += -lpthread
LDLIBS-test_start_pthread_m += -lm

%: %.c
	$(call cmd,csingle)

%: %.cpp
	$(call cmd,cxxsingle)

include $(wildcard *.d)
