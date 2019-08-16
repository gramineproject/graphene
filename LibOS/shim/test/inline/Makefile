c_executables = $(patsubst %.c,%,$(wildcard *.c))
cxx_executables = $(patsubst %.cpp,%,$(wildcard *.cpp))

exec_target = $(c_executables) $(cxx_executables)
target = $(c_executables) $(cxx_executables) manifest

.PHONY: default
default: all

level = ../
include ../../../../Makefile.configs
include ../../../../Makefile.rules
include ../Makefile

CFLAGS-debug += -fno-builtin -nostdlib

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)
LDLIBS-c_executables = $(libs) $(level)../../../Pal/src/user_start.o
$(c_executables): CFLAGS += $(CFLAGS-debug)
$(c_executables): LDLIBS += $(LDFLAGS-debug) $(LDLIBS-c_executables) -lpal -lsysdb_debug
%: %.c $(LDLIBS-c_executables)
	$(call cmd,csingle)

LDLIBS-cxx_executables = $(libs) $(level)../../../Pal/src/user_start.o
$(cxx_executables): CXXFLAGS += $(CFLAGS-debug)
$(cxx_executables): LDLIBS += $(LDFLAGS-debug) $(LDLIBS-cxx_executables) -lpal -lsysdb_debug
%: %.cpp $(LDLIBS-cxx_executables)
	$(call cmd,cxxsingle)
else
.IGNORE: $(c_executables) $(cxx_executables)
$(c_executables) $(cxx_executables):
endif
