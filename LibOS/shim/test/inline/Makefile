include ../../../../build-config.mk

c_executables = $(patsubst %.c,%,$(wildcard *.c))
cxx_executables = $(patsubst %.cpp,%,$(wildcard *.cpp))

exec_target = $(c_executables) $(cxx_executables)
target = $(c_executables) $(cxx_executables) manifest

.PHONY: default
default: all

include ../../../../Makefile.configs
include ../../../../Makefile.rules
include ../Makefile.Test

$(PALDIR)/user_start.o: $(PALDIR)/user_start.S
	$(MAKE) -C $(PALDIR) $(notdir $@)

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)
LDLIBS-c_executables = $(libs) $(PALDIR)/user_start.o
$(c_executables): CFLAGS += $(CFLAGS-libos-debug)
$(c_executables): LDLIBS += $(LDLIBS-c_executables) $(LDFLAGS-libos-debug)
$(c_executables): %: %.c $(LDLIBS-c_executables)
	$(call cmd,csingle)

LDLIBS-cxx_executables = $(libs) ../../../../Pal/src/user_start.o
$(cxx_executables): CXXFLAGS += $(CXXFLAGS-libos-debug)
$(cxx_executables): LDLIBS += $(LDLIBS-cxx_executables) $(LDFLAGS-libos-debug)
$(cxx_executables): %: %.cpp $(LDLIBS-cxx_executables)
	$(call cmd,cxxsingle)
else
.IGNORE: $(c_executables) $(cxx_executables)
$(c_executables) $(cxx_executables):
endif
