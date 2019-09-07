c_executables = $(patsubst %.c,%,$(wildcard *.c))
cxx_executables = $(patsubst %.cpp,%,$(wildcard *.cpp))

exec_target = $(c_executables) $(cxx_executables)
target = $(c_executables) $(cxx_executables) manifest

.PHONY: default
default: all

include ../../../../Makefile.configs
include ../../../../Makefile.rules
include ../../../../Makefile.manifest
include ../../../../Makefile.Test

LDLIBS-user_start = $(PALDIR)/../csu/user_start.o
$(PALDIR)/../csu/user_start.o: $(PALDIR)/../csu/user_start.S
	$(MAKE) -C $(dir $@) $(notdir $@)

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)

CFLAGS += $(CFLAGS-libos-debug)
CXXFLAGS += $(CXXFLAGS-libos-debug)
LDLIBS += $(LDLIBS-user_start) $(LDFLAGS-libos-debug)

$(c_executables): %: %.c $(LDLIBS-user_start)
	$(call cmd,csingle)

$(cxx_executables): %: %.cpp $(LDLIBS-user_start)
	$(call cmd,cxxsingle)
else
.IGNORE: $(c_executables) $(cxx_executables)
$(c_executables) $(cxx_executables):
endif
