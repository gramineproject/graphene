c_executables = \
	fork \
	helloworld \
	vfork

cxx_executables =

exec_target = \
	$(c_executables) \
	$(cxx_executables)

target = \
	$(c_executables) \
	$(cxx_executables) \
	manifest

include ../../../../Scripts/Makefile.configs
include ../../../../Scripts/Makefile.manifest
include ../../../../Scripts/Makefile.Test

.PHONY: crt_init-recurse
crt_init-recurse:
	$(MAKE) -C ../crt_init all

../crt_init/user_shared_start.o ../crt_init/user_start.o: crt_init-recurse
	@true

LDLIBS-user_start = $(PALDIR)/../crt_init/user_start.o
.PHONY: crt_init-recurse
crt_init-recurse:
	$(MAKE) -C $(PALDIR)/../crt_init/ all
$(PALDIR)/../crt_init/user_start.o: crt_init-recurse
	@true

CFLAGS += $(CFLAGS-libos-debug)
CXXFLAGS += $(CXXFLAGS-libos-debug)
LDLIBS += $(LDLIBS-user_start) $(LDFLAGS-libos-debug)

$(c_executables): %: %.c $(LDLIBS-user_start)
	$(call cmd,csingle)

$(cxx_executables): %: %.cpp $(LDLIBS-user_start)
	$(call cmd,cxxsingle)
