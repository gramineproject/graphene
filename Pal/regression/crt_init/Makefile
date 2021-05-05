# crt_init files (user_start.o and user_shared_start.o) are needed solely for PAL regression tests.
# We use the default GCC linker script when building these tests. This script expects an entrypoint
# symbol named `_start` that prepares the stack layout (argc, argv, env) and jumps into `main`. So
# we have a trivial `user_start.S` file that contains this symbol and logic, and link its *.o
# version into each PAL regression test. There is no other usage for this crt_init/ dir.

include ../../../Scripts/Makefile.configs
include ../../../Scripts/Makefile.rules

files_to_build += user_start.o user_shared_start.o

.PHONY: all test
all: $(files_to_build)
test:

user_start.o: arch/$(ARCH)/user_start.S
	$(call cmd,as_o_S)

ASFLAGS-user_shared_start.o = -DSHARED -fPIC
user_shared_start.o: arch/$(ARCH)/user_start.S
	$(call cmd,as_o_S)

include $(wildcard *.d)

.PHONY: clean
clean:
	$(RM) $(files_to_build) *.d

.PHONY: distclean
distclean: clean
