include ../../Scripts/Makefile.configs
include ../../Scripts/Makefile.rules

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)
files_to_build += user_start.o user_shared_start.o
endif

.PHONY: all test
all: $(files_to_build)
test:

user_start.o: user_start.S
	$(call cmd,as_o_S)

ASFLAGS-user_shared_start.o = -DSHARED -fPIC
user_shared_start.o: user_start.S
	$(call cmd,as_o_S)

include $(wildcard *.d)

.PHONY: clean
clean:
	$(RM) $(files_to_build) *.d

.PHONY: distclean
distclean: clean
