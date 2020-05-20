include ../../Scripts/Makefile.configs
include ../../Scripts/Makefile.rules

files_to_build += user_start.o user_shared_start.o

.PHONY: all test
all: $(files_to_build)
test:

user_start.o: user_start-$(ARCH).S
	$(call cmd,as_o_S)

ASFLAGS-user_shared_start.o = -DSHARED -fPIC
user_shared_start.o: user_start-$(ARCH).S
	$(call cmd,as_o_S)

include $(wildcard *.d)

.PHONY: clean
clean:
	$(RM) $(files_to_build) *.d

.PHONY: distclean
distclean: clean
