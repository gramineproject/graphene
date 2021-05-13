include ../Scripts/Makefile.configs
include ../Scripts/Makefile.rules

.PHONY: all
all: argv_serializer

.PHONY: test sgx-tokens
test sgx-tokens:

%: %.c
	$(call cmd,csingle)

.PHONY: clean
clean:
	$(RM) argv_serializer *.d

.PHONY: distclean
distclean: clean
