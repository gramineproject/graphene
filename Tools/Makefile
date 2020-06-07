include ../Scripts/Makefile.configs
include ../Scripts/Makefile.rules

.PHONY: all
all: argv_serializer

.PHONY: test sgx-tokens
test sgx-tokens:

.PHONY: format
format:
	clang-format -i $(shell find . \( -name '*.h' -o -name '*.c' \) -print)

%: %.c
	$(call cmd,csingle)

.PHONY: clean
clean:
	$(RM) argv_serializer *.d

.PHONY: distclean
distclean: clean
