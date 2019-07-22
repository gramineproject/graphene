MAKEFLAGS += --check-symlink-times

SYS ?= $(shell gcc -dumpmachine)
export SYS

targets = all debug clean

.PHONY: $(targets)
$(targets):
	make $@ -C example

.PHONY: format
format:
	clang-format -style=file -verbose -i $(shell find -name '*.[ch]')
