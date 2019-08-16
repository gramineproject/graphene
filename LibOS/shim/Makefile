MAKEFLAGS += --check-symlink-times

SYS ?= $(shell gcc -dumpmachine)
export SYS

.PHONY: all
all:
	$(MAKE) -C src

.PHONY: test
test:
	$(MAKE) -C test

.PHONY: clean
clean:
	$(MAKE) -C src clean
	$(MAKE) -C test clean

.PHONY: format
format:
	clang-format -i $(shell find . -path ./test/apps -prune -o \( -name '*.h' -o -name '*.c' \) -print)
