MAKEFLAGS += --check-symlink-times

SYS ?= $(shell gcc -dumpmachine)
export SYS

.PHONY: all
all:
	make -C src

.PHONY: test
test:
	make -C test

.PHONY: clean
clean:
	make -C src clean
	make -C test clean

.PHONY: format
format:
	clang-format -i $(shell find . -path ./test/apps -prune -o \( -name '*.h' -o -name '*.c' \) -print)
