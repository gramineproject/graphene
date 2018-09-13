MAKEFLAGS += --check-symlink-times

SYS ?= $(shell gcc -dumpmachine)
export SYS

targets = all debug clean
ifeq ($(findstring linux,$(SYS)),linux)
targets += pack
endif

.PHONY: $(targets)
$(targets): src test
	make $@ -C src
	make $@ -C test
