MAKEFLAGS += --check-symlink-times

SYS ?= $(shell gcc -dumpmachine)
export SYS

targets = all debug clean
ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)
targets += pack
endif

.PHONY: $(targets)
$(targets):
	make $@ -C src
	make $@ -C test
