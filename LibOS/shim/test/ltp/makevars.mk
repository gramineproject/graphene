# Everything here must be absolute because other Makefiles assume this.
ROOTDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SRCDIR = $(ROOTDIR)/src
BUILDDIR = $(ROOTDIR)/build
INSTALLDIR = $(ROOTDIR)/install
LTPROOT = install
RUNLTPOPTS =
ifeq ($(SGX),1)
	BUILDDIR:=$(BUILDDIR)-sgx
	INSTALLDIR:=$(INSTALLDIR)-sgx
	LTPROOT = install-sgx
endif
TESTCASEDIR = $(INSTALLDIR)/testcases/bin
LTPSCENARIO = $(INSTALLDIR)/runtest/syscalls
