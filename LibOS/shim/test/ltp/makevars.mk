ROOTDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SRCDIR = $(ROOTDIR)/src
BUILDDIR = $(ROOTDIR)/opt/ltp
TESTCASEDIR = $(BUILDDIR)/testcases/bin
LTPSCENARIO = $(BUILDDIR)/runtest/syscalls
RUNLTPOPTS = -c ltp-bug-1248.cfg
