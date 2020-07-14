# -------------------------------------------------------------------
#  Function : parent-dir
#  Arguments: 1: path
#  Returns  : Parent dir or path of $1, with final separator removed.
# -------------------------------------------------------------------
parent-dir = $(patsubst %/,%,$(dir $(1:%/=%)))

# ------------------------------------------------------------------
#  Macro    : my-dir
#  Returns  : the directory of the current Makefile
#  Usage    : $(my-dir)
# ------------------------------------------------------------------
my-dir = $(realpath $(call parent-dir,$(lastword $(MAKEFILE_LIST))))

ROOT_DIR := $(call my-dir)
ifneq ($(words $(subst :, ,$(ROOT_DIR))), 1)
  $(error main directory cannot contain spaces nor colons)
endif

#-------------------------------------------------------------------
# This is the output folder.
#-------------------------------------------------------------------
BIN_DIR := bin
TOPDIR = $(ROOT_DIR)
OUTDIR := $(BIN_DIR)
LIBDIR := lib


CP = cp
CC ?= gcc
CXX ?= g++

# turn on cet
CC_GREAT_EQUAL_8 := $(shell expr "`$(CC) -dumpversion`" \>= "8")
ifeq ($(CC_GREAT_EQUAL_8), 1)
    COMMON_FLAGS += -fcf-protection
endif

# ------------------------------------------------------------------
#  Define common variables
# ------------------------------------------------------------------
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 0

#-------------------------------------------------------------------
# Define common compile flags used for GCC and G++ 
#-------------------------------------------------------------------
COMMON_FLAGS = -ffunction-sections -fdata-sections

COMMON_FLAGS += -Wall -Wextra -Wchar-subscripts -Wno-coverage-mismatch -Winit-self \
		-Wpointer-arith -Wreturn-type -Waddress -Wsequence-point -Wformat-security \
		-Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
		-Wcast-align -Wconversion -Wredundant-decls -fPIC

ifeq ($(SGX_DEBUG), 1)
	COMMON_FLAGS += -ggdb -DDEBUG 
	COMMON_FLAGS += -DSE_DEBUG_LEVEL=SE_TRACE_DEBUG
else
	COMMON_FLAGS += -o2 -UDEBUG
endif

CFLAGS = $(COMMON_FLAGS)
CXXFLAGS = $(COMMON_FLAGS) 

# additional warnings flags for C
CFLAGS += -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants

# additional warnings flags for C++
CXXFLAGS += -Wnon-virtual-dtor -std=c++11 

# ----------------------------------------------------------------
#  Define common link options
# ----------------------------------------------------------------
COMMON_LDFLAGS := -Wl,-z,relro,-z,now,-z,noexecstack

# Compiler and linker options for an Enclave
#
# We are using '--export-dynamic' so that `g_global_data_sim' etc.
# will be exported to dynamic symbol table.
#
# When `pie' is enabled, the linker (both BFD and Gold) under Ubuntu 14.04
# will hide all symbols from dynamic symbol table even if they are marked
# as `global' in the LD version script.
ENCLAVE_CFLAGS   = -ffreestanding -nostdinc -fvisibility=hidden -fpie
ifeq ($(CC_GREAT_EQUAL_8), 1)
    ENCLAVE_CFLAGS += -fcf-protection
endif

RM = rm -f

ifeq ($(shell getconf LONG_BIT), 32)
        SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
        SGX_ARCH := x86
endif

# Relative path to Graphene root
GRAPHENEDIR = $(TOPDIR)/../../
SGX_SIGNER_KEY ?= $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENEDEBUG = inline
else
GRAPHENEDEBUG = none
endif

include $(TOPDIR)/../../Scripts/Makefile.configs
