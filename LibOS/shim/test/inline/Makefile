c_executables = $(patsubst %.c,%,$(wildcard *.c))
cxx_executables = $(patsubst %.cpp,%,$(wildcard *.cpp))

target = $(c_executables) $(cxx_executables) manifest

level = ../
include ../Makefile

CFLAGS-debug += -fno-builtin -nostdlib

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)
$(c_executables): %: %.c $(libs) $(level)../../../Pal/src/user_start.o
	@echo [ $@ ]
	$(CC) $(CFLAGS-debug) $(LDFLAGS-debug) -o $@ $^ -lpal -lsysdb_debug


$(cxx_executables): %: %.cpp $(libs) $(level)../../../Pal/src/user_start.o
	@echo [ $@ ]
	$(CXX) $(CFLAGS-debug) $(LDFLAGS-debug) -o $@ $^ -lpal -lsysdb_debug
else
.IGNORE: $(c_executables) $(cxx_executables)
$(c_executables) $(cxx_executables):
endif
