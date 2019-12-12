c_executables = $(patsubst %.c,%,$(wildcard *.c))
cxx_executables = $(patsubst %.cpp,%,$(wildcard *.cpp))
manifests = $(patsubst %.template,%,$(wildcard *.manifest.template)) manifest

exec_target = $(c_executables) $(cxx_executables) ls.manifest
target = $(exec_target) $(manifests)

include ../Makefile.Test

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)

CFLAGS-msg_create.libos += $(CFLAGS-libos)
CFLAGS-msg_send.libos += $(CFLAGS-libos)
# CFLAGS-attestation += -I/opt/intel/sgxsdk/include -I../../../../Pal/lib/crypto/mbedtls/include  -I../../../../Pal/src/host/Linux-SGX
CFLAGS-attestation += -I../../../../Pal/lib/crypto/mbedtls/install/include -I../../../../Pal/src/host/Linux-SGX -I../../../../Pal/lib  -I../../../../Pal/src
LDLIBS-attestation += -L../../../../Pal/lib/crypto/mbedtls/install/lib -lmbedcrypto

LDLIBS-condvar.pthread += -lpthread
LDLIBS-futextest.pthread += -lpthread
LDLIBS-get_time.m += -lm
LDLIBS-helloworld.pthread += -lpthread
LDLIBS-msg_create.libos += -llibos
LDLIBS-msg_send.libos += -llibos
LDLIBS-sqrt.m += -lm
LDLIBS-start.pthread.m += -lpthread -lm
LDLIBS-sync.pthread += -lpthread
LDLIBS-test_start_pthread_m.m += -lm

$(c_executables): %: %.c
	$(call cmd,csingle)

$(cxx_executables): %: %.cpp
	$(call cmd,cxxsingle)

ifeq ($(filter clean,$(MAKECMDGOALS)),)
include $(wildcard *.d)
endif
else
.IGNORE: $(c_executables) $(cxx_executables)
$(c_executables) $(cxx_executables):
endif
