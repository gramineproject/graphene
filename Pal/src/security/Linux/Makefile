CC	= gcc
LD	= ld

CFLAGS	= -Wall -fPIC -O2 -std=c11 -Wall -U_FORTIFY_SOURCE \
	  -fno-stack-protector -fno-builtin \
	  -DRUNTIME_DIR=$(abspath $(RUNTIME_DIR)) \
	  -I. -I../../host/Linux/include -I../.. -I../../../include -I../../host/Linux \
	  -I../../../lib -I../../../linux-kernel/graphene
LDFLAGS	= -shared -nostdlib -z combreloc -z defs --version-script pal-sec.map -e start

objs	= bpf_helper filter main manifest printf
graphene_lib = ../../host/Linux/.lib/graphene-lib.a

.PHONY: all
all: libpal_sec.so

ifeq ($(DEBUG),1)
CC += -g
CFLAGS += -DDEBUG
endif

include ../../../../Makefile.rules

libpal_sec.so: $(addsuffix .o,$(objs)) $(graphene_lib)
	$(call cmd,ld_so_o)

%.o: %.c
	$(call cmd,cc_o_c)

%.e %.i: %.c
	$(call cmd,cpp_i_o)

%.s: %.c
	$(call cmd,cc_s_c)

.PHONY: clean
clean:
	rm -rf *.o libpal_sec.so
