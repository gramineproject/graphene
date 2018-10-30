CC	= gcc
LD	= ld

CFLAGS	= -Wall -fPIC -O2 -std=gnu99 -fgnu89-inline -Wall -U_FORTIFY_SOURCE \
	  -fno-stack-protector -fno-builtin \
	  -DPAL_LOADER_PATH="$(abspath ../../libpal.so)" \
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

libpal_sec.so: $(addsuffix .o,$(objs)) $(graphene_lib)
	@echo [ security/Linux/$@ ]
	@$(LD) $(LDFLAGS) -o $@ $^ -soname=libpal_sec.so

%.o: %.c
	@echo [ security/Linux/$@ ]
	@$(CC) $(CFLAGS) -c $< -o $@

%.e: %.c
	@echo [ security/Linux/$@ ]
	@$(CC) $(CFLAGS) -E $< -o $@

.PHONY: clean
clean:
	rm -rf *.o libpal_sec.so
