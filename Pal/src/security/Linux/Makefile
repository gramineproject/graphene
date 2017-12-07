CC	= gcc
LD	= ld

CFLAGS	= -Wall -fPIC -Os -std=gnu99 -fgnu89-inline -Wall -U_FORTIFY_SOURCE \
	  -fno-stack-protector -fno-builtin \
	  -DRUNTIME_DIR=$(RUNTIME_DIR) \
	  -I. -I../../host/Linux/include -I../.. -I../../../include\
	  -I../../host/Linux -I../../../lib \
	  -I../../../ipc/linux -I../../../security/linux
LDFLAGS	= -static -nostdlib -z combreloc -z defs --gc-sections \
	  --version-script pal-sec.map -T pal-sec.lds -z max-page-size=0x1000

objs	= bpf_helper filter main manifest printf
deps	= ../../host/Linux/sysdep-x86_64.h pal-sec.map pal-sec.lds
graphene_lib = ../../.lib/graphene-lib.a
pal_sec_lib = pal-sec

all: $(pal_sec_lib)

ifeq ($(DEBUG),1)
CC += -g
CFLAGS += -DDEBUG
endif

$(pal_sec_lib): $(addsuffix .o,$(objs)) $(graphene_lib) $(deps)
	@echo [ security/Linux/$@ ]
	$(LD) $(LDFLAGS) -o $@ $(filter-out %.h %.map %.lds,$^)

%.o: %.c
	@echo [ security/Linux/$@ ]
	@$(CC) $(CFLAGS) -c $< -o $@

%.e: %.c
	@echo [ security/Linux/$@ ]
	@$(CC) $(CFLAGS) -E $< -o $@

.PHONY: clean
clean:
	rm -rf *.o $(pal_sec_lib)
