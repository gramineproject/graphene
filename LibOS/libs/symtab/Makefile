export RUNTIME_DIR = $(CURDIR)/../../../Runtime

include ../../../Pal/src/Makefile.Host

CC	= gcc
AS	= gcc
AR	= ar rcs
LD	= ld

# We link to this to access useful utility functions
graphene_lib = ../../../Pal/lib/graphene-lib.a
pal_lib = $(RUNTIME_DIR)/libpal-$(PAL_HOST).so

OMIT_FRAME_POINTER = no

CFLAGS	= -Wall -fPIC -std=gnu99 -fgnu89-inline -Winline -Wwrite-strings \
	  -fmerge-all-constants -Wstrict-prototypes \
	  -Werror=implicit-function-declaration \
	  -fno-stack-protector -fno-builtin -Wno-inline \
	  -I../include -I../../../Pal/include -I../../../Pal/lib

EXTRAFLAGS = -Wextra -Wno-unused-parameter -Wno-sign-compare -Os

CFLAGS += $(EXTRAFLAGS)

ifeq ($(OMIT_FRAME_POINTER),yes)
CFLAGS += -DOMIT_FRAME_POINTER=1
else
CFLAGS += -fno-omit-frame-pointer -DOMIT_FRAME_POINTER=0
endif
ASFLAGS	= -Wa,--noexecstack -x assembler-with-cpp -I../include

LDFLAGS	= -shared -nostdlib -z combreloc -z relro -z defs \
		  -L$(abspath $(RUNTIME_DIR)) \
		  --entry=__entry -init __init -fini __fini -z now
ARFLAGS	=

ifeq ($(WERROR),1)
CFLAGS += -Werror
endif

files_to_build = libsymtab.so
files_to_install = $(addprefix $(RUNTIME_DIR)/,$(files_to_build))

defs	=
objs	= entry lib
headers = ../include/*.h

all: $(files_to_build) $(files_to_install)

ifeq ($(DEBUG),1)
CC += -gdwarf-2 -g3
CFLAGS += -DDEBUG
ASFLAGS += -DDEBUG
endif
export DEBUG

$(files_to_install): $(RUNTIME_DIR)/%: %
	cp -f $< $@

.PHONY:	$(graphene_lib)
$(graphene_lib):
	$(MAKE) -C ../../../Pal/lib

libsymtab.so: $(addsuffix .o,$(objs)) $(graphene_lib) $(pal_lib)
	@echo [ $@ ]
	$(LD) $(LDFLAGS) \
		-o $@ $(filter-out %.map %.lds,$^) -soname $@ \
		-rpath-link=$(abspath $(RUNTIME_DIR)) \
		$(graphene_lib) $(pal_lib)

%.asm: %.c $(headers)
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $(defs) -c $< -o $<.o
	@objdump -S $<.o > $@
	@rm $<.o

%.o: %.c $(headers)
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $(defs) -c $< -o $@

%.e %.i: %.c $(headers)
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $(defs) -E $< -o $@

%.s: %.c $(headers)
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $(defs) -S $< -o $@

%.o: %.S $(headers)
	@echo [ $@ ]
	@$(AS) $(ASFLAGS) $(defs) -c $< -o $@

%.e %.s: %.S $(headers)
	@echo [ $@ ]
	@$(AS) $(ASFLAGS) $(defs) -E $< -o $@

# include ../../../Makefile.rules

clean:
	rm -rf $(addsuffix .o,$(objs)) $(files_to_build) $(CLEAN_FILES)
