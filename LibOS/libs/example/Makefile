export RUNTIME_DIR = $(CURDIR)/../../../Runtime

include ../../../Pal/src/Makefile.Host
include ../../../Makefile.rules
include ../../../Makefile.configs

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

LDFLAGS	= -shared -nostdlib -z combreloc -z relro -z defs -z now \
		  -L$(abspath $(RUNTIME_DIR)) \
		  --entry=__entry -init __dt_init
ARFLAGS	=

ifeq ($(WERROR),1)
CFLAGS += -Werror
endif

files_to_build = libexample.so
files_to_install = $(addprefix $(RUNTIME_DIR)/,$(files_to_build))

defs	=
objs	= entry lib
headers = ../include/*.h

CFLAGS += $(defs)
ASFLAGS += $(defs)

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
$(target)graphene-lib.a: $(addprefix $(target),$(objs))
	@mkdir -p $(dir $@)
	$(call cmd,ar_a_o)

$(pal_lib):
	make -C ../../../Pal/src

libexample.so: $(addsuffix .o,$(objs)) $(graphene_lib) $(pal_lib)
	@echo [ $@ ]
	$(LD) $(LDFLAGS) \
		-o $@ $(filter-out %.map %.lds,$^) -soname $@ \
		-rpath-link=$(abspath $(RUNTIME_DIR)) \
		$(graphene_lib) $(pal_lib)

%.asm: %.c $(headers)
	@echo [ $@ ]
	@$(CC) $(CFLAGS) -c $< -o $<.o
	@objdump -S $<.o > $@
	@rm $<.o

%.o: %.c $(headers)
	$(call cmd,cc_o_c)

%.e %.i: %.c $(headers)
	$(call cmd,cpp_i_c)

%.s: %.c $(headers)
	$(call cmd,cc_s_c)

%.o: %.S $(headers)
	$(call cmd,as_o_S)

%.e %.s: %.S $(headers)
	$(call cmd,cpp_s_S)

clean:
	rm -rf $(addsuffix .o,$(objs)) $(files_to_build) $(CLEAN_FILES)
