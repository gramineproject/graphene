include ../../../../Scripts/Makefile.configs
include Makefile.am

CFLAGS	+= -I. -Iinclude -I../.. -I../../../include -I../../../include/pal \
	-I../../../include/host/Linux -I../../../include/lib \
	-I../../../include/host/Linux-common
ASFLAGS += -I. -Iinclude -I../.. -I../../../include

host_files = libpal-Linux.a pal.map

defs	= -DIN_PAL -DPAL_DIR=$(PAL_DIR) -DRUNTIME_DIR=$(RUNTIME_DIR)
CFLAGS += $(defs)
ASFLAGS += $(defs)

commons_objs = bogomips.o

objs = \
	clone-x86_64.o \
	db_devices.o \
	db_eventfd.o \
	db_events.o \
	db_exception.o \
	db_files.o \
	db_main.o \
	db_memory.o \
	db_misc.o \
	db_mutex.o \
	db_object.o \
	db_pipes.o \
	db_process.o \
	db_rtld.o \
	db_sockets.o \
	db_streams.o \
	db_threading.o \
	$(commons_objs)

graphene_lib = .lib/graphene-lib.a

.PHONY: all
all: $(host_files)

libpal-Linux.a: $(objs) $(graphene_lib)
	$(call cmd,ar_a_o)

$(commons_objs): %.o: ../Linux-common/%.c
	$(call cmd,cc_o_c)

%.o: %.c
	$(call cmd,cc_o_c)

%.i: %.c
	$(call cmd,cpp_i_c)

%.s: %.c
	$(call cmd,cc_s_c)

%.o: %.S
	$(call cmd,as_o_S)

%.s: %.S
	$(call cmd,cpp_s_S)

include ../../../../Scripts/Makefile.rules

ifeq ($(filter %clean,$(MAKECMDGOALS)),)
-include $(patsubst %.o,%.d,$(objs)) $(patsubst %.o,%.i.d,$(objs)) $(patsubst %.o,%.s.d,$(objs))
endif

CLEAN_FILES += $(notdir $(pal_static) $(pal_lib) $(pal_sec) $(pal_loader))

.PHONY: clean
clean:
	$(RM) $(objs) $(host_files) $(CLEAN_FILES) \
	      $(patsubst %.o,%.d,$(objs)) $(patsubst %.o,%.i.d,$(objs)) \
	      $(patsubst %.o,%.s.d,$(objs))

.PHONY: distclean
distclean: clean

.PHONY: test
test:
