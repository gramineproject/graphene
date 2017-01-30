exec_target = busybox.manifest busybox_nofork.manifest
target = busybox busybox_gdb busybox_nofork busybox_nofork_gdb

level = ../../
include ../../Makefile

BUSYBOX_DIR = busybox-1.23.1

ifeq ($(DEBUG),1)
MAKE_FLAGS = CC="gcc -g"
endif

busybox busybox_gdb: config-graphene
	[ -d $(BUSYBOX_DIR) ] || tar -xjf $(BUSYBOX_DIR).tar.bz2
	cp config-graphene $(BUSYBOX_DIR)/.config
	cd $(BUSYBOX_DIR) && $(MAKE) $(MAKE_FLAGS)
	cp $(BUSYBOX_DIR)/busybox busybox
	cp $(BUSYBOX_DIR)/busybox_unstripped busybox_gdb

busybox_nofork busybox_nofork_gdb: $(BUSYBOX_DIR) config-graphene-nofork
	[ -d $(BUSYBOX_DIR) ] || tar -xjf $(BUSYBOX_DIR).tar.bz2
	cp config-graphene-nofork $(BUSYBOX_DIR)/.config
	cd $(BUSYBOX_DIR) && $(MAKE) $(MAKE_FLAGS)
	cp $(BUSYBOX_DIR)/busybox busybox_nofork
	cp $(BUSYBOX_DIR)/busybox_unstripped busybox_nofork_gdb

distclean: clean
	rm -rf $(BUSYBOX_DIR)
