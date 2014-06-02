busybox_src = busybox-1.19.4

manifests = busybox.manifest busybox_nofork.manifest
targets = busybox busybox_gdb busybox_nofork busybox_nofork_gdb $(manifests)
test_targets =

all: $(targets)

debug: MAKE_FLAGS=CC="gcc -g"
debug: $(targets)

busybox busybox_gdb: config_for_graphene
	[ -d $(busybox_src) ] || tar -xzf $(busybox_src).tar.gz
	cp config_for_graphene $(busybox_src)/.config
	cd $(busybox_src) && make $(MAKE_FLAGS)
	cp $(busybox_src)/busybox busybox
	cp $(busybox_src)/busybox_unstripped busybox_gdb

busybox_nofork busybox_nofork_gdb: $(busybox_src) config_for_graphene_nofork
	[ -d $(busybox_src) ] || tar -xzf $(busybox_src).tar.gz
	cp config_for_graphene_nofork $(busybox_src)/.config
	cd $(busybox_src) && make $(MAKE_FLAGS)
	cp $(busybox_src)/busybox busybox_nofork
	cp $(busybox_src)/busybox_unstripped busybox_nofork_gdb

test: all $(test_targets)

%.manifest: %.manifest.template
	make -C .. busybox/$@ appdir=busybox/

distclean: clean
	rm -rf $(busybox_src)

clean: clean-manifests
	rm -rf result $(test_targets) busybox busybox_gdb

clean-manifests:
	rm -rf $(manifests)
