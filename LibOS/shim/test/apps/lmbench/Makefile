LMBENCHDIR = lmbench-2.5
LMBENCHMANIFEST = manifest-list

export CC
export CFLAGS

all debug: $(LMBENCHMANIFEST)
	for f in `cat $(LMBENCHMANIFEST)`; do make $${f%.template}; done

debug: CC="gcc -g"

kvm: CFLAGS += -DKVM_BENCH -D_DEBUG
kvm: all

servers = lat_udp lat_tcp lat_rpc lat_connect bw_tcp

%.manifest: manifest.template
	make -C .. lmbench/$@ appdir=lmbench/
	echo $(if $(findstring $(notdir $(basename $@)),$(servers)),"loader.daemonize = 1") >> $@


$(LMBENCHDIR)/bin/linux: $(wildcard $(LMBENCHDIR)/src/*.c) $(wildcard $(LMBENCHDIR)/src/*.h)
	make -C $(LMBENCHDIR)/src OS=linux CC="gcc -g"

manifest-list: $(LMBENCHDIR)/bin/linux
	mkdir -p $(LMBENCHDIR)/bin/graphene
	cp -n $(LMBENCHDIR)/bin/linux/* $(LMBENCHDIR)/bin/graphene
	find $(LMBENCHDIR)/bin/linux/ -type f -executable \
		-not -name lmbench -not -name hello | \
		sed 's:linux/\(.*\):graphene/\1.manifest.template:g' | \
		tee manifest-list | \
		xargs -l ln -sf ../../../manifest.template
	for f in `cat manifest-list`; do f=$${f%.manifest.template}; \
		ln -sf $${f##*/}.manifest $$f ; done

config = $(shell $(LMBENCHDIR)/scripts/config)

config-native: $(LMBENCHDIR)/bin/linux
	[ -f "$(LMBENCHDIR)/bin/linux/$(config)" ] || \
	(cd $(LMBENCHDIR)/scripts && env OS=linux ./config-run)

test-native: config-native
	make -C $(LMBENCHDIR) OS=linux rerun

config-graphene: config-native $(LMBENCHMANIFEST)
	[ -f "$(LMBENCHDIR)/bin/graphene/$(config)" ] || \
	sed -e "s/OS=\"linux\"/OS=\"graphene\"/g" "$(LMBENCHDIR)/bin/linux/$(config)" \
	    > "$(LMBENCHDIR)/bin/graphene/$(config)"
	cp $(LMBENCHDIR)/bin/graphene/hello /tmp

test-graphene: config-graphene
	make -C $(LMBENCHDIR) OS=graphene rerun

clean:
	rm -rf $(LMBENCHMANFIEST)
	make -C $(LMBENCHDIR) clean
