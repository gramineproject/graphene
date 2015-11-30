SYS ?= $(shell gcc -dumpmachine)
export SYS

LMBENCHDIR = lmbench-2.5
HOST_BINARIES = /bin/sh /usr/include/x86_64-linux-gnu/sys/types.h
BINARIES = $(LMBENCHDIR)/bin/linux test-list $(addprefix host,$(HOST_BINARIES))
NO_MANIFEST = lmbench lmbench.a *.o hello INFO.*

export CC
export CFLAGS

all debug: test-list $(LMBENCHDIR)/bin/linux
	for f in `cat test-list`; do \
		[ -f $(LMBENCHDIR)/bin/graphene/$$f.manifest ] || \
		$(MAKE) $(LMBENCHDIR)/bin/graphene/$$f.manifest; \
		ln -sf $$f.manifest $(LMBENCHDIR)/bin/graphene/$$f; \
	done
	cp -f $(foreach p,$(addprefix $(LMBENCHDIR)/bin/linux/,$(NO_MANIFEST)),$(wildcard $(p))) \
		$(LMBENCHDIR)/bin/graphene

debug: CC="gcc -g"

kvm: CFLAGS += -DKVM_BENCH -D_DEBUG
kvm: all

servers = lat_udp lat_tcp lat_rpc lat_connect bw_tcp

$(LMBENCHDIR)/bin/graphene/%.manifest: $(LMBENCHDIR)/bin/graphene/%.manifest.template
	$(MAKE) -C .. lmbench/$@ appdir=lmbench/

$(LMBENCHDIR)/bin/graphene/%.manifest.template: manifest.template $(LMBENCHDIR)/bin/graphene
	ln -s ../../../$< $@

$(LMBENCHDIR)/bin/graphene:
	mkdir -p $@

ifeq ($(SYS),x86_64-linux-gnu)
$(LMBENCHDIR)/bin/linux: $(wildcard $(LMBENCHDIR)/src/*.c) $(wildcard $(LMBENCHDIR)/src/*.h)
	$(MAKE) -C $(LMBENCHDIR)/src OS=linux CC="gcc -g"

test-list: $(LMBENCHDIR)/bin/linux
	for f in `find $(LMBENCHDIR)/bin/linux/ \
		-type f -executable \
		$(subst *,\\*,$(addprefix -not -name ,$(NO_MANIFEST)))`;  \
	do \
		echo $${f##*/}; \
	done > test-list

.PHONY: pack
$(addprefix host,$(HOST_BINARIES)):
	@echo "$(patsubst host%,%,$@) -> $@"
	@mkdir -p $(dir $@)
	@cp -LTrf $(patsubst host%,%,$@) $@

pack: $(BINARIES)
	@../../../../../Scripts/pack_binaries.sh lmbench $^
else
all: $(addprefix /tmp/host,$(HOST_BINARIES))

$(filter-out $(HOST_BINARIES),$(BINARIES)): .packed/lmbench.tar.gz
	tar -xmozf $< $@

$(addprefix /tmp/host,$(HOST_BINARIES)): .packed/lmbench.tar.gz
	cd /tmp && tar -xmozf $(abspath $<) $(subst /tmp/,,$@)
endif

LMBENCHCONFIG = $(shell $(LMBENCHDIR)/scripts/config)

$(LMBENCHDIR)/bin/linux/$(LMBENCHCONFIG):
	cd $(LMBENCHDIR)/scripts && env OS=linux ./config-run

/tmp/hello: $(LMBENCHDIR)/bin/linux/hello
	cp -f $< $@

test-native: $(LMBENCHDIR)/bin/linux $(LMBENCHDIR)/bin/linux/$(LMBENCHCONFIG) /tmp/hello
	cd $(LMBENCHDIR)/scripts && env OS=linux ./results

$(LMBENCHDIR)/bin/graphene/$(LMBENCHCONFIG): $(LMBENCHDIR)/bin/linux/$(LMBENCHCONFIG)
	sed -e "s/OS=\"linux\"/OS=\"graphene\"/g" $< > $@

test-graphene: all $(LMBENCHDIR)/bin/graphene/$(LMBENCHCONFIG) /tmp/hello
	cd $(LMBENCHDIR)/scripts && env OS=graphene ./results

clean:
	rm -rf test-list
	$(MAKE) -C $(LMBENCHDIR) clean
