LMBENCHDIR = lmbench-2.5
LINUXDIR=$(LMBENCHDIR)/bin/linux/
GRAPHENEDIR=$(LMBENCHDIR)/bin/graphene/
RUNDIR=$(LMBENCHDIR)/bin/graphene.run/

HOST_BINARIES = /bin/sh /usr/include/x86_64-linux-gnu/sys/types.h
BINARIES = $(LINUXDIR) $(addprefix host,$(HOST_BINARIES))
LMBENCH_TESTS = lat_syscall lat_connect lat_fcntl lat_select lat_fs \
		lat_mmap lat_fifo lat_mem_rd lat_msg lat_tcp lat_udp \
		lat_unix_connect lat_pagefault \
		bw_tcp bw_mem bw_unix lat_proc lat_ctx lat_rpc \
		lat_unix lat_sig lat_http lat_pipe \
		bw_pipe bw_file_rd bw_mmap_rd lmhttp lmdd
MANIFESTS = $(addsuffix .manifest,$(addprefix $(RUNDIR),$(LMBENCH_TESTS)))
RUNTIME_BINS = $(LINUXDIR)hello /bin/sh
RUNTIME_MANIFESTS=$(addsuffix .manifest,$(addprefix $(RUNDIR),$(foreach f,$(RUNTIME_BINS),$(notdir $(f)))))

target = $(addprefix $(LINUXDIR),$(LMBENCH_TESTS)) $(GRAPHENEDIR)
exec_target = $(MANIFESTS) $(RUNTIME_MANIFESTS)
clean-extra = clean-lmbench

level = ../../
include ../../Makefile

export CC
export CFLAGS

servers = lat_udp lat_tcp lat_rpc lat_connect bw_tcp

$(GRAPHENEDIR): $(MANIFESTS) $(addprefix $(RUNDIR),$(LMBENCH_TESTS)) $(LINUXDIR)
	mkdir -p $@
	for f in $(MANIFESTS); do \
		f=$${f##*/}; f=$${f%.manifest}; \
		echo "#!/bin/sh\ncd $(abspath $(RUNDIR)) && exec ./$$f.manifest \$$@" > $(GRAPHENEDIR)$$f; \
		chmod +x $(GRAPHENEDIR)$$f; \
	done
	cd $(LINUXDIR) && for f in *; do \
		if [ ! -f ../graphene/$$f ]; then cp $$f ../graphene/$$f; fi; \
	done

$(MANIFESTS): $(RUNDIR)%.manifest: $(RUNDIR)%.manifest.template $(LINUXDIR)%
	$(MAKE) -C .. lmbench/$@ appdir=lmbench/

$(addsuffix .template,$(MANIFESTS)): $(RUNDIR)%.manifest.template: manifest.template $(RUNDIR)
	ln -sf ../../../$< $@

$(RUNTIME_MANIFESTS): %.manifest: %.manifest.template
	$(MAKE) -C .. lmbench/$@ appdir=lmbench/

$(addsuffix .template,$(RUNTIME_MANIFESTS)): $(RUNDIR)%.manifest.template: %.manifest.template $(RUNDIR)
	ln -sf ../../../$< $@

$(addprefix $(RUNDIR),$(LMBENCH_TESTS)): $(RUNDIR)%: $(LINUXDIR)%
	ln -sf ../linux/$(notdir $@) $@

$(RUNDIR):
	mkdir -p $@

ifeq ($(SYS),x86_64-linux-gnu)
$(addprefix $(LINUXDIR),$(LMBENCH_TESTS)): \
	$(wildcard $(LMBENCHDIR)/src/*.c) $(wildcard $(LMBENCHDIR)/src/*.h)
	$(MAKE) -C $(LMBENCHDIR)/src OS=linux CC="gcc -g"
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

$(LINUXDIR)$(LMBENCHCONFIG):
	cd $(LMBENCHDIR)/scripts && env OS=linux ./config-run

/tmp/hello: $(LINUXDIR)hello
	cp -f $< $@

test-native: $(LINUXDIR) $(LINUXDIR)$(LMBENCHCONFIG) /tmp/hello
	cd $(LMBENCHDIR)/scripts && env OS=linux ./results

$(RUNDIR)$(LMBENCHCONFIG): $(LINUXDIR)$(LMBENCHCONFIG)
	sed -e "s/OS=\"linux\"/OS=\"graphene\"/g" $< > $@

test-graphene: all $(RUNDIR)$(LMBENCHCONFIG) /tmp/hello
	cd $(LMBENCHDIR)/scripts && env OS=graphene ./results

clean-lmbench:
	$(MAKE) -C $(LMBENCHDIR) clean
