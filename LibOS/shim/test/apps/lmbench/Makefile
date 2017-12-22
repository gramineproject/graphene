LMBENCHDIR = lmbench-2.5
LINUXDIR = $(LMBENCHDIR)/bin/linux/

host_files = /bin/sh /usr/include/x86_64-linux-gnu/sys/types.h
lmbench_tests = $(addprefix $(LINUXDIR),lat_syscall lat_connect lat_fcntl \
		lat_select lat_fs lat_mmap lat_fifo lat_mem_rd lat_msg \
		lat_tcp lat_udp lat_unix_connect lat_pagefault \
		bw_tcp bw_mem bw_unix lat_proc lat_ctx lat_rpc \
		lat_unix lat_sig lat_http lat_pipe \
		bw_pipe bw_file_rd bw_mmap_rd lmhttp lmdd)
manifests = $(addprefix $(LINUXDIR),$(patsubst %.template,%,$(wildcard *.manifest.template)) manifest)

target = $(lmbench_tests)
clean-extra = clean-lmbench

level = ../../
include ../../Makefile

export CC
export CFLAGS

$(LINUXDIR)Makefile: Makefile.lmbench
	ln -sf ../../../$< $@

build-manifest: $(LINUXDIR) $(LINUXDIR)Makefile
	$(MAKE) -C $(LINUXDIR)

$(lmbench_tests): $(LINUXDIR) build-manifest

$(LINUXDIR): $(wildcard $(LMBENCHDIR)/src/*.c) $(wildcard $(LMBENCHDIR)/src/*.h)
	$(MAKE) -C $(LMBENCHDIR)/src OS=linux

lmbench_config = $(LINUXDIR)$(shell $(LMBENCHDIR)/scripts/config)

$(lmbench_config):
	cd $(LMBENCHDIR)/scripts && env OS=linux ./config-run

test-native: $(lmbench_tests) $(lmbench_config)
	cd $(LMBENCHDIR)/scripts && env OS=linux ./results

test-graphene: all $(lmbench_config)
	cd $(LMBENCHDIR)/scripts && \
		env LOADER=./pal_loader OS=linux RESULTS=results/graphene \
		./results

regression: all
	cp -f $(LMBENCHDIR)/lmbench-regression $(LMBENCHDIR)/bin/linux
	cd $(LMBENCHDIR)/bin/linux && \
		env LOADER=./pal_loader OS=linux \
		./lmbench-regression 

clean-lmbench:
	$(MAKE) -C $(LMBENCHDIR) clean
