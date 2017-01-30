manifests = memcached.manifest
SRCDIR = memcached-master
HOST = $(firstword $(shell ifconfig | grep 'inet addr:'| grep -v '127.0.0.1' -m 1 | cut -d: -f2))
PORT = 8000
CORES = 4
MAXMEM = 256
MAXTHREADS = 16

target = memcached $(manifests)
exec_target = memcached

clean-extra = clean-build

extra_rules = \
	-e 's:\$$(HOST):$(HOST):g' \
	-e 's:\$$(PORT):$(PORT):g' \
	-e 's:\$$(MEMSIZE):$(shell expr $(MAXMEM) + $(MAXMEM))M:g' \
	-e 's:\$$(THREADNUM):$(shell expr 2 + $(MAXTHREADS)):g'

level = ../../
include ../../Makefile

master.zip:
	wget https://github.com/memcached/memcached/archive/master.zip

$(SRCDIR)/configure: master.zip
	unzip master.zip
	cd $(SRCDIR) && ./autogen.sh

$(SRCDIR)/memcached: $(SRCDIR)/configure
	cd $(SRCDIR) && ./configure
	cd $(SRCDIR) && make

memcached: $(SRCDIR)/memcached
	cp -f $< $@

clean-build:
	rm -rf $(BUILDDIR)

distclean: clean
	rm -rf $(SRCDIR)
