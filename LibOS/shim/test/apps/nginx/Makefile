manifests = nginx.manifest
SRCDIR = nginx-1.10.1
HOST = $(firstword $(shell ifconfig | grep 'inet addr:'| grep -v '127.0.0.1' -m 1 | cut -d: -f2))
PORT = 8000
CORES = 4
THREADS = 25

conf_files = http.t

target = build-nginx $(conf_files) test-data
exec_target = $(manifests)
clean-extra = clean-others

extra_rules = -e 's:\$$(HOST):$(HOST):g' -e 's:\$$(PORT):$(PORT):g'

level = ../../
include ../../Makefile

build-nginx: build/sbin/nginx

build/sbin/nginx: $(SRCDIR)
	cd $(SRCDIR) && ./configure --prefix=$(PWD)/build
	$(MAKE) -C $(SRCDIR)
	$(MAKE) -C $(SRCDIR) install

$(SRCDIR): %: %.tar.gz
	tar -xmzf $<

$(conf_files): %.t: %.t.template
	sed $(extra_rules) $< > $@

start-native-server:
	$(PREFIX) build/sbin/nginx -c $(abspath http.t)

start-graphene-server:
	$(PREFIX) ./nginx.manifest -c $(abspath http.t) -g "user root;"

random-data = $(foreach n,1 2 3 4 5 6 7 8 9 10,2K.$n.html) \
	      $(foreach n,1 2 3 4 5,10K.$n.html) \
	      $(foreach n,1 2 3 4 5,100K.$n.html) \
	      $(foreach n,1 2 3,1M.$n.html) \
	      $(foreach n,1 2 3,10M.$n.html) \
	      $(foreach n,1 2 3,100.$n.html)

test-data = build/html/oscar-web build/html/oscar-web-static build/html/random \
	    $(addprefix build/html/random/,$(random-data))

build/html/%: ../web-data/%.tar.gz
	[ -d "$@" ] || (cd $(dir $@) && tar -xmzf ../../$^)

build/html/random:
	mkdir -p $@

build/html/random/%.html: build/html/random
	dd if=/dev/urandom of=$@ count=1 bs=$(basename $(basename $(notdir $@)))

test-data: $(test-data)

distclean: clean
	rm -rf build $(SRCDIR)

clean-others:
	rm -rf $(conf_files) $(test-data)
