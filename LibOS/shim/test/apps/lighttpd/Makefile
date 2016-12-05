manifests = lighttpd.manifest lighttpd-angel.manifest
SRCDIR = lighttpd-1.4.30
HOST = $(firstword $(shell ifconfig | grep 'inet addr:'| grep -v '127.0.0.1' -m 1 | cut -d: -f2))
PORT = 8000
CORES = 4

conf_files = lighttpd-server.conf lighttpd.conf lighttpd-multithreaded.conf

target = build-lighttpd $(conf_files) test-data
exec_target = $(manifests)
clean-extra = clean-others

extra_rules = \
	-e 's:\$$(PAL):../pal_loader:g' \
	-e 's:\$$(HOST):$(HOST):g' \
	-e 's:\$$(PORT):$(PORT):g'

level = ../../
include ../../Makefile

build-lighttpd: build/sbin/lighttpd

build/sbin/lighttpd: $(SRCDIR)
	cd $(SRCDIR) && ./configure --prefix=$(PWD)/build \
		--without-openssl --without-pcre --without-zlib --without-bzip2
	$(MAKE) -C $(SRCDIR)
	$(MAKE) -C $(SRCDIR) install

$(SRCDIR): %: %.tar.gz
	tar -xzf $<

lighttpd-server.conf:
	rm -rf $@
	echo "server.document-root       = \"$(PWD)/html\""    >> $@
	echo "server.port                = $(PORT)"            >> $@
	echo "server.bind                = \"$(HOST)\""        >> $@

lighttpd.conf:
	rm -rf $@
	echo "include \"lighttpd-server.conf\""                >> $@
	echo "include \"lighttpd-generic.conf\""               >> $@

lighttpd-multithreaded.conf:
	rm -rf $@
	echo "include \"lighttpd-server.conf\""                >> $@
	echo "server.max-worker          = $(CORES)"           >> $@
	echo "include \"lighttpd-generic.conf\""               >> $@

start-native-server:
	$(PREFIX) build/sbin/lighttpd -D -m build/lib -f \
		$(if $(CONF),$(CONF),lighttpd.conf)

start-multithreaded-native-server:
	$(PREFIX) build/sbin/lighttpd -D -m build/lib -f \
                $(if $(CONF),$(CONF),lighttpd-multithreaded.conf)

start-graphene-server:
	$(PREFIX) ./lighttpd.manifest -D -m /lighttpd -f \
		$(if $(CONF),$(CONF),lighttpd.conf)

start-multithreaded-graphene-server:
	$(PREFIX) ../pal_loader build/sbin/lighttpd -D -m /lighttpd -f \
                $(if $(CONF),$(CONF),lighttpd-multithreaded.conf)


random-data = $(foreach n,1 2 3 4 5 6 7 8 9 10,2K.$n.html) \
	      $(foreach n,1 2 3 4 5,10K.$n.html) \
	      $(foreach n,1 2 3 4 5,100K.$n.html) \
	      $(foreach n,1 2 3,1M.$n.html) \
	      $(foreach n,1 2 3,10M.$n.html) \
	      $(foreach n,1 2 3,100.$n.html)

test-data = html/oscar-web html/oscar-web-static html/random \
	    $(addprefix html/random/,$(random-data))

try-download:
	echo "download random files ($(TESTNAME)):" >> result; \
	time -a -o result -p wget $(addprefix http://$(HOST):$(PORT)/random/,$(random-data)) -O wget-out; \
	echo "download random files again ($(TESTNAME)):" >> result; \
	time -a -o result -p wget $(addprefix http://$(HOST):$(PORT)/random/,$(random-data)) -O wget-out; \
	echo "download static oscar-web ($(TESTNAME)):" >> result; \
	time -a -o result -p wget -r http://$(HOST):$(PORT)/oscar-web-static/index.php -O wget-out;

test-native: $(test-data)
	$(MAKE) start-native-server & serverid=$$!; sleep 1; \
	$(MAKE) try-download TESTNAME=native; \
	rm wget-out; kill $$serverid

test-multithreaded-native: $(test-data)
	$(MAKE) start-multithreaded-native-server & serverid=$$!; sleep 1; \
	$(MAKE) try-download TESTNAME=native; \
        rm wget-out; kill $$serverid


test-graphene: $(test-data)
	$(MAKE) start-graphene-server & serverid=$$!; sleep 1; \
	$(MAKE) try-download TESTNAME=graphene; \
	rm wget-out; kill $$serverid

test-multithreaded-graphene: $(test-data)
	$(MAKE) start-multithreaded-graphene-server & serverid=$$!; sleep 1; \
        $(MAKE) try-download TESTNAME=graphene; \
        rm wget-out; kill $$serverid


html/%: ../web-data/%.tar.gz
	[ -d "$@" ] || (cd html && tar -xzf ../$^)

html/random:
	mkdir -p html/random

html/random/%.html: html/random
	dd if=/dev/urandom of=$@ count=1 bs=$(basename $(basename $(notdir $@)))

test-data: $(test-data)

distclean: clean
	rm -rf build $(SRCDIR)

clean-others:
	rm -rf $(conf_files) $(test-data)
