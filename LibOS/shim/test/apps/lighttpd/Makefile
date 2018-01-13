manifests = lighttpd.manifest lighttpd-angel.manifest
SRCDIR = lighttpd-1.4.30
HOST = $(firstword $(shell ifconfig | grep 'inet addr:'| grep -v '127.0.0.1' -m 1 | cut -d: -f2))
PORT = 8000
CORES = 4
THREADS = 25

conf_files = lighttpd-server.conf lighttpd.conf lighttpd-multithreaded.conf lighttpd-ssl.conf

target = build-lighttpd $(conf_files) test-data
exec_target = $(manifests)
clean-extra = clean-others

extra_rules = -e 's:\$$(HOST):$(HOST):g' -e 's:\$$(PORT):$(PORT):g'

level = ../../
include ../../Makefile

build-lighttpd: build/sbin/lighttpd

build/sbin/lighttpd: $(SRCDIR)
	cd $(SRCDIR) && ./configure --prefix=$(PWD)/build \
		--with-openssl --without-pcre --without-zlib --without-bzip2
	$(MAKE) -C $(SRCDIR)
	$(MAKE) -C $(SRCDIR) install

$(SRCDIR): %: %.tar.gz
	tar -xmzf $<

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
	echo "server.max-worker          = $(THREADS)"         >> $@
	echo "include \"lighttpd-generic.conf\""               >> $@

lighttpd-ssl.conf: server.pem
	rm -rf $@
	echo "include \"lighttpd-server.conf\""                >> $@
	echo "include \"lighttpd-generic.conf\""               >> $@
	echo ""                                                >> $@
	echo "\$$SERVER[\"socket\"] == \"0.0.0.0:443\" {"      >> $@
	echo "ssl.engine = \"enable\""                         >> $@
	echo "ssl.pemfile = \"server.pem\""                    >> $@
	echo "ssl.cipher-list = \"ECDHE-RSA-AES256-SHA384:AES256-SHA256:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM\""                                                           >> $@
	echo "ssl.honor-cipher-order = \"enable\""             >> $@
	echo "}" 

server.pem:
	openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes -subj "/cn=lighttpd/o=oscar/dc=cs/dc=stonybrook/dc=edu/"

start-native-server:
	$(PREFIX) build/sbin/lighttpd -D -m build/lib -f \
		$(if $(CONF),$(CONF),lighttpd.conf)

start-multithreaded-native-server:
	$(PREFIX) build/sbin/lighttpd -D -m build/lib -f \
                $(if $(CONF),$(CONF),lighttpd-multithreaded.conf)

start-ssl-native-server:
	$(PREFIX) build/sbin/lighttpd -D -m build/lib -f \
                $(if $(CONF),$(CONF),lighttpd-ssl.conf)

start-graphene-server:
	$(PREFIX) ./lighttpd.manifest -D -m /lighttpd -f \
		$(if $(CONF),$(CONF),lighttpd.conf)

start-multithreaded-graphene-server:
	$(PREFIX) ./lighttpd.manifest -D -m /lighttpd -f \
                $(if $(CONF),$(CONF),lighttpd-multithreaded.conf)

start-ssl-graphene-server:
	$(PREFIX) ./lighttpd.manifest -D -m /lighttpd -f \
                $(if $(CONF),$(CONF),lighttpd-ssl.conf)


random-data = $(foreach n,1 2 3 4 5 6 7 8 9 10,2K.$n.html) \
	      $(foreach n,1 2 3 4 5,10K.$n.html) \
	      $(foreach n,1 2 3 4 5,100K.$n.html) \
	      $(foreach n,1 2 3,1M.$n.html) \
	      $(foreach n,1 2 3,10M.$n.html) \
	      $(foreach n,1 2 3,100.$n.html)

test-data = html/oscar-web html/oscar-web-static html/random \
	    $(addprefix html/random/,$(random-data))

html/%: ../web-data/%.tar.gz
	[ -d "$@" ] || (cd $(dir $@) && tar -xzf ../$^)

html/random:
	mkdir -p $@

html/random/%.html: html/random
	dd if=/dev/urandom of=$@ count=1 bs=$(basename $(basename $(notdir $@)))

test-data: $(test-data)

distclean: clean
	rm -rf build $(SRCDIR)

clean-others:
	rm -rf $(conf_files) $(test-data)
