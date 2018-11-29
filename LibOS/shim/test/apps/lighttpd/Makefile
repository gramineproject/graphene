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

.PHONY: build-lighttpd
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

lighttpd-ssl.conf: server.pem dhparam.pem
	rm -rf $@
	echo "include \"lighttpd-server.conf\""                >> $@
	echo "include \"lighttpd-generic.conf\""               >> $@
	echo ""                                                >> $@
	echo "\$$SERVER[\"socket\"] == \"0.0.0.0:443\" {"      >> $@
	echo "ssl.engine = \"enable\""                         >> $@
	echo "ssl.pemfile = \"server.pem\""                    >> $@
	echo "ssl.cipher-list = \"ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA\""	>> $@
	echo "ssl.honor-cipher-order = \"enable\""             >> $@
	echo "ssl.dh-file = \"dhparam.pem\""                   >> $@
	echo "ssl.ec-curve = \"secp384r1\""                    >> $@
	echo "}"                                               >> $@

server.pem:
	openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes -subj "/cn=lighttpd/o=oscar/dc=cs/dc=stonybrook/dc=edu/"

dhparam.pem:
	openssl dhparam -out dhparam.pem 2048

.PHONY: start-native-server
start-native-server:
	$(PREFIX) build/sbin/lighttpd -D -m build/lib -f \
		$(if $(CONF),$(CONF),lighttpd.conf)

.PHONY: start-multithreaded-native-server
start-multithreaded-native-server:
	$(PREFIX) build/sbin/lighttpd -D -m build/lib -f \
                $(if $(CONF),$(CONF),lighttpd-multithreaded.conf)

.PHONY: start-ssl-native-server
start-ssl-native-server:
	$(PREFIX) build/sbin/lighttpd -D -m build/lib -f \
                $(if $(CONF),$(CONF),lighttpd-ssl.conf)

.PHONY: start-graphene-server
start-graphene-server:
	$(PREFIX) ./lighttpd.manifest -D -m /lighttpd -f \
		$(if $(CONF),$(CONF),lighttpd.conf)

.PHONY: start-multithreaded-graphene-server
start-multithreaded-graphene-server:
	$(PREFIX) ./lighttpd.manifest -D -m /lighttpd -f \
                $(if $(CONF),$(CONF),lighttpd-multithreaded.conf)

.PHONY: start-ssl-graphene-server
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

.PHONY: distclean
distclean: clean
	rm -rf build $(SRCDIR)

.PHONY: clean-others
clean-others:
	rm -rf $(conf_files) $(test-data)
