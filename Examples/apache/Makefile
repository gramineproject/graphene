THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

INSTALL_DIR ?= $(THIS_DIR)install
HTTPD_SRC ?= $(THIS_DIR)httpd-2.4.46
HTTPD_CHECKSUM ?= 44b759ce932dc090c0e75c0210b4485ebf6983466fb8ca1b446c8168e1a1aec2

# Mirros for downloading the Apache source code
HTTPD_MIRRORS ?= \
    https://www-eu.apache.org/dist/httpd \
    https://www-us.apache.org/dist/httpd \
    https://ftp.fau.de/apache/httpd \
    https://archive.apache.org/dist/httpd \
    https://packages.grapheneproject.io/distfiles

LISTEN_HOST ?= 127.0.0.1
LISTEN_PORT ?= 8001

SGX_SIGNER_KEY ?= ../../Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENE_LOG_LEVEL = debug
else
GRAPHENE_LOG_LEVEL = error
endif

.PHONY: all
all: $(INSTALL_DIR)/bin/httpd httpd.manifest config testdata ssldata
ifeq ($(SGX),1)
all: httpd.manifest.sgx httpd.sig httpd.token
endif

$(INSTALL_DIR)/bin/httpd: $(HTTPD_SRC)/configure
	cd $(HTTPD_SRC) && ./configure --prefix=$(abspath $(INSTALL_DIR)) \
		--with-mpm=prefork --enable-mpms-shared='prefork worker event' \
		--enable-ssl
	cd $(HTTPD_SRC) && $(MAKE)
	cd $(HTTPD_SRC) && $(MAKE) install

# We need to patch the Apache makefile: it has broken group-target, which does
# not work on parallel builds.
$(HTTPD_SRC)/configure: $(HTTPD_SRC).tar.gz
	tar --touch -xzf $<
	cd $(HTTPD_SRC) && patch -p1 -l < ../apache_makefile.patch

$(HTTPD_SRC).tar.gz:
	../common_tools/download --output $@ --sha256 $(HTTPD_CHECKSUM) \
		$(foreach mirror,$(HTTPD_MIRRORS),--url $(mirror)/$(HTTPD_SRC).tar.gz)

$(INSTALL_DIR)/conf/httpd.conf: $(INSTALL_DIR)/bin/httpd
$(INSTALL_DIR)/conf/extra/httpd-ssl.conf: $(INSTALL_DIR)/bin/httpd

# Listing all the enabled modules in Apache, by greping httpd.conf
.INTERMEDIATE: httpd-modules
httpd-modules: $(INSTALL_DIR)/conf/httpd.conf
	@grep "^LoadModule" $(INSTALL_DIR)/conf/httpd.conf | \
		awk '{print "$(INSTALL_DIR)/" $$3}' > $@
	@echo $(INSTALL_DIR)/modules/mod_mpm_worker.so >> $@
	@echo $(INSTALL_DIR)/modules/mod_mpm_event.so  >> $@
	@echo $(INSTALL_DIR)/modules/mod_ssl.so        >> $@

httpd.manifest: httpd.manifest.template
	graphene-manifest \
		-Dlog_level=$(GRAPHENE_LOG_LEVEL) \
		-Dinstall_dir=$(INSTALL_DIR) \
		-Dinstall_dir_abspath=$(abspath $(INSTALL_DIR)) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		$< > $@

httpd.manifest.sgx: httpd.manifest $(INSTALL_DIR)/bin/httpd \
		$(INSTALL_DIR)/conf/httpd-graphene.conf \
		$(INSTALL_DIR)/conf/extra/httpd-ssl-graphene.conf \
		$(TEST_DATA) \
		$(INSTALL_DIR)/conf/server.crt
	@test -s $(SGX_SIGNER_KEY) || \
	    { echo "SGX signer private key was not found, please specify SGX_SIGNER_KEY!"; exit 1; }
	graphene-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest httpd.manifest \
		--output $@

httpd.sig: httpd.manifest.sgx

httpd.token: httpd.sig
	graphene-sgx-get-token --output $@ --sig $<

.PHONY: config
config: $(INSTALL_DIR)/conf/httpd-graphene.conf $(INSTALL_DIR)/conf/extra/httpd-ssl-graphene.conf

$(INSTALL_DIR)/conf/httpd-graphene.conf: $(INSTALL_DIR)/conf/httpd.conf
	sed \
		-e "s|^Listen |#Listen |g" \
		-e "s|^User |#User |g" \
		-e "s|^Group |#Group |g" \
		-e "s|^LoadModule mpm_prefork|#LoadModule mpm_prefork|g" \
		-e "s|^#LoadModule ssl_module|LoadModule ssl_module|g" \
		-e "s|^#Include conf/extra/httpd-ssl.conf|Include conf/extra/httpd-ssl-graphene.conf|g" \
		-e "s|#EnableMMAP off|EnableMMAP off|g" \
		-e "s|#EnableSendfile on|EnableSendfile on|g" \
	$< > $@
	echo "\n\
<IfModule mpm_prefork_module>\n\
    StartServers             4\n\
    MinSpareServers          1\n\
    MaxSpareServers          4\n\
    MaxConnectionsPerChild   0\n\
</IfModule>\n" >> $@
	echo "\n\
<IfModule mpm_worker_module>\n\
    StartServers             1\n\
    MinSpareThreads          25\n\
    MaxSpareThreads          75\n\
    ThreadsPerChild          25\n\
</IfModule>\n" >> $@

$(INSTALL_DIR)/conf/extra/httpd-ssl-graphene.conf: $(INSTALL_DIR)/conf/extra/httpd-ssl.conf
	sed \
		-e "s|^Listen 443|Listen 127.0.0.1:8443|g" \
		-e "s|^<VirtualHost _default_:443>|<VirtualHost 127.0.0.1:8443>|g" \
		-e "s|^ServerName www.example.com:443|ServerName www.example.com:8443|g" \
		-e "s|^SSLSessionCache|#SSLSessionCache|g" \
	$< > $@

# HTTP docs:
# Generating random HTML files in $(INSTALL_DIR)/htdocs/random
RANDOM_DIR = $(INSTALL_DIR)/htdocs/random
RANDOM_FILES = \
	$(foreach n,1 2 3 4 5 6 7 8 9 10,2K.$n.html) \
	$(foreach n,1 2 3 4 5,10K.$n.html) \
	$(foreach n,1 2 3 4 5,100K.$n.html) \
	$(foreach n,1 2 3,1M.$n.html) \
	$(foreach n,1 2 3,10M.$n.html) \
	$(foreach n,1 2 3,100.$n.html)

TEST_DATA = $(addprefix $(RANDOM_DIR)/,$(RANDOM_FILES))

# We need to first build and install httpd, otherwise its makefiles think that they already
# filled $(INSTALL_DIR)/htdocs and skip copying installation files.
$(RANDOM_DIR)/%.html: $(INSTALL_DIR)/bin/httpd
	mkdir -p $(RANDOM_DIR)
	dd if=/dev/urandom of=$@ count=1 bs=$(basename $(basename $(notdir $@))) status=none

.PHONY: testdata
testdata: $(TEST_DATA)

# SSL data: key and x.509 self-signed certificate (to test SSL/TLS)
$(INSTALL_DIR)/conf/server.crt: ssl/ca_config.conf $(INSTALL_DIR)/bin/httpd
	openssl genrsa -out ssl/ca.key 2048
	openssl req -x509 -new -nodes -key ssl/ca.key -sha256 -days 1024 -out ssl/ca.crt -config ssl/ca_config.conf
	openssl genrsa -out ssl/server.key 2048
	openssl req -new -key ssl/server.key -out ssl/server.csr -config ssl/ca_config.conf
	openssl x509 -req -days 360 -in ssl/server.csr -CA ssl/ca.crt -CAkey ssl/ca.key -CAcreateserial -out ssl/server.crt
	cp -f ssl/* $(INSTALL_DIR)/conf/

.PHONY: ssldata
ssldata: $(INSTALL_DIR)/conf/server.crt

ifeq ($(SGX),)
GRAPHENE = graphene-direct
else
GRAPHENE = graphene-sgx
endif

.PHONY: clean-server
clean-server:
	$(RM) $(INSTALL_DIR)/logs/httpd-$(LISTEN_HOST)-$(LISTEN_PORT).pid

.PHONY: start-native-server
start-native-server: all clean-server
	@echo "Listen on $(LISTEN_HOST):$(LISTEN_PORT)"
	$(INSTALL_DIR)/bin/httpd -D FOREGROUND \
		-f conf/httpd-graphene.conf \
		-C "LoadModule mpm_prefork_module modules/mod_mpm_prefork.so" \
		-C "Listen $(LISTEN_HOST):$(LISTEN_PORT)" \
		-C "ServerName $(LISTEN_HOST)" \
		-C "PidFile logs/httpd-$(LISTEN_HOST)-$(LISTEN_PORT).pid"

.PHONY: start-graphene-server
start-graphene-server: all clean-server
	@echo "Listen on $(LISTEN_HOST):$(LISTEN_PORT)"
	$(GRAPHENE) ./httpd -D FOREGROUND \
		-f conf/httpd-graphene.conf \
		-C "LoadModule mpm_prefork_module modules/mod_mpm_prefork.so" \
		-C "Listen $(LISTEN_HOST):$(LISTEN_PORT)" \
		-C "ServerName $(LISTEN_HOST)" \
		-C "PidFile logs/httpd-$(LISTEN_HOST)-$(LISTEN_PORT).pid"

.PHONY: start-native-multithreaded-server
start-native-multithreaded-server: all clean-server
	@echo "Listen on $(LISTEN_HOST):$(LISTEN_PORT)"
	$(INSTALL_DIR)/bin/httpd -D FOREGROUND \
		-f conf/httpd-graphene.conf \
		-C "LoadModule mpm_worker_module modules/mod_mpm_worker.so" \
		-C "Listen $(LISTEN_HOST):$(LISTEN_PORT)" \
		-C "ServerName $(LISTEN_HOST)" \
		-C "PidFile logs/httpd-$(LISTEN_HOST)-$(LISTEN_PORT).pid"

.PHONY: start-graphene-multithreaded-server
start-graphene-multithreaded-server: all clean-server
	@echo "Listen on $(LISTEN_HOST):$(LISTEN_PORT)"
	$(GRAPHENE) ./httpd -D FOREGROUND \
		-f conf/httpd-graphene.conf \
		-C "LoadModule mpm_worker_module modules/mod_mpm_worker.so" \
		-C "Listen $(LISTEN_HOST):$(LISTEN_PORT)" \
		-C "ServerName $(LISTEN_HOST)" \
		-C "PidFile logs/httpd-$(LISTEN_HOST)-$(LISTEN_PORT).pid"

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig OUTPUT result-* httpd-ldd httpd-modules tmp

.PHONY: distclean
distclean: clean
	$(RM) -r $(HTTPD_SRC).tar.gz $(HTTPD_SRC) $(INSTALL_DIR)
	$(RM) ssl/server.* ssl/ca.*
