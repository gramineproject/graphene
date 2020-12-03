# Build the manifest for Apache (httpd):
#
# - make                  Building for Linux
# - make DEBUG=1          Building for Linux, with Graphene debug output
# - make SGX=1            Building for SGX
# - make SGX=1 DEBUG=1    Building for SGX
#
# Use `make clean` to remove Graphene-generated files.
#
# Use `make distclean` to further remove the Apache tarball, source code,
# and installation.

THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

INSTALL_DIR ?= $(THIS_DIR)install
HTTPD_SRC ?= $(THIS_DIR)httpd-2.4.41
HTTPD_CHECKSUM ?= 3c0f9663240beb0f008acf3b4501c4f339d7467ee345a36c86c46b4d6f3a5461

# Mirros for downloading the Apache source code
HTTPD_MIRRORS ?= \
	https://www-eu.apache.org/dist/ \
	https://www-us.apache.org/dist/ \
	https://ftp.fau.de/apache/ \
	https://archive.apache.org/dist/

# Address and port for the Apache server to listen
LISTEN_HOST ?= 127.0.0.1
LISTEN_PORT ?= 8001

# Relative path to Graphene root
GRAPHENEDIR ?= $(THIS_DIR)../..
SGX_SIGNER_KEY ?= $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENEDEBUG = inline
else
GRAPHENEDEBUG = none
endif

.PHONY: all
all: $(INSTALL_DIR)/bin/httpd httpd.manifest config testdata ssldata | httpd pal_loader
ifeq ($(SGX),1)
all: httpd.manifest.sgx httpd.sig httpd.token
endif

include ../../Scripts/Makefile.configs

# The make targets for downloading and compiling the Apache source code, and
# installing the binaries.

$(INSTALL_DIR)/bin/httpd: $(HTTPD_SRC)/configure
	cd $(HTTPD_SRC) && ./configure --prefix=$(abspath $(INSTALL_DIR)) \
		--with-mpm=prefork --enable-mpms-shared='prefork worker event' \
		--enable-ssl
	cd $(HTTPD_SRC) && $(MAKE)
	cd $(HTTPD_SRC) && $(MAKE) install

$(HTTPD_SRC)/configure: $(HTTPD_SRC).tar.gz
	tar --touch -xzf $<

$(HTTPD_SRC).tar.gz:
	$(GRAPHENEDIR)/Scripts/download --output $@ --sha256 $(HTTPD_CHECKSUM) $(foreach mirror,$(HTTPD_MIRRORS),--url $(mirror)httpd/$(HTTPD_SRC).tar.gz)

# Apache dependencies (generate from ldd):
#
# For SGX, the manifest needs to list all the libraries loaded during the
# execution, so that the signer can include the file checksums.
#
# The dependencies are generated from the ldd results.

# We need to replace Glibc dependencies with Graphene-specific Glibc. The Glibc
# binaries are already listed in the manifest template, so we can skip them
# from the ldd results
GLIBC_DEPS = linux-vdso /lib64/ld-linux-x86-64 libc libm librt libdl libpthread

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

# Listing all the Apache dependencies, besides Glibc libraries
.INTERMEDIATE: httpd-ldd
httpd-ldd: httpd-modules $(INSTALL_DIR)/bin/httpd
	@for F in $(INSTALL_DIR)/bin/httpd `cat httpd-modules`; do \
		ldd $$F >> $@ || exit 1; done

.INTERMEDIATE: httpd-deps
httpd-deps: httpd-ldd
	@cat $< | awk '{if ($$2 =="=>") {split($$1,s,/\./); print s[1]}}' \
		| sort | uniq | grep -v -x $(patsubst %,-e %,$(GLIBC_DEPS)) > $@

# Generating manifest rules for Apache modules
.INTERMEDIATE: httpd-trusted-mods
httpd-trusted-mods: httpd-modules
	@for F in `cat httpd-modules`; do \
		N=`echo $$F | awk '{n=split($$1,s,/\/|\./); print s[n-1]}'`; \
		echo -n "sgx.trusted_files.$$N = \\\"file:$$F\\\"\\\\n"; \
	done > $@

# Generating manifest rules for Apache dependencies
.INTERMEDIATE: httpd-trusted-libs
httpd-trusted-libs: httpd-deps httpd-modules $(INSTALL_DIR)/bin/httpd
	@HTTPD_LIBS="$(INSTALL_DIR)/bin/httpd `cat httpd-modules`" && \
	for F in `cat httpd-deps`; do \
		P=`ldd $$HTTPD_LIBS | grep $$F | awk '{print $$3; exit}'`; \
		N=`echo $$F | tr --delete '-'`; \
		echo -n "sgx.trusted_files.$$N = \\\"file:$$P\\\"\\\\n"; \
	done > $@

httpd.manifest: httpd.manifest.template httpd-trusted-mods httpd-trusted-libs
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
	    -e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
	    -e 's|$$(INSTALL_DIR)|'"$(INSTALL_DIR)"'|g' \
	    -e 's|$$(INSTALL_DIR_ABSPATH)|'"$(abspath $(INSTALL_DIR))"'|g' \
	    -e 's|$$(HTTPD_TRUSTED_MODS)|'"`cat httpd-trusted-mods`"'|g' \
	    -e 's|$$(HTTPD_TRUSTED_LIBS)|'"`cat httpd-trusted-libs`"'|g' \
	    -e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
	    $< > $@

# Generating the SGX-specific manifest (httpd.manifest.sgx), the enclave signature,
# and the token for enclave initialization.
httpd.manifest.sgx: httpd.manifest $(INSTALL_DIR)/bin/httpd \
		$(INSTALL_DIR)/conf/httpd-graphene.conf \
		$(INSTALL_DIR)/conf/extra/httpd-ssl-graphene.conf \
		$(TEST_DATA) \
		$(INSTALL_DIR)/conf/server.crt \
		| httpd
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-exec httpd \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest httpd.manifest -output $@

httpd.sig: httpd.manifest.sgx

httpd.token: httpd.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@ -sig $<

httpd: $(INSTALL_DIR)/bin/httpd
	ln -s $< $@

pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/pal_loader $@

# Apache configuration and test data

.PHONY: config
config: $(INSTALL_DIR)/conf/httpd-graphene.conf $(INSTALL_DIR)/conf/extra/httpd-ssl-graphene.conf

$(INSTALL_DIR)/conf/httpd-graphene.conf: $(INSTALL_DIR)/conf/httpd.conf
	sed -e "s|^Listen |#Listen |g" \
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
	sed -e "s|^Listen 443|Listen 127.0.0.1:8443|g" \
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

# Commands for running Apache
#
# - make start-native-server:
#     Start the Apache server natively in the foreground (using the Prefork MPM)
#
# - make start-graphene-server:
#     Start the Apache server under Graphene in the foreground (using the Prefork MPM)
#
# - make start-native-multithreaded-server:
#     Start the Apache server natively in the foreground (using the Worker MPM)
#
# - make start-graphene-multithreaded-server:
#     Start the Apache server under Graphene in the foreground (using the Worker MPM)
#
# - make clean-server:
#      Clean up the PID files generated by Apache

.PHONY: clean-server
clean-server:
	$(RM) $(INSTALL_DIR)/logs/httpd-$(LISTEN_HOST)-$(LISTEN_PORT).pid

.PHONY: start-native-server
start-native-server: all clean-server
	@echo "Listen on $(LISTEN_HOST):$(LISTEN_PORT)"
	$(PREFIX) $(INSTALL_DIR)/bin/httpd -D FOREGROUND \
		-f conf/httpd-graphene.conf \
		-C "LoadModule mpm_prefork_module modules/mod_mpm_prefork.so" \
		-C "Listen $(LISTEN_HOST):$(LISTEN_PORT)" \
		-C "ServerName $(LISTEN_HOST)" \
		-C "PidFile logs/httpd-$(LISTEN_HOST)-$(LISTEN_PORT).pid"

.PHONY: start-graphene-server
start-graphene-server: all clean-server
	@echo "Listen on $(LISTEN_HOST):$(LISTEN_PORT)"
	$(PREFIX) ./pal_loader ./httpd -D FOREGROUND \
		-f conf/httpd-graphene.conf \
		-C "LoadModule mpm_prefork_module modules/mod_mpm_prefork.so" \
		-C "Listen $(LISTEN_HOST):$(LISTEN_PORT)" \
		-C "ServerName $(LISTEN_HOST)" \
		-C "PidFile logs/httpd-$(LISTEN_HOST)-$(LISTEN_PORT).pid"

.PHONY: start-native-multithreaded-server
start-native-multithreaded-server: all clean-server
	@echo "Listen on $(LISTEN_HOST):$(LISTEN_PORT)"
	$(PREFIX) $(INSTALL_DIR)/bin/httpd -D FOREGROUND \
		-f conf/httpd-graphene.conf \
		-C "LoadModule mpm_worker_module modules/mod_mpm_worker.so" \
		-C "Listen $(LISTEN_HOST):$(LISTEN_PORT)" \
		-C "ServerName $(LISTEN_HOST)" \
		-C "PidFile logs/httpd-$(LISTEN_HOST)-$(LISTEN_PORT).pid"

.PHONY: start-graphene-multithreaded-server
start-graphene-multithreaded-server: all clean-server
	@echo "Listen on $(LISTEN_HOST):$(LISTEN_PORT)"
	$(PREFIX) ./pal_loader ./httpd -D FOREGROUND \
		-f conf/httpd-graphene.conf \
		-C "LoadModule mpm_worker_module modules/mod_mpm_worker.so" \
		-C "Listen $(LISTEN_HOST):$(LISTEN_PORT)" \
		-C "ServerName $(LISTEN_HOST)" \
		-C "PidFile logs/httpd-$(LISTEN_HOST)-$(LISTEN_PORT).pid"

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig httpd pal_loader OUTPUT result-* httpd-ldd \
	      httpd-modules tmp

.PHONY: distclean
distclean: clean
	$(RM) -r $(HTTPD_SRC).tar.gz $(HTTPD_SRC) $(INSTALL_DIR)
	$(RM) ssl/server.* ssl/ca.*
