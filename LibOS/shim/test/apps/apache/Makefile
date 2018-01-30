HOST ?= $(firstword $(shell ifconfig | grep 'inet addr:' | grep -v '127.0.0.1' -m 1 | cut -d: -f2))
PORT ?= 8001

NPROCS := 1
OS := $(shell uname -s)
ifeq ($(OS),Linux)
	NPROCS := $(shell grep -c ^processor /proc/cpuinfo)
endif

PREFORK_WORKERS := $(shell expr $(NPROCS) + 1)

HTTPD_DIR = httpd-2.4.3
APR_DIR = apr-1.4.6
APRUTIL_DIR = apr-util-1.5.1
PHP_DIR = php-5.6.6

INSTALL_DIR = $(PWD)/obj
SRC_DIRS = $(HTTPD_DIR) $(APR_DIR) $(APRUTIL_DIR) $(PHP_DIR)
HTDOC=$(INSTALL_DIR)/htdocs

exec_target = httpd.manifest

target = build-apache build-modules build-conf test-data

clean-extra = clean-apache

extra_rules = -e 's:\$$(HOST):$(HOST):g' -e 's:\$$(PORT):$(PORT):g'

level = ../../
include ../../Makefile

.PHONY: build-apache build-modules build-conf

build-apache: $(INSTALL_DIR)/bin/httpd $(INSTALL_DIR)/modules/libphp5.so

ifeq ($(DEBUG),1)
MAKE_FLAGS = CC="gcc -g"
APXS_FLAGS = -S CC="gcc -g"
endif

%: %.tar.gz
	tar -xmzf $<

%: %.tar.bz2
	tar -xmjf $<

$(INSTALL_DIR)/lib/libapr-1.so.0: $(APR_DIR)
	#cd $< && patch -p1 < ../disable-epoll.patch
	cd $< && ./configure --prefix=$(INSTALL_DIR)
	cd $< && $(MAKE) -j$(NPROCS) $(MAKE_FLAGS)
	cd $< && $(MAKE) install

$(INSTALL_DIR)/lib/libaprutil-1.so.0: $(APRUTIL_DIR) $(INSTALL_DIR)/lib/libapr-1.so.0
	cd $< && ./configure --prefix=$(INSTALL_DIR) --with-apr=$(INSTALL_DIR)
	cd $< && $(MAKE) -j$(NPROCS) $(MAKE_FLAGS)
	cd $< && $(MAKE) install

$(INSTALL_DIR)/bin/httpd $(INSTALL_DIR)/bin/apxs: $(INSTALL_DIR)/lib/libapr-1.so.0 $(INSTALL_DIR)/lib/libaprutil-1.so.0
	[ -d $(HTTPD_DIR) ] || tar -xzf $(HTTPD_DIR).tar.gz
	[ -f $(HTTPD_DIR)/Makefile ] || ( \
	cd $(HTTPD_DIR) && ./configure --prefix=$(INSTALL_DIR) --with-apr=$(INSTALL_DIR) \
	--with-apr-util=$(INSTALL_DIR) --with-mpm=prefork)
	cd $(HTTPD_DIR) && $(MAKE) -j$(NPROCS) $(MAKE_FLAGS)
	cd $(HTTPD_DIR) && $(MAKE) install

$(INSTALL_DIR)/modules/libphp5.so: $(PHP_DIR) $(INSTALL_DIR)/bin/apxs
	cd $< && ./configure --prefix=$(INSTALL_DIR) --with-apxs2=$(INSTALL_DIR)/bin/apxs \
	--disable-cgi --disable-cli --disable-soap
	cd $< && $(MAKE) -j$(NPROCS) $(MAKE_FLAGS)
	cd $< && $(MAKE) install

build-modules: $(INSTALL_DIR)/modules/mod_auth_basic_sandbox.so

$(INSTALL_DIR)/modules/mod_auth_basic_sandbox.so: mod_auth_basic_sandbox.c $(INSTALL_DIR)/bin/apxs
	$(INSTALL_DIR)/bin/apxs $(APXS_FLAGS) \
		-S CFLAGS="-I$(SHIMDIR)/../include" \
		-S LDFLAGS="-L. -l:$(RUNTIME)/liblibos.so.1" -c -i -A $<

build-conf:
	[ -f $(INSTALL_DIR)/conf/httpd.conf.old ] || \
		mv $(INSTALL_DIR)/conf/httpd.conf $(INSTALL_DIR)/conf/httpd.conf.old
	sed -e "s/Listen 80/#Listen 80/g" \
	    -e "s/User daemon/#User root/g" \
	    -e "s/Group daemon/#Group root/g" \
	    -e "s/#EnableMMAP off/EnableMMAP off/g" \
	    -e "s/#EnableSendfile on/EnableSendfile on/g" \
	    -e "s/DirectoryIndex index.html/DirectoryIndex index.html index.php/g" \
	    -e "s/^[ ]*CustomLog/#CustomLog/g" \
	$(INSTALL_DIR)/conf/httpd.conf.old > $(INSTALL_DIR)/conf/httpd.conf.new
	echo "\n\
<IfModule mpm_prefork_module>\n\
    StartServers             $(PREFORK_WORKERS)\n\
    MinSpareServers          1\n\
    MaxSpareServers          $(PREFORK_WORKERS)\n\
    MaxConnectionsPerChild   0\n\
</IfModule>\n" >> $(INSTALL_DIR)/conf/httpd.conf.new
	echo "\n\
<IfModule mime_module>\n\
    AddType application/x-httpd-php .php\n\
</IfModule>\n" >> $(INSTALL_DIR)/conf/httpd.conf.new
	cd $(INSTALL_DIR)/conf && ln -sf httpd.conf.new httpd.conf

clean-server:
	rm -f $(INSTALL_DIR)/logs/httpd-$(HOST)-$(PORT).pid

start-native-server: clean-server
	@echo "Listen on $(HOST):$(PORT)"
	$(PREFIX) $(INSTALL_DIR)/bin/httpd -D FOREGROUND -C "ServerName $(HOST)" -C "Listen $(HOST):$(PORT)" -C "PidFile logs/httpd-$(HOST)-$(PORT).pid"

start-graphene-server: clean-server
	@echo "Listen on $(HOST):$(PORT)"
	$(PREFIX) ./httpd.manifest -D FOREGROUND -C "ServerName $(HOST)" -C "Listen $(HOST):$(PORT)" -C "PidFile logs/httpd-$(HOST)-$(PORT).pid"

random-data = $(foreach n,1 2 3 4 5 6 7 8 9 10,2K.$n.html) \
	      $(foreach n,1 2 3 4 5,10K.$n.html) \
	      $(foreach n,1 2 3 4 5,100K.$n.html) \
	      $(foreach n,1 2 3,1M.$n.html) \
	      $(foreach n,1 2 3,10M.$n.html) \
	      $(foreach n,1 2 3,100.$n.html)

test-data = $(HTDOC)/oscar-web $(HTDOC)/oscar-web-static \
	    $(addprefix $(HTDOC)/random/,$(random-data)) \
	    $(HTDOC)/auth/secret.html $(HTDOC)/auth/.htaccess

$(HTDOC)/%: $(PWD)/../web-data/%.tar.gz
	[ -d "$@" ] || (mkdir -p $@ && cd $(HTDOC) && tar -xzf $^)

$(HTDOC)/random/%.html:
	[ -d $(HTDOC)/random ] || mkdir -p $(HTDOC)/random
	dd if=/dev/urandom of=$@ count=1 bs=$(basename $(basename $(notdir $@)))

$(HTDOC)/auth:
	mkdir -p $@

$(HTDOC)/auth/secret.html: $(HTDOC)/auth
	echo "This is the secret" > $@

$(HTDOC)/auth/.htpasswd: $(INSTALL_DIR)/bin/htpasswd $(HTDOC)/auth
	$< -b -c $@ test test

$(HTDOC)/auth/.htaccess: $(HTDOC)/auth/.htpasswd
	echo "AuthName \"Login\"\n\
AuthType Basic\n\
AuthUserFile $(HTDOC)/auth/.htpasswd\n\
AuthGroupFile /dev/null\n\
require user test" > $@

test-data: $(test-data)

distclean: clean
	rm -rf $(INSTALL_DIR) $(SRC_DIRS)

clean-apache:
	rm -rf $(test-data) $(addprefix mod_auth_basic_sandbox,.so .la .lo .o .slo)
