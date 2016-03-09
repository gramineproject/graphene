NPROCS := 1
OS := $(shell uname -s)
ifeq ($(OS),Linux)
	NPROCS := $(shell grep -c ^processor /proc/cpuinfo)
endif

TEST_CLASS = $(patsubst %.java,%,$(wildcard classes/*.java))

target = java test java.manifest
exec_target = java.manifest
clean-extra = clean-classes

level = ../../
include ../../Makefile

USE_UBUNTU_SRC = no
VERSION := 7

ifeq ($(USE_UBUNTU_SRC),yes)

ifeq ($(JRE_VERSION),7)
JAVA_DIR = openjdk-7-7u79-2.5.5
JAVA_HOME = openjdk-7-jre
endif

ifeq ($(JRE_VERSION),6)
JAVA_DIR = openjdk-6-6b32-1.13.4
JAVA_HOME = openjdk-6-jre
endif

ifndef JAVA_DIR
$(error Unknown JRE Version)
endif

INSTALL_DIR = $(JAVA_DIR)/openjdk.build
JRE_DIR = $(INSTALL_DIR)/j2sdk-image/jre
JDK_DIR = $(INSTALL_DIR)/j2sdk-image
JAVAC = $(JDK_DIR)/bin/javac
TARGET = $(JAVA_HOME)/bin/java $(JAVAC)

%/Makefile: %.tar.gz
	tar -xzf $<
	cd $(dir $@) && ./configure \
		--prefix=$(shell readlink -f $(INSTALL_DIR)) \
		--disable-docs \
		--enable-optimizations

$(JRE_DIR)/bin/java $(JAVAC): $(JAVA_DIR)/Makefile
	cd $(JAVA_DIR) && make -j$(NPROCS) all $(MAKE_FLAGS)

$(JAVA_HOME)/bin/java: $(JRE_DIR)/bin/java
	rm -rf $(JAVA_HOME)
	cp -rf $(JRE_DIR) $(JAVA_HOME)
	find $(JAVA_HOME) -type f -executable -exec strip --strip-debug {} \;

distclean: clean
	rm -rf $(INSTALL_DIR) $(JAVA_HOME)

else # USE_UBUNTU_SRC = no

ifeq ($(VERSION),7)

ICEDTEA_URL = http://icedtea.wildebeest.org/download/drops/icedtea7/2.7.0/
JAVA_DIR = openjdk-7
JAVA_SRC = $(JAVA_DIR) $(JAVA_DIR)/hotspot $(JAVA_DIR)/jdk $(JAVA_DIR)/jdk/src/share/lib/security/nss.cfg
JAVA_HOME = openjdk-7-jre

$(JAVA_DIR): openjdk.tar.bz2
	tar -xjf $<
	rm -rf $@
	mv $(shell tar -tjf $< | sed -e 's@/.*@@' | head -n 1) $@

$(JAVA_DIR)/hotspot: hotspot.tar.bz2 | $(JAVA_DIR)
	tar -xjf $<
	rm -rf $@
	mv $(shell tar -tjf $< | sed -e 's@/.*@@' | head -n 1) $@

$(JAVA_DIR)/jdk: jdk.tar.bz2 | $(JAVA_DIR)
	tar -xjf $<
	rm -rf $@
	cd $(shell tar -tjf $< | sed -e 's@/.*@@' | head -n 1) && patch -p1 < ../smaller-jdk.patch
	mv $(shell tar -tjf $< | sed -e 's@/.*@@' | head -n 1) $@

openjdk.tar.bz2 hotspot.tar.bz2 jdk.tar.bz2:
	wget $(ICEDTEA_URL)$@

$(JAVA_DIR)/jdk/src/share/lib/security/nss.cfg: $(JAVA_DIR)/jdk/src/share/lib/security/nss.cfg.in | $(JAVA_DIR)/jdk
	sed 's:@NSS_LIBDIR@:/usr/lib/x86_64-linux-gnu:g' $< > $@

endif

HOST_JAVA_HOME=$(subst /jre/bin/java,,$(shell readlink -f $(shell which java)))
INSTALL_DIR = $(JAVA_DIR)/build/linux-amd64
JRE_DIR = $(INSTALL_DIR)/j2sdk-image/jre
JDK_DIR = $(INSTALL_DIR)/j2sdk-image
JAVAC = $(JDK_DIR)/bin/javac
TARGET = $(JAVA_HOME)/bin/java $(JAVAC)

$(JRE_DIR)/bin/java $(JAVAC): $(JAVA_SRC)
	cd $(JAVA_DIR) && \
		make \
		ALT_BOOTDIR=$(HOST_JAVA_HOME) \
		ALT_JDK_IMPORT_PATH=$(HOST_JAVA_HOME) \
		ANT=/usr/bin/ant \
		INSANE="true" \
		FT2_CFLAGS=$(shell pkg-config --cflags freetype2) \
		FT2_LIBS=$(shell pkg-config --libs freetype2) \
		STATIC_CXX="false" \
		EXTRA_CFLAGS="-fPIC" \
		NO_DOCS="true" \
		BUILD_HEADLESS_ONLY="true" \
		BUILD_HOTSPOT="true" BUILD_JDK="true" \
		BUILD_LANGTOOLS="false" \
		BUILD_JAXP="false" BUILD_JAXWS="false" BUILD_CORBA="false" \
		HOTSPOT_BUILD_JOBS="$(NPROCS)" \
		TEST_IN_BUILD="false" \
		product_build

$(JAVA_HOME)/bin/java: $(JRE_DIR)/bin/java
	rm -rf $(JAVA_HOME)
	cp -rf $(JRE_DIR) $(JAVA_HOME)
	find $(JAVA_HOME) -type f -executable -exec strip --strip-debug {} \;

distclean: clean
	rm -rf $(JAVA_DIR) $(JAVA_HOME)

endif

java: $(TARGET)
test: $(addsuffix .class,$(TEST_CLASS))

%.manifest: %.manifest.template
	$(MAKE) -C .. openjdk/$@ appdir=openjdk/ \
		extra_rules="-e 's:\\\$$\$$(JAVA_HOME):$(JAVA_HOME):g'"

java_home:
	@echo $(JAVA_HOME)

%.class: %.java $(JAVAC)
	$(JAVAC) $<

clean-classes:
	rm -f $(addsuffix .class,$(TEST_CLASS))
