JAVA_HOME = /usr/lib/jvm/java-7-openjdk-amd64
AVIAN_SRC = avian
AVIAN_INSTALL = $(AVIAN_SRC)/build/linux-x86_64

manifests = avian.manifest

target = $(AVIAN_INSTALL)/avian
exec_target = $(manifests)

clean-extra += clean-tmp

level = ../../
include ../../Makefile

$(AVIAN_INSTALL)/avian: $(AVIAN_SRC)/makefile
	cd $(AVIAN_SRC) && $(MAKE)

$(AVIAN_SRC)/makefile: avian.tgz
	tar -xzf $<

clean-tmp:
	rm -f avian.manifest.sgx

distclean: clean
	rm -rf $(AVIAN_SRC)
