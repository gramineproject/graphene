include makevars.mk

ifeq ($(TESTDIR), "")
	target = src-configure build-ltp link-pal build-manifest
else
	target = src-configure build-lib build-test link-pal build-manifest
endif
exec_target =

clean-extra += clean-build

include ../../../../Scripts/Makefile.rules
include ../../../../Scripts/Makefile.configs
# Make ARCH_LIBDIR visible in Makefile.Test
export ARCH_LIBDIR
include Makefile.Test

ifeq ($(BUILD_VERBOSE),1)
	RUNLTPOPTS += -v
endif

$(SRCDIR)/Makefile:
	$(error "$(SRCDIR) is empty. Please run `git submodule update --init $(SRCDIR)` or download the LTP source code (https://github.com/linux-test-project/ltp) into $(SRCDIR).")

.PHONY: make-autotools
make-autotools: $(SRCDIR)/Makefile
	$(MAKE) -C $(SRCDIR) autotools

.PHONY: src-configure
src-configure: make-autotools
	# Out-of-tree build steps were taken from ltp/INSTALL.
	# The instructions below assume that SRCDIR and BUILDDIR are absolute.
	mkdir -p $(BUILDDIR)
	mkdir -p $(INSTALLDIR)
	# Kernel module tests are not meaningful for our LibOS and building them causes troubles on
	# incompatible host kernels.
	cd $(BUILDDIR) && $(SRCDIR)/configure --without-modules --prefix $(INSTALLDIR)

.PHONY: build-ltp
build-ltp: 
	mkdir -p $(BUILDDIR)
	$(MAKE) -C $(BUILDDIR) -f $(SRCDIR)/Makefile top_srcdir=$(SRCDIR) top_builddir=$(BUILDDIR) all
	touch $(BUILDDIR)/BUILD_SUCCESS.txt
	$(MAKE) -C $(BUILDDIR) -f $(SRCDIR)/Makefile top_srcdir=$(SRCDIR) top_builddir=$(BUILDDIR) SKIP_IDCHECK=1 install
	touch $(INSTALLDIR)/INSTALL_SUCCESS.txt

.PHONY: build-lib
build-lib: 
	$(MAKE) -C $(BUILDDIR)/lib -f $(SRCDIR)/lib/Makefile top_srcdir=$(SRCDIR) top_builddir=$(BUILDDIR) all
	touch $(BUILDDIR)/BUILD_SUCCESS.txt

.PHONY: build-test
build-test:
	mkdir -p $(BUILDDIR)/$(TESTDIR)
	mkdir -p $(TESTCASEDIR)
	$(MAKE) -C $(BUILDDIR)/$(TESTDIR) -f $(SRCDIR)/$(TESTDIR)/Makefile top_srcdir=$(SRCDIR) top_builddir=$(BUILDDIR) all
	$(MAKE) -C $(BUILDDIR)/$(TESTDIR) -f $(SRCDIR)/$(TESTDIR)/Makefile top_srcdir=$(SRCDIR) top_builddir=$(BUILDDIR) SKIP_IDCHECK=1 install
	touch $(INSTALLDIR)/INSTALL_SUCCESS.txt

.PHONY: clean-test
clean-test:
	$(MAKE) -C $(BUILDDIR)/$(TESTDIR) -f $(SRCDIR)/$(TESTDIR)/Makefile top_srcdir=$(SRCDIR) top_builddir=$(BUILDDIR) clean

.PHONY: link-pal
link-pal:
	ln -sf $(call relative-to,$(TESTCASEDIR),../../../Runtime/pal_loader) $(TESTCASEDIR)/pal_loader
	ln -sf $(abspath Makefile.testcases) $(TESTCASEDIR)/Makefile

.PHONY: build-manifest
build-manifest: $(TESTCASEDIR)/manifest.template
	$(MAKE) -C $(TESTCASEDIR)


$(TESTCASEDIR)/manifest.template: manifest.template
	sed -e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
		$< > $@

.PHONY: sgx-tokens
sgx-tokens: build-manifest
	$(MAKE) -C $(TESTCASEDIR) $@

.PHONY: regression
regression:
ifeq ($(SGX),"1")
	$(RM) ltp-sgx.xml
	$(MAKE) ltp-sgx.xml
else
	$(RM) ltp.xml
	$(MAKE) ltp.xml
endif

ltp.xml: CFG = ltp.cfg
ltp-sgx.xml: CFG = ltp.cfg ltp-sgx.cfg ltp-bug-1075.cfg

%.xml: $(CFG) $(LTPSCENARIO) $(target)
	./contrib/conf_lint.py $(CFG) --scenario $(LTPSCENARIO)
	./runltp_xml.py $(RUNLTPOPTS) $(foreach cfg,$(CFG),-c $(cfg)) $(LTPSCENARIO) -O $@

.PHONY: clean-build
clean-build:
	$(MAKE) -C $(SRCDIR) clean
	$(RM) -r $(BUILDDIR) $(INSTALLDIR) ltp*.xml
