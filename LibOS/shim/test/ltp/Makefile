include makevars.mk

target = $(INSTALLDIR)/INSTALL_SUCCESS build-manifest
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

$(SRCDIR)/configure: $(SRCDIR)/Makefile
	$(MAKE) -C $(SRCDIR) autotools

.SECONDARY: $(BUILDDIR)/BUILD_SUCCESS
$(BUILDDIR)/BUILD_SUCCESS: $(SRCDIR)/configure
	# Out-of-tree build steps were taken from ltp/INSTALL.
	# The instructions below assume that SRCDIR and BUILDDIR are absolute.
	mkdir -p $(BUILDDIR)
	# Kernel module tests are not meaningful for our LibOS and building them causes troubles on
	# incompatible host kernels.
	cd $(BUILDDIR) && $(SRCDIR)/configure --without-modules --prefix $(INSTALLDIR)
	$(MAKE) -C $(BUILDDIR) -f $(SRCDIR)/Makefile top_srcdir=$(SRCDIR) top_builddir=$(BUILDDIR) all
	touch $@

.SECONDARY: $(INSTALLDIR)/INSTALL_SUCCESS
$(INSTALLDIR)/INSTALL_SUCCESS: $(BUILDDIR)/BUILD_SUCCESS
	$(MAKE) -C $(BUILDDIR) -f $(SRCDIR)/Makefile top_srcdir=$(SRCDIR) top_builddir=$(BUILDDIR) SKIP_IDCHECK=1 install
	ln -sf $(abspath Makefile.testcases) $(TESTCASEDIR)/Makefile
	touch $@

.PHONY: build-manifest
build-manifest: $(TESTCASEDIR)/manifest.template $(INSTALLDIR)/INSTALL_SUCCESS
	$(MAKE) -C $(TESTCASEDIR)

$(TESTCASEDIR)/manifest.template: manifest.template $(INSTALLDIR)/INSTALL_SUCCESS
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

%.xml: $(CFG) $(target) $(INSTALLDIR)/INSTALL_SUCCESS
	./contrib/conf_lint.py $(CFG) --scenario $(LTPSCENARIO)
	./runltp_xml.py $(RUNLTPOPTS) $(foreach cfg,$(CFG),-c $(cfg)) $(LTPSCENARIO) -O $@

.PHONY: clean-build
clean-build:
	$(MAKE) -C $(SRCDIR) clean
	$(RM) -r $(BUILDDIR) $(INSTALLDIR) ltp*.xml
