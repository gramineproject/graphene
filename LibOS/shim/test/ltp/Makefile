include makevars.mk

target = $(TESTCASEDIR)/pal_loader build-manifest
exec_target =

clean-extra = clean-build

include ../../../../Scripts/Makefile.configs
include Makefile.Test

$(SRCDIR)/Makefile:
	$(error "$(SRCDIR) is empty. Please run `git submodule update --init $(SRCDIR)` or download the LTP source code (https://github.com/linux-test-project/ltp) into $(SRCDIR).")

$(SRCDIR)/configure: $(SRCDIR)/Makefile
	cd $(SRCDIR) && $(MAKE) autotools

$(BUILDDIR)/runltp: $(SRCDIR)/configure
	cd $(SRCDIR) && ./configure
	cd $(SRCDIR) && $(MAKE) FILTER_OUT_DIRS=delete_module -C testcases/kernel/syscalls
	cd $(SRCDIR) && $(MAKE) FILTER_OUT_DIRS=delete_module "DESTDIR=$(PWD)" -C runtest SKIP_IDCHECK=1 install
	cd $(SRCDIR) && $(MAKE) FILTER_OUT_DIRS=delete_module "DESTDIR=$(PWD)" -C testcases/kernel/syscalls SKIP_IDCHECK=1 install

$(TESTCASEDIR)/pal_loader: $(BUILDDIR)/runltp
	ln -sf $(call relative-to,$(dir $@),../../Runtime/pal_loader) $@

build-manifest: $(TESTCASEDIR)/manifest.template $(TESTCASEDIR)/Makefile
	cd $(TESTCASEDIR) && $(MAKE)

$(TESTCASEDIR)/manifest.template: manifest.template
	sed -e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
		$< > $@

$(TESTCASEDIR)/Makefile: Makefile.testcases
	ln -sf $(abspath $<) $@

.PHONY: sgx-tokens
sgx-tokens: build-manifest
	$(MAKE) -C $(TESTCASEDIR) $@

.PHONY: regression
regression:
	if test "$(SGX)" -eq 1; then \
		$(RM) ltp-sgx.xml; \
		$(MAKE) ltp-sgx.xml; \
	else \
		$(RM) ltp.xml; \
		$(MAKE) ltp.xml; \
	fi

%.xml: %.cfg ltp-bug-1248.cfg ltp-bug-1075.cfg $(LTPSCENARIO) $(target)
	./contrib/conf_lint.py < $<
	./runltp_xml.py $(RUNLTPOPTS) -c $< $(LTPSCENARIO) > $@

ltp-sgx.xml: RUNLTPOPTS += -c ltp-bug-1075.cfg

clean-build:
	cd $(SRCDIR) && $(MAKE) clean
	rm -rf opt ltp*.xml
