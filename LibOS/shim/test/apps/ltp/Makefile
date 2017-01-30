SRCDIR = ltp-master
BUILDDIR = opt/ltp
TESTCASEDIR = $(BUILDDIR)/testcases/bin

target = $(BUILDDIR)/bin/run_in_graphene.awk $(TESTCASEDIR)/pal_loader $(TESTCASEDIR)/manifest
exec_target =

clean-extra = clean-build

level = ../../
include ../../Makefile

master.zip:
	wget https://github.com/linux-test-project/ltp/archive/master.zip

$(SRCDIR)/configure: master.zip
	unzip master.zip
	cd $(SRCDIR) && make autotools

$(BUILDDIR)/runltp: $(SRCDIR)/configure
	cd $(SRCDIR) && ./configure
	cd $(SRCDIR) && make all
	cd $(SRCDIR) && make "DESTDIR=$(PWD)" SKIP_IDCHECK=1 install
	patch -d $(dir $@) < runltp.patch

$(BUILDDIR)/bin/run_in_graphene.awk: run_in_graphene.awk $(BUILDDIR)/runltp
	cp -f $< $@

$(TESTCASEDIR)/pal_loader: $(BUILDDIR)/runltp
	ln -sf $(call relative-to,$(dir $@),../../pal_loader) $@

$(TESTCASEDIR)/manifest.template: manifest.template
	cp -f $< $@

clean-build:
	rm -rf $(BUILDDIR)
