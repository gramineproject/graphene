manifest = R$(if $(LOCAL),-local,).manifest

target =
exec_target = $(manifest)
clean-extra = clean-local

level = ../../
include ../../Makefile

local:
	make LOCAL=1

R_SRC = R-3.1.2
R_INSTALL = $(R_SRC)/build

$(R_INSTALL)/lib/R/bin/exec/R: $(R_SRC)/Makefile
	cd $(R_SRC) && $(MAKE)
	cd $(R_SRC) && $(MAKE) install

$(R_SRC)/Makefile: $(R_SRC)/configure
	cd $(R_SRC) && \
		./configure --prefix=$(shell readlink -f $(R_INSTALL))

$(R_SRC)/configure: $(R_SRC).tar.gz
	tar -xzf $<

test_targets =

test: all $(test_targets)

R.manifest: R.manifest.template
	$(MAKE) -C .. r/$@ appdir=r/

R-local.manifest: R-local.manifest.template $(R_INSTALL)/lib/R/bin/exec/R
	$(MAKE) -C .. r/$@ appdir=r/ \
		extra_rules="-e 's:\\\$$\$$(RDIR):$(shell readlink -f $(R_INSTALL)/lib/R)/:g'"

distclean: clean
	rm -rf $(R_SRC)

clean-local:
ifneq ($(LOCAL),1)
	make clean LOCAL=1
endif
