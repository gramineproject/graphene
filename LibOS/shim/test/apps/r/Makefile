R_SRC = R-3.1.2
R_INSTALL = $(R_SRC)/build

manifests = R.manifest $(if $(wildcard R-local),R-local.manifest,)

target =
exec_target = $(manifests)

extra_rules = \
	-e 's:\$$(PAL):../pal_loader:g' \
	-e 's:\$$(RDIR):$(R_INSTALL)/lib/R/:g'

level = ../../
include ../../Makefile

$(R_INSTALL)/lib/R/bin/exec/R: $(R_SRC)/Makefile
	cd $(R_SRC) && $(MAKE)
	cd $(R_SRC) && $(MAKE) install

$(R_SRC)/Makefile: $(R_SRC)/configure
	cd $(R_SRC) && \
		./configure --prefix=$(shell readlink -f $(R_INSTALL))

$(R_SRC)/configure: $(R_SRC).tar.gz
	tar -xzf $<

distclean: clean
	rm -rf $(R_SRC)
