BASH_DIR = bash-4.1

manifests = $(addsuffix .manifest,bash ls cp rm)
exec_target = $(manifests)

extra_rules = -e 's:\$$(PAL):../pal_loader:g'

level = ../../
include ../../Makefile

$(bash_src): $(BASH_DIR).tar.gz
	tar -xzf $<

$(bash_src)/bash: $(BASH_DIR)
	cd $(BASH_DIR) && ./configure --without-gnu-malloc
	cd $(BASH_DIR) && $(MAKE) CC="gcc -g"

bash-local: $(BASH_DIR)/bash
	cp $< bash-local

distclean: clean-manifests
	rm -rf $(bash_src)
	rm -rf bash result $(test_targets)
