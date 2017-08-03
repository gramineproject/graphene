BASH_DIR = bash-4.1

manifests = $(patsubst %.manifest.template,%.manifest,$(wildcard *.manifest.template))
exec_target = $(manifests)

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
