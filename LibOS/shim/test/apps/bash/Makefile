BASH_DIR = bash-4.1

manifests = $(addsuffix .manifest,bash ls cp rm cat date)
exec_target = $(manifests)

level = ../../
include ../../Makefile

$(bash_src): $(BASH_DIR).tar.gz
	tar -xmzf $<

$(bash_src)/bash: $(BASH_DIR)
	cd $(BASH_DIR) && ./configure --without-gnu-malloc
	cd $(BASH_DIR) && $(MAKE) CC="gcc -g"

bash-local: $(BASH_DIR)/bash
	cp $< bash-local

regression:
	@echo "\n\nBuilding Bash Manifests"
	@$(MAKE) >> /dev/null 2>&1

	@echo "\n\nRun bash_test.sh:"
	-./bash.manifest bash_test.sh 2
	-grep -q "hello 2" OUTPUT
	@rm OUTPUT



distclean: clean-manifests
	rm -rf $(bash_src)
	rm -rf bash result $(test_targets)
