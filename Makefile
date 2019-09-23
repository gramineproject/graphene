SYS ?= $(shell gcc -dumpmachine)
export SYS

targets = all clean format test

.PHONY: $(targets)
$(targets):
	cd Pal && cmake . && $(MAKE) $(subst all,install,$@)
	$(MAKE) -C LibOS $@
	$(MAKE) -C Runtime $@
