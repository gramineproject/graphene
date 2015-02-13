apps = lmbench gcc busybox lighttpd bash apache make

targets = pal pal_sec
clean-extra = clean-all

level = ../
include ../Makefile

manifest_rules = \
	-e 's:\$$(PAL):$(shell pwd)/pal_loader:g' \
	-e 's:\$$(PWD):$(shell pwd)/$(appdir):g' \
	-e 's:\$$(BIN):$(subst .manifest,,$(notdir $@)):g' \
	-e 's:\$$(SHIMPATH):$(shell readlink -f ../../src/libsysdb.so):g' \
	-e 's:\$$(GLIBCDIR):$(shell readlink -f $(glibc_dir)):g' \
	$(extra_rules)

%.manifest: %.manifest.template
	rm -f $@ $@.backup
	sed $(manifest_rules) $< >$@
	chmod +x $@

build-all:
	for f in $(apps); do (cd $$f; make $(DEBUG) || true; cd ..); done

clean-all:
	for f in $(apps); do (cd $$f; make clean; cd ..); done
