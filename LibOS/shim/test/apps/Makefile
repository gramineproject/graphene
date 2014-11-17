apps = lmbench gcc busybox lighttpd bash apache make

targets = pal
clean-extra = clean-all

level = ../
include ../Makefile

manifest_rules = \
	-e 's:\$$(PWD):$(shell pwd)/$(appdir):g' \
	-e 's:\$$(BIN):$(subst .manifest,,$(notdir $@)):g' \
	-e 's:\$$(SHIMPATH):$(shell readlink -f ../../src/libsysdb.so):g' \
	-e 's:\$$(GLIBCDIR):$(shell readlink -f $(glibc_dir)):g' \
	$(extra_rules)

%.manifest: %.manifest.template libpal.so
	rm -f $@ $@.backup
	sed $(manifest_rules) $< >$@
	chmod +x $@

libpal.so:
	make pal

build-all:
	for f in $(apps); do (cd $$f; make $(DEBUG) || true; cd ..); done

clean-all:
	for f in $(apps); do (cd $$f; make clean; cd ..); done
