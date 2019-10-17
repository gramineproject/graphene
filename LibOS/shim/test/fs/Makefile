copy_execs = \
	copy_mmap_rev \
	copy_mmap_seq \
	copy_mmap_whole \
	copy_rev \
	copy_seq \
	copy_whole

execs = \
	$(copy_execs) \
	delete \
	open_close \
	read_write \
	seek_tell \
	stat \
	truncate

manifests = manifest

exec_target = $(execs)

target = \
	$(exec_target) \
	$(manifests)

clean-extra += clean-tmp

.PHONY: default
default: all

include ../../../../Scripts/Makefile.configs
include ../../../../Scripts/Makefile.manifest
include ../../../../Scripts/Makefile.Test

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)

$(execs): common.o

$(copy_execs): common_copy.o

%.o: %.c
	$(call cmd,cc_o_c)

else
.IGNORE: $(execs)
$(execs)
endif

export PAL_LOADER = $(RUNTIME)/pal-$(PAL_HOST)
export PAL_TOOLS  = ../../../../Pal/src/host/$(PAL_HOST)/tools
export PYTHONPATH = ../../../../Scripts

.PHONY: fs-test
fs-test: $(target)
	$(RM) fs-test.xml
	$(MAKE) fs-test.xml

.PHONY: test
test: $(target)
	$(RM) pf-test.xml
	$(MAKE) pf-test.xml

fs-test.xml: test_fs.py $(call expand_target_to_token,$(target))
	python3 -m pytest --junit-xml $@ -v $<

pf-test.xml: test_pf.py $(call expand_target_to_token,$(target))
	python3 -m pytest --junit-xml $@ -v $<

.PHONY: clean-tmp
clean-tmp:
	$(RM) -r *.tmp *.cached *.manifest.sgx *~ *.sig *.token *.o __pycache__ .pytest_cache .cache *.xml
