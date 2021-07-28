copy_mmap_execs = \
	copy_mmap_rev \
	copy_mmap_seq \
	copy_mmap_whole

copy_execs = \
	$(copy_mmap_execs) \
	copy_rev \
	copy_sendfile \
	copy_seq \
	copy_whole

execs = \
	$(copy_execs) \
	delete \
	multiple_writers \
	open_close \
	open_flags \
	read_write \
	seek_tell \
	stat \
	truncate

all_manifests = $(addsuffix .manifest,$(execs))

exec_target = $(execs)

target = \
	$(exec_target) \
	$(all_manifests)

clean-extra += clean-tmp

.PHONY: default
default: all

include ../../../../Scripts/Makefile.configs
include ../../../../Scripts/manifest.mk
include ../../../../Scripts/Makefile.Test

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)

$(execs): common.o

$(copy_execs): common_copy.o

$(copy_mmap_execs): CFLAGS += -DCOPY_MMAP

multiple_writers: LDLIBS += -lpthread

%.o: %.c
	$(call cmd,cc_o_c)

else
.IGNORE: $(execs)
$(execs)
endif

.PHONY: fs-test
fs-test: $(target)
	$(RM) fs-test.xml
	$(MAKE) fs-test.xml

.PHONY: tmpfs-test
tmpfs-test: $(target)
	$(RM) tmpfs-test.xml
	$(MAKE) tmpfs-test.xml

.PHONY: pf-test
pf-test: $(target)
	$(RM) pf-test.xml
	$(MAKE) pf-test.xml

.PHONY: test
test: fs-test tmpfs-test pf-test

fs-test.xml: test_fs.py $(call expand_target_to_token,$(target))
	$(SCRIPTS_DIR)/run-pytest --junit-xml $@ -v $<

tmpfs-test.xml: test_tmpfs.py $(call expand_target_to_token,$(target))
	$(SCRIPTS_DIR)/run-pytest --junit-xml $@ -v $<

pf-test.xml: test_pf.py $(call expand_target_to_token,$(target))
	$(SCRIPTS_DIR)/run-pytest --junit-xml $@ -v $<

.PHONY: clean-tmp
clean-tmp:
	$(RM) -r *.tmp *.cached $(all_manifests) *.manifest.sgx *~ *.sig *.token *.o \
	         __pycache__ .pytest_cache .cache *.xml bin lib
