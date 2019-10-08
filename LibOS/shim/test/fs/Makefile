execs = $(filter-out common common_copy,$(patsubst %.c,%,$(wildcard *.c)))
copy_execs = $(filter copy_%,$(execs))
manifests = $(patsubst %.manifest.template,%.manifest,$(wildcard *.manifest.template)) manifest

exec_target = $(execs)
target = $(exec_target) $(manifests)

clean-extra += clean-tmp

.PHONY: default
default: all

include ../Makefile.Test

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
export PYTHONPATH = ../../../../Scripts

.PHONY: regression
regression: $(target)
	$(RM) fs-test.xml
	$(MAKE) fs-test.xml

fs-test.xml:
	python3 -m pytest --junit-xml $@ -v test_fs.py

.PHONY: clean-tmp
clean-tmp:
	rm -rf *.tmp *.cached *.manifest.sgx *~ *.sig *.token *.o __pycache__ .pytest_cache .cache *.xml
