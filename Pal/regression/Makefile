include ../../Scripts/Makefile.configs
include ../../Scripts/Makefile.rules

GRAPHENE_PKGLIBDIR = $(graphene-manifest -c '{{ graphene.pkglibdir }}')

%.manifest: %.manifest.template
	graphene-manifest -Dentrypoint=$(GRAPHENE_PKGLIBDIR)/tests/pal/$(patsubst %.manifest,%,$@)

executables-x86_64 = \
    Exception \
    Exception2 \
    Segment \
    Thread

executables = \
	..Bootstrap \
	AttestationReport \
	avl_tree_test \
	Bootstrap \
	Bootstrap3 \
	Bootstrap7 \
	Directory \
	Event \
	Exit \
	File \
	File2 \
	HelloWorld \
	Hex \
	Memory \
	Misc \
	Pie \
	Pipe \
	Process \
	Process3 \
	Process4 \
	Select \
	SendHandle \
	Socket \
	Symbols \
	Tcp \
	Thread2 \
	Udp \
	normalize_path \
	$(executables-$(ARCH))

all_manifests = $(addsuffix .manifest,$(executables))

target = \
	$(all_manifests)

include ../../Scripts/manifest.mk

.PHONY: all
all: $(target) $(call expand_target_to_sig,$(target)) \
     $(call expand_target_to_sgx,$(target)) $(preloads)

.PHONY: sgx-tokens
sgx-tokens: $(call expand_target_to_token,$(target))

ifeq ($(filter %clean,$(MAKECMDGOALS)),)
include $(wildcard *.d)
endif

.PHONY: regression
regression:
	$(RM) pal-regression.xml
	$(MAKE) pal-regression.xml

pal-regression.xml: test_pal.py $(target) $(call expand_target_to_sig,$(target)) $(call expand_target_to_sgx,$(target)) $(call expand_target_to_token,$(target))
	../../Scripts/run-pytest --junit-xml $@ -v $<

.PHONY: clean
clean:
	$(MAKE) -C crt_init $@
	$(RM) -r \
		$(executables) \
		$(gen_manifests) \
		$(preloads) \
		*.cached \
		*.d \
		.*.d \
		*.manifest.sgx \
		.*.manifest.sgx \
		*.o \
		*.sig \
		.*.sig \
		*.tmp \
		*.token \
		.*.token \
		.cache \
		.lib \
		.output.* \
		.pytest_cache \
		__pycache__ \
		pal-regression.xml

.PHONY: distclean
distclean: clean
