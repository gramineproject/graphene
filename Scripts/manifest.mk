ifeq ($(PAL_HOST),)
$(error include Makefile.configs before including manifest.mk)
endif

MAKEFILE_MANIFEST_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

%.manifest: %.toml.in
	graphene-manifest $(MANIFESTOPTS) $< $@

%.manifest: %.manifest.template
	$(call cmd,manifest,$*,$(manifest_rules))

%.manifest: manifest.template
	$(call cmd,manifest,$*,$(manifest_rules))

-include $(MAKEFILE_MANIFEST_DIR)/../Pal/src/host/$(PAL_HOST)/manifest.mk
