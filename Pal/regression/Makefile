include ../../Scripts/Makefile.configs
include ../../Scripts/Makefile.rules

CFLAGS	+= -fno-builtin -nostdlib \
	  -I../include/pal -I../include/lib -I../src

preloads = \
	Preload1.so \
	Preload2.so

executables = \
	..Bootstrap \
	AtomicMath \
	AvxDisable \
	Bootstrap \
	Bootstrap2 \
	Bootstrap3 \
	Bootstrap7 \
	Directory \
	Event \
	Exception \
	Exit \
	File \
	Hex \
	Memory \
	Misc \
	Pipe \
	Process \
	Process2 \
	Process3 \
	Semaphore \
	SendHandle \
	Socket \
	Symbols \
	Thread \
	Thread2 \
	normalize_path

manifests = \
	manifest \
	AvxDisable.manifest \
	Bootstrap2.manifest \
	Bootstrap3.manifest \
	Bootstrap4.manifest \
	Bootstrap5.manifest \
	Bootstrap6.manifest \
	Bootstrap7.manifest \
	File.manifest \
	Process.manifest \
	Process2.manifest \
	Process3.manifest \
	SendHandle.manifest \
	Thread2.manifest \
	Thread2_exitless.manifest \
	nonelf_binary.manifest

target = $(executables) $(manifests)

include ../../Scripts/Makefile.manifest
graphene_lib = .lib/graphene-lib.a
pal_lib = ../../Runtime/libpal-$(PAL_HOST).so

RUNTIME_DIR = $(CURDIR)/../../Runtime

ifneq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)
$(error unsupported platform. $(SYS))
endif

.PHONY: all
all: $(target) $(call expand_target_to_sig,$(target)) $(call expand_target_to_sgx,$(target)) $(preloads)

.PHONY: sgx-tokens
sgx-tokens: $(call expand_target_to_token,$(target))

manifest_rules = \
	-e 's:\$$(PAL):$(abspath ../../Runtime/pal_loader):g' \
	-e 's:\$$(PWD):$(shell pwd)/:g' \
	-e 's:\$$(RA_CLIENT_SPID):$(RA_CLIENT_SPID):g' \
	-e 's:\$$(RA_CLIENT_LINKABLE):$(if $(RA_CLIENT_LINKABLE),$(RA_CLIENT_LINKABLE),0):g'

.PHONY: crt_init-recurse
crt_init-recurse:
	$(MAKE) -C ../crt_init all

../crt_init/user_shared_start.o ../crt_init/user_start.o: crt_init-recurse
	@true

CFLAGS-AvxDisable += -mavx

# workaround: File.manifest.template has strange reference
# to ../regression/File
../regression/File: | File
	@true

LDLIBS-preloads = ../crt_init/user_shared_start.o $(graphene_lib) $(pal_lib)
$(preloads): CFLAGS += -shared -fPIC
$(preloads): LDLIBS = $(LDLIBS-preloads)
$(preloads): %.so: %.c $(LDLIBS-preloads)
	$(call cmd,csingle)

LDLIBS-executables = ../crt_init/user_start.o $(graphene_lib) $(pal_lib) $(preloads)
$(executables): CFLAGS += -no-pie
$(executables): LDLIBS = $(LDLIBS-executables)
$(executables): %: %.c $(LDLIBS-executables)
	$(call cmd,csingle)

ifeq ($(filter %clean,$(MAKECMDGOALS)),)
include $(wildcard *.d)
ifeq ($(SGX), 1)
# Bootstrap5.manifest doesn't have main executable, but only preloaded
# libraries. Static pattern rule is needed to override the implicit pattern
# rule defined in Pal/src/host/Linux-SGX/Makefile.Test.
Bootstrap5.manifest.sgx.d: %.manifest.sgx.d: %.manifest
	$(call cmd,sgx_sign_depend)
endif
endif

$(graphene_lib):
	$(MAKE) -C ../lib target=$(abspath .lib)/

export PAL_LOADER = $(RUNTIME_DIR)/pal-$(PAL_HOST)
export PYTHONPATH=../../Scripts

.PHONY: regression
regression:
	$(RM) pal-regression.xml
	$(MAKE) pal-regression.xml

pal-regression.xml: test_pal.py $(target) $(call expand_target_to_sig,$(target)) $(call expand_target_to_sgx,$(target)) $(call expand_target_to_token,$(target))
	python3 -m pytest --junit-xml $@ -v $<

.PHONY: clean
clean:
	$(RM) -r $(target) $(preloads) *.tmp .lib *.cached *.sig .*.sig *.d .*.d .output.* *.token .*.token *.manifest.sgx .*.manifest.sgx __pycache__ .cache pal-regression.xml

.PHONY: distclean
distclean: clean
