include ../../Scripts/Makefile.configs
include ../../Scripts/Makefile.rules

CFLAGS	+= -Wp,-U_FORTIFY_SOURCE -fno-stack-protector -fno-builtin -nostdlib \
	  -I../src \
	  -I../include \
	  -I../include/pal \
	  -I../include/lib \
	  -I../include/arch/$(ARCH) \
	  -I../include/arch/$(ARCH)/$(PAL_HOST)

preloads = \
	Preload1.so \
	Preload2.so

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
	Event2 \
	Exit \
	Failure \
	File \
	File2 \
	HelloWorld \
	Hex \
	Memory \
	Misc \
	Pie \
	Pipe \
	Process \
	Process2 \
	Process3 \
	Process4 \
	Select \
	Semaphore \
	SendHandle \
	Sleep \
	Socket \
	Symbols \
	Tcp \
	Thread2 \
	Udp \
	Wait \
	Yield \
	normalize_path \
	$(executables-$(ARCH))

manifests = \
	manifest \
	Bootstrap3.manifest \
	Bootstrap6.manifest \
	Bootstrap7.manifest \
	File.manifest \
	Process.manifest \
	Process2.manifest \
	Process3.manifest \
	SendHandle.manifest \
	Thread2.manifest \
	Thread2_exitless.manifest

target = \
	Bootstrap6 \
	Thread2_exitless \
	$(executables) \
	$(manifests)

include ../../Scripts/Makefile.manifest
graphene_lib = .lib/graphene-lib.a
pal_lib = ../../Runtime/libpal-$(PAL_HOST).so

RUNTIME_DIR = $(CURDIR)/../../Runtime

.PHONY: all
all: $(target) $(call expand_target_to_sig,$(target)) $(call expand_target_to_sgx,$(target)) $(preloads)

.PHONY: sgx-tokens
sgx-tokens: $(call expand_target_to_token,$(target))

.PHONY: crt_init-recurse
crt_init-recurse:
	$(MAKE) -C ../crt_init all

../crt_init/user_shared_start.o ../crt_init/user_start.o: crt_init-recurse
	@true

CFLAGS-Pie = -fPIC -pie
CFLAGS-AttestationReport = -I../src/host/Linux-SGX

# workaround: File.manifest.template has strange reference
# to ../regression/File
../regression/File: | File
	@true

LDLIBS-preloads = ../crt_init/user_shared_start.o $(graphene_lib) $(pal_lib)
$(preloads): %.so: %.c $(LDLIBS-preloads)
	$(call cmd,csingle) -shared -fPIC $(LDLIBS-preloads)

LDLIBS-executables = ../crt_init/user_start.o $(graphene_lib) $(pal_lib) $(preloads)
$(executables): %: %.c $(LDLIBS-executables)
	$(call cmd,csingle) -no-pie $(LDLIBS-executables)

# Handle multiple tests which share one binary (Graphene requires 1-1 manifest-executable
# correspondence).

Bootstrap6: Bootstrap
	$(call cmd,ln_sfr)

Thread2_exitless: Thread2
	$(call cmd,ln_sfr)

ifeq ($(filter %clean,$(MAKECMDGOALS)),)
include $(wildcard *.d)
endif

$(graphene_lib):
	$(MAKE) -C ../lib target=$(abspath .lib)/

.PHONY: regression
regression:
	$(RM) pal-regression.xml
	$(MAKE) pal-regression.xml

pal-regression.xml: test_pal.py $(target) $(call expand_target_to_sig,$(target)) $(call expand_target_to_sgx,$(target)) $(call expand_target_to_token,$(target))
	../../Scripts/run-pytest --junit-xml $@ -v $<

.PHONY: clean
clean:
	$(RM) -r $(target) $(preloads) *.tmp .lib *.cached *.sig .*.sig *.d .*.d .output.* *.token .*.token *.manifest.sgx .*.manifest.sgx __pycache__ .cache pal-regression.xml

.PHONY: distclean
distclean: clean
