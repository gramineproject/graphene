manifests = make.manifest

graphene_dirs = LibOS/shim/src LibOS/shim/include Pal/lib Pal/include Pal/src
graphene_target = $(addprefix graphene/,$(graphene_dirs))
graphene_libs = $(addprefix graphene/Pal/src/,libpal.so libpal.a)

target = configure $(graphene_target) $(graphene_libs)
exec_target = $(manifests)

clean-extra = clean-tests

huge_rule = sys.stack.size = 64M\nsys.brk.size = 256M\nglibc.heap_size = 16M\nsgx.enclave_size = 2G

extra_rules = \
	-e 's:\$$(DEBUGTYPE):$(if $(DEBUG),inline,none):g' \
	-e 's:\$$(GCCDIR):$(patsubst %/cc1,%,$(shell gcc -print-file-name=cc1)):g' \
	-e 's:\$$(HUGERULE):$(if $(HUGE),$(huge_rule),):g'

level = ../../
include ../../Makefile

test_tarballs = oggenc-1.4 bzip2-1.0.6
test_targets = $(test_tarballs) helloworld graphene

make_src = make-3.82

$(make_src) $(test_tarballs): %: %.tar.gz
	[ -d $@ ] || tar -zmxf $<

$(make_src)/make:
	cd $(make_src) && ./configure
	cd $(make_src) && $(MAKE) CC="gcc -g"

$(graphene_target): graphene/%: ../../../../../%
	cd $< && git checkout-index -a -f --prefix=$(PWD)/graphene/

$(graphene_libs): graphene/%: ../../../../../%
	mkdir -p $(dir $@)
	ln -sf $(shell readlink -f $<) $@

configure: $(test_targets)
	for d in $(test_targets); do \
		if [ ! -f $$d/Makefile ] && [ -f $$d/configure ]; then \
			cd $$d; ./configure; cd ..; \
		fi; \
	done

distclean: clean-manifests clean-tests
	rm -rf $(make_src) $(MAKE) result $(test_tarballs) $(graphene_target) $(graphene_libs)

clean-tests:
	for d in $(test_targets); do ([ ! -d $$d ] || $(MAKE) -C $$d clean); done
