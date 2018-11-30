test_sources = $(addprefix https://people.csail.mit.edu/smcc/projects/single-file-programs/, \
		bzip2.c gzip.c oggenc.c gcc.c.bz2)
test_files = $(addprefix test_files/,$(notdir $(test_sources)))

exec_target = $(addsuffix .manifest,gcc as ld cc1 collect2)

clean-extra = clean-garbages

huge_rule = sys.stack.size = 64M\nsys.brk.size = 256M\nglibc.heap_size = 16M\nsgx.enclave_size = 2G

extra_rules = \
	-e 's:\$$(DEBUGTYPE):$(if $(DEBUG),inline,none):g' \
	-e 's:\$$(GCCDIR):$(patsubst %/cc1,%,$(shell gcc -print-file-name=cc1)):g' \
	-e 's:\$$(HUGERULE):$(if $(HUGE),$(huge_rule),):g'

level = ../../
include ../../Makefile

$(test_files): get_test_files
get_test_files:
	cd test_files && for url in $(test_sources); do wget -nc $$url; done
	sha256sum --check test_files_checksums
	@for file in test_files/*.bz2; do bzip2 -d -k $$file || true; done
	@$(MAKE) patch_test_files

test_patches = $(patsubst %.patch,%,$(wildcard test_files/*.patch))

patch_test_files: $(patsubst %.c,%-patched.c,$(test_patches))
%-patched.c: %.c.patch
	@cp -f $(patsubst %.patch,%,$<) $@
	@patch -p1 $@ < $<

regression: $(test_files)
	@echo "\n\nBuilding manifest..."
	@($(MAKE) clean && $(MAKE)) >> /dev/null 2>&1

	@echo "\n\nTesting..."
	@env PYTHONPATH=../../../../../Scripts python test.py || exit $$?

	@echo "\n\nBuilding manifest with HUGE=1..."
	@($(MAKE) clean && $(MAKE) HUGE=1) >> /dev/null 2>&1

	@echo "\n\nTesting..."
	@env PYTHONPATH=../../../../../Scripts python test-huge.py || exit $$?

src:
	mkdir -p src

distclean: clean
	rm -rf src obj

clean-garbages:
	rm -rf cc*.s cc*.c cc*.ld cc*.le cc*.o a.out
