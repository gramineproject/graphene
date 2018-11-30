test_sources = $(addprefix https://people.csail.mit.edu/smcc/projects/single-file-programs/, \
		bzip2.c gzip.c oggenc.c gcc.c)
test_files = $(addprefix test_files/,$(notdir $(test_sources)))

exec_target = $(addsuffix .manifest,gcc as ld cc1 collect2)
target = $(test_files)

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

regression: $(test_files)
	@echo "\n\nBuilding GCC..."
	@$(MAKE) >> /dev/null 2>&1

	@echo "\n\nCompile hello.c:"
	-./gcc.manifest test_files/helloworld.c -o test_files/hello
	@chmod 755 test_files/hello
	-./test_files/hello
	@rm -f test_files/hello

	@echo "\n\nCompile bzip2.c:"
	-./gcc.manifest test_files/bzip2.c -o test_files/bzip2
	@chmod 755 test_files/bzip2
	@[ ! -f bzip2.tmp ] || rm -f bzip2.tmp
	@cp -f test_files/bzip2 test_files/bzip2.copy
	-./test_files/bzip2 -z test_files/bzip2.copy
	-./test_files/bzip2 -d test_files/bzip2.copy.bz2
	diff -q test_files/bzip2 test_files/bzip2.copy
	@rm -f test_files/bzip2 test_file/bzip2.copy

	@echo "\n\nCompile gzip.c:"
	-./gcc.manifest test_files/gzip.c -o test_files/gzip
	@chmod 755 test_files/gzip
	@cp -f test_files/gzip test_files/gzip.copy
	-./test_files/gzip test_files/gzip.copy
	-./test_files/gzip -d test_files/gzip.copy.gz
	diff -q test_files/gzip test_files/gzip.copy
	@rm -f test_files/gzip test_files/gzip.copy


src:
	mkdir -p src

distclean: clean
	rm -rf src obj

clean-garbages:
	rm -rf cc*.s cc*.c cc*.ld cc*.le cc*.o a.out
