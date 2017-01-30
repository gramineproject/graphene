test_files = test_files

exec_target = $(addsuffix .manifest,gcc as ld cc1 collect2)

clean-extra = clean-garbages

huge_rule = sys.stack.size = 64M\nsys.brk.size = 256M\nglibc.heap_size = 16M\nsgx.enclave_size = 2G

extra_rules = \
	-e 's:\$$(DEBUGTYPE):$(if $(DEBUG),inline,none):g' \
	-e 's:\$$(GCCDIR):$(patsubst %/cc1,%,$(shell gcc -print-file-name=cc1)):g' \
	-e 's:\$$(HUGERULE):$(if $(HUGE),$(huge_rule),):g'

level = ../../
include ../../Makefile

GCC_VER = 4.8.4
BINUTILS_VER = 2.20.1
GMP_SRC = gmp-5.1.3
GMP_OBJ = libgmp.so.3
GMPXX_OBJ = libgmpxx.so.4
PPL_SRC = ppl-1.1
PPL_OBJ = libppl_c.so.2
MPFR_SRC = mpfr-3.1.2
MPFR_OBJ = libmpfr.so.1
MPC_SRC = mpc-1.0.1
MPC_OBJ = libmpc.so.2

LINK_LIBC =
GCC_FLAGS = \
	--build=x86_64-linux-gnu --host=x86_64-linux-gnu --target=x86_64-linux-gnu --with-gnu-ld \
	--enable-languages=c,c++ --disable-shared --disable-multilib \
	--with-gmp=$(PWD)/obj --with-mpfr=$(PWD)/obj --with-mpc=$(PWD)/obj --without-cloog \
	--without-htmldir --without-pdfdir --without-docdir --without-datarootdir \
	--disable-cloog-version-check --disable-stage1-languages --disable-objc-gc \
	--disable-bootstrap --disable-maintainer-mode --disable-werror \
	$(LINK_LIBC)
GCC_MAKE_FLAGS = \
	LD_LIBRARY_PATH="$(PWD)/obj/lib:/usr/lib:/lib"

obj/bin/gcc: src/gcc-$(GCC_VER) obj/bin/ld $(addprefix obj/lib/,$(GMP_OBJ) $(GMPXX_OBJ) $(PPL_OBJ) $(MPFR_OBJ) $(MPC_OBJ))
	cd $< && ./configure --prefix=$(PWD)/obj $(GCC_FLAGS)
	$(MAKE) -C $< $(GCC_MAKE_FLAGS)
	$(MAKE) -C $< install

src/gcc-$(GCC_VER): gcc-$(GCC_VER).tar.bz2 src
	cd src && tar -xjf ../$<

obj/bin/ld: src/binutils-$(BINUTILS_VER)
	cd $< && ./configure --prefix=$(PWD)/obj $(GCC_FLAGS) --enable-shared
	$(MAKE) -C $< $(GCC_MAKE_FLAGS)
	$(MAKE) -C $< install

src/binutils-$(BINUTILS_VER): binutils-$(BINUTILS_VER).tar.bz2 src
	cd src && tar -xjf ../$<

obj/lib/$(GMP_OBJ) obj/lib/$(GMPXX_OBJ): src/$(GMP_SRC)
	cd $< && ./configure --prefix=$(PWD)/obj --enable-cxx --enable-shared \
	$(LINK_LIBC)
	$(MAKE) -C $<
	$(MAKE) -C $< install

src/$(GMP_SRC): $(GMP_SRC).tar.bz2 src
	cd src && tar -xjf ../$<

obj/lib/$(PPL_OBJ): src/$(PPL_SRC) obj/lib/$(GMP_OBJ)
	cd $< && ./configure --prefix=$(PWD)/obj --with-libgmp-prefix=$(PWD)/obj --enable-shared \
	$(LINK_LIBC) CXXFLAGS=-fpermissive
	$(MAKE) -C $<
	$(MAKE) -C $< install

src/$(PPL_SRC): $(PPL_SRC).tar.gz src
	cd src && tar -xzf ../$<

obj/lib/$(MPFR_OBJ): src/$(MPFR_SRC) obj/lib/$(GMP_OBJ)
	cd $< && ./configure --prefix=$(PWD)/obj --enable-shared \
	$(LINK_LIBC) CXXFLAGS=-D__gmp_const=const
	$(MAKE) -C $<
	$(MAKE) -C $< install

src/$(MPFR_SRC): $(MPFR_SRC).tar.bz2 src
	cd src && tar -xjf ../$<

obj/lib/$(MPC_OBJ): src/$(MPC_SRC)
	cd $< && ./configure --prefix=$(PWD)/obj --with-gmp=$(PWD)/obj --enable-shared \
	$(LINK_LIBC)
	$(MAKE) -C $<
	$(MAKE) -C $< install

src/$(MPC_SRC): $(MPC_SRC).tar.gz src
	cd src && tar -xzf ../$<

src:
	mkdir -p src

distclean: clean
	rm -rf src obj

clean-garbages:
	rm -rf cc*.s cc*.c cc*.ld cc*.le cc*.o a.out
