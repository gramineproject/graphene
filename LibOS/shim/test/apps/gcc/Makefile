manifests = gcc g++ gcc-huge g++-huge gcc-local g++-local

all debug: $(addsuffix .manifest, $(manifests))

c_targets = helloworld gzip oggenc.m single-gcc

test_targets = $(c_targets) $(make_targets)

test: all $(test_targets)

%.manifest: %.manifest.template
	make -C .. gcc/$@ appdir=gcc/

$(c_targets): %: %.c
	echo "$@ (native):" >> result
	rm -rf $@
	time -a -o result -p gcc -o $@ $^ \
	$(shell echo $@ | sed 's/^[^\.]*//g' | sed 's/\./ -l/g')
	sleep 0.5
	echo "$@ (graphene):" >> result
	rm -rf $@
	time -a -o result -p ./gcc.manifest -o $@ $^ \
	$(shell echo $@ | sed 's/^[^\.]*//g' | sed 's/\./ -l/g')

$(make_targets): %:
	echo "$@ (native2):" >> result
	make -C $(dir $@) clean
	time -a -o result -p make -C $(dir $@) $(notdir $@) CC=g++
	echo "$@ (graphene):" >> result
	make -C $(dir $@) clean
	time -a -o result -p make -C $(dir $@) $(notdir $@) CC=$(shell pwd)/g++.manifest

gcc-local: obj/bin/gcc

GCC_VER = 4.4.5
BINUTILS_VER = 2.20.1
GMP_SRC = gmp-4.3.2
GMP_OBJ = libgmp.so.3
PPL_SRC = ppl-0.10.2
PPL_OBJ = libppl_c.so.2
MPFR_SRC = mpfr-2.4.2
MPFR_OBJ = libmpfr.so.1
MPC_SRC = mpc-0.8.1
MPC_OBJ = libmpc.so.2

LINK_LIBC =
MAKE = make #-j$(shell grep -c processor /proc/cpuinfo)
GCC_FLAGS = \
	--with-build-libsubdir=$(PWD)/../../../../build \
	--build=x86_64-linux-gnu --host=x86_64-linux-gnu --target=x86_64-linux-gnu --with-gnu-ld \
	--enable-languages=c,c++ --disable-shared --disable-multilib \
	--with-gmp=$(PWD)/obj --with-mpfr=$(PWD)/obj --with-mpc=$(PWD)/obj --without-cloog \
	--without-htmldir --without-pdfdir --without-docdir --without-datarootdir \
	--disable-cloog-version-check --disable-stage1-languages --disable-objc-gc \
	--disable-bootstrap --disable-maintainer-mode --disable-werror \
	$(LINK_LIBC)
GCC_MAKE_FLAGS = \
	LD_LIBRARY_PATH="$(PWD)/obj/lib:/usr/lib:/lib"

export CFLAGS
export CXXFLAGS="-fpermissive"

obj/bin/gcc: src/gcc-$(GCC_VER) obj/bin/ld $(addprefix obj/lib/,$(GMP_OBJ) $(PPL_OBJ) $(MPFR_OBJ) $(MPC_OBJ))
	cd $< && ./configure --prefix=$(PWD)/obj $(GCC_FLAGS)
	$(MAKE) -C $< $(GCC_MAKE_FLAGS)
	$(MAKE) -C $< install

src/gcc-$(GCC_VER): gcc-$(GCC_VER).tar.bz2 src
	cd src && tar -xjf ../$<

obj/bin/ld: src/binutils-$(BINUTILS_VER)
	cd $< && ./configure --prefix=$(PWD)/obj $(GCC_FLAGS)
	$(MAKE) -C $< $(GCC_MAKE_FLAGS)
	$(MAKE) -C $< install

src/binutils-$(BINUTILS_VER): binutils-$(BINUTILS_VER).tar.bz2 src
	cd src && tar -xjf ../$<

obj/lib/$(GMP_OBJ): src/$(GMP_SRC)
	cd $< && ./configure --prefix=$(PWD)/obj --enable-shared --enable-cxx \
	$(LINK_LIBC)
	$(MAKE) -C $<
	$(MAKE) -C $< install

src/$(GMP_SRC): $(GMP_SRC).tar.bz2 src
	cd src && tar -xjf ../$<

obj/lib/$(PPL_OBJ): src/$(PPL_SRC) obj/lib/$(GMP_OBJ)
	cd $< && ./configure --prefix=$(PWD)/obj --with-libgmp-prefix=$(PWD)/obj --enable-shared \
	$(LINK_LIBC)
	$(MAKE) -C $<
	$(MAKE) -C $< install

src/$(PPL_SRC): $(PPL_SRC).tar.gz src
	cd src && tar -xzf ../$<

obj/lib/$(MPFR_OBJ): src/$(MPFR_SRC) obj/lib/$(GMP_OBJ)
	cd $< && ./configure --prefix=$(PWD)/obj --enable-shared \
	$(LINK_LIBC)
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

test-native:
	echo "Result for helloworld(native)" >> result
	/usr/bin/time -a -o result -p gcc helloworld.c
	echo "Result for gzip.c(native)" >> result
	/usr/bin/time -a -o result -p gcc gzip.c
	echo "Result for oggenc.m.c(native)" >> result
	/usr/bin/time -a -o result -p gcc oggenc.m.c -lm
	echo "Result for single-gcc.c(native)" >> result
	/usr/bin/time -a -o result -p gcc single-gcc.c


test-graphene:
	echo "Result for helloworld(graphene)" >> result
	/usr/bin/time -a -o result -p ./gcc.manifest helloworld.c
	echo "Result for gzip.c(graphene)" >> result
	/usr/bin/time -a -o result -p ./gcc-huge.manifest gzip.c
	echo "Result for oggenc.m.c(graphene)" >> result
	/usr/bin/time -a -o result -p ./gcc-huge.manifest oggenc.m.c -lm
	echo "Result for single-gcc.c(graphene)" >> result
	/usr/bin/time -a -o result -p ./gcc-huge.manifest single-gcc.c

distclean: clean
	rm -rf src obj

clean: clean-manifests clean-garbages
	rm -rf result $(test_targets)

clean-manifests:
	rm -rf $(addsuffix .manifest, $(manifests))

clean-garbages:
	rm -rf cc*.s cc*.c cc*.ld cc*.le cc*.o
