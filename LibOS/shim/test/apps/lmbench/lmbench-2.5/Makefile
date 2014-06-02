# Makefile for top level of lmbench
# $Id$

# Possible things to $(MAKE):
#
# build		(default) go to the source directory and build the benchmark
# results	go to the source directory and build and run the benchmark
# rerun		run the benchmark again
# see		see the results that came with this release
#		Go to the results directory and read the Makefile.
# doc.lpr	print the documentation
# doc.x		preview the documentation (needs X, groff, pic, etc)
# clean		go to the subdirs and $(MAKE) clean
# get		$(MAKE) sure all files are checked out
# shar		build a shippable shar archive

SHELL=/bin/sh

export CC
export CFLAGS

build: 
	cd src && $(MAKE)
	cp bin/linux/hello /tmp

results: FRC
	cd src && $(MAKE) results

rerun: 
	cd src && $(MAKE) rerun

see:
	cd results && $(MAKE) summary percent 2>/dev/null | more

doc.lpr:
	cd doc && $(MAKE) PS && lpr *.PS

doc.x:
	cd doc && $(MAKE) x

clobber clean: 
	for i in doc src results scripts; do \
		echo ===== $$i =====; \
		(cd $$i && $(MAKE) clean); \
	done
	/bin/rm -rf bin/*

get: 
	for i in doc src results scripts; do \
		echo ===== $$i =====; \
		(cd $$i && co -q); \
	done
	@co -q

info: 
	for i in doc src results scripts; do \
		echo ===== $$i =====; \
		(cd $$i && info); \
	done

release: scripts/mkrelease
	scripts/mkrelease

scripts/mkrelease:
	cd scripts && co mkrelease

# XXX - . must be named lmbench for this to work
shar:
	$(MAKE) clean
	co -q Makefile
	$(MAKE) get
	cd .. && \
	find lmbench -type f -print  | egrep -v 'noship|RCS' > /tmp/FILES
	cd .. && shar -S -a -n lmbench1.0 -L 50K < /tmp/FILES 

FRC:
