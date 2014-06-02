# $Id$

# Make targets:
#
# lmbench	[default] builds the benchmark suite for the current os/arch
# results	builds, configures run parameters, and runs the benchmark
# rerun		reruns the benchmark using the same parameters as last time
# clean		cleans out sources and run configuration
# clobber	clean and removes the bin directories
# shar		obsolete, use cd .. && make shar
# depend	builds make dependencies (needs gcc)
#
# This is largely self configuring.  Most stuff is pretty portable.  
#
# If you don't have gcc, try make CC=cc and see if that works.
#
# If you want to do cross-compilation try make OS=armv5tel-linux-gnu
# or whatever your OS string should be in the target environment.
# Since many embedded development environments also have a special
# cross-compiler, you might want to also select a particular compiler,
# so your build command would look something like:
#	make OS=armv5tel-linux-gnu CC=gcc-arm
#
# Overriding the OS and CC make parameters needs to be done as an
# argument to make, not as an environment variable.  See above comments.

# I finally know why Larry Wall's Makefile says "Grrrr".
SHELL=/bin/sh

CC = `../scripts/compiler`
LDLIBS = -lm
AR = ar
ARCREATE = cr
BASE=/usr/local		# base of installation location
O= ../bin/unknown
D= ../doc
TRUE=/bin/true
OS=`../scripts/os`
TARGET=`../scripts/target`
BINDIR=../bin/$(OS)
CONFIG=../bin/$(OS)/`../scripts/config`
UTILS=../scripts/target ../scripts/os ../scripts/gnu-os ../scripts/compiler \
	../scripts/info ../scripts/info-template ../scripts/version \
	../scripts/config ../scripts/config-run ../scripts/results \
	../scripts/lmbench ../scripts/build ../scripts/depend
INSTALL=cp
RESULTS=Results/$(OS)
SAMPLES=lmbench/Results/aix/rs6000 lmbench/Results/hpux/snake \
	lmbench/Results/irix/indigo2 lmbench/Results/linux/pentium \
	lmbench/Results/osf1/alpha lmbench/Results/solaris/ss20* 

COMPILE=$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) 

INCS =	bench.h lib_tcp.h lib_udp.h stats.h timing.h

SRCS =  bench.h bw_file_rd.c bw_mmap_rd.c				\
	bw_pipe.c bw_tcp.c clock.c hello.c lat_connect.c lat_ctx.c	\
	lat_fs.c lat_mem_rd.c lat_mmap.c lat_pagefault.c lat_pipe.c	\
	lat_proc.c lat_rpc.c lat_syscall.c lat_tcp.c lat_udp.c		\
	lib_tcp.c lib_udp.c mhz.c lib_timing.c lat_sig.c 		\
	memsize.c bw_unix.c lat_unix.c lmdd.c loop_o.c timing_o.c	\
	timing.h stats.h lib_tcp.h lib_udp.h  enough.c lat_select.c	\
	msleep.c bw_mem.c lat_fifo.c lmhttp.c lat_http.c		\
	disk.c flushdisk.c lat_unix_connect.c lib_unix.c lib_stats.c \
	lib_unix.h names.h version.h lat_msg.c lib_confidence.c

EXES =	$O/bw_file_rd $O/bw_mem $O/bw_mmap_rd $O/bw_pipe $O/bw_tcp 	\
	$O/lat_select $O/lat_pipe $O/lat_rpc $O/lat_syscall $O/lat_tcp	\
	$O/lat_udp $O/lat_mmap $O/lat_proc $O/lat_pagefault $O/mhz	\
	$O/lat_connect $O/lat_fs $O/lat_sig $O/lat_mem_rd $O/lat_ctx	\
	$O/memsize $O/lat_unix $O/bw_unix $O/lmdd $O/timing_o $O/enough	\
	$O/msleep $O/loop_o $O/lat_fifo $O/lmhttp $O/lat_http		\
	$O/lat_unix_connect $O/lat_fcntl				\
	$O/disk $O/flushdisk $O/clock $O/hello $O/lat_msg

MAN1 =	lmdd.1 $D/bargraph.1 $D/graph.1 $D/pgraph.1 $D/rccs.1

MAN3 =	$D/lmbench.3 $D/reporting.3 $D/results.3 $D/timing.3

MAN8 =	$D/bw_file_rd.8 $D/bw_mem.8 $D/bw_pipe.8 $D/bw_pipe.8		\
	$D/bw_tcp.8 $D/bw_unix.8					\
	$D/lat_connect.8 $D/lat_ctx.8 $D/lat_fcntl.8 $D/lat_fifo.8	\
	$D/lat_fs.8 $D/lat_http.8 $D/lat_mem_rd.8 $D/lat_mmap.8		\
	$D/lat_pagefault.8 $D/lat_pipe.8 $D/lat_proc.8 $D/lat_rpc.8 	\
	$D/lat_select.8 $D/lat_sig.8 $D/lat_syscall.8 $D/lat_tcp.8 	\
	$D/lat_udp.8 $D/lat_unix.8 $D/lat_unix_connect.8		\
	$D/lmbench.8 $D/disk.8 $D/lmdd.8 $D/mhz.8 			\
	$D/clock.8 $D/enough.8 $D/loop_o.8 $D/timing_o.8

LIBOBJS= $O/lib_tcp.o $O/lib_udp.o $O/lib_unix.o $O/lib_timing.o $O/lib_stats.o $O/lib_confidence.o

lmbench: $(UTILS)
	@env OS="${OS}" CC="${CC}" CFLAGS="${CFLAGS} -O" MAKE="$(MAKE)" MAKEFLAGS="$(MAKEFLAGS)" ../scripts/build all

results: lmbench
	@env OS="${OS}" ../scripts/config-run
	@env OS="${OS}" ../scripts/results

rerun: lmbench
	@if [ ! -f $(CONFIG) ]; then env OS="${OS}" ../scripts/config-run; fi
	@env OS="${OS}" ../scripts/results

install: lmbench
	$(MAKE) O=$(BINDIR) install-target

install-target:
	if [ ! -d $(BASE) ]; then mkdir $(BASE); fi
	if [ ! -d $(BASE)/bin ]; then mkdir $(BASE)/bin; fi
	if [ ! -d $(BASE)/include ]; then mkdir $(BASE)/include; fi
	if [ ! -d $(BASE)/lib ]; then mkdir $(BASE)/lib; fi
	if [ ! -d $(BASE)/man ]; then mkdir $(BASE)/man; fi
	if [ ! -d $(BASE)/man/man1 ]; then mkdir $(BASE)/man/man1; fi
	if [ ! -d $(BASE)/man/man3 ]; then mkdir $(BASE)/man/man3; fi
	if [ ! -d $(BASE)/man/man8 ]; then mkdir $(BASE)/man/man8; fi
	cp $(EXES) $(BASE)/bin
	cp $(INCS) $(BASE)/include
	cp $O/lmbench.a $(BASE)/lib/libmbench.a
	cp $(MAN1) $(BASE)/man/man1
	cp $(MAN3) $(BASE)/man/man3
	cp $(MAN8) $(BASE)/man/man8


# No special handling for all these
all: $(EXES) $O/lmbench

Wall:
	@env OS="${OS}" CC="${CC}" CFLAGS="-Wall -ansi" MAKE="$(MAKE)" MAKEFLAGS="$(MAKEFLAGS)" ../scripts/build all

debug:
	@env OS="${OS}" CC="${CC}" CFLAGS="-g -O -D_DEBUG" MAKE="$(MAKE)" MAKEFLAGS="$(MAKEFLAGS)" ../scripts/build all

dist: 
	SRCDIR=`pwd`; \
	ROOT=`cat ../CVS/Root`; \
	MODULE=`cat ../CVS/Repository`; \
	VERSION=`../scripts/version`; \
	cd /tmp \
	&& cvs -d$${ROOT} export -Dtomorrow \
		 -d $${MODULE}-$${VERSION} $${MODULE} \
	&& chmod +x $${MODULE}-$${VERSION}/scripts/[a-z]* \
	&& mv $${MODULE}-$${VERSION} lmbench-$${VERSION} \
	&& tar czf $${SRCDIR}/../../lmbench-$${VERSION}.tgz \
		lmbench-$${VERSION} \
	&& rm -rf lmbench-$${VERSION};

clean:
	/bin/rm -f ../bin/*/CONFIG.* ../bin/*.[oa] ../bin/*/*.[oa]

clobber:
	/bin/rm -rf ../bin* SHAR

shar:
	cd ../.. && shar lmbench/Results/Makefile $(SAMPLES) lmbench/scripts/* lmbench/src/Makefile lmbench/src/*.[ch] > lmbench/SHAR

depend: ../scripts/depend
	../scripts/depend

$(UTILS):
	@cd ../scripts; make get

$O/lmbench : ../scripts/lmbench version.h
	rm -f $O/lmbench
	VERSION=`../scripts/version`; \
	sed -e "s/<version>/$${VERSION}/g" < ../scripts/lmbench > $O/lmbench
	chmod +x $O/lmbench

$O/lmbench.a: $(LIBOBJS)
	/bin/rm -f $O/lmbench.a
	$(AR) $(ARCREATE) $O/lmbench.a $(LIBOBJS)
	-ranlib $O/lmbench.a

$O/lib_timing.o : lib_timing.c $(INCS)
	$(COMPILE) -c lib_timing.c -o $O/lib_timing.o -lm
$O/lib_confidence.o : lib_confidence.c $(INCS)
	$(COMPILE) -c lib_confidence.c -o $O/lib_confidence.o -lm
$O/lib_tcp.o : lib_tcp.c $(INCS)
	$(COMPILE) -c lib_tcp.c -o $O/lib_tcp.o -lm
$O/lib_udp.o : lib_udp.c $(INCS)
	$(COMPILE) -c lib_udp.c -o $O/lib_udp.o -lm
$O/lib_unix.o : lib_unix.c $(INCS)
	$(COMPILE) -c lib_unix.c -o $O/lib_unix.o -lm
$O/lib_stats.o : lib_stats.c $(INCS)
	$(COMPILE) -c lib_stats.c -o $O/lib_stats.o -lm

# Do not remove the next line, $(MAKE) depend needs it
# MAKEDEPEND follows
$O/rhttp:  rhttp.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/rhttp rhttp.c $O/lmbench.a $(LDLIBS) -lm

$O/http:  http.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/http http.c $O/lmbench.a $(LDLIBS) -lm

$O/flushdisk:  flushdisk.c 
	$(COMPILE) -DMAIN -o $O/flushdisk flushdisk.c -lm

$O/mhz: mhz.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/mhz mhz.c $O/lmbench.a $(LDLIBS) -lm

$O/lat_ctx: lat_ctx.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/lat_ctx lat_ctx.c $O/lmbench.a $(LDLIBS) -lm

$O/lmhttp:  lmhttp.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/lmhttp lmhttp.c $O/lmbench.a $(LDLIBS) -lm

$O/lat_http:  lat_http.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/lat_http lat_http.c $O/lmbench.a $(LDLIBS) -lm

$O/bw_file_rd:  bw_file_rd.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/bw_file_rd bw_file_rd.c $O/lmbench.a $(LDLIBS) -lm

$O/bw_mem:  bw_mem.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/bw_mem bw_mem.c $O/lmbench.a $(LDLIBS) -lm

$O/bw_mmap_rd:  bw_mmap_rd.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/bw_mmap_rd bw_mmap_rd.c $O/lmbench.a $(LDLIBS) -lm

$O/bw_pipe:  bw_pipe.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/bw_pipe bw_pipe.c $O/lmbench.a $(LDLIBS) -lm

$O/bw_tcp:  bw_tcp.c bench.h timing.h stats.h lib_tcp.h $O/lmbench.a
	$(COMPILE) -o $O/bw_tcp bw_tcp.c $O/lmbench.a $(LDLIBS) -lm

$O/bw_unix:  bw_unix.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/bw_unix bw_unix.c $O/lmbench.a $(LDLIBS) -lm

$O/disk:  disk.c flushdisk.c bench.h timing.h stats.h lib_tcp.h $O/lmbench.a
	$(COMPILE) -o $O/disk disk.c flushdisk.c $O/lmbench.a $(LDLIBS) -lm

$O/clock:  clock.c timing.h stats.h bench.h version.h $O/lmbench.a
	$(COMPILE) -o $O/clock clock.c $O/lmbench.a $(LDLIBS) -lm

$O/hello:  hello.c $O/lmbench.a
	$(COMPILE) -o $O/hello hello.c $O/lmbench.a $(LDLIBS) -lm

$O/lat_alarm:  lat_alarm.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/lat_alarm lat_alarm.c $O/lmbench.a $(LDLIBS) -lm

$O/lat_connect:  lat_connect.c lib_tcp.c bench.h lib_tcp.h timing.h stats.h $O/lmbench.a
	$(COMPILE) -o $O/lat_connect lat_connect.c $O/lmbench.a $(LDLIBS)  -lm

$O/lat_unix_connect:  lat_unix_connect.c lib_tcp.c bench.h lib_tcp.h timing.h stats.h $O/lmbench.a
	$(COMPILE) -o $O/lat_unix_connect lat_unix_connect.c $O/lmbench.a $(LDLIBS) -lm

$O/lat_fcntl:  lat_fcntl.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/lat_fcntl lat_fcntl.c $O/lmbench.a $(LDLIBS) -lm

$O/lat_fs:  lat_fs.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/lat_fs lat_fs.c $O/lmbench.a $(LDLIBS)  -lm

$O/lat_mem_rd:  lat_mem_rd.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/lat_mem_rd lat_mem_rd.c $O/lmbench.a $(LDLIBS) -lm

$O/lat_mem_rd2:  lat_mem_rd2.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/lat_mem_rd2 lat_mem_rd2.c $O/lmbench.a $(LDLIBS) -lm

$O/lat_mem_wr:  lat_mem_wr.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/lat_mem_wr lat_mem_wr.c $O/lmbench.a $(LDLIBS) -lm

$O/lat_mem_wr2:  lat_mem_wr2.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/lat_mem_wr2 lat_mem_wr2.c $O/lmbench.a $(LDLIBS) -lm

$O/lat_mmap:  lat_mmap.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/lat_mmap lat_mmap.c $O/lmbench.a $(LDLIBS) -lm

$O/lat_mmaprd:  lat_mmaprd.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/lat_mmaprd lat_mmaprd.c $O/lmbench.a $(LDLIBS) -lm

$O/lat_pagefault:  lat_pagefault.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/lat_pagefault lat_pagefault.c $O/lmbench.a $(LDLIBS) -lm

$O/lat_pipe:  lat_pipe.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/lat_pipe lat_pipe.c $O/lmbench.a $(LDLIBS) -lm

$O/lat_fifo:  lat_fifo.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/lat_fifo lat_fifo.c $O/lmbench.a $(LDLIBS) -lm

$O/lat_proc:  lat_proc.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/lat_proc lat_proc.c $O/lmbench.a $(LDLIBS) -lm

$O/lat_rpc:  lat_rpc.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/lat_rpc lat_rpc.c $O/lmbench.a $(LDLIBS) -lm

$O/lat_sig:  lat_sig.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/lat_sig lat_sig.c $O/lmbench.a $(LDLIBS) -lm

$O/lat_syscall:  lat_syscall.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/lat_syscall lat_syscall.c $O/lmbench.a $(LDLIBS) -lm

$O/lat_select:  lat_select.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/lat_select lat_select.c $O/lmbench.a $(LDLIBS)  -lm 

$O/lat_tcp:  lat_tcp.c timing.h stats.h bench.h lib_tcp.h $O/lmbench.a
	$(COMPILE) -o $O/lat_tcp lat_tcp.c $O/lmbench.a $(LDLIBS) -lm 

$O/lat_udp:  lat_udp.c timing.h stats.h bench.h lib_udp.h $O/lmbench.a
	$(COMPILE) -o $O/lat_udp lat_udp.c $O/lmbench.a $(LDLIBS)  -lm

$O/lat_unix:  lat_unix.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -g3 -o $O/lat_unix lat_unix.c $O/lmbench.a $(LDLIBS) -lm

$O/lib_tcp:  lib_tcp.c bench.h lib_tcp.h $O/lmbench.a
	$(COMPILE) -o $O/lib_tcp lib_tcp.c $O/lmbench.a $(LDLIBS)   -lm

$O/lib_udp:  lib_udp.c bench.h lib_udp.h $O/lmbench.a
	$(COMPILE) -o $O/lib_udp lib_udp.c $O/lmbench.a $(LDLIBS)  -lm

$O/lat_msg:  lat_msg.c bench.h $O/lmbench.a
	$(COMPILE) -o $O/lat_msg lat_msg.c $O/lmbench.a $(LDLIBS)  -lm

$O/lmdd:  lmdd.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/lmdd lmdd.c $O/lmbench.a $(LDLIBS) -lm

$O/enough:  enough.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/enough enough.c $O/lmbench.a $(LDLIBS) -lm

$O/loop_o:  loop_o.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/loop_o loop_o.c $O/lmbench.a $(LDLIBS) -lm

$O/timing_o:  timing_o.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/timing_o timing_o.c $O/lmbench.a $(LDLIBS) -lm

$O/memsize:  memsize.c timing.h stats.h bench.h $O/lmbench.a
	$(COMPILE) -o $O/memsize memsize.c $O/lmbench.a $(LDLIBS) -lm

$O/msleep:  msleep.c timing.h stats.h bench.h 
	$(COMPILE) -o $O/msleep msleep.c -lm
