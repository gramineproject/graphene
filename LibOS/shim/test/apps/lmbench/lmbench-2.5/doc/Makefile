# Makefile for lmbench doc subdir.
# $Id$

SHELL=/bin/sh
DESC = description.ms 
USENIX = tmac.usenix usenix96.ms 
PIC = ctx.pic mem.pic 
SCRIPTS = ../scripts/

MAN =	bargraph.1 graph.1 pgraph.1 rccs.1				\
	lmbench.3 reporting.3 results.3 timing.3			\
	bw_file_rd.8 bw_mem.8 bw_pipe.8 bw_pipe.8 bw_tcp.8 bw_unix.8	\
	lat_connect.8 lat_ctx.8 lat_fcntl.8 lat_fifo.8 lat_fs.8 	\
	lat_http.8 lat_mem_rd.8 lat_mmap.8 lat_pagefault.8 lat_pipe.8 	\
	lat_proc.8 lat_rpc.8 lat_select.8 lat_sig.8 lat_syscall.8 	\
	lat_tcp.8 lat_udp.8 lat_unix.8 lat_unix_connect.8		\
	lmbench.8 disk.8 lmdd.8 mhz.8 					\
	clock.8 enough.8 loop_o.8 timing_o.8				\
	bargraph.1 graph.1

ALL = $(DESC) $(USENIX) $(PIC) $(MAN) $(REFER) references

PS ps: $(ALL)
	gindxbib references
	groff -t -e -s -p -R $(USENIX) > USENIX.PS
	#groff -s -p -mgs $(DESC) > DESC.PS
	#groff -fH -man $(MAN) > MAN.PS

X x: $(ALL)
	gindxbib references
	$(SCRIPTS)xroff -t -e -s -p -R $(USENIX) 
	#$(SCRIPTS)xroff -s -p -mgs $(DESC) 
	#$(SCRIPTS)xroff -man -fH $(MAN) 

text: $(ALL)
	gindxbib references
	gsoelim usenix96.ms | sed "s/expand doublebox/center/" | \
	sed s/doublebox// > Fixed.ms
	groff -Tascii -t -e -s -p -R -mgs Fixed.ms 2>/dev/null | colcrt - | more

get: $(ALL)

edit:
	get -e -s $(ALL)

$(MAN):
	get -s $(MAN)

$(PIC):
	get -s $(PIC)

$(DESC):
	get -s $(DESC)

$(USENIX):
	get -s $(USENIX)

clean:
	/bin/rm -f *.PS XXX bw.pic memrd_bcopy_comp.pic references.i
