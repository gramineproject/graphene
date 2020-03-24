#!/bin/bash

# lmbench - run the lmbench benchmark suite.
#
# Hacked by Larry McVoy (lm@sun.com, lm@sgi.com, lm@bitmover.com).
# Copyright (c) 1994 Larry McVoy.  GPLed software.
# $Id$

# Make sure we can find: ./cmd, df, and netstat
PATH=.:../../scripts:$PATH:/etc:/usr/etc:/sbin:/usr/sbin
export PATH

echo PATH = $PATH
echo lat_syscall = `readlink -f lat_syscall`

# lat_unix, lat_udp, lat_tcp only do one run!!!
# we loop to repeat the tests
N_RUNS=${N_RUNS:-1}

if [ -f $1 ]
then	. $1
	echo Using config in $1
else	echo Using defaults
	ENOUGH=${ENOUGH:-1000}
	TIMING_O=0
	LOOP_O=0
fi
export ENOUGH TIMING_O LOOP_O

if [ X$FILE = X ]
then
	FILE=/tmp/XXX
	touch $FILE || echo Can not create $FILE
fi
if [ X$MB = X ]
then
	MB=8
fi
AVAILKB=`expr $MB \* 1024`

# Figure out how big we can go for stuff that wants to use
# all and half of memory.
HALF="512 1k 2k 4k 8k 16k 32k 64k 128k 256k 512k 1m"
ALL="$HALF 2m"
i=4
while [ $i -le $MB ]
do
	ALL="$ALL ${i}m"
	h=`expr $i / 2`
	HALF="$HALF ${h}m"
	i=`expr $i \* 2`
done


if [ X$FSDIR = X ]
then
	FSDIR=/tmp/lat_fs
fi
MP=N

# Figure out as much stuff as we can about this system.
# Sure would be nice if everyone had SGI's "hinv".
echo \[lmbench2.0 results for `uname -a`] 1>&2
echo \[ALL: ${ALL}] 1>&2
echo \[DISKS: ${DISKS}] 1>&2
echo \[DISK_DESC: ${DISK_DESC}] 1>&2
echo \[ENOUGH: ${ENOUGH}] 1>&2
echo \[FAST: ${FAST}] 1>&2
echo \[FASTMEM: ${FASTMEM}] 1>&2
echo \[FILE: ${FILE}] 1>&2
echo \[FSDIR: ${FSDIR}] 1>&2
echo \[HALF: ${HALF}] 1>&2
echo \[INFO: ${INFO}] 1>&2
echo \[LOOP_O: ${LOOP_O}] 1>&2
echo \[MB: ${MB}] 1>&2
echo \[MHZ: ${MHZ}] 1>&2
echo \[MOTHERBOARD: ${MOTHERBOARD}] 1>&2
echo \[NETrunS: ${NETrunS}] 1>&2
echo \[PROCESSORS: ${PROCESSORS}] 1>&2
echo \[REMOTE: ${REMOTE}] 1>&2
echo \[SLOWFS: ${SLOWFS}] 1>&2
echo \[OS: ${OS}] 1>&2
echo \[TIMING_O: ${TIMING_O}] 1>&2
echo \[LMBENCH VERSION: ${VERSION}] 1>&2
echo \[USER: $USER] 1>&2
echo \[HOSTNAME: `hostname`] 1>&2
echo \[NODENAME: `uname -n`] 1>&2
echo \[SYSNAME: `uname -s`] 1>&2
echo \[PROCESSOR: `uname -p`] 1>&2
echo \[MACHINE: `uname -m`] 1>&2
echo \[RELEASE: `uname -r`] 1>&2
echo \[VERSION: `uname -v`] 1>&2
#if 0
echo \[`date`] 1>&2
echo \[`uptime`] 1>&2
netstat -i | while read i
do
	echo \[net: "$i"] 1>&2
	set `echo $i`
	case $1 in
	    *ame)	;;
	    *)		ifconfig $1 | while read i
			do
				echo \[if: "$i"] 1>&2
			done
			;;
	esac
done

mount | while read i
do
	echo \[mount: "$i"] 1>&2
done

STAT=$FSDIR/lmbench
mkdir $FSDIR 2>/dev/null
touch $STAT 2>/dev/null
if [ ! -f $STAT ]
then
	echo "Can't make a file - $STAT - in $FSDIR"
	touch $STAT
	exit 1
fi

if [ ! -f "/tmp/hello" ]
then
	cp hello /tmp/hello
fi

function run {
	echo "$@"
	TMPOUT=/tmp/OUT
	rm -rf $TMPOUT
	$LOADER "$@" 2>>$TMPOUT | tee -a $TMPOUT
	retval=$?
	echo $retval
	if [ $retval -ne 0 ]
	then
	    cat $TMPOUT 1>&2
	    exit $retval
	else
	    cat $TMPOUT 1>&2
	fi
}

function af_unix {
# DP 7/4/18: This test intermittently hangs on SGX, taking out of CI for now
#AF_UNIX
	echo AF_UNIX socket latency
	for i in `seq 1 $N_RUNS`
	do
		run lat_unix
	done
}


function wr_bw {
	for i in `seq 1 $N_RUNS`
	do
		rm -f $FILE
		run lmdd label="File $FILE write bandwidth:" of=$FILE move=${MB}m fsync=1 print=3
	done
}

function udp_soc_lat {
	echo UDP socket latency
	run lat_udp -s &
	sleep 3
	for i in `seq 1 $N_RUNS`
	do
		run lat_udp 127.0.0.1
		sleep 1
	done
	run lat_udp -127.0.0.1
	sleep 3
}

function tcp_soc_lat {
	echo TCP socket latency
	run lat_tcp -s &
	sleep 3
	for i in `seq 1 $N_RUNS`
	do
		run lat_tcp 127.0.0.1
		sleep 1
	done
	run lat_tcp -127.0.0.1
	sleep 3
}

function tcp_con_lat {
	echo TCP connect latency
	run lat_connect -s &
	sleep 3
	run lat_connect 127.0.0.1
	sleep 1
	run lat_connect -127.0.0.1
	sleep 3
}

function tcp_soc_bw {
	echo TCP socket bandwidth
	run bw_tcp -s &
	sleep 3
	for i in `seq 1 $N_RUNS`
	do
		run bw_tcp 127.0.0.1
		sleep 1
	done
	run bw_tcp -127.0.0.1
	sleep 3
}

function bw_unix {
	for i in `seq 1 $N_RUNS`
	do
		run bw_unix
	done
}

function bw_pipe {
	for i in `seq 1 $N_RUNS`
	do
		run bw_pipe
	done
}


declare -a tests=(
			"lat_syscall null"
			"lat_syscall read"
			"lat_syscall write"
			"lat_syscall stat $STAT"
			"lat_syscall fstat $STAT"
			"lat_syscall open $STAT"
			"lat_select file 500"
# DP 1/20/18: This test intermittently hangs on SGX, taking out of CI for now
#			"lat_select tcp 500"
			"lat_sig install"
			"lat_sig catch"
			"lat_sig prot lat_sig"
## DEP  2/4/19: Temporarily remove fork from the unit tests
#			"lat_proc fork"
## DEP 11/1/18: Temporarily remove exec from the unit tests
#			"lat_proc exec"
## DEP 6/16/18: Temporarily remove shell from the unit tests
#			"lat_proc shell"
			"lat_fs $FSDIR"
		);

declare -a test_funcs=(
# DP 7/4/18: This test intermittently hangs on SGX, taking out of CI for now
#			"af_unix"
			"wr_bw"
			"udp_soc_lat"
			"tcp_soc_lat"
			"tcp_con_lat"
			"tcp_soc_bw"
			"bw_unix"
## DEP 1/20/18: Temporarliy remove bw_pipe from the unit tests - intermittent hangs
#			"bw_pipe"
		);

date
echo Latency measurements
msleep 250

for i in `seq 0 $((${#tests[@]}-1))`
do
	echo "Running ${tests[$i]}"
	run ${tests[$i]}
done


for i in `seq 0 $((${#test_funcs[@]}-1))`
do
	echo "Calling ${test_funcs[$i]}"
	${test_funcs[$i]}
done

exit 0

