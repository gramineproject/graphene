#!/usr/bin/env bash

ID=`id -u`
PGIDS=`ps -a -o pgid,command | tail -n +2 | \
	awk "{ if (\\\$2 ~ /\\/pal\$/ ) print \\\$1 }" | uniq`

NONE=1
for PGID in $PGIDS
do
	NONE=0
	ps -p $PGID -o pid,args 2> /dev/null | tail -n +2
done

if [ "$NONE" = "1" ]; then
	echo "no graphene instance"
	exit 0
fi

echo -n "choose intance(s): "
read SELECT_PGIDS

DO_KILL=0
for CMD in $SELECT_PGIDS
do
	if [ "$CMD" = "kill" ]; then
		SELECT_PGIDS=${SELECT_PGIDS:4}
		DO_KILL=1
	fi
	break
done

do_list()
{
	PGID=$1
	echo "instance $PGID:"
	PIDS=`ps -a -o pgid,pid --sort=start_time 2> /dev/null | tail -n +2 | \
		awk "{ if (\\\$1 == $PGID) print \\\$2 }"`

	CNT=1
	for PID in $PIDS
	do
		STAT=`ps -a -p $PID -o stat | tail -n +2`
		if [[ $STAT == Z* ]]; then
			printf "    %3d: process %5d (DEAD):" $CNT $PID
		else
			printf "    %3d: process %5d       :" $CNT $PID
		fi
		for TASK in /proc/$PID/task/*
		do
			printf " %5d" ${TASK##*/}
		done
		echo
		CNT=`expr $CNT + 1`
	done
}

do_kill()
{
	PGID=$1
	PIDS=`ps -a -o pgid,pid 2> /dev/null | tail -n +2 | \
		awk "{ if (\\\$1 == $PGID) print \\\$2 }"`
	kill -9 $PGID $PIDS
}

NONE=1
for PGID in $SELECT_PGIDS
do
	if [ "$DO_KILL" = "1" ]; then
		do_kill $PGID
	else
		do_list $PGID
	fi
	NONE=0
done

if [ "$NONE" = "1" ]; then
	for PGID in $PGIDS
	do
		if [ "$DO_KILL" = "1" ]; then
			do_kill $PGID
		else
			do_list $PGID
		fi
	done
fi
