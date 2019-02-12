#!/usr/bin/env bash

PROTOCOL=${PROTOCOL:=http}
declare -A THROUGHPUTS
declare -A LATENCIES
LOOP=5
DOWNLOAD_HOST=$1
DOWNLOAD_FILE=random/10K.1.html
REQUESTS=10000
CONCURRENCY_LIST="1 2 4 8 16 32 64 128 256"
RESULT=result-$(date +%y%m%d-%H%M%S)
URL="$PROTOCOL://$DOWNLOAD_HOST/$DOWNLOAD_FILE"

touch $RESULT

RUN=0
while [ $RUN -lt $LOOP ]
do
	for CONCURRENCY in $CONCURRENCY_LIST
	do
		rm -f OUTPUT
		echo "ab -n $REQUESTS -c $CONCURRENCY $URL"
		ab -n $REQUESTS -c $CONCURRENCY $URL >> OUTPUT
		sleep 5

		THROUGHPUT=$(grep -m1 "Requests per second:" OUTPUT | awk '{ print $4 }')
		LATENCY=$(grep -m1 "Time per request:" OUTPUT | awk '{ print $4 }')
		THROUGHPUTS[$CONCURRENCY]="${THROUGHPUTS[$CONCURRENCY]} $THROUGHPUT"
		LATENCIES[$CONCURRENCY]="${LATENCIES[$CONCURRENCY]} $LATENCY"
		echo "concurrency=$CONCURRENCY, throughput=$THROUGHPUT, latency=$LATENCY"
	done
	RUN=$(expr $RUN + 1)
done

for CONCURRENCY in $CONCURRENCY_LIST
do
	THROUGHPUT=$(echo ${THROUGHPUTS[$CONCURRENCY]} | tr " " "\n" | sort -n | awk '{a[NR]=$0}END{if(NR%2==1)print a[int(NR/2)+1];else print(a[NR/2-1]+a[NR/2])/2}')
	LATENCY=$(echo ${LATENCIES[$CONCURRENCY]} | tr " " "\n" | sort -n | awk '{a[NR]=$0}END{if(NR%2==1)print a[int(NR/2)+1];else print(a[NR/2-1]+a[NR/2])/2}')
	echo "$THROUGHPUT,$LATENCY" >> $RESULT
done

echo "Result file: $RESULT"
