#!/bin/bash

###############################################################################
## Sample script for running SPECjbb2015 in Composite mode.
## 
## This sample script demonstrates launching the Controller, TxInjector and 
## Backend in a single JVM.
###############################################################################

# Launch command: java [options] -jar specjbb2015.jar [argument] [value] ...

# Benchmark options (-Dproperty=value to override the default and property file value)
# Please add -Dspecjbb.controller.host=$CTRL_IP (this host IP) and -Dspecjbb.time.server=true
# when launching Composite mode in virtual environment with Time Server located on the native host.
SPEC_OPTS=""

# Java options for Composite JVM
JAVA_OPTS=""

# Optional arguments for the Composite mode (-l <num>, -p <file>, -skipReport, etc.)
MODE_ARGS=""

# Number of successive runs
NUM_OF_RUNS=1

###############################################################################
# This benchmark requires a JDK7 compliant Java VM.  If such a JVM is not on
# your path already you must set the JAVA environment variable to point to
# where the 'java' executable can be found.
#
# If you are using a JDK9 Java VM, see the FAQ at:
#                       http://spec.org/jbb2015/docs/faq.html
###############################################################################

JAVA=java
NO_OF_ARGS=$#
ENV_TYPE=$1
STACK_SIZE=$2
MAX_HEAP_SIZE=$3
which $JAVA > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "ERROR: Could not find a 'java' executable. Please set the JAVA environment variable or update the PATH."
    exit 1
fi

if [ $NO_OF_ARGS -eq 0 ]
then
	ENV_TYPE="graphene-direct"
	STACK_SIZE="-Xss256K"
	MAX_HEAP_SIZE="-Xmx32G"
	echo "no argument passed. Usage:"
	echo "./run_composite.sh <graphene-SGX | graphene-direct> <JVM Stack Size> <Max JVM Heap Size>"
	echo "Example: ./run_composite.sh graphene-sgx -Xss256K -Xmx32G"
	echo "specjbb2015 ill be executed with default arguments: ./run_composite.sh graphene-direct -Xss256K -Xmx32G"
fi

for ((n=1; $n<=$NUM_OF_RUNS; n=$n+1)); do

  # Create result directory                
  timestamp=$(date '+%y-%m-%d_%H%M%S')
  result=./$timestamp
  mkdir $result

  # Copy current config to the result directory
  cp -r config $result

  cd $result
  cd ../
  echo "Run $n: $timestamp"
  echo "Launching SPECjbb2015 in Composite mode..."
  echo

  echo "Start Composite JVM"
  echo "[ $ENV_TYPE $JAVA $STACK_SIZE $MAX_HEAP_SIZE -XX:+UseParallelOldGC -jar files/specjbb2015.jar -m COMPOSITE $MODE_ARGS ]"
$ENV_TYPE $JAVA $STACK_SIZE $MAX_HEAP_SIZE  -XX:+UseParallelOldGC -jar files/specjbb2015.jar -m COMPOSITE $MODE_ARGS 2>$result/composite.log > $result/composite.out &

 COMPOSITE_PID=$!
 echo "Composite JVM PID = $COMPOSITE_PID"


  sleep 3

  echo
  echo "SPECjbb2015 is running..."
  echo "Please monitor $result/composite.out for progress"

  wait $COMPOSITE_PID
  echo
  echo "Composite JVM has stopped"

  echo "SPECjbb2015 has finished"
  echo


 cd ..

done

exit 0
