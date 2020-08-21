#!/bin/bash

# BEFORE RUNNING THIS, FOR SGX PPML:
# - Build Examples/ra-tls-secret-prov with DCAP and start ./secret_prov_server_dcap
# - Build libsecret_prov_attest.so and copy here

set -e

SCRIPT=pytorchexample.py
STDERRFWD=stderr.log

# batch size of 1 best for latency, batch size of 32 best for throughput;
# we use 32 because higher batch sizes (64, 128) lead to 64GB enclaves and
# are thus too slow for our experiments
sizes=(
    1
    32
)

# experiments performed on 36 physical cores, 72 hyperthreads
threads=(
    1
    2
    4
    8
    16
    24
    32
    36
    40
    48
    56
    64
    72
)

# for experiments, use only 4 most interesting network models
networks=(
	squeezenet1_0
	vgg19
	wide_resnet50_2
	resnet50
#	alexnet
#	densenet161
#	mobilenet_v2
#	googlenet
#	inception_v3
)

if [ "$#" -eq  "0" ]
then
	echo "this script needs an argument"
	echo "choose one of following: native, graphene, sgx, ppml"
	exit 1
fi

if [ "$1" == "ppml" ]
then
	cp pytorch.manifest.template.ppml pytorch.manifest.template
	sed "s/^#alexnet/alexnet/" -i pytorchexample.py
	sed "s/^alexnet = models/#alexnet = models/" -i pytorchexample.py
else
	cp plaintext/* .
	cp pytorch.manifest.template.sgx pytorch.manifest.template
	sed "s/^#alexnet/alexnet/" -i pytorchexample.py
	sed "s/^alexnet = torch/#alexnet = torch/" -i pytorchexample.py
fi

for i in {1..3}; do
for SIZE in "${sizes[@]}"; do
for NETWORK in "${networks[@]}"; do
for NUM_THREADS in ${threads[@]}; do
	echo "=== $1 $i $SIZE $NETWORK $NUM_THREADS ==="

	# set the number of threads, batch size, and used model
	sed "s/EXP_NUM_THREADS = [0-9]*/EXP_NUM_THREADS = $NUM_THREADS/" -i $SCRIPT
	sed "s/EXP_BATCH_SIZE  = [0-9]*/EXP_BATCH_SIZE  = $SIZE/" -i $SCRIPT
	sed "s/models.[a-zA-Z0-9_]*(/models.$NETWORK(/" -i $SCRIPT

	if [ "$1" == "native" ]; then
		make clean >/dev/null
		make SGX=1 >/dev/null
		OMP_NUM_THREADS=$NUM_THREADS MKL_NUM_THREADS=$NUM_THREADS numactl --cpunodebind=0 --membind=0 \
        python3 $SCRIPT
	fi

	if [ "$1" == "graphene" ]; then
		make clean >/dev/null
		make SGX=1 >/dev/null
		OMP_NUM_THREADS=$NUM_THREADS MKL_NUM_THREADS=$NUM_THREADS numactl --cpunodebind=0 --membind=0 \
		./pal_loader pytorch.manifest $SCRIPT 2>$STDERRFWD
	fi

	if [ "$1" == "sgx" ]; then
		make clean >/dev/null
		NETFILE=$(ls ~/.cache/torch/hub/checkpoints | grep "^$NETWORK")
		sed "s/[a-z0-9_-]*\.pth$/$NETFILE/" -i pytorch.manifest.template
		make SGX=1 >/dev/null
		SGX=1 OMP_NUM_THREADS=$NUM_THREADS MKL_NUM_THREADS=$NUM_THREADS numactl --cpunodebind=0 --membind=0 \
		./pal_loader pytorch.manifest $SCRIPT 2>$STDERRFWD
	fi

	if [ "$1" == "ppml" ]; then
		sed "s/models\.[a-zA-Z0-9_]*(/models\.$NETWORK(/" -i download-pretrained-model.py
		make clean >/dev/null
		make download_model >/dev/null
		LD_LIBRARY_PATH=../ra-tls-secret-prov ../ra-tls-secret-prov/pf_crypt encrypt -w ../ra-tls-secret-prov/files/wrap-key -i ./plaintext/pretrained.pt -o pretrained.pt >/dev/null
		LD_LIBRARY_PATH=../ra-tls-secret-prov ../ra-tls-secret-prov/pf_crypt encrypt -w ../ra-tls-secret-prov/files/wrap-key -i ./plaintext/input.jpg -o input.jpg >/dev/null
		LD_LIBRARY_PATH=../ra-tls-secret-prov ../ra-tls-secret-prov/pf_crypt encrypt -w ../ra-tls-secret-prov/files/wrap-key -i ./plaintext/classes.txt -o classes.txt >/dev/null
		make SGX=1 >/dev/null
		SGX=1 OMP_NUM_THREADS=$NUM_THREADS MKL_NUM_THREADS=$NUM_THREADS numactl --cpunodebind=0 --membind=0 \
		./pal_loader pytorch.manifest $SCRIPT 2>$STDERRFWD
	fi
done
done
done
done
