# OpenVINO benchmark

For additional information on supported models for GSC, how to install, run and optimize OpenVINO,
please see
https://github.com/sahason/graphene/blob/ov_benchmark/Examples/openvino_benchmark/README.md.

## Building graphenize docker image

1. Build docker image:
```bash
docker build --build-arg BUILD_ID=2021.4.582 --shm-size=4g --rm -t ubuntu18.04-openvino -f \
ubuntu18.04-openvino.dockerfile .
```

2. Graphenize the docker image using `gsc build`:
```bash
cd ../..
./gsc build --insecure-args ubuntu18.04-openvino Examples/openvino_benchmark/ubuntu18.04-openvino.manifest
```

3. Sign the graphenized Docker image using `gsc sign-image`:
```bash
./gsc sign-image ubuntu18.04-openvino enclave-key.pem
```

## Running the benchmark

### Throughput runs

#### GSC

```bash
$ docker run --cpuset-cpus="0-35,72-107" --cpuset-mems=0 \
--env KMP_AFFINITY=granularity=fine,noverbose,compact,1,0 --device /dev/sgx_enclave \
gsc-ubuntu18.04-openvino -i <image files> \
-m model/<public | intel>/<model_dir>/<INT8 | FP16 | FP32>/<model_xml_file> \
-d CPU -b 1 -t 20 -nstreams 72 -nthreads 72 -nireq 72
```

#### Native

To run benchmark on native container (outside Graphene), remove
`--device=/dev/sgx_enclave` and replace `gsc-ubuntu18.04-openvino` with
`ubuntu18.04-openvino` in the above command.

### Latency runs

#### GSC

```bash
$ docker run --cpuset-cpus="0-35,72-107" --cpuset-mems="0" \
--env KMP_AFFINITY=granularity=fine,noverbose,compact,1,0 --device /dev/sgx_enclave \
gsc-ubuntu18.04-openvino -i <image files> \
-m model/<public | intel>/<model_dir>/<INT8 | FP16 | FP32>/<model_xml_file> \
-d CPU -b 1 -t 20 -api sync
```

#### Native

To run benchmark on native container (outside Graphene), remove
`--device=/dev/sgx_enclave` and replace `gsc-ubuntu18.04-openvino` with
`ubuntu18.04-openvino` in the above command.

The above `docker run` commands are for a 36-core system. Please check
https://github.com/sahason/graphene/blob/ov_benchmark/Examples/openvino_benchmark/README.md for an
overview of options to achieve optimal performance on different systems.
