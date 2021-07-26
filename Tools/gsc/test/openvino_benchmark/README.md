OpenVINO benchmark runs with GSC
=====================================================
The ``../test`` directory contains a dockerfile and a manifest file for the most recent version of
OpenVINO toolkit (as of this writing, version 2021.4). We use the ``Benchmark C++ Tool`` (benchmark_app) from
the OpenVINO distribution as a concrete application running under Graphene-SGX to estimate deep
learning inference performance. We test only the CPU backend (i.e., no GPU or FPGA).

## Tips for better performance:
Linux systems have CPU frequency scaling governor that helps the system to scale the CPU frequency
to achieve best performance or to save power based on the requirement. To achieve the best
performance, please set the CPU frequency scaling governor to `performance` mode.

```
for ((i=0; i<$(nproc); i++)); \
do echo 'performance' > /sys/devices/system/cpu/cpu$i/cpufreq/scaling_governor; done
```

## Software requirements:
Check Prerequisites section from https://graphene.readthedocs.io/en/latest/manpages/gsc.html#prerequisites
to install all software packages required for GSC.

## Supported models for Graphene-SGX:
The following models have been enabled and tested with Graphene-SGX.

- resnet-50-tf(FP16/FP32)
- ssd_mobilenet_v1_coco(FP16/FP32)
- bert-large-uncased-whole-word-masking-squad-0001(FP16/FP32)
- bert-large-uncased-whole-word-masking-squad-int8-0001(INT8)
- brain-tumor-segmentation-0001(FP16/FP32)
- brain-tumor-segmentation-0002(FP16/FP32)

## Build graphenize docker image:
1. Go to gsc directory. 
```
cd $(GRAPHENE_DIR)/Tools/gsc
```

2. Create a configuration file: Manually adopt config.yaml to the installed Intel SGX driver and
desired Graphene repository/version
```
cp config.yaml.template config.yaml
```

3. Generate the signing key:
```
openssl genrsa -3 -out enclave-key.pem 3072
```

4. Build docker image:
```
cd test
docker build --build-arg BUILD_ID=2021.4.582 --shm-size=4g --rm -t ubuntu18.04-openvino -f \
ubuntu18.04-openvino.dockerfile ../../../Examples
```

5. Graphenize the docker image using gsc build:
```
cd ..
./gsc build --insecure-args ubuntu18.04-openvino test/ubuntu18.04-openvino.manifest
```

6. Sign the graphenized Docker image using gsc sign-image: 
```
./gsc sign-image ubuntu18.04-openvino enclave-key.pem
```

## Running the benchmark:
Performance benchmark on Xeon servers (Silver/Gold/Platinum) must be launched with increased number
of inference requests. Options ``-nireq``, ``-nstreams`` and ``-nthreads`` should be set to the
``number of physical cores * 2`` (take into account hyperthreading) for achieving maximum
performance.

**NOTE**: To get `number of physical cores`, do ``lscpu | grep 'Core(s) per socket'``.

### Throughput runs:

#### GSC:
```
$ docker run --cpuset-cpus="0-35,72-107" --cpuset-mems=0 \
--env KMP_AFFINITY=granularity=fine,noverbose,compact,1,0 --device /dev/sgx_enclave \
gsc-ubuntu18.04-openvino -c './benchmark_app -i <image files> \
-m model/<public | intel>/<model_dir>/<INT8 | FP16 | FP32>/<model_xml_file> \
-d CPU -b 1 -t 20 -nstreams 72 -nthreads 72 -nireq 72'
```
change --device=/dev/sgx_enclave to your version of the Intel SGX driver if needed.

#### Native:
```
$ docker run --privileged -it ubuntu18.04-openvino bash
$ KMP_AFFINITY=granularity=fine,noverbose,compact,1,0 numactl --cpubind=0 --membind=0 \
./benchmark_app -i <image files> \
-m model/<public | intel>/<model_dir>/<INT8 | FP16 | FP32>/<model_xml_file> \
-d CPU -b 1 -t 20 -nstreams 72 -nthreads 72 -nireq 72
```

Above commands are for a 36 core system. Please set the following options accordingly for 
optimal performance.
- cpuset-cpus=`NUMA node0 CPU(s)`
- nstreams=`<number of physical cores * 2>`
- nthread=`<number of physical cores * 2>`
- nireq=`<number of physical cores * 2>` 
- **NOTE**: To get `number of physical cores`, do ``lscpu | grep 'Core(s) per socket'``.
- **NOTE**: To get `NUMA node0 CPU(s)` do ``lscpu | grep 'NUMA node0 CPU(s)'``.

**NOTE 1**: Option ``-i <image files>`` is optional. A user may use this option as required.\
**NOTE 2**: Please tune batch size to get best performance in your system.\
**NOTE 3**: Model files for bert-large can be found in ``model/intel`` directory and for rest of
the models these are stored in ``model/public`` directory.\
**NOTE 4**: Based on the precision for bert-large and brain-tumor-segmentation models the enclave
size must be set to 64/128 GB.\
**NOTE 5**: In multi-socket systems for bert-large-uncased-whole-word-masking-squad-0001 and
brain-tumor-segmentation-0001 FP32/FP16 models please expand memory nodes usage with
``numactl --membind`` if memory allocation fails.

### Latency runs:

#### GSC:
```
$ docker run --cpuset-cpus="0-35,72-107" --cpuset-mems="0" \
--env KMP_AFFINITY=granularity=fine,noverbose,compact,1,0 --device /dev/sgx_enclave \
gsc-ubuntu18.04-openvino -c './benchmark_app -i <image files> \
-m model/<public | intel>/<model_dir>/<INT8 | FP16 | FP32>/<model_xml_file> \
-d CPU -b 1 -t 20 -api sync'
```

#### Native:
```
$ docker run --privileged -it ubuntu18.04-openvino bash
$ KMP_AFFINITY=granularity=fine,noverbose,compact,1,0 numactl --cpubind=0 --membind=0 \
./benchmark_app -i <image files> \
-m model/<public | intel>/<model_dir>/<INT8 | FP16 | FP32>/<model_xml_file> \
-d CPU -b 1 -t 20 -api sync
```

Above commands are for a 36 core system. Please set the following options accordingly for 
optimal performance.
- cpuset-cpus=`NUMA node0 CPU(s)`
- **NOTE**: To get 'NUMA node0 CPU(s)' do ``lscpu | grep 'NUMA node0 CPU(s)'``

**NOTE**: Option ``-i <image files>`` is optional. A user may use this option as required.

# Performance considerations
- Preheat manifest option pre-faults the enclave memory and moves the performance penalty to
graphene-sgx startup (before the workload starts executing). To use preheat option, add
``sgx.preheat_enclave = 1`` to the manifest template.
- Skipping invalid user pointer checks when the application does not invoke system calls with
invalid pointers (typical case) can help improve performance. To use this option, add
``libos.check_invalid_pointers = 0`` to the
manifest template.
- TCMalloc and mimalloc are memory allocator libraries from Google and Microsoft that can help
improve performance significantly based on the workloads. At any point, only one of these
allocators can be used.
  - TCMalloc (please update the binary location and name if different from default)
    - Install tcmalloc : ``sudo apt-get install google-perftools``
    - Add these in the manifest template:
        - ``loader.env.LD_PRELOAD = "/usr/lib/x86_64-linux-gnu/libtcmalloc.so.4"``
        - ``sgx.trusted_files.libtcmalloc = "file:/usr/lib/x86_64-linux-gnu/libtcmalloc.so.4"``
        - ``sgx.trusted_files.libunwind = "file:/usr/lib/x86_64-linux-gnu/libunwind.so.8"``
    - Save the manifest template and rebuild this example.
  - mimalloc (please update the binary location and name if different from default)
    - Install mimalloc using the steps from https://github.com/microsoft/mimalloc
    - Add these in the manifest template:
        - ``loader.env.LD_PRELOAD = "/usr/local/lib/mimalloc-1.7/libmimalloc.so.1.7"``
        - ``sgx.trusted_files.libmimalloc = "file:/usr/local/lib/mimalloc-1.7/libmimalloc.so.1.7"``
    - Save the manifest template and rebuild this example.
