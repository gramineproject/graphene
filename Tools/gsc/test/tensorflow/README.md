# Inference on TensorFlow BERT and ResNet50 models:
The ``../test`` directory contains dockerfile and manifest file to run inference with TensorFlow BERT and 
ResNet50 sample workloads on GSC. Specifically, both these examples use pre-trained models to run 
inference. We tested this on Ubuntu 18.04 and uses the package version with Python 3.6.

## Bidirectional Encoder Representations from Transformers (BERT):
BERT is a method of pre-training language representations and then use that trained model for 
downstream NLP tasks like 'question answering'. BERT is an unsupervised, deeply birectional system 
for pre-training NLP. In this BERT sample, we use 'BERT-Large, Uncased (Whole Word Masking)' model 
and perform int8 inference. More details about BERT can be found at 
https://github.com/google-research/bert.

## Residual Network (ResNet):
ResNet50 is a convolutional neural network that is 50 layers deep. In this ResNet50(v1.5) sample, 
we use a pre-trained model and perform int8 inference. More details about ResNet50 can be found at 
https://github.com/IntelAI/models/tree/icx-launch-public/benchmarks/image_recognition/tensorflow/resnet50v1_5.

## Pre-System setting:
Linux systems have CPU frequency scaling governor that helps the system to scale the CPU frequency 
to achieve best performance or to save power based on the requirement. To achieve the best 
peformance, please set the CPU frequency scaling governor to performance mode.

```
for ((i=0; i<$(nproc); i++)); \
do echo 'performance' > /sys/devices/system/cpu/cpu$i/cpufreq/scaling_governor; done
```

## Common build steps:
1. ``cd $(GRAPHENE_DIR)/Tools/gsc``

2. Create a configuration file: ``cp config.yaml.template config.yaml``  
Manually adopt config.yaml to the installed Intel SGX driver and desired Graphene repository/version

3. Generate the signing key: ``openssl genrsa -3 -out enclave-key.pem 3072``

## Build graphenize Docker image and run BERT inference:
1. Build docker image:
```
cd test
docker build --rm -t ubuntu18.04-tensorflow-bert -f ubuntu18.04-tensorflow-bert.dockerfile \
../../../Examples
```

2. Graphenize the docker image using gsc build:
```
cd ..
./gsc build --insecure-args ubuntu18.04-tensorflow-bert test/ubuntu18.04-tensorflow.manifest
```

3. Sign the graphenized Docker image using gsc sign-image:
```
./gsc sign-image ubuntu18.04-tensorflow-bert enclave-key.pem
```

4. To run int8 inference on GSC:
```
docker run --device=/dev/sgx_enclave --cpuset-cpus="0-35" --env OMP_NUM_THREADS=36 \
--env KMP_AFFINITY=granularity=fine,noverbose,compact,1,0 \
gsc-ubuntu18.04-tensorflow-bert \
models/models/language_modeling/tensorflow/bert_large/inference/run_squad.py \
--init_checkpoint=data/bert_large_checkpoints/model.ckpt-3649 \
--vocab_file=data/wwm_uncased_L-24_H-1024_A-16/vocab.txt \
--bert_config_file=data/wwm_uncased_L-24_H-1024_A-16/bert_config.json \
--predict_file=data/wwm_uncased_L-24_H-1024_A-16/dev-v1.1.json \
--precision=int8 \
--predict_batch_size=32 \
--experimental_gelu=True \
--optimized_softmax=True \
--input_graph=data/asymmetric_per_channel_bert_int8.pb \
--do_predict=True \
--mode=benchmark \
--inter_op_parallelism_threads=1 \
--intra_op_parallelism_threads=36 \
--output_dir=output/bert-squad-output
```

5. To run int8 inference on native container:
```
docker run --cpuset-cpus="0-35" --env OMP_NUM_THREADS=36 \
--env KMP_AFFINITY=granularity=fine,noverbose,compact,1,0 \
ubuntu18.04-tensorflow-bert \
models/models/language_modeling/tensorflow/bert_large/inference/run_squad.py \
--init_checkpoint=data/bert_large_checkpoints/model.ckpt-3649 \
--vocab_file=data/wwm_uncased_L-24_H-1024_A-16/vocab.txt \
--bert_config_file=data/wwm_uncased_L-24_H-1024_A-16/bert_config.json \
--predict_file=data/wwm_uncased_L-24_H-1024_A-16/dev-v1.1.json \
--precision=int8 \
--predict_batch_size=32 \
--experimental_gelu=True \
--optimized_softmax=True \
--input_graph=data/asymmetric_per_channel_bert_int8.pb \
--do_predict=True \
--mode=benchmark \
--inter_op_parallelism_threads=1 \
--intra_op_parallelism_threads=36 \
--output_dir=output/bert-squad-output
```

6. Above commands are for a 36 core system. Please set the following options accordingly for 
optimal performance.
    - OMP_NUM_THREADS='Core(s) per socket'
    - --cpuset-cpus to 'Core(s) per socket'
    - num-intra-threads='Core(s) per socket'
    - If hyperthreading is enabled: use ``KMP_AFFINITY=granularity=fine,verbose,compact,1,0``
    - If hyperthreading is disabled: use ``KMP_AFFINITY=granularity=fine,verbose,compact``
    - **NOTE** To get 'Core(s) per socket', do ``lscpu | grep 'Core(s) per socket'`` \
    OMP_NUM_THREADS sets the maximum number of threads to use for OpenMP parallel regions. \
    KMP_AFFINITY binds OpenMP threads to physical processing units.

## Build graphenize Docker image and run ResNet50 inference:
1. Build docker image:
```
cd test
docker build --rm -t ubuntu18.04-tensorflow-resnet50 -f ubuntu18.04-tensorflow-resnet50.dockerfile \
../../../Examples
```

2. Graphenize the docker image using gsc build:
```cd ..
./gsc build --insecure-args ubuntu18.04-tensorflow-resnet50 test/ubuntu18.04-tensorflow.manifest
```

3. Sign the graphenized Docker image using gsc sign-image:
```
./gsc sign-image ubuntu18.04-tensorflow-resnet50 enclave-key.pem
```

4. To run inference on GSC:
```
docker run --device=/dev/sgx_enclave --cpuset-cpus="0-35" --env OMP_NUM_THREADS=36 \
--env KMP_AFFINITY=granularity=fine,noverbose,compact,1,0 \
gsc-ubuntu18.04-tensorflow-resnet50 \
models/models/image_recognition/tensorflow/resnet50v1_5/inference/eval_image_classifier_inference.py \
--input-graph=resnet50v1_5_int8_pretrained_model.pb \
--num-inter-threads=1 \
--num-intra-threads=36 \
--batch-size=32 \
--warmup-steps=50 \
--steps=500
```
**NOTE**: When OOM happens user can set environment varibale ``TF_MKL_ALLOC_MAX_BYTES`` to upper 
bound on memory allocation. As an example in a machine with 32 GB memory pass option 
``--env TF_MKL_ALLOC_MAX_BYTES=17179869184`` to docker run command when OOM happens.

5. To run inference on native Container:
```
docker run --cpuset-cpus="0-35" --env OMP_NUM_THREADS=36 \
--env KMP_AFFINITY=granularity=fine,noverbose,compact,1,0 \
ubuntu18.04-tensorflow-resnet50 \
models/models/image_recognition/tensorflow/resnet50v1_5/inference/eval_image_classifier_inference.py \
--input-graph=resnet50v1_5_int8_pretrained_model.pb \
--num-inter-threads=1 \
--num-intra-threads=36 \
--batch-size=32 \
--warmup-steps=50 \
--steps=500
```

6. Above commands are for a 36 core system. Please set the following options accordingly for 
optimal performance.
    - OMP_NUM_THREADS='Core(s) per socket'
    - --cpuset-cpus to 'Core(s) per socket'
    - num-intra-threads='Core(s) per socket'
    - If hyperthreading is enabled: use ``KMP_AFFINITY=granularity=fine,verbose,compact,1,0``
    - If hyperthreading is disabled: use ``KMP_AFFINITY=granularity=fine,verbose,compact``
    - The options batch-size, warmup-steps and steps can be varied.
    - **NOTE** To get 'Core(s) per socket', do ``lscpu | grep 'Core(s) per socket'`` \
    OMP_NUM_THREADS sets the maximum number of threads to use for OpenMP parallel regions. \
    KMP_AFFINITY binds OpenMP threads to physical processing units.

## Performance considerations:
- Preheat manifest option pre-faults the enclave memory and moves the performance penalty to 
graphene-sgx invocation (before the workload starts executing). To use preheat option, add 
``sgx.preheat_enclave = 1`` to the manifest template.
- TCMalloc and mimalloc are memory allocator libraries from Google and Microsoft that can help 
improve performance significantly based on the workloads. At any point, only one of these 
allocators can be used.
  - TCMalloc (Please update the binary location and name if different from default)
    - Install tcmalloc: ``sudo apt-get install google-perftools``
    - Add these in the manifest template
        - ``loader.env.LD_PRELOAD = "/usr/lib/x86_64-linux-gnu/libtcmalloc.so.4"``
        - ``sgx.trusted_files.libtcmalloc = "file:/usr/lib/x86_64-linux-gnu/libtcmalloc.so.4"``
        - ``sgx.trusted_files.libunwind = "file:/usr/lib/x86_64-linux-gnu/libunwind.so.8"``
    - Save the template and rebuild.
  - mimalloc (Please update the binary location and name if different from default)
    - Install mimalloc using the steps from https://github.com/microsoft/mimalloc
    - Add these in the manifest template
        - ``loader.env.LD_PRELOAD = "/usr/local/lib/mimalloc-1.7/libmimalloc.so.1.7"``
        - ``sgx.trusted_files.libmimalloc = "file:/usr/local/lib/mimalloc-1.7/libmimalloc.so.1.7"``
    - Save the template and rebuild.