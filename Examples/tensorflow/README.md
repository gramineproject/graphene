## Run inference on TensorFlow BERT and ResNet50 models
This directory contains steps and artifacts to run inference with TensorFlow BERT and ResNet50 sample workloads on Graphene. Specifically, both these examples use pre-trained models to run inference. We tested this on Ubuntu 18.04 and uses the package version of Python 3.6.

## Pre-System setting
Linux systems have CPU frequency scaling governor that helps the system to scale the CPU frequency to achieve best performance or to save power based on the requirement. To achieve the best peformance, please set the CPU frequency scaling governor to performance mode.

``for ((i=0; i<$(nproc); i++)); do echo 'performance' > /sys/devices/system/cpu/cpu$i/cpufreq/scaling_governor; done``

## Pre-requisites
- Install python3.6.
- Upgrade pip/pip3.
- Install tensorflow using ``pip install intel-tensorflow-avx512==2.4.0`` or by downloading whl package from https://pypi.org/project/intel-tensorflow-avx512/2.4.0/#files.

## Build BERT or ResNet50 samples
- To build BERT sample, do ``cd BERT`` or to build ResNet50 sample, do ``cd ResNet50``.
- To clean the sample, do ``make clean``
- To clean and remove downloaded  models and datasets, do ``make distclean``
- To build the non-SGX version, do ``make PYTHONDISTPATH=path_to_python_dist_packages/``
- To build the SGX version, do ``make PYTHONDISTPATH=path_to_python_dist_packages/ SGX=1``
>**NOTE** Typically, path_to_python_dist_packages is '/usr/local/lib/python3.6/dist-packages', but can change based on python's installation directory.

## Run inference on BERT model
- To run int8 inference on graphene-sgx(SGX version)<br>
``KMP_BLOCKTIME=1 KMP_SETTINGS=1 OMP_NUM_THREADS=36 KMP_AFFINITY=granularity=fine,verbose,compact,1,0 taskset -c 0-35 graphene-sgx ./python models/models/language_modeling/tensorflow/bert_large/inference/run_squad.py --init_checkpoint=data/bert_large_checkpoints/model.ckpt-3649 --vocab_file=data/wwm_uncased_L-24_H-1024_A-16/vocab.txt --bert_config_file=data/wwm_uncased_L-24_H-1024_A-16/bert_config.json --predict_file=data/wwm_uncased_L-24_H-1024_A-16/dev-v1.1.json --precision=int8 --output_dir=output/bert-squad-output --predict_batch_size=32 --experimental_gelu=True --optimized_softmax=True --input_graph=data/asymmetric_per_channel_bert_int8.pb --do_predict=True --mode=benchmark --inter_op_parallelism_threads=1 --intra_op_parallelism_threads=36``
- To run int8 inference on graphene-direct(non-SGX version)<br>
``KMP_BLOCKTIME=1 KMP_SETTINGS=1 OMP_NUM_THREADS=36 KMP_AFFINITY=granularity=fine,verbose,compact,1,0 taskset -c 0-35 graphene-direct ./python models/models/language_modeling/tensorflow/bert_large/inference/run_squad.py --init_checkpoint=data/bert_large_checkpoints/model.ckpt-3649 --vocab_file=data/wwm_uncased_L-24_H-1024_A-16/vocab.txt --bert_config_file=data/wwm_uncased_L-24_H-1024_A-16/bert_config.json --predict_file=data/wwm_uncased_L-24_H-1024_A-16/dev-v1.1.json --precision=int8 --output_dir=output/bert-squad-output --predict_batch_size=32 --experimental_gelu=True --optimized_softmax=True --input_graph=data/asymmetric_per_channel_bert_int8.pb --do_predict=True --mode=benchmark --inter_op_parallelism_threads=1 --intra_op_parallelism_threads=36``
- To run int8 inference on native baremetal(outside graphene)<br>
``KMP_BLOCKTIME=1 KMP_SETTINGS=1 OMP_NUM_THREADS=36 KMP_AFFINITY=granularity=fine,verbose,compact,1,0 taskset -c 0-35 python3.6 models/models/language_modeling/tensorflow/bert_large/inference/run_squad.py --init_checkpoint=data/bert_large_checkpoints/model.ckpt-3649 --vocab_file=data/wwm_uncased_L-24_H-1024_A-16/vocab.txt --bert_config_file=data/wwm_uncased_L-24_H-1024_A-16/bert_config.json --predict_file=data/wwm_uncased_L-24_H-1024_A-16/dev-v1.1.json --precision=int8 --output_dir=output/bert-squad-output --predict_batch_size=32 --experimental_gelu=True --optimized_softmax=True --input_graph=data/asymmetric_per_channel_bert_int8.pb --do_predict=True  --mode=benchmark --inter_op_parallelism_threads=1 --intra_op_parallelism_threads=36``
- Above commands are for a 36 core system. Please set the following options accordingly for optimal performance.
	- OMP_NUM_THREADS='Core(s) per socket'
	- taskset to 'Core(s) per socket'
	- intra_op_parallelism_threads='Core(s) per socket'
>**NOTE** To get 'Core(s) per socket', do ``lscpu | grep 'Core(s) per socket'``

## Run inference on ResNet50 model
- To run inference on graphene-sgx(SGX version)<br>
``OMP_NUM_THREADS=36 KMP_AFFINITY=granularity=fine,verbose,compact,1,0 taskset -c 0-35 graphene-sgx ./python models/models/image_recognition/tensorflow/resnet50v1_5/inference/eval_image_classifier_inference.py --input-graph=resnet50v1_5_int8_pretrained_model.pb --num-inter-threads=1 --num-intra-threads=36 --batch-size=512 --warmup-steps=50 --steps=500``
- To run inference on graphene-direct(non-SGX version)<br>
``OMP_NUM_THREADS=36 KMP_AFFINITY=granularity=fine,verbose,compact,1,0 taskset -c 0-35 graphene-direct ./python models/models/image_recognition/tensorflow/resnet50v1_5/inference/eval_image_classifier_inference.py --input-graph=resnet50v1_5_int8_pretrained_model.pb --num-inter-threads=1 --num-intra-threads=36 --batch-size=512 --warmup-steps=50 --steps=500``
- To run inference on native baremetal(outside graphene)<br>
``OMP_NUM_THREADS=36 KMP_AFFINITY=granularity=fine,verbose,compact,1,0 taskset -c 0-35 python3.6 models/models/image_recognition/tensorflow/resnet50v1_5/inference/eval_image_classifier_inference.py --input-graph=resnet50v1_5_int8_pretrained_model.pb --num-inter-threads=1 --num-intra-threads=36 --batch-size=128 --warmup-steps=50 --steps=500``
- Above commands are for a 36 core system. Please set the following options accordingly for optimal performance.
	- OMP_NUM_THREADS='Core(s) per socket'
	- taskset to 'Core(s) per socket'
	- num-intra-threads='Core(s) per socket'
>**NOTE** To get 'Core(s) per socket', do ``lscpu | grep 'Core(s) per socket'``

# GSC :

## Build graphenize Docker image and run BERT inference :
1. ``cd $(GRAPHENE_DIR)/Tools/gsc``

2. Create a configuration file : ``cp config.yaml.template config.yaml``  
Manually adopt config.yaml to the installed Intel SGX driver and desired Graphene repository/version

3. Generate the signing key : ``openssl genrsa -3 -out enclave-key.pem 3072``

4. Build docker image :
    - ``cd test``
    - ``docker build --rm -t ubuntu18.04-tensorflow-bert -f ubuntu18.04-tensorflow-bert.dockerfile ../../../Examples``

5. Graphenize the docker image using gsc build :
    - ``cd ..``
    - ``./gsc build --insecure-args ubuntu18.04-tensorflow-bert test/ubuntu18.04-tensorflow.manifest``

6. Sign the graphenized Docker image using gsc sign-image : ``./gsc sign-image ubuntu18.04-tensorflow-bert enclave-key.pem``

7. To run int8 inference on GSC <br>
``docker run --device=/dev/sgx_encalve --cpuset-cpus="0-35" --env OMP_NUM_THREADS=36 --env KMP_BLOCKTIME=1 --env KMP_SETTINGS=1 --env KMP_AFFINITY=granularity=fine,noverbose,compact,1,0 gsc-ubuntu18.04-tensorflow-bert models/models/language_modeling/tensorflow/bert_large/inference/run_squad.py --init_checkpoint=data/bert_large_checkpoints/model.ckpt-3649 --vocab_file=data/wwm_uncased_L-24_H-1024_A-16/vocab.txt --bert_config_file=data/wwm_uncased_L-24_H-1024_A-16/bert_config.json --predict_file=data/wwm_uncased_L-24_H-1024_A-16/dev-v1.1.json --precision=int8 --predict_batch_size=32 --experimental_gelu=True --optimized_softmax=True --input_graph=data/asymmetric_per_channel_bert_int8.pb --do_predict=True --mode=benchmark --inter_op_parallelism_threads=1 --intra_op_parallelism_threads=36 --output_dir=output/bert-squad-output``

8. To run int8 inference on native container <br>
``docker run --cpuset-cpus="0-35" --env OMP_NUM_THREADS=36 --env KMP_BLOCKTIME=1 --env KMP_SETTINGS=1 --env KMP_AFFINITY=granularity=fine,noverbose,compact,1,0 ubuntu18.04-tensorflow-bert models/models/language_modeling/tensorflow/bert_large/inference/run_squad.py --init_checkpoint=data/bert_large_checkpoints/model.ckpt-3649 --vocab_file=data/wwm_uncased_L-24_H-1024_A-16/vocab.txt --bert_config_file=data/wwm_uncased_L-24_H-1024_A-16/bert_config.json --predict_file=data/wwm_uncased_L-24_H-1024_A-16/dev-v1.1.json --precision=int8 --predict_batch_size=32 --experimental_gelu=True --optimized_softmax=True --input_graph=data/asymmetric_per_channel_bert_int8.pb --do_predict=True --mode=benchmark --inter_op_parallelism_threads=1 --intra_op_parallelism_threads=36 --output_dir=output/bert-squad-output``

9. Above commands are for a 36 core system. Please set the following options accordingly for optimal performance.
	- OMP_NUM_THREADS='Core(s) per socket'
	- --cpuset-cpus to 'Core(s) per socket'
	- intra_op_parallelism_threads='Core(s) per socket'
>**NOTE** To get 'Core(s) per socket', do ``lscpu | grep 'Core(s) per socket'``

## Build graphenize Docker image and run ResNet50 inference :
1. ``cd $(GRAPHENE_DIR)/Tools/gsc``

2. Create a configuration file : ``cp config.yaml.template config.yaml``  
Manually adopt config.yaml to the installed Intel SGX driver and desired Graphene repository/version

3. Generate the signing key : ``openssl genrsa -3 -out enclave-key.pem 3072``

4. Build docker image :
    - ``cd test``
    - ``docker build --rm -t ubuntu18.04-tensorflow-resnet50 -f ubuntu18.04-tensorflow-resnet50.dockerfile ../../../Examples``

5. Graphenize the docker image using gsc build :
    - ``cd ..``
    - ``./gsc build --insecure-args ubuntu18.04-tensorflow-resnet50 test/ubuntu18.04-tensorflow.manifest``

6. Sign the graphenized Docker image using gsc sign-image : ``./gsc sign-image ubuntu18.04-tensorflow-resnet50 enclave-key.pem``

7. To run inference on GSC <br>
``docker run --device=/dev/sgx_enclave --cpuset-cpus="0-35" --env OMP_NUM_THREADS=36 --env KMP_AFFINITY=granularity=fine,noverbose,compact,1,0 gsc-ubuntu18.04-tensorflow-resnet50 models/models/image_recognition/tensorflow/resnet50v1_5/inference/eval_image_classifier_inference.py --input-graph=resnet50v1_5_int8_pretrained_model.pb --num-inter-threads=1 --num-intra-threads=36 --batch-size=128 --warmup-steps=50 --steps=500``  
	> **NOTE**: When OOM happens pass option ``-env TF_MKL_ALLOC_MAX_BYTES=34359738368`` to docker run command.  
8. To run inference on native Container <br>
``docker run --cpuset-cpus="0-35" --env OMP_NUM_THREADS=36 --env KMP_AFFINITY=granularity=fine,noverbose,compact,1,0 ubuntu18.04-tensorflow-resnet50 models/models/image_recognition/tensorflow/resnet50v1_5/inference/eval_image_classifier_inference.py --input-graph=resnet50v1_5_int8_pretrained_model.pb --num-inter-threads=1 --num-intra-threads=36 --batch-size=128 --warmup-steps=50 --steps=500``

9. Above commands are for a 36 core system. Please set the following options accordingly for optimal performance.
	- OMP_NUM_THREADS='Core(s) per socket'
	-  --cpuset-cpus to 'Core(s) per socket'
	- num-intra-threads='Core(s) per socket'
>**NOTE** To get 'Core(s) per socket', do ``lscpu | grep 'Core(s) per socket'``

## Performance considerations
- Preheat manifest option pre-faults the enclave memory and moves the performance penalty to graphene-sgx invocation (before the workload starts executing). To use preheat option, add ``sgx.preheat_enclave = 1`` to the manifest template.
- TCMalloc and mimalloc are memory allocator libraries from Google and Microsoft that can help improve performance significantly based on the workloads. At any point, only one of these allocators can be used.
  - TCMalloc (Please update the binary location and name if different from default)
	- Install tcmalloc : sudo apt-get install google-perftools
	- Add these in the manifest template<br>
		``loader.env.LD_PRELOAD = "/usr/lib/x86_64-linux-gnu/libtcmalloc.so.4"``<br>
		``sgx.trusted_files.libtcmalloc = "file:/usr/lib/x86_64-linux-gnu/libtcmalloc.so.4"``<br>
		``sgx.trusted_files.libunwind = "file:/usr/lib/x86_64-linux-gnu/libunwind.so.8"``
	- Save the template and rebuild.
  - mimalloc (Please update the binary location and name if different from default)
	- Install mimalloc using the steps from https://github.com/microsoft/mimalloc
	- Add these in the manifest template<br>
		``loader.env.LD_PRELOAD = "/usr/local/lib/mimalloc-1.7/libmimalloc.so.1.7"``<br>
		``sgx.trusted_files.libmimalloc = "file:/usr/local/lib/mimalloc-1.7/libmimalloc.so.1.7"``
	- Save the template and rebuild.
