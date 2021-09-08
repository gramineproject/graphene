# Inference on TensorFlow BERT and ResNet50 models:
For additional information on how to install, run and optimize TensorFlow, please see
https://github.com/Satya1493/graphene/blob/tensorflow/Examples/tensorflow/README.md.

## Build graphenize Docker image and run BERT inference:
1. Build docker image:
```
docker build --rm -t ubuntu18.04-tensorflow-bert -f ubuntu18.04-tensorflow-bert.dockerfile .
```

2. Graphenize the docker image using gsc build:
```
cd ../..
./gsc build --insecure-args ubuntu18.04-tensorflow-bert Examples/tensorflow/ubuntu18.04-tensorflow.manifest
```

3. Sign the graphenized Docker image using gsc sign-image:
```
./gsc sign-image ubuntu18.04-tensorflow-bert enclave-key.pem
```

4. To run fp32 inference on GSC:
```
docker run --device=/dev/sgx_enclave --cpuset-cpus="0-35" --env OMP_NUM_THREADS=36 \
--env KMP_AFFINITY=granularity=fine,noverbose,compact,1,0 \
gsc-ubuntu18.04-tensorflow-bert \
models/models/language_modeling/tensorflow/bert_large/inference/run_squad.py \
--init_checkpoint=data/bert_large_checkpoints/model.ckpt-3649 \
--vocab_file=data/wwm_uncased_L-24_H-1024_A-16/vocab.txt \
--bert_config_file=data/wwm_uncased_L-24_H-1024_A-16/bert_config.json \
--predict_file=data/wwm_uncased_L-24_H-1024_A-16/dev-v1.1.json \
--precision=fp32 \
--predict_batch_size=32 \
--experimental_gelu=True \
--optimized_softmax=True \
--input_graph=data/fp32_bert_squad.pb \
--do_predict=True \
--mode=benchmark \
--inter_op_parallelism_threads=1 \
--intra_op_parallelism_threads=36 \
--output_dir=output/bert-squad-output
```

5. To run fp32 inference on native container (outside Graphene), remove
``--device=/dev/sgx_enclave`` and replace ``gsc-ubuntu18.04-tensorflow-bert`` with
``ubuntu18.04-tensorflow-bert`` in the above command.

6. Above commands are for a 36 core system. Please check
https://github.com/Satya1493/graphene/blob/tensorflow/Examples/tensorflow/README.md for setting
different options for optimal performance.

## Build graphenize Docker image and run ResNet50 inference:
1. Build docker image:
```
docker build --rm -t ubuntu18.04-tensorflow-resnet50 -f ubuntu18.04-tensorflow-resnet50.dockerfile .
```

2. Graphenize the docker image using gsc build:
```
cd ../..
./gsc build --insecure-args ubuntu18.04-tensorflow-resnet50 Example/tensorflow/ubuntu18.04-tensorflow.manifest
```

3. Sign the graphenized Docker image using gsc sign-image:
```
./gsc sign-image ubuntu18.04-tensorflow-resnet50 enclave-key.pem
```

4. To run int8 inference on GSC:
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

5. To run int8 inference on native container (outside Graphene), remove
``--device=/dev/sgx_enclave`` and replace ``gsc-ubuntu18.04-tensorflow-resnet50`` with
``ubuntu18.04-tensorflow-resnet50`` in the above command.

6. Above commands are for a 36 core system. Please check
https://github.com/Satya1493/graphene/blob/tensorflow/Examples/tensorflow/README.md for setting
different options for optimal performance.
