From ubuntu:18.04

# Install prerequisites
RUN apt-get update \
    && apt-get install -y git wget python3 python3-pip unzip \
    && pip3 install --upgrade pip

# Install tensorflow
RUN pip3 install intel-tensorflow-avx512==2.4.0

# Download models
RUN git clone https://github.com/IntelAI/models.git /models/

# Download data
RUN mkdir -p data \
    && cd data \
    && wget https://storage.googleapis.com/bert_models/2019_05_30/wwm_uncased_L-24_H-1024_A-16.zip \
    && unzip wwm_uncased_L-24_H-1024_A-16.zip \
    && wget https://rajpurkar.github.io/SQuAD-explorer/dataset/dev-v1.1.json -P wwm_uncased_L-24_H-1024_A-16 \
    && wget https://storage.googleapis.com/intel-optimized-tensorflow/models/v1_8/bert_large_checkpoints.zip \
    && unzip bert_large_checkpoints.zip \
    && wget https://storage.googleapis.com/intel-optimized-tensorflow/models/v2_4_0/fp32_bert_squad.pb

ENTRYPOINT ["python3"]
