From ubuntu:18.04

# Install prerequisites
RUN apt-get update \
    && apt-get install -y git wget \
    && apt-get install -y python3.6 python3-pip

RUN pip3 install --upgrade pip

# Install tensorflow
RUN pip3 install intel-tensorflow-avx512==2.4.0

# Download input graph file
RUN wget https://storage.googleapis.com/intel-optimized-tensorflow/models/v1_8/resnet50v1_5_int8_pretrained_model.pb

# Download model
RUN git clone https://github.com/IntelAI/models.git /models/

ENTRYPOINT ["python3.6"]
