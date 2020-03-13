From ubuntu:18.04

RUN apt-get update \
    && apt-get upgrade -y

RUN apt-get install -y python3 python3-pip git \
    && pip3 install torch torchvision

RUN git clone https://github.com/oscarlab/graphene-tests.git

WORKDIR /graphene-tests/pytorch

CMD ["python3"]
