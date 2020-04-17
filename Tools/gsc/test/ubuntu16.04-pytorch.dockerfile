From ubuntu:16.04

RUN apt-get update

RUN apt-get install -y python3 python3-pip \
    && pip3 install torch torchvision \
    && mkdir -p /graphene/Examples

COPY pytorch/ /graphene/Examples

WORKDIR /graphene/Examples

CMD ["python3"]
