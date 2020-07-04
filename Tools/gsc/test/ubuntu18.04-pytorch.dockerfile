From ubuntu:18.04

RUN apt-get update

RUN apt-get install -y python3 python3-pip \
    && pip3 install torch torchvision \
    && mkdir -p /graphene/Examples

# The build environment of this Dockerfile should point to the root of Graphene's Examples
# directory.
COPY pytorch/ /graphene/Examples

WORKDIR /graphene/Examples

RUN python3 download-pretrained-model.py

CMD ["python3"]
