From ubuntu:18.04

RUN apt-get update \
    && apt-get install -y python3 python3-pip git \
    && pip3 install numpy \
    && mkdir -p /graphene/Examples

# Build environment of this Dockerfile should point to the root of Graphene's Examples/
COPY python/ /graphene/Examples

CMD ["python3"]
