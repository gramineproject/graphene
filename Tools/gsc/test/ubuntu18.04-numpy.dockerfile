From ubuntu:18.04

RUN apt-get update

RUN apt-get install -y python3 python3-pip git \
    && pip3 install numpy \
    && mkdir -p /graphene/Examples

# The build environment of this Dockerfile should point to the root of Graphene's Examples
# directory.
COPY python-scipy-insecure/ /graphene/Examples

CMD ["python3"]
