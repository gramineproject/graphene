From ubuntu:16.04

RUN apt-get update

RUN apt-get install -y python3 python3-pip \
    && pip3 install numpy \
    && mkdir -p /graphene/Examples

COPY python-scipy-insecure/ /graphene/Examples

CMD ["python3"]
