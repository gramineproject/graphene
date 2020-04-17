From ubuntu:18.04

RUN apt-get update

RUN apt-get install -y python3 \
    && mkdir -p /graphene/Examples

COPY python-simple/ /graphene/Examples

CMD ["python3"]
