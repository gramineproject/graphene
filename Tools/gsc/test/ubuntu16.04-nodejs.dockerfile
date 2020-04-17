From ubuntu:16.04

WORKDIR /app

RUN apt-get update

RUN apt-get -y install nodejs \
    && mkdir -p /graphene/Examples

COPY nodejs/ /graphene/Examples

CMD ["nodejs"]