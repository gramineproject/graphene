From ubuntu:18.04

WORKDIR /app

RUN apt-get update \
    && apt-get -y install nodejs \
    && mkdir -p /graphene/Examples

# Build environment of this Dockerfile should point to the root of Graphene's Examples/
COPY nodejs/ /graphene/Examples

CMD ["node"]
