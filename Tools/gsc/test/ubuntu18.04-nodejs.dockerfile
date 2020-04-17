From ubuntu:18.04

WORKDIR /app

RUN apt-get update

RUN apt-get -y install nodejs \
    && mkdir -p /graphene/Examples

# The build environment of this Dockerfile should point to the root of Graphene's Examples
# directory.
COPY nodejs/ /graphene/Examples

CMD ["node"]
