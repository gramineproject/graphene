From ubuntu:18.04

RUN apt-get update

RUN apt-get install -y python3 \
    && mkdir -p /graphene/Examples

# The build environment of this Dockerfile should point to the root of Graphene's Examples
# directory.
COPY python-simple/ /graphene/Examples

CMD ["python3"]
