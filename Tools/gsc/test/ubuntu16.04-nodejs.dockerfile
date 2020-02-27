From ubuntu:16.04

WORKDIR /app

RUN apt-get update

RUN env DEBIAN_FRONTEND=noninteractive apt-get -y install nodejs git

RUN git clone https://github.com/oscarlab/graphene-tests.git

CMD ["nodejs"]