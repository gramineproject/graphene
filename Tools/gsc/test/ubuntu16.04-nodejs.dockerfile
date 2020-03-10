From ubuntu:16.04

WORKDIR /app

RUN apt-get update \
    && apt-get upgrade -y

RUN apt-get -y install nodejs git

RUN git clone https://github.com/oscarlab/graphene-tests.git

CMD ["nodejs"]