From ubuntu:18.04

RUN apt-get update \
    && apt-get upgrade -y

RUN apt-get install -y python3 git

RUN git clone https://github.com/oscarlab/graphene-tests.git

CMD ["python3"]
