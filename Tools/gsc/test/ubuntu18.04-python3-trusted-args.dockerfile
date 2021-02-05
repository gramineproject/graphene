From ubuntu:18.04

RUN apt-get update \
    && apt-get install -y python3

CMD ["python3", "-c", "print('HelloWorld!')"]
