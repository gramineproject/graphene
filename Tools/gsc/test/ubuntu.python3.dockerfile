From ubuntu:18.04

RUN apt-get update && apt-get upgrade -y

RUN env DEBIAN_FRONTEND=noninteractive apt-get install -y python3

CMD ["python3"]
