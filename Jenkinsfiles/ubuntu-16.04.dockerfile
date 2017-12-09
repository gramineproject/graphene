# Start with 16.04
FROM ubuntu:16.04

# Add steps here to set up dependencies
RUN apt-get update && apt-get install -y \
    apache2-utils \
    autoconf \
    build-essential \
    gawk \
    gettext \
    git \
    libpcre3-dev \
    libxml2-dev \
    python \
    texinfo \
    wget


# Set environment variables.
ENV HOME /root

# Define working directory.
WORKDIR /root

# Define default command.
CMD ["bash"]
