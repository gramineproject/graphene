# Start with 18.04
FROM ubuntu:18.04

# Add steps here to set up dependencies
RUN apt-get update && env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    apache2-utils \
    autoconf \
    build-essential \
    gawk \
    bison \
    gettext \
    git \
    libelf-dev \
    libexpat1 \
    libexpat1-dev \
    libomp-dev \
    libpcre3-dev \
    libxml2-dev \
    linux-headers-4.15.0-20-generic \
    net-tools \
    python \
    python3-pip \
    python3-protobuf \
    python3-pytest \
    python3-breathe \
    texinfo \
    wget \
    curl \
    libprotobuf-c-dev \
    protobuf-c-compiler

RUN pip3 install 'Sphinx>=1.8' sphinx_rtd_theme recommonmark

# Add the user UID:1001, GID:1001, home at /leeroy
RUN groupadd -r leeroy -g 1001 && useradd -u 1001 -r -g leeroy -m -d /leeroy -c "Leeroy Jenkins" leeroy && \
    chmod 755 /leeroy

# Make sure /leeroy can be written by leeroy
RUN chown 1001 /leeroy

# Blow away any random state
RUN rm -f /leeroy/.rnd

# Make a directory for the intel driver
RUN mkdir -p /opt/intel && chown 1001 /opt/intel

# Set the working directory to leeroy home directory
WORKDIR /leeroy

# Specify the user to execute all commands below
USER leeroy

# Set environment variables.
ENV HOME /leeroy

# Define default command.
CMD ["bash"]
