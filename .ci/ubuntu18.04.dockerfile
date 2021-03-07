# Start with 18.04
FROM ubuntu:18.04

# Add steps here to set up dependencies
RUN apt-get update && env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    apache2-utils \
    autoconf \
    bison \
    build-essential \
    curl \
    flex \
    gawk \
    gdb \
    gettext \
    git \
    libapr1-dev \
    libaprutil1-dev \
    libcurl4-openssl-dev \
    libelf-dev \
    libevent-dev \
    libexpat1 \
    libexpat1-dev \
    libmemcached-tools \
    libnss-mdns \
    libnuma1 \
    libomp-dev \
    libpcre2-dev \
    libpcre3-dev \
    libprotobuf-c-dev \
    libssl-dev \
    libxfixes3 \
    libxi6 \
    libxml2-dev \
    libxrender1 \
    libxxf86vm1 \
    linux-headers-4.15.0-20-generic \
    meson \
    net-tools \
    pkg-config \
    protobuf-c-compiler \
    pylint3 \
    python \
    python3-apport \
    python3-apt \
    python3-breathe \
    python3-pyelftools \
    python3-lxml \
    python3-numpy \
    python3-pip \
    python3-protobuf \
    python3-pytest \
    python3-scipy \
    r-base-core \
    shellcheck \
    texinfo \
    wget \
    zlib1g \
    zlib1g-dev

RUN python3 -m pip install \
    asv \
    recommonmark \
    'Sphinx==1.8' \
    sphinx_rtd_theme \
    toml>=0.10

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
