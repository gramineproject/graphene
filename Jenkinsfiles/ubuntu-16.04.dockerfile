# Start with 16.04
FROM ubuntu:16.04

# Add steps here to set up dependencies
RUN apt-get update \
    && apt-get install -y \
       apache2-utils \
       autoconf \
       bison \
       build-essential \
       curl \
       flex \
       gawk \
       gettext \
       git \
       libapr1-dev \
       libaprutil1-dev \
       libexpat1 \
       libexpat1-dev \
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
       linux-headers-4.4.0-161-generic \
       net-tools \
       protobuf-c-compiler \
       python \
       python3-apport \
       python3-apt \
       python3-lxml \
       python3-minimal \
       python3-numpy \
       python3-pip \
       python3-pytest \
       python3-scipy \
       shellcheck \
       texinfo \
       wget \
       zlib1g \
       zlib1g-dev \
    && /usr/bin/pip3 install protobuf \

# Add the user UID:1001, GID:1001, home at /leeroy
    && groupadd -r leeroy -g 1001 \
    && useradd -u 1001 -r -g leeroy -m -d /leeroy -c "Leeroy Jenkins" leeroy \
    && chmod 755 /leeroy \

# Make sure /leeroy can be written by leeroy
    && chown 1001 /leeroy \

# Blow away any random state
    && rm -f /leeroy/.rnd \

# Make a directory for the intel driver
    && mkdir -p /opt/intel && chown 1001 /opt/intel

# Set the working directory to leeroy home directory
WORKDIR /leeroy

# Specify the user to execute all commands below
USER leeroy

# Set environment variables.
ENV HOME /leeroy

# Define default command.
CMD ["bash"]
