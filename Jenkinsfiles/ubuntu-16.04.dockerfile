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
    net-tools \
    python \
    texinfo \
    wget

# Add the user UID:1000, GID:1000, home at /leeroy
RUN groupadd -r leeroy -g 1000 && useradd -u 1000 -r -g leeroy -m -d /leeroy -c "Leeroy Jenkins" leeroy && \
    chmod 755 /leeroy

# Make sure /leeroy can be written by leeroy
RUN chown 1000 /leeroy

# Blow away any random state
RUN rm -f /leeroy/.rnd

# Set the working directory to leeroy home directory
WORKDIR /leeroy

# Specify the user to execute all commands below
USER leeroy

# Set environment variables.
ENV HOME /leeroy

# Define default command.
CMD ["bash"]
