# Start with 16.04
FROM ubuntu:16.04

# Add steps here to set up dependencies
RUN apt-get update && apt-get install -y \
    autoconf \
    build-essential \
    gawk \
    git \
    python \
    wget


# Set environment variables.
ENV HOME /root

# Define working directory.
WORKDIR /root

# Define default command.
CMD ["bash"]
