#!/usr/bin/env sh

set -e

groupmod -g $(stat -c '%g' /var/run/docker.sock) docker
usermod -aG docker leeroy

gosu leeroy $@