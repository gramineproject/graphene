#!/usr/bin/env sh

set -e

groupmod -g $(stat -c '%g' /var/run/docker.sock) docker
usermod -aG docker leeroy

exec gosu leeroy $@