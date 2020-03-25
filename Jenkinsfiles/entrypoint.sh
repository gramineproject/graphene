#!/usr/bin/env sh

set -e


if test -e "/var/run/docker.sock" ; then
    groupmod -g $(stat -c '%g' /var/run/docker.sock) docker
fi
usermod -aG docker leeroy

gosu leeroy $@