#!/usr/bin/env sh

set -e

userid=`id -u $USER`
rootid=`id -u root`
if test "$userid" != "$rootid" ; then
    exec "$@"
else
    if test -e "/var/run/docker.sock" ; then
        groupmod -g $(stat -c '%g' /var/run/docker.sock) docker
    fi
    usermod -aG docker leeroy

    exec gosu leeroy "$@"
fi