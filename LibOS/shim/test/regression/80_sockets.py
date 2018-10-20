#!/usr/bin/python

import os, sys, mmap
from regression import Regression

loader = sys.argv[1]

# Running getsockopt
regression = Regression(loader, "getsockopt", None)

regression.add_check(name="getsockopt",
    check=lambda res: "getsockopt: Got socket type OK" in res[0].out)

rv = regression.run_checks()
if rv: sys.exit(rv)

# Run epoll_socket
try:
    pid = os.fork()
except OSError, e:
    ## some debug output
    sys.exit(1)
if pid == 0:
    ## eventually use os.putenv(..) to set environment variables
    ## os.execv strips of args[0] for the arguments
    os.system("sleep 2 && telnet localhost 8001 2>&1 >/dev/null")
    sys.exit(0)


regression = Regression(loader, "epoll_socket", None)


regression.add_check(name="Epoll on a writeable socket",
                     args = ['8001'],
                     check=lambda res: "Accepted connection" in res[0].out and 
                     "socket is writable" in res[0].out)

rv = regression.run_checks()

if rv: sys.exit(rv)
