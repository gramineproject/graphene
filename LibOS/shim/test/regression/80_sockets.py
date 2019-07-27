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
except OSError:
    ## some debug output
    sys.exit(1)
if pid == 0:
    # wait till epoll_socket warms up and run telnet client
    os.system("sleep 10 && telnet localhost 8000 >/dev/null 2>/dev/null")
    sys.exit(0)

regression = Regression(loader, "epoll_socket", None, 50000)

regression.add_check(name="Epoll on a writable socket",
                     args = ['8000'],
                     check=lambda res: "Accepted connection" in res[0].out and
                     "socket is writable" in res[0].out)

rv = regression.run_checks()
if rv: sys.exit(rv)
