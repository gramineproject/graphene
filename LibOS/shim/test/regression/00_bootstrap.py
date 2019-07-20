import os, sys, mmap
from regression import Regression

loader = sys.argv[1]

# Running Bootstrap
regression = Regression(loader, "bootstrap")

regression.add_check(name="Basic Bootstrapping",
    check=lambda res: "User Program Started" in res[0].out)

regression.add_check(name="One Argument Given",
    check=lambda res: "# of Arguments: 1" in res[0].out and \
            "argv[0] = file:bootstrap" in res[0].out)

regression.add_check(name="Five Arguments Given",
    args = ['a', 'b', 'c', 'd'],
    check=lambda res: "# of Arguments: 5" in res[0].out and \
           "argv[0] = file:bootstrap" in res[0].out and \
           "argv[1] = a" in res[0].out and "argv[2] = b" in res[0].out and \
           "argv[3] = c" in res[0].out and "argv[4] = d" in res[0].out)

rv = regression.run_checks()
if rv: sys.exit(rv)

regression = Regression(loader, "bootstrap-c++")

regression.add_check(name="Basic Bootstrapping (C++)",
    check=lambda res: "User Program Started" in res[0].out)

rv = regression.run_checks()
if rv: sys.exit(rv)

# Running Exec
regression = Regression(loader, "exec")

regression.add_check(name="2 page child binary",
    check=lambda res: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 " in res[0].out)

rv = regression.run_checks()
if rv: sys.exit(rv)

# Running fork and exec
regression = Regression(loader, "fork_and_exec")

regression.add_check(name="fork and exec 2 page child binary",
    check=lambda res: "child exited with status: 0" in res[0].out and \
                      "test completed successfully" in res[0].out)

rv = regression.run_checks()
if rv: sys.exit(rv)

# Running vfork and exec
regression = Regression(loader, "vfork_and_exec")

regression.add_check(name="vfork and exec 2 page child binary",
    check=lambda res: "child exited with status: 0" in res[0].out and \
                      "test completed successfully" in res[0].out)

rv = regression.run_checks()
if rv: sys.exit(rv)

# Running execve with invalid pointers in arguments
regression = Regression(loader, "exec_invalid_args")

regression.add_check(name="Execve with invalid pointers in arguments",
    check=lambda res: "execve(invalid-path) correctly returned error" in res[0].out and \
                      "execve(invalid-argv-ptr) correctly returned error" in res[0].out and \
                      "execve(invalid-envp-ptr) correctly returned error" in res[0].out and \
                      "execve(invalid-argv) correctly returned error" in res[0].out and \
                      "execve(invalid-envp) correctly returned error" in res[0].out)

rv = regression.run_checks()
if rv: sys.exit(rv)

# Shared Object Test
regression = Regression(loader, "shared_object")

regression.add_check(name="Shared Object",
    check=lambda res: "Hello world" in res[0].out)

rv = regression.run_checks()
if rv: sys.exit(rv)

# Exit test
regression = Regression(loader, "exit")

regression.add_check(name="Exit Code Propagation",
    check=lambda res: 113 == res[0].code)

rv = regression.run_checks()
if rv: sys.exit(rv)

# Early abort test
regression = Regression(loader, "init_fail")

regression.add_check(name="Early abort",
    check=lambda res: res[0].code != 42 and res[0].code != 0)

rv = regression.run_checks()
if rv: sys.exit(rv)
