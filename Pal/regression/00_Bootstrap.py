#!/usr/bin/python

import os, sys, mmap
from regression import Regression

loader = '../src/pal'

def manifest_file(file):
    if 'SGX_RUN' in os.environ and os.environ['SGX_RUN'] == '1':
        return file + '.manifest.sgx'
    else:
        return file + '.manifest'

# Running Bootstrap
regression = Regression(loader, "Bootstrap")

regression.add_check(name="Basic Bootstrapping",
    check=lambda res: "User Program Started" in res[0].log)

regression.add_check(name="Control Block: Executable Name",
    check=lambda res: "Loaded Executable: file:Bootstrap" in res[0].log)

regression.add_check(name="One Argument Given",
    check=lambda res: "# of Arguments: 1" in res[0].log and \
            "argv[0] = file:Bootstrap" in res[0].log)

regression.add_check(name="Five Arguments Given",
    args = ['a', 'b', 'c', 'd'],
    check=lambda res: "# of Arguments: 5" in res[0].log and \
           "argv[1] = a" in res[0].log and "argv[2] = b" in res[0].log and \
           "argv[3] = c" in res[0].log and "argv[4] = d" in res[0].log)

regression.add_check(name="Control Block: Debug Stream (Inline)",
    check=lambda res: "Written to Debug Stream" in res[0].out)

regression.add_check(name="Control Block: Page Size",
    check=lambda res: ("Page Size: %d" % (mmap.PAGESIZE)) in res[0].log)

regression.add_check(name="Control Block: Allocation Alignment",
    check=lambda res: ("Allocation Alignment: %d" % (mmap.ALLOCATIONGRANULARITY)) in res[0].log)

regression.add_check(name="Control Block: Executable Range",
    check=lambda res: "Executable Range OK" in res[0].log)

regression.run_checks()

# Running ..Bootstrap
regression = Regression(loader, "..Bootstrap")

regression.add_check(name="Dotdot handled properly",
    check=lambda res: "User Program Started" in res[0].log)
regression.run_checks()

# Running Bootstrap2
regression = Regression(loader, "Bootstrap2")

regression.add_check(name="Control Block: Manifest as Executable Name",
    check=lambda res: "Loaded Manifest: file:" + manifest_file("Bootstrap2") in res[0].log)

regression.run_checks()

# Running Bootstrap3
regression = Regression(loader, "Bootstrap3")

regression.add_check(name="Preload Libraries",
    check=lambda res: "Binary 1 Preloaded" in res[0].log and
                      "Binary 2 Preloaded" in res[0].log)

regression.add_check(name="Preload Libraries Linking",
    check=lambda res: "Preloaded Function 1 Called" in res[0].log and
                      "Preloaded Function 2 Called" in res[0].log)

regression.run_checks()

# Running Bootstrap4
regression = Regression(loader, manifest_file("Bootstrap4"))

regression.add_check(name="Control Block: Manifest as Argument",
    check=lambda res: any([line.startswith("Loaded Manifest: file:" + manifest_file("Bootstrap4")) for line in res[0].log]))

regression.add_check(name="Control Block: Executable as in Manifest",
    check=lambda res: "Loaded Executable: file:Bootstrap" in res[0].log)

regression.run_checks()

# Running Bootstrap4.manifest
regression = Regression(executable = "./" + manifest_file("Bootstrap4"))

regression.add_check(name="Control Block: Manifest as Argument (Load by Shebang)",
    check=lambda res: "Loaded Manifest: file:" + manifest_file("Bootstrap4") in res[0].log)

regression.add_check(name="Control Block: Executable as in Manifest (Load by Shebang)",
    check=lambda res: "Loaded Executable: file:Bootstrap" in res[0].log)

regression.add_check(name="Arguments: loader.execname in Manifest",
    check=lambda res: "argv[0] = Bootstrap" in res[0].log)

regression.run_checks()

# Running Bootstrap5.manifest
regression = Regression(loader, manifest_file("Bootstrap5"))

regression.add_check(name="Bootstrap without Executable but Preload Libraries",
    check=lambda res: "Binary 1 Preloaded" in res[0].log and
                      "Binary 2 Preloaded" in res[0].log)

regression.run_checks()

# Running Bootstrap6.manifest
regression = Regression(loader, manifest_file("Bootstrap6"), timeout = 100000)

regression.add_check(name="8GB Enclave Creation (SGX Only)",
    check=lambda res: "Loaded Manifest: file:Bootstrap6.manifest.sgx" in res[0].log and
                      "Executable Range OK" in res[0].log)

regression.run_checks()
