#!/usr/bin/python

import os, sys, mmap
from regression import Regression

loader = os.environ['PAL_LOADER']
try:
    sgx = os.environ['SGX_RUN']
except KeyError:
    sgx = False

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

def check_cpu_info(res):
    cpu_num = cpu_model = cpu_family = cpu_stepping = 0
    cpu_vendor = cpu_brand = cpu_flags = None

    f = open("/proc/cpuinfo", "r")
    for line in f:
        line = line.strip()
        pos = line.find(":")
        if pos == -1:
            continue

        key = line[:pos].strip()
        val = line[pos+1:].strip()
        if key == "processor":  cpu_num += 1
        if key == "vendor_id":  cpu_vendor = val
        if key == "cpu family": cpu_family = int(val)
        if key == "model":      cpu_model = int(val)
        if key == "model name": cpu_brand = val
        if key == "stepping":   cpu_stepping = int(val)
        if key == "flags":
            cpu_flags = []
            for flag in val.split(" "):
                if flag in ["fpu", "vme", "de", "pse", "tsc", "msr", "pae",
                        "mce", "cx8", "apic", "sep", "mtrr", "pge", "mca",
                        "cmov", "pat", "pse36", "pn", "clflush", "dts", "acpi",
                        "mmx", "fxsr", "sse", "sse2", "ss", "ht", "tm",
                        "ia64", "pbe"]:
                    cpu_flags.append(flag)
            cpu_flags = " ".join(cpu_flags)

    return ("CPU num: %d"      % cpu_num)      in res[0].log and \
           ("CPU vendor: %s"   % cpu_vendor)   in res[0].log and \
           ("CPU brand: %s"    % cpu_brand)    in res[0].log and \
           ("CPU family: %d"   % cpu_family)   in res[0].log and \
           ("CPU model: %d"    % cpu_model)    in res[0].log and \
           ("CPU stepping: %d" % cpu_stepping) in res[0].log and \
           ("CPU flags: %s"    % cpu_flags)    in res[0].log

regression.add_check(name="Control Block: CPU Info",
    check=check_cpu_info)

rv = regression.run_checks()
if rv: sys.exit(rv)

# Running ..Bootstrap
regression = Regression(loader, "..Bootstrap")

regression.add_check(name="Dotdot handled properly",
    check=lambda res: "User Program Started" in res[0].log)
rv = regression.run_checks()
if rv: sys.exit(rv)
    

# Running Bootstrap2
regression = Regression(loader, manifest_file("Bootstrap2"))

regression.add_check(name="Control Block: Manifest as Executable Name",
    check=lambda res: "Loaded Manifest: file:" + manifest_file("Bootstrap2") in res[0].log
                     and "User Program Started" in res[0].log)

rv = regression.run_checks()
if rv: sys.exit(rv)

# Running Bootstrap3
regression = Regression(loader, "Bootstrap3")

regression.add_check(name="Preload Libraries",
    check=lambda res: "Binary 1 Preloaded" in res[0].log and
                      "Binary 2 Preloaded" in res[0].log)

regression.add_check(name="Preload Libraries Linking",
    check=lambda res: "Preloaded Function 1 Called" in res[0].log and
                      "Preloaded Function 2 Called" in res[0].log)

rv = regression.run_checks()
if rv: sys.exit(rv)

# Running Bootstrap4
regression = Regression(loader, manifest_file("Bootstrap4"))

regression.add_check(name="Control Block: Manifest as Argument",
    check=lambda res: any([line.startswith("Loaded Manifest: file:" + manifest_file("Bootstrap4")) for line in res[0].log]))

regression.add_check(name="Control Block: Executable as in Manifest",
    check=lambda res: "Loaded Executable: file:Bootstrap" in res[0].log)

rv = regression.run_checks()
if rv: sys.exit(rv)

# Running Bootstrap4.manifest
regression = Regression(executable = "./" + manifest_file("Bootstrap4"))

regression.add_check(name="Control Block: Manifest as Argument (Load by Shebang)",
    check=lambda res: "Loaded Manifest: file:" + manifest_file("Bootstrap4") in res[0].log)

regression.add_check(name="Control Block: Executable as in Manifest (Load by Shebang)",
    check=lambda res: "Loaded Executable: file:Bootstrap" in res[0].log)

regression.add_check(name="Arguments: loader.execname in Manifest",
    check=lambda res: "argv[0] = Bootstrap" in res[0].log)

rv = regression.run_checks()
if rv: sys.exit(rv)

# Running Bootstrap5.manifest
regression = Regression(loader, manifest_file("Bootstrap5"))

regression.add_check(name="Bootstrap without Executable but Preload Libraries",
    check=lambda res: "Binary 1 Preloaded" in res[0].log and
                      "Binary 2 Preloaded" in res[0].log)

rv = regression.run_checks()
if rv: sys.exit(rv)

# Running Bootstrap6.manifest - SGX-specific test
if sgx:
    regression = Regression(loader, manifest_file("Bootstrap6"), timeout = 100000)
    regression.add_check(name="8GB Enclave Creation (SGX Only)",
                         check=lambda res: "Loaded Manifest: file:Bootstrap6.manifest.sgx" in res[0].log and
                         "Executable Range OK" in res[0].log)

    rv = regression.run_checks()
    if rv: sys.exit(rv)

# Running Bootstrap7.manifest
regression = Regression(loader, manifest_file("Bootstrap7"))

regression.add_check(name="Load Large Number of Items in Manifest",
    check=lambda res: "key1000=na" in res[0].log and
                      "key1=na" in res[0].log)

rv = regression.run_checks()
if rv: sys.exit(rv)

# Running an executable that doesn't exist, should at least warn you
regression = Regression(loader, "fakenews")

regression.add_check(name="Error on missing executable and manifest",
    check=lambda res: "Executable not found" in res[0].log and 
                     any([line.startswith("USAGE: ") for line  in res[0].log]))

rv = regression.run_checks()
if rv: sys.exit(rv)
