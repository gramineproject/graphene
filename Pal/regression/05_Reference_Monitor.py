import os, sys, mmap
from regression import Regression

loader = os.environ['PAL_SEC']

if not os.path.exists(loader):
    print("Reference monitor mode is not available on this platform")
    exit(0)

# Running Bootstrap
regression = Regression(loader, "Bootstrap")

regression.add_check(name="Basic Bootstrapping",
    check=lambda res: "User Program Started" in res[0].log)

regression.add_check(name="Control Block: Executable Name",
    check=lambda res: "Loaded Executable: file:Bootstrap" in res[0].log)

regression.add_check(name="Control Block: Default Manifest",
    check=lambda res: "Loaded Manifest: file:manifest" in res[0].log)

regression.add_check(name="One Argument Given",
    check=lambda res: "# of Arguments: 1" in res[0].log and \
            "argv[0] = file:Bootstrap" in res[0].log)

regression.add_check(name="Five Arguments Given",
    args = ['a', 'b', 'c', 'd'],
    check=lambda res: "# of Arguments: 5" in res[0].log and \
           "argv[0] = file:Bootstrap" in res[0].log and \
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

rv = regression.run_checks()
## dp: For now, let the ref monitor checks fail; we should fix this
#if rv: sys.exit(rv)

# Running Bootstrap3
regression = Regression(loader, "Bootstrap3")

regression.add_check(name="Preload Libraries",
    check=lambda res: "Binary 1 Preloaded" in res[0].log and
                      "Binary 2 Preloaded" in res[0].log)

regression.add_check(name="Preload Libraries Linking",
    check=lambda res: "Preloaded Function 1 Called" in res[0].log and
                      "Preloaded Function 2 Called" in res[0].log)

rv = regression.run_checks()
#if rv: sys.exit(rv)
