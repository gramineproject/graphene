import os, sys, mmap
from regression import Regression

loader = sys.argv[1]

# Running Long Filepath Example
regression = Regression(loader, "fs_long_path")

regression.add_check(name="FS Long Paths",
        check=lambda res: "Successfully read from file: Hello World" in res[0].out)

rv = regression.run_checks()
if rv: sys.exit(rv)
