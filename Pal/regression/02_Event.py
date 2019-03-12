#!/usr/bin/env python2

import os, sys
from regression import Regression

loader = os.environ['PAL_LOADER']

regression = Regression(loader, "Event")

regression.add_check(name="Wait for event with too short timeout",
    check=lambda res: "Wait with too short timeout ok." in res[0].log)

regression.add_check(name="Wait for event with long enough timeout",
    check=lambda res: "Wait with long enough timeout ok." in res[0].log)

rv = regression.run_checks()
if rv: sys.exit(rv)
