import sys
from regression import Regression

loader = sys.argv[1]

# Running udp
regression = Regression(loader, "udp", None, 50000)

regression.add_check(name="udp",
    check=lambda res:
      "Data: This is packet 0" in res[0].out and
      "Data: This is packet 1" in res[0].out and
      "Data: This is packet 2" in res[0].out and
      "Data: This is packet 3" in res[0].out and
      "Data: This is packet 4" in res[0].out and
      "Data: This is packet 5" in res[0].out and
      "Data: This is packet 6" in res[0].out and
      "Data: This is packet 7" in res[0].out and
      "Data: This is packet 8" in res[0].out and
      "Data: This is packet 9" in res[0].out)

rv = regression.run_checks()
if rv:
    sys.exit(rv)
