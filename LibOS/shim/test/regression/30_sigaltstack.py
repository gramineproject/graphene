import sys
from regression import Regression

loader = sys.argv[1]

# Running sigaltstack
regression = Regression(loader, "sigaltstack")

messages = (
    "OK on sigaltstack in main thread before alarm",
    "&act == 0x",
    "sig 14 count 1 goes off with sp=0x",
    "OK on signal stack",
    "OK on sigaltstack in handler",
    "sig 14 count 2 goes off with sp=0x",
    "OK on signal stack",
    "OK on sigaltstack in handler",
    "sig 14 count 3 goes off with sp=0x",
    "OK on signal stack",
    "OK on sigaltstack in handler",
    "OK on sigaltstack in main thread",
    "done exiting",
)

regression.add_check(name="Sigaltstack Test",
    check=lambda res: all([x in res[0].out for x in messages]))

rv = regression.run_checks()
if rv: sys.exit(rv)
