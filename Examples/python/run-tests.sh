#!/usr/bin/env bash

set -e

if test -n "$SGX"
then
    GRAPHENE=graphene-sgx
else
    GRAPHENE=graphene-direct
fi

# === hellworld ===
echo -e "\n\nRunning helloworld.py:"
$GRAPHENE ./python scripts/helloworld.py > OUTPUT
grep -q "Hello World" OUTPUT && echo "[ Success 1/4 ]"
rm OUTPUT

# === web server and client (on port 8005) ===
echo -e "\n\nRunning HTTP server dummy-web-server.py in the background:"
$GRAPHENE ./python scripts/dummy-web-server.py 8005 & echo $! > server.PID
../../Scripts/wait_for_server 60 127.0.0.1 8005

echo -e "\n\nRunning HTTP client test-http.py:"
$GRAPHENE ./python scripts/test-http.py 127.0.0.1 8005 > OUTPUT1
wget -q http://127.0.0.1:8005/ -O OUTPUT2
echo >> OUTPUT2  # include newline since wget doesn't add it
# check if all lines from OUTPUT2 are included in OUTPUT1
# TODO: simplify after fixing Graphene logging subsystem, which currently mixes its output with the
# application output.
diff OUTPUT1 OUTPUT2 | grep -q '^>' || echo "[ Success 2/4 ]"
kill "$(cat server.PID)"
rm -f OUTPUT1 OUTPUT2 server.PID

# === numpy ===
$GRAPHENE ./python scripts/test-numpy.py > OUTPUT
grep -q "dot: " OUTPUT && echo "[ Success 3/4 ]"
rm OUTPUT

# === scipy ===
$GRAPHENE ./python scripts/test-scipy.py > OUTPUT
grep -q "cholesky: " OUTPUT && echo "[ Success 4/4 ]"
rm OUTPUT
