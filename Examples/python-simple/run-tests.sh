#!/usr/bin/env bash

set -e

failures=0

# === hellworld ===
echo -e "\n\nRunning helloworld.py:"
./pal_loader ./python scripts/helloworld.py > OUTPUT
if grep -q "Hello World" OUTPUT; then
    echo "[ Success 1/3 ]"
else
    echo "[ Failure 1/3 ]"
    failures=$((failures+1))
fi
rm OUTPUT

# === fibonacci ===
echo -e "\n\nRunning fibonacci.py:"
./pal_loader ./python scripts/fibonacci.py > OUTPUT
if grep -q "fib2              55" OUTPUT; then
    echo "[ Success 2/3 ]"
else
    echo "[ Failure 2/3 ]"
    failures=$((failures+1))
fi
rm OUTPUT

# === web server and client (on port 8005) ===
echo -e "\n\nRunning HTTP server dummy-web-server.py in the background:"
./pal_loader ./python scripts/dummy-web-server.py 8005 & echo $! > server.PID
# Graphene-SGX may take a lot of time to initialize
../../Scripts/wait_for_server 60 127.0.0.1 8005

echo -e "\n\nRunning HTTP client test-http.py:"
./pal_loader ./python scripts/test-http.py localhost 8005 > OUTPUT1
wget -q http://localhost:8005/ -O OUTPUT2
echo >> OUTPUT2  # include newline since wget doesn't add it
# check if all lines from OUTPUT2 are included in OUTPUT1
# TODO: simplify after fixing Graphene logging subsystem, which currently mixes its output with the
# application output.
if ! diff OUTPUT1 OUTPUT2 | grep -q '^>'; then
    echo "[ Success 3/3 ]"
else
    echo "[ Failure 3/3 ]"
    failures=$((failures+1))
fi
kill "$(cat server.PID)"
rm -f OUTPUT1 OUTPUT2 server.PID

exit "$failures"
