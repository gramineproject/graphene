#!/usr/bin/env bash

## We really need to pick a unique ephemeral port; start by just picking pid+1024
PORT=$(($$ + 1024))

echo "\n\nRun a HTTP server in the background on port " + $PORT
python scripts/dummy-web-server.py $PORT & echo $! > server.PID
sleep 1
echo "\n\nRun test-http.py:"
./python.manifest scripts/test-http.py 127.0.0.1 $PORT > OUTPUT1
wget -q http://127.0.0.1:$PORT/ -O OUTPUT2
diff -q OUTPUT1 OUTPUT2
kill `cat server.PID`
rm -f OUTPUT1 OUTPUT2 server.PID
