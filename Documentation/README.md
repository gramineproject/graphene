# Prerequisites (Ubuntu 18.04)

```
sudo apt-get install doxygen
pip3 install -r requirements.txt
```

# Build html

```
make html
```

# Test html

Start a web server.

```
python3 -m SimpleHTTPServer
```

Check your documentation by opening the following url in your browser.

```
http://<IP address>:8000/_build/html
```
