import sys,urllib2

request = urllib2.Request("http://" + sys.argv[1] + ":" + sys.argv[2] + "/index.html")
opener = urllib2.build_opener()
response = opener.open(request, timeout=10)
while True:
    data = response.read(1024)
    if data:
        sys.stdout.write(data)
    else:
        break
