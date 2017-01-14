import urllib2

request = urllib2.Request("http://google.com/")
opener = urllib2.build_opener()
response = opener.open(request, timeout=10)
while True:
    data = response.read(1024)
    if data:
        print data
    else:
        break
