#!/usr/bin/env python2

def myapp(environ, start_response):
    print 'got request: %s' % environ
    start_response('200 OK', [('Content-Type', 'text/plain')])
    return ['Hello World!']

if __name__ == '__main__':
    from flup.server.fcgi import WSGIServer
    WSGIServer(myapp).run()

