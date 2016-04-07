import httplib
import ssl
import sys

context = ssl._create_unverified_context()
hsc = httplib.HTTPSConnection(sys.argv[1], context=context)
hsc.request("GET", "/secret.html")
res = hsc.getresponse()
print res.read()

