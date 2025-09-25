#!/usr/bin/python3
from pwn import *
context(log_level='debug',arch='amd64')
file = ''
elf = ELF(file)
libc = ELF('')
rop = ROP(file)
ip,port = '',''
local = 1
if local:
    p = process(file)
else:
    p = remote(ip,port)



sd  = lambda data               :   p.send(data)
sl  = lambda data               :   p.sendline(data)
sa  = lambda delim,data         :   p.sendafter(delim,data)
sla = lambda delim,data         :   p.sendlineafter(delim,data)
ita = lambda                    :   p.interactive()
ra  = lambda                    :   p.recvall()
rv  = lambda numb               :   p.recv(numb)
ru  = lambda delim,drop=True    :   p.recvuntil(delim,drop)
lg  = lambda msg                :   log.success(msg)
def dbg(addr=0):
    if addr != 0:
        script = f'b *$rebase({str(addr)})'
        attach(p,script)
    else:
        attach(p)
    pause()



leaked = ''
libc_base = 0