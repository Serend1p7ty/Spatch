# Spatch ez patchelf

Help pwner ez patchelf

## Install

```sh
chmod +x setup.sh
./setup.sh
```

## Usage

```sh
➜  ~ Spatch -h
用法:
  Spatch                  列出版本目录（一行两列）
  Spatch ELF              用 libs/ 下版本 patch ELF（生成 ELF_patched、exp.py）
  Spatch ELF LIBC         按 LIBC 版本自动过滤后 patch
  Spatch - LIBC           仅显示与 LIBC 匹配的版本目录，不 patch
  Spatch -h/--help        显示本帮助
```

### Example

```sh
Spatch sometime libc.so.6 
[I] 检测到题目 libc 版本: 2.35  架构: amd64
[ 1] 2.35-0ubuntu3.10_amd64                 [ 2] 2.35-0ubuntu3_amd64
[?] 请选择 (1-2): 1
[+] 已选择版本: 2.35-0ubuntu3.10_amd64
[I] 执行: patchelf --set-interpreter /home/serend1p7ty/Spatch/libs/2.35-0ubuntu3.10_amd64/ld-linux-x86-64.so.2 sometime_patched
[I] 执行: patchelf --replace-needed libc.so.6 /home/serend1p7ty/Spatch/libs/2.35-0ubuntu3.10_amd64/libc.so.6 sometime_patched
[+] patchelf 完成 => sometime_patched
[?] 是否生成 exp.py？ [y/N] y
[+] 已生成 exploit 脚本 => exp.py
```

```sh
ldd sometime_patched 
	linux-vdso.so.1 (0x0000799e1ccc6000)
	/home/serend1p7ty/Spatch/libs/2.35-0ubuntu3.10_amd64/libc.so.6 (0x0000799e1ca00000)
	/home/serend1p7ty/Spatch/libs/2.35-0ubuntu3.10_amd64/ld-linux-x86-64.so.2 => /lib64/ld-linux-x86-64.so.2 (0x0000799e1ccc8000)

ls
exp.py  ld-linux-x86-64.so.2  libc.so.6  sometime  sometime_patched

cat exp.py
```

### EXP
```py
#!/usr/bin/python3
from pwn import *
context(log_level='debug',arch='amd64')
file = './sometime_patched'
elf = ELF(file)
libc = ELF('')
rop = ROP(file)
ip,port = '',''
local = 1
if local:
    p = process(file)
else:
    p = remote(ip,port)


sla = lambda delim,data         :   p.sendlineafter(delim,data)
sl  = lambda data               :   p.sendline(data)
sa  = lambda delim,data         :   p.sendafter(delim,data)
ita = lambda                    :   p.interactive()
ra  = lambda                    :   p.recvall()
ru  = lambda delim,drop=True    :   p.recvuntil(delim,drop)
rv  = lambda numb               :   p.recv(numb)
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
```

## Uninstall

```sh
sudo rm /usr/local/bin/Spatch
```

# ✨ Power by Kimi