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
[+] 用法:
  Spatch                    列出版本目录（一行两列）
  Spatch ELF                用 libs/ 下版本 patch ELF（生成 ELF_patched）
  Spatch ELF LIBC           按 LIBC 版本自动过滤后 patch ELF
  Spatch - LIBC             仅显示与 LIBC 匹配的版本目录，不 patch
  Spatch -h, --help         显示本帮助
```

### Example

```C
#include<stdio.h>
int main()
{
	printf("hello world\n");
	return 0;
}
```

```sh
gcc hello.c -o hello
Spatch hello
···libc versions···
[?] 挑选要用的版本 (1-78): 63
[+] 已选择版本: 2.39-0ubuntu8.5_amd64
[+] 已重新备份 => hello_patched
[I] 执行: patchelf --set-interpreter /home/serend1p7ty/Spatch/libs/2.39-0ubuntu8.5_amd64/ld-linux-x86-64.so.2 hello_patched
[I] 执行: patchelf --replace-needed libc.so.6 /home/serend1p7ty/Spatch/libs/2.39-0ubuntu8.5_amd64/libc.so.6 hello_patched
[+] patchelf 完成 => hello_patched
```

```sh
ldd hello
	linux-vdso.so.1 (0x00007256d0226000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007256cfe00000)
	/lib64/ld-linux-x86-64.so.2 (0x00007256d0228000)

ldd hello_patched
	linux-vdso.so.1 (0x000073b284410000)
	/home/serend1p7ty/Spatch/libs/2.39-0ubuntu8.5_amd64/libc.so.6 (0x000073b284000000)
	/home/serend1p7ty/Spatch/libs/2.39-0ubuntu8.5_amd64/ld-linux-x86-64.so.2 => /lib64/ld-linux-x86-64.so.2 (0x000073b284412000)

./hello_patched 
hello world
```

## Uninstall

```sh
sudo rm /usr/local/bin/Spatch
```

# ✨ Power by Kimi