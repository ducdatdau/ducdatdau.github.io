---
title: "Dream Hack Playround"
date: 2025-05-21
draft: false
tags: ["Wargame", "DreamHack", "Rev", "Pwn"]
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

