---
title: "Symbol Resolution in Linux"
date: 2025-07-17
draft: true
tags: ["R3CTF 2025", "Reverse-Engineering", "Pwnable"]
# categories: ["CTF Writeups"]
lightgallery: true
toc:
  enable: true
# description: "Solutions for some challenges in BKCTF 2023 by ducdatdau"
---

Vào đầu kỳ nghỉ hè vừa rồi, mình có xem thoáng qua các thử thách rev/pwn của giải R3CTF 2025 - được tổ chức bởi r3kapig - một đội CTF Trung Quốc thuộc top đầu thế giới trong khoảng 5 năm trở lại đây.

Bài rev được đánh giá dễ nhất🥶(Neon Deceit/15 solves) đã sử dụng một kỹ thuật obfuscate khá mới dựa trên việc thay đổi quá trình resolution symbols trên Linux làm cho các decompilers bị nhầm lẫn trong việc đặt tên hàm. 

Đây cũng chính là bản chất của kỹ thuật ret2dlresolve thường được sử dụng trong các bài pwn ctf mà mình sẽ trình bày ở writeup bài ROP (5 solves) của giải ASCIS Final 2024 được tổ chức vào năm ngoái. 

<!--more-->

<style>
img {
    box-shadow: rgba(0, 0, 0, 0.35) 0px 5px 15px;
    border-radius: 6px;
    display: block; 
    margin-left: auto; 
    margin-right: auto;
}
</style>

## 0x00. Overview

Dưới đây là hình ảnh để chúng ta có thể dễ dàng hình dung nhất kỹ thuật obfuscate này làm gì. 

<!-- Như chúng ta đã thấy, IDA đã bị xác định nhầm hàm `strdup` là hàm `puts`, hàm `sleep` là hàm `exit` mà không hề thay đổi chức năng của chương trình 🤨   -->

## 0x01. What is Symbols Resolution?

## 0x02. R3CTF 2025 - Neon Deceit (15 solves)

## 0x03. ASCIS Final 2024 - ROP (5 solves)

## 0x05. References 

1. https://rk700.github.io/2015/08/09/return-to-dl-resolve
2. https://ypl.coffee/dl-resolve
3. https://ir0nstone.gitbook.io/notes/binexp/stack/ret2dlresolve 
4. https://blog.elmo.sg/posts/breaking-disassembly-through-symbol-resolution