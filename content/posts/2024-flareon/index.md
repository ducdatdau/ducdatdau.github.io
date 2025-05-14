---
title: "Flare On 11"
date: 2025-05-14T19:18:47+07:00
draft: false
tags: ["2025", "Flare On", "Rev"]
categories: ["CTF Writeups"]
lightgallery: true
toc:
  enable: true
---

Solutions for some challenges in Flare On 11

<!--more-->

# Flare On 11

## Challenge 2: checksum

### Challenge Overview

Đề bài cho chúng ta một file PE64 viết bằng Go với một số câu hỏi liên quan tới kết quả tính toán cơ bản. 

```
C:\Users\PWN2OWN>"C:\Users\PWN2OWN\FlareOn\2024\checksum.exe"
Check sum: 9418 + 92 = 9510
Good math!!!
------------------------------
Check sum: 9397 + 3991 = 13388
Good math!!!
------------------------------
Check sum: 5380 + 1695 = 7075
Good math!!!
------------------------------
Check sum: 3936 + 7655 = 11591
Good math!!!
------------------------------
Checksum: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Maybe it's time to analyze the binary! ;)
```

### Challenge Static Analysis 

Chương trình có 3 hàm không phải là thư viện: `main_main`, `main_a`, `main_b`. 

<img src="./1.png">

Đầu tiên, `randomTimes` đại diện cho số lượng câu hỏi sẽ được tạo bởi hàm random, giá trị sẽ nằm trong khoảng [0, 5]. Giá trị này được cộng thêm 3 đơn vị. Vì vậy sẽ có từ 3 - 8 câu hỏi phép tính.\
Mỗi câu hỏi tiếp tục random ra 2 số hạng, tôi đã rename chúng thành `fsRandom` và `seRandom`. Nhiệm vụ của player sẽ là nhập chính xác kết quả tổng 2 số hạng vừa rồi. Nếu trả lời đúng toàn bộ câu hỏi sẽ bước tiếp vào phần sau chương trình. 

Chương trình tiếp tục yêu cầu nhập checksum và kiểm tra hợp lệ bằng Golang API. 

<img src="./2.png">

Yêu cầu của `input_checksum` là độ dài 32, trong đó 24 bytes đầu tiên được lấy làm `buffer`. Chương trình sử dụng thuật toán mã hóa XChaCha20-Poly1305, trong đó key 32 bytes và nonce 24 bytes. Từ đó, ta có thể đặt giả thiết `buffer` chính là nonce trong thuật toán này. 

<img src="./3.png">

Decode `encryptedFlagData` với key và nonce ở trên, chúng ta thu được decrypted data. 

<img src="./4.png">

Decrypted data được hash bởi SHA 256 rồi được chuyển thành mã hex, sau đó đem đi so sánh với `input_checksum`. Nếu bằng nhau thì `main_a` sẽ được gọi và in kết quả ở `{os_UserCacheDir}\REAL_FLAREON_FLAG.JPG`

<img src="./5.png">

Phân tích hàm `main_a`, ta thấy nội dung không quá phức tạp. `input_checksum` sẽ được xor với chuỗi `FlareOn2024`, mã hóa base 64 và đem đi so sánh với `cQoFRQErX1YAVw1zVQdFUSxfAQNRBXUNAxBSe15QCVRVJ1pQEwd/WFBUAlElCFBFUnlaB1ULByRdBEFdfVtWVA==`. 

<img src="./6.png">

### Flag 

Okay, chỉ cần xor ngược lại sẽ tìm được `input_checksum` yêu cầu. 

```python
>>> x = b"cQoFRQErX1YAVw1zVQdFUSxfAQNRBXUNAxBSe15QCVRVJ1pQEwd/WFBUAlElCFBFUnlaB1ULByRdBEFdfVtWVA=="
>>> y = b"FlareOn2024"
>>> import base64
>>> xx = base64.b64decode(x)
>>> "".join(chr(xx[i] ^ y[i % len(y)]) for i in range(len(xx)))
'7fd7dd1d0e959f74c133c13abb740b9faa61ab06bd0ecd177645e93b1e3825dd'
```

Tìm trong local app data, chúng ta thu được flag challenge. 

<img src="./7.jpg">