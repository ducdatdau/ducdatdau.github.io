---
title: "reversing.kr"
draft: false
tags: ["Reverse-Engineering"]
date: 2025-06-28
# categories: ["CTF Writeups"]
lightgallery: true
toc:
  enable: true
---

Vậy là mình đã kết thúc năm 3 đại học. Đúng là thời gian không chờ đợi một ai ... 

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

# reversing.kr

## Replace ~ 150 points 

### Overview 

Một bài yêu cầu nhập password chính xác. Khi click check, chương trình chạy một lúc và tự thoát ngay sau đó. 

<img src="./1.png" width=300rem>

### Static Analysis

Đây là mã giả của chương trình khi được phân tích trong IDAPRO32. 

<img src="./2.png">

Lời gọi hàm `sub_40466F()` dẫn tới lệnh `call $+5` rất lạ. Mình đặt breakpoint ngay chỗ này và debug để xem nó đang làm gì. 

### Dynamic Analysis

Quan sát kỹ càng, nhận thấy rằng giá trị `dword_4084D0` chính là giá trị hexacimal của input. 

<img src="./3.png">

Tiếp tục debug sâu vào từng dòng lệnh, giá trị `dword_4084D0` lần lượt được cộng thêm các giá trị: 2, 0x601605C7, 2. Chạy hết chương trình, xuất hiện cửa sổ lỗi như sau:

<img src="./4.png">

Instruction tham chiếu một địa chỉ không hợp lệ 0x60160A9D. Đây cũng chính là kết quả của `dword_4084D0`

```
dword_4084D0 = hex(input) + 2 + 0x601605C7 + 2
```

Vậy là chỉ cần đưa `dword_4084D0` trỏ về đoạn code `correct`. Giá trị input thỏa mãn là: 
```
input = (0x401071 - 2 - 0x601605C7 - 2) & 0xFFFFFFFF = 2687109798
```

> Do kết quả âm nên phải & 0xFFFFFFFF 

## ImagePrc ~ 120 points 