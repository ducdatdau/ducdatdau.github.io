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

### Solving 

Vậy nhiệm vụ lúc này là chỉ cần đưa `dword_4084D0` trỏ về đoạn code `correct`. Giá trị input thỏa mãn là: 
```
input = (0x401071 - 2 - 0x601605C7 - 2) & 0xFFFFFFFF = 2687109798
```

> Do kết quả âm nên phải & 0xFFFFFFFF 

## ImagePrc ~ 120 points 

### Overview 

Chương trình cho người chơi vẽ hình bất kỳ và có nút check kết quả. 

<img src="./5.png" width=400rem>

Với dạng bài này, khả năng cao chương trình sẽ so sánh hình chúng ta vẽ với dữ liệu đã có sẵn. 

### Static Analysis

Chương trình đăng ký lớp cửa sổ với các thuộc tính: Background, Cursor, Icon, ... Sau đó tính toán vị trí để cửa sổ ở giữa màn hình, tạo cửa sổ và hiển thị. 

<img src="./6.png">

Hàm xử lý logic chính của chương trình chính là `sub_401130()`. Trước tiên, nó tạo một bitmap có kích thước 200x150.

<img src="./7.png">

Tiếp theo, gọi các hàm `FindResourceA()`, `LoadResource()`, `LockResource()` để tải tài nguyên có sẵn lên rồi đem đi so sánh với dữ liệu mình vẽ. 

<img src="./8.png">

### Solving 

Sử dụng tool Paint, tạo ra một bức ảnh có kích thước 200x150, lưu dưới dạng BMP picture. 

<img src="./9.png">

Copy toàn bộ tài nguyên bằng tool Resource Hacker, tiếp tục dùng tool HxD để paste chúng vào ảnh ở trên. Phần được select là phần được giữ lại của BMP picture. 

<img src="./11.png" width=600rem>


Save lại và mở ra, ta có được đáp án thử thách. 

<img src="./10.png" width=300rem>

