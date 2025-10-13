---
title: "UART protocol"
date: 2024-08-24
draft: false
tags: ["IOT"]
# categories: ["CTF Writeups"]
lightgallery: true
toc:
  enable: true
---
<style>
img {
    box-shadow: rgba(0, 0, 0, 0.35) 0px 5px 15px;
    border-radius: 6px;
    display: block; 
    margin: 0 auto 15px;
}
</style>

## 0x01 Giới thiệu

Trong thế giới của các thiết bị nhúng (embedded system), từ những bộ định tuyến Wi-Fi, camera an ninh, thiết bị IoT cho đến các hệ thống điều khiển công nghiệp (ICS), giao thức **UART (Universal Asynchronous Receiver-Transmitter)** đóng một vai trò cực kỳ quan trọng. Ban đầu, nó được thiết kế như một giao diện gỡ lỗi (debug) đơn giản và hiệu quả cho các kỹ sư phát triển. Tuy nhiên, chính sự đơn giản và phổ biến này đã vô tình biến UART trở thành một "cửa hậu" đầy tiềm năng cho các nhà nghiên cứu bảo mật và tin tặc.

Trong quá trình sản xuất, các nhà phát triển thường để lại các cổng UART mở trên bo mạch chủ (PCB) của thiết bị. Mục đích là để gỡ lỗi, nạp firmware, hoặc kiểm tra hoạt động trong giai đoạn phát triển. Tuy nhiên, khi sản phẩm được tung ra thị trường, những cổng này thường bị "bỏ quên" và không được vô hiệu hóa.

Đây chính là điểm yếu giúp cho các hacker có thể thực hiện những hành vi nguy hiểm: 
- **Dễ dàng có Shell**:  Rất nhiều thiết bị cung cấp quyền truy cập vào một giao diện dòng lệnh (shell), thậm chí là quyền root (quản trị viên cao nhất) thông qua UART mà không cần bất kỳ cơ chế xác thực nào.
- **Can thiệp vào quá trình khởi động**: Bằng cách gửi các lệnh đặc biệt vào đúng thời điểm, kẻ tấn công có thể làm gián đoạn quá trình khởi động bình thường và ép thiết bị vào một chế độ đặc biệt (ví dụ: U-Boot shell), cho phép họ đọc/ghi firmware, thay đổi biến môi trường...
- **Trích xuất Firmware**: Đây là một trong những mục tiêu quan trọng nhất. Khi đã có quyền truy cập vào bootloader, kẻ tấn công có thể đọc toàn bộ nội dung của bộ nhớ flash và trích xuất firmware của thiết bị để tiến hành phân tích ngược (reverse engineering), tìm kiếm lỗ hổng 0-day hoặc đánh cắp tài sản trí tuệ. 

## 0x02 Giao thức UART

### Tổng quan 

UART là một giao thức giao tiếp nối tiếp không đồng bộ. "Không đồng bộ" có nghĩa là không có tín hiệu xung nhịp (clock signal) chung giữa bên gửi và bên nhận. Thay vào đó, hai bên phải thống nhất trước về tốc độ truyền dữ liệu (baud rate). UART interface có 4 chân cơ bản, đó là: `RX`, `TX`, `VCC`, `GND`. Trong đó có 3 chân thường thấy là `RX`, `TX` và `GND` có công dụng như sau:
- `TX` (Transmitter): chân truyền dữ liệu
- `RX` (Receiver): chân nhận dữ liệu
- `GND` (Ground reference): hay còn gọi là **tham chiếu "đất"**, dùng làm điểm để tham chiếu cho giá trị 0V và khử các tín hiệu nhiễu
- `VCC` (Voltage Common Collector): Chân cấp nguồn (thường là 3.3V hoặc 5V). Lưu ý quan trọng: Trong hầu hết các trường hợp, **KHÔNG** kết nối chân này với bộ chuyển đổi USB-to-TTL, vì thiết bị mục tiêu đã có nguồn riêng. Việc kết nối sai có thể gây hỏng thiết bị.

<img src="./imgs/0.png"/>

Để xác định được chính xác các chân, ta có thể sử dụng các công cụ như đồng hồ vạn năng hay Logic Anayzer. 

<img src="./imgs/1.png"/>

Tham khảo thêm cách sử dụng các thiết bị trên ở đây: 
- [Hacker's Guide to UART Root Shells](https://www.youtube.com/watch?v=01mw0oTHwxg)
- [Hardware Hacking 101: Getting a root shell via UART](https://riverloopsecurity.com/blog/2020/01/hw-101-uart/)

---

Trường hợp 1. Sử dụng đồng hồ vạn năng
- Nếu có tiếng kêu → Đó là chân GND
- Nếu điện áp là 0V → Đó là chân RX vì nó đợi dữ liệu
- Nếu điện áp thay đôi → Đó là chân TX vì nó đang gửi dữ liệu

Trường hợp 2. Sử dụng Logic Anayzer

<img src="./imgs/2.jpg" width=400px/>

Công cụ chúng ta sử dụng để bắt các tín hiệu là Saleae Logic Anayzer. Phần mềm để phân tích các tín hiệu là Logic 2. Để tiến hành phân tích, ta sẽ lần lượt thực hiện các bước sau:
1. Chọn Analyzers 
2. Chọn Async Serial 
3. Thiết lập các giá trị phù hợp cho Bit Rate, Stop Bits, Parity Bit. Những giá trị còn lại thường sẽ để standard.

Lấy ví dụ minh họa là kết quả bài ctf hardware/An4lyz3_1t ở giải ACSC 2024

<img src="./imgs/12.png"/>

### UART frame 

Để truyền dữ liệu đi, dữ liệu sẽ được đóng gói thành các packet. Cấu trúc của packet như trên ảnh: 

- Bit khởi đầu: 1 bit, luôn ở mức logic 0 (LOW), báo hiệu bắt đầu truyền.
- Bit dữ liệu: 5 → 9 bits, chứa dữ liệu thực tế.
- Bit chẵn lẻ: 1 bit, dùng để kiểm tra lỗi cơ bản.
- Bit kết thúc: 1 → 2 bits, luôn ở mức logic 1 (HIGH), báo hiệu kết thúc.

<img src="./imgs/3.png"/>

Dưới đây là ví dụ minh họa tín hiệu điện áp khi truyền ký tự 'A' (mã ASCII 0x41, nhị phân `01000001`).

<img src="./imgs/4.png"/>

### Baud Rates

Tốc độ Baud (đơn vị bps - bits per second) cho biết dữ liệu được truyền nhanh như thế nào. Cả bên gửi và bên nhận phải được cấu hình cùng một tốc độ baud để giao tiếp thành công.

Một số tốc độ phổ biến là: 
- 9600 (bps) trên thiết bị cũ
- 115200 (bps) trên thiết bị hiện đại

Công thức tính `bps = 1 / bit width`.

<!-- <img src="./imgs/11.png"/> -->

## 0x03 Tấn công UART (Reconnaissance &rarr; Shell)

**Bước 1: Reconnaissance Vật Lý & Xác Định Chân**

Đây là bước đầu tiên và quan trọng nhất. Nếu các chân không được đánh dấu, ta có thể dùng các công cụ sau:

Sử dụng Đồng hồ vạn năng:
- Tìm `GND`: Dùng chế độ đo thông mạch, que nào kêu "bíp" khi chạm vào vỏ kim loại (USB, LAN) là chân GND.
- Tìm `VCC`: Cấp nguồn cho thiết bị, dùng chế độ đo áp DC. Chân có điện áp ổn định (3.3V, 5V) là VCC.
- Tìm `TX`: Khi thiết bị khởi động, chân TX sẽ có điện áp dao động liên tục.
- Tìm `RX`: Chân còn lại là `RX`, thường có điện áp ổn định khi không có dữ liệu.

Ngoài việc sử dụng Đồng hồ vạn năng, chúng ta có thể sử dụng Logic Analyzer. Bằng cách kết nối với các chân nghi ngờ và ghi lại tín hiệu khi thiết bị khởi động, ta có thể dễ dàng xác định chân `TX` dựa trên dữ liệu nó phát ra.

**Bước 2: Kết Nối và Xác Định Thông Số**

Sau khi đã xác định các chân, ta cần kết nối chúng với một bộ chuyển đổi USB-to-TTL/Serial. Tiếp theo là xác định tốc độ Baud. Nếu sai tốc độ, ta sẽ chỉ nhận được dữ liệu rác. Hãy thử lần lượt các tốc độ phổ biến (9600, 57600, 115200...) cho đến khi thấy log khởi động rõ ràng.

**Bước 3: Tương Tác, Nghe Lén và Khai Thác**

1\. Transmitting UART nhận dữ liệu song song từ các bus dữ liệu 

<img src="./imgs/6.png" width=500px/>

2\. Nó đóng gói dữ liệu này vào một frame bằng cách thêm Start, Parity, và Stop bits.

<img src="./imgs/7.png" width=400px/>

3\. Frame được truyền nối tiếp qua chân TX.

<img src="./imgs/8.png" width=600px/>

4\. Receiving UART nhận chuỗi bit, unpack để lấy dữ liệu gốc.

<img src="./imgs/9.png" width=400px/>

5\. Cuối cùng, nó chuyển dữ liệu song song vào data bus của thiết bị nhận.

<img src="./imgs/10.png" width=500px/>


<!-- <img src="./imgs/5.png"/> -->

## 0x04 Các Kỹ Thuật Tấn Công Nâng Cao

### Khai thác Bootloader để chiếm quyền điều khiển

Nhiều thiết bị sử dụng bootloader như U-Boot, cung cấp một khoảng thời gian ngắn để người dùng ngắt quá trình khởi động và truy cập vào console của bootloader. Bằng cách nhấn một phím vào đúng thời điểm, ta có thể vào được môi trường này và thực thi các lệnh trước khi hệ điều hành chính khởi chạy, ví dụ như thay đổi tham số khởi động.

### Vượt qua màn hình đăng nhập với `init=/bin/sh`

Nếu đã vào được console của bootloader nhưng hệ điều hành chính vẫn yêu cầu mật khẩu, ta có thể áp dụng kỹ thuật sau:
- Sử dụng lệnh `printenv` để xem các biến môi trường.
- Tìm biến `bootargs` (tham số khởi động cho kernel).
- Sửa đổi biến này bằng lệnh `setenv` và thêm `init=/bin/sh` vào cuối.
- Lưu lại bằng `saveenv` và khởi động lại.

Thao tác này sẽ yêu cầu kernel Linux chạy một shell (`/bin/sh`) ngay sau khi khởi tạo, thay vì tiến trình `init` mặc định. Kết quả là sẽ có một root shell mà không cần xác thực.