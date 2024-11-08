---
title: "BKCTF 2023"
date: 2024-11-08T15:31:20+07:00
draft: false
tags: ["2023", "BKCTF", "Rev", "Pwn"]
categories: ["CTF Writeups"]
lightgallery: true
toc:
  enable: true
---

Solutions for some challenges in BKCTF 2023

<!--more-->

# BKCTF 2023

![](./0.jpg)

BKCTF là giải mà mình lần đầu tiên được tham gia onsite. Host là câu lạc bộ BKSEC của Trường Đại học Bách khoa Hà Nội, nơi đào tạo về kỹ thuật hàng hàng đầu tại Việt Nam, là niềm mơ ước của biết bao thế hệ học sinh, sinh viên trong nước. Mình nhớ tới BKSEC vì có biết một số anh chị rất khủng và có tiếng tăm trong ngành như anh chung96vn, chị lanleft, anh hacmao, ... 

Sau một năm, mình muốn chơi lại giải này để xem thử trình độ của mình đã tiến bộ được chút nào hay chưa. Đề bài mình chơi vẫn đang được mở trên web [Cookie Hân Hoan](https://battle.cookiearena.org/arenas/bkctf-2023), các bạn hoàn toàn có thể vào chơi và tận hưởng bộ đề theo mình nghĩ là khá thú vị. 

![](3.jpg "Phòng LAB siêu đẹp của CLB BKSEC")

![](1.jpg "2 team có bức hình chung với anh Hiếu - Founder Cookie Hân Hoan")

![](2.jpg "Thank youuuu")

# Let's get started

## rev/BabyStack

{{< admonition note "Challenge Information" >}}
* **Given files:** [BabyStack.zip](https://wru-my.sharepoint.com/:u:/g/personal/2251272678_e_tlu_edu_vn/EWmha5dk9GxHhMIDplXWwkwBcXd6O5JpYM1G38mtdG8Elw?e=EBWzTG)
* **Difficulty:** Hard
* **Description:** Stack up to the moon. Flag format: `BKSEC{}`
{{< /admonition >}}

**Solution**

> Theo quan điểm cá nhân của mình, bài này không thực sự quá khó. Nếu ai đã từng có một chút kinh nghiệm làm các dạng bài StackVM thì sẽ thấy bài này khá nhẹ nhàng. Mình sẽ cố gắng đi chi tiết từng thao tác nhỏ để các bạn mới có thể dễ dàng tiếp cận. Happy hacking ... 

### Overview & Clean code 

Đề bài cho chúng ta một file PE 64 bit `StackVM.exe` với mã giả dài hơn 300 dòng, chủ yếu là khai báo và gán giá trị cho các biến. 

Sau khi nhìn tổng quan, ta thấy chương trình khởi tạo cho vm một loạt bytecode như thế này 

<img src="./4.png">

Tiếp theo, chương trình cho nhập vào `Buffer` và kiểm tra kích thước xem có bằng 20 không. 

```c
fgets(Buffer, 0x15, v6);
    do
    {
        Buffer[++v4];
    }
    while ( Buffer[v4] );

    if ( v4 != 0x14 )
    {
        v7 = sub_140001000(std::cout, "Not enough length");
        std::ostream::operator<<(v7, sub_140001260);
        exit(0);
    }
```

Đầu tiên, chúng ta phải đi định nghĩa lại kích thước của mảng `bytecodes[]` và `Buffer[]` để chương trình nhìn gọn gàng hơn. 

Đặt lại cho mảng `Buffer[]` có kích thước 20 bytes và đổi tên thành `input[]`. 

<img src="./5.png">

và mảng `bytecodes[]` là 400 bytes. 

<img src="./6.png">

> Tại sao mình tính được kích thước là 400 bytes. Vì `bytecodes` bắt đầu từ `v24 [rsp+60h]`, kết thúc ở `v131 [rsp+1E8h]`, vậy nên 0x1E8 - 0x60 + 8 = 400

Okay, chương trình đã ngắn hơn một xíu rồi. Tiếp tục quan sát đoạn code dưới đây, ta thấy chương trình sử dụng vtable. Hiểu một cách đơn giản, vtable như là một cái bảng chứa các hàm, chương trình cần dùng hàm nào thì nhảy vào đó mà lấy. 

<img src="./7.png">

Ở đây mình sẽ tạo 1 struct cho vtable có kích thước 40 byte, đúng bằng kích thước của `v19`. Double click vào `vtable`, bôi đen toàn bộ các hàm, chuột phải và create struct. Đặt tên cho struct này là `struct_vtable`, tên các field mình vẫn giữ nguyên, sau này khi phân tích kỹ càng hơn mình sẽ rename sau. 

<img src="./8.png">

Thường những bài StackVM, mọi thao thác đều diễn ra trên cùng một stack. Và có 2 thứ không thể thiếu đó là: 
- `stack_base`: địa chỉ gốc stack
- `stack_esp`: địa chỉ đỉnh ngăn xếp 

Nhìn vào mã giả, mình đoán chắn chắn `v19[4]` là `stack_base` và `v19[3]` là `stack_esp`. Còn `v19[1]` và `v19[2]` chưa rõ nên mình không định nghĩa. 
Tạo tiếp một struct `struct_vm` như sau

<img src="./9.png">

và ép kiểu cho field đầu tiên là `*struct_vtable` mà chúng ta đã định nghĩa ở phía trên. 

Right click `v19`, nhấn `Convert to Struct * ...` và chọn `struct_vm` để sửa lại cấu trúc cho `v19`. 

### Analyze 

Chúng ta có thể thấy `input` được load vào mảng `bytecodes[]` như sau:
```c
bytecodes[29] = input[0];
bytecodes[28] = input[1];
bytecodes[79] = input[2];
bytecodes[78] = input[3];
bytecodes[117] = input[4];
bytecodes[116] = input[5];
bytecodes[155] = input[6];
bytecodes[154] = input[7];
bytecodes[193] = input[8];
bytecodes[192] = input[9];
bytecodes[231] = input[10];
bytecodes[230] = input[11];
bytecodes[269] = input[12];
bytecodes[268] = input[13];
bytecodes[307] = input[14];
bytecodes[306] = input[15];
bytecodes[345] = input[16];
bytecodes[344] = input[17];
bytecodes[383] = input[18];
total_bytecode = 0;
bytecodes[382] = input[19];
```

Nếu chú ý, ta có thể thấy các `bytecodes` chứa `input` liền kề nhau từng đôi một. Vậy rất có thể, chương trình sẽ đi xử lý từng cặp một của `input`. 

Đoạn xử lý chính của chương trình nằm ở đây
```c
do
    {
        v10 = bytecodes[idx];
        if ( bytecodes[idx + 1] == 6 )
        {
            instruction_sz = 4i64;
            HIDWORD(ptr_vm) = bytecodes[idx + 1];
            LOBYTE(ptr_vm) = bytecodes[idx];
            v12 = ptr_vm;
            LOWORD(v20) = bytecodes[idx + 3] + (bytecodes[idx + 2] << 8);
            v13 = v20;
        }
        else
        {
            HIDWORD(v21) = bytecodes[idx + 1];
            instruction_sz = 2i64;
            LOBYTE(v21) = bytecodes[idx];
            v12 = v21;
            LOWORD(v22) = 0;
            v13 = v22;
        }

        *(_DWORD *)&input[8] = v13;
        vtable = v3->vtable;
        total_bytecode += instruction_sz;
        *(_QWORD *)input = v12;
        ((void (__fastcall *)(struct_vm *, char *))vtable->___7stackVM__6B@)(v3, input);
        idx += instruction_sz;
    }
    while ( total_bytecode < 0x18C );
```
Tóm tắt đoạn code trên như sau: 
- Nếu `[idx + 1] == 6` thì 
  * Instruction sẽ có kích thước 4 byte, bắt đầu từ `[idx]` tới `[idx + 3]`
  * Value sẽ là sự kết hợp giữa `[idx + 2]` và `[idx + 3]`
  * Được xử lý bởi hàm `PUSH`
- Nếu `[idx + 1] != 6` thì: 
  - Instruction sẽ có kích thước 2 byte, bắt đầu từ `[idx]` tới `[idx + 1]`
  - Dựa vào `[idx + 1]` mà có 7 lựa chọn để gọi hàm xử lý: 
    - `CMP = 0`
    - `XOR = 1`
    - `ADD = 2`
    - `SUB = 3`
    - `SHL = 4`
    - `SHR = 5`
    - `POP = 7`
    - `AND = 8`

Dưới đây là minh họa cho việc mình rename và retype cho hàm `PUSH`. Các hàm khác các bạn làm tương tự thì code sẽ clean hơn rất nhiều. 

```c
__int64 __fastcall PUSH(struct_vm *a1, char a2, __int16 value)
{
    __int64 result; // rax
    __int64 stack_esp; // r9

    result = a1->stack_base;
    stack_esp = a1->stack_esp;
    if ( a2 == 1 )
    {
        *(result + stack_esp + 1) = value;
        a1->stack_esp += 2i64;
    }
    else
    {
        *(result + stack_esp + 1) = value;
        ++a1->stack_esp;
    }

    return result;
}
```

### Solve 
Sau khi đã hiểu cách thức hoạt động, mình đã lấy toàn bộ giá trị của mảng `bytecodes[]` và viết một đoạn code Python nhỏ để xem chương trình đang thực hiện những thao tác gì. 

```python
bytecodes = [0x00, 0x06, 0x00, 0x01, 0x01, 0x06, 0x0C, 0x0D, 0x01, 0x06, 
        0x00, 0x08, 0x01, 0x05, 0x01, 0x06, 0x22, 0x38, 0x01, 0x06, 
        0xFF, 0x00, 0x01, 0x08, 0x01, 0x02, 0x01, 0x06, 0x62, 0x61, 
        0x01, 0x01, 0x01, 0x06, 0x69, 0x4E, 0x01, 0x00, 0x00, 0x07, 
        0x00, 0x00, 0x01, 0x06, 0x0C, 0x0D, 0x01, 0x06, 0x2D, 0x41, 
        0x01, 0x02, 0x01, 0x06, 0x00, 0x08, 0x01, 0x05, 0x01, 0x06, 
        0x22, 0x38, 0x01, 0x06, 0x55, 0x22, 0x01, 0x01, 0x01, 0x06, 
        0xFF, 0x00, 0x01, 0x08, 0x01, 0x02, 0x01, 0x06, 0x64, 0x63, 
        0x01, 0x01, 0x01, 0x06, 0x32, 0x6A, 0x01, 0x00, 0x00, 0x07, 
        0x00, 0x00, 0x01, 0x06, 0x49, 0x30, 0x01, 0x06, 0x00, 0x08, 
        0x01, 0x05, 0x01, 0x06, 0x3E, 0x5E, 0x01, 0x06, 0xFF, 0x00, 
        0x01, 0x08, 0x01, 0x02, 0x01, 0x06, 0x66, 0x65, 0x01, 0x01, 
        0x01, 0x06, 0x45, 0x0A, 0x01, 0x00, 0x00, 0x07, 0x00, 0x00, 
        0x01, 0x06, 0x3B, 0x20, 0x01, 0x06, 0x00, 0x08, 0x01, 0x05, 
        0x01, 0x06, 0x6B, 0x2D, 0x01, 0x06, 0xFF, 0x00, 0x01, 0x08, 
        0x01, 0x02, 0x01, 0x06, 0x68, 0x67, 0x01, 0x01, 0x01, 0x06, 
        0x5B, 0x78, 0x01, 0x00, 0x00, 0x07, 0x00, 0x00, 0x01, 0x06, 
        0x2B, 0x79, 0x01, 0x06, 0x00, 0x08, 0x01, 0x05, 0x01, 0x06, 
        0x70, 0x41, 0x01, 0x06, 0xFF, 0x00, 0x01, 0x08, 0x01, 0x02, 
        0x01, 0x06, 0x6B, 0x69, 0x01, 0x01, 0x01, 0x06, 0x37, 0x45, 
        0x01, 0x00, 0x00, 0x07, 0x00, 0x00, 0x01, 0x06, 0x78, 0x79, 
        0x01, 0x06, 0x00, 0x08, 0x01, 0x05, 0x01, 0x06, 0x34, 0x41, 
        0x01, 0x06, 0xFF, 0x00, 0x01, 0x08, 0x01, 0x02, 0x01, 0x06, 
        0x6D, 0x6C, 0x01, 0x01, 0x01, 0x06, 0x55, 0x0A, 0x01, 0x00, 
        0x00, 0x07, 0x00, 0x00, 0x01, 0x06, 0x6A, 0x36, 0x01, 0x06, 
        0x00, 0x08, 0x01, 0x05, 0x01, 0x06, 0x2D, 0x01, 0x01, 0x06, 
        0xFF, 0x00, 0x01, 0x08, 0x01, 0x02, 0x01, 0x06, 0x32, 0x31, 
        0x01, 0x01, 0x01, 0x06, 0x58, 0x1E, 0x01, 0x00, 0x00, 0x07, 
        0x00, 0x00, 0x01, 0x06, 0x75, 0x1B, 0x01, 0x06, 0x00, 0x08, 
        0x01, 0x05, 0x01, 0x06, 0x3B, 0x17, 0x01, 0x06, 0xFF, 0x00, 
        0x01, 0x08, 0x01, 0x02, 0x01, 0x06, 0x34, 0x33, 0x01, 0x01, 
        0x01, 0x06, 0x0F, 0x19, 0x01, 0x00, 0x00, 0x07, 0x00, 0x00, 
        0x01, 0x06, 0x77, 0x7C, 0x01, 0x06, 0x00, 0x08, 0x01, 0x05, 
        0x01, 0x06, 0x45, 0x30, 0x01, 0x06, 0xFF, 0x00, 0x01, 0x08, 
        0x01, 0x02, 0x01, 0x06, 0x36, 0x35, 0x01, 0x01, 0x01, 0x06, 
        0x76, 0x03, 0x01, 0x00, 0x00, 0x07, 0x00, 0x00, 0x01, 0x06, 
        0x0F, 0x37, 0x01, 0x06, 0x00, 0x08, 0x01, 0x04, 0x01, 0x06, 
        0x3B, 0x23, 0x01, 0x06, 0x00, 0xFF, 0x01, 0x08, 0x01, 0x02, 
        0x01, 0x06, 0x38, 0x37, 0x01, 0x01, 0x01, 0x06, 0x4A, 0x12, 
        0x01, 0x00, 0x00, 0x07, 0x00, 0x00]

idx = 0 

while (idx < len(bytecodes)): 
    code = bytecodes[idx + 1]
    if (code == 0x06): 
        instruction_sz = 4 
        value = (bytecodes[idx + 2] << 8) | (bytecodes[idx + 3])
        print(f"PUSH {hex(value)}")
        idx += 4 
    else:
        instruction_sz = 2 
        match code:
            case 0x00: 
                print("CMP")
            case 0x01: 
                print("XOR")
            case 0x02: 
                print("ADD")
            case 0x03: 
                print("SUB")
            case 0x04: 
                print("SHL")
            case 0x05: 
                print("SHR")
            case 0x07: 
                print("POP")
            case 0x08: 
                print("AND")                            
        idx += 2
```

Mình sẽ thử phân tích một phần nhỏ kết quả thu được đầu tiên với `input` = `abcdefghiklm12345678`

```assembly
PUSH 0x1
PUSH 0xC0D
PUSH 0x8
SHR
PUSH 0x2238
PUSH 0xFF00
AND
ADD
PUSH 0x6261
XOR
PUSH 0x694E
CMP
```

1. `PUSH` 3 số 0x1, 0xC0D, 0x8 vào stack, `ESP` sẽ ở 0x8 
2. `SHR` là dịch phải: 0xC0D >> 0x8 = 0xC, `ESP` sẽ là 0xC 
3. `PUSH` 2 số 0x2238, 0xFF00 và `AND` với nhau. Kết quả là: 0x2238 & 0xFF00 = 0x2200
4. `ADD` sẽ cộng 2 số đầu tiên trên stack: 0x2200 + 0xC = 0x220C 
5. `PUSH` 0x6261 là 2 byte đầu tiên của `input`
6. `XOR` 0x220C ^ 0x6261 = 0x406D
7. `CMP` kết quả trên với `0x694E`

Phía trên chỉ là toàn bộ phỏng đoán của mình. Để kiểm chứng, mình debug và check ở hàm `CMP` xem logic trên có thực sự đúng không. 

<img src="./10.png">

Correct... 

Với việc dump được ra các instruction, chúng ta hoàn toàn có thể giải tay ra được flag. Nhưng để tiết kiệm thời gian, mình sẽ chỉ đặt breakpoint ở hàm `XOR` và hàm `CMP` để lấy các kết quả cuối cùng. 

Một số lưu ý nhỏ: 
1. Ta thấy trong đống `bytecodes[]` kia, 2 byte `0x01, 0x00` đại diện cho lệnh `CMP`. Vậy chắc chắn trước đó sẽ là lệnh `PUSH` giá trị `cipher` để so sánh kết quả đã xor. Từ đó ta không cần đặt breakpoint ở hàm `CMP` nữa. 
2. Việc thực hiện 1 loạt biến đổi rồi xor với 2 byte `input` ta không cần quan tâm. Chỉ cần `F9` và xem thử có input của mình không. Nếu có thì đó là giá trị chính xác. 
 
```python
value = [0x220c, 0x7739, 0x3e49, 0x6b3b, 0x702b, 0x3478, 0x2d6a, 0x3b75, 0x4577, 0x3723]
cipher = [0x694E, 0x326A, 0x450A, 0x5B78, 0x3745, 0x550A, 0x581E, 0xF19, 0x7603, 0x4A12]
flag = "".join([(v ^ c).to_bytes(2, "little").decode("utf8") for v, c in zip(value, cipher)])
```

Flag thu được là `BKSEC{C0nGratul4t31}`

## rev/Checker

{{< admonition note "Challenge Information" >}}
* **Given files:** [checker.zip](https://wru-my.sharepoint.com/:u:/g/personal/2251272678_e_tlu_edu_vn/EVfrh8c75apLnhn8Vv_rhBIBD1E3SAbCgdo35RI5QCEx4w?e=gggpRu)
* **Difficulty:** Easy
* **Description:** a checker ran with rice tree. Flag format: `BKSEC{}`
{{< /admonition >}}

**Solution**

Updating ... 

## rev/Reality

{{< admonition note "Challenge Information" >}}
* **Given files:** [reality.zip](https://wru-my.sharepoint.com/:u:/g/personal/2251272678_e_tlu_edu_vn/EYE-JsOfHUlLn3eLktQ-CXIB5e-4J0AhnZoM9qHwfNqGdA?e=Phj3TB)
* **Difficulty:** Easy
* **Description:** A simple reversing challenge... Flag format: `BKSEC{}`
{{< /admonition >}}

**Solution**

Updating ... 