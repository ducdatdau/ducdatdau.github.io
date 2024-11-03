---
title: "KCSC CTF 2024"
date: 2024-11-03
draft: false
description: "Solutions for some challenges in KCSC CTF 2024"
tags: ["2024", "KCSC CTF", "Rev", "Pwn", "Vietnamese"]
categories: ["CTF Writeups"]
lightgallery: true
toc:
  enable: true

---

Solutions for some challenges in KCSC CTF 2024

<!--more-->

# KCSC CTF 2024

Sau khi kết thúc thi cuối kỳ môn Pháp Luật Đại Cương, mình được nghỉ hơn 10 ngày để tiếp tục học giai đoạn mới. Đề CTF của KMA hay UIT luôn làm mình hứng thú, đặc biệt là những bài reverse. 

Thời gian cứ dần trôi, nỗi nhớ bạn gái cũ mỗi ngày một lớn, mình lại lặng lẽ lôi vài bài của giải KCSC CTF ra làm để khỏa lấp đi những trống vắng này. 

Trời mùa thu Hà Nội thật đẹp, nó sẽ đẹp hơn rất nhiều nếu như anh có em :fallen_leaf:

> **Trang** giấy trắng đâu thể mờ đi từng màu buồn của nắng\
**À** ơi vu vơ câu hát có lẽ chưa bao giờ anh viết tặng\
**Em** nhẹ bước chân qua bao ngọt ngào bao nhiêu cố gắng\
**Có** hay không những bước thềm trong con tim em cần một khoảng rộng\
**Biết** lúc nào anh có thể lại được gặp em một lần nữa\
**Là** khi đó anh cảm nhận mùi hương tàn cánh hoa sữa\
**Anh** yêu em thật nồng nàn như một định lí đã muôn thuở\
**Yêu** một người có lẽ phải học thêm nhiều điều\
**Em** là mảnh ghép cuối cùng anh còn thiếu\
**Nhiều** đêm dằn vặt tự gắng mình không hiểu\
**Lắm** những yêu thương trôi qua trong em nào thật nhiều\
**Không** lí do nào đã khiến em cùng người đó

## rev/f@k3

{{< admonition note "Challenge Information" >}}
* 16 solves / 356 pts 
* **Given files:** [re_fk3.exe](https://wru-my.sharepoint.com/:u:/g/personal/2251272678_e_tlu_edu_vn/EQes0cpg1-ZIusqmKlO22C0B0BNG_6kO3gZYsZa2tQtsqQ?e=8AqamO)
{{< /admonition >}}

**Solution**

Flow chương trình rất ngắn gọn. Mảng **`Str[]`** sẽ được decrypt bởi thuật toán RC4 với **`key`** = **`F@**!`**. Sau đó chương trình so sánh **`input`** nhập vào với **`output`** là kết quả của giải mã mảng trên. 

<img src="1.png"/>

Bật debug lên và check **`output`**, ta nhận được một fake flag 

<img src="2.png"/>

Mình xref **`key`** thì thấy nó còn được xuất hiện trong hàm **`sub_7FF7423313D0`**
```c
__int64 sub_7FF7423313D0()
{
  if ( !*(_BYTE *)(qword_7FF742335670 + 2) )
  {
    key[1] |= 1u;
    key[2] |= 1u;
    key[3] |= 1u;
    key[4] |= 1u;
  }
  return 0i64;
}
```

Vậy khả năng cao đây là hàm anti-debug. Nếu chúng ta debug thì sẽ nhận được key fake, mình đặt breakpoint tại hàm này, sửa lại giá trị cho thanh ghi **`ZF`** và thu được key chính xác là **`FA++!`**.

Sau khi có key đúng thì kết quả decrypt vẫn sai. Có một vấn đề là dù **`input`** của mình khác nhau nhưng chương trình vẫn luôn in ra **`Correct!`**. Tới đây thì mình đoán được luôn hàm **`lstrcmpA`** đã bị custom lại. 

> Nếu các bạn chơi giải KCSC/KMA đủ nhiều sẽ biết kỹ thuật này thường xuyên được sử dụng. 

Đi sâu vào hàm **`lstrcmpA`**, ta thấy flag được tạo ra bằng cách xor **`output`** với một mảng **`Str[]`** khác và luôn return 0. Đây cũng là lý do tại sao chương trình luôn in ra **`Correct!`**. 

<img src="3.png" height="600" style="display: block; margin-left: auto; margin-right: auto;"/>

Flag thu được là **`KCSC{1t_co5ld_be_right7_fla9_here_^.^@@}`**

## rev/RE x Rust

{{< admonition note "Challenge Information" >}}
* 5 solves / 489 pts / by JohnathanHuuTri
* **Given files:** 
  * [flag.enc](https://wru-my.sharepoint.com/:u:/g/personal/2251272678_e_tlu_edu_vn/ETw7mLb_E61Flv3qiLG1dboBxZt6nBy7-7rdnjg-4JtN6g?e=RAKj6l)
  * [rexrust](https://wru-my.sharepoint.com/:u:/g/personal/2251272678_e_tlu_edu_vn/EfKU4YDfSd9Pulfe-DQ_IdkBkZ8dRRyXosmgA4z0OAAURw?e=uOnSO1)
* **Description:** Challenge name tell everything!
{{< /admonition >}}

**Solution**

Updating... 

## rev/behind the scenes

{{< admonition note "Challenge Information" >}}
* 0 solve / 500 pts / by ndt
* **Given files:** [chall.zip](https://wru-my.sharepoint.com/:u:/g/personal/2251272678_e_tlu_edu_vn/Ec7HNS1M-OdJqmqPCLDivXsB--RiV_rQ9O4pT-fWe_E1kw?e=52AtSQ)
* **Description:** Don't miss anything. 
{{< /admonition >}}

**Solution**

Updating... 