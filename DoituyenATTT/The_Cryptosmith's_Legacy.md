# The Cryptosmith's Legacy
![image](https://hackmd.io/_uploads/H1r5naUD-l.png)

Bài này cho ta 2 file
- gen
- secret.txt

Chúng ta sẽ xem lướt qua thông tin về 2 file này
Đầu tiên là `secret.txt`
![image](https://hackmd.io/_uploads/BJkOk0LPZg.png)

Khi mở bằng notepad thì mình thấy hơi rác, vì không phải ascii. Nhận định ban đầu là 1 đoạn mã hoá do file `gen` sinh ra. Mình ném nó vào HxD để xem. Thì mình để ý thấy là toàn bộ file này chỉ xoay quanh các byte là `00, 03, 0C, 0F, 30, 33, 3C, 3F, C0, C3, CC, CF, F0, F3, FC, FF`. Lúc này chưa có kết luận gì nhưng là 1 điểm cần note

Mở file `gen` bằng DiE
![image](https://hackmd.io/_uploads/rk-dxRIw-e.png)

Không có gì lắm, tiếp tục bằng IDA

```c 
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  FILE *stream_2; // rax
  FILE *stream; // rbx
  void *ptr; // rbx
  FILE *s_1; // rax
  FILE *stream_1; // rbp
  int p_n; // [rsp+Ch] [rbp-12Ch] BYREF
  char s[264]; // [rsp+10h] [rbp-128h] BYREF
  unsigned __int64 v11; // [rsp+118h] [rbp-20h]

  v11 = __readfsqword(0x28u);
  stream_2 = fopen("flag.txt", "r");
  if ( stream_2 )
  {
    stream = stream_2;
    if ( fgets(s, 256, stream_2) )
    {
      s[strcspn(s, "\n")] = 0;
      fclose(stream);
      ptr = (void *)sub_1D70(s, 10, &p_n);
      if ( ptr )
      {
        s_1 = fopen("secret.txt", "w");
        stream_1 = s_1;
        if ( s_1 )
        {
          fwrite(ptr, 1u, p_n, s_1);
          fclose(stream_1);
          free(ptr);
          return 0;
        }
        free(ptr);
      }
    }
    else
    {
      fclose(stream);
    }
  }
  return 1;
}
```

Luồng chương trình này khá dễ thôi
- mở file `flag`, đọc vào biến `s`
- gọi hàm `sub_1D70(s, 10, &p_n)` để cook cái flag
- mở `secret.txt` để ghi vào

Vậy vấn đề ở đây là hàm sub_1D70 kia đang làm gì? Sau khi phân tích cả tĩnh và động 1 lúc thì mình vẫn chưa clear lắm về mục đích của nó.
Thêm nữa là chương trình có sử dụng antidebug. Cụ thể nhưu sau

![image](https://hackmd.io/_uploads/HJi9FywPbl.png)

Khi mình xem xref đến thì biết rằng nó đang làm 2 việc để antidebug là check `TracerPid` và scan xem có đang sử dụng các tool debug không.

Để bypass nó thì mình sẽ patch lại chương trình
- TracerPid: 
    - trước : ![image](https://hackmd.io/_uploads/HkAdlYwPZe.png)

    - sau : ![image](https://hackmd.io/_uploads/ryVpltvPbg.png)
- gdb : 
    - trước : ![image](https://hackmd.io/_uploads/r1XrMtPDZg.png)
    
    - sau : ![image](https://hackmd.io/_uploads/r1wsfFwPbl.png)
- các tool debug
    - trước : ![image](https://hackmd.io/_uploads/rJYK7tDPWl.png)
    - sau : ![image](https://hackmd.io/_uploads/HyrNEKwDWg.png)

=> đã bypass được antidebug của chương trình

Mình xem lại các byte của file `secret.txt`. Như mình đã nói thì các byte nó chỉ xoay quanh `00, 03, 0C, 0F, 30, 33, 3C, 3F, C0, C3, CC, CF, F0, F3, FC, FF`, và để kiểm chứng thì mình đã tạo các file `flag.txt` và mỗi lần điền các nội dung bừa vào trong đó, sau đó chạy file `gen` xem nó gen ra cái gì
![image](https://hackmd.io/_uploads/BkKJJywvZl.png)
![image](https://hackmd.io/_uploads/BJnZ1ywDWx.png)

Sau khi tra cứu 1 hồi thì mình kết luận rằng đây là dấu hiệu của dạng `2bpp` (2 bits per pixel), dạng này thì cứ 2 bit sẽ tạo thành các mức màu khác nhau, cụ thể:
- 00 : mức 0 - đen
- 01 : mức 1 - xám đậm
- 10 : mức 2 - xám nhạt
- 11 : mức 3 - trắng

Tức là thay vì 1byte/pixel thì qua đoạn mã hoá,nhiều pixel đã bị pack chung thành 1 byte. 

Rất có thể rằng file input (là 1 đoạn text) sau khi đi qua chương trình đã được gen thành qr code, sau đó các pixel trong qr code đó được pack lại và ghi ra file secret.txt.

Chúng ta sẽ đi theo hướng decode lại cái file secret.txt để tìm ra ảnh gốc

Bước đầu tách mỗi byte thành 4 giá trị 2-bit (2 bits/pixel), tức một byte chứa 1 trong các mức trong khoảng 0..3. Sau khi unpack ra chuỗi pixel, mình đổi nó về ảnh đen–trắng(ví dụ giá trị ≥2 coi là 1, còn lại là 0), rồi thử reshape thành ma trận vuông theo các kích thước QR hợp lệ (21×21, 25×25, 29×29,…).Với mỗi candidate,mình thêm quiet zone(viền trắng) và phóng to ảnh bằng nearest-neighbor để dễ quét

Vì không chắc thứ tự lấy 2-bit trong byte (MSB/LSB) và ảnh có thể bị đảo màu || xoay || lật, mình xuất thêm các biến thể (invert + rotate 90/180/270 + flip).Cuối cùng chỉ cần mở thư mục output và dùng QR scanner quét các ảnh, ảnh nào decode được thì ra nội dung/flag.


Code solve (nhớ sửa file secret.txt thành dạng Hex) : 
```python 
#!/usr/bin/env python3
import re, math, argparse
from pathlib import Path

import numpy as np
from PIL import Image

hexbytes = lambda p: bytes(int(x, 16) for x in re.findall(r"[0-9a-fA-F]{2}", Path(p).read_text("utf-8", "ignore")))
readkey   = lambda p, off, n: Path(p).read_bytes()[off:off+n]
xorrepeat = lambda data, key: bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def unpack2bpp(data: bytes, msb=True) -> np.ndarray:
    a = np.frombuffer(data, dtype=np.uint8)
    if msb:
        return np.stack([(a >> 6) & 3, (a >> 4) & 3, (a >> 2) & 3, a & 3], axis=1).reshape(-1).astype(np.uint8)
    return np.stack([a & 3, (a >> 2) & 3, (a >> 4) & 3, (a >> 6) & 3], axis=1).reshape(-1).astype(np.uint8)

def save_variants(im: Image.Image, base: str):
    im.save(base + ".png")
    im.rotate(90, expand=True).save(base + "_r90.png")
    im.rotate(180, expand=True).save(base + "_r180.png")
    im.rotate(270, expand=True).save(base + "_r270.png")
    im.transpose(Image.FLIP_LEFT_RIGHT).save(base + "_flipH.png")
    im.transpose(Image.FLIP_TOP_BOTTOM).save(base + "_flipV.png")

def stream_preview(mod2: np.ndarray, base: str, scale: int, invert: bool):
    N = mod2.size
    w = max(1, int(math.isqrt(N)))
    h = N // w
    m = mod2[:w*h].reshape(h, w)
    bw = ((m >= 2).astype(np.uint8) * 255)
    if invert: bw = 255 - bw
    im = Image.fromarray(bw, "L").resize((w*scale, h*scale), Image.NEAREST)
    save_variants(im, base)

def qr_image(mod2: np.ndarray, n: int, quiet: int, scale: int, invert: bool) -> Image.Image:
    bits = (mod2[:n*n] >= 2).astype(np.uint8).reshape(n, n)
    img = (1 - bits) * 255  # QR: 1=đen -> 0
    if invert: img = 255 - img
    img = np.pad(img.astype(np.uint8), quiet, constant_values=255)
    return Image.fromarray(img, "L").resize((img.shape[1]*scale, img.shape[0]*scale), Image.NEAREST)

def best_qr_ns(modcnt: int, top: int):
    ns = []
    for v in range(1, 41):
        n = 21 + 4*(v-1)
        if n*n <= modcnt:
            ns.append((modcnt - n*n, n))
    ns.sort()
    return [n for _, n in ns[:top]]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("secret")
    ap.add_argument("bin")
    ap.add_argument("--key-off", type=lambda x: int(x, 0), default=0xb0e0)
    ap.add_argument("--key-len", type=lambda x: int(x, 0), default=0x32d)
    ap.add_argument("--out", default="out")
    ap.add_argument("--scale", type=int, default=10)
    ap.add_argument("--quiet", type=int, default=4)
    ap.add_argument("--topn", type=int, default=12)
    ap.add_argument("--force-n", type=int, default=0)
    args = ap.parse_args()

    Path(args.out).mkdir(parents=True, exist_ok=True)

    cipher = hexbytes(args.secret)
    key = readkey(args.bin, args.key_off, args.key_len)
    raw = xorrepeat(cipher, key)

    for msb in (True, False):
        order = "msb" if msb else "lsb"
        m_cipher = unpack2bpp(cipher, msb=msb)
        m_raw    = unpack2bpp(raw,    msb=msb)

        stream_preview(m_cipher, f"{args.out}/cipher_stream_{order}_inv0", args.scale, False)
        stream_preview(m_cipher, f"{args.out}/cipher_stream_{order}_inv1", args.scale, True)
        stream_preview(m_raw,    f"{args.out}/raw_stream_{order}_inv0",    args.scale, False)
        stream_preview(m_raw,    f"{args.out}/raw_stream_{order}_inv1",    args.scale, True)

        ns = [args.force_n] if args.force_n else best_qr_ns(m_raw.size, args.topn)
        for n in ns:
            for inv in (0, 1):
                im = qr_image(m_raw, n, args.quiet, args.scale, bool(inv))
                save_variants(im, f"{args.out}/raw_qr_{order}_n{n}_inv{inv}")

if __name__ == "__main__":
    main()
```
![image](https://hackmd.io/_uploads/ryCQU5vvbe.png)

MỞ folder chứa ảnh decode thì khá nhiều, có cả flag fake, nhưng may mắn là vẫn có flag thật=))

![image](https://hackmd.io/_uploads/rkVdIqDwWx.png)


<details>
<summary><b>FLAG</b></summary>
    InfosecPTIT{Y0u_d1d_4ll_7h4t_f0r_a_QR}
</details>