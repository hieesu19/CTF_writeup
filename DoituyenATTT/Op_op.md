# Ọp ọp
![image](https://hackmd.io/_uploads/rJ7C26Lwbl.png)

![image](https://hackmd.io/_uploads/rJ1PwoPPWx.png)

File bị pack bằng upx, unpack nó thôi
![image](https://hackmd.io/_uploads/HkAoDiwP-g.png)


xem  lại profile![image](https://hackmd.io/_uploads/r1wpPjPD-e.png)


Bài nên mô tả rất liên quan đến vấn đề debug, thế nên mình sẽ chú ý các dấu hiệu của antidebug

Chạy thử đã xem nó làm gì

```bash
D:\CTF\ATTT_PTIT\re\Op_Op_Op\kk\Ọp ọp>RE4.exe
Input flag: chotaoflaggggggggg
Incorrect!
```

Mở lên bằng IDA
```c 
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _DWORD v4[9]; // [esp+0h] [ebp-28h] BYREF
  char v5; // [esp+24h] [ebp-4h]

  sub_403DE0();
  memset(v4, 0, sizeof(v4));
  v5 = 0;
  sub_401040(&unk_4649C0, v4, 37);
  if ( (unsigned __int8)sub_403D30(v4) )
    puts("Correct!");
  else
    puts("Incorrect!");
  return 0;
}
```

Sau khi debug qua chút, thì mình sửa pseudocode cho dễ đọc hơn như sau
```c 
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _DWORD v4[9]; // [esp+0h] [ebp-28h] BYREF
  char v5; // [esp+24h] [ebp-4h]

  in_thongbao();
  memset(v4, 0, sizeof(v4));
  v5 = 0;
  nhap(&unk_CF49C0, v4, 37);
  if ( (unsigned __int8)check(v4) )
    puts("Correct!");
  else
    puts("Incorrect!");
  return 0;
}
```

Nhìn qua thì thấy luồng hàm main rất đơn giản thôi, nên mình sẽ phân tích tĩnh tiếp hàm check xem như thế nào

```c 
char __cdecl check(const char *a1)
{
  if ( strlen(a1) == 32 )
    return sub_C93CC0(a1);
  else
    return 0;
}
```
Flag sẽ là `32` kí tự

Sau khi phân tích hàm sub_C93CC0() thì mình đã rename lại các hàm con được gọi trong đó để có thể dễ hiểu follow hơn

```c 
bool __cdecl sub_C93CC0(int a1)
{
  if ( !(unsigned __int8)check_0_7(a1) )
    return 0;
  if ( !(unsigned __int8)check_8_15(a1) )
    return 0;
  if ( (unsigned __int8)check_16_23(a1) )
    return (unsigned __int8)check_24_31(a1) != 0;
  return 0;
}

char __cdecl check_0_7(int a1)
{
  int i; // [esp+0h] [ebp-4h]

  for ( i = 0; i < 8; ++i )
  {
    *(_BYTE *)(i + a1) ^= byte_CF7930[i];
    if ( *(unsigned __int8 *)(i + a1) != (unsigned __int8)byte_CF8458[i] )
      return 0;
  }
  return 1;
}

char __cdecl check_8_15(int a1)
{
  int i; // [esp+0h] [ebp-4h]

  for ( i = 8; i < 16; ++i )
  {
    *(_BYTE *)(i + a1) ^= byte_CF7930[i];
    if ( *(unsigned __int8 *)(i + a1) != (unsigned __int8)byte_CF8458[i] )
      return 0;
  }
  return 1;
}

char __cdecl check_16_23(int a1)
{
  int i; // [esp+0h] [ebp-4h]

  for ( i = 16; i < 24; ++i )
  {
    *(_BYTE *)(i + a1) ^= byte_CF7930[i];
    if ( *(unsigned __int8 *)(i + a1) != (unsigned __int8)byte_CF8458[i] )
      return 0;
  }
  return 1;
}

char __cdecl check_24_31(int a1)
{
  int i; // [esp+0h] [ebp-4h]

  for ( i = 24; i < 32; ++i )
  {
    *(_BYTE *)(i + a1) ^= byte_CF7930[i];
    if ( *(unsigned __int8 *)(i + a1) != (unsigned __int8)byte_CF8458[i] )
      return 0;
  }
  return 1;
}

// cứ 1 hàm fail thì return 0 luôn, chỉ khi 4 hàm pass thì mới return 1
```

=> Ý tưởng : 
- input 32 kí tự sẽ được chia làm 4 phần, mỗi phần 8bytes
- Ở mỗi phần, với từng bytes `input[i]`: 
    - xor tại chỗ : `input[i] ^= byte_CF7930[i]`
    - cmp với byte mục tiêu : `input[i] == byte_CF8458[i]`, nếu khác trả luôn FAIL

=> input đúng sẽ là `input[i] = byte_CF8458[i] ^ byte_CF7930[i]`

Giờ việc đơn giản là dump giá trị của 2 mảng byte kia ra thôi

```c 
.data:00CF8458 aW3NDg3pFnva7u3 db 'w3_n_dg3p_fnva_7u3nm_7gmc_w6unZ?'



.data:00CF7930 byte_CF7930     db 13h                  ; DATA XREF: sub_C91BC0+1D↑r
.data:00CF7930                                         ; sub_C91BC0+2E↑w ...
.data:00CF7931                 db    3
.data:00CF7932                 db    0
.data:00CF7933                 db  1Bh
.data:00CF7934                 db    0
.data:00CF7935                 db  0Fh
.data:00CF7936                 db    9
.data:00CF7937                 db    3
.data:00CF7938 byte_CF7938     db 7                    ; DATA XREF: sub_C92590+14↑o
.data:00CF7938                                         ; sub_C92890+14↑o
.data:00CF7939                 db    0
.data:00CF793A                 db  0Bh
.data:00CF793B byte_CF793B     db 1Bh
.data:00CF793C byte_CF793C     db 15h
.data:00CF793D ; unsigned __int8 byte_CF793D[3]
.data:00CF793D byte_CF793D     db 9
.data:00CF793E                 db    0
.data:00CF793F                 db    3
.data:00CF7940                 db  17h                 ; DATA XREF: sub_C92C00+14↑o
.data:00CF7940                                         ; sub_C92F00+14↑o
.data:00CF7941                 db    3
.data:00CF7942                 db  1Bh
.data:00CF7943                 db  19h
.data:00CF7944                 db    0
.data:00CF7945                 db    3
.data:00CF7946                 db    9
.data:00CF7947                 db  19h
.data:00CF7948 unk_CF7948      db    9                 ; DATA XREF: sub_C93270+14↑o
.data:00CF7948                                         ; sub_C93570+14↑o
.data:00CF7949                 db    0
.data:00CF794A                 db  13h
.data:00CF794B                 db    5
.data:00CF794C                 db  17h
.data:00CF794D                 db  1Bh
.data:00CF794E                 db  1Dh
.data:00CF794F                 db    0
```

Code solve
```python 
target = b"w3_n_dg3p_fnva_7u3nm_7gmc_w6unZ?"
key = bytes([
    0x13, 0x03, 0x00, 0x1B, 0x00, 0x0F, 0x09, 0x03,
    0x07, 0x00, 0x0B, 0x1B, 0x15, 0x09, 0x00, 0x03,
    0x17, 0x03, 0x1B, 0x19, 0x00, 0x03, 0x09, 0x19,
    0x09, 0x00, 0x13, 0x05, 0x17, 0x1B, 0x1D, 0x00
])

inp = bytes([t ^ k for t, k in zip(target, key)])
print(inp.decode())

# d0_u_kn0w_much_4b0ut_4ntj_d3buG?
```
Tức là ở đây đang lẽ flag phải là InfosecPTIT{d0_u_kn0w_much_4b0ut_4ntj_d3buG?}
Nhưng khi submit thì nó sai liên tục, mình cũng check rất kĩ và chắc chắn code solve và thuật không sai. Và sau khi author xem có phải web nộp bị lỗi không thì hoá ra flag của mình chưa đúng <(") 

Đề bài liên tục nhắc đến debug, nên mình thử debug lại 1 lần nữa xem thế nào thì mình thấy có sự thay đổi ở mảng byte_CF7930[] 

![image](https://hackmd.io/_uploads/rkY7znPDZg.png)

Mình thử dump ra và thay vào code kia
![image](https://hackmd.io/_uploads/H1mCGhvvWl.png)

Nó ra 1 chuỗi khác đôi chút, nhưng không phải, vì dính kí tự không in được

Vậy là đã rõ, với đề bài như kia, thì byte_CF7930[] sẽ bị thay đổi khi debug, còn thay đổi như nào thif cần phải xem xref đến nó

![image](https://hackmd.io/_uploads/r18UXnPPWe.png)

bỏ qua 4 hàm check ở dưới cùng kia, mình sẽ xem từng xrref một

OK ta thấy rõ luôn,
```c 
int sub_C91BC0()
{
  int result; // eax

  byte_CF793B ^= byte_CF7950[sub_C91520(0x68u)];
  byte_CF793C ^= byte_CF7950[unknown_libname_2(227)];
  result = (unsigned __int8)byte_CF7950[sub_C91480(87)] ^ byte_CF793D[0];
  byte_CF793D[0] = result;
  return result;
}
```
Đây là đoạn mà byte_CF7930[] bị sửa đổi 1 chút

Chúng ta sẽ truy ngược lại xem hàm nào gọi hàm `sub_C91BC0`

```c 
void __thiscall TlsCallback_0(void *this, int a2, int a3, int a4)
{
  if ( a3 == 1 && !NtCurrentPeb_ww(this) )
    sub_C91BC0();
}
BOOL __thiscall sub_C91260(void *this)
{
  return NtCurrentPeb_w()->BeingDebugged != 0;
}
```

Rõ ràng rồi, đây là hàm check debug, nó lấy con trỏ PEB sau đó đọc trường BeingDebugged để biết ta có đang debug hay không, và vì TLS callback chạy trước main() nên là xảy ra các trờng hợp sau
- lúc debug : thì byte_CF7930[] sẽ không bị sửa, và ta lấy byte_CF7930 để giải flag thì ra vài kí tự không in được
- lúc khôg debug : một vài byte bị sửa, có thể là sửa để trở thành chuỗi byte_CF7930 chuẩn để giải được ra flag

Nhưng mình vẫn nghi ngờ rằng chuỗi byte byte_CF7930[] vẫn còn bị chỉnh sửa trước hàm main, bởi vì lúc static và lúc mình debug thì chuỗi nó khác nhau hầu hết các byte, mà nếu khi debug thì như mình nói ở trên, byte_CF7930[] sẽ không bị thay đổi đúng không 

Trace tiếp thì mình tìm đến hàm này

```c 
int sub_C93B00()
{
  return sub_C93970((int)byte_CF7A50);
}



.rdata:00CED160 First           dd 0                    ; DATA XREF: __scrt_common_main_seh(void)+72↑o
.rdata:00CED164                 dd offset sub_C93FCE
.rdata:00CED168                 dd offset sub_C92250
.rdata:00CED16C                 dd offset sub_C93B00
.rdata:00CED170                 dd offset sub_C92F30
.rdata:00CED174                 dd offset sub_C935A0
.rdata:00CED178                 dd offset sub_C928C0
.rdata:00CED17C ; const _PVFV Last
.rdata:00CED17C Last            dd 0                    ; DATA XREF: __scrt_common_main_seh(void):loc_C94057↑o
.rdata:00CED180 ; const _PIFV First_
.rdata:00CED180 First_          dd 0                    ; DATA XREF: __scrt_common_main_seh(void)+4C↑o
.rdata:00CED184                 dd offset ?pre_c_initialization@@YAHXZ ; pre_c_initialization(void)
.rdata:00CED188                 dd offset sub_C93FC6
.rdata:00CED18C                 dd offset ___acrt_initialize_stdio
.rdata:00CED190                 dd offset ?initialize_multibyte@@YAHXZ ; initialize_multibyte(void)
.rdata:00CED194                 dd offset ___acrt_initialize_fmode
.rdata:00CED198                 dd offset ___acrt_initialize_sse2
.rdata:00CED19C ; const _PIFV Last_
.rdata:00CED19C Last_           dd 0                    ; DATA XREF: __scrt_common_main_seh(void)+47↑o
.rdata:00CED1A0                 db    0
.rdata:00CED1A1                 db    0
.rdata:00CED1A2                 db    0
.rdata:00CED1A3                 db    0
.rdata:00CED1A4 TlsCallbacks    dd offset TlsCallback_0 ; DATA XREF: .rdata:TlsCallbacks_ptr↓o
.rdata:00CED1A8                 dd 0
.rdata:00CED1AC ; const _PVFV dword_CED1AC
```

Ok rồi, đây chính là CRT initializer tables. Và nó được gọi trước main, và hàm `sub_C93B00` có thay đổi dãy byte_CF7930[] .

Vậy là chương trình đã rõ ràng rồi. Nhưng nếu mà để phân tích static tiếp để tìm ngược lại byte đúng của chuỗi byte_CF7930[] thì khá mất time. Do đã biết rằng chall chỉ sử dụng kĩ thuật antidebug là sử dụng `PEB` để đọc trường `BeingDebugged` nên mình sẽ viết code để open 1 proc, sau đó chạy chương trình `RE4.exe` vào đó, từ đó đọc RAM để lấy chuỗi byte_CF7930[] mà không bị dính antidebug

Vậy thì ta chỉ cần xác định RVA của chuỗi byte_CF7930[] để cho code map đúng vào ram thôi

![image](https://hackmd.io/_uploads/rkpWlTDvWl.png)

`byte_CF7930_RVA` = 0xCF7930 - 0xC90000 =0x67930
tương tự 

Code lấy `byte_CF7930[]` chuẩn
```c 
import os, time, ctypes, subprocess
from ctypes import wintypes

KEY_RVA = 0x67930
TGT_RVA = 0x68458
N = 32

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
SIZE_T = getattr(wintypes, "SIZE_T", ctypes.c_size_t)

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", ctypes.c_char * 256),
        ("szExePath", ctypes.c_char * 260),
    ]

def get_base(pid):
    snap = k32.CreateToolhelp32Snapshot(0x08 | 0x10, pid)  
    me = MODULEENTRY32(); me.dwSize = ctypes.sizeof(me)
    k32.Module32First(snap, ctypes.byref(me))
    while me.szModule.lower() != b"re4.exe":
        k32.Module32Next(snap, ctypes.byref(me))
    k32.CloseHandle(snap)
    return ctypes.addressof(me.modBaseAddr.contents)

def rpm(h, addr, size):
    buf = (ctypes.c_ubyte * size)()
    nread = SIZE_T()
    k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(nread))
    return bytes(buf)

def fmt_0x_list(b: bytes) -> str:
    return ", ".join(f"0x{x:02x}" for x in b)

def main():
    exe = os.path.join(os.getcwd(), "RE4.exe")
    p = subprocess.Popen([exe], creationflags=subprocess.CREATE_NEW_CONSOLE)
    pid = p.pid
    time.sleep(0.2)

    base = get_base(pid)
    h = k32.OpenProcess(0x0400 | 0x0010, False, pid) 

    key = rpm(h, base + KEY_RVA, N)
    tgt = rpm(h, base + TGT_RVA, N)

    k32.CloseHandle(h)
    p.kill()

    print("KEY   =", fmt_0x_list(key))
    print("TARGET=", fmt_0x_list(tgt))

if __name__ == "__main__":
    main()
```

```bash=
KEY   = 0x02, 0x6c, 0x34, 0x00, 0x6f, 0x13, 0x38, 0x04, 0x18, 0x6c, 0x39, 0x03, 0x46, 0x54, 0x2b, 0x68, 0x41, 0x51, 0x5e, 0x18, 0x2b, 0x68, 0x53, 0x03, 0x17, 0x35, 0x28, 0x52, 0x46, 0x0c, 0x2f, 0x78
TARGET= 0x77, 0x33, 0x5f, 0x6e, 0x5f, 0x64, 0x67, 0x33, 0x70, 0x5f, 0x66, 0x6e, 0x76, 0x61, 0x5f, 0x37, 0x75, 0x33, 0x6e, 0x6d, 0x5f, 0x37, 0x67, 0x6d, 0x63, 0x5f, 0x77, 0x36, 0x75, 0x6e, 0x5a, 0x3f
```

Thay vào code solve
```c
target = b"w3_n_dg3p_fnva_7u3nm_7gmc_w6unZ?"
key = bytes([
    0x02, 0x6c, 0x34, 0x00, 0x6f, 0x13, 0x38, 0x04, 0x18, 0x6c, 0x39, 0x03, 0x46, 0x54, 0x2b, 0x68, 0x41, 0x51, 0x5e, 0x18, 0x2b, 0x68, 0x53, 0x03, 0x17, 0x35, 0x28, 0x52, 0x46, 0x0c, 0x2f, 0x78
])

inp = bytes([t ^ k for t, k in zip(target, key)])
print(inp.decode())

#u_kn0w_7h3_m05t_4b0ut_4ntj_d3buG
```

<details>
<summary><b>FLAG</b></summary>
    InfosecPTIT{u_kn0w_7h3_m05t_4b0ut_4ntj_d3buG}
</details>