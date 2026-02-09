# Checker
![image](https://hackmd.io/_uploads/HyfnDHLwWx.png)

Bài cho thẳng 1 file Python luôn.
![image](https://hackmd.io/_uploads/Sk6XSdIPbx.png)
Như tên bài thì nó là 1 checker
Mình sẽ comment bên cạnh code luôn cho dễ trace, đi từ hàm main cho dễ hiểu
Source code
```python
import sys
import hmac
import hashlib

ITERS = 1
SALT_A = bytes([196,8,106,71,60,169,89,72,228,89,219,245,149,143,29,107])
SALT_B = bytes([216,251,234,149,154,121,170,190,74,117,44,154,47,109,237,188])
DK_A   =  bytes([168,87,241,174,190,23,101,74,127,86,161,217,164,88,65,190,100,69,213,45,148,65,34,199,151,253,153,172,85,101,193,107])
DK_B   = bytes([13,235,207,168,10,48,191,193,16,238,246,98,11,190,50,45,165,65,185,179,171,25,190,199,203,84,57,172,216,245,0,219])

def xorb(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b): #khác len thì báo lỗi
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))    #so 2 chuỗi bytes với nhau rồi return

def derive(user_flag: bytes) -> bytes:
    salt = xorb(SALT_A, SALT_B) #tính salt
    return hashlib.pbkdf2_hmac("sha256", user_flag, salt, ITERS, dklen=32) #thêm salt vào và băm input bằng sha256 với 1 vòng lặp PBKDF2

def expected() -> bytes:
    return xorb(DK_A, DK_B) #trả về giá trị sau khi xor

def normalize(s: str) -> bytes: # hàm chuẩn hoá
    s = s.strip()    
    return s.encode("utf-8", "strict")

def main():
    if len(sys.argv) >= 2:
        inp = sys.argv[1]    # nếu truyền tham số khi run thì lấy argv[1] làm input
    else:
        inp = input("Flag: ") #nhập input

    try:
        candidate = normalize(inp) #gọi hàm normalize để chuẩn hoá input
    except UnicodeError:
        print("Invalid input.")
        return 1

    dk = derive(candidate) #tính derived key từ input
    ok = hmac.compare_digest(dk, expected()) #cmp dk với expected()

    if ok:
        print("Correct!")
        return 0
    else:
        print("Wrong!")
        return 1

if __name__ == "__main__":    # gọi main
    raise SystemExit(main()) 
```

Nói 1 cách dễ hiểu thì chương trình lấy input, sau đó thêm salt rồi tạo hash, và so sánh cái hash đó với 1 giá trị expected()

Ở đây giá trị expected thì đơn giản rồi, tự tính ra được

Ta chỉ cần chú ý đoạn `return hashlib.pbkdf2_hmac("sha256", user_flag, salt, ITERS, dklen=32)`. Với việc sử dụng hàm băm nên là việc giải ngược là vô x, bắt buộc phải thử sai, và do ITER = 1 nên việc bruteforce là khả thi (đề bài cũng hint như thế)

Solve:
```python 
import itertools,string,hashlib,hmac,sys

SALT_A = bytes([196,8,106,71,60,169,89,72,228,89,219,245,149,143,29,107])
SALT_B = bytes([216,251,234,149,154,121,170,190,74,117,44,154,47,109,237,188])
DK_A = bytes([168,87,241,174,190,23,101,74,127,86,161,217,164,88,65,190,100,69,213,45,148,65,34,199,151,253,153,172,85,101,193,107])
DK_B = bytes([13,235,207,168,10,48,191,193,16,238,246,98,11,190,50,45,165,65,185,179,171,25,190,199,203,84,57,172,216,245,0,219])
ITERS = 1

def xorb(a,b): return bytes(x^y for x,y in zip(a,b))

salt = xorb(SALT_A,SALT_B)
expected = xorb(DK_A,DK_B)

pref,suff="InfosecPTIT{","}"
lib = string.ascii_letters + string.digits + "_{}-@!#$%^&*()+=:;,.?/\\|<>[]~`\"'"

for i in itertools.count(1):
    for char in itertools.product(lib,repeat=i):
        mid="".join(char)
        flag = (pref + mid + suff).encode()

        dk = hashlib.pbkdf2_hmac("sha256",flag,salt,ITERS,dklen=32)
        if hmac.compare_digest(dk,expected):
            print("Flag : ",flag.decode())
            sys.exit(0)
```
<details>
<summary><b>FLAG</b></summary>
    InfosecPTIT{gggg}
</details>