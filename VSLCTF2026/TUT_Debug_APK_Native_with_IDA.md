# TUT Debug APK Native with IDA

Câu chuyện là dạo này gặp khá nhiều bài ctf dạng apk file, thế nhưng mình thấy việc static analyse mấy bài phức tạp sẽ không hiệu quả, và việc vứt nó vào Chat GPT không giúp mình nâng cấp skill nên mình quyết định học cách debug file apk để có thể trace runtime cho dễ hiểu.
Phương pháp này đúng thì sẽ là IDA Remote Debugging Android Native (.so)

## I. Dạng debug này là gì?
Đây là dạng remote native debugging (android) bằng IDA Pro, theo mô hình client-server:
- IDA trên PC = debugger client
- IDA debug server chạy trên Android (file trong dbgsrv) = debugger server
- 2 bên tương tác thông qua tcp (port 23946 - default của IDA)

Vì PC bản chất là không thể chạy được file APK do khác kiến trúc, thay vào đó : 
- app chạy trên Android (thiết bị thật/ hoặc emulator)
- chạy debug server trên đó
- IDA trên PC kết nối tới server và attach vào proccess app để debug native code trong `.so`

## II. TÌm hiểu qua về APK và `.so`, tại sao lại debug nó
APK (Android Package) là gói cài đặt ứng dụng Android, về bản chất thì nó là 1 file `zip` có cấu trúc được quy ước.

### 1.Cấu trúc APK 
#### 1.1 AndroidManifest.xml
Đây là file khai báo:
- package name (tên)
- conponents : activity, service, receiver, provider
- permissions & features
- entrypoint (activity launcher)
- flags quan trọng cho debug/RE như android:debuggable

#### 1.2 classes.dex, classes2.dex, ...
DEX bytecode chạy trên android runtime (ART). Nếu app viết Java/kotlin thuần thì phần lớn logic nằm ở đây
- classes.dex : file dex chính
- classes2.dex, classes3.dex…: khi app lớn vượt giới hạn method, nó tách multiple dex


Nếu APK không có lib/, rất có thể app “thuần Java/Kotlin” và bạn debug chủ yếu ở DEX

#### 1.3 lib/\_ABI\_/*.so (native libs)

thư mục lib/ chứa các thư viện dạng `.so` (shared object). Đây là phần code C/C++ build bằng NDK, chạy trực tiếp trên CPU, tương tự `.dll` ở windows

`Quy tắc runtime` : Thiết bị chạy ABI nào thì hệ thống sẽ chọn .so đúng ABI đó để load.

#### 1.4 res/ + resources.arcs
res/: layout XML, drawable, strings, styles…
resources.arsc: bảng tài nguyên compiled (mapping ID <-> resource)

Trong RE/CTF, strings.xml đôi khi có hint, URL, key, flag fake… nhưng nhớ rằng string nhạy cảm thường bị obfuscate hoặc chuyển vào native

#### 1.5 assets/
`assets/` là file raw được app tự động đọc bằng code. Đây là nơi hay được giấu hint,flag trong ctf/malware
- config, database, model, file mã hoá
- payload ẩn
- `.so` bị pack ở đây rồi lúc runtime mới giải nén ra và `dlopen`

#### 1.6 META-INF/
Chữ ký- chứa thông tin signature (v1/JAR signature). Android mới còn dùng scheme v2/v3/v4 (không nhất thiết lộ hết trong META-INF), nhưng nhìn chung:
`nếu patch APK thì phải re-sign, nếu không sẽ không chạy được`


### 2. `.so` là gì và nó liên quan gì đến debug
#### 2.1 .so trên android
.so là thư viện native. Khi app load .so, nó map các segment của .so vào memory và gọi hàm bên trong
.so thường chứa : 
- thuật toán check/verify
- crypto transform
- anti-debug / anti-tamper
- JNI bridges (Java_... hoặc RegisterNatives)

#### 2.2 .so được gọi từ java/kotlin như thế nào
- `Pattern A`: System.loadLibrary

Trong code Java/Kotlin thường thấy
```java 
static {
  System.loadLibrary("veilcore");
}
public native boolean check(String input);
```
Khi call check(), CPU nhảy sang native

- `Pattern B`: System.load("/path/to/libx.so")

App tự load .so theo đường dẫn, đôi khi là file vừa giải mã/tải về.

- `Pattern C`: dlopen / android_dlopen_ext

Native code tự load các module khác : plugin architecture, packer/loader, “dropper” malware

Vì vậy, đôi khi APK nhìn không có lib/ nhưng runtime vẫn load .so từ assets hoặc download.

### 3. Nếu APK không có .so thì debug ở đâu ?
#### 3.1 debug Java/Kotlin (DEX layer)
Nếu logic nằm ở trong DEX : 
- android studio java debugger (JDWP)
- bp ở method java/kotlin
- step/inspect var

#### 3.2 hook/instrumentation ở Java layer
vd Frida:
- hook method Java/kotlin đẻ log input/output
- bypass check bằng cách override ret value

#### 3.3 Runtime phân tích (khi app tự giải mã/tải .so)

Nếu APK không có lib/ nhưng app load .so runtime thì debug/hook theo runtime
- tìm .so được map theo /proc/\_pid\_/maps
- dump .so ra để analyse
- hook dlopen để biết tên file load

### 4. Cách nhận biết app có native .so hay không (tĩnh + động)
#### 4.1 Tĩnh: nhìn cấu trúc APK
Nếu có lib/ chắc chắn có native.
#### 4.2 Tĩnh: tìm dấu hiệu trong DEX (JADX)
Trong JADX, search
- System.loadLibrary
- System.load
- System.load
- dlopen
#### 4.3 Động: kiểm tra .so đang được load khi app chạy
Lấy PID app: adb shell pidof PACKAGE
Xem maps: adb shell "cat /proc/PID/maps" | findstr /i "\.so"
Tìm .so cụ thể: adb shell "cat /proc/PID/maps" | findstr /i name.so
   

## II. dbgsrv/ của IDA: các server dùng để làm gì?

Server phải khớp kiến trúc (ABI) của target
`Android`:
- arm64-v8a / aarch64        => android_server (64-bit ARM)
- armeabi-v7a / armv7l => android_server32 (32-bit ARM)
- x86_64 => android_x64_server
- x86 => android_x86_server

`Linux (chạy binary Linux trên máy Linux thật)`:
- Linux x64 => linux_server
- Linux x86 => linux_server32
- Linux ARM => armlinux_server / armlinux_server32 (tùy bản & ABI)

`Windows` : 
- Windows 64-bit => win64_remote.exe
- Windows 32-bit => win32_remote.exe

## III. Các bước cụ thể

1. Cài Android Studio để lấy adb và có emulator chạy chương trình
2. Kiểm tra root
```
adb root
adb shell id
```
Nếu thấy uid=0(root) là OK.

3. xác định ABI và chọn đúng .so

Mở Android Studio lên, check ABI ![image](https://hackmd.io/_uploads/rJLfjMp8We.png)
Ở đây mình chọn x86_64 cho ổn định và ít bị lỗi, do đó sẽ chọn debug server là `android_x64_server` và `.so` trong lib/x86_64/ . Làm tương tự với các ABI khác

4. Cleanup trước khi debug, rất nên làm trước khi debug

Kill mọi IDA server cũ + dọn port forward
```
adb shell "pkill -f ida_server; pkill -f android_server; pkill -f android_x64_server; pkill -f android_x86_server"
adb forward --remove-all
adb forward --list
```

5. Chạy IDA debug server trên Android

Push server lên /data/local/tmp và chmod
```
adb push android_x64_server /data/local/tmp/ida_server
adb shell chmod 755 /data/local/tmp/ida_server
```
`note` : nhớ đổi debug server tuỳ theo ABI

Port forwarding về PC
```
adb forward tcp:23946 tcp:23946
adb forward --list
```

Start server
`adb shell /data/local/tmp/ida_server -p 23946`



6. Cấu hình IDA để attach
- Mở đúng file .so (đúng ABI)
- Chọn đúng debugger, sau đó Debugger -> Process Option -> sửa Host: 127.0.0.1 và Port: 23946
- Chọn Debugger → Attach to process -> attach đúng process app cần debug

`note` : lưu ý khi debug, lúc này app sẽ trong trạng thái hold proc để chờ ta chạy lệnh. Vậy nên có thể nó sẽ hiện not respoding, Lúc này ta chỉ cần đặt bp cần trace và bấm resume là được. Còn nếu vẫn bị thì rất có khả năng dính antidebug,... 



## IV. DEMO

Mình sẽ demo bằng 1 chall ctf đơn giản

![image](https://hackmd.io/_uploads/HJXozXpL-x.png)

Đây là 1 checker thôi, nhập đúng thì ra flag. Như lúc nãy mình có bảo là mình ưu tiên dùng ABI x86_64 cho ổn định. Nên mình sẽ mở folder x86_64 trong lib/

![image](https://hackmd.io/_uploads/H1BzXQ6LZl.png)


Mình sẽ mở file chỉ định kia bằng IDA lên để debug

![image](https://hackmd.io/_uploads/BkolEX68Ze.png)
 
Hàm tô đỏ có vẻ như là logic chính của bài
```c 
__int64 __fastcall Java_hpandro_android_security_ui_activity_task_misc_Backdoor7Activity_hello(
        __int64 a1,
        __int64 a2,
        __int64 a3)
{
  const char *s1; // r15
  char *NO_1; // rbx
  char *s2; // r12
  const char *NO; // rsi

  s1 = (const char *)(*(__int64 (__fastcall **)(__int64, __int64, _QWORD))(*(_QWORD *)a1 + 1352LL))(a1, a3, 0);
  NO_1 = (char *)malloc(0xBu);
  s2 = (char *)malloc(5u);
  *(_WORD *)NO_1 = 51;
  *(_WORD *)s2 = 51;
  __strcat_chk(NO_1, "6", 11);
  __strcat_chk(NO_1, aDtw08, 11);
  __strcat_chk(NO_1, &aDtw08[1], 11);
  __strcat_chk(NO_1, &aDtw08[2], 11);
  __strcat_chk(NO_1, &aDtw08[4], 11);
  __strcat_chk(s2, "9", 5);
  __strcat_chk(NO_1, &aDtw08[3], 11);
  __strcat_chk(NO_1, "2", 11);
  __strcat_chk(s2, "6", 5);
  __strcat_chk(NO_1, "6", 11);
  __strcat_chk(s2, "1", 5);
  __strcat_chk(NO_1, "9", 11);
  NO = "NO";
  if ( !strcmp(s1, s2) )
    NO = NO_1;
  return (*(__int64 (__fastcall **)(__int64, const char *))(*(_QWORD *)a1 + 1336LL))(a1, NO);
}
```
Thực ra xem code này là cũng biết luôn PIN rồi, nhưng mình vẫn sẽ làm tiếp để debug :v 

Đặt bp ở vị trí nhập input và chỗ strcmp

Bật root
![image](https://hackmd.io/_uploads/HyxTHX6L-g.png)



Cleanup
![image](https://hackmd.io/_uploads/r1qF8XaIZe.png)

Push server và chmod
![image](https://hackmd.io/_uploads/Sy23IQa8bl.png)

Port forwarding về PC
![image](https://hackmd.io/_uploads/S1KJwQ6Ubl.png)

Khởi động server
![image](https://hackmd.io/_uploads/Hyv-DmTIbe.png)

Cấu hình lại Debugger 
![image](https://hackmd.io/_uploads/S18EvXaLZe.png)

Attach proc

![image](https://hackmd.io/_uploads/HkeIwXpI-e.png)

Chọn đúng proc
![image](https://hackmd.io/_uploads/BkJYwmTUWx.png)

Bấm Same, khi này app đang hold nên sẽ có hiện tượng treo, không thao tác được

![image](https://hackmd.io/_uploads/ryXsPXpLWl.png)

![image](https://hackmd.io/_uploads/HJLawQTU-e.png)

![image](https://hackmd.io/_uploads/Sk30w7TIbl.png)

Cứ wait chương trình và vào IDA bấm F9 hoặc click resume
![image](https://hackmd.io/_uploads/Byxbd7TL-x.png)

Hoặc thoát chương trình vào lại, nhưng phải thao tác nhanh, bấm resume ngay, hạn chế làm chương trình bị crash

![image](https://hackmd.io/_uploads/S1yvYmTLZx.png)
![image](https://hackmd.io/_uploads/r1kOYX68Wl.png)

Debug thành công và thấy mã PIN khi strcmp là 3961

![image](https://hackmd.io/_uploads/r1GnYQ6U-x.png)

OK mình sẽ nhập lại

![image](https://hackmd.io/_uploads/ryX29Q6U-x.png)


Ta đã có flag !

Trên đây là TUT debug android native qua IDA của mình !
Have fun....