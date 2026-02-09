# MiniVM

![image](https://hackmd.io/_uploads/Hy3Yit8v-l.png)

Bài cho ta 1 file thực thi .exe .Thử mở nó lên bằng DiE để xem qua profile

![image](https://hackmd.io/_uploads/B1i8D2Iw-l.png)

1 file được viết bằng Go và ở section .zdebug_line có dấu hiệu bị packed. Nhưng sau khi search thì có vẻ như việc section debug info của Go bị nén như vậy là bình thường :v Tiếp tục thực thi file để xem hành vi

![image](https://hackmd.io/_uploads/BJ4Ud2UD-x.png)

Vẫn là 1 dạng check flag thôi, nhưng nhìn qua thì khả năng bài này còn check cả len của input ,dựa vào thông báo nó in ra

Mở lên bằng IDA để xem pseudocode
```c 
// main.main
void __fastcall main_main()
{
  __int128 v0; // xmm15
  __int64 v1; // rsi
  __int64 v2; // rcx
  __int64 v3; // r8
  int v4; // r9d
  int v5; // r10d
  int v6; // r11d
  __int64 n10; // r9
  __int64 v8; // rdx
  __int64 os.Stdout; // rbx
  __int64 v10; // rax
  __int64 v11; // rcx
  int v12; // r8d
  int v13; // r9d
  int v14; // r10d
  int v15; // r11d
  __int64 v16; // rax
  __int64 v17; // rcx
  int String; // eax
  int v19; // ecx
  int v20; // r8d
  int v21; // r9d
  int v22; // r10d
  int v23; // r11d
  __int64 v24; // rax
  void *v25; // rdx
  int v26; // r11d
  __int64 n60; // r9
  int v28; // r8d
  int v29; // r9d
  int v30; // r10d
  int v31; // r11d
  int v32; // eax
  int v33; // ecx
  int v34; // r8d
  int v35; // r9d
  int v36; // r10d
  int v37; // r11d
  __int64 v38; // rax
  __int64 v39; // [rsp+10h] [rbp-2A0h]
  __int64 v40; // [rsp+10h] [rbp-2A0h]
  __int64 v41; // [rsp+18h] [rbp-298h]
  __int64 v42; // [rsp+18h] [rbp-298h]
  __int64 v43; // [rsp+20h] [rbp-290h]
  int v44; // [rsp+48h] [rbp-268h]
  _QWORD v45[2]; // [rsp+50h] [rbp-260h] BYREF
  __int128 v46; // [rsp+60h] [rbp-250h] BYREF
  _QWORD v47[2]; // [rsp+70h] [rbp-240h] BYREF
  _QWORD v48[2]; // [rsp+80h] [rbp-230h] BYREF
  void *p_p_runtime.noptrbss[2]; // [rsp+90h] [rbp-220h] BYREF
  _BYTE v50[40]; // [rsp+1B0h] [rbp-100h] BYREF
  __int128 v51; // [rsp+1D8h] [rbp-D8h] BYREF
  __int64 n4096; // [rsp+1E8h] [rbp-C8h]
  RTYPE **go:itab._os.File_io.Reader; // [rsp+1F0h] [rbp-C0h]
  __int64 runtime.bss_1; // [rsp+1F8h] [rbp-B8h]
  _QWORD v55[5]; // [rsp+208h] [rbp-A8h] BYREF
  _OWORD v56[5]; // [rsp+230h] [rbp-80h] BYREF
  _QWORD v57[2]; // [rsp+288h] [rbp-28h] BYREF
  _QWORD v58[2]; // [rsp+298h] [rbp-18h] BYREF
  __int64 runtime.bss; // [rsp+2A8h] [rbp-8h]

  v58[0] = &RTYPE_string;
  v58[1] = &off_1400F1710;
  v1 = 1;
  fmt_Fprintln((unsigned int)go_itab__os_File_io_Writer, os_Stdout, (unsigned int)v58, 1, 1);
  if ( qword_140182DC8 <= 1 )
  {
    v57[0] = &RTYPE_string;
    v57[1] = &off_1400F1720;
    os.Stdout = os_Stdout;
    v10 = fmt_Fprint((unsigned int)go_itab__os_File_io_Writer, os_Stdout, (unsigned int)v57, 1, 1, v3, v4, v5, v6);
    runtime.bss = runtime_bss;
    v56[0] = v0;
    ((void (__golang *)(__int64, __int64, __int64, _QWORD *))loc_140072470)(v10, os.Stdout, v11, v55);
    v16 = runtime_makeslice((unsigned int)&RTYPE_uint8, 4096, 4096, (unsigned int)v55, 1, v12, v13, v14, v15);
    v51 = v0;
    *(_QWORD *)&v51 = ((__int64 (__golang *)(__int64, __int64, __int64, _BYTE *))loc_140072470)(v16, 4096, v17, v50);
    *((_QWORD *)&v51 + 1) = 4096;
    n4096 = 4096;
    go:itab._os.File_io.Reader = go_itab__os_File_io_Reader;
    runtime.bss_1 = runtime.bss;
    v55[3] = -1;
    v55[4] = -1;
    *(_QWORD *)&v56[0] = v51;
    v1 = (__int64)&v51 + 8;
    ((void (__fastcall *)(char *, char *))loc_1400727DA)((char *)v56 + 8, (char *)&v51 + 8);
    String = bufio__ptr_Reader_ReadString(v56, 10);
    v24 = strings_TrimSpace(String, 10, v19, (unsigned int)v56 + 8, (unsigned int)&v51 + 8, v20, v21, v22, v23);
    n10 = 10;
    v8 = v24;
  }
  else
  {
    n10 = *(_QWORD *)(os_Args + 24);
    v8 = *(_QWORD *)(os_Args + 16);
  }
  p_p_runtime.noptrbss[1] = *((void **)&v0 + 1);
  ((void (__fastcall *)(void **, __int64, __int64, __int64, __int64, __int64))loc_14007241D)(
    &p_p_runtime.noptrbss[1],
    v1,
    v8,
    v2,
    v3,
    n10);
  p_p_runtime.noptrbss[0] = &runtime_noptrbss;
  v50[0] = 1;
  v50[32] = 1;
  if ( n60 == 60 )
  {
    v44 = (int)v25;
    if ( (unsigned __int8)main__ptr_MiniVM_execute(
                            p_p_runtime.noptrbss,
                            main_BYTECODE,
                            *(unsigned __int64 *)&qword_14017A9C8,
                            *(__int64 *)&qword_14017A9D0,
                            v25,
                            60,
                            60,
                            &runtime_noptrbss,
                            v26) )
    {
      v47[0] = &RTYPE_string;
      v47[1] = &off_1400F1740;                  // "\n[+] Congratulations! You found the flag!34694469519536141888238489627838134765625"
      fmt_Fprintln((unsigned int)go_itab__os_File_io_Writer, os_Stdout, (unsigned int)v47, 1, 1);
      v46 = v0;
      v32 = runtime_concatstring2(
              0,
              (unsigned int)"[+] Flag is correct: ",
              21,
              v44,
              60,
              v28,
              v29,
              v30,
              v31,
              v39,
              v41,
              v43);
      v38 = runtime_convTstring(v32, (unsigned int)"[+] Flag is correct: ", v33, v44, 60, v34, v35, v36, v37, v40, v42);
      *(_QWORD *)&v46 = &RTYPE_string;
      *((_QWORD *)&v46 + 1) = v38;
      fmt_Fprintln((unsigned int)go_itab__os_File_io_Writer, os_Stdout, (unsigned int)&v46, 1, 1);
    }
    else
    {
      v45[0] = &RTYPE_string;
      v45[1] = &off_1400F1750;                  // "\n[-] Wrong flag! Try again..."
      fmt_Fprintln((unsigned int)go_itab__os_File_io_Writer, os_Stdout, (unsigned int)v45, 1, 1);
    }
  }
  else
  {
    v48[0] = &RTYPE_string;
    v48[1] = &off_1400F1730;                    // "\n[-] Wrong flag length!"
    fmt_Fprintln((unsigned int)go_itab__os_File_io_Writer, os_Stdout, (unsigned int)v48, 1, 1);
  }
}
```
Đầu tiên mình sẽ làm rõ về việc check len, phần thông báo in ra ```Wrong flag length!``` ở trong nhánh else của chương trình, khi nhìn lên nhánh if thì thấy điều kiện `n60 == 60`, ở đây có thể đoán luôn là `len` == 60. Kiểm tra bằng cách điền 60bytes rác vào
![image](https://hackmd.io/_uploads/Bki8ohUwZl.png)

Ok vậy đúng là `len` = 60 rồi


### Ta sẽ xác định xem VM nằm ở đâu trong GO binary bằng cách liệt kê symbol
```bash
(base) ┌──(venv-pwn)(hieesu19㉿DESKTOP-BFB0MA5)-[/mnt/d/CTF/ATTT_PTIT/re/MiniVM/MiniVM]
└─$ go tool nm mini_vm.exe | grep -E "main\."
140175b60 D go:main.inittasks
1400a1980 T main.(*MiniVM).execute
14017a9c0 D main.BYTECODE
1400a23c0 T main.main
1400673a0 T runtime.main.func1
14003da00 T runtime.main.func2
```
=> VM chính là `main.(*MiniVM).execute`, còn chương trình VM nằm trong `main.BYTECODE`

### Tiếp theo ta sẽ rev lại `main.main` để hiểu rõ flow check flag
Ta cần disasm nó
```asm
└─$ go tool objdump -s "main\.main" mini_vm.exe
TEXT main.main(SB) C:/Users/toanv/OneDrive/Desktop/Challenge/Chall2/mini_vm.go
  mini_vm.go:190        0x1400a23c0             4c8da424d8fdffff                LEAQ 0xfffffdd8(SP), R12
  mini_vm.go:190        0x1400a23c8             4d3b6610                        CMPQ R12, 0x10(R14)
  mini_vm.go:190        0x1400a23cc             0f8672030000                    JBE 0x1400a2744
  mini_vm.go:190        0x1400a23d2             55                              PUSHQ BP
  mini_vm.go:190        0x1400a23d3             4889e5                          MOVQ SP, BP
  mini_vm.go:190        0x1400a23d6             4881eca0020000                  SUBQ $0x2a0, SP
  mini_vm.go:191        0x1400a23dd             488d159cb10000                  LEAQ type:*+42368(SB), DX
  mini_vm.go:191        0x1400a23e4             4889942488020000                MOVQ DX, 0x288(SP)
  mini_vm.go:191        0x1400a23ec             488d151df30400                  LEAQ runtime.buildVersion.str+16(SB), DX
  mini_vm.go:191        0x1400a23f3             4889942490020000                MOVQ DX, 0x290(SP)
  print.go:314          0x1400a23fb             488b1d26060e00                  MOVQ os.Stdout(SB), BX
  print.go:314          0x1400a2402             488d05cff90400                  LEAQ go:itab.*os.File,io.Writer(SB), AX
  print.go:314          0x1400a2409             488d8c2488020000                LEAQ 0x288(SP), CX
  print.go:314          0x1400a2411             bf01000000                      MOVL $0x1, DI
  print.go:314          0x1400a2416             4889fe                          MOVQ DI, SI
  print.go:314          0x1400a2419             e822a4ffff                      CALL fmt.Fprintln(SB)
  mini_vm.go:201        0x1400a241e             48833da2090e0001                CMPQ os.Args+8(SB), $0x1
  mini_vm.go:201        0x1400a2426             7e14                            JLE 0x1400a243c
  mini_vm.go:201        0x1400a2428             488b1591090e00                  MOVQ os.Args(SB), DX
  mini_vm.go:202        0x1400a242f             4c8b4a18                        MOVQ 0x18(DX), R9
  mini_vm.go:202        0x1400a2433             488b5210                        MOVQ 0x10(DX), DX
  mini_vm.go:202        0x1400a2437             e95e010000                      JMP 0x1400a259a
  mini_vm.go:204        0x1400a243c             488d153db10000                  LEAQ type:*+42368(SB), DX
  mini_vm.go:204        0x1400a2443             4889942478020000                MOVQ DX, 0x278(SP)
  mini_vm.go:204        0x1400a244b             488d15cef20400                  LEAQ runtime.buildVersion.str+32(SB), DX
  mini_vm.go:204        0x1400a2452             4889942480020000                MOVQ DX, 0x280(SP)
  print.go:272          0x1400a245a             488b1dc7050e00                  MOVQ os.Stdout(SB), BX
  print.go:272          0x1400a2461             488d0570f90400                  LEAQ go:itab.*os.File,io.Writer(SB), AX
  print.go:272          0x1400a2468             488d8c2478020000                LEAQ 0x278(SP), CX
  print.go:272          0x1400a2470             bf01000000                      MOVL $0x1, DI
  print.go:272          0x1400a2475             4889fe                          MOVQ DI, SI
  print.go:272          0x1400a2478             e8e3a2ffff                      CALL fmt.Fprint(SB)
  mini_vm.go:205        0x1400a247d             488b159c050e00                  MOVQ runtime.bss(SB), DX
  mini_vm.go:205        0x1400a2484             4889942498020000                MOVQ DX, 0x298(SP)
  bufio.go:63           0x1400a248c             90                              NOPL
  bufio.go:56           0x1400a248d             440f11bc2420020000              MOVUPS X15, 0x220(SP)
  bufio.go:56           0x1400a2496             488dbc2428020000                LEAQ 0x228(SP), DI
  bufio.go:56           0x1400a249e             488d7fd0                        LEAQ -0x30(DI), DI
  bufio.go:56           0x1400a24a2             48896c24f0                      MOVQ BP, -0x10(SP)
  bufio.go:56           0x1400a24a7             488d6c24f0                      LEAQ -0x10(SP), BP
  bufio.go:56           0x1400a24ac             e8bffffcff                      CALL 0x140072470
  bufio.go:56           0x1400a24b1             488b6d00                        MOVQ 0(BP), BP
  bufio.go:57           0x1400a24b5             488d0544b10000                  LEAQ type:*+42496(SB), AX
  bufio.go:57           0x1400a24bc             bb00100000                      MOVL $0x1000, BX
  bufio.go:57           0x1400a24c1             4889d9                          MOVQ BX, CX
  bufio.go:57           0x1400a24c4             e8579dfcff                      CALL runtime.makeslice(SB)
  bufio.go:88           0x1400a24c9             440f11bc24c8010000              MOVUPS X15, 0x1c8(SP)
  bufio.go:88           0x1400a24d2             488dbc24d0010000                LEAQ 0x1d0(SP), DI
  bufio.go:88           0x1400a24da             488d7fd0                        LEAQ -0x30(DI), DI
  bufio.go:88           0x1400a24de             6690                            NOPW
  bufio.go:88           0x1400a24e0             48896c24f0                      MOVQ BP, -0x10(SP)
  bufio.go:88           0x1400a24e5             488d6c24f0                      LEAQ -0x10(SP), BP
  bufio.go:88           0x1400a24ea             e881fffcff                      CALL 0x140072470
  bufio.go:88           0x1400a24ef             488b6d00                        MOVQ 0(BP), BP
  bufio.go:89           0x1400a24f3             48898424c8010000                MOVQ AX, 0x1c8(SP)
  bufio.go:89           0x1400a24fb             48c78424d001000000100000        MOVQ $0x1000, 0x1d0(SP)
  bufio.go:89           0x1400a2507             48c78424d801000000100000        MOVQ $0x1000, 0x1d8(SP)
  bufio.go:90           0x1400a2513             488d159ef80400                  LEAQ go:itab.*os.File,io.Reader(SB), DX
  bufio.go:90           0x1400a251a             48899424e0010000                MOVQ DX, 0x1e0(SP)
  bufio.go:90           0x1400a2522             488b942498020000                MOVQ 0x298(SP), DX
  bufio.go:90           0x1400a252a             48899424e8010000                MOVQ DX, 0x1e8(SP)
  bufio.go:91           0x1400a2532             48c7842410020000ffffffff        MOVQ $-0x1, 0x210(SP)
  bufio.go:92           0x1400a253e             48c7842418020000ffffffff        MOVQ $-0x1, 0x218(SP)
  bufio.go:88           0x1400a254a             488b9424c8010000                MOVQ 0x1c8(SP), DX
  bufio.go:88           0x1400a2552             4889942420020000                MOVQ DX, 0x220(SP)
  bufio.go:88           0x1400a255a             488dbc2428020000                LEAQ 0x228(SP), DI
  bufio.go:88           0x1400a2562             488db424d0010000                LEAQ 0x1d0(SP), SI
  bufio.go:88           0x1400a256a             48896c24f0                      MOVQ BP, -0x10(SP)
  bufio.go:88           0x1400a256f             488d6c24f0                      LEAQ -0x10(SP), BP
  bufio.go:88           0x1400a2574             e86102fdff                      CALL 0x1400727da
  bufio.go:88           0x1400a2579             488b6d00                        MOVQ 0(BP), BP
  mini_vm.go:206        0x1400a257d             488d842420020000                LEAQ 0x220(SP), AX
  mini_vm.go:206        0x1400a2585             bb0a000000                      MOVL $0xa, BX
  mini_vm.go:206        0x1400a258a             e891a5fdff                      CALL bufio.(*Reader).ReadString(SB)
  mini_vm.go:207        0x1400a258f             e8ac9dfdff                      CALL strings.TrimSpace(SB)
  mini_vm.go:212        0x1400a2594             4989d9                          MOVQ BX, R9
  mini_vm.go:212        0x1400a2597             4889c2                          MOVQ AX, DX
  mini_vm.go:210        0x1400a259a             90                              NOPL
  mini_vm.go:21         0x1400a259b             440f11bc2480000000              MOVUPS X15, 0x80(SP)
  mini_vm.go:21         0x1400a25a4             488dbc2488000000                LEAQ 0x88(SP), DI
  mini_vm.go:21         0x1400a25ac             48896c24f0                      MOVQ BP, -0x10(SP)
  mini_vm.go:21         0x1400a25b1             488d6c24f0                      LEAQ -0x10(SP), BP
  mini_vm.go:21         0x1400a25b6             e862fefcff                      CALL 0x14007241d
  mini_vm.go:21         0x1400a25bb             488b6d00                        MOVQ 0(BP), BP
  mini_vm.go:22         0x1400a25bf             4c8d157a5b1200                  LEAQ runtime.zerobase(SB), R10
  mini_vm.go:22         0x1400a25c6             4c89942480000000                MOVQ R10, 0x80(SP)
  mini_vm.go:23         0x1400a25ce             c68424a001000001                MOVB $0x1, 0x1a0(SP)
  mini_vm.go:24         0x1400a25d6             c68424c001000001                MOVB $0x1, 0x1c0(SP)
  mini_vm.go:24         0x1400a25de             6690                            NOPW
  mini_vm.go:212        0x1400a25e0             4983f93c                        CMPQ R9, $0x3c
  mini_vm.go:212        0x1400a25e4             0f8519010000                    JNE 0x1400a2703
  mini_vm.go:212        0x1400a25ea             4c894c2430                      MOVQ R9, 0x30(SP)
  mini_vm.go:212        0x1400a25ef             4889542438                      MOVQ DX, 0x38(SP)
  mini_vm.go:217        0x1400a25f4             488b1dc5830d00                  MOVQ main.BYTECODE(SB), BX
  mini_vm.go:217        0x1400a25fb             488b0dc6830d00                  MOVQ main.BYTECODE+8(SB), CX
  mini_vm.go:217        0x1400a2602             488b3dc7830d00                  MOVQ main.BYTECODE+16(SB), DI
  mini_vm.go:217        0x1400a2609             488d842480000000                LEAQ 0x80(SP), AX
  mini_vm.go:217        0x1400a2611             4889d6                          MOVQ DX, SI
  mini_vm.go:217        0x1400a2614             4d89c8                          MOVQ R9, R8
  mini_vm.go:217        0x1400a2617             e864f3ffff                      CALL main.(*MiniVM).execute(SB)
  mini_vm.go:217        0x1400a261c             0f1f4000                        NOPL 0(AX)
  mini_vm.go:217        0x1400a2620             84c0                            TESTL AL, AL
  mini_vm.go:219        0x1400a2622             0f849a000000                    JE 0x1400a26c2
  mini_vm.go:220        0x1400a2628             488d1551af0000                  LEAQ type:*+42368(SB), DX
  mini_vm.go:220        0x1400a262f             4889542460                      MOVQ DX, 0x60(SP)
  mini_vm.go:220        0x1400a2634             488d1505f10400                  LEAQ runtime.buildVersion.str+64(SB), DX
  mini_vm.go:220        0x1400a263b             4889542468                      MOVQ DX, 0x68(SP)
  print.go:314          0x1400a2640             488b1de1030e00                  MOVQ os.Stdout(SB), BX
  print.go:314          0x1400a2647             488d058af70400                  LEAQ go:itab.*os.File,io.Writer(SB), AX
  print.go:314          0x1400a264e             488d4c2460                      LEAQ 0x60(SP), CX
  print.go:314          0x1400a2653             bf01000000                      MOVL $0x1, DI
  print.go:314          0x1400a2658             4889fe                          MOVQ DI, SI
  print.go:314          0x1400a265b             0f1f440000                      NOPL 0(AX)(AX*1)
  print.go:314          0x1400a2660             e8dba1ffff                      CALL fmt.Fprintln(SB)
  mini_vm.go:221        0x1400a2665             440f117c2450                    MOVUPS X15, 0x50(SP)
  mini_vm.go:221        0x1400a266b             31c0                            XORL AX, AX
  mini_vm.go:221        0x1400a266d             488d1dfc8d0200                  LEAQ go:string.*+13720(SB), BX
  mini_vm.go:221        0x1400a2674             b915000000                      MOVL $0x15, CX
  mini_vm.go:221        0x1400a2679             488b7c2438                      MOVQ 0x38(SP), DI
  mini_vm.go:221        0x1400a267e             488b742430                      MOVQ 0x30(SP), SI
  mini_vm.go:221        0x1400a2683             e8181bfbff                      CALL runtime.concatstring2(SB)
  mini_vm.go:221        0x1400a2688             e85375fcff                      CALL runtime.convTstring(SB)
  mini_vm.go:221        0x1400a268d             488d15ecae0000                  LEAQ type:*+42368(SB), DX
  mini_vm.go:221        0x1400a2694             4889542450                      MOVQ DX, 0x50(SP)
  mini_vm.go:221        0x1400a2699             4889442458                      MOVQ AX, 0x58(SP)
  print.go:314          0x1400a269e             488b1d83030e00                  MOVQ os.Stdout(SB), BX
  print.go:314          0x1400a26a5             488d052cf70400                  LEAQ go:itab.*os.File,io.Writer(SB), AX
  print.go:314          0x1400a26ac             488d4c2450                      LEAQ 0x50(SP), CX
  print.go:314          0x1400a26b1             bf01000000                      MOVL $0x1, DI
  print.go:314          0x1400a26b6             4889fe                          MOVQ DI, SI
  print.go:314          0x1400a26b9             e882a1ffff                      CALL fmt.Fprintln(SB)
  print.go:314          0x1400a26be             6690                            NOPW
  mini_vm.go:225        0x1400a26c0             eb38                            JMP 0x1400a26fa
  mini_vm.go:223        0x1400a26c2             488d15b7ae0000                  LEAQ type:*+42368(SB), DX
  mini_vm.go:223        0x1400a26c9             4889542440                      MOVQ DX, 0x40(SP)
  mini_vm.go:223        0x1400a26ce             488d157bf00400                  LEAQ runtime.buildVersion.str+80(SB), DX
  mini_vm.go:223        0x1400a26d5             4889542448                      MOVQ DX, 0x48(SP)
  print.go:314          0x1400a26da             488b1d47030e00                  MOVQ os.Stdout(SB), BX
  print.go:314          0x1400a26e1             488d05f0f60400                  LEAQ go:itab.*os.File,io.Writer(SB), AX
  print.go:314          0x1400a26e8             488d4c2440                      LEAQ 0x40(SP), CX
  print.go:314          0x1400a26ed             bf01000000                      MOVL $0x1, DI
  print.go:314          0x1400a26f2             4889fe                          MOVQ DI, SI
  print.go:314          0x1400a26f5             e846a1ffff                      CALL fmt.Fprintln(SB)
  mini_vm.go:225        0x1400a26fa             4881c4a0020000                  ADDQ $0x2a0, SP
  mini_vm.go:225        0x1400a2701             5d                              POPQ BP
  mini_vm.go:225        0x1400a2702             c3                              RET
  mini_vm.go:213        0x1400a2703             488d1576ae0000                  LEAQ type:*+42368(SB), DX
  mini_vm.go:213        0x1400a270a             4889542470                      MOVQ DX, 0x70(SP)
  mini_vm.go:213        0x1400a270f             488d151af00400                  LEAQ runtime.buildVersion.str+48(SB), DX
  mini_vm.go:213        0x1400a2716             4889542478                      MOVQ DX, 0x78(SP)
  print.go:314          0x1400a271b             488b1d06030e00                  MOVQ os.Stdout(SB), BX
  print.go:314          0x1400a2722             488d05aff60400                  LEAQ go:itab.*os.File,io.Writer(SB), AX
  print.go:314          0x1400a2729             488d4c2470                      LEAQ 0x70(SP), CX
  print.go:314          0x1400a272e             bf01000000                      MOVL $0x1, DI
  print.go:314          0x1400a2733             4889fe                          MOVQ DI, SI
  print.go:314          0x1400a2736             e805a1ffff                      CALL fmt.Fprintln(SB)
  mini_vm.go:214        0x1400a273b             4881c4a0020000                  ADDQ $0x2a0, SP
  mini_vm.go:214        0x1400a2742             5d                              POPQ BP
  mini_vm.go:214        0x1400a2743             c3                              RET
  mini_vm.go:190        0x1400a2744             e8b7d7fcff                      CALL runtime.morestack_noctxt.abi0(SB)
  mini_vm.go:190        0x1400a2749             e972fcffff                      JMP main.main(SB)
  :-1                   0x1400a274e             cc                              INT $0x3
  :-1                   0x1400a274f             cc                              INT $0x3
  :-1                   0x1400a2750             cc                              INT $0x3
  :-1                   0x1400a2751             cc                              INT $0x3
  :-1                   0x1400a2752             cc                              INT $0x3
  :-1                   0x1400a2753             cc                              INT $0x3
  :-1                   0x1400a2754             cc                              INT $0x3
  :-1                   0x1400a2755             cc                              INT $0x3
  :-1                   0x1400a2756             cc                              INT $0x3
  :-1                   0x1400a2757             cc                              INT $0x3
  :-1                   0x1400a2758             cc                              INT $0x3
  :-1                   0x1400a2759             cc                              INT $0x3
  :-1                   0x1400a275a             cc                              INT $0x3
  :-1                   0x1400a275b             cc                              INT $0x3
  :-1                   0x1400a275c             cc                              INT $0x3
  :-1                   0x1400a275d             cc                              INT $0x3
  :-1                   0x1400a275e             cc                              INT $0x3
  :-1                   0x1400a275f             cc                              INT $0x3
```

Flow sẽ là : 
- in ra`Enter the flag`
- đọc input
- Check len(flag) == 60 (nếu sai thì in thông báo và thoát)
- tạo vm, gọi vm.execute(BYTECODE, flag)
- in ra  correct / wrong

=> cần tìm điều kiện để execute() trả về true

### rev lại miniVM để hiểu nó làm gì

`go tool objdump -s "main\.\(\*MiniVM\)\.execute" mini_vm.exe > execute.asm`

[execute.asm](https://ideone.com/7TudVL)

dùng GPT để đọc 
![image](https://hackmd.io/_uploads/BJtlo6vDZl.png)



### extract bytecode từ binary
Ta sẽ lấy địa chỉ của `main.BYTECODE`

```bash 
└─$ go tool nm mini_vm.exe | grep -i BYTECODE
14017a9c0 D main.BYTECODE
```

Tiếp đó ta cần đổi VA sang file offset bằng section ``.data`
```bash
└─$ objdump -h mini_vm.exe

mini_vm.exe:     file format pei-x86-64

Sections:
Idx Name          Size      VMA               LMA               File off  Algn
  0 .text         000a1791  0000000140001000  0000000140001000  00000600  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
  1 .rdata        000d18c8  00000001400a3000  00000001400a3000  000a1e00  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  2 .data         0000dc00  0000000140175000  0000000140175000  00173800  2**4
                  CONTENTS, ALLOC, LOAD, DATA
  3 .pdata        00004b18  00000001401cc000  00000001401cc000  00181400  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  4 .xdata        000000b4  00000001401d1000  00000001401d1000  00186000  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  5 .zdebug_abbrev 00000266  00000001401d2000  00000001401d2000  00186200  2**0
                  CONTENTS, READONLY, DEBUGGING, COMPRESSED
  6 .zdebug_line  00046996  00000001401d3000  00000001401d3000  00186400  2**0
                  CONTENTS, READONLY, DEBUGGING, COMPRESSED
  7 .zdebug_frame 0001677c  00000001401fa000  00000001401fa000  001ad200  2**0
                  CONTENTS, READONLY, DEBUGGING, COMPRESSED
  8 .debug_gdb_scripts 00000030  0000000140202000  0000000140202000  001b4a00  2**0
                  CONTENTS, READONLY, DEBUGGING
  9 .zdebug_info  000a0e19  0000000140203000  0000000140203000  001b4c00  2**0
                  CONTENTS, READONLY, DEBUGGING, COMPRESSED
 10 .zdebug_loclists 0003b465  0000000140247000  0000000140247000  001f8a00  2**0
                  CONTENTS, READONLY, DEBUGGING, COMPRESSED
 11 .zdebug_rnglists 0001bc3d  0000000140262000  0000000140262000  00213600  2**0
                  CONTENTS, READONLY, DEBUGGING, COMPRESSED
 12 .zdebug_addr  00003b68  0000000140273000  0000000140273000  00223a00  2**0
                  CONTENTS, READONLY, DEBUGGING, COMPRESSED
 13 .idata        0000053e  0000000140274000  0000000140274000  00224a00  2**2
                  CONTENTS, ALLOC, LOAD, DATA
 14 .reloc        00003ac4  0000000140275000  0000000140275000  00225000  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
 15 .symtab       0001a554  0000000140279000  0000000140279000  00228c00  2**2
                  CONTENTS, READONLY
```

![image](https://hackmd.io/_uploads/Bkjbn6wvZx.png)

Ok giờ dump bytecode ra thôi

```
OFF=$((0x174be0))
COUNT=545
BS=4096

dd if=mini_vm.exe of=bytecode.bin bs=$BS skip=$((OFF/BS)) status=none
dd if=mini_vm.exe of=bytecode.bin bs=1 skip=$((OFF - (OFF/BS)*BS)) count=$COUNT seek=0 conv=notrunc status=none
```

### disassemble bytecode và nhận diện pattern check

Ta disasm theo rule sau:
- opcode cần immediate: 0x10, 0x30
- opcode 1 byte: 0x22, 0x31, 0xFE, 0xFF

Ta sẽ thấy nó lặp theo khuôn sau với mỗi kí tự `i`
```
30 i        ; push flag[i]
10 k        ; push key
22          ; xor
10 expected ; push expected
31          ; eq
FE          ; check (phải == 1)
```

=> điều kiện là
```
(flag[i] ^ k) == expected
=> flag[i] == k ^ expected
```

Code solve 
```python 
#!/usr/bin/env python3
import sys

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "bytecode.bin"
    bc = open(path, "rb").read()
    constraints = []
    for p in range(len(bc) - 8):
        if (bc[p]   == 0x30 and
            bc[p+2] == 0x10 and
            bc[p+4] == 0x22 and
            bc[p+5] == 0x10 and
            bc[p+7] == 0x31 and
            bc[p+8] == 0xFE):
            idx = bc[p+1]
            key = bc[p+3]
            exp = bc[p+6]
            constraints.append((idx, key, exp))

    if not constraints:
        print("No constraints found. Pattern not present or bytecode differs.")
        return

    max_idx = max(idx for idx, _, _ in constraints)
    flag = bytearray(max_idx + 1)

    for idx, key, exp in constraints:
        flag[idx] = key ^ exp
    print("len_constraints =", len(constraints))
    print("flag_bytes =", " ".join(f"{b:02x}" for b in flag))
    print(flag.decode(errors="replace"))

if __name__ == "__main__":
    main()
```

<details>
<summary><b>FLAG</b></summary>
    InfosecPTIT{y0u_H4ve_8Een_S0LVeD_My_cH4llEn9e_M1V1_vM_:3333}
</details>