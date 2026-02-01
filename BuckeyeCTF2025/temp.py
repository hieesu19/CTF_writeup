.data:0000000000005020 off_5020        dq offset sub_212F      	pop rax ; ret
.data:0000000000005028                 dq offset unk_5560	RAX = 0x5560
.data:0000000000005030                 dq offset sub_212D	pop rdx ; ret
.data:0000000000005038                 dq 7920732774616857h	RDX = "What's y"
.data:0000000000005040                 dq offset sub_2131	mov [rax], rdx ; ret	|| *(uint64_t*)0x5560 = "What's y"
.data:0000000000005048                 dq offset sub_212F	pop rax
.data:0000000000005050                 dq offset unk_5568	RAX = 0x5568
.data:0000000000005058                 dq offset sub_212D	pop rdx
.data:0000000000005060                 dq 6F7661662072756Fh	RDX = "our favo"
.data:0000000000005068                 dq offset sub_2131	store	|| write "our favo" tại 0x5568
.data:0000000000005070                 dq offset sub_212F	pop rax
.data:0000000000005078                 dq offset unk_5570	RAX = 0x5570
.data:0000000000005080                 dq offset sub_212D	pop rdx
.data:0000000000005088                 dq 6D756E2065746972h	RDX = "rite num"
.data:0000000000005090                 dq offset sub_2131	store	|| write "rite num" tại 0x5570
.data:0000000000005098                 dq offset sub_212F	pop rax
.data:00000000000050A0                 dq offset unk_5578	RAX = 0x5578
.data:00000000000050A8                 dq offset sub_212D	pop rdx
.data:00000000000050B0                 dq 443A203F726562h	RDX = "ber? :D\0" 
.data:00000000000050B8                 dq offset sub_2131	store	|| write phần cuối tại 0x5578 => unk_5560 cos string prompt đầy đủ
.data:00000000000050C0                 dq offset sub_2129	pop rdi; ret
.data:00000000000050C8                 dq offset unk_5560	RDI = prompt
.data:00000000000050D0                 dq offset sub_212F	pop rax; ret
.data:00000000000050D8                 dq 0			RAX = 0
.data:00000000000050E0                 dq offset nullsub_1	ret/stub (đệm alighment)
.data:00000000000050E8                 dq offset puts		call puts(rdi) => in string
.data:00000000000050F0                 dq offset sub_2129	pop rdi
.data:00000000000050F8                 dq 0			rdi =0
.data:0000000000005100                 dq offset sub_212B	pop rsi
.data:0000000000005108                 dq offset unk_5540	rsi = buf
.data:0000000000005110                 dq offset sub_212D	pop rdx
.data:0000000000005118                 dq 10h			rdx = 16
.data:0000000000005120                 dq offset read		call read(0,buf,16)
.data:0000000000005128                 dq offset sub_2129	pop rdi
.data:0000000000005130                 dq offset unk_5540	rdi = buf
.data:0000000000005138                 dq offset sub_212B	pop rsi
.data:0000000000005140                 dq 0Ah			rsi = '\n'
.data:0000000000005148                 dq offset strchr		rax = strchr(buf,'\n')
.data:0000000000005150                 dq offset sub_212D	pop rdx
.data:0000000000005158                 dq 0			rdx = 0
.data:0000000000005160                 dq offset byte_2139+4	rax == 0 thì skip store | rax != 0 thì chạy tiếp
.data:0000000000005168                 dq offset sub_2131	*rax =0 
.data:0000000000005170                 dq offset nullsub_1	ret/stub
.data:0000000000005178                 dq offset sub_212F	pop rax
.data:0000000000005180                 dq offset unk_5560	rax = expected_ptr
.data:0000000000005188                 dq offset sub_212D	pop rdx
.data:0000000000005190                 dq 5CE8A297FA50CC11h	rdx = expected0
.data:0000000000005198                 dq offset sub_2131	*(uint64_t*)unk_5560 = expected0
.data:00000000000051A0                 dq offset sub_212F	pop rax
.data:00000000000051A8                 dq offset unk_5540	rax = &buf[0]
.data:00000000000051B0                 dq offset sub_212B	pop rsi
.data:00000000000051B8                 dq 25BCCCA48C35FD54h	rsi = key0
.data:00000000000051C0                 dq offset byte_2139	xor [rax], rsi ; ret || *(uint64_t*)buf ^= key0
.data:00000000000051C8                 dq offset sub_212F	pop rax
.data:00000000000051D0                 dq offset unk_5568       rax = expected_ptr+8
.data:00000000000051D8                 dq offset sub_212D	pop rdx
.data:00000000000051E0                 dq 6E8EEA35727Dh		rdx = expected1
.data:00000000000051E8                 dq offset sub_2131	store => *(uint64_t*)unk_5568 = expected1
.data:00000000000051F0                 dq offset sub_212F	pop rax
.data:00000000000051F8                 dq offset unk_5548	rax = &buf[8]
.data:0000000000005200                 dq offset sub_212B	pop rsi
.data:0000000000005208                 dq 20EB9C06215Dh		rsi = key1
.data:0000000000005210                 dq offset byte_2139	xor [rax], rsi ||  *(uint64_t*)(buf+8) ^= key1
.data:0000000000005218                 dq offset sub_2129	pop rdi
.data:0000000000005220                 dq offset unk_5560	rdi = expected
.data:0000000000005228                 dq offset sub_212B	pop rsi
.data:0000000000005230                 dq offset unk_5540	rsi - buf(đã xor)
.data:0000000000005238                 dq offset strcmp		RAX = strcmp(expected, buf)
.data:0000000000005240                 dq offset sub_2147	test rax, rax; jnz nullsub_1; add rsp, 0x1a0; ret || rax != 0 nhảy nullsub_1, fail; rax == 0 thì add rsp, 0x1a0, nhảy 52 qword trên stack 
.data:0000000000005248                 dq offset sub_212F	pop rax ; ret
.data:0000000000005250                 dq offset unk_5540	RAX = buf
.data:0000000000005258                 dq offset sub_212B	pop rsi ; ret
.data:0000000000005260                 dq 25BCCCA48C35FD54h	RSI = key0
.data:0000000000005268                 dq offset byte_2139	xor qword ptr [rax], rsi ; ret ||    *(uint64_t*)buf ^= key0
.data:0000000000005270                 dq offset sub_212F	pop rax ; ret
.data:0000000000005278                 dq offset unk_5548	RAX = buf+8
.data:0000000000005280                 dq offset sub_212B	pop rsi ; ret
.data:0000000000005288                 dq 20EB9C06215Dh		RSI = key1
.data:0000000000005290                 dq offset byte_2139	xor qword ptr [rax], rsi ; ret	|| *(uint64_t*)(buf+8) ^= key1
.data:0000000000005298                 dq offset sub_212F	pop rax ; ret	
.data:00000000000052A0                 dq offset unk_5560	RAX = scratch0
.data:00000000000052A8                 dq offset sub_212D	pop rdx ; ret
.data:00000000000052B0                 dq 61662061202C6841h	RDX = bytes("Ah, a fa")
.data:00000000000052B8                 dq offset sub_2131	mov [rax], rdx ; ret || ghi "Ah, a fa" vào unk_5560
.data:00000000000052C0                 dq offset sub_212F	pop rax ; ret	
.data:00000000000052C8                 dq offset unk_5568	RAX = scratch1
.data:00000000000052D0                 dq offset sub_212D	pop rdx ; ret
.data:00000000000052D8                 dq 73252220666F206Eh	RDX = bytes("n of s%$")
.data:00000000000052E0                 dq offset sub_2131	unk_5568
.data:00000000000052E8                 dq offset sub_212F	pop rax ; ret
.data:00000000000052F0                 dq offset unk_5570	RAX = scratch2
.data:00000000000052F8                 dq offset sub_212D	pop rdx ; ret
.data:0000000000005300                 dq 0A2E2E2E22h		RDX = bytes("\"...\n\0\0\0")
.data:0000000000005308                 dq offset sub_2131	store vào unk_5570 || Lúc này unk_5560 chứa một format string (dạng kiểu "Ah, a ... %s ...\n"), và ta sẽ printf nó với đối số là input
.data:0000000000005310                 dq offset sub_2129	pop rdi ; ret
.data:0000000000005318                 dq offset unk_5560	RDI = fmt
.data:0000000000005320                 dq offset sub_212B	pop rsi ; ret
.data:0000000000005328                 dq offset unk_5540	RSI = buf (đối số thứ 2 cho printf)
.data:0000000000005330                 dq offset sub_212F	pop rax ; ret
.data:0000000000005338                 dq 0			RAX = 0
.data:0000000000005340                 dq offset nullsub_1	ret/align đệm
.data:0000000000005348                 dq offset printf		call printf(fmt, buf)
.data:0000000000005350                 dq offset sub_2129	pop rdi ; ret
.data:0000000000005358                 dq 1			rdi = 1
.data:0000000000005360                 dq offset sleep		sleep(1)
.data:0000000000005368                 dq offset sub_212F	pop rax ; ret		
.data:0000000000005370                 dq offset unk_5560	RAX = scratch0
.data:0000000000005378                 dq offset sub_212D	pop rdx ; ret
.data:0000000000005380                 dq 2E657962646F6F47h	RDX = bytes("Goodbye.")
.data:0000000000005388                 dq offset sub_2131	store vào unk_5560
.data:0000000000005390                 dq offset sub_212F	pop rax ; ret
.data:0000000000005398                 dq offset unk_5568	RAX = scratch1
.data:00000000000053A0                 dq offset sub_212D	pop rdx ; ret
.data:00000000000053A8                 dq 0Ah			RDX = "\n"
.data:00000000000053B0                 dq offset sub_2131	store newline
.data:00000000000053B8                 dq offset sub_2129	pop rdi ; ret
.data:00000000000053C0                 dq offset unk_5560	RDI = fmt (string “Goodbye...\n”)
.data:00000000000053C8                 dq offset printf		printf("Goodbye...\n")
.data:00000000000053D0                 dq offset sub_2129	pop rdi ; ret
.data:00000000000053D8                 dq 0			RDI = 0
.data:00000000000053E0                 dq offset exit		exit(0)
.data:00000000000053E8                 dq offset sub_212B	pop rsi ; ret	
.data:00000000000053F0                 dq offset unk_5540	RSI = &buf[0]
.data:00000000000053F8                 dq offset sub_2135	mov rsi, qword ptr [rsi] ; ret || RSI = *(uint64_t*)buf || hay chính là expected0, làm key giải mã
.data:0000000000005400                 dq offset sub_212F	pop rax ; ret	
.data:0000000000005408                 dq offset unk_5560	RAX = flag_buf[0]
.data:0000000000005410                 dq offset sub_212D	pop rdx ; ret
.data:0000000000005418                 dq 6880F6EC9C24AF73h	RDX = enc0
.data:0000000000005420                 dq offset sub_2131	store enc0 vào unk_5560
.data:0000000000005428                 dq offset byte_2139	xor [rax], rsi || *(uint64_t*)unk_5560 ^= key || plaintext 8 byte đầu của flag
.data:0000000000005430                 dq offset sub_212F	pop rax
.data:0000000000005438                 dq offset unk_5568	RAX = flag_buf[8]
.data:0000000000005440                 dq offset sub_212D	pop rdx
.data:0000000000005448                 dq 1FD9CCC89B0FF965h	RDX = enc1
.data:0000000000005450                 dq offset sub_2131	ghi enc1
.data:0000000000005458                 dq offset byte_2139	decrypt qword1
.data:0000000000005460                 dq offset sub_212F	pop rax
.data:0000000000005468                 dq offset unk_5570	RAX = flag_buf[16]
.data:0000000000005470                 dq offset sub_212D	pop rdx
.data:0000000000005478                 dq 2EDBE0DA8F1E9322h	RDX = enc2
.data:0000000000005480                 dq offset sub_2131	store
.data:0000000000005488                 dq offset byte_2139	decrypt qword2
.data:0000000000005490                 dq offset sub_212F	pop rax
.data:0000000000005498                 dq offset unk_5578	RAX = flag_buf[24]
.data:00000000000054A0                 dq offset sub_212D	pop rdx
.data:00000000000054A8                 dq 6Ch			RDX = 0x6C
.data:00000000000054B0                 dq offset sub_2131	*(uint64_t*)unk_5578 = 0x6C
.data:00000000000054B8                 dq offset sub_212B	pop rsi
.data:00000000000054C0                 dq 11h			RSI = 0x11
.data:00000000000054C8                 dq offset byte_2139	xor [rax], rsi	|| 0x6C ^ 0x11 = 0x7D = '}'
.data:00000000000054D0                 dq offset sub_2129	pop rdi
.data:00000000000054D8                 dq offset unk_5560	RDI = flag_string	
.data:00000000000054E0                 dq offset sub_212F	pop rax
.data:00000000000054E8                 dq 0			RAX = 0
.data:00000000000054F0                 dq offset nullsub_1	ret/align	
.data:00000000000054F8                 dq offset puts		puts(flag)
.data:0000000000005500                 dq offset sub_2129	pop rdi
.data:0000000000005508                 dq 0			rdi =0
.data:0000000000005510                 dq offset exit		exit(0)
.data:0000000000005510 _data           ends
.data:0000000000005510