unit Hook;

interface

uses
  Windows;

  {$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}

procedure CodeHook(OldProcAddress, NewProcAddress: pointer; OPT : byte = 0);

var

  EPCODE : packed record               // Структура для формирования функции-моста точки входа
  SUB         : DWORD;                 // Поле для записи опкода инструкции SUB        |
  MOVRRAXOP   : WORD;                  // Поле для записи опкода инструкции MOV RAX    | 49 B8
  MOVRRAXARG  : UINT64;                // Поле для записи аргумента инструкции MOV RAX | QWORD $1122334455667788
  CALLRAXOP   : WORD;                  // Поле для записи опкода инструкции CALL RAX   | FF D0
  ADD         : DWORD;                 // Поле для записи опкода инструкции ADD        |
  JMPOP       : array [0..2] of Word;  // Опкод инструкции  Jmp qword ptr              | FF 25 00 00 00 00
  JMPARG      : POINTER;               // Поле для записи аргумента инструкции Jmp     | QWORD $11 22 33 44 55 66 77 88
  end;

  UPTCODE710 : packed record            // Структура для формирования функции-моста UpdateProcThreadAttribute для 7 и 10
  DATA        : array [0..20] of byte;  // Массив для храния начального кода перехватываемой функции 21 байт
  JMPOP       : array [0..2] of Word;   // Опкод инструкции  Jmp qword ptr              | FF 25 00 00 00 00
  JMPARG      : POINTER;                // Поле для записи аргумента инструкции Jmp     | QWORD $11 22 33 44 55 66 77 88
  end;

  UPTCODE11 : packed record             // Структура для формирования функции-моста UpdateProcThreadAttribute для 11
  DATA        : array [0..19] of byte;  // Массив для храния начального кода перехватываемой функции 20 байт
  JMPOP       : array [0..2] of Word;   // Опкод инструкции  Jmp qword ptr              | FF 25 00 00 00 00
  JMPARG      : POINTER;                // Поле для записи аргумента инструкции Jmp     | QWORD $11 22 33 44 55 66 77 88
  end;

  KEYCODE   : packed record             // Структура для формирования функции-моста NtCreateKey
  DATA      : array [0..23] of byte;    // Массив для храния начального кода перехватываемой функции 11 байт XP и 7 или 24 байта 10 и 11
  end;

  CRDCODEXP  : packed record             // Структура для формирования функции-моста CreateDirectoryW в XP
  DATA       : array [0..17] of byte;    // Массив для храния начального кода перехватываемой функции 18 байт в XP
  JMPOP      : array [0..2] of Word;     // Опкод инструкции  Jmp qword ptr              | FF 25 00 00 00 00
  JMPARG     : POINTER;                  // Поле для записи аргумента инструкции Jmp     | QWORD $11 22 33 44 55 66 77 88
  end;

  CRDCODE710 : packed record             // Структура для формирования функции-моста CreateDirectoryW в 7 и 10
  DATA       : array [0..28] of byte;    // Массив для храния начального кода перехватываемой функции 29 байт в 7 и 10
  JMPOP      : array [0..2] of Word;     // Опкод инструкции  Jmp qword ptr              | FF 25 00 00 00 00
  JMPARG     : POINTER;                  // Поле для записи аргумента инструкции Jmp     | QWORD $11 22 33 44 55 66 77 88
  end;

  CRDCODE11 : packed record              // Структура для формирования функции-моста CreateDirectoryW в 11
  DATA      : array [0..25] of byte;     // Массив для храния начального кода перехватываемой функции 26 байт в 11
  JMPOP     : array [0..2] of Word;      // Опкод инструкции  Jmp qword ptr              | FF 25 00 00 00 00
  JMPARG    : POINTER;                   // Поле для записи аргумента инструкции Jmp     | QWORD $11 22 33 44 55 66 77 88
  end;

  OS   : Byte = 0;
  Proc : procedure;                    // Процедурная переменная

  implementation

// Функция установливает перехват
procedure CodeHook(OldProcAddress, NewProcAddress: pointer; OPT : byte = 0);
var

  OEP : packed record                  // структура для чтения исходного кода OEP
  SUB         : DWORD;                 // Поле для записи опкода инструкции SUB     |
  CALL        : BYTE;                  // Поле для записи опкода инструкции CALL    | $E8
  CALLOFFSET  : DWORD;                 // Поле для записи аргумента инструкции CALL | DWORD
  ADD         : DWORD;                 // Поле для записи опкода инструкции ADD     |
  end;

  // структура для формирования прыжка в прокси функцию методом 1. mov rax,addr 2. jmp rax (12 байт)
  RAXJUMP    : packed record
  MOVRRAXOP  : WORD;                    // Поле для записи опкода инструкции MOV RAX    | 49 B8
  MOVRRAXARG : POINTER;                 // Поле для записи аргумента инструкции MOV RAX | QWORD $1122334455667788
  JMPRAXOP   : WORD;                    // Поле для записи опкода инструкции JMP RAX    | FF E0
  end;

  Protect : DWORD;                     // Переменная для хранения параметров доступа к странице памяти
  VALUE   : SIZE_T;                    // Переменная для функции WriteProcessMemory
const
  HANDLE = THandle(-1);
begin

  if OPT = 1 then  // Это для создание моста при перехвате точки входа
  begin
    // Изменить параметры доступа к памяти где расположена структура EPCODE
    if not VirtualProtect(ADDR(EPCODE), 32, PAGE_EXECUTE_READWRITE, Protect) then exit;
    // Схранить начало исходной функци точки входа в структуру OEP. Это 3 инструкции подряд SUB CALL ADD.
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(OEP), 13, VALUE);
    // Заполнить структуру EPCODE. Расчитать смещение и записать его значение в поле структуры
    EPCODE.SUB := OEP.SUB;
    EPCODE.MOVRRAXOP := $B848;
    EPCODE.MOVRRAXARG := (UInt64(OldProcAddress) + UInt64(OEP.CALLOFFSET) + 9);
    EPCODE.CALLRAXOP := $D0FF;
    EPCODE.ADD := OEP.ADD;
    // Формирование кода прыжка для возврата. Расчитать смещение и записать его значение в поле структуры
    EPCODE.JMPOP[0] := $25FF;
    EPCODE.JMPOP[1] := $0000;
    EPCODE.JMPOP[2] := $0000;
    EPCODE.JMPARG := Pointer(UInt64(OldProcAddress) + 13);
  end;

  if (OPT = 2) and (OS = 2) then  // Это для создание моста при перехвате UpdateProcThreadAttribute WIN7-10
  begin
    // Изменить параметры доступа к памяти где расположена структура OLDCODE
    if not VirtualProtect(ADDR(UPTCODE710), 35, PAGE_EXECUTE_READWRITE, Protect) then exit;
    // Схранить начало исходной функци в структуру OLDCODE. Целое число инструкций занимает 21 байт.
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(UPTCODE710), 21, VALUE);
    // Формирование кода прыжка для возврата. Расчитать смещение и записать его значение в поле структуры
    UPTCODE710.JMPOP[0] := $25FF;
    UPTCODE710.JMPOP[1] := $0000;
    UPTCODE710.JMPOP[2] := $0000;
    UPTCODE710.JMPARG := Pointer(UInt64(OldProcAddress) + 21);
  end;

  if (OPT = 2) and (OS = 3) then  // Это для создание моста при перехвате UpdateProcThreadAttribute  WIN11
  begin
    // Изменить параметры доступа к памяти где расположена структура OLDCODE
    if not VirtualProtect(ADDR(UPTCODE11), 34, PAGE_EXECUTE_READWRITE, Protect) then exit;
    // Схранить начало исходной функци в структуру UPTCODE. Целое число инструкций занимает 20 байт.
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(UPTCODE11), 20, VALUE);
    // Формирование кода прыжка для возврата. Расчитать смещение и записать его значение в поле структуры
    UPTCODE11.JMPOP[0] := $25FF;
    UPTCODE11.JMPOP[1] := $0000;
    UPTCODE11.JMPOP[2] := $0000;
    UPTCODE11.JMPARG := Pointer(UInt64(OldProcAddress) + 20);
  end;

  if OPT = 3 then  // Это для создание моста при перехвате NtCreateKey
  begin
    // Изменить параметры доступа к памяти где расположена структура KEYCODE
    if not VirtualProtect(ADDR(KEYCODE), 24, PAGE_EXECUTE_READWRITE, Protect) then exit;
    // Схранить исходную функци в структуру KEYCODE
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(KEYCODE), 24, VALUE);
  end;

  if (OPT = 4) and (OS = 1) then  // Это для создание моста при перехвате CreateDirectoryW  WINXP
  begin
    // Изменить параметры доступа к памяти где расположена структура CRDCODE
    if not VirtualProtect(ADDR(CRDCODEXP), 32, PAGE_EXECUTE_READWRITE, Protect) then exit;
    // Схранить начало исходной функци в структуру CRDCODE. Целое число инструкций занимает 18 байт.
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(CRDCODEXP), 18, VALUE);
    // Формирование кода прыжка для возврата. Расчитать смещение и записать его значение в поле структуры
    CRDCODEXP.JMPOP[0] := $25FF;
    CRDCODEXP.JMPOP[1] := $0000;
    CRDCODEXP.JMPOP[2] := $0000;
    CRDCODEXP.JMPARG := Pointer(UInt64(OldProcAddress) + 18);
  end;

  if (OPT = 4) and (OS = 2) then  // Это для создание моста при перехвате CreateDirectoryW  WIN7-10
  begin
    // Изменить параметры доступа к памяти где расположена структура CRDCODE
    if not VirtualProtect(ADDR(CRDCODE710), 43, PAGE_EXECUTE_READWRITE, Protect) then exit;
    // Схранить начало исходной функци в структуру CRDCODE. Целое число инструкций занимает 29 байт.
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(CRDCODE710), 29, VALUE);
    // Формирование кода прыжка для возврата. Расчитать смещение и записать его значение в поле структуры
    CRDCODE710.JMPOP[0] := $25FF;
    CRDCODE710.JMPOP[1] := $0000;
    CRDCODE710.JMPOP[2] := $0000;
    CRDCODE710.JMPARG := Pointer(UInt64(OldProcAddress) + 29);
  end;

  if (OPT = 4) and (OS = 3) then  // Это для создание моста при перехвате CreateDirectoryW  WIN11
  begin
    // Изменить параметры доступа к памяти где расположена структура CRDCODE
    if not VirtualProtect(ADDR(CRDCODE11), 40, PAGE_EXECUTE_READWRITE, Protect) then exit;
    // Схранить начало исходной функци в структуру CRDCODE. Целое число инструкций занимает 26 байт.
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(CRDCODE11), 26, VALUE);
    // Формирование кода прыжка для возврата. Расчитать смещение и записать его значение в поле структуры
    CRDCODE11.JMPOP[0] := $25FF;
    CRDCODE11.JMPOP[1] := $0000;
    CRDCODE11.JMPOP[2] := $0000;
    CRDCODE11.JMPARG := Pointer(UInt64(OldProcAddress) + 26);
  end;

  // Формирование прыжка в прокси функцию в теле исходной функции методом mov rax,addr jmp rax (12 байт)
  RAXJUMP.MOVRRAXOP := $B848;
  RAXJUMP.MOVRRAXARG := NewProcAddress;
  RAXJUMP.JMPRAXOP := $E0FF;
  // Изменить параметры доступа к области памяти
  if not VirtualProtect(OldProcAddress, 12, PAGE_EXECUTE_READWRITE, Protect) then exit;
  // Записать в память процесса прыжок на прокси функцию
  // HANDLE := GetCurrentProcess; // Определить идентификатор текущего процесса
  // Вместо HANDLE можно вписать INVALID_HANDLE_VALUE - это идентификатор текущего процесса.
  WriteProcessMemory(HANDLE, OldProcAddress, ADDR(RAXJUMP), 12, VALUE);
  // Восстановить прежние параметры доступа к памяти
  VirtualProtect(OldProcAddress, 12, Protect, Protect);
end;

end.