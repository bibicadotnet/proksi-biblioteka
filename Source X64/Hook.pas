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

  OLDCODE710 : packed record            // Структура для формирования функции-моста UpdateProcThreadAttribute
  DATA        : array [0..20] of byte;  // Массив для храния начального кода перехватываемой функции 21 байт
  JMPOP       : array [0..2] of Word;   // Опкод инструкции  Jmp qword ptr              | FF 25 00 00 00 00
  JMPARG      : POINTER;                // Поле для записи аргумента инструкции Jmp     | QWORD $11 22 33 44 55 66 77 88
  end;

  OLDCODE11 : packed record             // Структура для формирования функции-моста UpdateProcThreadAttribute
  DATA        : array [0..19] of byte;  // Массив для храния начального кода перехватываемой функции 20 байт
  JMPOP       : array [0..2] of Word;   // Опкод инструкции  Jmp qword ptr              | FF 25 00 00 00 00
  JMPARG      : POINTER;                // Поле для записи аргумента инструкции Jmp     | QWORD $11 22 33 44 55 66 77 88
  end;

  KEYCODE   : packed record             // Структура для формирования функции-моста NtCreateKey
  DATA      : array [0..23] of byte;    // Массив для храния начального кода перехватываемой функции 11 байт XP и 7 или 24 байта 10 и 11
  end;

  OS   : Byte;
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
    if not VirtualProtect(ADDR(OLDCODE710), 35, PAGE_EXECUTE_READWRITE, Protect) then exit;
    // Схранить начало исходной функци в структуру OLDCODE. Целое число инструкций занимает 15 байт.
    ReadProcessMemory(HANDLE, ADDR(Proc), ADDR(OLDCODE710), 21, VALUE);
    // Формирование кода прыжка для возврата. Расчитать смещение и записать его значение в поле структуры
    OLDCODE710.JMPOP[0] := $25FF;
    OLDCODE710.JMPOP[1] := $0000;
    OLDCODE710.JMPOP[2] := $0000;
    OLDCODE710.JMPARG := Pointer(UInt64(OldProcAddress) + 21);
  end;

  if (OPT = 2) and (OS = 3) then  // Это для создание моста при перехвате UpdateProcThreadAttribute  WIN11
  begin
    // Изменить параметры доступа к памяти где расположена структура OLDCODE
    if not VirtualProtect(ADDR(OLDCODE11), 34, PAGE_EXECUTE_READWRITE, Protect) then exit;
    // Схранить начало исходной функци в структуру OLDCODE. Целое число инструкций занимает 15 байт.
    ReadProcessMemory(HANDLE, ADDR(Proc), ADDR(OLDCODE11), 20, VALUE);
    // Формирование кода прыжка для возврата. Расчитать смещение и записать его значение в поле структуры
    OLDCODE11.JMPOP[0] := $25FF;
    OLDCODE11.JMPOP[1] := $0000;
    OLDCODE11.JMPOP[2] := $0000;
    OLDCODE11.JMPARG := Pointer(UInt64(OldProcAddress) + 20);
  end;

  if OPT = 3 then  // Это для создание моста при перехвате NtCreateKey
  begin
    // Изменить параметры доступа к памяти где расположена структура KEYCODE
    if not VirtualProtect(ADDR(KEYCODE), 24, PAGE_EXECUTE_READWRITE, Protect) then exit;
    // Схранить исходную функци в структуру KEYCODE
    ReadProcessMemory(HANDLE, ADDR(Proc), ADDR(KEYCODE), 24, VALUE);
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
