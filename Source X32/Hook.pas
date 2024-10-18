unit Hook;

interface

uses
  Windows;

{$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}

procedure CodeHook(OldProcAddress, NewProcAddress: pointer; OPT : byte = 0);
function  CODEOFFSET(NEWADDR, OLDADDR: DWORD): DWORD;

type
  HOOKDATA = packed record              // Структура для хранения данных перехвата
  FUNCADDRES : pointer;                 // Адрес исходной функции
  OLDDATA      : array [0..4] of byte;  // Массив для храния начального кода перехватываемой функции. 5 байт.
  NEWDATA      : array [0..4] of byte;  // Массив для храния кода прыжка в прокси функцию. 5 байт.
  end;

procedure SetHook(HOOK: HOOKDATA; OPT: byte);

type
  CODEJPM = packed record              // Структура для формирования функции-моста
  DATA        : array [0..4] of byte;  // Массив для храния начального кода перехватываемой функции. В 32-х битной ОС это 5 байт.
  JMP         : Byte;                  // Поле для записи опкода инструкции JMP     | $E9
  JMPOFFSET   : DWORD;                 // Поле для записи аргумента инструкции JMP  | DWORD
  end;

var
  EPCODE : packed record               // Структура для формирования функции-моста точки входа
  CALL        : Byte;                  // Поле для записи опкода инструкции CALL    | $E8
  CALLOFFSET  : DWORD;                 // Поле для записи аргумента инструкции CALL | DWORD
  JMP         : Byte;                  // Поле для записи опкода инструкции JMP     | $E9
  JMPOFFSET   : DWORD;                 // Поле для записи аргумента инструкции JMP  | DWORD
  end;

  UPTCODE : CODEJPM;                   // Для формирования функции-моста UpdateProcThreadAttribute
  KEYCODE : CODEJPM;                   // Для формирования функции-моста NtCreateKey
  WSACODE : CODEJPM;                   // Для формирования функции-моста WSASend

  CRDCODE : HOOKDATA;                  // Для формирования перхвата CreateDirectoryW

implementation

// Функция установливает перехват
procedure CodeHook(OldProcAddress, NewProcAddress: pointer; OPT : byte = 0);
var

  // структура для хранения кода прыжка пехвата методом JMP NEAR OFFSET
  CODE   : packed record
  JMP    : BYTE;                       // Поле для записи опкода инструкции JMP     | $E9
  OFFSET : DWORD;                      // Поле для записи аргумента инструкции JMP  | DWORD
  end;

  Protect : DWORD;                     // Переменная для хранения параметров доступа к странице памяти
  VALUE   : DWORD;                     // Переменная для функции WriteProcessMemory

const
  HANDLE = THandle(-1);
begin

  if OPT = 1 then  // Это для создание моста при перехвате точки входа
  begin
    // Изменить параметры доступа к памяти где расположена структура EPCODE
    if not VirtualProtect(ADDR(EPCODE), 10, PAGE_EXECUTE_READWRITE, ADDR(Protect)) then exit;
    // Схранить начало исходной функци точки входа в структуру EPCODE. Это инструкция CALL.
    ReadProcessMemory(HANDLE, OldProcAddress, Addr(EPCODE), 5, VALUE);
    // Расчитать новое смещение для инструкции CALL и записать его значение в поле структуры
    EPCODE.CALL := $E8;
    EPCODE.CALLOFFSET := EPCODE.CALLOFFSET + CODEOFFSET(DWORD(ADDR(EPCODE)), DWORD(OldProcAddress)) + 5;
    // Формирование кода прыжка для возврата. Расчитать смещение и записать его значение в поле структуры
    EPCODE.JMP  := $E9;
    EPCODE.JMPOFFSET := CODEOFFSET(DWORD(ADDR(EPCODE)), DWORD(OldProcAddress));
  end;

  if OPT = 2 then  // Это для создание моста при перехвате UpdateProcThreadAttribute
  begin
    // Изменить параметры доступа к памяти где расположена структура UPTCODE
    if not VirtualProtect(ADDR(UPTCODE), 10, PAGE_EXECUTE_READWRITE, ADDR(Protect)) then exit;
    // Схранить начало исходной функци в структуру UPTCODE
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(UPTCODE), 5, VALUE);
    // Формирование кода прыжка для возврата. Расчитать смещение и записать его значение в поле структуры
    UPTCODE.JMP := $E9;
    UPTCODE.JMPOFFSET := CODEOFFSET(DWORD(ADDR(UPTCODE)), DWORD(OldProcAddress));
  end;

  if OPT = 3 then  // Это для создание моста при перехвате NtCreateKey
  begin
    // Изменить параметры доступа к памяти где расположена структура KEYCODE
    if not VirtualProtect(ADDR(KEYCODE), 10, PAGE_EXECUTE_READWRITE, ADDR(Protect)) then exit;
    // Схранить начало исходной функци в структуру KEYCODE
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(KEYCODE), 5, VALUE);
    // Формирование кода прыжка для возврата. Расчитать смещение и записать его значение в поле структуры
    KEYCODE.JMP := $E9;
    KEYCODE.JMPOFFSET := CODEOFFSET(DWORD(ADDR(KEYCODE)), DWORD(OldProcAddress));
  end;

  if OPT = 4 then  // Это для перехвата CreateDirectoryW
  begin
    // Сохранить адрес функции
    CRDCODE.FUNCADDRES := OldProcAddress;
    // Схранить начало исходной функци в структуру CRDCODE
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(CRDCODE.OLDDATA), 5, VALUE);
  end;

  if OPT = 5 then  // Это для создание моста при перехвате WSASend
  begin
    // Изменить параметры доступа к памяти где расположена структура WSACODE
    if not VirtualProtect(ADDR(WSACODE), 10, PAGE_EXECUTE_READWRITE, ADDR(Protect)) then exit;
    // Схранить начало исходной функци в структуру WSACODE
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(WSACODE), 5, VALUE);
    // Формирование кода прыжка для возврата. Расчитать смещение и записать его значение в поле структуры
    WSACODE.JMP := $E9;
    WSACODE.JMPOFFSET := CODEOFFSET(DWORD(ADDR(WSACODE)), DWORD(OldProcAddress));
  end;

  // Формирование кода прыжка в прокси функцию в теле исходной функции
  CODE.JMP := $E9;
  CODE.OFFSET := DWORD (NewProcAddress) - DWORD (OldProcAddress) - 5;

  // Записать код прыжка в структуру 
  if OPT = 4 then  Move(CODE, CRDCODE.NEWDATA, 5);
  // Изменить параметры доступа к области памяти
  if not VirtualProtect(OldProcAddress, 5, PAGE_EXECUTE_READWRITE, ADDR(Protect)) then exit;
  // HANDLE := GetCurrentProcess; // Определить идентификатор текущего процесса
  // Когда HANDLE := -1 будет использоваться тпкущий процесс
  WriteProcessMemory(HANDLE, OldProcAddress, Addr(CODE), 5, VALUE);
  // Восстановить прежние параметры доступа к памяти
  VirtualProtect(OldProcAddress, 5, Protect, ADDR(Protect));
end;

// Функция расчета смещения
function CODEOFFSET(NEWADDR, OLDADDR: DWORD):DWORD;
begin
  if(OLDADDR < NEWADDR) then
    begin
      Result := NEWADDR - OLDADDR;
      Result := $FFFFFFFF - Result;
      Result := Result - 4;
    end
  else
    begin
      Result := OLDADDR - NEWADDR;
      Result := Result - 5;
    end;
end;

// Включить или Отключить перхват
procedure SetHook(HOOK: HOOKDATA; OPT: byte);
var
  Protect : DWORD;                     // Переменная для хранения параметров доступа к странице памяти
  VALUE   : DWORD;                     // Переменная для функции WriteProcessMemory
const
  HANDLE = THandle(-1);
begin
  // Изменить параметры доступа к памяти где расположена функция
  if not VirtualProtect(HOOK.FUNCADDRES, 5, PAGE_EXECUTE_READWRITE, ADDR(Protect)) then exit;
  // Записать в память где расположена функция исходный код или код прыжка
  if OPT = 0 then WriteProcessMemory(HANDLE, HOOK.FUNCADDRES, ADDR(HOOK.OLDDATA), 5, VALUE);
  if OPT = 1 then WriteProcessMemory(HANDLE, HOOK.FUNCADDRES, ADDR(HOOK.NEWDATA), 5, VALUE);
  // Восстановить прежние параметры доступа к памяти
  VirtualProtect(HOOK.FUNCADDRES, 5, Protect, ADDR(Protect));
end;

end.