unit Hook;

interface

uses
  Windows;

{$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}

type
  HOOKDATA = packed record              // Структура для хранения данных перехвата
  FUNCADDRES : pointer;                 // Адрес исходной функции
  OLDDATA      : array [0..4] of byte;  // Массив для храния начального кода перехватываемой функции. 5 байт.
  NEWDATA      : array [0..4] of byte;  // Массив для храния кода прыжка в прокси функцию. 5 байт.
  end;

var
  CMDCODE : HOOKDATA;                  // Для формирования перехвата GetCommandLineW
  KEYCODE : HOOKDATA;                  // Для формирования перехвата NtCreateKey
  UPTCODE : HOOKDATA;                  // Для формирования перехвата UpdateProcThreadAttribute
  CRDCODE : HOOKDATA;                  // Для формирования перехвата CreateDirectoryW
  WSACODE : HOOKDATA;                  // Для формирования перехвата WSASend
  SSOCODE : HOOKDATA;                  // Для формирования перехвата setsockopt
  GAICODE : HOOKDATA;                  // Для формирования перехвата getaddrinfo

procedure SetHook(HOOK: HOOKDATA; OPT: byte);
procedure CodeHook(OldProcAddress, NewProcAddress: pointer; OPT : byte = 0);
function  CodeOffset(NEWADDR, OLDADDR: DWORD): DWORD;

implementation

// Функция установливает перехват
procedure CodeHook(OldProcAddress, NewProcAddress: pointer; OPT : byte = 0);
var

  // структура для хранения кода прыжка перехвата методом JMP NEAR OFFSET
  CODE   : packed record
  JMP    : BYTE;                       // Поле для записи опкода инструкции JMP     | $E9
  OFFSET : DWORD;                      // Поле для записи аргумента инструкции JMP  | DWORD
  end;

  Protect : DWORD;                     // Переменная для хранения параметров доступа к странице памяти
  VALUE   : DWORD;                     // Переменная для функции WriteProcessMemory

const
  HANDLE = THandle(-1);
  
begin

  if OPT = 1 then  // Это для перехвата GetCommandLineW
  begin
    // Сохранить адрес функции в структуру
    CMDCODE.FUNCADDRES := OldProcAddress;
    // Схранить начало исходной функци в структуру CMDCODE
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(CMDCODE.OLDDATA), 5, VALUE);
  end;

  if OPT = 2 then  // Это для перехвата UpdateProcThreadAttribute
  begin
    // Сохранить адрес функции в структуру
    UPTCODE.FUNCADDRES := OldProcAddress;
    // Схранить начало исходной функци в структуру UPTCODE
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(UPTCODE.OLDDATA), 5, VALUE);
  end;

  if OPT = 3 then  // Это для перехвата NtCreateKey
  begin
    // Сохранить адрес функции в структуру
    KEYCODE.FUNCADDRES := OldProcAddress;
    // Схранить начало исходной функци в структуру KEYCODE
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(KEYCODE.OLDDATA), 5, VALUE);
  end;

  if OPT = 4 then  // Это для перехвата CreateDirectoryW
  begin
    // Сохранить адрес функции в структуру
    CRDCODE.FUNCADDRES := OldProcAddress;
    // Схранить начало исходной функци в структуру CRDCODE
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(CRDCODE.OLDDATA), 5, VALUE);
  end;

  if OPT = 5 then  // Это для перехвата WSASend
  begin
    // Сохранить адрес функции в структуру
    WSACODE.FUNCADDRES := OldProcAddress;
    // Схранить начало исходной функци в структуру WSACODE
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(WSACODE.OLDDATA), 5, VALUE);
  end;

  if OPT = 6 then  // Это для перехвата setsockopt
  begin
    // Сохранить адрес функции в структуру
    SSOCODE.FUNCADDRES := OldProcAddress;
    // Схранить начало исходной функци в структуру SSOCODE
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(SSOCODE.OLDDATA), 5, VALUE);
  end;

  if OPT = 7 then  // Это для перехвата getaddrinfo
  begin
    // Сохранить адрес функции в структуру
    GAICODE.FUNCADDRES := OldProcAddress;
    // Схранить начало исходной функци в структуру GAICODE
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(GAICODE.OLDDATA), 5, VALUE);
  end;

  // Формирование кода прыжка в прокси функцию в теле исходной функции
  CODE.JMP := $E9;
  CODE.OFFSET := DWORD (NewProcAddress) - DWORD (OldProcAddress) - 5;

  // Сохранить код прыжка в структуру
  if OPT = 1 then  Move(CODE, CMDCODE.NEWDATA, 5);
  if OPT = 2 then  Move(CODE, UPTCODE.NEWDATA, 5);
  if OPT = 3 then  Move(CODE, KEYCODE.NEWDATA, 5);
  if OPT = 4 then  Move(CODE, CRDCODE.NEWDATA, 5);
  if OPT = 5 then  Move(CODE, WSACODE.NEWDATA, 5);
  if OPT = 6 then  Move(CODE, SSOCODE.NEWDATA, 5);
  if OPT = 7 then  Move(CODE, GAICODE.NEWDATA, 5);

  // Изменить параметры доступа к области памяти
  if not VirtualProtect(OldProcAddress, 5, PAGE_EXECUTE_READWRITE, ADDR(Protect)) then exit;
  // HANDLE := GetCurrentProcess; // Определить идентификатор текущего процесса
  // Вместо HANDLE можно вписать INVALID_HANDLE_VALUE - это идентификатор текущего процесса.
  WriteProcessMemory(HANDLE, OldProcAddress, Addr(CODE), 5, VALUE);
  // Восстановить прежние параметры доступа к памяти
  VirtualProtect(OldProcAddress, 5, Protect, ADDR(Protect));
end;

// Функция расчета смещения
function CodeOffset(NEWADDR, OLDADDR: DWORD):DWORD;
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