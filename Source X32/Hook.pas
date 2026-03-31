unit Hook;

interface

uses
  SysTypFunc;

{$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}

type
  HOOKDATA = packed record              // Структура для хранения данных перехвата
  FUNCADDRES : pointer;                 // Адрес исходной функции
  OldDATA      : array [0..4] of byte;  // Массив для храния начального кода перехватываемой функции. 5 байт.
  NewDATA      : array [0..4] of byte;  // Массив для храния кода прыжка в прокси функцию. 5 байт.
  end;

var
  CMDCODE : HOOKDATA;                  // Для формирования перехвата GetCommandLineW
  KEYCODE : HOOKDATA;                  // Для формирования перехвата NtCreateKey
  UPTCODE : HOOKDATA;                  // Для формирования перехвата UpdateProcThreadAttribute
  CRDCODE : HOOKDATA;                  // Для формирования перехвата CreateDirectoryW
  WSACODE : HOOKDATA;                  // Для формирования перехвата WSASend
  SSOCODE : HOOKDATA;                  // Для формирования перехвата setsockopt
  GAICODE : HOOKDATA;                  // Для формирования перехвата getaddrinfo
  PFPCODE : HOOKDATA;                  // Для формирования перехвата PSStringFromPropertyKey
  WSTCODE : HOOKDATA;                  // Для формирования перехвата WSASendTo

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

  Protect : LongWord;                  // Переменная для хранения параметров доступа к странице памяти
  VALUE   : LongWord;                  // Переменная для функции WriteProcessMemory

begin

  // Формирование кода прыжка в прокси функцию
  CODE.JMP := $E9;
  CODE.OFFSET := CodeOffset(DWORD(OldProcAddress), DWORD(NewProcAddress));

  if OPT = 1 then  // Это для перехвата GetCommandLineW
  begin
    CMDCODE.FUNCADDRES := OldProcAddress;                                       // Сохранить адрес функции в структуру
    CopyMemory(ADDR(CMDCODE.NewDATA), Addr(CODE), 5);                           // Сохранить код прыжка в структуру
    CopyMemory(ADDR(CMDCODE.OldDATA), OldProcAddress, 5);                       // Схранить начало исходной функци в структуру
  end;

  if OPT = 2 then  // Это для перехвата UpdateProcThreadAttribute
  begin
    UPTCODE.FUNCADDRES := OldProcAddress;                                       // Сохранить адрес функции в структуру
    CopyMemory(ADDR(UPTCODE.NewDATA), Addr(CODE), 5);                           // Сохранить код прыжка в структуру
    CopyMemory(ADDR(UPTCODE.OldDATA), OldProcAddress, 5);                       // Схранить начало исходной функци в структуру
  end;

  if OPT = 3 then  // Это для перехвата NtCreateKey
  begin
    KEYCODE.FUNCADDRES := OldProcAddress;                                       // Сохранить адрес функции в структуру
    CopyMemory(ADDR(KEYCODE.NewDATA), Addr(CODE), 5);                           // Сохранить код прыжка в структуру
    CopyMemory(ADDR(KEYCODE.OldDATA), OldProcAddress, 5);                       // Схранить начало исходной функци в структуру
  end;

  if OPT = 4 then  // Это для перехвата CreateDirectoryW
  begin
    CRDCODE.FUNCADDRES := OldProcAddress;                                       // Сохранить адрес функции в структуру
    CopyMemory(ADDR(CRDCODE.NewDATA), Addr(CODE), 5);                           // Сохранить код прыжка в структуру
    CopyMemory(ADDR(CRDCODE.OldDATA), OldProcAddress, 5);                       // Схранить начало исходной функци в структуру
  end;

  if OPT = 5 then  // Это для перехвата WSASend
  begin
    WSACODE.FUNCADDRES := OldProcAddress;                                       // Сохранить адрес функции в структуру
    CopyMemory(ADDR(WSACODE.NewDATA), Addr(CODE), 5);                           // Сохранить код прыжка в структуру
    CopyMemory(ADDR(WSACODE.OldDATA), OldProcAddress, 5);                       // Схранить начало исходной функци в структуру
  end;

  if OPT = 6 then  // Это для перехвата setsockopt
  begin
    SSOCODE.FUNCADDRES := OldProcAddress;                                       // Сохранить адрес функции в структуру
    CopyMemory(ADDR(SSOCODE.NewDATA), Addr(CODE), 5);                           // Сохранить код прыжка в структуру
    CopyMemory(ADDR(SSOCODE.OldDATA), OldProcAddress, 5);                       // Схранить начало исходной функци в структуру
  end;

  if OPT = 7 then  // Это для перехвата getaddrinfo
  begin
    GAICODE.FUNCADDRES := OldProcAddress;                                       // Сохранить адрес функции в структуру
    CopyMemory(ADDR(GAICODE.NewDATA), Addr(CODE), 5);                           // Сохранить код прыжка в структуру
    CopyMemory(ADDR(GAICODE.OldDATA), OldProcAddress, 5);                       // Схранить начало исходной функци в структуру
  end;

  if OPT = 8 then  // Это для перехвата PSStringFromPropertyKey
  begin
    PFPCODE.FUNCADDRES := OldProcAddress;                                       // Сохранить адрес функции в структуру
    CopyMemory(ADDR(PFPCODE.NewDATA), Addr(CODE), 5);                           // Сохранить код прыжка в структуру
    CopyMemory(ADDR(PFPCODE.OldDATA), OldProcAddress, 5);                       // Схранить начало исходной функци в структуру
  end;

  if OPT = 9 then  // Это для перехвата WSASendTo
  begin
    WSTCODE.FUNCADDRES := OldProcAddress;                                       // Сохранить адрес функции в структуру
    CopyMemory(ADDR(WSTCODE.NewDATA), Addr(CODE), 5);                           // Сохранить код прыжка в структуру
    CopyMemory(ADDR(WSTCODE.OldDATA), OldProcAddress, 5);                       // Схранить начало исходной функци в структуру
  end;
  
  // Изменить параметры доступа к области памяти
  if not VirtualProtect(OldProcAddress, 5, PAGE_EXECUTE_READWRITE, ADDR(Protect)) then exit;
  // Записать код прыжка в начало исходной функци
  WriteProcessMemory(INVALID_HANDLE_VALUE, OldProcAddress, Addr(CODE), 5, VALUE);
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
  Protect : LongWord;                  // Переменная для хранения параметров доступа к странице памяти
  VALUE   : LongWord;                   // Переменная для функции WriteProcessMemory
begin
  // Изменить параметры доступа к памяти где расположена функция
  if not VirtualProtect(HOOK.FUNCADDRES, 5, PAGE_EXECUTE_READWRITE, ADDR(Protect)) then exit;
  // Записать в память где расположена функция исходный код или код прыжка
  if OPT = 0 then WriteProcessMemory(INVALID_HANDLE_VALUE, HOOK.FUNCADDRES, Addr(HOOK.OldDATA), 5, VALUE); // Записать в память по адресу функции исходный код
  if OPT = 1 then WriteProcessMemory(INVALID_HANDLE_VALUE, HOOK.FUNCADDRES, Addr(HOOK.NewDATA), 5, VALUE); // Записать в память по адресу функции код прыжка
  // Восстановить прежние параметры доступа к памяти
  VirtualProtect(HOOK.FUNCADDRES, 5, Protect, ADDR(Protect));
end;

end.