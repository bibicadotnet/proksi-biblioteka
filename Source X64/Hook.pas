unit Hook;

interface

uses
  SysTypFunc;

  {$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}

type
  HOOKDATA = packed record              // Структура для хранения данных перехвата
  FUNCADDRES : POINTER;                 // Адрес исходной функции
  OLDDATA    : array [0..11] of byte;   // Массив для храния начального кода перехватываемой функции. 12 байт.
  NEWDATA    : array [0..11] of byte;   // Массив для храния кода прыжка в прокси функцию. 12 байт.
  end;

var
  CMDCODE : HOOKDATA;                  // Для формирования перехвата GetCommandLineW
  UPTCODE : HOOKDATA;                  // Для формирования перехвата UpdateProcThreadAttribute
  CRDCODE : HOOKDATA;                  // Для формирования перехвата CreateDirectoryW
  WSACODE : HOOKDATA;                  // Для формирования перехвата WSASend
  KEYCODE : HOOKDATA;                  // Для формирования перехвата NtCreateKey
  SSOCODE : HOOKDATA;                  // Для формирования перехвата Setsockopt
  GAICODE : HOOKDATA;                  // Для формирования перехвата getaddrinfo
  PFPCODE : HOOKDATA;                  // Для формирования перехвата PSStringFromPropertyKey
  WSTCODE : HOOKDATA;                  // Для формирования перехвата WSASendTo

procedure SetHook(HOOK: HOOKDATA; OPT: byte);
procedure CodeHook(OldProcAddress, NewProcAddress: pointer; OPT : byte = 0);

implementation

// Функция установливает перехват
procedure CodeHook(OldProcAddress, NewProcAddress: pointer; OPT : byte = 0);
var
  // структура для формирования кода прыжка в прокси функцию методом 1. mov rax,addr 2. jmp rax (12 байт)
  RAXJUMP    : packed record
  MOVRRAXOP  : WORD;                    // Поле для записи опкода инструкции MOV RAX    | 49 B8
  MOVRRAXARG : POINTER;                 // Поле для записи аргумента инструкции MOV RAX | QWORD $1122334455667788
  JMPRAXOP   : WORD;                    // Поле для записи опкода инструкции JMP RAX    | FF E0
  end;

  Protect : Cardinal;                   // Переменная для хранения параметров доступа к странице памяти
  VALUE   : NativeUInt;                 // Переменная для функции WriteProcessMemory

begin
  // Формирование кода прыжка в прокси функцию методом mov rax,addr jmp rax (12 байт)
  RAXJUMP.MOVRRAXOP := $B848;
  RAXJUMP.MOVRRAXARG := NewProcAddress;
  RAXJUMP.JMPRAXOP := $E0FF;

  if OPT = 1 then  // Это для перехвата GetCommandLineW
  begin
    CMDCODE.FUNCADDRES := OldProcAddress;                  // Сохранить адрес функции в структуру
    CopyMemory(ADDR(CMDCODE.NEWDATA), ADDR(RAXJUMP), 12);  // Сохранить код прыжка в структуру
    CopyMemory(ADDR(CMDCODE.OLDDATA), OldProcAddress, 12); // Схранить начало исходной функци в структуру CMDCODE. Размер 12 байт.
  end;

  if OPT = 2 then  // Это для создания перехвата UpdateProcThreadAttribute WIN7-11
  begin
    UPTCODE.FUNCADDRES := OldProcAddress;                  // Сохранить адрес функции в структуру
    CopyMemory(ADDR(UPTCODE.NEWDATA), ADDR(RAXJUMP), 12);  // Сохранить код прыжка в структуру
    CopyMemory(ADDR(UPTCODE.OLDDATA), OldProcAddress, 12); // Схранить начало исходной функци в структуру UPTCODE. Размер 12 байт.
  end;

  if OPT = 3 then  // Это для создания перехвата NtCreateKey
  begin
    KEYCODE.FUNCADDRES := OldProcAddress;                  // Сохранить адрес функции в структуру
    CopyMemory(ADDR(KEYCODE.NEWDATA), ADDR(RAXJUMP), 12);  // Сохранить код прыжка в структуру
    CopyMemory(ADDR(KEYCODE.OLDDATA), OldProcAddress, 12); // Схранить начало исходной функци в структуру KEYCODE. Размер 12 байт.
  end;

  if OPT = 4 then  // Это для создание перехвата CreateDirectoryW WIN XP - 11
  begin
    CRDCODE.FUNCADDRES := OldProcAddress;                  // Сохранить адрес функции в структуру
    CopyMemory(ADDR(CRDCODE.NEWDATA), ADDR(RAXJUMP), 12);  // Сохранить код прыжка в структуру
    CopyMemory(ADDR(CRDCODE.OLDDATA), OldProcAddress, 12); // Схранить начало исходной функци в структуру CRDCODE. Размер 12 байт.
  end;

  if OPT = 5 then  // Это для создания перехвата WSASend  WIN XP-11
  begin
    WSACODE.FUNCADDRES := OldProcAddress;                  // Сохранить адрес функции в структуру
    CopyMemory(ADDR(WSACODE.NEWDATA), ADDR(RAXJUMP), 12);  // Сохранить код прыжка в структуру
    CopyMemory(ADDR(WSACODE.OLDDATA), OldProcAddress, 12); // Схранить начало исходной функци в структуру WSACODE. Размер 12 байт.
  end;

  if OPT = 6 then // Это для перехвата setsockopt
  begin
    SSOCODE.FUNCADDRES := OldProcAddress;                  // Сохранить адрес функции в структуру
    CopyMemory(ADDR(SSOCODE.NEWDATA), ADDR(RAXJUMP), 12);  // Сохранить код прыжка в структуру
    CopyMemory(ADDR(SSOCODE.OLDDATA), OldProcAddress, 12); // Схранить начало исходной функци в структуру SSOCODE. Размер 12 байт.
  end;

  if OPT = 7 then  // Это для перехвата getaddrinfo
  begin
    GAICODE.FUNCADDRES := OldProcAddress;                  // Сохранить адрес функции в структуру
    CopyMemory(ADDR(GAICODE.NEWDATA), ADDR(RAXJUMP), 12);  // Сохранить код прыжка в структуру
    CopyMemory(ADDR(GAICODE.OLDDATA), OldProcAddress, 12); // Схранить начало исходной функци в структуру GAICODE. Размер 12 байт.
  end;

    if OPT = 8 then  // Это для перехвата PSStringFromPropertyKey
  begin
    PFPCODE.FUNCADDRES := OldProcAddress;                  // Сохранить адрес функции в структуру
    CopyMemory(ADDR(PFPCODE.NEWDATA), ADDR(RAXJUMP), 12);  // Сохранить код прыжка в структуру
    CopyMemory(ADDR(PFPCODE.OLDDATA), OldProcAddress, 12); // Схранить начало исходной функци в структуру PFPCODE. Размер 12 байт.
  end;

  if OPT = 9 then  // Это для перехвата WSASendTo
  begin
    WSTCODE.FUNCADDRES := OldProcAddress;                  // Сохранить адрес функции в структуру
    CopyMemory(ADDR(WSTCODE.NEWDATA), ADDR(RAXJUMP), 12);  // Сохранить код прыжка в структуру
    CopyMemory(ADDR(WSTCODE.OLDDATA), OldProcAddress, 12); // Схранить начало исходной функци в структуру WSTCODE. Размер 12 байт.
  end;

  // Изменить параметры доступа к области памяти
  if not VirtualProtect(OldProcAddress, 12, PAGE_EXECUTE_READWRITE, ADDR(Protect)) then exit;
  // Записать код прыжка в начало исходной функци
  WriteProcessMemory(INVALID_HANDLE_VALUE, OldProcAddress, ADDR(RAXJUMP), 12, VALUE);
  // Восстановить прежние параметры доступа к памяти
  VirtualProtect(OldProcAddress, 12, Protect, ADDR(Protect));
end;

// Включить или Отключить перхват
procedure SetHook(HOOK: HOOKDATA; OPT: byte);
var
  Protect : Cardinal;                      // Переменная для хранения параметров доступа к странице памяти
  VALUE   : NativeUInt;                    // Переменная для функции WriteProcessMemory
begin
  // Изменить параметры доступа к памяти где расположена функция
  if not VirtualProtect(HOOK.FUNCADDRES, 12, PAGE_EXECUTE_READWRITE, ADDR(Protect)) then exit;
  if OPT = 0 then WriteProcessMemory(INVALID_HANDLE_VALUE, HOOK.FUNCADDRES, ADDR(HOOK.OLDDATA), 12, VALUE); // Записать в память по адресу функции исходный код
  if OPT = 1 then WriteProcessMemory(INVALID_HANDLE_VALUE, HOOK.FUNCADDRES, ADDR(HOOK.NEWDATA), 12, VALUE); // Записать в память по адресу функции код прыжка
  // Восстановить прежние параметры доступа к памяти
  VirtualProtect(HOOK.FUNCADDRES, 12, Protect, ADDR(Protect));
end;

end.