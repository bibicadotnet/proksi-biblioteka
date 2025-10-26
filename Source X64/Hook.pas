unit Hook;

interface

uses
  Windows;

  {$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}

type
  HOOKDATA = packed record              // Структура для хранения данных перехвата
  FUNCADDRES : POINTER;                 // Адрес исходной функции
  OLDDATA    : array [0..11] of byte;   // Массив для храния начального кода перехватываемой функции. 12 байт.
  NEWDATA    : array [0..11] of byte;   // Массив для храния кода прыжка в прокси функцию. 12 байт.
  end;

var
  OEPCODE : HOOKDATA;                  // Структурная переменная для формирования перхвата точки входа
  UPTCODE : HOOKDATA;                  // Структурная переменная для формирования перхвата UpdateProcThreadAttribute
  CRDCODE : HOOKDATA;                  // Структурная переменная для формирования перхвата CreateDirectoryW
  WSACODE : HOOKDATA;                  // Структурная переменная для формирования перхвата WSASend
  KEYCODE : HOOKDATA;                  // Структурная переменная для формирования перхвата NtCreateKey
  SSOCODE : HOOKDATA;                  // Структурная переменная для формирования перхвата Setsockopt

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

  Protect : DWORD;                     // Переменная для хранения параметров доступа к странице памяти
  VALUE   : SIZE_T;                    // Переменная для функции WriteProcessMemory

const
  HANDLE = THandle(-1);

begin

  if OPT = 1 then  // Это для перехвата точки входа
  begin
    // Сохранить адрес функции
    OEPCODE.FUNCADDRES := OldProcAddress;
    // Схранить начало исходной функци в структуру OEPCODE. Размер 12 байт.
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(OEPCODE.OLDDATA), 12, VALUE);
  end;

  if OPT = 2 then  // Это для создания перехвата UpdateProcThreadAttribute WIN7-11
  begin
    // Сохранить адрес функции
    UPTCODE.FUNCADDRES := OldProcAddress;
    // Схранить начало исходной функци в структуру UPTCODE. Размер 12 байт.
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(UPTCODE.OLDDATA), 12, VALUE);
  end;

  if OPT = 3 then  // Это для создания перехвата NtCreateKey
  begin
    // Сохранить адрес функции
    KEYCODE.FUNCADDRES := OldProcAddress;
    // Схранить начало исходной функци в структуру KEYCODE. Размер 12 байт.
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(KEYCODE.OLDDATA), 12, VALUE);
  end;

  if OPT = 4 then  // Это для создание перехвата CreateDirectoryW WIN XP - 11
  begin
    // Сохранить адрес функции
    CRDCODE.FUNCADDRES := OldProcAddress;
    // Схранить начало исходной функци в структуру CRDCODE
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(CRDCODE.OLDDATA), 12, VALUE);
  end;

  if OPT = 5 then  // Это для создания перехвата WSASend  WIN XP-11
  begin
    // Сохранить адрес функции
    WSACODE.FUNCADDRES := OldProcAddress;
    // Схранить начало исходной функци в структуру WSACODE
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(WSACODE.OLDDATA), 12, VALUE);
  end;

  if OPT = 6 then // Это для перехвата setsockopt
  begin
    // Сохранить адрес функции в структуру
    SSOCODE.FUNCADDRES := OldProcAddress;
    // Схранить начало исходной функци в структуру SSOCODE
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(SSOCODE.OLDDATA), 12, VALUE);
  end;

  if OPT = 7 then  // Это для перехвата getaddrinfo
  begin
    // Сохранить адрес функции в структуру
    GAICODE.FUNCADDRES := OldProcAddress;
    // Схранить начало исходной функци в структуру GAICODE
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(GAICODE.OLDDATA), 12, VALUE);
  end;

  // Формирование кода прыжка в прокси функцию в теле исходной функции методом mov rax,addr jmp rax (12 байт)
  RAXJUMP.MOVRRAXOP := $B848;
  RAXJUMP.MOVRRAXARG := NewProcAddress;
  RAXJUMP.JMPRAXOP := $E0FF;

  // Записать код прыжка в структуру
  if OPT = 1 then Move(RAXJUMP, OEPCODE.NEWDATA, 12);
  if OPT = 2 then Move(RAXJUMP, UPTCODE.NEWDATA, 12);
  if OPT = 3 then Move(RAXJUMP, KEYCODE.NEWDATA, 12);
  if OPT = 4 then Move(RAXJUMP, CRDCODE.NEWDATA, 12);
  if OPT = 5 then Move(RAXJUMP, WSACODE.NEWDATA, 12);
  if OPT = 6 then Move(RAXJUMP, SSOCODE.NEWDATA, 12);
  if OPT = 7 then Move(RAXJUMP, GAICODE.NEWDATA, 12);

  // Изменить параметры доступа к области памяти
  if not VirtualProtect(OldProcAddress, 12, PAGE_EXECUTE_READWRITE, ADDR(Protect)) then exit;
  // Записать в тело функции в памяти процесса код прыжка в прокси функцию
  // HANDLE := GetCurrentProcess; // Определить идентификатор текущего процесса
  WriteProcessMemory(HANDLE, OldProcAddress, ADDR(RAXJUMP), 12, VALUE);
  // Восстановить прежние параметры доступа к памяти
  VirtualProtect(OldProcAddress, 12, Protect, ADDR(Protect));
end;

// Включить или Отключить перхват
procedure SetHook(HOOK: HOOKDATA; OPT: byte);
var
  Protect : DWORD;                      // Переменная для хранения параметров доступа к странице памяти
  VALUE   : SIZE_T;                     // Переменная для функции WriteProcessMemory
const
  HANDLE = THandle(-1);
begin
  // Изменить параметры доступа к памяти где расположена функция
  if not VirtualProtect(HOOK.FUNCADDRES, 12, PAGE_EXECUTE_READWRITE, ADDR(Protect)) then exit;
  // Записать в память где расположена функция исходный код
  if OPT = 0 then WriteProcessMemory(HANDLE, HOOK.FUNCADDRES, ADDR(HOOK.OLDDATA), 12, VALUE);
  // Записать в память где расположена функция код прыжка
  if OPT = 1 then WriteProcessMemory(HANDLE, HOOK.FUNCADDRES, ADDR(HOOK.NEWDATA), 12, VALUE);
  // Восстановить прежние параметры доступа к памяти
  VirtualProtect(HOOK.FUNCADDRES, 12, Protect, ADDR(Protect));
end;

end.