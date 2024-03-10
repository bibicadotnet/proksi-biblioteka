unit Portable;

interface

uses
Windows,
Hook;

{$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}

procedure HookPreferences;
procedure HookLoader;
var REGOFF : boolean;          // Переменная для отключения записи в реестр

implementation

type
  // Объявление перечисляемого типа данных с именем COMPUTER_NAME_FORMAT
  COMPUTER_NAME_FORMAT = (ComputerNameNetBIOS, ComputerNameDnsHostname, ComputerNameDnsDomain, ComputerNameDnsFullyQualified,
                          ComputerNamePhysicalNetBIOS, ComputerNamePhysicalDnsHostname, ComputerNamePhysicalDnsDomain,
                          ComputerNamePhysicalDnsFullyQualified, ComputerNameMax);

  NTStatus = cardinal;

  // Структура для функции LdrLoadDll и NtCreateKey
  UNICODE_STRING = record
  Length :        Word ;           // размер строки в байтах без учета символа конца строки
  MaximumLength : Word ;           // размер памяти, выделенной для буфера
  Buffer :  WideString ;           // буффер - указатель на строку WideString (уникоде строка)
  end;
  PUNICODESTR = ^UNICODE_STRING;   // указатель на структуру

  // Структура для функции NtCreateKey
  ObjectAttributes = packed record
  Length: ULONG;
  RootDirectory: THandle;
  ObjectName: PUNICODESTR;
  Attributes: ULONG;
  SecurityDescriptor: Pointer;
  SecurityQualityOfService: Pointer;
  end;
  PObjectAttributes = ^ObjectAttributes;

  // Структура для описания входных и выходных данных
  DATA_BLOB = record
  cbData: DWORD;            // Размер данных в байтах
  pbData: pByte;            // Указатель на первый байт в блоке данных
  end;

  // Структура для описания дополнительных данных шифрования
  CRYPTPROTECT_PROMPTSTRUCT = record
  cbSize: DWORD;            // Размер этой структуры в байтах
  dwPromptFlags: DWORD;     // флаги, указывающие, когда должны отображаться приглашения в пользовательскую область
  hwndApp: HWND;            // Дескриптор окна для родительского окна.
  szPrompt: PWideChar;      // Строка, содержащая текст приглашения, которое должно быть отображено.
  end;

  // Обявление типа фукции с парамеи вызова и возврата соответующими оригинальной функции  UpdateProcThreadAttribute
  UpdProcThrAttr = function (lpAttributeList: Pointer; dwFlags: DWORD; Attribute: DWORD; lpValue: Pointer;
                             cbSize: integer; lpPreviousValue: PPointer; lpReturnSize: PInteger): INTEGER; stdcall;

  // Обявление типа фукции с парамеи вызова и возврата соответующими оригинальной функции  LoadDll
  LoadDll = function(PathToFile: PWideChar; Flags: DWORD; ModuleFileName: PUNICODESTR; ModuleHandle: PPointer):NTSTATUS; stdcall;

  // Обявление типа фукции с парамеи вызова и возврата соответующими оригинальной функции  NtCreateKey
  CreateKey= function(KeyHandle : PHANDLE; DesiredAccess : ACCESS_MASK; ObjectAttributes : PObjectAttributes; TitleIndex:ULONG;
                      ObjectClass : PUNICODESTR; CreateOptions:ULONG; Disposition:PULONG) : NTSTATUS; stdcall;

// Объявление константы с именем PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
// с типом данных DWORD и присвоение ей значения в соответствии с WinBase.h
const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = DWORD ($00020007);

var
  RawUpdateProcThreadAttribute : UpdProcThrAttr;
  RawLdrLoadDll : LoadDll;
  RawCreateKey  : CreateKey;

{
  Описание функций для подмены в системных библиотеках
  kernel32.dll (GetComputerName, GetVolumeInformation, UpdateProcThreadAttribute)
  Advapi32.dll (LogonUserA, LogonUserW)
  Crypt32.dll (CryptProtectData, CryptUnprotectData)
  ntdll.dll (NtCreateKey, LoadDll)
}

function GetComputerNameA(lpBuffer: PChar; var nSize: DWORD): INTEGER; stdcall;
begin
  result := 0;
end;

function GetComputerNameW(lpBuffer: PWideChar; var nSize: DWORD): INTEGER; stdcall;
begin
  result := 0;
end;

function GetComputerNameExA(NameType: COMPUTER_NAME_FORMAT; lpBuffer: PChar; var nSize: DWORD): INTEGER; stdcall;
begin
  result := 0;
end;

function GetComputerNameExW(NameType: COMPUTER_NAME_FORMAT; lpBuffer: PChar; var nSize: DWORD): INTEGER; stdcall;
begin
  result := 0;
end;

function GetVolumeInformationA
  (
   lpRootPathName: PChar;                                  // путь к сетевому или локальному тому
   lpVolumeNameBuffer: PChar;                              // буфер в котором будет храниться имя тома
   nVolumeNameSize: DWORD;                                 // размер буфера
   lpVolumeSerialNumber: PDWORD;                           // серийный номер тома
   var lpMaximumComponentLength, lpFileSystemFlags: DWORD; // размер тома и тип файловой системы
   lpFileSystemNameBuffer: PChar;                          // название файловой системы
   nFileSystemNameSize: DWORD                              // размер буфера под название файловой системы
  ): INTEGER; stdcall;
begin
  result := 0;
end;

function GetVolumeInformationW
  (
   lpRootPathName: PWideChar;                               // путь к сетевому или локальному тому
   lpVolumeNameBuffer: PWideChar;                           // буфер в котором будет храниться имя тома
   nVolumeNameSize: DWORD;                                  // размер буфера
   lpVolumeSerialNumber: PDWORD;                            // серийный номер тома
   var lpMaximumComponentLength, lpFileSystemFlags: DWORD;  // размер тома и тип файловой системы
   lpFileSystemNameBuffer: PWideChar;                       // название файловой системы
   nFileSystemNameSize: DWORD                               // размер буфера под название файловой системы
  ): INTEGER; stdcall;
begin
  result := 0;
end;

// Функция UpdateProcThreadAttribute модифирована чтобы сбрасывать бит PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
function UpdateProcThreadAttribute
  (
   lpAttributeList: Pointer;        // Указатель на список атрибутов
   dwFlags: DWORD;                  // Этот параметр зарезервирован и должен иметь значение 0
   Attribute: DWORD;                // Ключ атрибута для обновления в списке атрибутов
   lpValue: Pointer;                // Указатель на значение атрибута
   cbSize: Integer;                 // Размер значения атрибута, заданного параметром lpValue
   lpPreviousValue: PPointer;       // Этот параметр зарезервирован и должен иметь значение NULL
   lpReturnSize: PInteger           // Этот параметр зарезервирован и должен иметь значение NULL
  ): INTEGER; stdcall;
var
  Buffer : array of byte;
begin
  if (Attribute = PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY) and (cbSize >= sizeof(UInt64)) then
  begin
    SetLength(Buffer, cbSize);                     // Задать размер буфера
    CopyMemory(Addr(Buffer[0]), lpValue, cbSize);  // Скопировать в массив значение атрибута из адреса по указателю
    Buffer[5] := Buffer[5] and (0 shl 4);          // Сбросить бит MICROSOFT_BINARIES_ALWAYS_ON - это пятый бит шестого байта Int64 $100000000000
    CopyMemory(lpValue, Addr(Buffer[0]), cbSize);  // Скопировать в адрес по указателю значения из буфера
    Buffer := nil;                                 // Освободить память буфера
  end;
  result := RawUpdateProcThreadAttribute(lpAttributeList, dwFlags, Attribute, lpValue, cbSize, lpPreviousValue, lpReturnSize);
end;

function LogonUserA(lpszUsername, lpszDomain, lpszPassword: PAnsiChar; dwLogonType, dwLogonProvider: DWORD; var phToken: THandle): DWORD; stdcall;
begin
  phToken := $09051945;
  result := $09051945;
end;

function LogonUserW(lpszUsername, lpszDomain, lpszPassword: PWideChar; dwLogonType, dwLogonProvider: DWORD; var phToken: THandle): DWORD; stdcall;
begin
  phToken := $09051945;
  result := $09051945;
end;

// Модифицированная функция CryptProtectData. Входные данные передаются в выходные без шифрования.
function CryptProtectData  (
                            var pDataIn: DATA_BLOB;                       // указатель на структуру pDataIn типа DATA_BLOB с входными данными.
                            ppszDataDescr: PWideChar;                     // описание данных, этот параметр можно не задавать.
                            var pOptionalEntropy: DATA_BLOB;              // указатель на структуру pOptionalEntropy типа DATA_BLOB. исподбзуется для задания энтропии.
                            pvReserved: Pointer;                          // этот параметр зарезервирован и может не задаваться.
                            var pPromptStruct: CRYPTPROTECT_PROMPTSTRUCT; // указатель на структуру pPromptStruct типа CRYPTPROTECT_PROMPTSTRUCT для ввода доп. пароля для шифрования
                            dwFlags: DWORD;                               // флаги, управляющие процессом шифрования
                            var pDataOut: DATA_BLOB                       // указатель на структуру pDataOut типа DATA_BLOB с выходными данными
                            ): BOOL; stdcall;
var
  Buffer : array of byte;
begin
  pDataOut.cbData := pDataIn.cbData;                                      // Размер выходных данных равен размеру входных
  SetLength(Buffer, pDataIn.cbData);                                      // Задать размер буфера равным размеру входных данных
  CopyMemory(Addr(Buffer[0]), pDataIn.pbData, pDataIn.cbData);            // Скопировать в массив входные данные
  pDataOut.pbData := PBYTE(LocalAlloc(LMEM_FIXED, pDataIn.cbData));       // Выделить фиксированную память для блока выходных данных
  CopyMemory(pDataOut.pbData, Addr(Buffer[0]), pDataIn.cbData);           // Скопировать из массива в блок выходных данных
  Buffer := nil;                                                          // Освободить память буфера
  result := TRUE;
end;

// Модифицированная функция CryptUnprotectData. Входные данные передаются в выходные без дешифрования.
function CryptUnprotectData(
                            var pDataIn: DATA_BLOB;                       // указатель на структуру pDataIn типа DATA_BLOB с входными данными.
                            ppszDataDescr: PWideChar;                     // описание данных, этот параметр можно не задавать.
                            var pOptionalEntropy: DATA_BLOB;              // указатель на структуру pOptionalEntropy типа DATA_BLOB. исподбзуется для задания энтропии.
                            pvReserved: Pointer;                          // этот параметр зарезервирован и может не задаваться.
                            var pPromptStruct: CRYPTPROTECT_PROMPTSTRUCT; // указатель на структуру pPromptStruct типа CRYPTPROTECT_PROMPTSTRUCT для ввода доп. пароля для шифрования
                            dwFlags: DWORD;                               // флаги, управляющие процессом шифрования
                            var pDataOut: DATA_BLOB                       // указатель на структуру pDataOut типа DATA_BLOB с выходными данными
                            ): BOOL; stdcall;
var
  Buffer : array of byte;
begin
  pDataOut.cbData := pDataIn.cbData;                                      // Размер выходных данных равен размеру входных
  SetLength(Buffer, pDataOut.cbData);                                     // Задать размер буфера равным размеру входных данных
  CopyMemory(Addr(Buffer[0]), pDataIn.pbData, pDataIn.cbData);            // Скопировать в массив входные данные
  pDataOut.pbData := PBYTE(LocalAlloc(LMEM_FIXED, pDataIn.cbData));       // Выделить фиксированную память для блока выходных данных
  CopyMemory(pDataOut.pbData, Addr(Buffer[0]), pDataIn.cbData);           // Скопировать из массива в блок выходных данных
  Buffer := nil;                                                          // Освободить память буфера
  result := TRUE;
end;

function RegCreateKeyA(hKey: HKEY; lpSubKey: PAnsiChar; var phkResult: HKEY): Longint; stdcall;
begin
  phkResult := 0;
  Result := 0;
end;

function RegCreateKeyW(hKey: HKEY; lpSubKey: PWideChar; var phkResult: HKEY): Longint; stdcall;
begin
  phkResult := 0;
  Result := 0;
end;

function RegCreateKeyExA(hKey: HKEY; lpSubKey: PAnsiChar; Reserved: DWORD; lpClass: PAnsiChar; dwOptions: DWORD; samDesired: REGSAM;
                         lpSecurityAttributes: PSecurityAttributes; var phkResult: HKEY; lpdwDisposition: PDWORD): Longint; stdcall;
begin
  phkResult := 0;
  lpdwDisposition := nil;
  Result := 0;
end;

function RegCreateKeyExW(hKey: HKEY; lpSubKey: PWideChar; Reserved: DWORD; lpClass: PWideChar; dwOptions: DWORD; samDesired: REGSAM;
                         lpSecurityAttributes: PSecurityAttributes; var phkResult: HKEY; lpdwDisposition: PDWORD): Longint; stdcall;
begin
  phkResult := 0;
  lpdwDisposition := nil;
  Result := 0;
end;

function RegSetValueA(hKey: HKEY; lpSubKey: PAnsiChar; dwType: DWORD; lpData: PAnsiChar; cbData: DWORD): Longint; stdcall;
begin
  Result := 0;
end;

function RegSetValueW(hKey: HKEY; lpSubKey: PWideChar; dwType: DWORD; lpData: PWideChar; cbData: DWORD): Longint; stdcall;
begin
  Result := 0;
end;

function RegSetValueExA(hKey: HKEY; lpValueName: PAnsiChar; Reserved: DWORD; dwType: DWORD; lpData: Pointer; cbData: DWORD): Longint; stdcall;
begin
  Result := 0;
end;

function RegSetValueExW(hKey: HKEY; lpValueName: PWideChar; Reserved: DWORD; dwType: DWORD; lpData: Pointer; cbData: DWORD): Longint; stdcall;
begin
  Result := 0;
end;

function RegCreateKeyTransactedA(
                                 hKey: HKEY; lpSubKey: PAnsiChar;
                                 Reserved: DWORD; lpClass: PAnsiChar;
                                 dwOptions: DWORD; samDesired: REGSAM;
                                 lpSecurityAttributes: PSecurityAttributes;
                                 var phkResult: HKEY; lpdwDisposition: PDWORD;
                                 hTransaction: DWORD; pExtendedParemeter: Pointer
                                 ): Longint; stdcall;
begin
  phkResult := 0;
  lpdwDisposition := nil;
  Result := 0;
end;

function RegCreateKeyTransactedW(
                                 hKey: HKEY; lpSubKey: PWideChar;
                                 Reserved: DWORD; lpClass: PWideChar;
                                 dwOptions: DWORD; samDesired: REGSAM;
                                 lpSecurityAttributes: PSecurityAttributes;
                                 var phkResult: HKEY; lpdwDisposition: PDWORD;
                                 hTransaction: DWORD; pExtendedParemeter: Pointer
                                 ): Longint; stdcall;
begin
  phkResult := 0;
  lpdwDisposition := nil;
  Result := 0;
end;

function RegNotifyChangeKeyValue(hKey: HKEY; bWatchSubtree: BOOL; dwNotifyFilter: DWORD; hEvent: THandle; fAsynchronus: BOOL): Longint; stdcall;
begin
  Result := 0;
end;

// Модифицированная функция NtCreateKey для блокировки записи в реестр
function NtCreateKey(
                     KeyHandle : PHANDLE;
                     DesiredAccess : ACCESS_MASK;
                     ObjectAttributes : PObjectAttributes;
                     TitleIndex:ULONG;
                     ObjectClass : PUNICODESTR;
                     CreateOptions:ULONG;
                     Disposition:PULONG
                     ): NTSTATUS; stdcall;
var
Name : String;
begin
  //Name := PWIDECHAR(ObjectAttributes.ObjectName.Buffer);     // Узнать имя раздела реестра к которому осуществляется доступ
  //if (POS('Software', Name) <> 0) then DesiredAccess := 0;   // Если в имени есть Software то установить атрибут доступа только чтение
  if DesiredAccess = 3 then DesiredAccess := 0;
  Result := RawCreateKey(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, ObjectClass, CreateOptions, Disposition);
end;

// Модифицированная функция LdrLoadDll для блокировки через загрузчик
function LdrLoadDll(PathToFile: PWideChar; Flags: DWORD; ModuleFileName: PUNICODESTR; ModuleHandle: PPointer): NTSTATUS; stdcall;
var
ModuleLoaded : boolean;
Name : String;
begin
  Result := RawLdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle);
  Name := PWIDECHAR(ModuleFileName.Buffer);
  if (Result = 0) then HMODULE := GetModuleHandle('chrome_elf.dll');
  if (HMODULE <> 0) and (BLOK1 = FALSE) then REGBLOCKER(1);
  if (Result = 0) then HMODULE := GetModuleHandle('chrome.dll');
  if (HMODULE <> 0) and (BLOK2 = FALSE) then REGBLOCKER(2);
end;

// Включить перехват функции LdrLoadDll
procedure HookLoader;
begin
  HMODULE := GetModuleHandle('ntdll.dll');                              // HMODULE = дескриптор модуля (адрес по которому он загружен)
  Addr(Proc) := GetProcAddress(HMODULE, 'LdrLoadDll');                  // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(LdrLoadDll), 3);                            // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  ADDR(RawLdrLoadDll) := ADDR(LDRCODE);                                 // Присвоить адрес функции RawLdrLoadDll
end;

procedure HookPreferences;
var
  DLLHandle : THandle;                                                  // Переменная типа THandle (соответствует LONGWORD)
  SysPatch  : array [0..MAX_PATH] of Char;                              // Переменная для хранения пути
  FileName  : string;                                                   // Переменная для хранения полного имени файла
const
  HANDLE = DWORD(-1);
begin
  GetSystemDirectory(SysPatch, SizeOf(SysPatch));                       // Определить Путь к системной директории
  // Перехват вызова функций из kernel32.dll
  FileName :=  SysPatch + '\kernel32.dll';                              // Получить полное имя файла
  DLLHandle := LoadLibrary(pchar(FileName));                            // Загрузить библиотеку и получить её идентификатор
  Addr(Proc) := GetProcAddress(DLLHandle, 'GetComputerNameA');          // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(GetComputerNameA));                         // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'GetComputerNameW');          // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(GetComputerNameW));                         // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'GetComputerNameExA');        // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(GetComputerNameExA));                       // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'GetComputerNameExW');        // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(GetComputerNameExW));                       // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'GetVolumeInformationA');     // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(GetVolumeInformationA));                    // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'GetVolumeInformationW');     // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(GetVolumeInformationW));                    // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'UpdateProcThreadAttribute'); // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(UpdateProcThreadAttribute), 2);             // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  ADDR(RawUpdateProcThreadAttribute) := ADDR(OLDCODE);                  // Присвоить адрес функции RawUpdateProcThreadAttribute
  // Перехват вызова функций из advapi32.dll
  FileName :=  SysPatch + '\advapi32.dll';                              // Получить полное имя файла
  DLLHandle := LoadLibrary(pchar(FileName));                            // Загрузить библиотеку и получить её идентификатор
  Addr(Proc) := GetProcAddress(DLLHandle, 'LogonUserA');                // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(LogonUserW));                               // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'LogonUserW');                // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(LogonUserW));                               // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  // Перехват вызова функций записи в реестр
  if REGOFF = True then begin
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegCreateKeyA');             // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegCreateKeyA));                            // Подмена адреса точки входа функции в процессе на адрес функции из DL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegCreateKeyW');             // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegCreateKeyW));                            // Подмена адреса точки входа функции в процессе на адрес функции из DL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegCreateKeyExA');           // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegCreateKeyExA));                          // Подмена адреса точки входа функции в процессе на адрес функции из DL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegCreateKeyExW');           // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegCreateKeyExW));                          // Подмена адреса точки входа функции в процессе на адрес функции из DL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegCreateKeyTransactedA');   // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegCreateKeyTransactedA));                  // Подмена адреса точки входа функции в процессе на адрес функции из DL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegCreateKeyTransactedW');   // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegCreateKeyTransactedW));                  // Подмена адреса точки входа функции в процессе на адрес функции из DL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegSetValueA');              // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegSetValueA));                             // Подмена адреса точки входа функции в процессе на адрес функции из DL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegSetValueW');              // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegSetValueW));                             // Подмена адреса точки входа функции в процессе на адрес функции из DL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegSetValueExA');            // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegSetValueExA));                           // Подмена адреса точки входа функции в процессе на адрес функции из DL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegSetValueExW');            // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegSetValueExW));                           // Подмена адреса точки входа функции в процессе на адрес функции из DL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegNotifyChangeKeyValue');   // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegNotifyChangeKeyValue));                  // Подмена адреса точки входа функции в процессе на адрес функции из DL
  end;
  // Перехват вызова функций из Crypt32.dll
  FileName :=  SysPatch + '\Crypt32.dll';                               // Получить полное имя файла
  DLLHandle := LoadLibrary(pchar(FileName));                            // Загрузить библиотеку и получить её идентификатор
  Addr(Proc) := GetProcAddress(DLLHandle, 'CryptProtectData');          // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(CryptProtectData));                         // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'CryptUnprotectData');        // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(CryptUnprotectData));                       // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  // Перехват вызова функции NtCreateKey
  if REGOFF = TRUE then begin
  HMODULE := GetModuleHandle('ntdll.dll');                              // HMODULE = дескриптор модуля (адрес по которому он загружен)
  Addr(Proc) := GetProcAddress(HMODULE, 'NtCreateKey');                 // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(NtCreateKey), 4);                           // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  ADDR(RawCreateKey) := ADDR(KEYCODE);                                  // Присвоить адрес функции RawCreateKey
  end;
  end;
end.
