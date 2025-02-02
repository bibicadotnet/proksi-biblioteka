unit Portable;

interface

uses
  Windows,
  Utils,
  Hook,
  PsApi,
  Refining;

{$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}

procedure HookPreferences;

var
  REGOFF : boolean;          // Переменная для отключения записи в реестр
  AIDOFF : boolean;          // Переменная для отключения идентификации приложения
  DIROFF : boolean;          // Переменная для отключения создания и удаления папок и файлов
  RMDISK : boolean;          // Переменная для включения определения пути к TEMP на рамдиске
  REFINE : boolean;          // Переменная для включения обнуления запросов по протоколу TCP  
  SPFOLD : boolean;          // Переменная для включения указания пути к спецпапкам

  OS   : Byte;               // Переменная условного номера версии ОС
  Proc : procedure;          // Процедурная переменная

  FILELIST     : array of String;  // Массив списка файлов для удаления
  DELDIRLIST   : array of String;  // Массив списка директорий для удаления
  BLOCKDIRLIST : array of String;  // Массив списка директорий для блокировки
  DIRLISTNUM   : integer;          // Число эдементов массива списка директорий
  FILELISTNUM  : integer;          // Число эдементов массива списка файлов

  SPECFOLDER : string;

implementation

type

  NTStatus = cardinal;

  // Структура для функции LdrLoadDll и NtCreateKey
  UNICODESTRING = packed record
  Length :        Word;           // размер строки в байтах без учета символа конца строки
  MaximumLength : Word;           // размер памяти, выделенной для буфера
  Buffer :   PWideChar;           // буффер - указатель на строку WideString (уникоде строка)
  end;

  // Структура для функции NtCreateKey
  ObjectAttributes = packed record
  Length: ULONG;
  RootDirectory: THandle;
  var ObjectName: UNICODESTRING;  // так можно определить указатель на тип UNICODESTRING
  Attributes: ULONG;
  SecurityDescriptor: Pointer;
  SecurityQualityOfService: Pointer;
  end;

  // Структура для функции PSStringFromPropertyKey
  PROPERTYKEY = record
  fmtid: TGUID;
  pid: DWORD;
  end;

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
                             cbSize: integer; lpPreviousValue: PPointer; lpReturnSize: PInteger): BOOL; stdcall;

  // Обявление типа фукции с параметрами вызова и возврата соответующими оригинальной функции  NtCreateKey
  CreateKey = function(KeyHandle : PHANDLE; DesiredAccess : ACCESS_MASK; var ObjectAttributes : ObjectAttributes; TitleIndex:ULONG;
                       var ObjectClass : UNICODESTRING; CreateOptions:ULONG; Disposition:PULONG) : NTSTATUS; stdcall;


// Объявление константы с именем PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
// с типом данных DWORD и присвоение ей значения в соответствии с WinBase.h
const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = DWORD ($00020007);

var
  RawUpdateProcThreadAttribute : UpdProcThrAttr;
  RawCreateKey  : CreateKey;

{
  Описание функций для подмены в системных библиотеках
  kernel32.dll (GetComputerName, GetVolumeInformation, UpdateProcThreadAttribute, CreateDirectoryW в XP)
  kernelbase.dll (CreateDirectoryW в 7-11)
  Advapi32.dll (LogonUserA, LogonUserW)
  Crypt32.dll (CryptProtectData, CryptUnprotectData)
  ntdll.dll (NtCreateKey, LoadDll)
  Propsys.dll (PSStringFromPropertyKey)
}

// Это модифицированная функция для блокировки System.AppUserModel.ID
function PSStringFromPropertyKey(const pkey: PROPERTYKEY; psz: PWideChar; cch: INTEGER): HRESULT ; stdcall;
begin
  result := 0;
end;

function GetComputerNameA(lpBuffer: PChar; var nSize: DWORD): BOOL; stdcall;
begin
  result := False;
end;

function GetComputerNameW(lpBuffer: PWideChar; var nSize: DWORD): BOOL; stdcall;
begin
  result := False;
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
  ): BOOL; stdcall;
begin
  result := False;
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
  ): BOOL; stdcall;
begin
  result := False;
end;

// Функция UpdateProcThreadAttribute модифирована чтобы сбрасывать
// бит PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON (0x00000001ui64 << 44)
// бит PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON (0x00000001ui64 << 28)
function UpdateProcThreadAttribute
  (
   lpAttributeList: Pointer;        // Указатель на список атрибутов
   dwFlags: DWORD;                  // Этот параметр зарезервирован и должен иметь значение 0
   Attribute: DWORD;                // Ключ атрибута для обновления в списке атрибутов
   lpValue: Pointer;                // Указатель на значение атрибута
   cbSize: Integer;                 // Размер значения атрибута, заданного параметром lpValue
   lpPreviousValue: PPointer;       // Этот параметр зарезервирован и должен иметь значение NULL
   lpReturnSize: PInteger           // Этот параметр зарезервирован и должен иметь значение NULL
  ): BOOL; stdcall;
var
  Buffer : array of byte;
begin
  if (Attribute = PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY) and (cbSize >= sizeof(UInt64)) then
  begin
    SetLength(Buffer, cbSize);                     // Задать размер буфера
    CopyMemory(Addr(Buffer[0]), lpValue, cbSize);  // Скопировать в массив значение атрибута из адреса по указателю
    Buffer[5] := Buffer[5] and (0 shl 4);          // Сбросить бит NON_MICROSOFT_BINARIES_ALWAYS_ON - это пятый бит шестого байта Int64
    Buffer[3] := Buffer[3] and (0 shl 4);          // Сбросить бит WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON - это пятый бит четвертого байта Int64
    CopyMemory(lpValue, Addr(Buffer[0]), cbSize);  // Скопировать в адрес по указателю значения из буфера
    Buffer := nil;                                 // Освободить память буфера
  end;
  SetHook(UPTCODE, 0);
  result := RawUpdateProcThreadAttribute(lpAttributeList, dwFlags, Attribute, lpValue, cbSize, lpPreviousValue, lpReturnSize);
  SetHook(UPTCODE, 1);
end;

function LogonUserA(lpszUsername, lpszDomain, lpszPassword: PAnsiChar; dwLogonType, dwLogonProvider: DWORD; var phToken: THandle): BOOL; stdcall;
begin
  phToken := $09051945;
  result := True;
end;

function LogonUserW(lpszUsername, lpszDomain, lpszPassword: PWideChar; dwLogonType, dwLogonProvider: DWORD; var phToken: THandle): BOOL; stdcall;
begin
  phToken := $09051945;
  result := True;
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
begin
  pDataOut.cbData := pDataIn.cbData;                                      // Размер выходных данных равен размеру входных
  pDataOut.pbData := PBYTE(LocalAlloc(LMEM_FIXED, pDataIn.cbData));       // Выделить фиксированную память для блока выходных данных
  CopyMemory(pDataOut.pbData, pDataIn.pbData, pDataIn.cbData);            // Скопировать входные данные в блок выходных данных
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
begin
  pDataOut.cbData := pDataIn.cbData;                                      // Размер выходных данных равен размеру входных
  pDataOut.pbData := PBYTE(LocalAlloc(LMEM_FIXED, pDataIn.cbData));       // Выделить фиксированную память для блока выходных данных
  CopyMemory(pDataOut.pbData, pDataIn.pbData, pDataIn.cbData);            // Скопировать входные данные в блок выходных данных
  result := TRUE;
end;

function RegCreateKeyA(hKey: HKEY; lpSubKey: PAnsiChar; phkResult: PHKEY): Longint; stdcall;
begin
  Result := 0;
end;

function RegCreateKeyW(hKey: HKEY; lpSubKey: PWideChar; phkResult: PHKEY): Longint; stdcall;
begin
  Result := 0;
end;

function RegCreateKeyExA(hKey: HKEY; lpSubKey: PAnsiChar; Reserved: DWORD; lpClass: PAnsiChar; dwOptions: DWORD; samDesired: REGSAM;
                         lpSecurityAttributes: PSecurityAttributes; phkResult: PHKEY; lpdwDisposition: PDWORD): Longint; stdcall;
begin
  Result := 0;
end;

function RegCreateKeyExW(hKey: HKEY; lpSubKey: PWideChar; Reserved: DWORD; lpClass: PWideChar; dwOptions: DWORD; samDesired: REGSAM;
                         lpSecurityAttributes: PSecurityAttributes; phkResult: PHKEY; lpdwDisposition: PDWORD): Longint; stdcall;
begin
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

function RegCreateKeyTransactedA(hKey: HKEY; lpSubKey: PAnsiChar; Reserved: DWORD; lpClass: PAnsiChar; dwOptions: DWORD; samDesired: REGSAM;
                                 lpSecurityAttributes: PSecurityAttributes; var phkResult: HKEY; lpdwDisposition: PDWORD;
                                 hTransaction: DWORD; pExtendedParemeter: Pointer): Longint; stdcall;
begin
  Result := 0;
end;

function RegCreateKeyTransactedW(hKey: HKEY; lpSubKey: PWideChar; Reserved: DWORD; lpClass: PWideChar; dwOptions: DWORD; samDesired: REGSAM;
                                 lpSecurityAttributes: PSecurityAttributes; var phkResult: HKEY; lpdwDisposition: PDWORD;
                                 hTransaction: DWORD; pExtendedParemeter: Pointer): Longint; stdcall;
begin
  Result := 0;
end;

function RegNotifyChangeKeyValue(hKey: HKEY; bWatchSubtree: BOOL; dwNotifyFilter: DWORD; hEvent: THandle; fAsynchronus: BOOL): Longint; stdcall;
begin
  Result := 0;
end;

// Модифицированная функция NtCreateKey для блокировки записи в реестр
function NtCreateKey(
                     KeyHandle : PHANDLE;                    // Указатель на переменную-дескриптор, которая получает дескриптор ключа.
                     DesiredAccess : ACCESS_MASK;            // Указывает значение ACCESS_MASK, которое определяет запрашиваемый доступ к объекту.
                     var ObjectAttributes : ObjectAttributes;// Указатель на структуру ObjectAttributes, которая определяет имя объекта и другие атрибуты.
                     TitleIndex:ULONG;                       // Драйверы устройств и промежуточных устройств устанавливают этот параметр равным нулю.
                     var ObjectClass : UNICODESTRING;        // Указатель на строку UNICODESTRING, содержащую класс объекта ключа.
                     CreateOptions:ULONG;                    // Определяет параметры, применяемые при создании или открытии ключа.
                     Disposition:PULONG                      // указатель на переменную, которая получает значение, указывающее, был ли создан новый ключ или открыт существующий.
                     ): NTSTATUS; stdcall;
begin
  if DesiredAccess = 1 then DesiredAccess := 0;
  if DesiredAccess = 3 then DesiredAccess := 0;
  if DesiredAccess = 514 then DesiredAccess := 0;
  SetHook(KEYCODE, 0);
  Result := RawCreateKey(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, ObjectClass, CreateOptions, Disposition);
  SetHook(KEYCODE, 1);
end;

// Модифицированная функция CreateDirectoryW для блокировки создания директорий по списку
function CreateDirectory(lpPathName: PWideChar; lpSecurityAttributes: PSecurityAttributes): BOOL; stdcall;
var
  PathName : String;
  DirName  : String;
  I: integer;
  NoCreate : boolean;
begin
  PathName := PWIDECHAR(lpPathName);                         // Взять имя директории из указателя
  NoCreate := False;                                         // Снять флаг
  for I := 0 to DIRLISTNUM - 1 do                            // Цикл сравнения имени директории со списком
  begin
    DirName := BLOCKDIRLIST[i];                              // Имя из списка блокировки в переменную
    if XPOS(DirName, PathName) <> 0 then NoCreate := True;   // Если имя совпадает с именем из списка установить флаг
    if NoCreate = True then break;                           // Если флаг установлен прервать цикл
  end;
  // Если флаг не установлен выполнить функции CreateDirectoryW иначе просто вернуть положительный результат
  SetHook(CRDCODE, 0);
  if NoCreate = False then Result := CreateDirectoryW(lpPathName, lpSecurityAttributes) else Result := True;
  SetHook(CRDCODE, 1);
end;

// Модифицированная функция для получения имени файла из его указателя
function GetFinalPathNameByHandleW(hFile: THandle; lpszFilePath: PWidechar; cchFilePath: DWORD; dwFlags: DWORD): DWORD; stdcall;
var
  FileSizeHi, FileSizeLo : cardinal;
  hFileMap : THandle;
  FileName : array [0..MAX_PATH] of WideChar;
  pMem : pointer;
begin
  FileSizeHi := 0;
  FileSizeLo := GetFileSize(hFile, ADDR(FileSizeHi));                              // Получить размер файла по указателю на него
  hFileMap := CreateFileMapping(hFile, nil, PAGE_READONLY, 0, FileSizeLo, nil);    // Создать объект "проецируемый файл"
  if (hFileMap <> 0) then                                                          // Если объект создан, тогда
  begin
    pMem := MapViewOfFile (hFileMap, FILE_MAP_READ, 0, 0, 1);                      // Создать проецируемый файл, чтобы получить имя файла.
    if (pMem <> nil) then                                                          // если успешно, тогда
      begin
      if GetMappedFileNameW(GetCurrentProcess, pMem, FileName, MAX_PATH) <> 0 then // Получить имя файла в виде пути к имени устройства, если успешно тогда
        begin
            CopyMemory(lpszFilePath, ADDR(FileName), Length(FileName));
        end;
      UnmapViewOfFile(pMem);
      end;
    CloseHandle(hFileMap);
  end;
  Result := Length(FileName);
end;

// Модифицированная функция SHGetFolderPathW для указания своего пути к спецпапкам
function SHGetFolderPathW(hwnd: HWND; csidl: Integer; hToken: THandle; dwFlags: DWord; pszPath: PWideChar): HRESULT; stdcall;
begin
  if SPECFOLDER = '' then SPECFOLDER := 'nul';
  CopyMemory(pszPath, PwideChar(WideString(SPECFOLDER + #0)), Length(WideString(SPECFOLDER + #0)) * 2);
  if SPECFOLDER = 'nul' then Result := E_ABORT  else Result := S_OK;
end;

procedure HookPreferences;
var
  DLLHandle : THandle;                                                  // Переменная типа THandle (соответствует LONGWORD)
  SysPatch  : array [0..MAX_PATH] of Char;                              // Переменная для хранения пути
  FileName  : string;                                                   // Переменная для хранения полного имени файла
begin
  GetSystemDirectory(SysPatch, SizeOf(SysPatch));                       // Определить Путь к системной директории

  // Перехват вызова функций из kernel32.dll
  DLLHandle := GetModuleHandle('kernel32.dll');                         // Получить идентификатор
  Addr(Proc) := GetProcAddress(DLLHandle, 'GetComputerNameA');          // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(GetComputerNameA));                         // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'GetComputerNameW');          // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(GetComputerNameW));                         // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'GetVolumeInformationA');     // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(GetVolumeInformationA));                    // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'GetVolumeInformationW');     // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(GetVolumeInformationW));                    // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  if OS > 1 then begin
  Addr(Proc) := GetProcAddress(DLLHandle, 'UpdateProcThreadAttribute'); // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(UpdateProcThreadAttribute), 2);             // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  ADDR(RawUpdateProcThreadAttribute) := ADDR(Proc);                     // Присвоить адрес функции RawUpdateProcThreadAttribute
  end;
  if DIROFF = TRUE then begin
  Addr(Proc) := GetProcAddress(DLLHandle, 'CreateDirectoryW');          // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(CreateDirectory), 4);                       // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  end;
  if (OS > 1) and (RMDISK = TRUE) then begin
  Addr(Proc) := GetProcAddress(DLLHandle, 'GetFinalPathNameByHandleW'); // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(GetFinalPathNameByHandleW));                // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  end;
  
   //Перехват вызова функций из advapi32.dll
  DLLHandle := GetModuleHandle('advapi32.dll');                         // Получить идентификатор
  Addr(Proc) := GetProcAddress(DLLHandle, 'LogonUserA');                // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(LogonUserW));                               // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'LogonUserW');                // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(LogonUserW));                               // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  // Перехват вызова функций записи в реестр
  if REGOFF = TRUE then begin
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegCreateKeyA');             // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegCreateKeyA));                            // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegCreateKeyW');             // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegCreateKeyW));                            // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegCreateKeyExA');           // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegCreateKeyExA));                          // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegCreateKeyExW');           // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegCreateKeyExW));                          // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegSetValueA');              // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegSetValueA));                             // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegSetValueW');              // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegSetValueW));                             // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegSetValueExA');            // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegSetValueExA));                           // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegSetValueExW');            // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegSetValueExW));                           // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegCreateKeyTransactedA');   // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegCreateKeyTransactedA));                  // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  if OS > 1 then begin
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegCreateKeyTransactedW');   // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegCreateKeyTransactedW));                  // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  end;
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegNotifyChangeKeyValue');   // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegNotifyChangeKeyValue));                  // Подмена адреса точки входа функции в процессе на адрес функции из DLL
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
  DLLHandle := GetModuleHandle('ntdll.dll');                            // DLLHandle = идентификатор модуля (адрес по которому он загружен)
  Addr(Proc) := GetProcAddress(DLLHandle, 'NtCreateKey');               // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(NtCreateKey), 3);                           // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  ADDR(RawCreateKey) := ADDR(Proc);                                     // Присвоить адрес функции RawCreateKey
  end;

  // Перехват вызова функции SHGetFolderPathW
  if SPFOLD = TRUE then begin
  DLLHandle := GetModuleHandle('SHELL32.dll');                          // Получить идентификатор модуля (адрес по которому он загружен)
  Addr(Proc) := GetProcAddress(DLLHandle, 'SHGetFolderPathW');          // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(SHGetFolderPathW));                         // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  end;

  // Перехват вызова функций из Propsys.dll
  if AIDOFF = TRUE then begin
  FileName :=  SysPatch + '\Propsys.dll';   ;                           // Получить полное имя файла
  DLLHandle := LoadLibrary(pchar(FileName));                            // Загрузить библиотеку и получить её идентификатор
  Addr(Proc) := GetProcAddress(DLLHandle, 'PSStringFromPropertyKey');   // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(PSStringFromPropertyKey));                  // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  end;

  //Перехват вызова функций из WS2_32.dll
  if REFINE = TRUE then begin
  FileName :=  SysPatch + '\WS2_32.dll';                                // Получить полное имя файла
  DLLHandle := LoadLibrary(pchar(FileName));                            // Загрузить библиотеку и получить её идентификатор
  Addr(Proc) := GetProcAddress(DLLHandle, 'WSASend');                   // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(WSASend), 5);                               // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  ADDR(RAWWSASend) := ADDR(Proc);                                       // Присвоить адрес функции RAWWSASend

  // Импорт функции closesocket
  ADDR(closesocket) := GetProcAddress(DLLHandle, 'closesocket');
  end;

  end;
end.